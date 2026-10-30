"""Lightweight FastAPI server for Raucle Detect REST API.

Start via the CLI::

    raucle serve --port 8000

Or directly with uvicorn::

    uvicorn raucle.server:app --host 0.0.0.0 --port 8000

Authentication
--------------
Set the ``RAUCLE_API_KEY`` environment variable (legacy ``RAUCLE_DETECT_API_KEY``
also accepted) to require callers to pass ``Authorization: Bearer <key>`` on
every request.  If the variable is unset the server runs unauthenticated
(suitable for localhost-only use).

Rate limiting
-------------
Set ``RAUCLE_RATE_LIMIT`` (requests per minute per IP, default 120) and
``RAUCLE_BURST_LIMIT`` (burst allowance, default 20) to tune limits; legacy
``RAUCLE_DETECT_*`` names remain supported.

Endpoints
---------
POST /scan          Scan a single prompt
POST /scan/batch    Scan multiple prompts
POST /scan/output   Scan LLM output
POST /scan/tool     Scan tool call arguments
GET  /rules         List loaded detection rules
GET  /health        Health check
GET  /metrics       Prometheus-compatible counters (plain text)
"""

from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from collections import defaultdict
from typing import Any

from raucle import __version__
from raucle._env import env as _env
from raucle.errors import ConfigurationError
from raucle.scanner import Scanner, ScanResult

logger = logging.getLogger(__name__)

try:
    from fastapi import FastAPI, HTTPException, Request  # type: ignore[import-untyped]
    from fastapi.responses import JSONResponse, PlainTextResponse  # type: ignore[import-untyped]
    from pydantic import BaseModel, Field  # type: ignore[import-untyped]
except ImportError as exc:
    raise ImportError(
        "FastAPI and Pydantic are required for the server.\n"
        "Install them with:  pip install raucle[server]"
    ) from exc


# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

_mode = _env("MODE", "standard")
_rules_dir = _env("RULES_DIR")
_api_key = _env("API_KEY", "")  # empty = no auth
_rate_limit_rpm = int(_env("RATE_LIMIT", "120"))
_burst_limit = int(_env("BURST_LIMIT", "20"))
_model_version = _env("MODEL_VERSION", "")
_tenant_default = os.environ.get("RAUCLE_DETECT_TENANT") or None


_HELP_SCANNER_MODE = "Override scanner mode"  # named once (Sonar S1192)


def _init_compliance() -> tuple[Any, Any]:
    """Build the optional audit sink + verdict signer from environment.

    The principle: **explicitly configured but broken = REFUSE; simply
    absent = WARN loudly and continue in unsigned mode.** Never silent.

    Returns ``(audit_sink, verdict_signer)``. Either may be ``None``.

    Raises
    ------
    ConfigurationError
        If an explicit env var is set but the corresponding initialiser
        fails (e.g. ``RAUCLE_DETECT_VERDICT_KEY_PEM`` set but unparseable).
    """
    audit_sink: Any = None
    verdict_signer: Any = None

    signer_pem = os.environ.get("RAUCLE_DETECT_VERDICT_KEY_PEM", "")

    # The audit + verdicts modules require ``cryptography``.
    try:
        from raucle.audit import sink_from_env
        from raucle.verdicts import VerdictSigner
    except ImportError as exc:
        if signer_pem or os.environ.get("RAUCLE_DETECT_AUDIT_PATH"):
            # Explicit config but the library isn't installed — that's
            # an operator error.
            logger.critical(
                "raucle server: cryptography backend unavailable but "
                "compliance env vars are set: %s",
                exc,
            )
            raise ConfigurationError(
                "compliance backend unavailable (install raucle[compliance]) "
                f"but compliance env vars are set: {exc}"
            ) from exc
        logger.warning(
            "raucle server: running in UNSIGNED mode — verdicts will not "
            "be verifiable. Install raucle[compliance] and set "
            "RAUCLE_DETECT_VERDICT_KEY_PEM for signed receipts."
        )
        return audit_sink, verdict_signer

    # Audit sink. ``sink_from_env`` itself raises ``ConfigurationError``
    # when the key env var is set but invalid; we let that propagate.
    audit_sink = sink_from_env()

    # Verdict signer.
    if signer_pem:
        try:
            verdict_signer = VerdictSigner.from_pem(signer_pem.encode())
        except Exception as exc:
            logger.critical(
                "raucle server: failed to load verdict signer from "
                "RAUCLE_DETECT_VERDICT_KEY_PEM: %s",
                exc,
            )
            raise ConfigurationError(
                f"verdict signer (RAUCLE_DETECT_VERDICT_KEY_PEM) failed to load: {exc}"
            ) from exc
    else:
        logger.warning(
            "raucle server: RAUCLE_DETECT_VERDICT_KEY_PEM not set — "
            "scan results will not include signed receipts."
        )

    return audit_sink, verdict_signer


_audit_sink, _verdict_signer = _init_compliance()

_scanner = Scanner(
    mode=_mode,
    rules_dir=_rules_dir,
    audit_sink=_audit_sink,
    verdict_signer=_verdict_signer,
    model_version=_model_version,
    tenant=_tenant_default,
)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


# Per-field caps bound the memory a single request can pin even before the
# body-size middleware (below) rejects oversized bodies (round-3 #3).
_MAX_PROMPT_CHARS = 100_000
_MAX_BATCH_PROMPTS = 1000


class ScanRequest(BaseModel):
    prompt: str = Field(
        ..., min_length=1, max_length=_MAX_PROMPT_CHARS, description="Prompt text to scan"
    )
    context: dict[str, Any] | None = Field(default=None, description="Optional context metadata")
    mode: str | None = Field(default=None, description="Override scanner mode for this request")


class BatchScanRequest(BaseModel):
    prompts: list[str] = Field(
        ...,
        min_length=1,
        max_length=_MAX_BATCH_PROMPTS,
        description="List of prompts to scan",
    )
    mode: str | None = Field(default=None, description=_HELP_SCANNER_MODE)
    workers: int = Field(default=4, ge=1, le=32, description="Concurrency level")


class OutputScanRequest(BaseModel):
    output: str = Field(..., min_length=1, description="LLM output text to scan")
    original_prompt: str | None = Field(
        default=None, description="Original user prompt for context"
    )
    mode: str | None = Field(default=None, description=_HELP_SCANNER_MODE)


class ToolCallScanRequest(BaseModel):
    tool_name: str = Field(..., description="Name of the tool being called")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Tool call arguments")
    mode: str | None = Field(default=None, description=_HELP_SCANNER_MODE)


class ScanResponse(BaseModel):
    verdict: str
    confidence: float
    injection_detected: bool
    categories: list[str]
    attack_technique: str
    layer_scores: dict[str, float]
    matched_rules: list[str]
    action: str
    scan_time_ms: float


class BatchScanResponse(BaseModel):
    results: list[ScanResponse]
    total: int
    scan_time_ms: float


class HealthResponse(BaseModel):
    status: str
    version: str
    mode: str
    rules_loaded: int
    auth_enabled: bool


# ---------------------------------------------------------------------------
# Prometheus-style metrics counters
# ---------------------------------------------------------------------------

_metrics_lock = threading.Lock()
_counters: dict[str, int] = defaultdict(int)
_histograms: dict[str, list[float]] = defaultdict(list)
_MAX_HISTOGRAM_SAMPLES = 1000  # cap per-endpoint to avoid unbounded growth


def _record(endpoint: str, verdict: str, elapsed_ms: float) -> None:
    with _metrics_lock:
        _counters["raucle_requests_total"] += 1
        _counters[f'raucle_requests_total{{endpoint="{endpoint}"}}'] += 1
        _counters[f'raucle_verdict_total{{verdict="{verdict}"}}'] += 1
        bucket = _histograms[f'raucle_scan_duration_ms{{endpoint="{endpoint}"}}']
        if len(bucket) < _MAX_HISTOGRAM_SAMPLES:
            bucket.append(elapsed_ms)


def _metrics_text() -> str:
    lines: list[str] = [
        "# HELP raucle_requests_total Total number of scan requests",
        "# TYPE raucle_requests_total counter",
    ]
    with _metrics_lock:
        for key, val in sorted(_counters.items()):
            lines.append(f"{key} {val}")

        lines += [
            "",
            "# HELP raucle_scan_duration_ms Scan latency in milliseconds",
            "# TYPE raucle_scan_duration_ms summary",
        ]
        for key, samples in sorted(_histograms.items()):
            if samples:
                avg = sum(samples) / len(samples)
                p99 = sorted(samples)[int(len(samples) * 0.99)]
                lines.extend(
                    [
                        f'{key},quantile="avg"}} {avg:.2f}',
                        f'{key},quantile="0.99"}} {p99:.2f}',
                        f"{key}_count}} {len(samples)}",
                    ]
                )

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Rate limiter (token-bucket per client IP)
# ---------------------------------------------------------------------------


class _TokenBucket:
    """Simple per-IP token bucket for rate limiting."""

    __slots__ = ("tokens", "last_refill")

    def __init__(self, capacity: float) -> None:
        self.tokens = capacity
        self.last_refill = time.monotonic()

    def consume(self, capacity: float, refill_rate: float) -> bool:
        """Return True if the request is allowed (token consumed), False if rate-limited."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(capacity, self.tokens + elapsed * refill_rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


_rate_buckets: dict[str, _TokenBucket] = {}
_rate_buckets_lock = threading.Lock()
_RATE_CAPACITY = float(_burst_limit)
_RATE_REFILL = _rate_limit_rpm / 60.0  # tokens per second
# Cap the bucket map so a flood of distinct client keys (e.g. rotating IPv6
# source addresses) cannot grow it without bound -> OOM (round-3 #11). When
# full we evict the oldest insertions (dicts preserve insertion order).
_MAX_RATE_BUCKETS = 100_000
# Largest request body we accept, pre-parse (round-3 #3). 16 MiB comfortably
# covers a full 1000-prompt batch of reasonable prompts.
_MAX_BODY_BYTES = 16 * 1024 * 1024
# Per-client rate limiting only works if request.client.host is the real
# client. Behind a TLS-terminating proxy it is the proxy IP (all clients share
# one bucket). Opt in to trusting the left-most X-Forwarded-For entry ONLY when
# the deployment sits behind a trusted proxy that sets it.
_trust_proxy = os.environ.get("RAUCLE_TRUST_PROXY", "").lower() in ("1", "true", "yes")


def _check_rate_limit(client_ip: str) -> bool:
    """Return True if request is within rate limit, False if it should be rejected."""
    if _rate_limit_rpm <= 0:
        return True
    with _rate_buckets_lock:
        if client_ip not in _rate_buckets:
            while len(_rate_buckets) >= _MAX_RATE_BUCKETS:
                # Evict the oldest-inserted bucket to bound memory.
                _rate_buckets.pop(next(iter(_rate_buckets)))
            _rate_buckets[client_ip] = _TokenBucket(_RATE_CAPACITY)
        return _rate_buckets[client_ip].consume(_RATE_CAPACITY, _RATE_REFILL)


def _client_key(request: Request) -> str:
    """Best-effort per-client key for rate limiting (see _trust_proxy)."""
    if _trust_proxy:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Raucle Detect",
    description="Prompt injection detection API",
    version=__version__,
)


# ---------------------------------------------------------------------------
# Middleware: auth + rate limiting
# ---------------------------------------------------------------------------


def _check_content_length(request: Request) -> JSONResponse | None:
    """Reject oversized bodies before reading/parsing them (round-3 #3)."""
    content_length = request.headers.get("content-length")
    if content_length is None:
        return None
    try:
        declared = int(content_length)
    except ValueError:
        return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length."})
    if declared > _MAX_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={"detail": f"Request body too large (max {_MAX_BODY_BYTES} bytes)."},
        )
    return None


def _check_api_key(request: Request) -> JSONResponse | None:
    """Validate the API key, allowing ?access_token= for SSE endpoints."""
    if not _api_key:
        return None
    # Browser EventSource cannot set an Authorization header, so the live
    # view endpoints also accept ?access_token=<key> (constant-time check).
    if request.url.path in ("/events", "/dashboard"):
        qtoken = request.query_params.get("access_token", "")
        if qtoken and secrets.compare_digest(qtoken.encode(), _api_key.encode()):
            return None
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        _counters["raucle_auth_failures_total"] += 1
        return JSONResponse(
            status_code=401,
            content={"detail": "Missing Authorization header. Use: Bearer <api-key>"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    provided_key = auth_header[len("Bearer ") :]
    if not secrets.compare_digest(provided_key.encode(), _api_key.encode()):
        _counters["raucle_auth_failures_total"] += 1
        return JSONResponse(
            status_code=403,
            content={"detail": "Invalid API key."},
        )
    return None


@app.middleware("http")
async def _auth_and_rate_limit(request: Request, call_next):  # type: ignore[no-untyped-def]
    # /health is always open (liveness probe). /metrics is open only when no
    # API key is configured; once auth is enabled it must not leak counters to
    # unauthenticated callers (round-3 #18).
    if request.url.path == "/health":
        return await call_next(request)
    if request.url.path == "/metrics" and not _api_key:
        return await call_next(request)

    body_error = _check_content_length(request)
    if body_error is not None:
        return body_error

    # Rate limiting
    if not _check_rate_limit(_client_key(request)):
        _counters["raucle_rate_limited_total"] += 1
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Slow down and retry."},
            headers={"Retry-After": "60"},
        )

    auth_error = _check_api_key(request)
    if auth_error is not None:
        return auth_error

    return await call_next(request)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/scan")
def scan_prompt(req: ScanRequest) -> ScanResponse:
    """Scan a single prompt for injection attacks."""
    start = time.perf_counter()
    result: ScanResult = _scanner.scan(req.prompt, context=req.context, mode=req.mode)
    elapsed_ms = (time.perf_counter() - start) * 1000
    _record("/scan", result.verdict, elapsed_ms)
    return ScanResponse(**result.to_dict(), scan_time_ms=round(elapsed_ms, 2))


@app.post("/scan/batch", responses={400: {"description": "Too many prompts"}})
def scan_batch(req: BatchScanRequest) -> BatchScanResponse:
    """Scan multiple prompts concurrently."""
    if len(req.prompts) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 prompts per batch")

    start = time.perf_counter()
    results = _scanner.scan_batch(req.prompts, workers=req.workers, mode=req.mode)
    elapsed_ms = (time.perf_counter() - start) * 1000
    _record("/scan/batch", "BATCH", elapsed_ms)

    return BatchScanResponse(
        results=[ScanResponse(**r.to_dict(), scan_time_ms=0) for r in results],
        total=len(results),
        scan_time_ms=round(elapsed_ms, 2),
    )


@app.post("/scan/output")
def scan_output(req: OutputScanRequest) -> ScanResponse:
    """Scan LLM output for data leakage, injection, and exfiltration."""
    start = time.perf_counter()
    result: ScanResult = _scanner.scan_output(
        req.output,
        original_prompt=req.original_prompt,
        mode=req.mode,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000
    _record("/scan/output", result.verdict, elapsed_ms)
    return ScanResponse(**result.to_dict(), scan_time_ms=round(elapsed_ms, 2))


@app.post("/scan/tool")
def scan_tool_call(req: ToolCallScanRequest) -> ScanResponse:
    """Scan tool call arguments for dangerous patterns."""
    start = time.perf_counter()
    result: ScanResult = _scanner.scan_tool_call(
        req.tool_name,
        req.arguments,
        mode=req.mode,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000
    _record("/scan/tool", result.verdict, elapsed_ms)
    return ScanResponse(**result.to_dict(), scan_time_ms=round(elapsed_ms, 2))


@app.get("/rules")
def list_rules() -> list[dict[str, Any]]:
    """List all loaded detection rules."""
    return _scanner.list_rules()


@app.get("/health")
def health() -> HealthResponse:
    """Health check."""
    return HealthResponse(
        status="ok",
        version=__version__,
        mode=_scanner.mode,
        rules_loaded=len(_scanner.list_rules()),
        auth_enabled=bool(_api_key),
    )


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    """Prometheus-compatible plain-text metrics."""
    return _metrics_text()


# ---------------------------------------------------------------------------
# Verdict receipt verification
# ---------------------------------------------------------------------------


class VerifyReceiptRequest(BaseModel):
    receipt: str = Field(..., description="Compact JWS receipt string")
    public_key_pem: str = Field(..., description="Ed25519 public key in PEM format")
    expected_input: str | None = Field(default=None, description="Optional input to bind")


class OutcomeVerifyRequest(BaseModel):
    prompt: str = Field(..., min_length=1)
    response: str = Field(..., min_length=1)
    tool_calls: list[dict[str, Any]] | None = Field(default=None)


@app.post("/verdict/verify", responses={400: {"description": "Invalid receipt"}})
def verify_receipt(req: VerifyReceiptRequest) -> dict[str, Any]:
    """Verify a signed verdict receipt and return its payload."""
    from raucle.verdicts import VerdictVerificationError, VerdictVerifier

    try:
        verifier = VerdictVerifier(public_key_pem=req.public_key_pem.encode())
        payload = verifier.verify(req.receipt, expected_input=req.expected_input)
        return {"valid": True, "payload": payload.to_dict()}
    except VerdictVerificationError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid receipt: {exc}") from exc


@app.post("/verify/outcome")
def verify_outcome(req: OutcomeVerifyRequest) -> dict[str, Any]:
    """Classify whether an attack actually landed by inspecting the response."""
    from raucle.outcome import OutcomeVerifier

    verifier = OutcomeVerifier()
    report = verifier.verify(req.prompt, req.response, tool_calls=req.tool_calls)
    return report.to_dict()


@app.get("/audit/status")
def audit_status() -> dict[str, Any]:
    """Report whether audit logging is active and the current chain tail."""
    if _audit_sink is None:
        return {"enabled": False}
    return {
        "enabled": True,
        "event_count": _audit_sink.event_count,
        "tail_hash": _audit_sink.tail_hash,
    }


# ---------------------------------------------------------------------------
# Live view — SSE event stream + minimal dashboard (v0.21.0)
# ---------------------------------------------------------------------------
#
# Tails the audit chain file (RAUCLE_DETECT_AUDIT_PATH) and pushes each new
# event to connected browsers via Server-Sent Events. The dashboard is a
# single self-contained HTML page — no build step, no external assets.
#
# Auth: the global middleware applies. Because the browser EventSource API
# cannot set an Authorization header, when an API key is configured the
# dashboard and /events also accept ``?access_token=<key>`` (checked with a
# constant-time compare in the middleware below).

_audit_path_for_stream = os.environ.get("RAUCLE_DETECT_AUDIT_PATH", "")

_DASHBOARD_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>raucle live</title><style>
 body{font:13px/1.5 ui-monospace,Menlo,monospace;background:#0d1117;
  color:#c9d1d9;margin:0;padding:1.2rem}
 h1{font-size:15px;color:#58a6ff;margin:0 0 .2rem} small{color:#8b949e}
 table{border-collapse:collapse;width:100%;margin-top:.8rem}
 td,th{padding:.25rem .6rem;border-bottom:1px solid #21262d;text-align:left;white-space:nowrap}
 td.reason{white-space:normal;color:#8b949e}
 .ALLOW,.CLEAN{color:#3fb950;font-weight:600}.DENY,.MALICIOUS{color:#f85149;font-weight:700}
 .SUSPICIOUS{color:#d29922;font-weight:600}
 #stats{margin-top:.4rem}#stats b{color:#c9d1d9}
</style></head><body>
<h1>raucle &mdash; live decisions</h1>
<small>streaming from the audit chain via /events (newest first)</small>
<div id="stats">allow <b id="na">0</b> &middot; deny <b id="nd">0</b>
 &middot; scans <b id="ns">0</b></div>
<table><thead><tr><th>time</th><th>kind</th><th>outcome</th>
<th>who / what</th><th>detail</th></tr></thead>
<tbody id="rows"></tbody></table>
<script>
 const qs=new URLSearchParams(location.search);
 const tok=qs.get("access_token");
 const es=new EventSource("/events"+(tok?"?access_token="+encodeURIComponent(tok):""));
 let na=0,nd=0,ns=0;
 es.onmessage=(m)=>{const e=JSON.parse(m.data);const tr=document.createElement("tr");
  let kind,outcome,who,detail;
  if("decision" in e){kind="gate";outcome=e.decision;
   who=(e.agent_id||"?")+" \\u2192 "+(e.tool||"?");
   detail=e.decision==="ALLOW"?"":(e.decision_reason||"");
   e.decision==="ALLOW"?na++:nd++;}
  else if("verdict" in e){kind=e.kind||"scan";outcome=e.verdict;
   who=e.ruleset_hash?e.ruleset_hash.slice(0,12):"";
   detail=(e.matched_rules||[]).join(", ");ns++;}
  else{kind=e.kind||"event";outcome="";who="";detail="";}
  tr.innerHTML=`<td>${(e.timestamp||"").slice(0,19)}</td><td>${kind}</td>`+
   `<td class="${outcome}">${outcome}</td><td>${who}</td><td class="reason">${detail}</td>`;
  const tb=document.getElementById("rows");tb.insertBefore(tr,tb.firstChild);
  while(tb.children.length>500)tb.removeChild(tb.lastChild);
  document.getElementById("na").textContent=na;document.getElementById("nd").textContent=nd;
  document.getElementById("ns").textContent=ns;};
</script></body></html>"""


def _audit_line_to_frame(line: str) -> str | None:
    """Parse one audit log line into an SSE data frame (or ``None`` to skip)."""
    import json as _json

    try:
        rec = _json.loads(line)
    except ValueError:
        return None
    if not isinstance(rec, dict) or "chain_meta" in rec or "checkpoint" in rec:
        return None
    ev = rec.get("event") if isinstance(rec.get("event"), dict) else rec
    return "data: " + _json.dumps(ev, ensure_ascii=False) + "\n\n"


def _follow_audit_stream(fh):
    """Yield live SSE frames from an open file handle, with keepalive on idle."""
    import time as _time

    while True:
        line = fh.readline()
        if not line:
            _time.sleep(0.5)
            yield ": keepalive\n\n"
            continue
        frame = _audit_line_to_frame(line)
        if frame:
            yield frame


def _iter_audit_events(path: str, replay: int = 50, follow: bool = True):
    """Yield audit events as SSE frames: last *replay* existing, then live.

    ``follow=False`` ends the stream after the replay — used by clients that
    want a snapshot, and by tests (an infinite generator cannot be cleanly
    exhausted through a test client's thread portal).
    """
    with open(path, encoding="utf-8") as fh:
        tail = fh.readlines()[-replay:]
        for line in tail:
            frame = _audit_line_to_frame(line)
            if frame:
                yield frame
        if not follow:
            return
        yield from _follow_audit_stream(fh)


@app.get("/dashboard", responses={404: {"description": "Live view disabled"}})
def dashboard() -> Any:
    """Self-contained live dashboard (SSE-fed)."""
    from fastapi.responses import HTMLResponse

    if not _audit_path_for_stream:
        raise HTTPException(
            status_code=404,
            detail="Live view disabled: set RAUCLE_DETECT_AUDIT_PATH to enable.",
        )
    return HTMLResponse(_DASHBOARD_HTML)


@app.get("/events", responses={404: {"description": "Live view disabled"}})
def events(follow: bool = True) -> Any:
    """Server-Sent Events stream of audit events (replays last 50, then live).

    ``?follow=false`` returns the replay snapshot and closes the stream.
    """
    from fastapi.responses import StreamingResponse

    if not _audit_path_for_stream or not os.path.exists(_audit_path_for_stream):
        raise HTTPException(
            status_code=404,
            detail="Live view disabled: set RAUCLE_DETECT_AUDIT_PATH to enable.",
        )
    return StreamingResponse(
        _iter_audit_events(_audit_path_for_stream, follow=follow),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
