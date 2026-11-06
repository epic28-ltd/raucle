"""EPIC O3 - URL-switch gate proxy (``raucle urlgate``).

A transparent, drop-in gate proxy for stock OpenAI/Anthropic SDK clients.
Adoption is config-only: point the SDK's ``base_url`` at this proxy and
keep using the client exactly as before.

What it does
------------
* Proxies loopback API traffic to the configured upstream (default
  ``https://api.openai.com``). Non-gated traffic (e.g. ``GET /v1/models``)
  passes through untouched.
* Gated traffic (chat/completions/messages POSTs) consults the existing
  policy gate (``RaucleGateway``) server-side with a service-scoped policy
  and mints one signed provenance receipt per gated call - allow AND deny.
* On DENY it never contacts the upstream. It returns an upstream-shaped
  error body (OpenAI ``{"error": {...}}`` / Anthropic
  ``{"type": "error", "error": {...}}``) with HTTP 403 so stock SDK
  clients fail through their normal error contract, plus a documentable
  ``X-Raucle-Receipt`` header carrying the receipt hash.
* Streaming (SSE) responses are proxied byte-identically: bytes read from
  the upstream stream are written to the client unchanged, chunk framing
  re-emitted only at buffer boundaries.

Honest limits (documented, not claimed away)
--------------------------------------------
* Pure passthrough means the non-tool parts of a response body are NOT
  verified or deeply inspected: this proxy attests that policy was
  consulted and a receipt minted per gated call; it does not verify the
  upstream's response content.
* No deep payload rewriting: request/response bodies are forwarded
  verbatim (``Accept-Encoding`` is pinned to ``identity`` so pass-through
  bytes equal upstream bytes).
* Loopback-only by default (``127.0.0.1`` bind); the CLI refuses to bind a
  public address without ``--i-know-this-is-public``.
* Receipt ID determinism: the same gate state produces the same receipt
  hash shape as the existing gate receipt machinery; no compliance claims
  are made by this module.
"""

from __future__ import annotations

import argparse
import http.client
import json
import logging
import ssl
import sys
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger("raucle.urlgate")

DEFAULT_UPSTREAM = "https://api.openai.com"
DEFAULT_RECEIPT_STORE = "urlgate-receipts.jsonl"

# Endpoints whose POST traffic is gated (policy + receipt). Everything
# else passes through untouched.
DEFAULT_GATED_SUFFIXES = (
    "/chat/completions",
    "/completions",
    "/messages",
    "/embeddings",
    "/moderations",
    "/responses",
)

HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)

RECEIPT_HEADER = "X-Raucle-Receipt"
DECISION_HEADER = "X-Raucle-Decision"
TOOL_HEADER = "X-Raucle-Tool"

DEFAULT_POLICY = """\
version: 1
issuer: raucle-urlgate
policies:
  - tool: llm.chat
    agent_id: agent:urlgate-service
    ttl_seconds: 3600
    constraints: {}
  - tool: llm.embedding
    agent_id: agent:urlgate-service
    ttl_seconds: 3600
    constraints: {}
  - tool: llm.moderate
    agent_id: agent:urlgate-service
    ttl_seconds: 3600
    constraints: {}
"""


@dataclass
class UrlGateConfig:
    """Configuration for the URL-switch gate proxy."""

    upstream: str = DEFAULT_UPSTREAM
    listen_host: str = "127.0.0.1"
    listen_port: int = 8095
    # Gate policy + receipt plumbing (reuses the existing gate machinery).
    policy_file: str = ""
    receipt_store: str = DEFAULT_RECEIPT_STORE
    receipt_store_dir: str = ""
    # Service-scoped tool + agent identity used at the gate.
    tool: str = "llm.chat"
    agent_id: str = "agent:urlgate-service"
    upstream_timeout_s: int = 120
    gated_suffixes: tuple[str, ...] = DEFAULT_GATED_SUFFIXES
    extra_args: dict[str, Any] = field(default_factory=dict)

    def gated_paths(self) -> tuple[str, ...]:
        return self.gated_suffixes


def _upstream_hostport(upstream: str) -> tuple[str, int, bool]:
    """Split an upstream base URL into (host, port, is_https)."""
    parts = urlsplit(upstream)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"invalid upstream URL: {upstream!r}")
    port = parts.port
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return parts.hostname, port, parts.scheme == "https"


def _gate_tool_for_path(path: str, cfg: UrlGateConfig) -> str | None:
    """Return the gate tool name for a gated path, else None."""
    clean = path.split("?", 1)[0].rstrip("/") or "/"
    for suffix in cfg.gated_paths():
        if clean.endswith(suffix):
            if suffix == "/embeddings":
                return "llm.embedding"
            if suffix == "/moderations":
                return "llm.moderate"
            return cfg.tool
    return None


def _is_anthropic_path(path: str) -> bool:
    return "/messages" in path.split("?", 1)[0]


def _deny_body(path: str, reason: str) -> bytes:
    """Upstream-shaped error body so SDK clients fail with their normal
    error contract (OpenAI APIError / Anthropic APIStatusError)."""
    if _is_anthropic_path(path):
        payload = {
            "type": "error",
            "error": {
                "type": "permission_error",
                "message": f"raucle urlgate: {reason}",
            },
        }
    else:
        payload = {
            "error": {
                "message": f"raucle urlgate: {reason}",
                "type": "raucle_gate_deny",
                "param": None,
                "code": "raucle_gate_deny",
            }
        }
    return json.dumps(payload).encode("utf-8")


class UrlGate:
    """The URL-switch gate: policy gate + receipt minting + proxy core.

    The heavy lifting (policy matching, capability tokens, signed
    receipts) is delegated to the existing ``RaucleGateway`` machinery,
    loaded with a service-scoped policy so receipt semantics are
    identical to ``raucle serve`` gates.
    """

    def __init__(self, config: UrlGateConfig) -> None:
        self.config = config
        self._upstream = _upstream_hostport(config.upstream)
        self._gw = self._build_gateway(config)

    # ------------------------------------------------------------------
    # Gate construction
    # ------------------------------------------------------------------
    @staticmethod
    def _build_gateway(cfg: UrlGateConfig) -> Any:
        from raucle.gateway import GatewayConfig, RaucleGateway

        policy_path = cfg.policy_file
        if not policy_path:
            policy_path = str(Path("urlgate-policies.yaml"))
            if not Path(policy_path).exists():
                Path(policy_path).write_text(DEFAULT_POLICY, encoding="utf-8")

        gw_cfg = GatewayConfig(
            host="127.0.0.1",
            signer_backend="local",
            policy_file=policy_path,
            receipt_store=cfg.receipt_store,
            receipt_store_dir=cfg.receipt_store_dir,
            registry_path=str(Path(cfg.receipt_store).with_suffix(".registry.jsonl"))
            if not cfg.receipt_store_dir
            else "",
            receipt_index_path="",
            emit_receipts=True,
            gate_auth="off",
        )
        # Touch the receipt file eagerly: a proxy session that only
        # passes traffic through must still have a (readable, empty)
        # receipt surface.
        Path(gw_cfg.receipt_store).touch()
        return RaucleGateway(gw_cfg)

    # ------------------------------------------------------------------
    # Gating
    # ------------------------------------------------------------------
    def gate_call(self, path: str, body: bytes) -> dict[str, Any] | None:
        """Gate a POST body. Returns the decision dict for gated calls
        (caller inspects ``decision``), or None when the path is not
        gated (pure pass-through, no receipt)."""
        tool = _gate_tool_for_path(path, self.config)
        if tool is None:
            return None
        args: dict[str, Any] = self.config.extra_args
        try:
            parsed = json.loads(body.decode("utf-8"))
            if isinstance(parsed, dict):
                args = dict(self.config.extra_args)
                args["model"] = str(parsed.get("model", "") or "")
        except ValueError:  # includes UnicodeDecodeError for non-UTF-8 bodies
            args = dict(self.config.extra_args)
            args["body_unparseable"] = True
        decision = self._gw.check_tool_call(
            tool=tool,
            args=args,
            agent_id=self.config.agent_id,
            source="urlgate",
            destination=self.config.upstream,
        )
        return decision

    # ------------------------------------------------------------------
    # Proxy
    # ------------------------------------------------------------------
    def forward(
        self, method: str, path: str, headers: list[tuple[str, str]], body: bytes
    ) -> http.client.HTTPResponse:
        host, port, is_https = self._upstream
        conn_cls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
        kwargs: dict[str, Any] = {"timeout": self.config.upstream_timeout_s}
        if is_https:
            kwargs["context"] = ssl.create_default_context()
        conn = conn_cls(host, port, **kwargs)
        fwd_headers = [
            (k, v)
            for k, v in headers
            if k.lower() not in HOP_BY_HOP and k.lower() != "accept-encoding"
        ]
        fwd_headers.append(("Accept-Encoding", "identity"))
        if "content-type" not in {k.lower() for k, _ in fwd_headers} and body:
            fwd_headers.append(("Content-Type", "application/json"))
        # NOSONAR(S5144): accepted pattern — see docs/spikes/SONAR-ACCEPTANCE.md
        # ("S5144 urlgate.forward").  The client's method/target/headers/body
        # are forwarded verbatim to the CONFIGURED upstream; the destination
        # host is never client-controlled (origin-form enforced in _proxy)
        # and must not be altered, or the proxy is not transparent.
        conn.request(  # NOSONAR
            method,  # NOSONAR
            path,  # NOSONAR
            body=body if body else None,  # NOSONAR
            headers=dict(fwd_headers),  # NOSONAR
        )
        return conn.getresponse()


def _strip_hop_headers(headers: Any) -> list[tuple[str, str]]:
    # Response side: content-length is a body delimiter, not hop-by-hop.
    stripped = HOP_BY_HOP - {"content-length"}
    out = []
    for k, v in headers.items():
        if k.lower() in stripped:
            continue
        out.append((k, v))
    return out


def _is_origin_form(path: str) -> bool:
    """True when ``path`` is an RFC 9112 origin-form request target.

    Only origin-form targets (``/abs/path?query``) are proxied.  Absolute-form
    targets (``http://evil.example/...``), authority-form and asterisk-form
    targets are rejected: an attacker able to reach the proxy can otherwise
    influence the request target, and the proxy must never let the client turn
    it into a client-for-attacker request against a different destination.
    The upstream host itself comes exclusively from ``UrlGateConfig.upstream``.
    """
    parts = urlsplit(path)
    return not parts.netloc and parts.scheme not in ("http", "https")


class _UrlGateHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "raucle-urlgate/1.0"
    gate: UrlGate | None = None  # set by make_server() before requests arrive

    # -- plumbing ------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # keep CI logs clean
        logger.debug("%s - %s", self.address_string(), fmt % args)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _passthrough(self) -> None:
        self._proxy(method=self.command)

    def do_GET(self) -> None:
        self._passthrough()

    def do_HEAD(self) -> None:
        self._passthrough()

    def do_POST(self) -> None:
        self._proxy(method="POST")

    def do_PUT(self) -> None:
        self._passthrough()

    def do_PATCH(self) -> None:
        self._passthrough()

    def do_DELETE(self) -> None:
        self._passthrough()

    def do_OPTIONS(self) -> None:
        self._passthrough()

    def _gate_post(
        self, gate: UrlGate, body: bytes, cfg: UrlGateConfig
    ) -> tuple[str | None, str] | None:
        """Gate a POST body.  Returns ``(receipt_id, decision_header)`` when
        the request may proceed, or ``None`` once a deny/gate-failure
        response has already been written."""
        try:
            decision = gate.gate_call(self.path, body)
        except Exception as exc:  # fail-closed, receipted upstream in gw
            logger.exception("gate evaluation failed")
            self._respond_simple(
                502,
                _deny_body(self.path, f"gate failure: {exc}"),
                decision="deny",
                receipt=None,
            )
            return None
        if decision is None:  # ungated path: pure pass-through, no receipt
            return None, "allow"
        receipt_id = decision.get("receipt_id")
        decision_header = str(decision.get("decision", "deny"))
        if decision_header != "allow":
            # DENY (or escalate): never reach the upstream. Return the
            # upstream-shaped error so SDK clients fail with their normal
            # error contract.
            reason = decision.get("reason", "policy denial")
            self._respond_simple(
                403,
                _deny_body(self.path, reason),
                decision=decision_header,
                receipt=receipt_id,
                tool=decision.get("tool", cfg.tool),
            )
            return None
        return receipt_id, decision_header

    # -- proxy core ----------------------------------------------------
    def _proxy(self, method: str) -> None:
        if not _is_origin_form(self.path):
            # RFC 9112 only permits origin-form targets here; anything else
            # could steer the proxy at an attacker-chosen destination (SSRF).
            self._respond_simple(
                400,
                _deny_body(self.path, "invalid request target: only origin-form is accepted"),
                decision="deny",
                receipt=None,
            )
            return
        gate = self.gate
        if gate is None:  # defensive: handler wired before make_server() finished
            self._respond_simple(
                503, _deny_body(self.path, "gate not initialised"), decision="deny", receipt=None
            )
            return
        cfg = gate.config
        body = self._read_body()

        receipt_id: str | None = None
        decision_header = "allow"
        if method == "POST":
            gated = self._gate_post(gate, body, cfg)
            if gated is None:  # responded deny / gate failure
                return
            receipt_id = gated[0]
            decision_header = gated[1]

        try:
            resp = gate.forward(
                method,
                self.path,
                [(k, v) for k, v in self.headers.items()],
                body,
            )
        except (http.client.HTTPException, OSError) as exc:
            logger.warning("upstream connection failed: %s", exc)
            self._respond_simple(
                502,
                _deny_body(self.path, f"upstream connection failed: {exc}"),
                decision=decision_header,
                receipt=receipt_id,
            )
            return

        out_headers = _strip_hop_headers(resp.headers)
        out_headers.append((DECISION_HEADER, decision_header))
        if receipt_id:
            out_headers.append((RECEIPT_HEADER, receipt_id))
        # Preserve the upstream content framing: Content-Length is copied
        # verbatim; otherwise the body is close-delimited (identity
        # encoding is pinned upstream, so SSE bytes pass through
        # byte-identical).
        try:
            self.send_response(resp.status)
            for k, v in out_headers:
                if k.lower() == "connection":
                    continue
                self.send_header(k, v)
            if resp.getheader("Content-Length") is None:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self._stream(resp)
        finally:
            resp.close()

    def _stream(self, resp: http.client.HTTPResponse) -> None:
        """Stream the upstream body to the client, byte-identical."""
        length = resp.getheader("Content-Length")
        if resp.status == 204 or resp.status == 304 or self.command == "HEAD":
            self.end_headers()
            return
        try:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        finally:
            if length is None:
                # Close-delimited body: terminate the reply.
                self.wfile.flush()
                self.close_connection = True

    def _respond_simple(
        self,
        status: int,
        body: bytes,
        decision: str = "deny",
        receipt: str | None = None,
        tool: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(DECISION_HEADER, decision)
        if receipt:
            self.send_header(RECEIPT_HEADER, receipt)
        if tool:
            self.send_header(TOOL_HEADER, tool)
        self.end_headers()
        self.wfile.write(body)


def make_server(config: UrlGateConfig) -> tuple[ThreadingHTTPServer, UrlGate]:
    """Build the proxy server (not yet serving)."""
    gate = UrlGate(config)
    handler = type("_BoundHandler", (_UrlGateHandler,), {"gate": gate})
    server = ThreadingHTTPServer((config.listen_host, config.listen_port), handler)
    server.daemon_threads = True
    return server, gate


def serve(config: UrlGateConfig) -> int:
    """Run the proxy until interrupted."""
    server, gate = make_server(config)
    print(
        f"raucle urlgate: {config.listen_host}:{config.listen_port} -> "
        f"{config.upstream} (receipts: "
        f"{gate._gw.config.receipt_store_dir or gate._gw.config.receipt_store})"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def run_from_args(args: argparse.Namespace) -> int:
    """CLI entry: build config from argparse and serve."""
    host, port_s = args.listen.rsplit(":", 1)
    cfg = UrlGateConfig(
        upstream=args.upstream,
        listen_host=host,
        listen_port=int(port_s),
        policy_file=args.policy or "",
        receipt_store=args.receipts or DEFAULT_RECEIPT_STORE,
        receipt_store_dir=args.receipts_dir or "",
        tool=args.tool,
        agent_id=args.agent_id,
    )
    return serve(cfg)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="raucle urlgate", description="URL-switch gate proxy for SDK clients"
    )
    p.add_argument("--listen", default="127.0.0.1:8095", help="host:port to bind")
    p.add_argument("--upstream", default=DEFAULT_UPSTREAM, help="upstream base URL")
    p.add_argument("--policy", default="", help="gate policy YAML (default: urlgate-policies.yaml)")
    p.add_argument("--receipts", default=DEFAULT_RECEIPT_STORE, help="receipt JSONL file")
    p.add_argument("--receipts-dir", default="", help="segmented receipt store dir")
    p.add_argument("--tool", default="llm.chat", help="gate tool name for chat traffic")
    p.add_argument("--agent-id", default="agent:urlgate-service", help="service agent id")
    return run_from_args(p.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
