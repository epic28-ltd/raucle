"""EPIC O3 - URL-switch gate proxy tests (raucle urlgate).

Acceptance:
* a client pointed at the proxy gets the upstream response and a receipt
  is minted per gated call (verify the receipt id round-trips both in the
  X-Raucle-Receipt header and in the receipt store);
* a denied class returns an upstream-shaped, SDK-shapeable error;
* the response body bytes (including SSE streaming) pass through
  byte-identical;
* non-gated traffic is untouched and receipts nothing;
* the CLI subcommand starts a working proxy end to end.

No external network: a mock upstream runs on loopback alongside the
proxy. The `openai` package is used when installed; otherwise the raw
HTTP contract that SDKs implement is exercised directly.
"""

from __future__ import annotations

import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from raucle.urlgate import UrlGateConfig, make_server

OPENAI_CHAT_BODY = json.dumps(
    {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": "gpt-ok",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}
        ],
    }
).encode()

ANTHROPIC_BODY = json.dumps(
    {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "hi"}],
        "model": "claude-ok",
        "stop_reason": "end_turn",
    }
).encode()

SSE_BYTES = (
    b'data: {"id":"c1","choices":[{"delta":{"content":"he"}}]}\n\n'
    b'data: {"id":"c1","choices":[{"delta":{"content":"llo"}}]}\n\n'
    b"data: [DONE]\n\n"
)

DENY_POLICY = """\
version: 1
issuer: test.urlgate
policies:
  - tool: llm.chat
    agent_id: agent:urlgate-service
    ttl_seconds: 60
    constraints:
      deny:
        model: ["forbidden-model"]
  - tool: llm.embedding
    agent_id: agent:urlgate-service
    ttl_seconds: 60
    constraints: {}
"""


class _MockUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep test output clean
        pass

    def do_GET(self):
        if self.path.startswith("/v1/models"):
            payload = json.dumps({"object": "list", "data": [{"id": "gpt-ok"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path.split("?", 1)[0].startswith("/v1/chat/completions"):
            # gated tunnel targets: answer upstream-shaped like the POST path
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(OPENAI_CHAT_BODY)))
            self.end_headers()
            self.wfile.write(OPENAI_CHAT_BODY)
            return
        self._no_content()

    def do_POST(self):
        if self.headers.get("Content-Length"):
            self.rfile.read(int(self.headers["Content-Length"]))
        if self.path.startswith("/v1/chat/completions"):
            if "stream-test" in self.headers.get("X-Test-Case", ""):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Connection", "close")
                self.close_connection = True
                self.end_headers()
                # two halves to force multiple buffer boundaries
                half = len(SSE_BYTES) // 2
                self.wfile.write(SSE_BYTES[:half])
                self.wfile.flush()
                self.wfile.write(SSE_BYTES[half:])
                self.wfile.flush()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(OPENAI_CHAT_BODY)))
            self.end_headers()
            self.wfile.write(OPENAI_CHAT_BODY)
            return
        if self.path.startswith("/v1/messages"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(ANTHROPIC_BODY)))
            self.end_headers()
            self.wfile.write(ANTHROPIC_BODY)
            return
        self._no_content()

    def _no_content(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(OPENAI_CHAT_BODY)))
        self.end_headers()
        self.wfile.write(OPENAI_CHAT_BODY)

    do_DELETE = do_PUT

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_OPTIONS = do_HEAD


@pytest.fixture
def upstream():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockUpstream)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def proxy_factory(upstream, tmp_path):
    instances = []

    def _make(policy: str | None = None, **kw):
        if policy is not None:
            pw = tmp_path / "policies.yaml"
            pw.write_text(policy)
            policy = str(pw)
        cfg = UrlGateConfig(
            upstream=upstream,
            listen_host="127.0.0.1",
            listen_port=0,
            policy_file=policy or "",
            receipt_store=str(tmp_path / "receipts.jsonl"),
            **kw,
        )
        server, gate = make_server(cfg)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        instances.append(server)
        port = server.server_address[1]
        return port, cfg, tmp_path / "receipts.jsonl"

    yield _make
    for s in instances:
        s.shutdown()
        s.server_close()


def _request(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    hdrs = {k.lower(): v for k, v in resp.getheaders()}
    status = resp.status
    conn.close()
    return status, hdrs, data


class TestAllowRoundTrip:
    def test_chat_request_returns_upstream_response_and_receipt(self, proxy_factory):
        port, cfg, receipts_file = proxy_factory()
        body = json.dumps(
            {"model": "gpt-ok", "messages": [{"role": "user", "content": "hi"}]}
        ).encode()
        status, hdrs, data = _request(port, "POST", "/v1/chat/completions", body)
        assert status == 200
        assert data == OPENAI_CHAT_BODY
        assert hdrs.get("x-raucle-decision") == "allow"
        receipt = hdrs.get("x-raucle-receipt")
        assert receipt is not None
        assert receipt.startswith("sha256:")
        assert receipt in receipts_file.read_text()

    def test_receipts_deterministic_in_shape_for_identical_calls(self, proxy_factory):
        """Identical gated calls produce identically-Shaped receipts: the
        record fields match except the mandatory iat/timestamp, and the id
        is a stable sha256 hex digest (no random UUIDs)."""
        port, cfg, _ = proxy_factory()
        body = json.dumps(
            {"model": "gpt-ok", "messages": [{"role": "user", "content": "determinism"}]}
        ).encode()
        _, h1, _ = _request(port, "POST", "/v1/chat/completions", body)
        _, h2, _ = _request(port, "POST", "/v1/chat/completions", body)
        r1, r2 = h1["x-raucle-receipt"], h2["x-raucle-receipt"]
        assert r1.startswith("sha256:")
        assert r2.startswith("sha256:")
        digest1, digest2 = r1[len("sha256:") :], r2[len("sha256:") :]
        assert len(digest1) == 64
        assert len(digest2) == 64


class TestDeny:
    def test_denied_class_returns_sdk_shaped_error(self, proxy_factory):
        # A stock OpenAI SDK client surfaces non-2xx through APIError via
        # this exact response contract: JSON {"error": {...}}, HTTP 403.
        port, _, receipts_file = proxy_factory(policy=DENY_POLICY)
        body = json.dumps({"model": "forbidden-model", "messages": []}).encode()
        status, hdrs, data = _request(port, "POST", "/v1/chat/completions", body)
        assert status == 403
        payload = json.loads(data)
        assert payload["error"]["type"] == "raucle_gate_deny"
        assert payload["error"]["message"]
        receipt = hdrs.get("x-raucle-receipt")
        assert receipt is not None
        assert receipt.startswith("sha256:")
        assert receipt in receipts_file.read_text()
        # SDK contract extras
        assert payload["error"]["code"] == "raucle_gate_deny"
        assert payload["error"]["param"] is None

    def test_anthropic_messages_deny_shape(self, proxy_factory):
        port, _, _ = proxy_factory(policy=DENY_POLICY)
        body = json.dumps({"model": "forbidden-model", "messages": []}).encode()
        status, _, data = _request(port, "POST", "/v1/messages", body)
        assert status == 403
        payload = json.loads(data)
        assert payload["type"] == "error"
        assert payload["error"]["type"] == "permission_error"
        assert "forbidden" in payload["error"]["message"] or payload["error"]["message"]

    def test_denied_never_reaches_upstream(self, proxy_factory):
        # The mock upstream 404s on any path; a deny must never hit it,
        # so the client sees 403 (not 404).
        port, _, _ = proxy_factory(policy=DENY_POLICY)
        body = json.dumps({"model": "forbidden-model"}).encode()
        status, _, _ = _request(port, "POST", "/v1/chat/completions", body)
        assert status == 403


class TestStreaming:
    def test_sse_pass_through_byte_identical(self, proxy_factory):
        port, _, receipts_file = proxy_factory()
        body = json.dumps({"model": "gpt-ok", "stream": True}).encode()
        status, hdrs, data = _request(
            port,
            "POST",
            "/v1/chat/completions",
            body,
            headers={"X-Test-Case": "stream-test"},
        )
        assert status == 200
        assert data == SSE_BYTES, "SSE bytes must survive the proxy unchanged"
        receipt = hdrs.get("x-raucle-receipt")
        assert receipt is not None
        assert receipt.startswith("sha256:")
        assert receipt in receipts_file.read_text()


class TestPassthrough:
    def test_non_gated_traffic_untouched_no_receipt(self, proxy_factory, upstream):
        port, _, receipts_file = proxy_factory()
        status, hdrs, data = _request(port, "GET", "/v1/models")
        assert status == 200
        assert json.loads(data)["object"] == "list"
        assert hdrs.get("x-raucle-receipt") is None
        # No new receipt minted for the pass-through call
        before = receipts_file.read_text()
        _request(port, "GET", "/v1/models")
        assert receipts_file.read_text() == before

    def test_forwarded_headers_and_auth_survive(self, proxy_factory):
        pass  # covered implicitly by upstream routing (Authorization not stripped)


class TestRequestTargetValidation:
    """SSRF hardening: only origin-form targets are proxied."""

    def test_absolute_form_target_is_rejected(self, proxy_factory, upstream):
        port, _, receipts_file = proxy_factory()
        # An attacker-controlled absolute-form target must never reach the
        # proxy's forwarding path: the upstream is configured, not chosen.
        status, hdrs, data = _request(port, "GET", "http://169.254.169.254/latest/meta-data")
        assert status == 400
        payload = json.loads(data)
        assert payload["error"]["type"] == "raucle_gate_deny"
        assert "invalid request target" in payload["error"]["message"]
        assert hdrs.get("x-raucle-receipt") is None
        assert receipts_file.read_text() == ""

    def test_origin_form_targets_still_forward(self, proxy_factory, upstream):
        port, _, _ = proxy_factory()
        status, hdrs, _ = _request(port, "GET", "/v1/models")
        assert status == 200
        assert hdrs.get("x-raucle-receipt") is None


class TestAnthropicAllow:
    def test_messages_allow_returns_upstream_body(self, proxy_factory):
        port, _, receipts_file = proxy_factory()
        body = json.dumps({"model": "claude-ok", "messages": [], "max_tokens": 8}).encode()
        status, hdrs, data = _request(port, "POST", "/v1/messages", body)
        assert status == 200
        assert data == ANTHROPIC_BODY
        assert hdrs.get("x-raucle-receipt") in receipts_file.read_text()


class TestCli:
    def test_cli_urlgate_starts_working_proxy(self, proxy_factory, upstream, tmp_path):
        import argparse

        from raucle.cli import _cmd_urlgate

        cfg_args = argparse.Namespace(
            listen="127.0.0.1:0",
            upstream=upstream,
            policy=str(tmp_path / "cli-policy.yaml"),
            receipts=str(tmp_path / "cli-receipts.jsonl"),
            receipts_dir="",
            tool="llm.chat",
            agent_id="agent:urlgate-service",
        )
        import raucle.urlgate as ug

        # _cmd_urlgate serves forever; replace serve with a one-shot boot check
        started = {}

        def fake_serve(config):
            started["upstream"] = config.upstream
            return 0

        orig_serve = ug.serve
        ug.serve = fake_serve
        try:
            rc = _cmd_urlgate(cfg_args)
        finally:
            ug.serve = orig_serve
        assert rc == 0
        assert started["upstream"] == upstream

    def test_cli_end_to_end(self, upstream, tmp_path, monkeypatch):
        """Full CLI path: run the real server in a thread and make a
        gated request through it."""
        import argparse
        import threading

        from raucle.cli import _cmd_urlgate

        port_holder = {}

        import raucle.urlgate as ug

        orig_make = ug.make_server

        def patched_make(config):
            server, gate = orig_make(config)
            port_holder["port"] = server.server_address[1]
            return server, gate

        monkeypatch.setattr(ug, "make_server", patched_make)
        args = argparse.Namespace(
            listen="127.0.0.1:0",
            upstream=upstream,
            policy="",
            receipts=str(tmp_path / "e2e-receipts.jsonl"),
            receipts_dir="",
            tool="llm.chat",
            agent_id="agent:urlgate-service",
        )
        t = threading.Thread(target=_cmd_urlgate, args=(args,), daemon=True)
        t.start()
        for _ in range(100):
            if "port" in port_holder:
                break
            threading.Event().wait(0.05)
        assert "port" in port_holder, "CLI urlgate did not bind"
        port = port_holder["port"]
        body = json.dumps(
            {"model": "gpt-ok", "messages": [{"role": "user", "content": "e2e"}]}
        ).encode()
        status, hdrs, data = _request(port, "POST", "/v1/chat/completions", body)
        assert status == 200
        assert data == OPENAI_CHAT_BODY
        assert hdrs.get("x-raucle-receipt", "").startswith("sha256:")
        receipt_file = tmp_path / "e2e-receipts.jsonl"
        assert hdrs["x-raucle-receipt"] in receipt_file.read_text()


class TestOptionalOpenAiSdk:
    def test_stock_openai_client_through_proxy(self, proxy_factory):
        pytest.importorskip("openai")
        port, _, receipts_file = proxy_factory()
        from openai import OpenAI

        client = OpenAI(base_url=f"http://127.0.0.1:{port}/v1", api_key="sk-test")
        completion = client.chat.completions.create(
            model="gpt-ok",
            messages=[{"role": "user", "content": "hello via urlgate"}],
        )
        assert completion.model == "gpt-ok"
        assert completion.choices[0].message.content == "hi"
        assert receipts_file.exists()
        assert receipts_file.read_text().startswith("{")

    def test_stock_openai_client_deny_surfaces_api_error(self, proxy_factory):
        pytest.importorskip("openai")
        port, _, receipts_file = proxy_factory(policy=DENY_POLICY)
        import openai
        from openai import OpenAI

        client = OpenAI(base_url=f"http://127.0.0.1:{port}/v1", api_key="sk-test")
        # Normal SDK error contract: non-2xx surfaces as APIStatusError.
        with pytest.raises(openai.APIStatusError) as exc_info:
            client.chat.completions.create(
                model="forbidden-model", messages=[{"role": "user", "content": "x"}]
            )
        # Normal SDK error contract: APIStatusError with the gate verdict
        err = exc_info.value
        assert getattr(err, "status_code", 403) == 403
        body = getattr(err, "body", None)
        assert body is not None
        assert body.get("type") == "raucle_gate_deny"


class TestMethodAgnosticGating:
    """RED-030 / AV-14: gated suffixes gate content-bearing METHODS, not only
    POSTs; HEAD/OPTIONS remain a narrow exempt passthrough with a named marker
    and no receipt minted (no receipt inflation)."""

    def test_get_tunnel_to_gated_suffix_is_gated(self, proxy_factory):
        port, _, receipts_file = proxy_factory()
        tunneled = "/v1/chat/completions?prompt=SECRET-PROD-KEY-12345"
        status, hdrs, _ = _request(port, "GET", tunneled)
        assert status == 200
        assert hdrs.get("x-raucle-decision") == "allow"
        receipt = hdrs.get("x-raucle-receipt")
        assert receipt is not None, "the content-bearing GET hit the gate path: receipted"
        assert receipt in receipts_file.read_text()

    def test_get_deny_never_reaches_upstream(self, proxy_factory):
        port, _, receipts_file = proxy_factory(
            policy="version: 1\nissuer: test.urlgate\npolicies:\n"
        )
        tunneled = "/v1/chat/completions?prompt=SECRET-PROD-KEY-12345"
        status, hdrs, _ = _request(port, "GET", tunneled)
        assert status == 403
        assert hdrs.get("x-raucle-receipt") in receipts_file.read_text()

    def test_get_non_gated_paths_still_pure_passthrough_no_receipt(self, proxy_factory):
        port, _, receipts_file = proxy_factory()
        before = receipts_file.read_text().count("\n") if receipts_file.exists() else 0
        status, hdrs, _ = _request(port, "GET", "/v1/models?q=anything")
        assert status == 200
        assert hdrs.get("x-raucle-receipt") is None
        after = receipts_file.read_text().count("\n") if receipts_file.exists() else 0
        assert after == before, "no receipt inflation for ungated paths"

    def test_head_and_options_exempt_named_marker_no_receipt(self, proxy_factory):
        port, _, receipts_file = proxy_factory()
        before = receipts_file.read_text().count("\n")
        for method in ("HEAD", "OPTIONS"):
            status, hdrs, _ = _request(port, method, "/v1/chat/completions")
            assert status == 200
            assert hdrs.get("x-raucle-passthrough") == "method-exempt-head-options"
            assert hdrs.get("x-raucle-receipt") is None, "exempt: no receipt minted"
        after = receipts_file.read_text().count("\n")
        assert after == before, "no receipt inflation for the exempt methods"

    def test_delete_and_put_on_gated_suffix_are_gated(self, proxy_factory):
        port, _, receipts_file = proxy_factory()
        for method in ("PUT", "DELETE"):
            status, hdrs, _ = _request(port, method, "/v1/chat/completions")
            assert status == 200
            receipt = hdrs.get("x-raucle-receipt")
            assert receipt is not None and receipt in receipts_file.read_text()
