"""RAU-04: SIEM forwarding DNS-based SSRF (RED-036).

``siem_target_allowed`` judged only literal addresses; a hostname that
RESOLVED into a private address passed validation and the forwarder
posted wherever DNS pointed. The fix validates every address the
resolution returns at validation time, and pins the connection at
connect time through the forwarder's pinned transport
(:mod:`raucle.siem_pinned`): the address dialed IS the address the
connect-time re-check validated, so a rebinding race between validation
and request cannot slip through. Every test here uses a monkeypatched
``resolve_siem_host`` - never a real network call - except the honest
public-path test, which drives a real loopback listener (the only
socket the forward path may touch in tests).
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from raucle.gateway import GatewayConfig, SIEMForwarder, siem_target_allowed


@pytest.fixture
def no_allow_private(monkeypatch):
    monkeypatch.delenv("RAUCLE_SIEM_ALLOW_PRIVATE", raising=False)


def _resolution(monkeypatch, answers: dict[str, list[str]], calls: list[str] | None = None):
    """Patch the pinned module's resolution seam (no real DNS anywhere)."""
    from raucle import siem_pinned

    def fake_resolve_siem_host(host: str) -> list[tuple[int, str]]:
        if calls is not None:
            calls.append(host)
        # one entry per A/AAAA record, in getaddrinfo order
        return [(socket.AF_INET, ip) for ip in answers[host]]

    monkeypatch.setattr(siem_pinned, "resolve_siem_host", fake_resolve_siem_host)
    return fake_resolve_siem_host


def _nx_domain(monkeypatch):
    from raucle import siem_pinned

    def refuse(host: str) -> list[tuple[int, str]]:
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(siem_pinned, "resolve_siem_host", refuse)


def _no_real_dial(monkeypatch):
    """Any attempt to open a real TCP connection aborts loudly (red lamp)."""

    def boom(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("a real socket dial was attempted during the test")

    import urllib3.util.connection as _u_conn_mod

    monkeypatch.setattr(_u_conn_mod, "create_connection", boom)


class TestSiemTargetDnsValidation:
    def test_hostname_resolving_internal_refused(self, monkeypatch, no_allow_private):
        _resolution(monkeypatch, {"collector.example.com": ["10.0.0.5"]})
        assert siem_target_allowed("https://collector.example.com:8088/services/collector") is False

    def test_multi_record_with_one_internal_refused(self, monkeypatch, no_allow_private):
        _resolution(
            monkeypatch,
            {"collector.example.com": ["93.184.216.34", "10.0.0.5", "93.184.216.35"]},
        )
        assert siem_target_allowed("https://collector.example.com/") is False

    def test_hostname_resolving_public_allowed(self, monkeypatch, no_allow_private):
        _resolution(monkeypatch, {"siem.example.com": ["93.184.216.34", "93.184.216.35"]})
        assert siem_target_allowed("https://siem.example.com:8088/") is True

    def test_unresolvable_target_refused_fail_closed(self, monkeypatch, no_allow_private):
        _nx_domain(monkeypatch)
        # a target that cannot resolve cannot be forwarded to; validation
        # refuses instead of letting the request-time resolution decide
        assert siem_target_allowed("https://gone.example.com/") is False

    def test_literal_targets_never_touch_dns(self, monkeypatch, no_allow_private):
        _nx_domain(monkeypatch)  # resolution absent entirely
        assert siem_target_allowed("http://10.0.0.5:8088/") is False
        assert siem_target_allowed("http://localhost:8088/") is False
        assert siem_target_allowed("http://93.184.216.34/") is True

    def test_allow_private_opt_in_skips_resolution(self, monkeypatch):
        _nx_domain(monkeypatch)
        monkeypatch.setenv("RAUCLE_SIEM_ALLOW_PRIVATE", "1")
        assert siem_target_allowed("https://collector.example.com/") is True


def _forwarder(tmp_path, backend: str = "splunk", url: str = "") -> SIEMForwarder:
    config = GatewayConfig(
        policy_file=str(tmp_path / "policies.yaml"),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        signer_key_path=str(tmp_path / "signer.pem"),
        gate_auth="off",
        signer_backend="local",
        siem_enabled=True,
        siem_backend=backend,
        siem_url=url,
    )
    return SIEMForwarder(config)


_EVENT = {
    "event": "gate_decision",
    "decision": "deny",
    "tool": "pay",
    "reason": "test case",
}


class TestConnectTimePinning:
    def test_rebinding_race_refused_at_connect(
        self, monkeypatch, tmp_path, no_allow_private, caplog
    ):
        """Validation sees a public address; the connect-time re-check sees
        the changed (internal) address and refuses: no request is issued
        and no socket is ever dialed."""
        calls: list[str] = []
        from raucle import siem_pinned

        def flapping(host: str) -> list[tuple[int, str]]:
            calls.append(host)
            if len(calls) == 1:
                return [(socket.AF_INET, "93.184.216.34")]
            return [(socket.AF_INET, "10.0.0.9")]

        monkeypatch.setattr(siem_pinned, "resolve_siem_host", flapping)
        _no_real_dial(monkeypatch)
        forwarder = _forwarder(tmp_path, url="http://collector.example.com:8088/")

        forwarder.forward(dict(_EVENT))
        assert len(forwarder._buffer) == 1, "the refused event is buffered for retry"
        assert len(calls) == 2, (
            "validation resolved public (call 1); the connect-time "
            "re-check resolved internal (call 2) and refused"
        )
        assert any("10.0.0.9" in rec.getMessage() for rec in caplog.records), (
            "the refusal naming the offending address reaches the log"
        )

    def test_public_path_forwards_unchanged_through_a_loopback_siem(self, monkeypatch, tmp_path):
        """The honest path: a public-resolving target is pinned and POSTed
        with the original name - Host header and body intact, no URL
        rewrite. Uses a real loopback listener (the one socket this suite
        touches) with resolution monkeypatched onto it."""
        seen = {"posts": []}

        class _RecordingHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server API
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                seen["posts"].append(
                    {
                        "path": self.path,
                        "host": self.headers.get("Host", ""),
                        "content_type": self.headers.get("Content-Type", ""),
                        "body": body,
                    }
                )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, format: str, *args) -> None:  # noqa: A002 - http.server API
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            _resolution(monkeypatch, {"collector.example.com": ["127.0.0.1"]})
            monkeypatch.setenv("RAUCLE_SIEM_ALLOW_PRIVATE", "1")
            forwarder = _forwarder(
                tmp_path, url=f"http://collector.example.com:{port}/services/collector"
            )
            original_url = forwarder.url
            forwarder.forward(dict(_EVENT))
            assert len(seen["posts"]) == 1
            post = seen["posts"][0]
            assert post["path"] == "/services/collector"
            assert post["host"].startswith("collector.example.com"), (
                "Host must preserve the operator's name, not the pinned address"
            )
            body = json.loads(post["body"])
            assert body["event"] == _EVENT
            assert body["sourcetype"] == "raucle:gate"
            assert forwarder.url == original_url, "no URL rewrite"
        finally:
            server.shutdown()
            server.server_close()

    def test_connect_time_multi_record_internal_refused(
        self, monkeypatch, tmp_path, no_allow_private
    ):
        """The connect re-check judges EVERY address, not just the first:
        this target resolves public on record one and internal on record
        two, so even first-record preference must refuse the dial."""
        from raucle import siem_pinned

        _resolution(
            monkeypatch,
            {"collector.example.com": ["93.184.216.34", "10.0.0.5"]},
        )
        _no_real_dial(monkeypatch)
        forwarder = _forwarder(tmp_path, url="http://collector.example.com/")
        # drive the transport directly (validation is bypassed; the forward
        # would refuse earlier): the pinned dial still refuses
        with pytest.raises(siem_pinned.SIEMTargetRefused) as exc:
            forwarder._pinned_session().post(
                "http://collector.example.com/", json=_EVENT, timeout=1
            )
        assert "10.0.0.5" in str(exc.value)


class TestPinnedSessionWiring:
    def test_forwarder_session_carries_the_pinned_adapter(self, tmp_path):
        forwarder = _forwarder(tmp_path, url="http://93.184.216.34/")
        session = forwarder._pinned_session()
        from raucle.siem_pinned import PinnedHTTPAdapter

        adapters = [a for a in session.adapters.values() if isinstance(a, PinnedHTTPAdapter)]
        assert adapters, f"no pinned adapter mounted: {list(session.adapters.values())}"

    def test_disabled_forwarder_never_builds_a_session(self, tmp_path):
        config = GatewayConfig(
            policy_file=str(tmp_path / "policies.yaml"),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            signer_key_path=str(tmp_path / "signer.pem"),
            gate_auth="off",
            signer_backend="local",
            siem_enabled=False,
        )
        forwarder = SIEMForwarder(config)
        forwarder.forward(dict(_EVENT))
        # disabled: the event is buffered and no session, no resolution
        assert forwarder._session is None
        assert forwarder._session_built is False
        assert len(forwarder._buffer) == 1
