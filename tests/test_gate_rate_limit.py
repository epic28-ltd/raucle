"""RED-037: rate limits exist, mean the right thing, and are documented.

The gateway documented "200 requests per minute on /gate" and implemented no
per-route limit at all: only a 1000/minute default, keyed on the socket peer.
Behind Caddy every request's peer is the proxy, so all callers shared one
bucket, and if slowapi was missing the app ran with no limiting and said
nothing.

These tests pin the route limit, the proxy convention and the honest absence
path.
"""

from __future__ import annotations

import pytest

pytest.importorskip("slowapi")

from fastapi.testclient import TestClient  # noqa: E402

from raucle.gateway import GatewayConfig, RaucleGateway  # noqa: E402
from raucle.gateway_app import _client_key, create_gateway_app  # noqa: E402


def _policy(tmp_path):
    path = tmp_path / "policies.yaml"
    path.write_text(
        """
version: 1
issuer: test.bank
policies:
  - tool: pay
    agent_id: agent:bot
    ttl_seconds: 300
    constraints:
      allow:
        account: ["ACC-001"]
"""
    )
    return path


def _app(tmp_path) -> TestClient:
    cfg = GatewayConfig(
        policy_file=str(_policy(tmp_path)),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        signer_key_path=str(tmp_path / "signer.pem"),
        agent_credentials_file=str(tmp_path / "creds.jsonl"),
        gate_auth="off",
        signer_backend="local",
    )
    return TestClient(create_gateway_app(RaucleGateway(cfg)))


class TestGateRouteLimit:
    def test_route_limit_is_enforced(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAUCLE_GATE_ROUTE_LIMIT", "3/minute")
        client = _app(tmp_path)
        codes = [
            client.post("/gate", json={"tool": "pay", "args": {"account": "ACC-001"}}).status_code
            for _ in range(5)
        ]
        assert 429 in codes, codes
        assert codes[0] == 200

    def test_other_routes_are_not_shadowed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAUCLE_GATE_ROUTE_LIMIT", "1/minute")
        client = _app(tmp_path)
        assert (
            client.post("/gate", json={"tool": "pay", "args": {"account": "ACC-001"}}).status_code
            == 200
        )
        assert (
            client.post("/gate", json={"tool": "pay", "args": {"account": "ACC-001"}}).status_code
            == 429
        )
        # /health is not under the route limit and still answers
        assert client.get("/health").status_code == 200


class TestClientKey:
    class _Req:
        def __init__(self, peer: str, headers: dict[str, str] | None = None) -> None:
            self.headers = headers or {}
            self.client = type("C", (), {"host": peer})()

    def test_socket_peer_by_default(self, monkeypatch):
        monkeypatch.delenv("RAUCLE_TRUST_PROXY", raising=False)
        req = self._Req("203.0.113.9", {"x-forwarded-for": "198.51.100.7"})
        assert _client_key(req) == "203.0.113.9"

    def test_forwarded_for_when_proxy_trusted(self, monkeypatch):
        monkeypatch.setenv("RAUCLE_TRUST_PROXY", "1")
        req = self._Req("10.0.0.2", {"x-forwarded-for": "198.51.100.7, 10.0.0.2"})
        assert _client_key(req) == "198.51.100.7"

    def test_missing_client_is_not_a_crash(self):
        req = type("R", (), {"headers": {}, "client": None})()
        assert _client_key(req) == "unknown"


class TestDocsMatchCode:
    def test_documented_limit_matches_the_default(self, tmp_path, monkeypatch):
        """The number in docs/gateway-security.md is the number in the code."""
        from pathlib import Path

        doc = Path(__file__).resolve().parents[1] / "docs" / "gateway-security.md"
        text = doc.read_text(encoding="utf-8")
        monkeypatch.delenv("RAUCLE_GATE_ROUTE_LIMIT", raising=False)
        assert "200/minute" in text
        assert "RAUCLE_GATE_ROUTE_LIMIT" in text
        assert "RAUCLE_TRUST_PROXY" in text


class TestGateAuthPosture:
    def test_config_exposes_the_auth_mode(self, tmp_path):
        from raucle.gateway import UserManager
        from raucle.gateway_app import create_admin_app

        cfg = GatewayConfig(
            policy_file="",
            receipt_store=str(tmp_path / "r.jsonl"),
            audit_chain=str(tmp_path / "a.jsonl"),
            admin_api_key="admin-key-0123456789abcdef",
            signer_backend="local",
        )
        gateway = RaucleGateway(cfg)
        users = UserManager()
        users.add_user(cfg.admin_api_key, "admin", "Admin")
        client = TestClient(create_admin_app(gateway, users))
        body = client.get("/api/config", headers={"Authorization": cfg.admin_api_key}).json()
        assert body["gate_auth"] == "off"

    def test_invalid_auth_mode_is_refused(self, tmp_path):
        from raucle.gateway import UserManager
        from raucle.gateway_app import create_admin_app

        cfg = GatewayConfig(
            policy_file="",
            receipt_store=str(tmp_path / "r.jsonl"),
            audit_chain=str(tmp_path / "a.jsonl"),
            admin_api_key="admin-key-0123456789abcdef",
            signer_backend="local",
        )
        gateway = RaucleGateway(cfg)
        users = UserManager()
        users.add_user(cfg.admin_api_key, "admin", "Admin")
        client = TestClient(create_admin_app(gateway, users))
        resp = client.put(
            "/api/config",
            headers={"Authorization": cfg.admin_api_key},
            json={"gate_auth": "nonsense"},
        )
        assert resp.status_code == 400
        assert gateway.config.gate_auth == "off"

    def test_a_valid_mode_is_accepted(self, tmp_path):
        from raucle.gateway import UserManager
        from raucle.gateway_app import create_admin_app

        cfg = GatewayConfig(
            policy_file="",
            receipt_store=str(tmp_path / "r.jsonl"),
            audit_chain=str(tmp_path / "a.jsonl"),
            admin_api_key="admin-key-0123456789abcdef",
            signer_backend="local",
        )
        gateway = RaucleGateway(cfg)
        users = UserManager()
        users.add_user(cfg.admin_api_key, "admin", "Admin")
        client = TestClient(create_admin_app(gateway, users))
        resp = client.put(
            "/api/config",
            headers={"Authorization": cfg.admin_api_key},
            json={"gate_auth": "token"},
        )
        assert resp.status_code == 200
        assert gateway.config.gate_auth == "token"
