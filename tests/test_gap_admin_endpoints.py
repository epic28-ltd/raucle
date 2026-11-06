"""Admin-panel API sweep: drives the un-exercised admin endpoints end to end.

Complements tests/test_gateway.py: every admin route gets at least one call,
with a real gateway (learn mode on), a real policy file, and real credentials.
MFA is pre-enabled on the operator user so TOTP-gated routes are reachable
via the ``X-Totp`` header the panel uses.
"""

from __future__ import annotations

import json
import sys

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import (
    GatewayConfig,
    RaucleGateway,
    UserManager,
)
from raucle.gateway_app import create_admin_app, create_gateway_app

POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
"""


@pytest.fixture
def stack(tmp_path, monkeypatch) -> tuple[TestClient, RaucleGateway, str, str]:
    totp = pytest.importorskip("pyotp")
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    config = GatewayConfig(
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="admin-key",
        signer_backend="local",
        learn_mode=True,
        siem_enabled=True,
        siem_backend="splunk",
        siem_url="http://127.0.0.1:9",
        siem_token="tok",
    )
    gateway = RaucleGateway(config)
    users = UserManager()
    users.add_user("admin-key", "admin", "Admin")
    admin = users.get_user("admin-key")
    users.setup_mfa("admin-key")
    code = totp.TOTP(admin.totp_secret).now()
    app = create_admin_app(gateway, users)
    client = TestClient(app)
    return client, gateway, "admin-key", code


def _hdr(api_key: str, totp: str) -> dict:
    return {"Authorization": f"Bearer {api_key}", "X-Totp": totp}


def test_admin_sweeps_operator_endpoints(stack):
    client, gateway, key, code = stack
    h = _hdr(key, code)

    # policies: read, write, validate, reload
    r = client.get("/api/policies", headers=h)
    assert r.status_code == 200, r.text
    r = client.put(
        "/api/policies",
        headers=h,
        json={"content": POLICY.replace("ACC-001", "ACC-001", 1)},
    )
    assert r.status_code == 200, r.text
    r = client.post(
        "/api/policies/validate", headers=h, json={"content": "version: 1\nissuer: x\npolicies: []"}
    )
    assert r.status_code == 200, r.text
    r = client.post("/api/policies/reload", headers=h)
    assert r.status_code == 200, r.text

    # learn mode aggregate + clear (learn_mode on)
    gateway.check_tool_call(
        "unknown_tool", {"a": 1}, "agent:learner", source="", destination="", trace_id="t"
    )
    r = client.get("/api/learn/summary", headers=h)
    assert r.status_code == 200, r.text
    r = client.post("/api/learn/clear", headers=h)
    assert r.status_code == 200, r.text

    # approvals / activation lists
    assert client.get("/api/approvals", headers=h).status_code == 200
    assert client.get("/api/activation-requests", headers=h).status_code == 200
    assert client.get("/api/policy-ledger", headers=h).status_code == 200
    # learn draft endpoint
    assert client.get("/api/learn/draft", headers=h).status_code == 200

    # connections with filters (drives every filter branch)
    r = client.get(
        "/api/connections",
        headers=h,
        params={"tool": "nope", "decision": "DENY", "source": "s", "destination": "d"},
    )
    assert r.status_code == 200

    # receipts export (empty trail is fine)
    r = client.get("/api/receipts/export", headers=h)
    assert r.status_code == 200, r.text

    # stats + demo-key (demo key unconfigured -> 404)
    assert client.get("/api/stats", headers=h).status_code == 200
    assert client.get("/api/demo-key", headers=h).status_code == 404

    # siem config get + update
    r = client.get("/api/siem", headers=h)
    assert r.status_code == 200
    assert r.json()["backend"] == "splunk"
    r = client.put(
        "/api/siem",
        headers=h,
        json={"enabled": False, "backend": "elastic", "url": "", "token": ""},
    )
    assert r.status_code == 200, r.text

    # receipts query (empty trail is a valid page)
    r = client.get("/api/receipts", headers=h)
    assert r.status_code == 200, r.text

    # config read + write
    r = client.get("/api/config", headers=h)
    assert r.status_code == 200, r.text
    r = client.put("/api/config", headers=h, json={"host": "127.0.0.1"})
    assert r.status_code == 200, r.text


def test_admin_users_mfa_and_delete(stack):
    totp = pytest.importorskip("pyotp")
    client, _gateway, key, code = stack
    h = _hdr(key, code)
    assert (
        client.post(
            "/api/users", headers=h, json={"api_key": "op-2", "role": "operator", "name": "Op2"}
        ).status_code
        == 200
    )
    r = client.post("/api/users/op-2/mfa/setup", headers=h)
    assert r.status_code == 200, r.text
    assert "secret" in r.json(), r.text
    secret = r.json()["secret"]
    code2 = str(totp.TOTP(secret).now())
    r = client.post("/api/users/op-2/mfa/verify", headers=h, params={"code": code2})
    assert r.status_code == 200, r.text
    assert (
        client.post("/api/users/op-2/mfa/verify", headers=h, params={"code": ""}).status_code == 400
    )
    r = client.post("/api/users/op-2/mfa/disable", headers=h)
    assert r.status_code == 200
    assert r.json()["mfa_enabled"] is False
    assert client.delete("/api/users/ghost", headers=h).status_code == 404
    assert client.delete("/api/users/op-2", headers=h).status_code == 200


def test_health_token_enforced_on_both_apps(tmp_path, monkeypatch):
    pytest.importorskip("pyotp")
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    config = GatewayConfig(
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="admin-key",
        signer_backend="local",
        health_check_token="sekrit",
    )
    gateway = RaucleGateway(config)
    users = UserManager()
    users.add_user("admin-key", "admin", "Admin")
    ac = TestClient(create_admin_app(gateway, users))
    gc = TestClient(create_gateway_app(gateway))
    for client in (ac, gc):
        assert client.get("/health").status_code == 401
        assert client.get("/health", headers={"Authorization": "Bearer sekrit"}).status_code == 200


# ---------------------------------------------------------------------------
# gateway internals: splunk/elastic senders, audit log file, connections
# ---------------------------------------------------------------------------


def test_siem_forwarders_splunk_and_elastic(monkeypatch):
    sent = []

    class _FakeRequests:
        @staticmethod
        def post(url, data=None, headers=None, timeout=None, json=None):
            sent.append((url, headers, json))
            return None

    monkeypatch.setitem(sys.modules, "requests", _FakeRequests)
    for backend, url in (
        ("splunk", "http://hk.example/services/collector"),
        ("elastic", "http://es.example:9200/raucle"),
    ):
        config = GatewayConfig(
            siem_enabled=True, siem_backend=backend, siem_url=url, siem_token="tok"
        )
        from raucle.gateway import SIEMForwarder

        SIEMForwarder(config).forward({"decision": "ALLOW"})
    assert len(sent) == 2
    assert sent[0][2]["event"] == {"decision": "ALLOW"}
    assert sent[1][1]["Content-Type"] == "application/json"


def test_audit_log_file_persisted(tmp_path):
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    log_file = tmp_path / "audit.log"
    config = GatewayConfig(
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        audit_log_file=str(log_file),
        audit_persist=True,
        signer_backend="local",
    )
    gateway = RaucleGateway(config)
    gateway.check_tool_call(
        "lookup_balance",
        {"account": "ACC-001"},
        "agent:svc",
        source="s",
        destination="d",
        trace_id="t",
    )
    entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
    assert entries
    assert entries[-1]["tool"]


def test_get_connections_lists_gate_traffic(tmp_path):
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    config = GatewayConfig(
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        signer_backend="local",
    )
    gateway = RaucleGateway(config)
    gateway.check_tool_call(
        "lookup_balance",
        {"account": "ACC-001"},
        "agent:svc",
        source="agent-source",
        destination="d",
        trace_id="t",
    )
    conns = gateway.get_connections(limit=10)
    assert conns
    assert conns[-1]["tool"] == "lookup_balance"


def test_admin_live_pulse_on_admin_app(stack):
    client, _gateway, _key, _code = stack
    r = client.get("/api/live-pulse")
    assert r.status_code == 200
    assert "totals" in r.json()


def test_admin_panel_pages_render(stack):
    client, _gateway, _key, _code = stack
    r = client.get("/")
    assert r.status_code == 200
    assert "html" in r.text.lower()
    r = client.get("/topology")
    assert r.status_code == 200
    assert "html" in r.text.lower()


def test_gateway_app_health_and_gate_roundtrip(tmp_path):
    """The agent-facing app answers /health (no token configured) and /gate."""
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    config = GatewayConfig(
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        signer_backend="local",
    )
    gateway = RaucleGateway(config)
    client = TestClient(create_gateway_app(gateway))
    assert client.get("/health").status_code == 200
    r = client.post(
        "/gate",
        json={"tool": "lookup_balance", "args": {"account": "ACC-001"}, "agent_id": "agent:svc"},
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "allow"
