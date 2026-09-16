"""Receipt query + ancestry API tests (PR-C Tasks C2/C3)."""

import json

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import create_admin_app

POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-002"]
  - tool: send_email
    agent_id: agent:comms
    ttl_seconds: 60
    constraints:
      allow:
        recipient: ["ops@example.com"]
"""


@pytest.fixture()
def gw(tmp_path):
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY)
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file=str(policy),
        receipt_store=str(tmp_path / "flat.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "reg.jsonl"),
        emit_receipts=True,
        receipt_store_dir=str(tmp_path / "segs"),
        receipt_segment_max_bytes=1_000_000,
        receipt_index_path=str(tmp_path / "idx.sqlite"),
    )
    return RaucleGateway(config)


@pytest.fixture()
def admin(gw):
    users = UserManager()
    users.add_user("admin-key", "admin", "Admin")
    return TestClient(create_admin_app(gw, users))


AUTH = {"Authorization": "admin-key"}


def _gate(client_gw, tool, args, agent, trace=None):
    """Drive traffic through the gateway app's /gate."""
    from raucle.gateway_app import create_gateway_app

    gc = TestClient(create_gateway_app(client_gw))
    headers = {}
    if trace:
        headers["X-Trace-Id"] = trace
    return gc.post(
        "/gate", json={"tool": tool, "args": args, "agent_id": agent}, headers=headers
    ).json()


class TestReceiptQueryAPI:
    def test_query_all_newest_first(self, gw, admin):
        _gate(gw, "lookup_balance", {"account": "ACC-001"}, "agent:svc")
        _gate(gw, "send_email", {"recipient": "ops@example.com"}, "agent:comms")
        resp = admin.get("/api/receipts", headers=AUTH)
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 2
        assert body["total"] >= 2

    def test_filter_by_tool(self, gw, admin):
        _gate(gw, "lookup_balance", {"account": "ACC-001"}, "agent:svc")
        _gate(gw, "send_email", {"recipient": "ops@example.com"}, "agent:comms")
        resp = admin.get("/api/receipts", params={"tool": "lookup_balance"}, headers=AUTH)
        receipts = resp.json()["receipts"]
        assert len(receipts) == 1
        assert receipts[0]["tool"] == "lookup_balance"

    def test_filter_by_decision(self, gw, admin):
        _gate(gw, "lookup_balance", {"account": "ACC-001"}, "agent:svc")  # allow
        _gate(gw, "lookup_balance", {"account": "ACC-999"}, "agent:svc")  # deny
        resp = admin.get("/api/receipts", params={"decision": "deny"}, headers=AUTH)
        receipts = resp.json()["receipts"]
        assert len(receipts) == 1
        assert receipts[0]["decision"] == "deny"

    def test_filter_by_agent(self, gw, admin):
        _gate(gw, "lookup_balance", {"account": "ACC-001"}, "agent:svc")
        _gate(gw, "send_email", {"recipient": "ops@example.com"}, "agent:comms")
        resp = admin.get("/api/receipts", params={"agent_id": "agent:comms"}, headers=AUTH)
        receipts = resp.json()["receipts"]
        assert len(receipts) == 1
        assert receipts[0]["agent_id"] == "agent:comms"

    def test_filter_by_trace(self, gw, admin):
        _gate(gw, "lookup_balance", {"account": "ACC-001"}, "agent:svc", trace="tr-1")
        _gate(gw, "lookup_balance", {"account": "ACC-002"}, "agent:svc", trace="tr-2")
        _gate(gw, "lookup_balance", {"account": "ACC-001"}, "agent:svc", trace="tr-1")
        resp = admin.get("/api/receipts", params={"trace_id": "tr-1"}, headers=AUTH)
        assert len(resp.json()["receipts"]) == 2

    def test_cursor_pagination(self, gw, admin):
        for i in range(15):
            _gate(gw, "lookup_balance", {"account": "ACC-001"}, "agent:svc", trace=f"t{i}")
        r1 = admin.get("/api/receipts", params={"limit": 10}, headers=AUTH).json()
        assert r1["count"] == 10
        assert r1["next_cursor"] is not None
        r2 = admin.get(
            "/api/receipts", params={"limit": 10, "cursor": r1["next_cursor"]}, headers=AUTH
        ).json()
        hashes1 = {r["receipt_hash"] for r in r1["receipts"]}
        hashes2 = {r["receipt_hash"] for r in r2["receipts"]}
        assert not (hashes1 & hashes2)
        assert r2["count"] == 5

    def test_requires_auth(self, gw, admin):
        resp = admin.get("/api/receipts")
        assert resp.status_code == 401


class TestAncestryAPI:
    def test_ancestry_returns_nodes_edges(self, gw, admin):
        r = _gate(gw, "lookup_balance", {"account": "ACC-001"}, "agent:svc", trace="tr-a")
        resp = admin.get(f"/api/receipts/{r['receipt_id']}/ancestors", headers=AUTH)
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body["nodes"], list)
        assert isinstance(body["edges"], list)
        node_hashes = {n["receipt_hash"] for n in body["nodes"]}
        assert r["receipt_id"] in node_hashes

    def test_ancestry_requires_index(self, tmp_path, admin):
        # gateway without index -> 501
        from fastapi.testclient import TestClient as TC

        from raucle.gateway import GatewayConfig, RaucleGateway
        from raucle.gateway_app import create_admin_app

        policy = tmp_path / "p2.yaml"
        policy.write_text(POLICY)
        cfg = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file=str(policy),
            receipt_store=str(tmp_path / "f2.jsonl"),
            audit_chain=str(tmp_path / "a2.jsonl"),
            registry_path=str(tmp_path / "r2.jsonl"),
            emit_receipts=True,
            receipt_store_dir="",  # no store dir -> no index
        )
        gw2 = RaucleGateway(cfg)
        users = UserManager()
        users.add_user("admin-key", "admin", "A")
        client = TC(create_admin_app(gw2, users))
        resp = client.get("/api/receipts/sha256:x/ancestors", headers=AUTH)
        assert resp.status_code == 501


class TestExportAPI:
    def test_export_streams_receipts(self, gw, admin):
        _gate(gw, "lookup_balance", {"account": "ACC-001"}, "agent:svc")
        _gate(gw, "send_email", {"recipient": "ops@example.com"}, "agent:comms")
        resp = admin.get("/api/receipts/export", headers=AUTH)
        assert resp.status_code == 200
        assert "x-ndjson" in resp.headers.get("content-type", "")
        lines = [ln for ln in resp.text.splitlines() if ln.strip()]
        assert len(lines) == 2
        rec = json.loads(lines[0])
        assert {"receipt_hash", "jws"} <= set(rec.keys())

    def test_export_time_bounds(self, gw, admin):
        import time as _time

        before = int(_time.time()) - 10
        _gate(gw, "lookup_balance", {"account": "ACC-001"}, "agent:svc")
        after = int(_time.time()) + 10
        # window covering the receipt
        resp = admin.get(
            "/api/receipts/export", params={"since": before, "until": after}, headers=AUTH
        )
        lines = [ln for ln in resp.text.splitlines() if ln.strip()]
        assert len(lines) == 1
        # window excluding the receipt
        resp2 = admin.get("/api/receipts/export", params={"since": after}, headers=AUTH)
        lines2 = [ln for ln in resp2.text.splitlines() if ln.strip()]
        assert len(lines2) == 0

    def test_export_requires_auth(self, gw, admin):
        resp = admin.get("/api/receipts/export")
        assert resp.status_code == 401
