"""Authority attribution features (PR-E): approval receipts, policy change
ledger, authority envelope, kill switch.

The Plexal Area 1 reading: establish which agent or process initiated an
action, the authority it held and what it could use. These tests pin the
"authority" leg of that sentence.
"""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
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
        account: ["ACC-001", "ACC-002"]
  - tool: transfer_money
    agent_id: agent:pay
    ttl_seconds: 300
    constraints:
      allow:
        from_account: ["ACC-001"]
    require_approval_when:
      amount_gt: 100
"""


@pytest.fixture()
def config(tmp_path):
    return GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        emit_receipts=True,
        gate_auth="apikey",
        agent_credentials_file=str(tmp_path / "creds.jsonl"),
        approval_ttl_seconds=120,
        policy_ledger_path=str(tmp_path / "policy-ledger.jsonl"),
    )


@pytest.fixture()
def gw(config, tmp_path):
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY)
    config.policy_file = str(policy)
    g = RaucleGateway(config)
    g._agent_creds.issue(agent_id="agent:pay")
    g._agent_creds.issue(agent_id="agent:svc")
    return g


@pytest.fixture()
def admin(gw):
    users = UserManager()
    users.add_user("admin-key", "admin", "Admin")
    users.add_user("operator-key", "operator", "Operator")
    return TestClient(create_admin_app(gw, users))


@pytest.fixture()
def gate(gw):
    return TestClient(create_gateway_app(gw))


def _pay_key(gw):
    # issue fresh key for a call (issue replaces the previous)
    return gw._agent_creds.issue(agent_id="agent:pay")


def _svc_key(gw):
    return gw._agent_creds.issue(agent_id="agent:svc")


def _decode_payload(jws: str) -> dict:
    parts = jws.split(".")
    padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _chain_records(gw):
    with open(gw.config.receipt_store, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


AUTH = {"Authorization": "admin-key"}
OP_AUTH = {"Authorization": "operator-key"}


class TestApprovalReceipts:
    def test_escalation_creates_approval_request(self, gw, gate):
        key = _pay_key(gw)
        resp = gate.post(
            "/gate",
            json={
                "tool": "transfer_money",
                "args": {"from_account": "ACC-001", "amount": 500},
                "agent_id": "agent:pay",
            },
            headers={"X-Api-Key": key},
        )
        body = resp.json()
        assert body["decision"] == "escalate"
        assert body["approval_request_id"]
        # the request receipt is in the chain with the approval extension
        recs = _chain_records(gw)
        req_recs = [
            r
            for r in recs
            if _decode_payload(r["jws"]).get("x_approval", {}).get("request_id")
            == body["approval_request_id"]
        ]
        assert req_recs, "no approval-request receipt in chain"
        payload = _decode_payload(req_recs[0]["jws"])
        assert payload["x_approval"]["tool"] == "transfer_money"
        assert payload["x_approval"]["agent_id"] == "agent:pay"
        assert payload["guardrail_verdict"] == "approval_requested"

    def test_full_approval_flow(self, gw, gate, admin):
        key = _pay_key(gw)
        r1 = gate.post(
            "/gate",
            json={
                "tool": "transfer_money",
                "args": {"from_account": "ACC-001", "amount": 500},
                "agent_id": "agent:pay",
            },
            headers={"X-Api-Key": key},
        )
        approval_id = r1.json()["approval_request_id"]

        # human approves through the admin API
        r2 = admin.post(
            f"/api/approvals/{approval_id}/decision",
            json={"approved": True},
            headers=AUTH,
        )
        assert r2.status_code == 200
        assert r2.json()["status"] == "approved"

        # the approval decision receipt is in the chain, naming the approver
        recs = _chain_records(gw)
        dec = [
            r
            for r in recs
            if _decode_payload(r["jws"]).get("x_approval", {}).get("request_id") == approval_id
            and _decode_payload(r["jws"]).get("guardrail_verdict") == "approval_granted"
        ]
        assert dec, "no approval-decision receipt"
        assert _decode_payload(dec[0]["jws"])["x_approval"]["approver"] == "Admin"

        # re-submit the SAME call with the approval reference
        r3 = gate.post(
            "/gate",
            json={
                "tool": "transfer_money",
                "args": {"from_account": "ACC-001", "amount": 500},
                "agent_id": "agent:pay",
            },
            headers={"X-Api-Key": key, "X-Approval-Id": approval_id},
        )
        assert r3.json()["decision"] == "allow"
        assert r3.json()["reason"].startswith("approved")

        # the action receipt cites the approval
        action = _chain_records(gw)[-1]
        payload = _decode_payload(action["jws"])
        assert payload["x_gate"]["approval_id"] == approval_id

    def test_approval_binds_exact_args(self, gw, gate, admin):
        key = _pay_key(gw)
        r1 = gate.post(
            "/gate",
            json={
                "tool": "transfer_money",
                "args": {"from_account": "ACC-001", "amount": 500},
                "agent_id": "agent:pay",
            },
            headers={"X-Api-Key": key},
        )
        approval_id = r1.json()["approval_request_id"]
        admin.post(f"/api/approvals/{approval_id}/decision", json={"approved": True}, headers=AUTH)
        # a DIFFERENT amount cannot ride the approval
        r2 = gate.post(
            "/gate",
            json={
                "tool": "transfer_money",
                "args": {"from_account": "ACC-001", "amount": 5000},
                "agent_id": "agent:pay",
            },
            headers={"X-Api-Key": key, "X-Approval-Id": approval_id},
        )
        assert r2.json()["decision"] == "deny"

    def test_approval_consumed_once(self, gw, gate, admin):
        key = _pay_key(gw)
        args = {
            "tool": "transfer_money",
            "args": {"from_account": "ACC-001", "amount": 500},
            "agent_id": "agent:pay",
        }
        r1 = gate.post("/gate", json=args, headers={"X-Api-Key": key})
        approval_id = r1.json()["approval_request_id"]
        admin.post(f"/api/approvals/{approval_id}/decision", json={"approved": True}, headers=AUTH)
        gate.post("/gate", json=args, headers={"X-Api-Key": key, "X-Approval-Id": approval_id})
        # second use: consumed
        r3 = gate.post("/gate", json=args, headers={"X-Api-Key": key, "X-Approval-Id": approval_id})
        assert r3.json()["decision"] == "deny"

    def test_approval_expiry(self, config, tmp_path, gate, admin):
        config.approval_ttl_seconds = 0  # immediate expiry
        policy = tmp_path / "policies.yaml"
        policy.write_text(POLICY)
        config.policy_file = str(policy)
        g = RaucleGateway(config)
        g._agent_creds.issue(agent_id="agent:pay")
        gt = TestClient(create_gateway_app(g))
        users = UserManager()
        users.add_user("admin-key", "admin", "Admin")
        ad = TestClient(create_admin_app(g, users))
        r1 = gt.post(
            "/gate",
            json={
                "tool": "transfer_money",
                "args": {"from_account": "ACC-001", "amount": 500},
                "agent_id": "agent:pay",
            },
            headers={"X-Api-Key": g._agent_creds.issue(agent_id="agent:pay")},
        )
        approval_id = r1.json()["approval_request_id"]
        import time as _time

        _time.sleep(0.05)
        r2 = ad.post(
            f"/api/approvals/{approval_id}/decision", json={"approved": True}, headers=AUTH
        )
        # expired requests cannot be decided (or are gone from pending)
        assert r2.status_code in (404, 410)

    def test_human_denial(self, gw, gate, admin):
        key = _pay_key(gw)
        args = {
            "tool": "transfer_money",
            "args": {"from_account": "ACC-001", "amount": 500},
            "agent_id": "agent:pay",
        }
        r1 = gate.post("/gate", json=args, headers={"X-Api-Key": key})
        approval_id = r1.json()["approval_request_id"]
        r2 = admin.post(
            f"/api/approvals/{approval_id}/decision", json={"approved": False}, headers=AUTH
        )
        assert r2.json()["status"] == "denied"
        r3 = gate.post("/gate", json=args, headers={"X-Api-Key": key, "X-Approval-Id": approval_id})
        assert r3.json()["decision"] == "deny"

    def test_pending_list(self, gw, gate, admin):
        key = _pay_key(gw)
        gate.post(
            "/gate",
            json={
                "tool": "transfer_money",
                "args": {"from_account": "ACC-001", "amount": 500},
                "agent_id": "agent:pay",
            },
            headers={"X-Api-Key": key},
        )
        pending = admin.get("/api/approvals", headers=AUTH).json()
        assert pending["count"] >= 1
        assert pending["approvals"][0]["tool"] == "transfer_money"

    def test_decision_receipt_written_on_deny_too(self, gw, gate, admin):
        key = _pay_key(gw)
        r1 = gate.post(
            "/gate",
            json={
                "tool": "transfer_money",
                "args": {"from_account": "ACC-001", "amount": 500},
                "agent_id": "agent:pay",
            },
            headers={"X-Api-Key": key},
        )
        approval_id = r1.json()["approval_request_id"]
        admin.post(f"/api/approvals/{approval_id}/decision", json={"approved": False}, headers=AUTH)
        recs = _chain_records(gw)
        deny_recs = [
            r
            for r in recs
            if _decode_payload(r["jws"]).get("x_approval", {}).get("request_id") == approval_id
            and _decode_payload(r["jws"]).get("guardrail_verdict") == "approval_denied"
        ]
        assert deny_recs


class TestPolicyChangeLedger:
    def test_policy_update_appends_ledger(self, gw, admin):
        new_policy = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-002", "ACC-003"]
"""
        resp = admin.put("/api/policies", json={"content": new_policy}, headers=AUTH)
        assert resp.status_code == 200
        ledger = admin.get("/api/policy-ledger", headers=AUTH).json()
        assert ledger["count"] >= 1
        entry = ledger["entries"][-1]
        assert entry["actor"] == "Admin"
        assert entry["action"] == "policy_updated"
        assert entry["sha256"]
        assert entry["prev_hash"]

    def test_ledger_detects_tampering(self, gw, admin):
        admin.put("/api/policies", json={"content": POLICY}, headers=AUTH)
        admin.put("/api/policies", json={"content": POLICY}, headers=OP_AUTH)
        # tamper: rewrite the last entry's actor
        from pathlib import Path as _Path

        path = _Path(gw.config.policy_ledger_path)
        lines = path.read_text().strip().splitlines()
        rec = json.loads(lines[-1])
        rec["actor"] = "ghost"
        lines[-1] = json.dumps(rec)
        path.write_text("\n".join(lines) + "\n")
        result = admin.get("/api/policy-ledger", headers=AUTH).json()
        assert result["integrity"]["valid"] is False

    def test_ledger_integrity_ok_when_untouched(self, gw, admin):
        admin.put("/api/policies", json={"content": POLICY}, headers=AUTH)
        result = admin.get("/api/policy-ledger", headers=AUTH).json()
        assert result["integrity"]["valid"] is True


class TestAuthorityEnvelope:
    def test_envelope_lists_authority(self, gw, admin):
        resp = admin.get("/api/agents/agent:pay/authority", headers=AUTH)
        assert resp.status_code == 200
        body = resp.json()
        assert body["envelope"]["agent_id"] == "agent:pay"
        tools = {p["tool"] for p in body["envelope"]["policies"]}
        assert "transfer_money" in tools
        assert body["envelope"]["credential"]["apikey_active"] is True
        # the envelope JWS payload IS the envelope (signed canonical)
        payload = _decode_payload(body["jws"])
        assert payload["agent_id"] == "agent:pay"
        assert payload["typ"] == "raucle/authority-envelope/v1"

    def test_envelope_unknown_agent(self, gw, admin):
        resp = admin.get("/api/agents/agent:nobody/authority", headers=AUTH)
        assert resp.status_code == 200
        body = resp.json()
        assert body["envelope"]["policies"] == []
        assert body["envelope"]["credential"]["apikey_active"] is False


class TestKillSwitch:
    def test_suspend_stops_agent(self, gw, gate, admin):
        key = _pay_key(gw)
        # agent can act before suspension (call fires; decision not asserted
        # here - the svc assertion below is the pre-suspension control)
        gate.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:pay",
            },
            headers={"X-Api-Key": key},
        )
        # (lookup policy is for agent:svc; pay gets denied here - use svc for act)
        svc_key = _svc_key(gw)
        r_before = gate.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
            headers={"X-Api-Key": svc_key},
        )
        assert r_before.json()["decision"] == "allow"

        resp = admin.post(
            "/api/agents/agent:svc/suspend", json={"reason": "incident test"}, headers=AUTH
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["suspended"] is True
        assert "apikey" in body["revoked"]
        assert body["receipt_id"].startswith("sha256:")

        # after suspension the credential is dead
        r_after = gate.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
            headers={"X-Api-Key": svc_key},
        )
        assert r_after.json()["decision"] == "deny"
        assert "invalid or revoked" in r_after.json()["reason"]

        # the stop receipt is in the chain with the reason and actor
        recs = _chain_records(gw)
        stops = [r for r in recs if _decode_payload(r["jws"]).get("x_stop")]
        assert stops
        stop_payload = _decode_payload(stops[-1]["jws"])
        assert stop_payload["x_stop"]["agent_id"] == "agent:svc"
        assert stop_payload["x_stop"]["reason"] == "incident test"
        assert stop_payload["x_stop"]["actor"] == "Admin"

    def test_suspend_requires_admin_role(self, gw, admin):
        resp = admin.post("/api/agents/agent:svc/suspend", json={"reason": "x"}, headers=OP_AUTH)
        assert resp.status_code == 403

    def test_suspend_without_credential_still_receipts(self, gw, admin):
        resp = admin.post(
            "/api/agents/agent:ghost/suspend", json={"reason": "precaution"}, headers=AUTH
        )
        assert resp.status_code == 200
        assert resp.json()["revoked"] == []
        assert resp.json()["receipt_id"]
