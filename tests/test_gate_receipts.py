"""Gate receipt emission tests (PR-B Task B1).

The gate must emit a REAL signed provenance receipt for every decision -
allow, deny AND escalate - returned by /gate, verifiable offline with
ProvenanceVerifier, the CLI and the reference ports.
"""

import json

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.provenance import ProvenanceVerifier

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
    )


@pytest.fixture()
def gw(config, tmp_path):
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY)
    config.policy_file = str(policy)
    return RaucleGateway(config)


def _client(g):
    return TestClient(create_gateway_app(g))


class TestGateReceiptEmission:
    def test_allow_emits_receipt_with_id(self, gw):
        client = _client(gw)
        resp = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
        )
        body = resp.json()
        assert body["decision"] == "allow"
        assert body["receipt_id"]
        assert body["receipt_id"].startswith("sha256:")

    def test_deny_emits_receipt(self, gw):
        client = _client(gw)
        resp = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-999"},
                "agent_id": "agent:svc",
            },
        )
        body = resp.json()
        assert body["decision"] == "deny"
        assert body["receipt_id"].startswith("sha256:")

    def test_unknown_tool_deny_emits_receipt(self, gw):
        client = _client(gw)
        resp = client.post(
            "/gate", json={"tool": "no_such_tool", "args": {}, "agent_id": "agent:x"}
        )
        assert resp.json()["receipt_id"].startswith("sha256:")

    def test_escalate_emits_receipt(self, gw):
        client = _client(gw)
        resp = client.post(
            "/gate",
            json={
                "tool": "transfer_money",
                "args": {"from_account": "ACC-001", "amount": 500},
                "agent_id": "agent:pay",
            },
        )
        assert resp.json()["decision"] == "escalate"
        assert resp.json()["receipt_id"].startswith("sha256:")

    def test_receipt_verifies_with_provenance_verifier(self, gw, tmp_path):
        """The dogfood test: a gate receipt verifies with the standard
        verifier against the gateway identity's public key."""
        client = _client(gw)
        resp = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
        )
        receipt_id = resp.json()["receipt_id"]

        verifier = ProvenanceVerifier(
            public_keys={gw.gate_identity.key_id: gw.gate_identity.public_key_pem()}
        )
        report = verifier.verify_chain(gw.config.receipt_store)
        assert report.valid, report.errors
        # the receipt we handed out is IN the chain (tampered list is empty and
        # the count includes it: read the store and confirm by hash)
        import json as _json

        with open(gw.config.receipt_store, encoding="utf-8") as fh:
            hashes = [_json.loads(line)["receipt_hash"] for line in fh]
        assert receipt_id in hashes

    def test_receipt_content_binds_decision(self, gw):
        client = _client(gw)
        resp = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-999"},
                "agent_id": "agent:svc",
            },
        )
        receipt_id = resp.json()["receipt_id"]
        # read the receipt from the store, decode, check extension fields
        found = None
        with open(gw.config.receipt_store, encoding="utf-8") as fh:
            for line in fh:
                rec = json.loads(line)
                if rec["receipt_hash"] == receipt_id:
                    found = rec
                    break
        assert found, "receipt not found in store"
        import base64

        payload_b64 = found["jws"].split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        assert payload["guardrail_verdict"] == "deny"
        assert payload["x_gate"]["tool"] == "lookup_balance"
        assert payload["x_gate"]["agent_id"] == "agent:svc"
        assert payload["x_gate"]["reason"]

    def test_trace_id_threads_receipts(self, gw):
        """Receipts in the same trace share the trace extension; new trace
        gets a different one."""
        client = _client(gw)
        r1 = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
            headers={"X-Trace-Id": "trace-abc"},
        )
        r2 = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-002"},
                "agent_id": "agent:svc",
            },
            headers={"X-Trace-Id": "trace-abc"},
        )
        r3 = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
        )
        assert r1.json()["trace_id"] == "trace-abc"
        assert r2.json()["trace_id"] == "trace-abc"
        assert r3.json()["trace_id"] and r3.json()["trace_id"] != "trace-abc"

    def test_emit_receipts_false_disables(self, config, tmp_path):
        """emit_receipts=False restores pre-PR-B behaviour exactly."""
        policy = tmp_path / "policies.yaml"
        policy.write_text(POLICY)
        config.policy_file = str(policy)
        config.emit_receipts = False
        g = RaucleGateway(config)
        client = _client(g)
        resp = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
        )
        assert resp.json()["decision"] == "allow"
        assert resp.json()["receipt_id"] is None
        import os

        assert not os.path.exists(config.receipt_store)

    def test_restart_same_identity_same_chain(self, config, tmp_path):
        """Receipts from boot 1 verify at boot 2 (persistence contract)."""
        policy = tmp_path / "policies.yaml"
        policy.write_text(POLICY)
        config.policy_file = str(policy)
        gw1 = RaucleGateway(config)
        c1 = _client(gw1)
        c1.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
        )
        kid1 = gw1.gate_identity.key_id

        gw2 = RaucleGateway(config)
        assert gw2.gate_identity.key_id == kid1
        verifier = ProvenanceVerifier(
            public_keys={gw2.gate_identity.key_id: gw2.gate_identity.public_key_pem()}
        )
        report = verifier.verify_chain(config.receipt_store)
        assert report.valid, report.errors


class TestSegmentedStoreIntegration:
    """B2: the emitter writes through SegmentedReceiptStore when configured."""

    def test_receipts_landed_in_segments(self, tmp_path):
        from raucle.receipt_store import SegmentedReceiptStore

        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file="",
            receipt_store=str(tmp_path / "legacy.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            emit_receipts=True,
            receipt_store_dir=str(tmp_path / "segments"),
            receipt_segment_max_bytes=4096,
        )
        policy = tmp_path / "policies.yaml"
        policy.write_text(POLICY)
        config.policy_file = str(policy)
        gw = RaucleGateway(config)
        client = _client(gw)
        for account in ["ACC-001", "ACC-002", "ACC-001", "ACC-002"]:
            client.post(
                "/gate",
                json={
                    "tool": "lookup_balance",
                    "args": {"account": account},
                    "agent_id": "agent:svc",
                },
            )
        store = SegmentedReceiptStore(base_dir=tmp_path / "segments", max_segment_bytes=4096)
        assert store.total_receipt_count() == 4

    def test_segmented_receipts_verify(self, tmp_path):
        """Every receipt across segments verifies with ProvenanceVerifier."""

        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file="",
            receipt_store=str(tmp_path / "legacy.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            emit_receipts=True,
            receipt_store_dir=str(tmp_path / "segments"),
            receipt_segment_max_bytes=2048,
        )
        policy = tmp_path / "policies.yaml"
        policy.write_text(POLICY)
        config.policy_file = str(policy)
        gw = RaucleGateway(config)
        client = _client(gw)
        for i in range(30):
            client.post(
                "/gate",
                json={
                    "tool": "lookup_balance",
                    "args": {"account": "ACC-001"},
                    "agent_id": "agent:svc",
                },
                headers={"X-Trace-Id": f"t{i % 3}"},
            )
        # several segments created at 2048 bytes
        import glob

        segs = sorted(glob.glob(str(tmp_path / "segments" / "seg-*.jsonl")))
        assert len(segs) >= 2, f"expected rollover, got {len(segs)}"
        # each sealed segment is a verifiable chain
        verifier = ProvenanceVerifier(
            public_keys={gw.gate_identity.key_id: gw.gate_identity.public_key_pem()}
        )
        for seg in segs:
            report = verifier.verify_chain(seg)
            assert report.valid, (seg, report.errors)

    def test_trace_id_in_segmented_receipts(self, tmp_path):
        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file="",
            receipt_store=str(tmp_path / "legacy.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            emit_receipts=True,
            receipt_store_dir=str(tmp_path / "segments"),
        )
        policy = tmp_path / "policies.yaml"
        policy.write_text(POLICY)
        config.policy_file = str(policy)
        gw = RaucleGateway(config)
        client = _client(gw)
        client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
            headers={"X-Trace-Id": "trace-xyz"},
        )
        from raucle.receipt_store import SegmentedReceiptStore

        store = SegmentedReceiptStore(base_dir=tmp_path / "segments")
        recs = store.recent(limit=1)
        import base64 as _b64
        import json as _json

        payload = _json.loads(_b64.urlsafe_b64decode(recs[0]["jws"].split(".")[1] + "=="))
        assert payload["x_gate"]["trace_id"] == "trace-xyz"
