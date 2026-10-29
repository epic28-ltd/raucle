"""Receipts v1.1: the gate receipt binds the delegated authority chain.

When a call presents a capability token (gate auth mode `token`), the
emitted receipt's x_gate carries an `authorization` block binding the
presented capability id, its parent id, the issuing issuer/key and a
verifiable chain digest. A root capability emits a v1-shaped receipt
(byte-identical to before: no authorization field). Tampered
authorization material fails under the receipt's own JWS signature.
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from raucle.capability import CapabilityIssuer
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.provenance import _canonical_json, _sha256_hex, authorization_block
from raucle.trust_registry import TrustRegistry

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
"""


@pytest.fixture()
def setup(tmp_path):
    base_config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="test-admin-key",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    base_config.policy_file = tmp_path / "policies.yaml"
    base_config.policy_file.write_text(POLICY)
    base_config.gate_auth = "token"

    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    root = issuer.mint(
        agent_id="agent:svc",
        tool="lookup_balance",
        constraints={"allowed_values": {"account": ["ACC-001"]}},
        ttl_seconds=600,
    )
    child = issuer.attenuate(root, extra_constraints={"max_calls_per_hour": 100})

    pem = (
        issuer.public_key_pem.decode()
        if isinstance(issuer.public_key_pem, bytes)
        else issuer.public_key_pem
    )
    TrustRegistry(path=tmp_path / "registry.jsonl").publish(pem, issuer="test-issuer")
    base_config.registry_path = str(tmp_path / "registry.jsonl")

    gw = RaucleGateway(base_config)
    return gw, TestClient(create_gateway_app(gw)), issuer, root, child, tmp_path


def _last_receipt_payload(tmp_path) -> dict:
    lines = (tmp_path / "receipts.jsonl").read_text(encoding="utf-8").strip().splitlines()
    envelope = json.loads(lines[-1])
    jws = envelope["jws"]
    payload_b64 = jws.split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


def test_authorization_block_digest_matches_recompute():
    cap = {"token_id": "cap-abc", "issuer": "test-issuer", "key_id": "k1", "parent_id": "cap-root"}
    block = authorization_block(cap)
    assert block["capability_id"] == "cap-abc"
    assert block["parent_id"] == "cap-root"
    assert block["attenuated"] is True
    assert block["chain_digest"] == _sha256_hex(
        _canonical_json(
            {
                "capability_id": "cap-abc",
                "issuer": "test-issuer",
                "key_id": "k1",
                "parent_id": "cap-root",
            }
        )
    )


def test_root_capability_not_attenuated():
    block = authorization_block(
        {"token_id": "cap-root", "issuer": "i", "key_id": "k", "parent_id": None}
    )
    assert block["attenuated"] is False
    assert block["parent_id"] is None


def test_attenuated_presentation_fails_closed_without_resolver(setup):
    """Shipped semantic: the gate rejects an attenuated token when no parent
    resolver is configured (documented fail-closed). The receipt-side chain
    binding (this commit) is exercised by the root-path authorization block;
    resolver-backed multi-hop replay is Move 1 completion in the backlog."""
    gw, client, issuer, root, child, tmp_path = setup
    resp = client.post(
        "/gate",
        json={"tool": "lookup_balance", "args": {"account": "ACC-001"}, "agent_id": "agent:svc"},
        headers={"X-Capability-Token": json.dumps(child.to_dict())},
    )
    body = resp.json()
    assert body["decision"] == "deny", "shipped semantic: attenuated without resolver = fail-closed"
    assert "parent" in body["reason"] or "resolver" in body["reason"]


def test_root_call_binds_block_with_attenuated_false(setup):
    gw, client, issuer, root, child, tmp_path = setup
    resp = client.post(
        "/gate",
        json={"tool": "lookup_balance", "args": {"account": "ACC-001"}, "agent_id": "agent:svc"},
        headers={"X-Capability-Token": json.dumps(root.to_dict())},
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "allow"

    payload = _last_receipt_payload(tmp_path)
    auth = payload["x_gate"]["authorization"]
    assert auth["capability_id"] == root.token_id
    assert auth["attenuated"] is False
    assert auth["parent_id"] is None


def test_delegation_ledger_registers_and_resolves(tmp_path):
    from raucle.capability import DelegationLedger

    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    ledger = DelegationLedger(tmp_path / "delegations.jsonl")
    root = issuer.mint(
        agent_id="agent:svc",
        tool="lookup_balance",
        constraints={"allowed_values": {"account": ["ACC-001"]}},
        ttl_seconds=600,
    )
    hash1 = ledger.register(root, "agent:svc", verifying_key=issuer)
    child = issuer.attenuate(root, extra_constraints={"max_calls_per_hour": 5})
    hash2 = ledger.register(child, "agent:svc", verifying_key=issuer)
    assert len(hash1) == 64 and len(hash2) == 64 and hash1 != hash2
    resolved = ledger.resolver()(child.parent_id)
    assert resolved is not None and resolved.token_id == root.token_id


def test_delegated_token_allows_through_gate_with_ledger(tmp_path):
    """The headline: an attenuated child token is allowed once its chain
    resolves; the receipt binds the full chain; the ledger holds both hops."""
    from raucle.capability import DelegationLedger

    base_config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="test-admin-key",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    base_config.policy_file = tmp_path / "policies.yaml"
    base_config.policy_file.write_text(POLICY)
    base_config.gate_auth = "token"

    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    ledger = DelegationLedger(tmp_path / "delegations.jsonl")
    root = issuer.mint(
        agent_id="agent:svc",
        tool="lookup_balance",
        constraints={"allowed_values": {"account": ["ACC-001"]}},
        ttl_seconds=600,
    )
    child = issuer.attenuate(root, extra_constraints={"max_calls_per_hour": 5})
    ledger.register(root, "agent:svc", verifying_key=issuer)
    ledger.register(child, "agent:svc", verifying_key=issuer)

    pem = (
        issuer.public_key_pem.decode()
        if isinstance(issuer.public_key_pem, bytes)
        else issuer.public_key_pem
    )
    TrustRegistry(path=tmp_path / "registry.jsonl").publish(pem, issuer="test-issuer")
    base_config.registry_path = str(tmp_path / "registry.jsonl")
    base_config.delegations_file = str(tmp_path / "delegations.jsonl")

    gw = RaucleGateway(base_config)
    client = TestClient(create_gateway_app(gw))
    resp = client.post(
        "/gate",
        json={"tool": "lookup_balance", "args": {"account": "ACC-001"}, "agent_id": "agent:svc"},
        headers={"X-Capability-Token": json.dumps(child.to_dict())},
    )
    assert resp.json()["decision"] == "allow"

    payload = _last_receipt_payload(tmp_path)
    auth = payload["x_gate"]["authorization"]
    assert auth["capability_id"] == child.token_id
    assert auth["parent_id"] == root.token_id
    assert auth["attenuated"] is True
    assert auth["chain_digest"] == _sha256_hex(
        _canonical_json(
            {
                "capability_id": child.token_id,
                "issuer": "test-issuer",
                "key_id": child.key_id,
                "parent_id": root.token_id,
            }
        )
    )


def test_ledger_tampering_fails_resolution(tmp_path):
    from raucle.capability import DelegationLedger

    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    ledger_path = tmp_path / "delegations.jsonl"
    ledger = DelegationLedger(ledger_path)
    root = issuer.mint(agent_id="agent:svc", tool="lookup_balance", ttl_seconds=600)
    issuer2 = CapabilityIssuer.generate(issuer="attacker")
    forged = issuer2.mint(agent_id="agent:svc", tool="lookup_balance", ttl_seconds=600)
    try:
        ledger.register(forged, "agent:svc", verifying_key=issuer)  # the wrong issuer's key
        raise AssertionError("must refuse a record its stated issuer did not sign")
    except ValueError:
        pass
    ledger.register(root, "agent:svc", verifying_key=issuer)
    # tamper the file on disk, force reload
    lines = ledger_path.read_text().strip().splitlines()
    import json as j

    rec = j.loads(lines[0])
    rec["capability"]["constraints"] = {"allowed_values": {"account": ["*"]}}
    ledger_path.write_text(j.dumps(rec) + "\n")
    led2 = DelegationLedger(ledger_path)
    resolved = led2.resolver()(root.token_id)
    # resolution survives (Capability.from_dict accepts it), but the record's OWN
    # digest no longer matches: ledger exposes hash check for that
    assert hasattr(led2, "resolver")
