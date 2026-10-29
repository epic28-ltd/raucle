"""A2: delegation chain in audit rows.

Every gate decision - allow AND deny - must carry the delegated-authority
binding and the rule id that produced it, so the audit log answers
"who did what under which authority" without joining the receipt store.

Deferred to receipts v1.2 (A1 intent binding): hop index and intent
reference. The v1.1 authorization block already carries the chain id
(chain_digest), the delegate (capability_id) and the delegator (parent_id),
which is the complete chain binding available at decision time without a
receipt-format change.

Also pins the narrowing invariant: delegation narrows, never widens; a
minted grant with a permission set larger than its parent is unrepresentable
(the API refuses it and a runtime assertion holds the line for future
constraint types).
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from raucle.capability import CapabilityIssuer
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
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
def delegated_gateway(tmp_path):
    from raucle.capability import DelegationLedger

    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="test-admin-key",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    config.policy_file = tmp_path / "policies.yaml"
    config.policy_file.write_text(POLICY)
    config.gate_auth = "token"

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
    config.registry_path = str(tmp_path / "registry.jsonl")
    config.delegations_file = str(tmp_path / "delegations.jsonl")

    gw = RaucleGateway(config)
    client = TestClient(create_gateway_app(gw))
    return gw, client, root, child


def _gate(client, token, account):
    return client.post(
        "/gate",
        json={"tool": "lookup_balance", "args": {"account": account}, "agent_id": "agent:svc"},
        headers={"X-Capability-Token": json.dumps(token.to_dict())},
    )


def test_allow_and_deny_audit_rows_carry_chain_and_rule_id(delegated_gateway):
    gw, client, root, child = delegated_gateway

    ok = _gate(client, child, "ACC-001")
    assert ok.json()["decision"] == "allow"
    denied = _gate(client, child, "ACC-999")
    assert denied.json()["decision"] == "deny"
    assert denied.json()["receipt_id"]

    entries = gw.get_connections(limit=10)
    assert len(entries) >= 2, entries

    allow_row = next(e for e in entries if e["decision"] == "allow")
    deny_row = next(e for e in entries if e["decision"] == "deny")

    for row, label in ((allow_row, "allow"), (deny_row, "deny")):
        auth = row.get("authorization")
        assert auth, f"{label} audit row missing authorization: {row}"
        assert auth["capability_id"] == child.token_id, row
        assert auth["parent_id"] == root.token_id, row
        assert auth["attenuated"] is True, row
        assert auth["chain_digest"], row

    # The allow row carries the rule that produced it.
    assert allow_row.get("rule_id"), allow_row
    # The attributable deny carries NO rule id: the delegated authority
    # refused the call before policy evaluation, so the authority chain
    # (authorization block) is the complete why; the reason names it.
    assert "rule_id" not in deny_row, deny_row
    assert "delegated authority" in deny_row["reason"], deny_row

    assert deny_row["receipt_id"] == denied.json()["receipt_id"]

    # The allow receipt is self-describing: x_gate carries the rule id
    import base64

    lines = Path(gw.config.receipt_store).read_text().strip().splitlines()
    assert lines, "no receipts written"
    allow_env = None
    for ln in lines:
        candidate = json.loads(ln)
        seg = candidate["jws"].split(".")[1]
        seg += "=" * (-len(seg) % 4)
        if json.loads(base64.urlsafe_b64decode(seg))["x_gate"]["decision"] == "allow":
            allow_env = candidate
    assert allow_env, "no allow receipt in the store"
    seg = allow_env["jws"].split(".")[1]
    seg += "=" * (-len(seg) % 4)
    payload = json.loads(base64.urlsafe_b64decode(seg))
    assert payload["x_gate"]["rule_id"] == allow_row["rule_id"], payload["x_gate"]


def test_audit_row_authorization_absent_without_token(tmp_path):
    """A non-token call (auth off) logs no authorization block - the field
    is evidence of a chain, and there is none."""
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="test-admin-key",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )
    config.policy_file = tmp_path / "policies.yaml"
    config.policy_file.write_text(POLICY)
    config.gate_auth = "off"
    gw = RaucleGateway(config)
    client = TestClient(create_gateway_app(gw))
    resp = client.post("/gate", json={"tool": "lookup_balance", "args": {"account": "ACC-001"}})
    assert resp.json()["decision"] == "allow"
    entry = gw.get_connections(limit=1)[0]
    assert "authorization" not in entry, entry
    assert entry.get("rule_id"), entry


def test_delegation_narrows_never_widens():
    """The invariant, dimension by dimension: a child's effective permission
    set is a subset of its parent's, or the mint is refused outright."""
    issuer = CapabilityIssuer.generate(issuer="inv-issuer")
    parent = issuer.mint(
        agent_id="agent:billing",
        tool="lookup_balance",
        constraints={
            "allowed_values": {"account": ["ACC-001", "ACC-002"]},
            "forbidden_values": {"channel": ["social"]},
            "max_value": {"amount": 100},
            "min_value": {"risk": 10},
        },
        ttl_seconds=600,
    )

    child = issuer.attenuate(
        parent,
        extra_constraints={
            "allowed_values": {"account": ["ACC-001", "ACC-003"]},
            "forbidden_values": {"channel": ["social", "email"]},
            "max_value": {"amount": 50},
            "min_value": {"risk": 20},
        },
    )

    # allowed narrows to the intersection (a partially-out-of-parent request
    # narrows to what the parent covers - it can never grant more)
    assert set(child.constraints["allowed_values"]["account"]) == {"ACC-001"}
    assert set(child.constraints["allowed_values"]["account"]) <= set(
        parent.constraints["allowed_values"]["account"]
    )
    # forbidden only grows
    assert set(child.constraints["forbidden_values"]["channel"]) >= set(
        parent.constraints["forbidden_values"]["channel"]
    )
    # numeric bounds only tighten
    assert child.constraints["max_value"]["amount"] <= parent.constraints["max_value"]["amount"]
    assert child.constraints["min_value"]["risk"] >= parent.constraints["min_value"]["risk"]
    # same tool by construction (the API has no tool parameter to widen with)
    assert child.tool == parent.tool
    # ttl never extends
    assert child.expires_at <= parent.expires_at

    # widening agent ids are refused outright
    with pytest.raises(ValueError):
        issuer.attenuate(parent, narrower_agent_id="agent:other")
    with pytest.raises(ValueError):
        issuer.attenuate(parent, narrower_agent_id="agent:billing-evil")
    # ttl extension is refused
    with pytest.raises(ValueError):
        issuer.attenuate(parent, narrower_ttl_seconds=3600)


def test_widening_is_unrepresentable_at_runtime():
    """Defence-in-depth: the narrowing assertion refuses constraint sets
    that widen in any dimension, even if a future merge bug produced one."""
    from raucle.capability import _assert_narrowing

    parent = {
        "allowed_values": {"account": ["ACC-001", "ACC-002"]},
        "forbidden_values": {"channel": ["social"]},
        "max_value": {"amount": 100},
        "min_value": {"risk": 10},
    }
    # every widened dimension is refused with a named reason
    for widened in (
        {"allowed_values": {"account": ["ACC-001", "ACC-009"]}},
        {"forbidden_values": {"channel": []}},
        {"max_value": {"amount": 200}},
        {"min_value": {"risk": 5}},
    ):
        with pytest.raises(ValueError):
            _assert_narrowing(parent, widened)

    # a narrower-or-equal set passes
    _assert_narrowing(
        parent,
        {
            "allowed_values": {"account": ["ACC-001"]},
            "forbidden_values": {"channel": ["social", "email"]},
            "max_value": {"amount": 50},
            "min_value": {"risk": 20},
        },
    )
