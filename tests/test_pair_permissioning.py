"""B1: agent+user pair permissioning.

The principal becomes the (agent, acting-for user) pair: a capability may
bind to a pair, the gate refuses a call whose declared acting-for user does
not match the token's (cross-pair use is attributable misuse), and receipts
record both halves of the pair. A delegated child inherits the pair and
may never re-target a different user.

OSS (this file): the pair in the token format, gate enforcement, receipt
fields. raucle-cloud: the per-pair policy resolution, adapter wiring and
the two-user demo (the §16.3 split).
"""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from raucle.capability import CapabilityGate, CapabilityIssuer, DelegationLedger
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


def test_token_carries_the_pair_conditionally():
    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    paired = issuer.mint(
        agent_id="agent:svc",
        tool="lookup_balance",
        acting_for="user:alice",
        ttl_seconds=600,
    )
    assert paired.acting_for == "user:alice"
    assert paired.body()["acting_for"] == "user:alice"

    # byte-compat: a token without a pair keeps the v1.1 body exactly
    plain = issuer.mint(agent_id="agent:svc", tool="lookup_balance", ttl_seconds=600)
    assert plain.acting_for == ""
    assert "acting_for" not in plain.body()


def test_gate_refuses_cross_pair_use():
    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    token = issuer.mint(
        agent_id="agent:svc",
        tool="lookup_balance",
        acting_for="user:alice",
        constraints={"allowed_values": {"account": ["ACC-001"]}},
        ttl_seconds=600,
    )
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})

    ok = gate.check(
        token,
        tool="lookup_balance",
        args={"account": "ACC-001"},
        agent_id="agent:svc",
        acting_for="user:alice",
    )
    assert ok.allowed, ok.reason

    # the same token used for a different user: cross-pair misuse, denied
    cross = gate.check(
        token,
        tool="lookup_balance",
        args={"account": "ACC-001"},
        agent_id="agent:svc",
        acting_for="user:mallory",
    )
    assert not cross.allowed
    assert cross.attributable
    assert "acting-for" in cross.reason, cross.reason

    # and when the call declares no user at all while the token is pair-bound
    unbound = gate.check(
        token, tool="lookup_balance", args={"account": "ACC-001"}, agent_id="agent:svc"
    )
    assert not unbound.allowed
    assert unbound.attributable


def test_attenuate_never_retargets_the_pair():
    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    # a pair-bound parent: the child cannot act for a different user
    parent = issuer.mint(
        agent_id="agent:svc", tool="lookup_balance", acting_for="user:alice", ttl_seconds=600
    )
    with pytest.raises(ValueError):
        issuer.attenuate(parent, acting_for="user:mallory")
    child = issuer.attenuate(parent)
    assert child.acting_for == "user:alice"

    # an unpaired parent: the child MAY narrow to a pair (setting a user
    # narrows the authority, it does not widen it)
    unpaired = issuer.mint(agent_id="agent:svc", tool="lookup_balance", ttl_seconds=600)
    narrowed = issuer.attenuate(unpaired, acting_for="user:alice")
    assert narrowed.acting_for == "user:alice"


def test_gateway_receipt_records_the_pair(tmp_path):
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
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
    config.delegations_file = str(tmp_path / "delegations.jsonl")

    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    ledger = DelegationLedger(tmp_path / "delegations.jsonl")
    token = issuer.mint(
        agent_id="agent:svc",
        tool="lookup_balance",
        acting_for="user:alice",
        ttl_seconds=600,
    )
    ledger.register(token, "agent:svc", verifying_key=issuer)
    pem = (
        issuer.public_key_pem.decode()
        if isinstance(issuer.public_key_pem, bytes)
        else issuer.public_key_pem
    )
    TrustRegistry(path=tmp_path / "registry.jsonl").publish(pem, issuer="test-issuer")

    gw = RaucleGateway(config)
    client = TestClient(create_gateway_app(gw))

    ok = client.post(
        "/gate",
        json={
            "tool": "lookup_balance",
            "args": {"account": "ACC-001"},
            "agent_id": "agent:svc",
            "acting_for": "user:alice",
        },
        headers={"X-Capability-Token": json.dumps(token.to_dict())},
    )
    assert ok.json()["decision"] == "allow", ok.json()

    envelope = json.loads((tmp_path / "receipts.jsonl").read_text().strip().splitlines()[-1])
    seg = envelope["jws"].split(".")[1]
    seg += "=" * (-len(seg) % 4)
    payload = json.loads(base64.urlsafe_b64decode(seg))
    assert payload["x_gate"]["acting_for"] == "user:alice"
    assert payload["x_gate"]["agent_id"] == "agent:svc"

    # cross-pair through the gateway: denied, attributable, receipted
    cross = client.post(
        "/gate",
        json={
            "tool": "lookup_balance",
            "args": {"account": "ACC-001"},
            "agent_id": "agent:svc",
            "acting_for": "user:mallory",
        },
        headers={"X-Capability-Token": json.dumps(token.to_dict())},
    )
    assert cross.json()["decision"] == "deny"
    assert "acting-for" in cross.json()["reason"]
    assert cross.json()["receipt_id"]
