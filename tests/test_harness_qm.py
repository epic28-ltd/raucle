"""QM harness adapter tests (Move 3): hand-off, gate, wiring."""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from raucle.capability import CapabilityIssuer, DelegationLedger
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.integrations.qm import QmHarnessBridge, wiring
from raucle.provenance import _canonical_json, _sha256_hex
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
def bridge(tmp_path):
    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    ledger = DelegationLedger(tmp_path / "delegations.jsonl")
    return (
        QmHarnessBridge(issuer, ledger, gateway_url="http://raucle-gateway:8080"),
        issuer,
        tmp_path,
    )


def test_mint_for_task_root_and_chain(bridge):
    b, _issuer, tmp = bridge
    root_tok = b.mint_for_task(
        tool="lookup_balance",
        agent_id="agent:svc",
        constraints={"allowed_values": {"account": ["ACC-001"]}},
    )
    child_tok = b.mint_for_task(
        tool="lookup_balance",
        agent_id="agent:svc",
        parent=type("C", (), {})()
        if False
        else _as_cap(child_from_ledger(tmp, root_tok["token_id"])),
    )
    assert child_tok["parent_id"] == root_tok["token_id"]
    # ledger holds both hops
    res = b.ledger.resolver()
    assert res(child_tok["token_id"]) is not None
    assert res(child_tok["parent_id"]).token_id == root_tok["token_id"]
    # the authorization digest the gate will bind, recomputed locally
    auth = b.authorization_from(child_tok)
    assert auth["chain_digest"] == _sha256_hex(
        _canonical_json(
            {
                "capability_id": child_tok["token_id"],
                "issuer": "test-issuer",
                "key_id": child_tok["key_id"],
                "parent_id": root_tok["token_id"],
            }
        )
    )


def child_from_ledger(tmp, root_id):
    """Resolve the root token from the ledger, then re-mint through the bridge
    parent path: helper returns a Capability."""
    from raucle.capability import DelegationLedger

    led = DelegationLedger(tmp / "delegations.jsonl")
    return led.resolver()(root_id)


def _as_cap(cap):
    return cap


def test_gate_call_via_testclient(bridge):
    b, issuer, tmp = bridge
    base_config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp / "receipts.jsonl"),
        audit_chain=str(tmp / "audit.jsonl"),
        registry_path=str(tmp / "registry.jsonl"),
        agent_credentials_file=str(tmp / "agent-credentials.jsonl"),
    )
    base_config.policy_file = tmp / "policies.yaml"
    base_config.policy_file.write_text(POLICY)
    base_config.gate_auth = "token"
    root_tok = b.mint_for_task(
        tool="lookup_balance",
        agent_id="agent:svc",
        constraints={"allowed_values": {"account": ["ACC-001"]}},
    )
    child_tok = b.mint_for_task(
        tool="lookup_balance",
        agent_id="agent:svc",
        parent=child_from_ledger(tmp, root_tok["token_id"]),
        constraints={"max_calls_per_hour": 50},
    )
    pem = (
        issuer.public_key_pem.decode()
        if isinstance(issuer.public_key_pem, bytes)
        else issuer.public_key_pem
    )
    TrustRegistry(path=tmp / "registry.jsonl").publish(pem, issuer="test-issuer")
    base_config.registry_path = str(tmp / "registry.jsonl")
    base_config.delegations_file = str(tmp / "delegations.jsonl")
    gw = RaucleGateway(base_config)
    client = TestClient(create_gateway_app(gw))
    resp = client.post(
        "/gate",
        json={
            "tool": "lookup_balance",
            "args": {"account": "ACC-001"},
            "agent_id": "agent:svc",
        },
        headers=b.gate_headers(child_tok),
    )
    body = resp.json()
    assert body["decision"] == "allow", body
    # the receipt binds the chain (v1.1)
    lines = (tmp / "receipts.jsonl").read_text().strip().splitlines()
    env = json.loads(lines[-1])
    p = env["jws"].split(".")[1]
    p += "=" * (-len(p) % 4)
    payload = json.loads(base64.urlsafe_b64decode(p))
    assert payload["x_gate"]["authorization"]["capability_id"] == child_tok["token_id"]
    assert payload["x_gate"]["authorization"]["attenuated"] is True


def test_wiring_bundle_shape(bridge):
    b, _issuer, _tmp = bridge
    w = json.loads(
        wiring(
            b,
            ledger_path="/data/delegations.jsonl",
            receipt_store="/data/receipts.jsonl",
        )
    )
    assert w["capability_header"] == "X-Capability-Token"
    assert w["receipts"]["version"] == "v1.1"
    assert "unresolved_parent" in w["fail_closed_on"]
