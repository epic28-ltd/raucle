"""A3: cascade revocation with evidence.

Revoking a chain hop invalidates its whole subtree: the gate refuses new
actions (per-call revocation reload), the revocation itself is a signed,
attributable receipt so a third party can verify revoked-by-whom-when-
which-subtree offline, and the verifier marks every receipt minted after a
revocation of its cited authority as invalid (revoked-at-H). Receipts
minted BEFORE the revocation remain valid evidence - the authority was
live when they were minted.
"""

import base64
import json

from fastapi.testclient import TestClient

from raucle.capability import CapabilityIssuer, DelegationLedger
from raucle.gateway import GateReceiptContext, GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.provenance import ProvenanceVerifier
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


def _setup(tmp_path, chains=1):
    """A delegated gateway: root -> child per chain, revocations file live."""
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
    config.revocations_file = str(tmp_path / "revocations.jsonl")

    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    ledger = DelegationLedger(tmp_path / "delegations.jsonl")
    pem = (
        issuer.public_key_pem.decode()
        if isinstance(issuer.public_key_pem, bytes)
        else issuer.public_key_pem
    )
    TrustRegistry(path=tmp_path / "registry.jsonl").publish(pem, issuer="test-issuer")

    tokens = {}
    for c in range(chains):
        root = issuer.mint(
            agent_id="agent:svc",
            tool="lookup_balance",
            constraints={"allowed_values": {"account": [f"ACC-{c + 1:03d}"]}},
            ttl_seconds=600,
        )
        child = issuer.attenuate(root)
        ledger.register(root, "agent:svc", verifying_key=issuer)
        ledger.register(child, "agent:svc", verifying_key=issuer)
        tokens[f"root{c}"] = root
        tokens[f"child{c}"] = child

    gw = RaucleGateway(config)
    client = TestClient(create_gateway_app(gw))
    return gw, client, tokens, tmp_path


def _gate(client, token, account="ACC-001", amount=1):
    return client.post(
        "/gate",
        json={
            "tool": "lookup_balance",
            "args": {"account": account, "amount": amount},
            "agent_id": "agent:svc",
        },
        headers={"X-Capability-Token": json.dumps(token.to_dict())},
    )


def test_revoke_mid_chain_cascades(tmp_path):
    gw, client, tokens, tmp = _setup(tmp_path)
    assert _gate(client, tokens["child0"]).json()["decision"] == "allow"

    result = gw.revoke_capability(
        tokens["child0"].token_id, reason="suspected compromise", actor="admin"
    )
    assert result["receipt_id"]
    assert tokens["child0"].token_id in result["revoked"]

    # the gate refuses new actions on the revoked chain (per-call reload)
    denied = _gate(client, tokens["child0"])
    assert denied.json()["decision"] == "deny"
    assert "revoked" in denied.json()["reason"], denied.json()
    # the root remains live: revoking a child never kills its parent
    assert _gate(client, tokens["root0"]).json()["decision"] == "allow"

    # the revocation receipt: signed, attributable, subtree named
    payload = _revocation_payload(tmp)
    rev = payload["x_revocation"]
    assert rev["actor"] == "admin"
    assert rev["reason"] == "suspected compromise"
    assert tokens["child0"].token_id in rev["revoked_ids"]


def test_verifier_marks_post_revocation_receipts(tmp_path):
    """The acceptance: pre-revocation receipts stay valid; a receipt minted
    AFTER the revocation of its cited authority is invalid with a named
    reason (simulated enforcement failure - the honest gate denies it)."""
    gw, client, tokens, tmp = _setup(tmp_path)
    # 1: a legitimate allow under the child (pre-revocation)
    assert _gate(client, tokens["child0"]).json()["decision"] == "allow"
    # 2: the revocation
    gw.revoke_capability(tokens["child0"].token_id, reason="test", actor="admin")
    # 3: a forged/buggy allow citing the revoked child (bypasses the gate)
    from raucle.provenance import authorization_block

    gw._emit_gate_receipt(
        GateReceiptContext(
            decision="allow",
            reason="ok",
            tool="lookup_balance",
            agent_id="agent:svc",
            args={"account": "ACC-001"},
            policy=None,
            latency_us=100,
            source="agent:svc",
            destination="lookup_balance",
            trace_id="t-forged",
            authorization=authorization_block(tokens["child0"].to_dict()),
        )
    )

    verifier = ProvenanceVerifier(
        public_keys={gw._gate_identity.key_id: gw._gate_identity.public_key_pem()}
    )
    report = verifier.verify_chain(tmp / "receipts.jsonl")
    assert not report.valid
    assert any("revoked" in e for e in report.errors), report.errors


def test_owner_departure_revokes_all_chains(tmp_path):
    gw, client, tokens, tmp = _setup(tmp_path, chains=2)
    for c in (0, 1):
        assert (
            _gate(client, tokens[f"child{c}"], account=f"ACC-{c + 1:03d}").json()["decision"]
            == "allow"
        )

    result = gw.revoke_agent_chains("agent:svc", reason="departure", actor="hr")
    assert result["receipt_id"]
    for c in (0, 1):
        for kind in ("root", "child"):
            denied = _gate(client, tokens[f"{kind}{c}"])
            assert denied.json()["decision"] == "deny", (kind, c, denied.json())
            assert "revoked" in denied.json()["reason"]

    payload = _revocation_payload(tmp)
    assert len(payload["x_revocation"]["revoked_ids"]) == 4


def _payload_of(envelope):
    seg = envelope["jws"].split(".")[1]
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def _revocation_payload(tmp):
    """The x_revocation receipt, wherever it sits in the chain (gate calls
    may follow it)."""
    for ln in (tmp / "receipts.jsonl").read_text().strip().splitlines():
        payload = _payload_of(json.loads(ln))
        if "x_revocation" in payload:
            return payload
    raise AssertionError("no revocation receipt in the chain")
