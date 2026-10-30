"""EPIC D: harness test findings as replay-verifiable evidence.

A QM/Pentagon-class harness runs its security tests through the raucle
gate. Every finding the harness reports is itself a receipt with
request-level provenance: it CITES the gate receipt covering the request
and states what the harness expected and what the gate actually did.

The verifier re-checks the finding offline, the same way it re-checks a
delegation or a lease: a finding that cites a receipt not in the chain
fails, and a finding that MISREPORTS the gate's decision fails. The
harness cannot lie about what happened; that is the whole point.
"""

import json

import pytest

from raucle.capability import CapabilityIssuer, DelegationLedger
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.provenance import ProvenanceVerifier
from raucle.trust_registry import TrustRegistry

POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: export_records
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
"""


def _gateway(tmp_path):
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
        tool="export_records",
        constraints={"allowed_values": {"account": ["ACC-001"]}},
        ttl_seconds=600,
    )
    ledger.register(root, "agent:svc", verifying_key=issuer)
    pem = (
        issuer.public_key_pem.decode()
        if isinstance(issuer.public_key_pem, bytes)
        else issuer.public_key_pem
    )
    TrustRegistry(path=tmp_path / "registry.jsonl").publish(pem, issuer="test-issuer")
    config.registry_path = str(tmp_path / "registry.jsonl")
    config.delegations_file = str(tmp_path / "delegations.jsonl")

    from fastapi.testclient import TestClient

    gw = RaucleGateway(config)
    client = TestClient(create_gateway_app(gw))
    return gw, client, root


def _run(client, token, args):
    """A harness test request crossing the gate, the HTTP form QM uses."""
    resp = client.post(
        "/gate",
        json={"tool": "export_records", "args": args, "agent_id": "agent:svc"},
        headers={"X-Capability-Token": json.dumps(token.to_dict())},
    )
    return resp.json()


def _verify(tmp_path, gw):
    report = ProvenanceVerifier(
        public_keys={gw._gate_identity.key_id: gw._gate_identity.public_key_pem()}
    ).verify_chain(tmp_path / "receipts.jsonl")
    return report


def test_confirmed_finding_cites_the_gate_receipt_and_verifies(tmp_path):
    """The acceptance: a QM-class harness run over the gate produces a
    findings ledger where every confirmed issue is replay-verifiable
    offline. A confirmed finding (harness expected deny, gate allowed)
    verifies when it cites the real receipt and states the real decision."""
    gw, client, token = _gateway(tmp_path)

    allowed = _run(client, token, {"account": "ACC-001"})
    assert allowed["decision"] == "allow"
    assert allowed["receipt_id"]

    finding_id = gw.emit_finding(
        harness="qm",
        test_id="exfil:oversized-export",
        verdict="confirmed",
        cited_receipt=allowed["receipt_id"],
        expected_decision="deny",
        actual_decision="allow",
        tool="export_records",
        args_digest=allowed["args_hash"],
        note="policy allowed a 5-year export for a today check",
    )
    assert finding_id

    report = _verify(tmp_path, gw)
    assert report.valid, report.errors
    # the test id rides inside the signed (base64) payload, not the envelope
    import base64 as _b64

    decoded = "".join(
        _b64.urlsafe_b64decode(line.split(".")[1] + "=" * (-len(line.split(".")[1]) % 4)).decode(
            "utf-8", "replace"
        )
        for line in (tmp_path / "receipts.jsonl").read_text().splitlines()
    )
    assert "exfil:oversized-export" in decoded


def test_lying_finding_fails_verification(tmp_path):
    """A finding that misreports the gate's decision does not verify. The
    harness cannot invent evidence about what the gate did."""
    gw, client, token = _gateway(tmp_path)

    allowed = _run(client, token, {"account": "ACC-001"})
    assert allowed["decision"] == "allow"

    gw.emit_finding(
        harness="qm",
        test_id="exfil:false-report",
        verdict="confirmed",
        cited_receipt=allowed["receipt_id"],
        expected_decision="deny",
        actual_decision="deny",  # the LIE: the gate allowed this call
        tool="export_records",
        args_digest=allowed["args_hash"],
    )
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("misreports" in e for e in report.errors), report.errors


def test_finding_citing_a_missing_receipt_fails(tmp_path):
    gw, client, token = _gateway(tmp_path)
    _run(client, token, {"account": "ACC-001"})

    gw.emit_finding(
        harness="qm",
        test_id="exfil:ghost",
        verdict="confirmed",
        cited_receipt="sha256:" + "ff" * 32,
        expected_decision="deny",
        actual_decision="allow",
        tool="export_records",
        args_digest="sha256:" + "00" * 32,
    )
    report = _verify(tmp_path, gw)
    assert not report.valid
    assert any("not in the chain" in e for e in report.errors), report.errors


def test_refuted_and_expected_pass_findings_verify(tmp_path):
    """A deny the gate produced: the harness expected the violation to go
    through, the gate blocked it, so the issue is refuted. And a finding
    where expectation and reality agree (expected_pass) verifies too."""
    gw, client, token = _gateway(tmp_path)

    allowed = _run(client, token, {"account": "ACC-001"})
    denied = _run(client, token, {"account": "ACC-999"})
    assert denied["decision"] == "deny"
    assert denied["receipt_id"]

    gw.emit_finding(
        harness="qm",
        test_id="exfil:off-limits-account",
        verdict="refuted",
        cited_receipt=denied["receipt_id"],
        expected_decision="allow",
        actual_decision="deny",
        tool="export_records",
        args_digest=denied["args_hash"],
        note="gate blocked the off-limits account; issue does not stand",
    )
    gw.emit_finding(
        harness="qm",
        test_id="baseline:allowed-account-flows",
        verdict="expected_pass",
        cited_receipt=allowed["receipt_id"],
        expected_decision="allow",
        actual_decision="allow",
        tool="export_records",
        args_digest=allowed["args_hash"],
    )
    report = _verify(tmp_path, gw)
    assert report.valid, report.errors


def test_deterministic_finding_id_is_replayable(tmp_path):
    """The finding id derives from (harness, test, cited receipt): the
    same run replays to the same findings ledger line."""
    gw, client, token = _gateway(tmp_path)
    allowed = _run(client, token, {"account": "ACC-001"})

    first = gw.emit_finding(
        harness="qm",
        test_id="exfil:oversized-export",
        verdict="confirmed",
        cited_receipt=allowed["receipt_id"],
        expected_decision="deny",
        actual_decision="allow",
        tool="export_records",
        args_digest=allowed["args_hash"],
    )
    second = gw.emit_finding(
        harness="qm",
        test_id="exfil:oversized-export",
        verdict="confirmed",
        cited_receipt=allowed["receipt_id"],
        expected_decision="deny",
        actual_decision="allow",
        tool="export_records",
        args_digest=allowed["args_hash"],
    )
    assert first == second


@pytest.mark.parametrize("verdict", ["confirmed", "refuted", "expected_pass"])
def test_verdict_vocabulary_accepts_known_words(tmp_path, verdict):
    """The verdict vocabulary is closed and covers the three known words."""
    gw, client, token = _gateway(tmp_path)
    allowed = _run(client, token, {"account": "ACC-001"})
    receipt = gw.emit_finding(
        harness="qm",
        test_id="vocabulary",
        verdict=verdict,
        cited_receipt=allowed["receipt_id"],
        expected_decision="allow",
        actual_decision="allow",
        tool="export_records",
        args_digest=allowed["args_hash"],
    )
    assert receipt


def test_arbitrary_verdict_refused(tmp_path):
    gw, client, token = _gateway(tmp_path)
    allowed = _run(client, token, {"account": "ACC-001"})
    with pytest.raises(ValueError):
        gw.emit_finding(
            harness="qm",
            test_id="vocabulary",
            verdict="mostly-fine",
            cited_receipt=allowed["receipt_id"],
            expected_decision="allow",
            actual_decision="allow",
            tool="export_records",
            args_digest=allowed["args_hash"],
        )
