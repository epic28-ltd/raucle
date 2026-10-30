"""H1b-1: the receipt-chain-to-audit-chain projection (a format bridge).

The projection re-encodes what the gate receipt chain (JWS envelopes) and
the org's audit chain already carry into the audit-chain shape
compliance_pack.build_pack consumes. These tests pin the bridge contract:
bounded re-encoding, no minting, no re-signing, tamper refusal, and the
same verifier path an operator-built bundle flows through.
"""

import json
from pathlib import Path

import pytest

from raucle.audit import AuditVerifier, HashChainSink
from raucle.compliance import extract_evidence
from raucle.compliance_pack import build_pack, verify_pack_certificate
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.projection import project_pack_chain
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
"""

_OLD_TS = "2020-01-01T00:00:00+00:00"


@pytest.fixture()
def gw(tmp_path):
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        emit_receipts=True,
    )
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY)
    config.policy_file = str(policy)
    return RaucleGateway(config)


def _calls(gw):
    """One allowed and one denied gated call, receipts into the store."""
    allow = gw.check_tool_call("lookup_balance", {"account": "ACC-001"}, agent_id="agent:svc")
    deny = gw.check_tool_call("lookup_balance", {"account": "ACC-999"}, agent_id="agent:svc")
    assert allow["decision"] == "allow"
    assert deny["decision"] == "deny"
    return allow, deny


def _operator_key(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem, pub


def _events(path):
    """The event dicts in a projected chain (header and checkpoints aside)."""
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("chain_meta") or rec.get("checkpoint"):
            continue
        out.append(rec["event"])
    return out


def _write_audit_chain(path, rows):
    with HashChainSink(path) as sink:
        for row in rows:
            sink.append(row)


def test_projection_output_flows_through_the_operator_verifier_path(tmp_path, gw):
    """The headline contract: what the projection writes verifies through
    the same machinery an operator-built bundle uses (AuditVerifier via
    extract_evidence, then build_pack + the offline certificate check)."""
    allow, deny = _calls(gw)
    receipts = tmp_path / "receipts.jsonl"
    out = tmp_path / "projected.jsonl"

    summary = project_pack_chain(
        receipts,
        out_path=out,
        gateway_public_key_pem=gw.gate_identity.public_key_pem(),
    )
    assert summary["projected_receipts"] == 2

    # Same verifier path: the audit-chain verifier accepts the container.
    report = AuditVerifier().verify_chain(out)
    assert report.valid, report.errors
    assert report.event_count == 2

    # Same pack path: the bundle builds and the certificate verifies offline.
    op_priv, op_pub = _operator_key(tmp_path)
    bundle = tmp_path / "bundle"
    manifest = build_pack(out, framework="eu-ai-act", out_dir=bundle, operator_key_pem=op_priv)
    assert manifest["verifier_result"] == "valid"
    assert verify_pack_certificate(manifest["certificate"], op_pub) is True

    # One extract per gate decision, receipt_id binding back to the signed
    # receipt (the auditor's pull key).
    extracts = [
        json.loads(line)
        for line in (bundle / "extracts.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert {e["decision"] for e in extracts} == {"ALLOW", "DENY"}
    assert {e["receipt_id"] for e in extracts} == {allow["receipt_id"], deny["receipt_id"]}

    # The cited receipts still verify in the ORIGINAL chain: the projection
    # moved nothing, it re-encoded.
    verifier = ProvenanceVerifier(
        public_keys={gw.gate_identity.key_id: gw.gate_identity.public_key_pem()}
    )
    assert verifier.verify_chain(receipts).valid


def test_projection_rows_carry_exactly_the_extract_fields(tmp_path, gw):
    allow, deny = _calls(gw)
    out = tmp_path / "projected.jsonl"
    project_pack_chain(tmp_path / "receipts.jsonl", out_path=out)

    events = _events(out)
    assert len(events) == 2
    for event in events:
        assert set(event) <= {
            "decision",
            "agent_id",
            "tool",
            "timestamp",
            "receipt_id",
            "rule_id",
            "authorization",
        }
        assert event["decision"] in {"ALLOW", "DENY"}
        assert event["agent_id"] == "agent:svc"
        assert event["tool"] == "lookup_balance"
        assert event["timestamp"]
        assert event["receipt_id"] in {allow["receipt_id"], deny["receipt_id"]}
    assert {e["decision"] for e in events} == {"ALLOW", "DENY"}


def test_projection_never_carries_values_or_reasons(tmp_path, gw):
    """Bounded disclosure at the bridge: no call args, no denial reason
    (it quotes constraint VALUES), no latency, no trace ids."""
    _calls(gw)
    out = tmp_path / "projected.jsonl"
    project_pack_chain(tmp_path / "receipts.jsonl", out_path=out)

    text = out.read_text(encoding="utf-8")
    assert "ACC-001" not in text
    assert "ACC-999" not in text
    assert "reason" not in text
    assert "latency" not in text
    assert "trace" not in text


def test_projection_never_signs(tmp_path, gw):
    """The output container is always an unsigned hash chain: the module
    takes no signer, writes no checkpoints, and the original chains stay
    the attribution source. The pack says so honestly."""
    _calls(gw)
    out = tmp_path / "projected.jsonl"
    project_pack_chain(tmp_path / "receipts.jsonl", out_path=out)

    lines = out.read_text(encoding="utf-8").splitlines()
    header = json.loads(lines[0])
    assert header["chain_meta"] is True
    assert header["signed"] is False
    assert all('"checkpoint"' not in line for line in lines)

    ev = extract_evidence(out)
    assert ev.chain_valid is True
    assert ev.signature_verified is False


def test_projection_refuses_a_tampered_receipt_envelope(tmp_path, gw):
    """Fail-closed: an envelope whose hash no longer binds its JWS is
    tampered source material and is refused, never re-encoded."""
    _calls(gw)
    receipts = tmp_path / "receipts.jsonl"
    lines = receipts.read_text(encoding="utf-8").splitlines()
    envelope = json.loads(lines[0])
    tampered_jws = envelope["jws"][:-6] + "AAAAAA"
    lines[0] = json.dumps({"receipt_hash": envelope["receipt_hash"], "jws": tampered_jws})
    receipts.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="tamper"):
        project_pack_chain(receipts, out_path=tmp_path / "projected.jsonl")


def test_projection_verifies_source_signatures_when_a_key_is_supplied(tmp_path, gw):
    """With the gate's public key the projection also refuses receipts the
    key does not authenticate (a forged re-sign cannot ride the bridge)."""
    _calls(gw)
    receipts = tmp_path / "receipts.jsonl"
    out = tmp_path / "projected.jsonl"

    project_pack_chain(
        receipts, out_path=out, gateway_public_key_pem=gw.gate_identity.public_key_pem()
    )
    assert len(_events(out)) == 2

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    wrong = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    with pytest.raises(ValueError, match="signature"):
        project_pack_chain(
            receipts, out_path=tmp_path / "again.jsonl", gateway_public_key_pem=wrong
        )


def test_projection_dedups_decisions_already_in_the_audit_chain(tmp_path, gw):
    """A gate decision the audit chain already records (joined on
    receipt_id) projects no second row."""
    allow, deny = _calls(gw)
    audit = tmp_path / "audit.jsonl"
    _write_audit_chain(
        audit,
        [
            {
                "timestamp": _OLD_TS,
                "decision": "ALLOW",
                "agent_id": "agent:svc",
                "tool": "lookup_balance",
                "receipt_id": allow["receipt_id"],
            }
        ],
    )
    out = tmp_path / "projected.jsonl"
    summary = project_pack_chain(tmp_path / "receipts.jsonl", audit, out_path=out)

    assert summary["duplicates_skipped"] == 1
    assert summary["projected_receipts"] == 1
    assert summary["audit_events"] == 1
    events = _events(out)
    assert len(events) == 2
    assert sum(1 for e in events if e.get("receipt_id") == allow["receipt_id"]) == 1
    # the audit row's own event came through unchanged
    assert events[0]["timestamp"] == _OLD_TS


def test_projection_merges_chronologically(tmp_path, gw):
    """Audit rows and projected receipts merge in event-time order, stable
    on ties (audit rows first)."""
    _calls(gw)
    audit = tmp_path / "audit.jsonl"
    _write_audit_chain(
        audit,
        [
            {
                "timestamp": _OLD_TS,
                "decision": "DENY",
                "agent_id": "agent:svc",
                "tool": "lookup_balance",
            }
        ],
    )
    out = tmp_path / "projected.jsonl"
    project_pack_chain(tmp_path / "receipts.jsonl", audit, out_path=out)

    events = _events(out)
    assert events[0]["timestamp"] == _OLD_TS
    assert all(e["timestamp"] > _OLD_TS for e in events[1:])


def test_projection_carries_authorization_blocks_bounded(tmp_path, gw):
    """Receipts v1.1 delegated-authority bindings ride the bridge, bounded
    to the extract keys."""
    from raucle.provenance import authorization_block

    cap = {
        "token_id": "cap:root",
        "issuer": "test-issuer",
        "key_id": "k1",
        "parent_id": None,
    }
    allow = gw.check_tool_call(
        "lookup_balance",
        {"account": "ACC-001"},
        agent_id="agent:svc",
        _authorization_hint=authorization_block(cap),
    )
    assert allow["decision"] == "allow"
    out = tmp_path / "projected.jsonl"
    project_pack_chain(tmp_path / "receipts.jsonl", out_path=out)

    events = _events(out)
    assert len(events) == 1
    auth = events[0].get("authorization")
    assert auth is not None
    assert set(auth) <= {"capability_id", "chain_digest", "issuer"}
    assert auth["capability_id"] == "cap:root"


def test_authority_receipts_are_counted_not_projected(tmp_path, gw):
    """Non-decision receipts (authority events) are not decision evidence;
    they are counted, not re-encoded as decisions."""
    _calls(gw)
    gw._emit_authority_receipt(
        verdict="agent_suspended",
        extension_key="x_suspension",
        extension={"agent_id": "agent:svc", "actor": "test"},
    )
    out = tmp_path / "projected.jsonl"
    summary = project_pack_chain(tmp_path / "receipts.jsonl", out_path=out)

    assert summary["projected_receipts"] == 2
    assert summary["non_decision_receipts"] == 1
    assert len(_events(out)) == 2


def test_projection_refuses_to_extend_an_existing_output(tmp_path, gw):
    """A projection is a fresh container: an existing out_path is refused,
    never appended to (appending would mix two projections)."""
    _calls(gw)
    out = tmp_path / "projected.jsonl"
    out.touch()
    with pytest.raises(ValueError, match="exists"):
        project_pack_chain(tmp_path / "receipts.jsonl", out_path=out)


def test_projection_reports_input_digests(tmp_path, gw):
    """The summary binds what it was built from, so callers can receipt it."""
    import hashlib

    _calls(gw)
    audit = tmp_path / "audit.jsonl"
    _write_audit_chain(
        audit,
        [{"timestamp": _OLD_TS, "decision": "DENY", "agent_id": "agent:svc", "tool": "t"}],
    )
    receipts = tmp_path / "receipts.jsonl"
    out = tmp_path / "projected.jsonl"
    summary = project_pack_chain(receipts, audit, out_path=out)

    prefix = "sha256:"
    assert summary["receipts_digest"] == prefix + hashlib.sha256(receipts.read_bytes()).hexdigest()
    assert summary["audit_chain_digest"] == prefix + hashlib.sha256(audit.read_bytes()).hexdigest()
    assert summary["out"] == str(out)
