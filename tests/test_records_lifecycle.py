"""G3: records lifecycle - retention stamps and tamper-evident disposal.

The contract: disposal is a signed destruction receipt (x_destruction)
binding the time span, count and digest of what left; the survivors
re-anchor as a fresh chain; the escrow copy re-checks the digest offline;
a forged escrow fails. Neither mode upgrades bad evidence.
"""

import json

import pytest

from raucle.audit import AuditVerifier, Ed25519Signer, HashChainSink
from raucle.records import (
    build_destruction,
    split_chain,
    verify_destruction,
)

ROWS = [
    {
        "timestamp": "2026-10-01T09:00:00+00:00",
        "decision": "ALLOW",
        "tool": "export_records",
        "agent_id": "agent:svc",
    },
    {
        "timestamp": "2026-10-01T10:00:00+00:00",
        "decision": "DENY",
        "tool": "export_records",
        "agent_id": "agent:svc",
    },
    {
        "timestamp": "2026-10-02T09:00:00+00:00",
        "decision": "ALLOW",
        "tool": "export_records",
        "agent_id": "agent:svc",
    },
    {
        "timestamp": "2026-10-02T11:00:00+00:00",
        "decision": "DENY",
        "tool": "export_records",
        "agent_id": "agent:svc",
    },
]


def _chain(tmp_path):
    path = tmp_path / "chain.jsonl"
    signer = Ed25519Signer.generate()
    with HashChainSink(path, signer=signer, checkpoint_every=2) as sink:
        for row in ROWS:
            sink.append(row)
    return path


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
    (tmp_path / "operator-private.pem").write_bytes(pem)
    return pem, pub


def test_split_selects_only_the_span(tmp_path):
    chain = _chain(tmp_path)
    removed, retained = split_chain(
        chain,
        from_ts="2026-10-01T00:00:00+00:00",
        to_ts="2026-10-01T23:59:59+00:00",
    )
    assert len(removed) == 2  # both day-1 rows
    assert len(retained) >= 2  # both day-2 rows (+ meta)
    assert all(r["event"]["timestamp"].startswith("2026-10-01") for r in removed)


def test_destruction_verifies_and_escrow_digest_matches(tmp_path):
    chain = _chain(tmp_path)
    operator_priv, operator_pub = _operator_key(tmp_path)
    out = tmp_path / "disposal"

    manifest = build_destruction(
        chain,
        from_ts="2026-10-01T00:00:00+00:00",
        to_ts="2026-10-01T23:59:59+00:00",
        reason="annual review: 2025 Q4 records past retention",
        actor="records-officer:craig",
        operator_key_pem=operator_priv,
        out_dir=out,
    )
    assert manifest["record_count"] == 2
    assert manifest["retained_count"] == 2

    # signature valid, and the escrow copy re-checks the span digest
    report = verify_destruction(out / "destruction.json", escrow_path=out / "removed-records.jsonl")
    assert report["valid"], report
    assert report["span_digest_matches_escrow"] is True
    assert report["block"]["actor"] == "records-officer:craig"

    # the surviving chain is a fresh, valid chain carrying only day 2
    survivor = AuditVerifier().verify_chain(out / "retained-chain.jsonl")
    assert survivor.valid, survivor.errors if hasattr(survivor, "errors") else survivor
    kept = [
        json.loads(line)
        for line in (out / "retained-chain.jsonl").read_text().splitlines()
        if line.strip() and not json.loads(line).get("chain_meta")
    ]
    assert len(kept) == 2
    assert all(r["event"]["timestamp"].startswith("2026-10-02") for r in kept)


def test_forged_escrow_fails_the_digest(tmp_path):
    chain = _chain(tmp_path)
    operator_priv, _ = _operator_key(tmp_path)
    out = tmp_path / "disposal"
    build_destruction(
        chain,
        from_ts="2026-10-01T00:00:00+00:00",
        to_ts="2026-10-01T23:59:59+00:00",
        reason="annual review",
        actor="records-officer:craig",
        operator_key_pem=operator_priv,
        out_dir=out,
    )
    # forge the escrow: flip a payload byte after the fact
    lines = (out / "removed-records.jsonl").read_text().splitlines()
    rec = json.loads(lines[0])
    rec["event"]["agent_id"] = "agent:other"  # the forgery
    lines[0] = json.dumps(rec)
    (out / "removed-records.jsonl").write_text("\n".join(lines) + "\n")

    report = verify_destruction(out / "destruction.json", escrow_path=out / "removed-records.jsonl")
    assert report["span_digest_matches_escrow"] is False
    assert report["valid"] is False


def test_signature_only_mode_without_escrow(tmp_path):
    """Without the records, the destruction receipt still proves the
    disposal event happened as signed (tamper-evident, not re-checkable)."""
    chain = _chain(tmp_path)
    operator_priv, operator_pub = _operator_key(tmp_path)
    out = tmp_path / "disposal"
    build_destruction(
        chain,
        from_ts="2026-10-01T00:00:00+00:00",
        to_ts="2026-10-01T23:59:59+00:00",
        reason="annual review",
        actor="records-officer:craig",
        operator_key_pem=operator_priv,
        out_dir=out,
    )
    report = verify_destruction(out / "destruction.json", operator_public_pem=operator_pub)
    assert report["valid"] is True
    assert report["span_digest_matches_escrow"] is None


def test_empty_span_refused(tmp_path):
    chain = _chain(tmp_path)
    operator_priv, _ = _operator_key(tmp_path)
    with pytest.raises(ValueError):
        build_destruction(
            chain,
            from_ts="2020-01-01T00:00:00+00:00",
            to_ts="2020-01-02T00:00:00+00:00",
            reason="nothing",
            actor="x",
            operator_key_pem=operator_priv,
            out_dir=tmp_path / "empty",
        )


def test_gate_receipts_stamp_retention_until(tmp_path):
    """The retention schedule rides on the gate receipt when configured:
    retention_until = iat + retention_days, zero when unset."""
    from raucle.capability import CapabilityIssuer, DelegationLedger
    from raucle.gateway import GatewayConfig, RaucleGateway
    from raucle.gateway_app import create_gateway_app
    from raucle.trust_registry import TrustRegistry

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
    config.policy_file.write_text(
        "version: 1\nissuer: t\npolicies:\n  - tool: t\n    agent_id: agent:a\n"
    )
    config.gate_auth = "token"
    config.retention_days = 2555  # a seven-year public-records schedule

    issuer = CapabilityIssuer.generate(issuer="test-issuer")
    token = issuer.mint(agent_id="agent:a", tool="t", constraints={}, ttl_seconds=600)
    DelegationLedger(tmp_path / "delegations.jsonl").register(
        token, "agent:a", verifying_key=issuer
    )
    TrustRegistry(path=tmp_path / "registry.jsonl").publish(
        issuer.public_key_pem.decode()
        if isinstance(issuer.public_key_pem, bytes)
        else issuer.public_key_pem,
        issuer="test-issuer",
    )
    config.registry_path = str(tmp_path / "registry.jsonl")
    config.delegations_file = str(tmp_path / "delegations.jsonl")

    gw = RaucleGateway(config)
    from fastapi.testclient import TestClient

    client = TestClient(create_gateway_app(gw))
    resp = client.post(
        "/gate",
        json={"tool": "t", "args": {}, "agent_id": "agent:a"},
        headers={"X-Capability-Token": json.dumps(token.to_dict())},
    )
    assert resp.status_code == 200

    import base64

    for line in (tmp_path / "receipts.jsonl").read_text().splitlines():
        envelope = json.loads(line)
        seg = envelope["jws"].split(".")
        payload = json.loads(base64.urlsafe_b64decode(seg[1] + "==" * (-len(seg[1]) % 4)))
        block = payload.get("x_gate", {})
        if block.get("decision"):
            assert block["retention_until"] == payload["iat"] + 2555 * 86400


def test_retention_zero_when_unset(tmp_path):
    from raucle.gateway import GatewayConfig

    config = GatewayConfig(host="127.0.0.1", admin_api_key="k", signer_backend="local")
    assert config.retention_days == 0  # the stamp is zero, never absent
