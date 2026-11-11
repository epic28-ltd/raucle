"""Audit pack (E2): self-contained, offline-verifiable custody evidence.

Drives the AWS Egress Gate to produce a real JWS receipt chain, bundles it into a
pack, and proves the pack verifies fully offline — then proves each tamper is
caught.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

cryptography = pytest.importorskip("cryptography")

BACKSLASH = chr(92)  # member-name escape shape below
NULLBYTE = chr(0)

from raucle.audit_pack import build_pack, verify_pack
from raucle.broker import AWSEgressGate, CapabilityDenied
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.provenance import AgentIdentity, ProvenanceLogger


class _FakeTransport:
    def __init__(self):
        self.calls = []

    def __call__(self, req):
        self.calls.append(req)
        return 200, b'{"Item":{"customer_id":{"S":"C-123"}}}'


def _gate_chain(tmp_path: Path):
    """Produce a real gate chain (1 ALLOW + 1 DENY) and the broker pubkey."""
    issuer = CapabilityIssuer.generate(issuer="acme.bank")
    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    token = issuer.mint(
        agent_id="agent:kyc-prod",
        tool="dynamodb.GetItem",
        constraints={"allowed_values": {"TableName": ["customers"]}},
        ttl_seconds=300,
    )
    broker = AgentIdentity.generate(agent_id="agent:raucle-aws-egress-broker")
    chain = tmp_path / "custody.jsonl"
    writer = ProvenanceLogger(broker, sink_path=chain)
    egress = AWSEgressGate(
        gate,
        region="us-east-1",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        provenance_writer=writer,
        transport=_FakeTransport(),
        clock=lambda: 1_700_000_000,
    )
    egress.get_item(
        token, table="customers", key={"customer_id": {"S": "C-123"}}, agent_id="agent:kyc-prod"
    )
    with pytest.raises(CapabilityDenied):
        egress.get_item(
            token, table="forbidden", key={"customer_id": {"S": "C-9"}}, agent_id="agent:kyc-prod"
        )
    writer.close()
    return chain, broker


def _audit_key() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def test_pack_built_from_gate_chain_verifies_fully_offline(tmp_path):
    chain, broker = _gate_chain(tmp_path)
    out = tmp_path / "pack"
    build_pack(
        chain_path=chain,
        public_keys={broker.key_id: broker.public_key_pem()},
        audit_key_pem=_audit_key(),
        out_dir=out,
        generated_at=1_700_000_000,
    )

    # The pack is self-contained: PACK.json + chain + manifest + report + pubkey.
    assert (out / "PACK.json").is_file()
    assert (out / "chain.jsonl").is_file()
    assert (out / "manifest.json").is_file()
    assert (out / f"pubkeys/{broker.key_id}.pem").is_file()

    verdict = verify_pack(out)
    assert verdict.ok, verdict.reasons
    assert verdict.integrity_ok
    assert verdict.manifest_signature_ok
    assert verdict.chain_valid
    assert verdict.reproducible
    assert verdict.receipt_count == 3  # ALLOW: scan+tool_call, DENY: scan


def test_pack_detects_a_tampered_receipt_chain(tmp_path):
    chain, broker = _gate_chain(tmp_path)
    out = tmp_path / "pack"
    build_pack(
        chain_path=chain,
        public_keys={broker.key_id: broker.public_key_pem()},
        audit_key_pem=_audit_key(),
        out_dir=out,
        generated_at=1_700_000_000,
    )
    # Flip a single byte in the bundled chain after assembly (the args are
    # hashed, not stored plaintext, so we mutate a raw byte — integrity is a pure
    # hash check and catches any change regardless).
    chain_member = out / "chain.jsonl"
    data = bytearray(chain_member.read_bytes())
    idx = len(data) // 2
    data[idx] ^= 0x01
    chain_member.write_bytes(bytes(data))

    verdict = verify_pack(out)
    assert not verdict.ok
    assert not verdict.integrity_ok  # member hash no longer matches the index
    assert any("tampered" in r or "hash mismatch" in r for r in verdict.reasons)


def test_pack_detects_a_forged_manifest_body(tmp_path):
    chain, broker = _gate_chain(tmp_path)
    out = tmp_path / "pack"
    build_pack(
        chain_path=chain,
        public_keys={broker.key_id: broker.public_key_pem()},
        audit_key_pem=_audit_key(),
        out_dir=out,
        generated_at=1_700_000_000,
    )
    # Re-index a doctored manifest so the integrity check passes but the signed
    # body no longer matches its signature.
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["body"]["summary"]["green"] = 999
    new_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
    manifest_path.write_bytes(new_bytes)
    index = json.loads((out / "PACK.json").read_text())
    from raucle.provenance import _sha256_hex

    for m in index["members"]:
        if m["path"] == "manifest.json":
            m["sha256"] = "sha256:" + _sha256_hex(new_bytes)
    (out / "PACK.json").write_text(json.dumps(index, indent=2))

    verdict = verify_pack(out)
    assert not verdict.ok
    # Integrity passes (we re-indexed), but the signature no longer matches.
    assert verdict.integrity_ok
    assert not verdict.manifest_signature_ok


def test_cli_build_and_verify_roundtrip(tmp_path, capsys):
    """`raucle audit-pack build` then `verify` — the regulator's one-command,
    fully-offline check returns exit 0 on a clean pack."""
    from raucle.cli import main

    chain, broker = _gate_chain(tmp_path)
    # The broker public key as a capability statement (the --pubkeys input).
    stmt_path = tmp_path / "broker.json"
    stmt_path.write_text(json.dumps(broker.statement.to_dict()))
    key_path = tmp_path / "audit.pem"
    key_path.write_bytes(_audit_key())
    pack_dir = tmp_path / "pack"

    rc = main(
        [
            "audit-pack",
            "build",
            str(chain),
            "--pubkeys",
            str(stmt_path),
            "--sign-key",
            str(key_path),
            "--out",
            str(pack_dir),
        ]
    )
    assert rc == 0
    assert (pack_dir / "PACK.json").is_file()

    rc = main(["audit-pack", "verify", str(pack_dir)])
    assert rc == 0
    err = capsys.readouterr().err
    assert "RESULT: VERIFIED" in err


def test_pack_detects_doctored_report_html(tmp_path):
    """Codex High: report.html must match the signed manifest's own rendering —
    re-indexing a doctored human report must NOT verify."""
    from raucle.provenance import _sha256_hex

    chain, broker = _gate_chain(tmp_path)
    out = tmp_path / "pack"
    build_pack(
        chain_path=chain,
        public_keys={broker.key_id: broker.public_key_pem()},
        audit_key_pem=_audit_key(),
        out_dir=out,
        generated_at=1_700_000_000,
    )
    html = out / "report.html"
    doctored = html.read_bytes() + b"<!-- all clear, nothing to see -->"
    html.write_bytes(doctored)
    index = json.loads((out / "PACK.json").read_text())
    for m in index["members"]:
        if m["path"] == "report.html":
            m["sha256"] = "sha256:" + _sha256_hex(doctored)
    (out / "PACK.json").write_text(json.dumps(index, indent=2))

    verdict = verify_pack(out)
    assert not verdict.ok
    assert verdict.integrity_ok  # we re-indexed, so hashes match
    assert not verdict.reproducible
    assert any("report.html" in r for r in verdict.reasons)


def test_pack_rejects_path_traversal_member(tmp_path):
    """Codex Medium: a member path that escapes the pack must be rejected, not
    read from the host filesystem (self-contained guarantee)."""
    chain, broker = _gate_chain(tmp_path)
    out = tmp_path / "pack"
    build_pack(
        chain_path=chain,
        public_keys={broker.key_id: broker.public_key_pem()},
        audit_key_pem=_audit_key(),
        out_dir=out,
        generated_at=1_700_000_000,
    )
    index = json.loads((out / "PACK.json").read_text())
    index["members"].append(
        {"path": "../../../../etc/passwd", "role": "proof", "sha256": "sha256:00"}
    )
    (out / "PACK.json").write_text(json.dumps(index, indent=2))

    verdict = verify_pack(out)
    assert not verdict.ok
    assert not verdict.integrity_ok
    assert any("escapes the pack" in r for r in verdict.reasons)


def test_pinned_signer_anchor(tmp_path):
    """Codex High: without a pinned signer the pack is only 'internally
    consistent'; pinning the wrong custodian key must REJECT, the right one PASS."""
    chain, broker = _gate_chain(tmp_path)
    out = tmp_path / "pack"
    index = build_pack(
        chain_path=chain,
        public_keys={broker.key_id: broker.public_key_pem()},
        audit_key_pem=_audit_key(),
        out_dir=out,
        generated_at=1_700_000_000,
    )
    real_signer = index["audit_key_id"]

    # No anchor → ok, but signer_trusted is None (consistency only).
    v0 = verify_pack(out)
    assert v0.ok
    assert v0.signer_trusted is None

    # Wrong anchor → REJECT even though everything else is valid.
    v1 = verify_pack(out, expected_signer="deadbeefdeadbeef")
    assert not v1.ok
    assert v1.signer_trusted is False

    # Correct anchor → PASS and signer_trusted True.
    v2 = verify_pack(out, expected_signer=real_signer)
    assert v2.ok
    assert v2.signer_trusted is True


def test_index_signature_binds_the_member_set(tmp_path):
    """Codex re-review High: the PACK.json index is itself signed, so a member
    cannot be added/forged and re-indexed (even one whose bytes never reach the
    manifest body) without the audit key. Re-indexing without re-signing the
    index is caught by the index signature."""
    from raucle.provenance import _sha256_hex

    chain, broker = _gate_chain(tmp_path)
    out = tmp_path / "pack"
    build_pack(
        chain_path=chain,
        public_keys={broker.key_id: broker.public_key_pem()},
        audit_key_pem=_audit_key(),
        out_dir=out,
        generated_at=1_700_000_000,
    )
    # Smuggle in a new member and update its index hash so INTEGRITY passes —
    # but the attacker cannot re-sign the index without the audit private key.
    smuggled = b"smuggled-evidence"
    (out / "extra.bin").write_bytes(smuggled)
    index = json.loads((out / "PACK.json").read_text())
    index["members"].append(
        {"path": "extra.bin", "role": "note", "sha256": "sha256:" + _sha256_hex(smuggled)}
    )
    (out / "PACK.json").write_text(json.dumps(index, indent=2))

    verdict = verify_pack(out)
    assert not verdict.ok
    assert verdict.integrity_ok  # the re-indexed member hash matches...
    assert not verdict.index_signature_ok  # ...but the index signature is broken
    assert any("index" in r.lower() for r in verdict.reasons)


def test_resolve_member_refuses_escape_shapes(tmp_path):
    """Traversal-payload table: every member escape shape resolves to None.

    Mirrors the assurance-pack verifier recipe (absolute, dotted, backslash,
    drive-colon, null-byte, symlink escape, non-string index types)."""
    from raucle.audit_pack import _resolve_member

    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "chain.jsonl").write_text("receipt", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("SECRET", encoding="utf-8")
    (pack / "esc.txt").symlink_to(outside)
    payloads = [
        "/etc/passwd",
        "../../etc/passwd",
        "a/../../../etc/passwd",
        ".." + BACKSLASH + BACKSLASH + "windows" + BACKSLASH + BACKSLASH + "win.ini",
        "C:/etc/passwd",
        NULLBYTE + "chain.jsonl",
        "",
        123,
        None,
        "esc.txt",
    ]
    for payload in payloads:
        assert _resolve_member(pack, payload) is None, repr(payload)
    inside = _resolve_member(pack, "chain.jsonl")
    assert inside is not None
    assert inside.is_relative_to(pack.resolve())


def test_pack_traversal_payloads_fail_integrity(tmp_path):
    """A tampered index carrying traversal-shaped members fails integrity,
    each with a named escape reason, and nothing outside the pack is read."""
    chain, broker = _gate_chain(tmp_path)
    out = tmp_path / "pack"
    build_pack(
        chain_path=chain,
        public_keys={broker.key_id: broker.public_key_pem()},
        audit_key_pem=_audit_key(),
        out_dir=out,
        generated_at=1_700_000_000,
    )
    index = json.loads((out / "PACK.json").read_text())
    shapes = [
        "/etc/passwd",
        "../../etc/passwd",
        ".." + BACKSLASH + BACKSLASH + "etc" + BACKSLASH + BACKSLASH + "shadow",
        "C:/etc/passwd",
        "a/../../secrets.json",
    ]
    for shape in shapes:
        index["members"].append({"path": shape, "role": "proof", "sha256": "sha256:00"})
    (out / "PACK.json").write_text(json.dumps(index, indent=2))

    verdict = verify_pack(out)
    assert not verdict.ok
    assert not verdict.integrity_ok
    escaped = {r for r in verdict.reasons if "escapes the pack" in r}
    assert len(escaped) == len(shapes)
    assert not (tmp_path / "secrets.json").exists()
