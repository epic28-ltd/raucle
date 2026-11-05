"""Round-trip tests for the OV-23 audit-pack -> agent-passport export.

Export path: capability statement in an audit packet
(`raucle.audit_pack.build_pack`) -> `tools/passport_export.export_passports`
(which uses raucle's own `issue_passport`) -> verify through raucle's own
`verify_passport` against a `raucle.trust_registry.TrustRegistry`.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from raucle.audit import Ed25519Signer
from raucle.audit_pack import build_pack
from raucle.passport import verify_passport
from raucle.provenance import AgentIdentity
from raucle.trust_registry import TrustRegistry
from tools.passport_export.export import (
    chain_linkage_from_pack,
    export_passports,
    load_pack_statements,
)

ISSUER = "Epic28 Assurance Office"


def _fresh_audit_key_pem() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _make_pack(tmp_path):
    """Build a realistic assurance packet via raucle's own build_pack."""
    ident = AgentIdentity.generate(
        "agent:ov23-worker", allowed_tools=["search"], allowed_models=["glm-5.3-flash"]
    )
    # A pack with an empty-but-present receipt chain: the chain member (and
    # its digest) exists even with zero receipts.
    chain = tmp_path / "src-chain.jsonl"
    chain.write_text("", encoding="utf-8")
    out = tmp_path / "pack"
    build_pack(
        chain_path=chain,
        public_keys={ident.key_id: ident.public_key_pem()},
        audit_key_pem=_fresh_audit_key_pem(),
        out_dir=out,
        generated_at=1_700_000_000,
        capability_statements={ident.key_id: ident.statement},
    )
    return out, ident


def test_export_and_round_trip_verify(tmp_path):
    pack, ident = _make_pack(tmp_path)
    issuer = Ed25519Signer.generate()
    registry = TrustRegistry()
    registry.publish(issuer.public_key_pem(), issuer=ISSUER)

    out_dir = tmp_path / "passports"
    written = export_passports(
        pack, issuer_signer=issuer, issuer=ISSUER, out_dir=out_dir, ttl_seconds=3600
    )
    assert len(written) == 1

    saved = json.loads((out_dir / f"passport-{ident.key_id}.json").read_text())
    verdict = verify_passport(saved, registry=registry)
    assert verdict.valid is True, verdict.reason
    assert verdict.agent_id == "agent:ov23-worker"
    assert verdict.key_id == ident.key_id
    assert verdict.issuer == ISSUER
    assert verdict.allowed_tools == ["search"]
    assert verdict.allowed_models == ["glm-5.3-flash"]
    assert saved["version"] == "agent-passport/v1"


def test_pack_integrity_guard_rejects_non_pack(tmp_path):
    with pytest.raises(ValueError):
        export_passports(
            tmp_path,
            issuer_signer=Ed25519Signer.generate(),
            issuer=ISSUER,
            out_dir=tmp_path / "x",
        )


def test_chain_linkage_digest_and_summary(tmp_path):
    pack, ident = _make_pack(tmp_path)
    chain_file = pack / "chain.jsonl"
    linkage = chain_linkage_from_pack(pack)
    assert linkage is not None
    assert linkage["kind"] == "raucle-chain-linkage/v1"
    assert linkage["reference"] == "chain.jsonl"
    assert linkage["chain_sha256"] == hashlib.sha256(chain_file.read_bytes()).hexdigest()
    assert linkage["receipt_count"] == 0  # empty chain, digest still anchored

    issuer = Ed25519Signer.generate()
    registry = TrustRegistry()
    registry.publish(issuer.public_key_pem(), issuer=ISSUER)
    out_dir = tmp_path / "passports"
    export_passports(pack, issuer_signer=issuer, issuer=ISSUER, out_dir=out_dir)
    saved = json.loads((out_dir / f"passport-{ident.key_id}.json").read_text())
    assert saved["chain_linkage"]["chain_sha256"] == linkage["chain_sha256"]
    # The linkage annotation must not disturb verification of the signed body.
    assert verify_passport(saved, registry=registry).valid is True


def test_no_chain_file_means_no_linkage(tmp_path):
    pack, _ = _make_pack(tmp_path)
    (pack / "chain.jsonl").unlink()
    assert chain_linkage_from_pack(pack) is None


def test_load_pack_statements_strict(tmp_path):
    pack, ident = _make_pack(tmp_path)
    stmts = load_pack_statements(pack)
    assert len(stmts) == 1
    assert stmts[0].agent_id == "agent:ov23-worker"
    assert stmts[0].agent_id == ident.statement.agent_id


def test_main_cli_exports(tmp_path):
    pack, _ = _make_pack(tmp_path)
    key_pem = tmp_path / "issuer.pem"
    key_pem.write_bytes(_fresh_audit_key_pem())

    from tools.passport_export.export import main

    rc = main(
        [str(pack), str(tmp_path / "out"), "--issuer", ISSUER, "--issuer-key-pem", str(key_pem)]
    )
    assert rc == 0
    assert (tmp_path / "out" / "passport_export.json").exists()
    idx = json.loads((tmp_path / "out" / "passport_export.json").read_text())
    assert idx["issuer"] == ISSUER
