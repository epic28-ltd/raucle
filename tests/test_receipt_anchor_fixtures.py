"""Offline verification of the committed receipt-anchor fixtures.

Issue 342 slice THREE: fixtures for every supported proof path,
verified OFFLINE through the existing verifier APIs alone:

- the JWS provenance receipt chain (``receipt-chain.json``) and its
  key-rotation sibling, through :class:`ProvenanceVerifier.verify_chain`;
- a sealed segment and its Ed25519 seal sidecar, plus the
  rotated-seal pair, through :func:`verify_seal_meta` - including the
  retired-key rule (a retired seal key refuses the rotated seal);
- the signed audit hash chain, through :class:`AuditVerifier.verify_chain`;
- the SCITT head statement, through :func:`verify_transparency_anchor`;
- the hosted transparency log's inclusion and consistency proofs and
  its epoch checkpoints, through the log verifier APIs against the
  PINNED operator key.

The fixtures are committed byte-stable data (public keys only; the
private halves are throwaway seeds inside ``tests/ledger_support.py``,
so ``python -m tests.ledger_support regenerate`` reproduces the bytes
exactly). Every fixture carries only its expected verdict - the tests
hold it to its committed `expected` block and to the verifier's own
named failures for doctored copies.
"""

from __future__ import annotations

import json
from pathlib import Path

import tests.test_transparency_log_verify as _log_helpers
from raucle.audit import AuditVerifier
from raucle.provenance import ProvenanceVerifier
from raucle.receipt_store import verify_seal_meta
from raucle.transparency import (
    LOG_CHECKPOINT_TYP,
    STATUS_ANCHORED,
    STATUS_DIGEST_MISMATCH,
    STATUS_LOG_BAD_SIGNATURE,
    STATUS_LOG_CHAIN_BROKEN,
    STATUS_LOG_CONSISTENT,
    STATUS_LOG_INCLUDED,
    compute_chain_head,
    verify_log_consistency,
    verify_log_inclusion,
    verify_transparency_anchor,
)
from tests.ledger_support import FIXTURE_DIR


def _load(name: str) -> dict:
    return json.loads((Path(FIXTURE_DIR) / name).read_text(encoding="utf-8"))


def _write_chain(tmp_path: Path, name: str, lines: list[str]) -> Path:
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Receipt-chain fixtures (the JWS provenance receipt ledger)
# ---------------------------------------------------------------------------


class TestReceiptChainFixtures:
    def test_receipt_chain_fixture_verifies_offline(self, tmp_path):
        fixture = _load("receipt-chain.json")
        ((kid, pem),) = fixture["public_keys"].items()
        verifier = ProvenanceVerifier(public_keys={kid: pem.encode("ascii")})
        report = verifier.verify_chain(_write_chain(tmp_path, "chain.jsonl", fixture["chain"]))
        assert report.valid is True, report.errors
        assert report.receipt_count == fixture["expected"]["receipt_count"]
        assert report.signature_failures == 0
        hashes = [json.loads(line)["receipt_hash"] for line in fixture["chain"]]
        assert hashes == fixture["expected"]["receipt_hashes"]
        assert hashes[-1] == _last_receipt_hash(fixture)

    def test_rotated_chain_fixture_verifies_with_both_generations(self, tmp_path):
        """Per-generation archival verification: the whole chain
        verifies only against BOTH key generations, each receipt under
        the key id it was signed with."""
        fixture = _load("receipt-chain-rotation.json")
        keys = {kid: pem.encode("ascii") for kid, pem in fixture["public_keys"].items()}
        report = ProvenanceVerifier(public_keys=keys).verify_chain(
            _write_chain(tmp_path, "rotated.jsonl", fixture["chain"])
        )
        assert report.valid is True, report.errors
        assert report.receipt_count == fixture["expected"]["receipt_count"]

    def test_the_retired_key_alone_refuses_new_generation_receipts_by_name(self, tmp_path):
        """A verifier pinned to only the retained-generation key refuses
        every later-generation receipt by name - archival verification
        spans generations: both generations' keys must be held."""
        fixture = _load("receipt-chain-rotation.json")
        counts = fixture["expected"]["receipts_per_key"]
        kid_v1 = sorted(kid for kid, n in counts.items() if n == 3)[0]
        verifier = ProvenanceVerifier(
            public_keys={kid_v1: fixture["public_keys"][kid_v1].encode("ascii")}
        )
        report = verifier.verify_chain(
            _write_chain(tmp_path, "retired-key.jsonl", fixture["chain"])
        )
        assert report.valid is False
        assert report.signature_failures == 2
        assert any("signature verification failed" in err for err in report.errors), report.errors


# ---------------------------------------------------------------------------
# Seal fixtures (the receipt store's seal sidecars)
# ---------------------------------------------------------------------------


class TestSealFixtures:
    def test_seal_fixture_verifies_and_reconciles_offline(self):
        fixture = _load("segment-seal.json")
        verdict = verify_seal_meta(fixture["meta"], fixture["public_key_pem"].encode("ascii"))
        assert verdict.verified is True, verdict.reason
        assert verdict.unsigned is False
        assert fixture["meta"]["receipt_count"] == fixture["expected"]["receipt_count"]
        parsed = [json.loads(line) for line in fixture["segment"]]
        assert len(parsed) == fixture["meta"]["receipt_count"]
        assert parsed[-1]["receipt_hash"] == fixture["meta"]["last_receipt_hash"]
        assert parsed[-1]["receipt_hash"] == fixture["expected"]["last_receipt_hash"]

    def test_rotated_seal_fixture_verifies_each_seal_under_its_own_key(self):
        fixture = _load("segment-seal-rotation.json")
        v1 = verify_seal_meta(fixture["meta_v1"], fixture["public_key_v1"].encode("ascii"))
        v2 = verify_seal_meta(fixture["meta_v2"], fixture["public_key_v2"].encode("ascii"))
        assert v1.verified is True, (v1.reason, v2.reason)
        assert v2.verified is True, (v1.reason, v2.reason)
        assert fixture["meta_v1"]["receipt_count"] == fixture["expected"]["receipt_count_v1"]
        assert fixture["meta_v2"]["receipt_count"] == fixture["expected"]["receipt_count_v2"]
        assert (
            fixture["meta_v2"]["last_receipt_hash"] == fixture["expected"]["last_receipt_hash_v2"]
        )

    def test_the_rotated_seal_refuses_the_retired_key_by_name(self):
        """Key rotation: verifying the NEW seal with the RETIRED public
        key fails with a named signature refusal - stale keys never
        present as verified."""
        fixture = _load("segment-seal-rotation.json")
        verdict = verify_seal_meta(fixture["meta_v2"], fixture["public_key_v1"].encode("ascii"))
        assert verdict.verified is False
        assert verdict.unsigned is False
        assert verdict.reason is not None
        assert "does not verify" in verdict.reason

    def test_a_doctored_committed_meta_refuses_by_name(self):
        fixture = _load("segment-seal.json")
        meta = dict(fixture["meta"])
        meta["receipt_count"] = meta["receipt_count"] + 1
        verdict = verify_seal_meta(meta, fixture["public_key_pem"].encode("ascii"))
        assert verdict.verified is False
        assert verdict.reason is not None


# ---------------------------------------------------------------------------
# Audit-chain and SCITT anchor fixtures
# ---------------------------------------------------------------------------


class TestAuditChainAndAnchorFixtures:
    def test_audit_chain_fixture_verifies_signed(self, tmp_path):
        fixture = _load("audit-chain.json")
        verifier = AuditVerifier(public_key_pem=fixture["public_key_pem"].encode("ascii"))
        report = verifier.verify_chain(
            _write_chain(tmp_path, "audit-chain.jsonl", fixture["chain"])
        )
        assert report.valid is True, report.errors
        assert report.signed_mode == "signed"
        assert report.event_count == fixture["expected"]["event_count"]
        assert report.checkpoint_count == fixture["expected"]["checkpoint_count"]
        head = compute_chain_head(_write_chain(tmp_path, "head.jsonl", fixture["chain"]))
        assert head.index == fixture["expected"]["head_index"]

    def test_anchor_statement_fixture_is_anchored_against_its_chain(self, tmp_path):
        fixture = _load("anchor-statement.json")
        chain_path = _write_chain(tmp_path, "audit-chain.jsonl", fixture["chain"])
        statement = {"statement": fixture["statement"], "signature": fixture["signature"]}
        check = verify_transparency_anchor(chain_path, statement, chain_id=fixture["chain_id"])
        assert check.status == STATUS_ANCHORED, check.reasons
        assert check.chain_head.index == fixture["expected"]["head_index"]
        assert check.chain_head.hash == fixture["expected"]["head_hash"]

    def test_anchor_statement_refuses_a_rolled_back_chain(self, tmp_path):
        fixture = _load("anchor-statement.json")
        lines = fixture["chain"]
        event_positions = [
            i for i, ln in enumerate(lines) if json.loads(ln).get("event") is not None
        ]
        rolled_back = _drop(lines, event_positions[-1])
        path = _write_chain(tmp_path, "rolled-back.jsonl", rolled_back)
        statement = {"statement": fixture["statement"], "signature": fixture["signature"]}
        check = verify_transparency_anchor(path, statement, chain_id=fixture["chain_id"])
        assert check.status == STATUS_DIGEST_MISMATCH, check.reasons


def _drop(lines: list[str], drop_index: int) -> list[str]:
    return [ln for i, ln in enumerate(lines) if i != drop_index]


def _last_receipt_hash(fixture: dict) -> str:
    return fixture["expected"]["receipt_hashes"][-1]


# ---------------------------------------------------------------------------
# Transparency-log fixtures (registration proofs + epoch checkpoints)
# ---------------------------------------------------------------------------


class TestTransparencyLogFixtures:
    def test_inclusion_proof_fixture_verifies_against_the_pinned_operator_key(self):
        fixture = _load("transparency-log.json")
        result = verify_log_inclusion(
            fixture["inclusion_proof"],
            operator_public_key_pem=fixture["operator_public_key_pem"],
            org=fixture["org"],
        )
        assert result.status == STATUS_LOG_INCLUDED, result.reasons
        assert result.size == fixture["expected"]["size"]
        assert result.head_hash == fixture["expected"]["head_hash"]

    def test_consistency_proof_fixture_verifies_against_the_pinned_operator_key(self):
        fixture = _load("transparency-log.json")
        result = verify_log_consistency(
            fixture["consistency_proof"],
            operator_public_key_pem=fixture["operator_public_key_pem"],
            org=fixture["org"],
        )
        assert result.status == STATUS_LOG_CONSISTENT, result.reasons
        assert result.size == fixture["expected"]["size"]

    def test_checkpoint_fixture_binds_the_retained_epoch_heads(self):
        """The committed checkpoints are exactly the signed heads the
        proofs consume - the byte identity an auditor needs between a
        freshly presented proof and the independently retained epoch
        checkpoint."""
        fixture = _load("transparency-log.json")
        for size in fixture["expected"]["checkpoints_sizes"]:
            decoded = _decode_checkpoint_payload(fixture["checkpoints"][str(size)])
            assert decoded["typ"] == LOG_CHECKPOINT_TYP
            assert decoded["payload"]["size"] == size
            assert decoded["payload"]["org"] == fixture["org"]
        assert fixture["inclusion_proof"]["checkpoint_jws"] == fixture["checkpoints"]["5"]
        assert fixture["consistency_proof"]["from_checkpoint_jws"] == fixture["checkpoints"]["3"]
        assert fixture["consistency_proof"]["to_checkpoint_jws"] == fixture["checkpoints"]["5"]
        head = _decode_checkpoint_payload(fixture["checkpoints"]["5"])["payload"]["head_hash"]
        assert head == fixture["expected"]["head_hash"]

    def test_a_doctored_log_fixture_copy_refuses_by_name(self):
        fixture = _load("transparency-log.json")
        doctored = json.loads(json.dumps(fixture["inclusion_proof"]))
        doctored["entries"][0]["receipt_digest"] = _log_helpers._digest("doctored-in-test")
        result = verify_log_inclusion(
            doctored, operator_public_key_pem=fixture["operator_public_key_pem"], org=fixture["org"]
        )
        assert result.status == STATUS_LOG_CHAIN_BROKEN, result.reasons
        assert any("does not bind" in reason for reason in result.reasons), result.reasons

    def test_a_wrong_pinned_key_refuses_the_fixture_checkpoint_by_name(self):
        fixture = _load("transparency-log.json")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        other = (
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )
        result = verify_log_inclusion(
            fixture["inclusion_proof"], operator_public_key_pem=other, org=fixture["org"]
        )
        assert result.status == STATUS_LOG_BAD_SIGNATURE


def _decode_checkpoint_payload(checkpoint_jws: str) -> dict:
    header_b64, payload_b64, _signature_b64 = checkpoint_jws.split(".")

    def _decode(part: str) -> dict:
        from raucle.provenance import _b64url_decode

        return json.loads(_b64url_decode(part).decode("utf-8"))

    return {"typ": _decode(header_b64).get("typ"), "payload": _decode(payload_b64)}


def test_fixture_regeneration_is_byte_stable(tmp_path):
    """The committed fixture set is byte-stable data behind a
    regeneration command: freshly regenerating reproduces every
    committed fixture exactly (pinned once here so the contract stays
    visible). The committed bytes are read, never overwritten."""
    from tests.ledger_support import regenerate_fixtures

    committed = {path.name: path.read_bytes() for path in sorted(Path(FIXTURE_DIR).glob("*.json"))}
    assert set(committed), "the committed fixture set must exist"
    scratch = tmp_path / "regenerated"
    regenerate_fixtures(scratch)
    regenerated = {path.name: path.read_bytes() for path in sorted(scratch.glob("*.json"))}
    assert set(committed) == set(regenerated)
    for name in sorted(committed):
        assert committed[name] == regenerated[name], name
