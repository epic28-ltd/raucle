"""Tamper-class regression tests at the receipt-ledger and transparency layer.

Issue 342 slices TWO (tamper classes) and part of ONE (the matrix's
named evidence): six tamper classes exercised through the EXISTING
verifier APIs - named failures where a mechanism covers the class, and
explicit, documented limit-pins where it does not (the guarantee matrix
``docs/spec/receipt-anchor-map.md`` carries the same split, per ADR
0009's honest-classification doctrine).

Classes and the verifier that responds to each:

- truncation / deletion / withholding: the audit hash chain refuses by
  name (index/prev-hash/checkpoint Merkle refusals), the receipt chain
  refuses unresolvable parent citations, and the segment seal
  reconciliation names a presented tail that is short of its seal;
- reordering: the audit hash chain and the transparency log refuse by
  name; the receipt chain is a collection (honest limit: line order is
  not tamper evidence in that layer, by design);
- rollback (a reconstructed shorter chain): the externally anchored
  head (SCITT statement / expected head / seal receipt_count) refuses
  the rolled-back presentation by name;
- equivocation (two divergent histories from one trust root): the
  anchored-head statement refuses a divergent presentation by name and
  a retained registration proof refuses a forked log entry by name.

No test here claims WORM or immutable storage: receipt persistence is
append-oriented and fsynced; these tests prove only that every
presented tamper is nameable against retained material.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from raucle.audit import AuditVerifier, _canonical_json, _sha256_hex
from raucle.provenance import ProvenanceVerifier
from raucle.receipt_store import verify_seal_meta
from raucle.transparency import (
    STATUS_ANCHORED,
    STATUS_DIGEST_MISMATCH,
    STATUS_LOG_CHAIN_BROKEN,
    STATUS_LOG_CONSISTENT,
    STATUS_LOG_HEAD_MISMATCH,
    STATUS_LOG_INCLUDED,
    compute_chain_head,
    verify_log_consistency,
    verify_log_inclusion,
    verify_transparency_anchor,
)
from tests.ledger_support import (
    FIXTURE_DIR,
    chain_lines,
    identity_for_seed,
    inclusion_proof,
    log_entries,
    log_operator_key,
    mint_audit_chain,
    mint_receipt_dag_chain,
    mint_sealed_segments,
    seeded_public_pem,
    sign_checkpoint,
    statement_for_head,
    write_jsonl,
)
from tests.ledger_support import (
    consistency_proof as make_consistency_proof,
)

RECEIPT_SEED = "receipt-key-a"
AUDIT_SEED = "audit-key"
SEAL_SEED = "seal-key-a"
LOG_ORG = "anchorco"


def _verify_receipts(lines: list[str], tmp_path: Path, seed_name: str = RECEIPT_SEED):
    """Verify a receipt-ledger variant offline through the chain verifier."""
    identity = identity_for_seed(seed_name)
    path = write_jsonl(tmp_path / "receipt-variant.jsonl", lines)
    return ProvenanceVerifier(
        public_keys={identity.key_id: seeded_public_pem(seed_name)}
    ).verify_chain(path)


def _audit_lines(already_minted: Path) -> tuple[list[str], list[int]]:
    """The chain's non-blank lines plus the line positions of its events."""
    lines = [ln for ln in already_minted.read_text().splitlines() if ln.strip()]
    return lines, [i for i, ln in enumerate(lines) if json.loads(ln).get("event") is not None]


def _drop(lines: list[str], drop_index: int) -> list[str]:
    return [ln for i, ln in enumerate(lines) if i != drop_index]


def _recompute_event_hash(event: dict) -> str:
    """The event's own hash over its canonical bytes (hash field removed)."""
    body = {k: v for k, v in event.items() if k != "hash"}
    return _sha256_hex(_canonical_json(body))


# ---------------------------------------------------------------------------
# Class 1: the receipt chain (the JWS provenance receipt ledger)
# ---------------------------------------------------------------------------


class TestReceiptLedgerTamperClasses:
    """The receipt collection layer: per-receipt signature, hash and DAG
    checks through ProvenanceVerifier.verify_chain - and its honest
    limits, pinned and named."""

    def test_deleting_a_cited_parent_refuses_by_name(self, tmp_path):
        envelopes, _ids = mint_receipt_dag_chain(depth=3, seed_name=RECEIPT_SEED)
        deleted = [env for env in envelopes if env["receipt_hash"] != envelopes[2]["receipt_hash"]]
        report = _verify_receipts(chain_lines(deleted), tmp_path)
        assert report.valid is False
        assert any("not found in chain" in err for err in report.errors), report.errors

    def test_withholding_the_parent_unresolves_the_presented_child(self, tmp_path):
        """The withholding class at this layer: a presenter who keeps a
        downstream receipt but withholds its cited parent cannot
        resolve the citation - a named DAG refusal, never a pass."""
        envelopes, _ids = mint_receipt_dag_chain(depth=3, seed_name=RECEIPT_SEED)
        report = _verify_receipts(chain_lines([envelopes[3]]), tmp_path)
        assert report.valid is False
        assert any("not found in chain" in err for err in report.errors), report.errors

    def test_reordering_receipt_lines_is_not_tamper_evident_in_this_layer(self, tmp_path):
        """Honest-limit pin (GAP row in the matrix): the receipt chain is
        a collection of independently signed receipts plus a parent DAG;
        presentation order is not tamper evidence in this layer. Order
        evidence lives in the audit hash chain (record indices) and the
        transparency log (entry sequences). If this layer gains order
        semantics, this pin and its matrix row must be updated."""
        envelopes, _ids = mint_receipt_dag_chain(depth=2, seed_name=RECEIPT_SEED)
        lines = chain_lines(envelopes)
        report = _verify_receipts([lines[0], lines[2], lines[1]], tmp_path)
        assert report.valid is True, report.errors

    def test_truncating_the_collection_verifies_the_remaining_records(self, tmp_path):
        """Honest-limit pin (GAP row): a shorter valid collection passes
        this layer's verifier. Receipt-completeness is an anchor matter:
        the seal reconciliation, the anchored head and the log's
        retained proofs are the named controls."""

        envelopes, _ids = mint_receipt_dag_chain(depth=3, seed_name=RECEIPT_SEED)
        report = _verify_receipts(chain_lines(envelopes)[:2], tmp_path)
        assert report.valid is True, report.errors
        assert report.receipt_count == 2

    def test_two_divergent_collections_from_one_identity_both_verify(self, tmp_path):
        """Honest-limit pin (GAP row): two divergent histories minted
        under one trust root (the same signing identity) each verify
        alone; this layer binds receipt content, not which history is
        canonical. The anchored-head class below is where equivocation
        is refused by name."""

        def _fork_line(suffix: str) -> str:
            from raucle.provenance import Operation, ProvenanceReceipt, hash_text

            identity = identity_for_seed(RECEIPT_SEED)
            receipt = ProvenanceReceipt(
                agent_id=identity.agent_id,
                agent_key_id=identity.key_id,
                operation=Operation.USER_INPUT,
                input_hash=hash_text(suffix),
                issued_at=1_700_000_999,
            )
            receipt.sign(identity)
            return json.dumps(
                {"receipt_hash": receipt.receipt_hash, "jws": receipt.jws}, ensure_ascii=False
            )

        first = _verify_receipts([_fork_line("fork-a")], tmp_path)
        second = _verify_receipts([_fork_line("fork-b")], tmp_path)
        assert first.valid is True and second.valid is True


# ---------------------------------------------------------------------------
# Class 2: the audit hash chain (HashChainSink ledger)
# ---------------------------------------------------------------------------


class TestAuditChainTamperClasses:
    """Interior deletion, reordering and rollback at the hash-chain layer."""

    def _verify(self, tmp_path: Path, pem: bytes, lines: list[str], expected_head=None):
        path = write_jsonl(tmp_path / "audit-variant.jsonl", lines)
        return AuditVerifier(public_key_pem=pem).verify_chain(path, expected_head=expected_head)

    def test_deleting_a_middle_event_refuses_by_name(self, tmp_path):
        pem, _sink = mint_audit_chain(tmp_path / "chain.jsonl", seed_name=AUDIT_SEED)
        lines, event_positions = _audit_lines(tmp_path / "chain.jsonl")
        mid = event_positions[2]
        report = self._verify(tmp_path, pem, _drop(lines, mid))
        assert report.valid is False
        joined = " | ".join(report.errors)
        assert "index mismatch" in joined, report.errors
        assert "prev_hash mismatch" in joined, report.errors

    def test_swapping_two_event_records_refuses_by_name(self, tmp_path):
        pem, _sink = mint_audit_chain(tmp_path / "chain.jsonl", seed_name=AUDIT_SEED)
        lines, event_positions = _audit_lines(tmp_path / "chain.jsonl")
        i, j = event_positions[0], event_positions[1]
        swapped = list(lines)
        swapped[i], swapped[j] = swapped[j], swapped[i]
        report = self._verify(tmp_path, pem, swapped)
        assert report.valid is False
        joined = " | ".join(report.errors)
        assert "index mismatch" in joined, report.errors
        assert "prev_hash mismatch" in joined, report.errors

    def test_deleting_a_middle_event_breaks_the_checkpoint_binding(self, tmp_path):
        """Why interior deletion is caught: the chain's signed
        checkpoints bind their index and Merkle root, so removing an
        interior event makes every later checkpoint refuse to match the
        chain head it no longer sits on."""
        pem, _sink = mint_audit_chain(tmp_path / "chain.jsonl", seed_name=AUDIT_SEED)
        lines, event_positions = _audit_lines(tmp_path / "chain.jsonl")
        report = self._verify(tmp_path, pem, _drop(lines, event_positions[2]))
        assert report.valid is False
        joined = " | ".join(report.errors)
        assert "checkpoint at index" in joined and "does not match chain head" in joined, (
            report.errors
        )

    def test_rolled_back_chain_passes_alone_and_refuses_against_the_retained_head(self, tmp_path):
        """The rollback class end to end: a reconstructed shorter chain -
        an earlier, fully checkpointed snapshot under the same trust
        root - verifies alone (the bare verifier attests only what it
        sees), and is refused by name once the auditor pins the
        retained head (AUDIT-TRUNC)."""
        pem, _sink = mint_audit_chain(tmp_path / "chain.jsonl", seed_name=AUDIT_SEED)
        lines, event_positions = _audit_lines(tmp_path / "chain.jsonl")
        retained_head = compute_chain_head(tmp_path / "chain.jsonl")
        keep = set(event_positions[:4])
        keep.update(i for i, ln in enumerate(lines) if json.loads(ln).get("chain_meta"))
        keep.update(
            i
            for i, ln in enumerate(lines)
            if json.loads(ln).get("checkpoint") and json.loads(ln).get("index", 0) <= 4
        )
        rolled_back = [ln for i, ln in enumerate(lines) if i in keep]
        alone = self._verify(tmp_path, pem, rolled_back)
        assert alone.valid is True, alone.errors
        report = self._verify(
            tmp_path,
            pem,
            rolled_back,
            expected_head={"index": retained_head.index, "hash": retained_head.hash},
        )
        assert report.valid is False
        joined = " | ".join(report.errors)
        assert "head index mismatch" in joined, report.errors
        assert "AUDIT-TRUNC" in joined, report.errors


# ---------------------------------------------------------------------------
# Class 3: anchored-head rollback and equivocation (SCITT + hosted log)
# ---------------------------------------------------------------------------


class TestAnchoredRollbackAndEquivocation:
    """The anchor layer where rollback and equivocation are refused by
    name: the SCITT head statement and the hosted log's retained proofs."""

    def _anchored(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        pem, _sink = mint_audit_chain(path, seed_name=AUDIT_SEED)
        del pem, _sink
        lines, _positions = _audit_lines(path)
        head = compute_chain_head(path)
        return lines, statement_for_head(head)

    def _event_positions_after(self, lines: list[str]) -> list[int]:
        return [i for i, ln in enumerate(lines) if json.loads(ln).get("event") is not None]

    def test_rolled_back_chain_is_digest_mismatch_against_the_anchored_head(self, tmp_path):
        lines, statement = self._anchored(tmp_path)
        truncated = _drop(lines, self._event_positions_after(lines)[-1])
        path = write_jsonl(tmp_path / "rolled-back.jsonl", truncated)
        check = verify_transparency_anchor(path, statement, chain_id="chain-a")
        assert check.status == STATUS_DIGEST_MISMATCH, check.reasons
        assert any("anchored head hash" in reason for reason in check.reasons), check.reasons

    def test_divergent_chain_from_one_trust_root_is_digest_mismatch(self, tmp_path):
        """Equivocation: a second, divergent history signed by the SAME
        trust root. The verifier holds the anchored head of history A;
        presenting history B - which diverges at history A's final,
        anchored record - is refused by name."""
        _lines, statement = self._anchored(tmp_path)
        divergent_path = tmp_path / "divergent.jsonl"
        mint_audit_chain(divergent_path, events=5, seed_name=AUDIT_SEED)
        lines, event_positions = _audit_lines(divergent_path)
        last = event_positions[-1]
        event = json.loads(lines[last])
        event["event"]["note"] = "equivocated-note"
        event["hash"] = _recompute_event_hash(event)
        lines[last] = json.dumps(event, ensure_ascii=False)
        check = verify_transparency_anchor(
            write_jsonl(tmp_path / "equivocated.jsonl", lines), statement, chain_id="chain-a"
        )
        assert check.status == STATUS_DIGEST_MISMATCH, check.reasons

    def test_the_head_anchor_does_not_detect_middle_event_deletion(self, tmp_path):
        """Honest limit (matrix row): an anchored head binds the FINAL
        record's digest. Deleting a MIDDLE event leaves the head index
        and hash untouched, so the head-level anchor alone still answers
        TRANSPARENCY-ANCHORED. Interior completeness is the audit hash
        chain's own verifier - record indices, prev hashes and the
        checkpoint Merkle roots (proven right above in
        TestAuditChainTamperClasses)."""
        lines, statement = self._anchored(tmp_path)
        interior_deleted = _drop(lines, self._event_positions_after(lines)[2])
        path = write_jsonl(tmp_path / "interior-deleted.jsonl", interior_deleted)
        check = verify_transparency_anchor(path, statement, chain_id="chain-a")
        assert check.status == STATUS_ANCHORED, check.reasons

    def test_a_receipt_segment_is_not_a_conformable_anchor_artifact(self, tmp_path):
        """Named gap (matrix row): the anchoring machinery's head parser
        consumes the HashChainSink event format only; a receipt-ledger
        segment ({"receipt_hash", "jws"} lines) is refused. A receipt
        ledger head cannot be anchored today without a conformable
        wrapper (ADR 0009 required-validation item)."""
        envelopes, _ids = mint_receipt_dag_chain(depth=1, seed_name=RECEIPT_SEED)
        seg = write_jsonl(tmp_path / "seg.jsonl", chain_lines(envelopes))
        with pytest.raises(ValueError, match="refusing to anchor"):
            compute_chain_head(seg)

    def test_rewritten_log_history_contradicts_the_retained_registration_proof(self, tmp_path):
        """Log rollback: the auditor retains the registration proof that
        (org, sequence 3) carries digest D. A history rewritten to claim
        a different digest at that sequence is refused by name."""
        from tests.test_transparency_log_verify import _digest

        entries = log_entries(count=5)
        _priv, op_pem = log_operator_key()
        original = inclusion_proof(entries, target=1)
        assert (
            verify_log_inclusion(original, operator_public_key_pem=op_pem).status
            == STATUS_LOG_INCLUDED
        )
        rewritten = [dict(entry) for entry in entries]
        rewritten[2]["receipt_digest"] = _digest("rewritten-history-3")
        from tests.test_transparency_log_verify import compute_log_entry_hash as _cleh

        for seq in range(3, 6):
            if seq == 3:
                rewritten[2]["entry_hash"] = _cleh(rewritten[2])
            else:
                rewritten[seq - 1]["prev_hash"] = rewritten[seq - 2]["entry_hash"]
                rewritten[seq - 1]["entry_hash"] = _cleh(rewritten[seq - 1])
        rolled = _inclusion_proof(rewritten, target=1, iat=1_700_300_000)
        check = verify_log_inclusion(
            rolled,
            operator_public_key_pem=op_pem,
            org=LOG_ORG,
            expect_digest=_digest("receipt-anchorco-3"),
        )
        assert check.status == STATUS_LOG_HEAD_MISMATCH, check.reasons
        assert any("different digest" in reason for reason in check.reasons), check.reasons

    def test_forked_log_contradicting_a_retained_proof_is_refused_by_name(self, tmp_path):
        """Log equivocation: a forked history from the same pinned
        operator key. Against a retained (sequence 1, digest D) proof,
        the fork is refused by name; without retained material the next
        test's honest limit applies."""
        from tests.test_transparency_log_verify import _digest, _entry

        entries = log_entries(count=3)
        _priv, op_pem = log_operator_key()
        retained = inclusion_proof(entries, target=1)
        prev = "sha256:" + "0" * 64
        forked = []
        for seq in range(1, 4):
            entry = _entry(LOG_ORG, seq, prev, _digest(f"fork-{seq}"), 1_700_100_000 + seq)
            forked.append(entry)
            prev = entry["entry_hash"]
        forked_proof = _inclusion_proof(forked, target=1, iat=1_700_400_000)
        ok = verify_log_inclusion(retained, operator_public_key_pem=op_pem)
        fork = verify_log_inclusion(
            forked_proof,
            operator_public_key_pem=op_pem,
            org=LOG_ORG,
            expect_digest=_digest("receipt-anchorco-1"),
        )
        assert ok.status == STATUS_LOG_INCLUDED, ok.reasons
        assert fork.status == STATUS_LOG_HEAD_MISMATCH, fork.reasons

    def test_two_forks_without_retained_material_both_verify(self, tmp_path):
        """Honest-limit pin (GAP row): with NO retained registration
        proof (and no retained-checkpoint comparison in the verifier),
        two forks signed by the same pinned key each verify alone. The
        documented control is independent retention compared against
        retained material - a follow-up would add that comparison to the
        verifier API; until then this layer cannot name a fork alone."""
        from tests.test_transparency_log_verify import _digest, _entry

        _genesis = "sha256:" + "0" * 64
        _priv, op_pem = log_operator_key()
        entries = log_entries(count=3)
        prev = _genesis
        forked = []
        for seq in range(1, 4):
            entry = _entry(LOG_ORG, seq, prev, _digest(f"fork-{seq}"), 1_700_100_000 + seq)
            forked.append(entry)
            prev = entry["entry_hash"]
        original = verify_log_inclusion(
            inclusion_proof(entries, target=1), operator_public_key_pem=op_pem
        )
        fork = verify_log_inclusion(
            _inclusion_proof(forked, target=1, iat=1_700_400_000), operator_public_key_pem=op_pem
        )
        assert original.status == STATUS_LOG_INCLUDED, original.reasons
        assert fork.status == STATUS_LOG_INCLUDED, fork.reasons

    def test_consistency_growth_binding_refuses_a_rewritten_applied_segment(self, tmp_path):
        """The growth binding: a presented appended segment that does not
        grow from the from-checkpoint's signed head is refused by name."""
        from tests.test_transparency_log_verify import compute_log_entry_hash as _cleh

        entries = log_entries(count=5)
        _priv, op_pem = log_operator_key()
        proof = make_consistency_proof(entries, from_size=2)
        assert verify_log_consistency(proof, operator_public_key_pem=op_pem).status == (
            STATUS_LOG_CONSISTENT
        )
        doctored = [dict(entry) for entry in proof["entries"]]
        doctored[0]["prev_hash"] = "sha256:" + "f" * 64
        doctored[0]["entry_hash"] = _cleh(doctored[0])
        check = verify_log_consistency(
            dict(proof, entries=doctored), operator_public_key_pem=op_pem
        )
        assert check.status == STATUS_LOG_CHAIN_BROKEN, check.reasons


def _inclusion_proof(entries: list[dict], *, target: int, iat: int) -> dict:
    """An inclusion proof with a caller-chosen checkpoint iat."""
    head = entries[-1]
    return {
        "org": head["org"],
        "sequence": entries[target - 1]["sequence"],
        "entries": entries[target - 1 :],
        "size": head["sequence"],
        "head_hash": head["entry_hash"],
        "checkpoint_jws": sign_checkpoint(
            org=head["org"],
            size=head["sequence"],
            head_hash=head["entry_hash"],
            epoch=head["sequence"],
            iat=iat,
        ),
    }


# ---------------------------------------------------------------------------
# Class 4: segment seals (the reconciliation above the crash lane)
# ---------------------------------------------------------------------------


class TestSealReconciliation:
    """A sealed segment is verified against its seal meta, then
    reconciled against the presented segment content."""

    def _sealed(self, tmp_path: Path, *, ledger_depth: int = 3, present_depth: int = 1):
        envelopes, _ids = mint_receipt_dag_chain(depth=ledger_depth, seed_name=RECEIPT_SEED)
        lines = chain_lines(envelopes)
        (meta,) = mint_sealed_segments(tmp_path / "segments", [lines], seed_names=[SEAL_SEED])
        presented = write_jsonl(tmp_path / "presented.jsonl", lines[: present_depth + 1])
        return meta, len(lines), presented

    def test_presented_segment_shorter_than_its_seal_is_nameable(self, tmp_path):
        """Tail withholding at the segment boundary: the seal itself
        still verifies (it records the seal-time truth), and the
        reconciliation of the presented content against the seal names
        the mismatch on both the receipt count and the final hash."""
        meta, sealed_count, presented = self._sealed(tmp_path)
        verdict = verify_seal_meta(meta, seeded_public_pem(SEAL_SEED))
        assert verdict.verified is True, verdict.reason
        presented_lines = [ln for ln in presented.read_text().splitlines() if ln.strip()]
        assert len(presented_lines) < sealed_count
        assert meta["receipt_count"] == sealed_count
        assert meta["receipt_count"] != len(presented_lines)
        last_presented = json.loads(presented_lines[-1])["receipt_hash"]
        assert meta["last_receipt_hash"] != last_presented

    def test_forged_seal_meta_over_a_truncated_segment_refuses_by_name(self, tmp_path):
        """An attacker who rewrites the seal meta to match the withheld
        tail (holding no sealing key) fails the seal's own signature."""
        meta, sealed_count, _presented = self._sealed(tmp_path)
        forged = dict(meta)
        assert sealed_count > 1
        forged["receipt_count"] = sealed_count - 1
        verdict = verify_seal_meta(forged, seeded_public_pem(SEAL_SEED))
        assert verdict.verified is False
        assert verdict.reason is not None and "does not verify" in verdict.reason

    def test_committed_seal_fixture_still_reconciles(self):
        """Currency: the committed seal fixture verifies offline."""
        fixture = json.loads((Path(FIXTURE_DIR) / "segment-seal.json").read_text(encoding="utf-8"))
        verdict = verify_seal_meta(fixture["meta"], fixture["public_key_pem"].encode("ascii"))
        assert verdict.verified is True, verdict.reason
        assert len(fixture["segment"]) == fixture["expected"]["receipt_count"]
