"""Indicative proof-cost benchmark: the chain path versus the transparency path.

Issue 342 slice FOUR (ADR 0009 required-validation item: "Benchmark
hash-chain proof size and verification cost at increasing log sizes
before deciding whether Merkle is necessary").

Design constraints, stated up front:

- deterministic workloads only (fixed seeds, fixed content, integer
  epochs); Timings are the ONLY varying quantity and nothing here
  asserts a timing bound - a single measurement is indicative, never a
  performance claim, and no SLO is stated anywhere;
- runs under the ``bench`` pytest marker (``pytest -m bench``);
  the default suite runs it too because it is cheap (well under a
  few seconds) and asserts only verification correctness;
- prints numbers, never prose claims; the comparison table below is
  the whole output a CI log needs.

``proof size`` definitions, per path (proof = the material a verifier
must hold to prove one element, on top of the pinned public key):

- chain path: bytes of the FULL receipt-ledger chain file (every
  receipt), because the offline chain verifier re-verifies the whole
  presented bundle; the provenance receipts are independently signed.
- receipt chain against its seal: bytes of the seal meta sidecar.
- transparency inclusion proof: bytes of the proof object (entries
  from the target to the head plus the signed checkpoint).
- transparency consistency proof: bytes of the proof object.
- SCITT anchored head: bytes of the signed statement over the head.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from raucle.audit import AuditVerifier
from raucle.provenance import ProvenanceVerifier
from raucle.transparency import (
    STATUS_LOG_CONSISTENT,
    STATUS_LOG_INCLUDED,
    compute_chain_head,
    verify_log_consistency,
    verify_log_inclusion,
    verify_transparency_anchor,
)
from tests.ledger_support import (
    chain_lines,
    consistency_proof,
    inclusion_proof,
    log_entries,
    log_operator_key,
    mint_audit_chain,
    mint_receipt_dag_chain,
    seeded_public_pem,
    statement_for_head,
    write_jsonl,
)

pytestmark = pytest.mark.bench

_SCALES = (16, 48, 96)
_LOG_SCALES = (64, 256)
_AUDIT_EVENTS = (64, 512)

_HEADER = "measurement | proof bytes | verify ms"
_ROW = "{name} | {proof_bytes:>11,d} | {ms:>9.2f}"


def _bench_receipt_chains(tmp_path: Path) -> list[dict]:
    rows = []
    seed = "bench-receipt-key"
    identity_pem = seeded_public_pem(seed)
    for count in _SCALES:
        envelopes, key_ids = mint_receipt_dag_chain(depth=count - 1, seed_name=seed)
        lines = chain_lines(envelopes)
        path = write_jsonl(tmp_path / f"bench-chain-{count}.jsonl", lines)
        verifier = ProvenanceVerifier(public_keys={key_ids[0]: identity_pem})
        start = time.perf_counter()
        report = verifier.verify_chain(path)
        elapsed = (time.perf_counter() - start) * 1000.0
        assert report.valid is True, report.errors
        rows.append(
            {
                "name": f"receipt chain: {count} receipts (full-file verify)",
                "proof_bytes": sum(len(line) + 1 for line in lines),
                "ms": elapsed,
            }
        )
    return rows


def _bench_log_proofs() -> list[dict]:
    _priv, op_pem = log_operator_key()
    rows = []
    for size in _LOG_SCALES:
        entries = log_entries(count=size)
        inclusion = inclusion_proof(entries, target=1)
        start = time.perf_counter()
        result = verify_log_inclusion(
            inclusion, operator_public_key_pem=op_pem, org=entries[0]["org"]
        )
        elapsed = (time.perf_counter() - start) * 1000.0
        assert result.status == STATUS_LOG_INCLUDED, result.reasons
        rows.append(
            {
                "name": f"transparency inclusion: log {size}, target 1 (whole-segment proof)",
                "proof_bytes": len(json.dumps(inclusion, ensure_ascii=False)),
                "ms": elapsed,
            }
        )
        mid = inclusion_proof(entries, target=max(1, size // 2))
        start = time.perf_counter()
        result = verify_log_inclusion(mid, operator_public_key_pem=op_pem, org=entries[0]["org"])
        elapsed = (time.perf_counter() - start) * 1000.0
        assert result.status == STATUS_LOG_INCLUDED, result.reasons
        rows.append(
            {
                "name": f"transparency inclusion: log {size}, target {max(1, size // 2)}",
                "proof_bytes": len(json.dumps(mid, ensure_ascii=False)),
                "ms": elapsed,
            }
        )
        consistency = consistency_proof(entries, from_size=max(1, size // 2))
        start = time.perf_counter()
        result = verify_log_consistency(
            consistency, operator_public_key_pem=op_pem, org=entries[0]["org"]
        )
        elapsed = (time.perf_counter() - start) * 1000.0
        assert result.status == STATUS_LOG_CONSISTENT, result.reasons
        rows.append(
            {
                "name": f"transparency consistency: log {size}, from {max(1, size // 2)}",
                "proof_bytes": len(json.dumps(consistency, ensure_ascii=False)),
                "ms": elapsed,
            }
        )
    return rows


def _bench_anchor_head(tmp_path) -> list[dict]:
    rows = []
    for events in _AUDIT_EVENTS:
        seed = "bench-audit-key"
        path = tmp_path / f"bench-audit-{events}.jsonl"
        mint_audit_chain(path, events=events, checkpoint_every=max(1, events // 4), seed_name=seed)
        head = compute_chain_head(path)
        statement = statement_for_head(head)
        verifier = AuditVerifier(public_key_pem=seeded_public_pem(seed))
        start = time.perf_counter()
        report = verifier.verify_chain(path)
        chain_ms = (time.perf_counter() - start) * 1000.0
        assert report.valid is True, report.errors
        start = time.perf_counter()
        check = verify_transparency_anchor(path, statement, chain_id="chain-a")
        anchor_ms = (time.perf_counter() - start) * 1000.0
        assert check.status == "TRANSPARENCY-ANCHORED", check.reasons
        rows.append(
            {
                "name": f"audit hash chain: {events} events (full-file verify)",
                "proof_bytes": path.stat().st_size,
                "ms": chain_ms,
            }
        )
        rows.append(
            {
                "name": f"SCITT anchored head: {events} events (statement check)",
                "proof_bytes": len(json.dumps(statement, ensure_ascii=False)),
                "ms": anchor_ms,
            }
        )
    return rows


def test_bench_proof_cost_chain_versus_transparency(tmp_path):
    """Print the indicative table; assert verification correctness only."""
    rows = _bench_receipt_chains(tmp_path) + _bench_log_proofs() + _bench_anchor_head(tmp_path)
    print()
    print("Indicative proof cost, single measurement on the dev host; no SLO claim.")
    print(_HEADER)
    for row in rows:
        print(_ROW.format(**row))


def test_bench_scales_are_deterministic():
    """The workload constants are pinned so runs are comparable."""
    assert _SCALES == (16, 48, 96)
    assert _LOG_SCALES == (64, 256)
    assert _AUDIT_EVENTS == (64, 512)
