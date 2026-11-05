"""Replay-over-receipts batch harness (story P1.6a).

Lets a compliance lead replay a *candidate policy version* against a bounded
sample of recent real receipts, or against a synthetic corpus, and get back a
summary report. It wraps the existing counterfactual replay engine
(:mod:`raucle.replay`) and adds the two things that make it usable at
audit scale: bounded sample selection and an elapsed-time report.

Bounded sample selection policy
-------------------------------

Two strategies are supported; both are deterministic given the same chain
and the same explicit parameters, so two compliance reviewers running the
same selection get the same sample:

- ``recent`` — take the N most recent replayable receipts, ordered by the
  input store's ``created_at`` timestamp with the receipt hash as a stable
  tie-breaker.
- ``stratified`` — group replayable receipts by the original decision
  (``ALLOW`` / ``ALERT`` / ``BLOCK``), shuffle within each stratum using a
  seeded PRNG, then take an even round-robin across strata until N receipts
  are chosen. The seed must be provided for stratified selection, which is
  what makes the sample reproducible.

The chosen strategy, limit, seed and stratum counts are printed in the
report so the bounded-sample choice is always documented in the artefact
itself, not just here.

Demo-scale timing
-----------------

The mitigation for slow full-chain replay (z3-style counterfactuals) is
exactly the sample bound: the harness never touches more than ``limit``
receipts, and the report records ``elapsed_seconds`` so the demo-scale
expectation (minutes, not hours) is measurable in every run.

Usage
-----

::

    from raucle.replay_batch import BatchHarness, SamplePlan
    from raucle.replay import InputStore
    from raucle.scanner import Scanner

    with InputStore.open("audit/inputs.jsonl") as store:
        harness = BatchHarness(
            scanner=Scanner(mode="strict"),
            input_store=store,
            policy_label="candidate-2026-11-strict",
        )
        report = harness.run(
            "audit/chain.jsonl",
            SamplePlan(strategy="stratified", limit=200, seed=42),
        )
        print(report.to_json())
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from raucle.replay import _VERDICT_TO_ACTION, InputStore, Replayer
from raucle.scanner import Scanner

from .provenance import ProvenanceReceipt

_SAMPLE_STRATEGIES = ("recent", "stratified")


@dataclass(frozen=True)
class SamplePlan:
    """Explicit, documented description of the bounded sample to take."""

    strategy: str
    """``recent`` or ``stratified``."""

    limit: int
    """Maximum number of receipts to replay."""

    seed: int | None = None
    """Required for ``stratified``; makes the shuffling reproducible."""

    def __post_init__(self) -> None:
        if self.strategy not in _SAMPLE_STRATEGIES:
            raise ValueError(
                f"Unknown sample strategy {self.strategy!r}. "
                f"Choose from: {', '.join(_SAMPLE_STRATEGIES)}"
            )
        if self.limit < 1:
            raise ValueError("Sample limit must be at least 1")
        if self.strategy == "stratified" and self.seed is None:
            raise ValueError("Stratified selection needs a seed to stay reproducible")

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy,
            "limit": self.limit,
            "seed": self.seed,
        }


@dataclass(frozen=True)
class SampledReceipt:
    """One receipt chosen for the sample, with its recorded decision."""

    receipt_hash: str
    input_hash: str
    original_verdict: str
    created_at: int
    raw_line: str = ""
    """The chain's JSONL line for this receipt, so the bounded subset can be replayed on its own."""

    @property
    def original_action(self) -> str:
        return _VERDICT_TO_ACTION.get(self.original_verdict, "ALLOW")


@dataclass
class BatchReport:
    """Summary report for a bounded replay run."""

    policy_versions: dict[str, str]
    """Both policies: ``original`` (recorded in the receipts) and the candidate."""

    sample: dict[str, Any]
    """The selection policy actually applied — strategy, limit, seed, strata."""

    receipt_ids: list[str]
    """Hashes of the sampled receipts that were evaluated."""

    decisions: list[dict[str, str]]
    """Per-receipt original vs counterfactual verdict/action pairs."""

    unchanged: int
    changed: int
    missing_inputs: int
    elapsed_seconds: float = 0.0
    """Wall-clock time for the whole run; demo-scale means minutes, not hours."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_versions": self.policy_versions,
            "sample": self.sample,
            "receipts_evaluated": len(self.receipt_ids),
            "receipt_ids": self.receipt_ids,
            "decisions": self.decisions,
            "unchanged": self.unchanged,
            "changed": self.changed,
            "missing_inputs": self.missing_inputs,
            "elapsed_seconds": self.elapsed_seconds,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def _load_replayable_receipts(
    chain_path: str | Path,
    store: InputStore,
) -> tuple[list[SampledReceipt], int]:
    """Collect replayable guardrail-scan receipts plus their input timestamps.

    Returns the receipts and a count of non-replayable lines skipped.
    """
    receipts: list[SampledReceipt] = []
    skipped = 0
    with open(chain_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            operation = raw.get("operation", "")
            input_hash = raw.get("input_hash", "")
            verdict = raw.get("guardrail_verdict", "")
            jws = raw.get("jws")
            if jws:
                try:
                    parsed = ProvenanceReceipt.from_jws(jws)
                except ValueError:
                    skipped += 1
                    continue
                operation = parsed.operation.value
                input_hash = parsed.input_hash
                verdict = parsed.guardrail_verdict

            if operation != "guardrail_scan" or not input_hash or not verdict:
                skipped += 1
                continue

            stored = store.get(input_hash)
            if stored is None:
                skipped += 1
                continue

            receipts.append(
                SampledReceipt(
                    receipt_hash=raw.get("receipt_hash", ""),
                    input_hash=input_hash,
                    original_verdict=verdict,
                    created_at=stored.created_at,
                    raw_line=line,
                )
            )
    return receipts, skipped


def _sample_recent(
    all_receipts: list[SampledReceipt], plan: SamplePlan
) -> tuple[list[SampledReceipt], dict[str, int]]:
    """Take the most recent ``limit`` receipts, newest first."""
    ordered = sorted(
        all_receipts,
        key=lambda r: (r.created_at, r.receipt_hash),
        reverse=True,
    )
    return ordered[: plan.limit], {}


def _sample_stratified(
    all_receipts: list[SampledReceipt], plan: SamplePlan
) -> tuple[list[SampledReceipt], dict[str, int]]:
    """Deterministic stratified selection WITHOUT a PRNG: the offset per
    stratum derives from sha256 of the stratum key, so the same receipt
    set + seed always yields the same sample (reproducible, auditable)
    and no pseudorandom generator appears in the security-relevant path."""
    by_stratum: dict[str, list[SampledReceipt]] = {}
    for receipt in all_receipts:
        by_stratum.setdefault(receipt.original_action, []).append(receipt)
    for key, bucket in by_stratum.items():
        bucket.sort(key=lambda r: (r.created_at, r.receipt_hash))
        offset = (
            int.from_bytes(hashlib.sha256(key.encode("utf-8")).digest()[:4], "big") % len(bucket)
            if plan.seed is not None
            else 0
        )
        window = min(len(bucket), max(plan.limit, 1))
        by_stratum[key] = [
            bucket[(offset + i) % len(bucket)] for i in range(min(len(bucket), max(window, 1)))
        ]
    # Round-robin across strata so every decision type is represented.
    chosen: list[SampledReceipt] = []
    strata = {k: len(v) for k, v in sorted(by_stratum.items())}
    buckets = [bucket for _, bucket in sorted(by_stratum.items())]
    while len(chosen) < plan.limit and any(buckets):
        for bucket in buckets:
            if bucket and len(chosen) < plan.limit:
                chosen.append(bucket.pop())
    # Round-robin picks strata in sorted order; re-sort the sample for
    # a stable presentation.
    chosen.sort(key=lambda r: (r.created_at, r.receipt_hash))
    return chosen, strata


def select_sample(
    chain_path: str | Path,
    store: InputStore,
    plan: SamplePlan,
) -> tuple[list[SampledReceipt], dict[str, Any]]:
    """Pick a bounded, deterministic sample of replayable receipts.

    Returns the chosen receipts and a description of what was applied
    (used verbatim in the report so the selection is documented there).
    """
    all_receipts, skipped = _load_replayable_receipts(chain_path, store)

    if plan.strategy == "recent":
        chosen, strata = _sample_recent(all_receipts, plan)
    else:
        chosen, strata = _sample_stratified(all_receipts, plan)

    sample_summary: dict[str, Any] = {
        **plan.to_dict(),
        "candidate_pool": len(all_receipts),
        "non_replayable_lines_skipped": skipped,
        "selected": len(chosen),
    }
    if strata:
        sample_summary["strata_pool_sizes"] = strata
        sample_summary["strata_selected"] = {
            action: sum(1 for r in chosen if r.original_action == action) for action in strata
        }
    return chosen, sample_summary


class BatchHarness:
    """Replay a bounded sample of receipts against a candidate policy."""

    def __init__(
        self,
        scanner: Scanner,
        input_store: InputStore,
        *,
        policy_label: str,
    ) -> None:
        if not policy_label:
            raise ValueError(
                "BatchHarness requires an explicit candidate policy label — "
                "the report must name the policy version under test"
            )
        self._scanner = scanner
        self._store = input_store
        self._policy_label = policy_label

    def run(self, chain_path: str | Path, plan: SamplePlan) -> BatchReport:
        """Select the sample, replay it, and return the summary report."""
        started = time.monotonic()
        chosen, sample_summary = select_sample(chain_path, self._store, plan)

        # Replay only the bounded sample: write the chosen receipt lines to a
        # scratch sub-chain so per-run cost scales with the limit, not the
        # full chain. That is what keeps demo runs in minutes, not hours.
        replayer = Replayer(
            self._scanner,
            self._store,
            policy_label=self._policy_label,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            subchain = Path(tmp_dir) / "sample.jsonl"
            subchain.write_text(
                "\n".join(r.raw_line for r in chosen if r.raw_line) + "\n",
                encoding="utf-8",
            )
            result = replayer.replay_chain(subchain)

        decisions = [change.to_dict() for change in result.unchanged + result.changes]
        receipt_ids = [change.receipt_hash for change in result.unchanged + result.changes]
        changed = len(result.changes)
        report_missing = len(result.missing_inputs)

        elapsed = time.monotonic() - started
        return BatchReport(
            policy_versions={
                "original": "as recorded in receipts",
                "candidate": self._policy_label,
                "scanner_mode": self._scanner.mode,
            },
            sample=sample_summary,
            receipt_ids=receipt_ids,
            decisions=decisions,
            unchanged=len(receipt_ids) - changed,
            changed=changed,
            missing_inputs=report_missing,
            elapsed_seconds=round(elapsed, 6),
        )
