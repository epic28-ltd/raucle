"""Live non-enforcing shadow policy evaluation (issue #344 items 8-12).

ADR 0010 section 4: a live watch/shadow mode MAY evaluate the same
normalized request a live gate call is enforcing against a CANDIDATE
policy, but every observable property that matters is a negative one:

- the authoritative decision is made by the active policy alone; the
  shadow result never feeds it, never replaces it and never forwards it;
- the shadow surface is non-blocking: a submission is put on a bounded
  queue with ``put_nowait`` (overload sheds shadow work BEFORE it could
  ever push back on enforcement, and the shed is a named counter);
- the shadow surface is bounded: bounded queue depth, one bounded
  worker thread, a wall-clock budget per evaluation and a row-capped
  output artifact;
- shadow results are a DISTINCT evidence family: metadata-only rows in
  a dedicated file carrying the ``shadow_eval`` kind and the
  ``policy_shadow/v1`` mode marker. They are never signed gate
  decision receipts, never ``x_sim`` historical-simulation receipts and
  never gate-fault receipts; no signing path, receipt store, audit
  chain or ledger is touched;
- each row binds the candidate policy hash, the active policy digest
  for the request, the request identity (input hash over the canonical
  args JSON, same convention receipts use) and coverage/sampling
  metadata, including the loss counters - so an incomplete sample
  cannot look like complete coverage;
- bounded disclosure holds: rows carry field names, identifiers,
  digests and decisions only. Never argument values, never denial
  reasons (a reason can quote constraint VALUES), never credentials.

Deliberate boundaries of this slice (named, not hidden):

- the shadow evaluator mirrors enforcement's POLICY tier: candidate
  rule matching + constraint evaluation + approval-threshold decision,
  using the same deterministic machinery the gate itself uses. The
  dataflow (chain taint), EQR and session-window legs depend on live
  replayed state and are NOT evaluated here;
- calls refused before policy evaluation (containment, authentication,
  admission, no-policy) do not produce a live-vs-candidate comparison
  and are not submitted;
- cancellation of a CPU-bound evaluation inside the process is not
  possible in Python; an over-budget evaluation is abandoned
  (result dropped, named counter) and the worker moves on, so the
  bound is on enforcement impact (zero), not on the pathological
  evaluation itself;
- the candidate policy is loaded once at boot; changing it requires a
  restart, like the enforcement policy.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import logging
import queue
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Distinct evidence markers: a consumer can distinguish a shadow row from
# every other raucle evidence family by these two fields ALONE.
SHADOW_MODE = "policy_shadow/v1"
SHADOW_RECORD_KIND = "shadow_eval"

# The exact row schema. Any key outside this set is a construction bug and
# the row is refused rather than written (bounded evidence surface).
SHADOW_ROW_KEYS = frozenset(
    {
        "kind",
        "mode",
        "seq",
        "candidate_policy_hash",
        "active_policy_hash",
        "candidate_rule_id",
        "candidate_rule_matched",
        "tool",
        "agent_id",
        "source",
        "destination",
        "trace_id",
        "input_hash",
        "live_decision",
        "shadow_decision",
        "diverges",
        "sampling",
        "evaluated_at",
        "latency_us",
        "queue_wait_us",
    }
)

COUNTER_ROW_WRITTEN = "shadow_row_written"
COUNTER_QUEUE_OVERFLOW = "shadow_queue_overflow"
COUNTER_UNSAMPLED = "shadow_unsampled"
COUNTER_AFTER_CLOSE = "shadow_after_close"
COUNTER_OVER_BUDGET = "shadow_over_budget"
COUNTER_EVAL_ERROR = "shadow_eval_error"
COUNTER_SUBMIT_ERROR = "shadow_submit_error"
COUNTER_RECORD_CAP = "shadow_record_cap"

# Hash convention shared with receipts and simulation receipts: "sha256:".
_HASH_PREFIX = "sha256:"


class ShadowBudgetExceeded(Exception):
    """Wall-clock budget exhausted; the shadow result is dropped, never emitted."""


def _check_deadline(deadline_mono: float) -> None:
    if time.monotonic() > deadline_mono:
        raise ShadowBudgetExceeded("shadow evaluation exceeded its wall-clock budget")


def _sample_selected(trace_id: str, sample_every: int) -> bool:
    """Deterministic coverage filter: sha256 bucketed on the trace id.

    The SAME trace id is always selected or always skipped, so coverage is
    auditable and reproducible from the trace ids alone.
    """
    if sample_every <= 1:
        return True
    digest = hashlib.sha256(str(trace_id).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % sample_every == 0


def _input_hash(args: dict[str, Any]) -> str:
    """Request identity: sha256 over the canonical args JSON.

    Exactly the convention the gate receipts use for ``input_hash``, so a
    shadow row and the receipt of the same call can be correlated without
    ever storing or comparing argument values.
    """
    from raucle.provenance import _canonical_json, _sha256_hex

    return _sha256_hex(_canonical_json(args))


def _evaluate_request(
    request: dict[str, Any], ruleset: Any, *, deadline_mono: float
) -> dict[str, Any]:
    """Deterministic candidate-policy evaluation of ONE normalized request.

    Mirrors the gate's own policy tier: first matching rule for
    (tool, source, destination) wins, taint-participant rules are skipped
    (they are deny-only overlays, never authority), then constraint
    evaluation, then the approval threshold. Reasons are deliberately
    DISCARDED (never stored, never returned): a denial reason can quote
    constraint values and the shadow surface is metadata-only.

    Module-level so tests can patch this one seam to inject slow or
    failing evaluations without touching the gateway.
    """
    from raucle.capability import _check_constraints
    from raucle.policy import check_approval_needed, compile_constraint_dsl

    _check_deadline(deadline_mono)
    tool = request["tool"]
    args = request["args"]
    source = request["source"]
    destination = request["destination"]
    for rule in ruleset.policies:
        _check_deadline(deadline_mono)
        if rule.tool != tool:
            continue
        if (getattr(rule, "participant", "") or "") == "tool_response_taint":
            continue
        if not rule.matches(source, destination):
            continue
        _check_deadline(deadline_mono)
        why = _check_constraints(compile_constraint_dsl(rule.constraints), args)
        if why is not None:
            return {
                "shadow_decision": "deny",
                "candidate_rule_id": getattr(rule, "id", "") or "",
                "candidate_rule_matched": True,
            }
        if check_approval_needed(rule, args):
            # No approval exists in the shadow (and must never be consumed
            # from the live path): the candidate WOULD hold this call.
            return {
                "shadow_decision": "escalate",
                "candidate_rule_id": getattr(rule, "id", "") or "",
                "candidate_rule_matched": True,
            }
        return {
            "shadow_decision": "allow",
            "candidate_rule_id": getattr(rule, "id", "") or "",
            "candidate_rule_matched": True,
        }
    # No candidate rule covers the request: fail closed under the candidate.
    return {"shadow_decision": "deny", "candidate_rule_id": "", "candidate_rule_matched": False}


class ShadowEvaluator:
    """Bounded, non-enforcing live shadow evaluator (worker + bounded queue).

    Enforcement talks ONLY to :meth:`submit`, which is strictly
    non-blocking, never raises onto the enforcement path and drops work
    (with a named counter) before it could ever delay a gate decision.
    """

    def __init__(
        self,
        *,
        candidate_policy_path: str | Path,
        output_path: str | Path,
        queue_maxsize: int = 64,
        budget_ms: int = 200,
        sample_every: int = 1,
        max_records: int = 4096,
        counters_path: str | Path | None = None,
        autostart: bool = True,
    ) -> None:
        if queue_maxsize < 1:
            raise ValueError("shadow_eval_config_invalid: shadow_eval_queue_max must be >= 1")
        if budget_ms < 1:
            raise ValueError("shadow_eval_config_invalid: shadow_eval_budget_ms must be >= 1")
        if sample_every < 1:
            raise ValueError("shadow_eval_config_invalid: shadow_eval_sample_every must be >= 1")
        if max_records < 1:
            raise ValueError("shadow_eval_config_invalid: shadow_eval_max_records must be >= 1")
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=queue_maxsize)
        self._budget_s = budget_ms / 1000.0
        self._sample_every = sample_every
        self._max_records = max_records
        self._output_path = Path(output_path)
        # Candidate policy: loaded once, canonicalized and hashed exactly
        # like the historical simulation path resolves candidates
        # (resolve_candidate_policy), so the same candidate bytes carry the
        # same hash across both modes while the evidence stays distinct.
        from raucle.policy_simulate import resolve_candidate_policy

        canonical, candidate_hash = resolve_candidate_policy(
            candidate_policy_yaml=Path(candidate_policy_path).read_text(encoding="utf-8")
        )
        self._candidate_hash = _HASH_PREFIX + candidate_hash
        from raucle.policy import PolicyFile

        self._ruleset = PolicyFile.from_dict(yaml.safe_load(canonical))
        from raucle.fault_counter import FaultCounter

        self._counter = FaultCounter(counters_path) if counters_path else FaultCounter(None)
        self._records_written = 0
        self._submitted = 0
        self._busy = False
        self._closed = False
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None
        if autostart:
            self._start_worker()

    # ------------------------------------------------------------------
    # Enforcement-facing API (strictly non-throwing, non-blocking)
    # ------------------------------------------------------------------

    def submit(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        agent_id: str,
        source: str,
        destination: str,
        trace_id: str,
        live_decision: str,
        active_policy_hash: str,
    ) -> None:
        """Offer one normalized request for shadow evaluation. Never raises.

        The request is DEEP-COPIED at the boundary: later mutation of the
        caller's ``args`` cannot change the evaluated request, and the
        candidate evaluation can never write back into live state.
        """
        try:
            self._submit_inner(
                tool=tool,
                args=args,
                agent_id=agent_id,
                source=source,
                destination=destination,
                trace_id=trace_id,
                live_decision=live_decision,
                active_policy_hash=active_policy_hash,
            )
        except Exception:
            # Last line of defence: no failure in the shadow surface may
            # reach the enforcement path.
            logger.exception("shadow submission failed (enforcement untouched)")
            with contextlib.suppress(Exception):
                self._count(COUNTER_SUBMIT_ERROR, str(tool))

    def stats(self) -> dict[str, Any]:
        """Coverage and loss counters: an incomplete sample cannot hide."""
        return {
            "mode": SHADOW_MODE,
            "candidate_policy_hash": self._candidate_hash,
            "counters": self._counter.counts()["by_type"],
            "rows_written": self._records_written,
            "submitted": self._submitted,
            "queue_depth": self._queue.qsize(),
            "running": self._worker is not None and self._worker.is_alive(),
            "closed": self._closed,
        }

    def shutdown(self, timeout_s: float = 2.0) -> bool:
        """Stop the worker (drains the bounded queue first). Non-blocking live.

        Returns False when a queued or in-flight evaluation did not finish
        inside the timeout; the worker is a daemon thread either way.
        """
        self._closed = True
        self._stop_event.set()
        worker = self._worker
        if worker is None:
            return True
        if worker is not threading.current_thread():
            worker.join(timeout=timeout_s)
        return not worker.is_alive()

    def flush(self, timeout_s: float = 5.0) -> bool:
        """Drain barrier for tests/operators: wait until the queue is empty
        and the worker is idle. Bounded wait; False on timeout."""
        deadline = time.monotonic() + timeout_s
        while True:
            if self._queue.empty() and not self._busy:
                return True
            if time.monotonic() > deadline:
                return False
            time.sleep(0.01)

    # ------------------------------------------------------------------
    # Internals: one bounded worker, everything guarded
    # ------------------------------------------------------------------

    def _start_worker(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        self._stop_event.clear()
        self._worker = threading.Thread(target=self._run, name="raucle-shadow-eval", daemon=True)
        self._worker.start()

    def _run(self) -> None:
        while True:
            if self._stop_event.is_set() and self._queue.empty():
                return
            try:
                item = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self._busy = True
            try:
                self._process(item)
            finally:
                try:
                    self._queue.task_done()
                finally:
                    self._busy = False

    def _submit_inner(
        self,
        *,
        tool: str,
        args: dict[str, Any],
        agent_id: str,
        source: str,
        destination: str,
        trace_id: str,
        live_decision: str,
        active_policy_hash: str,
    ) -> None:
        if self._closed:
            self._count(COUNTER_AFTER_CLOSE, tool)
            return
        if not _sample_selected(trace_id, self._sample_every):
            self._count(COUNTER_UNSAMPLED, tool)
            return
        snapshot = copy.deepcopy(args)
        try:
            # Strictly non-blocking: an overloaded queue SHEDS shadow work
            # by name instead of pushing back on the enforcement path.
            self._queue.put_nowait(
                {
                    "tool": str(tool),
                    "args": snapshot,
                    "agent_id": str(agent_id),
                    "source": str(source),
                    "destination": str(destination),
                    "trace_id": str(trace_id),
                    "live_decision": str(live_decision),
                    "active_policy_hash": str(active_policy_hash),
                    "submitted_mono": time.monotonic(),
                }
            )
        except queue.Full:
            self._count(COUNTER_QUEUE_OVERFLOW, tool)
            return
        self._submitted += 1

    def _process(self, item: dict[str, Any]) -> None:
        submitted_mono = item.pop("submitted_mono")
        t0 = time.monotonic()
        deadline_mono = t0 + self._budget_s
        try:
            core = _evaluate_request(item, self._ruleset, deadline_mono=deadline_mono)
        except ShadowBudgetExceeded:
            self._count(COUNTER_OVER_BUDGET, item.get("tool", ""))
            return
        except Exception:
            # The exception TYPE is counted (house pattern); the result row
            # is dropped whole - a partial row is never written.
            logger.exception("shadow evaluation failed for tool %s", item.get("tool", ""))
            self._count(COUNTER_EVAL_ERROR, item.get("tool", ""))
            return
        elapsed_s = time.monotonic() - t0
        if elapsed_s > self._budget_s:
            # Completed, but over the published budget: dropped, named.
            self._count(COUNTER_OVER_BUDGET, item.get("tool", ""))
            return
        try:
            row = self._shape_row(item, core, elapsed_s, time.monotonic() - submitted_mono)
        except Exception:
            logger.exception("shadow row shaping failed")
            self._count(COUNTER_EVAL_ERROR, item.get("tool", ""))
            return
        self._append_row(row, item.get("tool", ""))

    def _shape_row(
        self, item: dict[str, Any], core: dict[str, Any], elapsed_s: float, wait_s: float
    ) -> dict[str, Any]:
        row: dict[str, Any] = {
            "kind": SHADOW_RECORD_KIND,
            "mode": SHADOW_MODE,
            "seq": self._records_written + 1,
            "candidate_policy_hash": self._candidate_hash,
            "active_policy_hash": item.get("active_policy_hash", ""),
            "tool": item.get("tool", ""),
            "agent_id": item.get("agent_id", ""),
            "source": item.get("source", ""),
            "destination": item.get("destination", ""),
            "trace_id": item.get("trace_id", ""),
            "input_hash": _input_hash(item.get("args", {})),
            "live_decision": item.get("live_decision", ""),
            "shadow_decision": core["shadow_decision"],
            "candidate_rule_id": core["candidate_rule_id"],
            "candidate_rule_matched": core["candidate_rule_matched"],
            "diverges": core["shadow_decision"] != item.get("live_decision", ""),
            "sampling": {"sample_every": self._sample_every, "selected": True},
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "latency_us": int(elapsed_s * 1e6),
            "queue_wait_us": int(wait_s * 1e6),
        }
        if set(row) != SHADOW_ROW_KEYS or not core:
            raise ValueError("shadow_evidence_shape_refused: row keys left the bounded schema")
        return row

    def _append_row(self, row: dict[str, Any], tool: str) -> None:
        if self._records_written >= self._max_records:
            self._count(COUNTER_RECORD_CAP, tool)
            return
        import json

        line = json.dumps(row, sort_keys=True, ensure_ascii=False)
        with open(self._output_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        self._records_written += 1
        self._count(COUNTER_ROW_WRITTEN, tool)

    def _count(self, fault_type: str, tool: str) -> None:
        try:
            self._counter.increment(fault_type, tool)
        except Exception:
            logger.exception("shadow counter increment failed")


__all__ = [
    "SHADOW_MODE",
    "SHADOW_RECORD_KIND",
    "SHADOW_ROW_KEYS",
    "ShadowBudgetExceeded",
    "ShadowEvaluator",
]
