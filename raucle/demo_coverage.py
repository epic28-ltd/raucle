"""Demo-mode coverage surface: the receipted-share metric contract, read-only.

The OSS receipted-share coverage engine and its ``GET /coverage/{org}``
endpoint live in the raucle-agent-assurance correlation service
(``oaa_correlation.coverage``, served by the investigation UI) — deliberately
NOT in this gateway, which holds only one evidence plane. This module is the
gateway-side demo view of the SAME metric contract, computed over the demo
gateway's own receipt stream: in a single-demo-org the gate's receipts ARE
the correlated ground truth, because every attributable action an agent drove
through this gate minted a signed receipt.

Buckets follow the assurance contract's documented semantics (ADR-0002
reconciliation states), applied to the terminal receipt plane a gate holds:

- ``receipted``: receipts counted via a bound ``x_gate.trace_id`` — the
  counting basis the assurance endpoint itself states. A receipt whose
  trace id is unbound (the ``check_tool_call`` API accepts an empty
  ``trace_id``; the HTTP gate generates one for every call) never touches
  the action number — exactly like the assurance engine's receipt-side-only
  records — and is disclosed in ``states`` under its
  ``(trace id not recorded)`` label instead of vanishing.
- ``out_of_gate``: never computed at this vantage and never claimed as
  zero: the gate cannot observe an action that never reached it. Observed-
  but-unreceipted actions need a trace-side or custody vantage (ADR-0004);
  the assurance service computes those as bypass_candidates.
- ``pending``: never computed on a terminal receipt plane (every receipt in
  the store is terminal at mint); grace-open windows are a trace-side
  reconciliation concept.

Flags (bypass_candidates, shadow_agents, uninstrumented_tools) carry their
documented semantics but are NOT computed here, and no zero is claimed where
cross-vantage evidence is absent: each flag states what vantage would be
required to compute it.

Determinism: the aggregation is a pure function of the enumerated rows and
reads no wall clock (no "now"-anchored window; the stream is read bounded,
newest-first). Two runs over the same receipt state serialise
byte-identically (asserted in tests).

Bounded disclosure: the surface carries aggregate counts, tool and agent
identifiers only — entries can quote constraint values, so denial reasons
never enter any row, and receipt payload detail stays out. The demo traffic
is simulated; the receipts are real gate output on that traffic.
"""

from __future__ import annotations

import base64 as _b64
import contextlib
import json
import os
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from fastapi import Header, HTTPException

from raucle.demo_ops import SIMULATED_LABEL

__all__ = [
    "DEMO_COVERAGE_ROW_CAP",
    "METRIC",
    "SCHEMA_VERSION",
    "aggregate_coverage",
    "build_demo_coverage",
    "register_demo_coverage_routes",
]

SCHEMA_VERSION = "raucle.demo.coverage/v1"
METRIC = "receipted_share"

#: Newest-first row bound for the aggregation; the truncation is disclosed
#: in the response so a bound can never silently shape the headline number.
DEMO_COVERAGE_ROW_CAP = 2000

_UNKNOWN_TOOL_LABEL = "(tool not recorded)"
_UNKNOWN_AGENT_LABEL = "(agent not recorded)"
_UNKNOWN_TRACE_LABEL = "(trace id not recorded)"

_BASIS = (
    "observed agent actions = the demo gate's own attributable receipts: "
    "every gate-decided action minted a signed receipt, so this single-org "
    "receipt stream is the correlated ground truth of the demo plane; "
    "receipts counted via bound x_gate.trace_id only"
)

_UNAVAILABLE_NOTE = (
    "coverage is unavailable here, never zero: no gate receipts on this "
    "plane yet, and absence of receipts is not a coverage result"
)

_OUT_OF_GATE_VANTAGE = (
    "not computed at this vantage: the gate cannot observe an action that "
    "never reached it, so the bucket stays a disclosed 0, never folded into "
    "receipted to inflate the number"
)

_PENDING_VANTAGE = (
    "not computed at this vantage: every stored receipt is terminal at "
    "mint, so the bucket stays a disclosed 0; grace-open windows exist only "
    "on the trace-reconciliation plane"
)

#: The three buckets of the receipted-share contract as documented in the
#: assurance service (ADR-0002 reconciliation states), each carrying what a
#: gate-side vantage can honestly compute for it.
BUCKETS: tuple[dict[str, str], ...] = (
    {
        "bucket": "receipted",
        "definition": (
            "the action's correlation state carries a gate receipt: matched, "
            "duplicate, late_arrival or ambiguous (ADR-0002 states where at "
            "least one receipt resolved to the record); counted here via "
            "bound x_gate.trace_id"
        ),
        "at_this_vantage": "computed over the gate's own receipt stream",
    },
    {
        "bucket": "out_of_gate",
        "definition": (
            "the action was observed outside the gate plane and its receipt "
            "never arrived past the grace window (ADR-0002 receipt_missing)"
        ),
        "at_this_vantage": _OUT_OF_GATE_VANTAGE,
    },
    {
        "bucket": "pending",
        "definition": (
            "the reconciliation window is still open (ADR-0002): absence "
            "inside the grace window is never a result, so the action is "
            "disclosed, never bucketed"
        ),
        "at_this_vantage": _PENDING_VANTAGE,
    },
)

#: Companion flags of the contract, stated read-only with their vantage
#: requirement — never fabricated at a vantage that cannot see them.
FLAGS: tuple[dict[str, Any], ...] = (
    {
        "flag": "bypass_candidates",
        "semantics": (
            "observed actions whose terminal state is receipt_missing: "
            "candidates only — trace-plane absence is never a bypass signal, "
            "and confirmation needs a tool-side or custody vantage the agent "
            "does not control (ADR-0004)"
        ),
        "computed_at_this_vantage": False,
        "vantage_note": (
            "no action outside the gate plane is observable here, so a zero "
            "would be a claim, not a result; the assurance service serves "
            "this flag via GET /coverage/{org} cross-vantage"
        ),
    },
    {
        "flag": "shadow_agents",
        "semantics": (
            "agents attributed to observed actions who minted zero receipts "
            "correlated to any of them"
        ),
        "computed_at_this_vantage": False,
        "vantage_note": (
            "every action that reached this gate minted a receipt: the flag "
            "cannot arise on a receipt-only plane"
        ),
    },
    {
        "flag": "uninstrumented_tools",
        "semantics": (
            "tools observed acting with zero receipted actions anywhere in "
            "the window: custody coverage for that tool is zero on the "
            "observed plane until a tool-side vantage verifies it"
        ),
        "computed_at_this_vantage": False,
        "vantage_note": (
            "the same receipt-plane arithmetic: every action passing this "
            "gate is instrumented by construction"
        ),
    },
)


# ---------------------------------------------------------------------------
# Enumeration: the demo gateway's own receipt stream
# ---------------------------------------------------------------------------


def _decode_envelope_payload(record: dict[str, Any]) -> dict[str, Any] | None:
    """Decode the signed payload of a receipt envelope, None when unreadable."""
    jws = record.get("jws")
    if not isinstance(jws, str):
        return None
    parts = jws.split(".")
    if len(parts) < 2:
        return None
    with contextlib.suppress(ValueError, TypeError):
        padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        payload = json.loads(_b64.urlsafe_b64decode(padded))
        if isinstance(payload, dict):
            return payload
    return None


def _decode_envelope_line(line: str) -> dict[str, Any] | None:
    """Parse one receipt-chain line into an envelope, skipping anything else."""
    with contextlib.suppress(json.JSONDecodeError):
        rec = json.loads(line)
        if isinstance(rec, dict) and isinstance(rec.get("jws"), str):
            return rec
    return None


def _row_fields(row: dict[str, Any]) -> dict[str, Any] | None:
    """Normalise one source row to the aggregate plane's fields.

    Index-projection rows carry the columns directly; envelope rows
    (segmented store or flat file) carry ``{receipt_hash, jws}`` and are
    decoded from their signed payload. The plane admits only receipts
    binding a gate decision context (tool, agent and decision set): admin-
    session lifecycle and authority receipts are infrastructure, not agent
    actions, and stay out of every bucket.
    """
    if "agent_id" in row and "tool" in row and "decision" in row:
        if not row.get("tool") or not row.get("agent_id") or not row.get("decision"):
            return None
        return {
            "agent_id": str(row["agent_id"]),
            "tool": str(row["tool"]),
            "decision": str(row["decision"]),
            "iat": int(row.get("iat") or 0),
            "trace_id": str(row["trace_id"]) if row.get("trace_id") else None,
        }
    payload = _decode_envelope_payload(row)
    if payload is None:
        return None
    x_gate = payload.get("x_gate") or {}
    if not x_gate.get("tool") or not x_gate.get("agent_id") or not x_gate.get("decision"):
        return None
    return {
        "agent_id": str(x_gate["agent_id"]),
        "tool": str(x_gate["tool"]),
        "decision": str(x_gate["decision"]),
        "iat": int(payload.get("iat") or 0),
        "trace_id": str(x_gate["trace_id"]) if x_gate.get("trace_id") else None,
    }


def _receipt_rows(gateway: Any, *, limit: int) -> tuple[list[dict[str, Any]], bool]:
    """Enumerate receipt rows newest-first, bounded, via the receipts-page
    precedence (index projection, segmented store, legacy flat chain).

    Returns the source rows and whether the cap truncated the stream.
    """
    index = getattr(gateway, "_receipt_index", None)
    store = getattr(gateway, "_receipt_store", None)
    if index is not None:
        rows: list[dict[str, Any]] = index.query(limit=limit + 1)
    elif store is not None:
        rows = store.recent(limit=limit + 1)
    else:
        path = Path(gateway.config.receipt_store)
        lines: list[str] = []
        if path.exists():
            lines = path.read_text(encoding="utf-8").strip().splitlines()
        rows = [rec for line in lines[-(limit + 1) :] if (rec := _decode_envelope_line(line))] or []
    truncated = len(rows) > limit
    return rows[:limit], truncated


# ---------------------------------------------------------------------------
# The pure metric over normalised rows
# ---------------------------------------------------------------------------


def _rollup(store: dict[str, dict[str, Any]], key: str | None, unknown: str) -> dict[str, Any]:
    """One rollup entry, folding a missing attribution to an explicit label."""
    name = key if key else unknown
    if name not in store:
        store[name] = {"total": 0, "receipted": 0, "out_of_gate": 0, "pending": 0}
    return store[name]


def aggregate_coverage(rows: Iterable[dict[str, Any]] | None) -> dict[str, Any]:
    """The receipted-share metric contract over normalised receipt rows.

    ``rows`` are the fields ``_row_fields`` produces. Every enumerated row
    already minted its receipt; the action plane counts the rows whose
    receipt binds ``x_gate.trace_id`` (the counting basis), and those all
    sit in the receipted bucket — out_of_gate and pending are the
    contract's disclosed zeros at this vantage (see the module docstring).
    A receipt whose trace id is unbound is receipt-side-only material for
    the correlation view: like the assurance engine's trace_missing records
    it never touches the action number, and it is disclosed in ``states``
    under its explicit label instead of vanishing.

    Returns the JSON-ready payload: pure, sorted, and byte-identical across
    repeated runs on the same rows.
    """
    plane = [row for row in (rows or []) if row is not None]
    traced = [row for row in plane if row["trace_id"]]
    untraced_count = len(plane) - len(traced)
    breakdown = {"total": len(traced), "receipted": len(traced), "out_of_gate": 0, "pending": 0}
    state_counts: Counter[str] = Counter()
    state_counts["traced"] += breakdown["total"]
    if untraced_count:
        state_counts[_UNKNOWN_TRACE_LABEL] += untraced_count
    decisions: Counter[str] = Counter()
    by_tool: dict[str, dict[str, Any]] = {}
    by_agent: dict[str, dict[str, Any]] = {}
    for row in traced:
        decisions[row["decision"]] += 1
        for store, key, unknown in (
            (by_tool, row.get("tool"), _UNKNOWN_TOOL_LABEL),
            (by_agent, row.get("agent_id"), _UNKNOWN_AGENT_LABEL),
        ):
            rollup = _rollup(store, key, unknown)
            rollup["total"] += 1
            rollup["receipted"] += 1
    states = {name: state_counts[name] for name in sorted(state_counts)}
    for store in (by_tool, by_agent):
        for rollup in store.values():
            rollup["receipted_share"] = (
                None if rollup["total"] == 0 else round(rollup["receipted"] / rollup["total"], 4)
            )
    assert breakdown["total"] == (
        breakdown["receipted"] + breakdown["out_of_gate"] + breakdown["pending"]
    )  # the buckets partition the action plane; exclusions live in ``states``
    share = (
        None if not breakdown["total"] else round(breakdown["receipted"] / breakdown["total"], 4)
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "metric": METRIC,
        "vantage": "gate-side receipt plane (single-demo-org)",
        "label": SIMULATED_LABEL,
        "basis": _BASIS,
        "unavailable_note": None if breakdown["total"] else _UNAVAILABLE_NOTE,
        "receipted_share": share,
        "breakdown": breakdown,
        "states": states,
        "decisions": dict(sorted(decisions.items())),
        "contract": {
            "buckets": [dict(bucket) for bucket in BUCKETS],
            "flags": [dict(flag) for flag in FLAGS],
        },
        "by_tool": dict(sorted(by_tool.items())),
        "by_agent": dict(sorted(by_agent.items())),
    }


def build_demo_coverage(gateway: Any) -> dict[str, Any]:
    """Compute the demo coverage view from the gateway's own receipt stream."""
    source_rows, truncated = _receipt_rows(gateway, limit=DEMO_COVERAGE_ROW_CAP)
    fields = [normal for row in source_rows if (normal := _row_fields(row)) is not None]
    payload = aggregate_coverage(fields)
    payload["window"] = {
        "row_cap": DEMO_COVERAGE_ROW_CAP,
        "rows_considered": len(fields),
        "truncated": truncated,
    }
    return payload


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _demo_mode_on() -> bool:
    return os.environ.get("RAUCLE_DEMO_MODE", "").lower() in ("1", "true", "yes")


def register_demo_coverage_routes(
    app: Any, gateway: Any, check_auth: Any, check_access: Any
) -> None:
    """Register the demo Coverage endpoint on *app*.

    Gated exactly like the other ``/api/demo/*`` surfaces: the route answers
    only when ``RAUCLE_DEMO_MODE`` is on, through the same authenticated,
    read-only resource gate, and answers 404 otherwise. GET only: nothing
    here mutates state, and the response carries aggregate counts and
    identifiers only — no credential, reason or payload detail.
    """

    def _gate(authorization: Any, x_totp: Any) -> Any:
        user = check_auth(authorization, x_totp)
        check_access(user, "stats")
        if not _demo_mode_on():
            raise HTTPException(404, "demo mode not configured")
        return user

    @app.get(
        "/api/demo/coverage",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_coverage(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        """The receipted-share metric contract over the gate receipt stream."""
        _gate(authorization, x_totp)
        return build_demo_coverage(gateway)
