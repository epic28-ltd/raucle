"""EQR — Evidence Quality Requirements as gate inputs (N6).

Implements the gate-input semantics of
[draft-watts-agent-evidence-boundary](https://datatracker.ietf.org/doc/draft-watts-agent-evidence-boundary/)
PROFILE: an Evidence Quality Requirement declares, per capability/tool, the
minimum DETERMINISTIC quality dimensions a piece of evidence must meet before
the gate may act on the authority the capability grants:

- ``evidence_kind``  — which kind of evidence the requirement is about;
- ``max_age_seconds`` — freshness bound (integer epoch arithmetic only);
- ``min_source_class`` — minimum class on the fixed source-class ladder;
- ``confidence_floor`` — integer confidence floor (0..100, never a float);

and what the gate does when the evidence fails: deny outright, or narrow the
authority to the EQR-declared reduced scope. Two invariants hold by
construction and are pinned by tests:

1. **Degraded evidence narrows, never widens.** An EQR-declared capability
   whose evidence is STALE / UNKNOWN / BELOW-FLOOR either denies the call or
   downgrades to a reduced-scope child token derived with the existing
   attenuation machinery (:meth:`raucle.capability.CapabilityIssuer.attenuate`
   — the Lean-proven meet, ``paper/lean/VCD/Attenuation.lean``). The reduced
   scope is the meet of the parent's constraints with the EQR's
   ``reduced_constraints``: strictly narrower or equal.
2. **Successor evidence narrows, never widens.** Evidence is consumed
   pessimistically: the evaluation projects the evidence set down to the WORST
   record of the required kind and evaluates THAT. A successor evidence event
   can therefore only degrade the verdict (or leave it), and the effective
   constraint set it yields is the meet with any earlier narrowed scope — a
   successor event can never re-open authority a prior decision withheld.
   Refresh is an explicit administrative act (:meth:`EvidenceStore.clear`),
   not an implicit consequence of new records arriving.

All numeric material is integer (epochs, seconds, confidence percentages);
floats are rejected at parse time (no floats in signed/hashed payload
material — the provenance layer's rule, applied here too).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Source-class ladder (deterministic, fixed)
# ---------------------------------------------------------------------------

SOURCE_CLASSES: tuple[str, ...] = (
    "unverified",
    "self-attested",
    "third-party",
    "certified",
)
_SOURCE_RANK: dict[str, int] = {name: rank for rank, name in enumerate(SOURCE_CLASSES)}

VERDICT_PASSING = "passing"
VERDICT_STALE = "stale"
VERDICT_BELOW_FLOOR = "below_floor"
VERDICT_UNKNOWN = "unknown"

# Worst-first severity order: the evidence-set projection keeps the WORST
# record's verdict, so accumulating evidence can only narrow.
_VERDICT_SEVERITY: dict[str, int] = {
    VERDICT_PASSING: 0,
    VERDICT_STALE: 1,
    VERDICT_BELOW_FLOOR: 2,
    VERDICT_UNKNOWN: 3,
}

_ON_DEGRADED_ALLOWED = ("deny", "reduce")

# The constraint-DSL keys compile_constraint_dsl understands; anything else
# in a reduced scope is a declaration error, not a silent no-op.
_CONSTRAINT_DSL_KEYS = frozenset(
    {"allow", "deny", "max", "min", "require", "starts_with", "forbidden_combinations"}
)


def source_rank(source_class: Any) -> int:
    """Rank of *source_class* on the ladder; -1 for unknown/unclassifiable.

    An unknown class ranks below every declared class, so it can only
    fail (narrow) an EQR - never satisfy it.
    """
    if not isinstance(source_class, str) or not source_class:
        return -1
    return _SOURCE_RANK.get(source_class, -1)


# ---------------------------------------------------------------------------
# Evidence record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Evidence:
    """One deterministic evidence record, as recorded by the harness.

    ``observed_at`` is an integer epoch SECOND; ``confidence`` an integer
    percentage 0..100. Malformed values raise at :meth:`from_dict` load
    time; the evaluation path additionally defends record-by-record and
    degrades to UNKNOWN (fail-closed) for anything unusable.
    """

    evidence_kind: str
    observed_at: int
    source_class: str
    confidence: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_kind": self.evidence_kind,
            "observed_at": self.observed_at,
            "source_class": self.source_class,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | Any) -> Evidence:
        if not isinstance(data, dict):
            raise ValueError(f"evidence must be a mapping, got {type(data).__name__}")
        kind = data.get("evidence_kind")
        observed_at = data.get("observed_at")
        source = data.get("source_class")
        confidence = data.get("confidence")
        if not isinstance(kind, str) or not kind:
            raise ValueError("evidence.evidence_kind must be a non-empty string")
        if isinstance(observed_at, bool) or not isinstance(observed_at, int) or observed_at < 0:
            raise ValueError("evidence.observed_at must be a non-negative integer epoch second")
        if not isinstance(source, str) or not source:
            raise ValueError("evidence.source_class must be a non-empty string")
        if isinstance(confidence, bool) or not isinstance(confidence, int):
            raise ValueError("evidence.confidence must be an integer percentage")
        if not 0 <= confidence <= 100:
            raise ValueError("evidence.confidence must be within 0..100")
        return cls(
            evidence_kind=kind, observed_at=observed_at, source_class=source, confidence=confidence
        )

    def _evaluate(self, eqr: EQR, now: int) -> tuple[str, str]:
        """Deterministic per-record verdict against *eqr* at epoch *now*."""
        if not isinstance(self.evidence_kind, str) or not self.evidence_kind:
            return VERDICT_UNKNOWN, "malformed evidence_kind (fail-closed)"
        if isinstance(self.observed_at, bool) or not isinstance(self.observed_at, int):
            return VERDICT_UNKNOWN, "malformed observed_at (fail-closed)"
        if self.observed_at < 0:
            # from_dict rejects negatives at load; a hand-built record that
            # slips past it must not silently read as ancient (-> stale).
            # Fail-closed: unknown.
            return VERDICT_UNKNOWN, "malformed observed_at (fail-closed)"
        age = now - self.observed_at
        if age < 0:
            return VERDICT_UNKNOWN, "future-dated evidence (fail-closed)"
        if age > eqr.max_age_seconds:
            return VERDICT_STALE, f"age {age}s exceeds freshness bound {eqr.max_age_seconds}s"
        rank = source_rank(self.source_class)
        if rank < source_rank(eqr.min_source_class):
            return (
                VERDICT_BELOW_FLOOR,
                f"source class '{self.source_class}' is below floor '{eqr.min_source_class}'",
            )
        if not isinstance(self.confidence, int) or isinstance(self.confidence, bool):
            return VERDICT_UNKNOWN, "malformed confidence (fail-closed)"
        if self.confidence < eqr.confidence_floor:
            return (
                VERDICT_BELOW_FLOOR,
                f"confidence {self.confidence} below floor {eqr.confidence_floor}",
            )
        return VERDICT_PASSING, ""


# ---------------------------------------------------------------------------
# The EQR (policy input)
# ---------------------------------------------------------------------------


def _validate_reduced_constraints(on_degraded: str, reduced: Any) -> None:
    """Validate the EQR reduced-scope DSL fail-closed at policy load."""
    if on_degraded != "reduce":
        if reduced is not None:
            raise ValueError("eqr.reduced_constraints is only valid when on_degraded is 'reduce'")
        return
    if not isinstance(reduced, dict) or not reduced:
        raise ValueError("eqr.reduced_constraints is required when on_degraded is 'reduce'")
    # Fail-closed at load: an unknown DSL key must be rejected, not
    # silently ignored by the compiler (a silently-dropped key would
    # widen the reduced scope below what the operator declared).
    unknown = set(reduced) - _CONSTRAINT_DSL_KEYS
    if unknown:
        raise ValueError(f"eqr.reduced_constraints has unknown constraint keys: {sorted(unknown)}")
    # Validate the DSL here (a malformed reduced scope fails CLOSED
    # at policy load, not at gate time) while storing the DSL-form
    # dict verbatim, so YAML round-trips keep the authored syntax.
    from raucle.policy import compile_constraint_dsl

    try:
        compile_constraint_dsl(reduced)
    except ValueError as exc:
        raise ValueError(f"eqr.reduced_constraints invalid: {exc}") from exc


@dataclass
class EQR:
    """Evidence Quality Requirement as a policy rule input.

    Deterministic fields only. ``on_degraded`` selects the narrowing-side
    behaviour when the evidence verdict is not passing:

    - ``deny``: the call denies with a named reason (fail-closed default);
    - ``reduce``: the authority downgrades to the EQR-declared reduced
      scope — ``reduced_constraints`` (policy DSL syntax) met with the
      parent token's constraints via the existing attenuation machinery.
    """

    evidence_kind: str
    max_age_seconds: int
    min_source_class: str
    confidence_floor: int
    on_degraded: str = "deny"
    reduced_constraints: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "evidence_kind": self.evidence_kind,
            "max_age_seconds": self.max_age_seconds,
            "min_source_class": self.min_source_class,
            "confidence_floor": self.confidence_floor,
            "on_degraded": self.on_degraded,
        }
        if self.reduced_constraints is not None:
            data["reduced_constraints"] = self.reduced_constraints
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any] | Any) -> EQR:

        if not isinstance(data, dict):
            raise ValueError(f"eqr must be a mapping, got {type(data).__name__}")
        kind = data.get("evidence_kind")
        max_age = data.get("max_age_seconds")
        min_class = data.get("min_source_class")
        floor = data.get("confidence_floor")
        on_degraded = data.get("on_degraded", "deny")
        reduced = data.get("reduced_constraints")
        if not isinstance(kind, str) or not kind:
            raise ValueError("eqr.evidence_kind must be a non-empty string")
        if (
            isinstance(max_age, bool)
            or not isinstance(max_age, int)
            or isinstance(max_age, float)
            or max_age <= 0
        ):
            raise ValueError("eqr.max_age_seconds must be a positive integer")
        if min_class not in SOURCE_CLASSES:
            raise ValueError(
                f"eqr.min_source_class must be one of {list(SOURCE_CLASSES)!r}, got {min_class!r}"
            )
        if isinstance(floor, bool) or not isinstance(floor, int) or not 0 <= floor <= 100:
            raise ValueError("eqr.confidence_floor must be an integer within 0..100")
        if on_degraded not in _ON_DEGRADED_ALLOWED:
            raise ValueError(f"eqr.on_degraded must be one of {list(_ON_DEGRADED_ALLOWED)!r}")
        _validate_reduced_constraints(on_degraded, reduced)
        return cls(
            evidence_kind=kind,
            max_age_seconds=max_age,
            min_source_class=min_class,
            confidence_floor=floor,
            on_degraded=on_degraded,
            reduced_constraints=reduced,
        )


# ---------------------------------------------------------------------------
# Pure evaluation (deterministic, fail-closed, narrowing-only)
# ---------------------------------------------------------------------------


def evaluate_eqr(
    eqr: EQR,
    evidences: list[Evidence],
    now: int,
) -> tuple[str, str]:
    """Evaluate *eqr* against the recorded evidence of its kind at epoch *now*.

    Returns ``(verdict, reason)`` with verdict one of ``passing`` /
    ``stale`` / ``below_floor`` / ``unknown``.

    Semantics (deterministic, fail-closed, narrowing-only):

    1. no recorded evidence of the required kind → UNKNOWN (fail-closed);
    2. the evidence set is projected to the WORST record of the kind and
       that record is evaluated; a record verdict is:
       malformed/unclassifiable → UNKNOWN, future-dated → UNKNOWN, older
       than the freshness bound → STALE, source class or confidence under
       the floors → BELOW_FLOOR, else passing;
    3. the projected (worst) verdict is the set verdict: accumulating
       successor evidence can only degrade (narrow) it - never improve it.

    The function is pure: the same ``(eqr, evidences, now)`` triple always
    yields the same answer.
    """
    if not isinstance(now, int) or isinstance(now, bool):
        return VERDICT_UNKNOWN, "unusable evaluation clock (fail-closed)"
    of_kind = [e for e in evidences if e.evidence_kind == eqr.evidence_kind]
    if not of_kind:
        return (
            VERDICT_UNKNOWN,
            f"no evidence of kind '{eqr.evidence_kind}' recorded (fail-closed)",
        )
    worst_verdict, worst_reason = VERDICT_PASSING, ""
    for record in of_kind:
        verdict, reason = record._evaluate(eqr, now)
        if _VERDICT_SEVERITY[verdict] > _VERDICT_SEVERITY[worst_verdict]:
            worst_verdict, worst_reason = verdict, reason
    return worst_verdict, worst_reason


def eqr_deny_reason(eqr: EQR, verdict: str, detail: str) -> str:
    """The named fail-closed deny reason for a degraded EQR verdict."""
    return (
        f"EQR: evidence for kind '{eqr.evidence_kind}' is {verdict} ({detail}) - fail-closed deny"
    )


def narrowed_reduced_constraints(eqr: EQR, base_constraints: dict[str, Any]) -> dict[str, Any]:
    """Return the EQR reduced scope: base constraints MEET reduced_constraints.

    Uses the same narrowing merge the delegation machinery proved
    (``_merge_narrowing`` / ``_assert_narrowing``), then asserts the result
    is tighter-or-equal to *base*. Raises ``ValueError`` if the merge would
    widen - the caller must deny (fail-closed) on that.
    """
    from raucle.capability import _assert_narrowing, _merge_narrowing
    from raucle.policy import compile_constraint_dsl

    reduced = compile_constraint_dsl(eqr.reduced_constraints or {})
    merged = _merge_narrowing(base_constraints, reduced)
    _assert_narrowing(base_constraints, merged)
    return merged


# ---------------------------------------------------------------------------
# Evidence store (replayable, mirrors ChainTaintState)
# ---------------------------------------------------------------------------


class EvidenceStore:
    """Replayable per-tool record of evidence events.

    The EQR evaluation at each gate decision replays exactly the recorded
    evidence - deterministic, no side-channel input. Records are
    :class:`Evidence` instances (validated at :meth:`record`); the store
    changes only through :meth:`record` and :meth:`clear`.
    """

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], list[Evidence]] = {}

    def record(self, tool: str, evidence: Evidence | dict[str, Any]) -> Evidence:
        """Record one evidence event for *tool* (kind taken from the record)."""
        record = evidence if isinstance(evidence, Evidence) else Evidence.from_dict(evidence)
        self._records.setdefault((tool, record.evidence_kind), []).append(record)
        return record

    def snapshot(self, tool: str, evidence_kind: str) -> list[Evidence]:
        """Return a copy of the evidence of *evidence_kind* for *tool*, in order."""
        return list(self._records.get((tool, evidence_kind), []))

    def clear(self, tool: str | None = None, evidence_kind: str | None = None) -> None:
        """Drop one (tool, kind) slice, one tool, or everything when None."""
        if tool is None:
            self._records.clear()
            return
        if evidence_kind is None:
            for key in [k for k in self._records if k[0] == tool]:
                del self._records[key]
            return
        self._records.pop((tool, evidence_kind), None)


@dataclass
class EQRDecision:
    """Gate-side outcome of an EQR evaluation over a capability token."""

    verdict: str
    detail: str
    deny_reason: str = ""
    # When set: the narrowed child token the call must be re-checked under.
    narrowed_token: Any = None
    extra_constraints: dict[str, Any] | None = None

    @property
    def degraded(self) -> bool:
        return self.verdict != VERDICT_PASSING


def apply_eqr_to_token(
    eqr: EQR,
    evidences: list[Evidence],
    token: Any,
    issuer: Any,
    now: int,
) -> EQRDecision:
    """Gate-side EQR handling: deny or narrow, never widen.

    ``passing`` evidence yields the decision unchanged. Degraded evidence:
    ``on_degraded == "deny"`` denies with a named reason; ``on_degraded ==
    "reduce"`` derives a reduced-scope child token via
    :meth:`raucle.capability.CapabilityIssuer.attenuate` (the proven meet),
    and the caller must re-check the call under it. Any narrowing failure
    (or inability to narrow) is fail-closed:
    :attr:`EQRDecision.deny_reason` is set.
    """
    verdict, detail = evaluate_eqr(eqr, evidences, now)
    if verdict == VERDICT_PASSING:
        return EQRDecision(verdict=verdict, detail="")
    if eqr.on_degraded != "reduce":
        return EQRDecision(
            verdict=verdict, detail=detail, deny_reason=eqr_deny_reason(eqr, verdict, detail)
        )
    # Narrowing fallback: reduced scope == parent constraints MEET the EQR's
    # reduced constraints. Narrowing is computed first (so a narrowing
    # failure denies even before token derivation) and the child token is
    # derived through the issuer's attenuation (the proven machinery).
    from raucle.capability import Capability

    if not isinstance(token, Capability):
        return EQRDecision(
            verdict=verdict,
            detail=detail,
            deny_reason=eqr_deny_reason(
                eqr, verdict, "no capability token to narrow (fail-closed)"
            ),
        )
    try:
        extra = narrowed_reduced_constraints(eqr, token.constraints)
    except ValueError as exc:
        return EQRDecision(
            verdict=verdict,
            detail=detail,
            deny_reason=eqr_deny_reason(eqr, verdict, f"reduced-scope narrowing failed: {exc}"),
        )
    try:
        child = issuer.attenuate(token, extra_constraints=extra)
    except Exception as exc:  # fail-closed: any derivation failure denies
        return EQRDecision(
            verdict=verdict,
            detail=detail,
            deny_reason=eqr_deny_reason(eqr, verdict, f"reduced-scope derivation failed: {exc}"),
        )
    return EQRDecision(
        verdict=verdict, detail=detail, narrowed_token=child, extra_constraints=extra
    )


__all__ = [
    "SOURCE_CLASSES",
    "VERDICT_PASSING",
    "VERDICT_STALE",
    "VERDICT_BELOW_FLOOR",
    "VERDICT_UNKNOWN",
    "Evidence",
    "EQR",
    "EQRDecision",
    "EvidenceStore",
    "source_rank",
    "evaluate_eqr",
    "eqr_deny_reason",
    "narrowed_reduced_constraints",
    "apply_eqr_to_token",
]
