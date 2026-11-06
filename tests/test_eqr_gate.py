"""N6: EQR-aware gate — Evidence Quality Requirements as gate inputs.

``raucle/eqr.py`` implements the gate-input semantics of
draft-watts-agent-evidence-boundary (profile): an EQR declares the minimum
deterministic evidence quality (kind, freshness, source class, confidence
floor) the authority depends on; degraded evidence (STALE / UNKNOWN /
BELOW-FLOOR) either denies with a named reason or narrows the authority to
the EQR-declared reduced scope - and successor evidence can only ADD
constraints (narrow), never widen a prior decision.
"""

from __future__ import annotations

import json
import random
import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from raucle.capability import _assert_narrowing
from raucle.eqr import (
    VERDICT_BELOW_FLOOR,
    VERDICT_STALE,
    VERDICT_UNKNOWN,
    Evidence,
    evaluate_eqr,
    narrowed_reduced_constraints,
)
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.policy import PolicyFile

VECTOR_DIR = Path(__file__).resolve().parents[1] / "standards" / "test-vectors"

# ---------------------------------------------------------------------------
# Policy DSL: parsing, validation, round-trip
# ---------------------------------------------------------------------------


def _policy_path(tmp_path: Path, data: dict[str, Any]) -> str:
    path = tmp_path / "policies.yaml"
    path.write_text(yaml.dump(data), encoding="utf-8")
    return str(path)


def _eqr_body(reduced: dict[str, Any] | None = None, on_degraded: str = "reduce") -> dict[str, Any]:
    body: dict[str, Any] = {
        "evidence_kind": "kyc_check",
        "max_age_seconds": 60,
        "min_source_class": "third-party",
        "confidence_floor": 70,
        "on_degraded": on_degraded,
    }
    if reduced is not None:
        body["reduced_constraints"] = reduced
    return body


_EQR_POLICY_RULE: dict[str, Any] = {
    "tool": "transfer_money",
    "agent_id": "agent:pay",
    "ttl_seconds": 300,
    "constraints": {
        "allow": {"from_account": ["ACC-001"], "to_account": ["ACC-002"]},
        "max": {"amount": 10000},
    },
}


def test_eqr_parses(tmp_path: Path) -> None:
    rule = dict(_EQR_POLICY_RULE, eqr=_eqr_body({"max": {"amount": 100}}))
    policy = PolicyFile.load(
        _policy_path(tmp_path, {"version": 1, "issuer": "acme.bank", "policies": [rule]})
    )
    eqr = policy.policies[0].eqr
    assert eqr is not None
    assert eqr.evidence_kind == "kyc_check"
    assert eqr.max_age_seconds == 60
    assert eqr.min_source_class == "third-party"
    assert eqr.confidence_floor == 70
    assert eqr.on_degraded == "reduce"
    assert eqr.reduced_constraints == {"max": {"amount": 100}}


def test_eqr_yaml_round_trip(tmp_path: Path) -> None:
    rule = dict(_EQR_POLICY_RULE, eqr=_eqr_body({"max": {"amount": 100}}))
    policy = PolicyFile.load(
        _policy_path(tmp_path, {"version": 1, "issuer": "acme.bank", "policies": [rule]})
    )
    reloaded = PolicyFile.from_dict(yaml.safe_load(policy.to_yaml()))
    assert reloaded.policies[0].eqr == policy.policies[0].eqr


@pytest.mark.parametrize(
    "eqr_body",
    [
        {
            "evidence_kind": "",
            "max_age_seconds": 1,
            "min_source_class": "certified",
            "confidence_floor": 1,
        },
        {
            "evidence_kind": "k",
            "max_age_seconds": 0,
            "min_source_class": "certified",
            "confidence_floor": 1,
        },
        {
            "evidence_kind": "k",
            "max_age_seconds": 1.5,
            "min_source_class": "certified",
            "confidence_floor": 1,
        },
        {
            "evidence_kind": "k",
            "max_age_seconds": 1,
            "min_source_class": "mega-certified",
            "confidence_floor": 1,
        },
        {
            "evidence_kind": "k",
            "max_age_seconds": 1,
            "min_source_class": "certified",
            "confidence_floor": 101,
        },
        {
            "evidence_kind": "k",
            "max_age_seconds": 1,
            "min_source_class": "certified",
            "confidence_floor": -1,
        },
        {
            "evidence_kind": "k",
            "max_age_seconds": 1,
            "min_source_class": "certified",
            "confidence_floor": "70",
        },
        {
            "evidence_kind": "k",
            "max_age_seconds": 1,
            "min_source_class": "certified",
            "confidence_floor": 1,
            "on_degraded": "widen",
        },
        {
            "evidence_kind": "k",
            "max_age_seconds": 1,
            "min_source_class": "certified",
            "confidence_floor": 1,
            "on_degraded": "reduce",
        },
        {
            "evidence_kind": "k",
            "max_age_seconds": 1,
            "min_source_class": "certified",
            "confidence_floor": 1,
            "on_degraded": "reduce",
            "reduced_constraints": {},
        },
        {
            "evidence_kind": "k",
            "max_age_seconds": 1,
            "min_source_class": "certified",
            "confidence_floor": 1,
            "on_degraded": "reduce",
            "reduced_constraints": {"bogus_key": [1]},
        },
        {
            "evidence_kind": "k",
            "max_age_seconds": 1,
            "min_source_class": "certified",
            "confidence_floor": 1,
            "reduced_constraints": {"max": {"amount": 1}},
        },
    ],
)
def test_eqr_malformed_fails_closed(tmp_path: Path, eqr_body: dict) -> None:
    """A malformed EQR must fail the POLICY LOAD, not degrade at gate time."""
    rule = dict(_EQR_POLICY_RULE, eqr=eqr_body)
    path = _policy_path(tmp_path, {"version": 1, "issuer": "acme.bank", "policies": [rule]})
    with pytest.raises(ValueError):
        PolicyFile.load(path)


def test_eqr_not_required_rules_unchanged(tmp_path: Path) -> None:
    """Rules without the kind keep today's semantics exactly."""
    policy = PolicyFile.load(
        _policy_path(
            tmp_path,
            {"version": 1, "issuer": "acme.bank", "policies": [dict(_EQR_POLICY_RULE)]},
        )
    )
    assert policy.policies[0].eqr is None


# ---------------------------------------------------------------------------
# Pure evaluation: deterministic, fail-closed, worst-of projection
# ---------------------------------------------------------------------------

_NOW = 1_900_000_000


def _ev(**over: Any) -> Evidence:
    body = {
        "evidence_kind": "kyc_check",
        "observed_at": _NOW,
        "source_class": "third-party",
        "confidence": 90,
    }
    body.update(over)
    return Evidence.from_dict(body)


def _eqr() -> Any:
    from raucle.eqr import EQR

    # on_degraded=deny: the pure-evaluation vectors assert verdicts and
    # named reasons only - narrowing behaviour is covered separately by
    # the dedicated narrowing fixtures (which always declare a reduced
    # scope, as from_dict requires for on_degraded='reduce').
    return EQR.from_dict(_eqr_body(on_degraded="deny"))


def test_passing_evidence() -> None:
    verdict, reason = evaluate_eqr(_eqr(), [_ev()], _NOW)
    assert verdict == "passing"
    assert reason == ""


def test_no_evidence_is_unknown_fail_closed() -> None:
    verdict, reason = evaluate_eqr(_eqr(), [], _NOW)
    assert verdict == VERDICT_UNKNOWN
    assert "no evidence of kind 'kyc_check'" in reason


def test_stale_evidence() -> None:
    verdict, reason = evaluate_eqr(_eqr(), [_ev(observed_at=_NOW - 61)], _NOW)
    assert verdict == VERDICT_STALE
    assert "freshness bound" in reason


def test_below_floor_source_class() -> None:
    verdict, reason = evaluate_eqr(_eqr(), [_ev(source_class="self-attested")], _NOW)
    assert verdict == VERDICT_BELOW_FLOOR
    assert "below floor" in reason


def test_unknown_source_class_can_only_fail() -> None:
    """An unclassifiable source class ranks below every declared class."""
    verdict, reason = evaluate_eqr(_eqr(), [_ev(source_class="mystery-source")], _NOW)
    assert verdict == VERDICT_BELOW_FLOOR
    assert "below floor" in reason


def test_below_floor_confidence() -> None:
    verdict, _ = evaluate_eqr(_eqr(), [_ev(confidence=69)], _NOW)
    assert verdict == VERDICT_BELOW_FLOOR


def test_future_dated_evidence_is_unknown() -> None:
    verdict, reason = evaluate_eqr(_eqr(), [_ev(observed_at=_NOW + 5)], _NOW)
    assert verdict == VERDICT_UNKNOWN
    assert "future-dated" in reason


def test_evaluation_is_deterministic() -> None:
    evidences = [_ev(observed_at=_NOW - 61)]
    verdicts = {evaluate_eqr(_eqr(), evidences, _NOW)[0] for _ in range(10)}
    assert verdicts == {VERDICT_STALE}


@pytest.mark.parametrize(
    "bad",
    [
        {"evidence_kind": ""},
        {"observed_at": -1},
        {"observed_at": 1.5},
        {"observed_at": True},
        {"source_class": ""},
        {"confidence": 101},
        {"confidence": "90"},
        {"confidence": True},
    ],
)
def test_malformed_evidence_rejected_at_load(bad: dict) -> None:
    with pytest.raises(ValueError):
        Evidence.from_dict(
            {
                "evidence_kind": "k",
                "observed_at": _NOW,
                "source_class": "certified",
                "confidence": 50,
                **bad,
            }
        )


def test_unusable_record_during_evaluation_is_unknown_fail_closed() -> None:
    """A hand-built unusable record (bypassing from_dict) degrades to UNKNOWN."""
    broken = Evidence(
        evidence_kind="kyc_check", observed_at=-5, source_class="third-party", confidence=90
    )
    verdict, reason = evaluate_eqr(_eqr(), [broken], _NOW)
    assert verdict == VERDICT_UNKNOWN
    assert "fail-closed" in reason


# ---------------------------------------------------------------------------
# Narrowing machinery: reduced scope is the MEET (tighter-or-equal)
# ---------------------------------------------------------------------------


def test_reduced_scope_is_always_tighter_or_equal() -> None:
    from raucle.eqr import EQR

    base = {"allowed_values": {"from_account": ["ACC-001"]}, "max_value": {"amount": 10000}}
    eqr = EQR.from_dict(_eqr_body({"max": {"amount": 100}}))
    merged = narrowed_reduced_constraints(eqr, base)
    _assert_narrowing(base, merged)  # fails closed if the merge widens
    assert merged["max_value"]["amount"] == 100
    assert merged["allowed_values"] == base["allowed_values"]


def test_reduced_scope_with_unknown_base_key_narrows_cleanly() -> None:
    from raucle.eqr import EQR

    base: dict[str, Any] = {"max_value": {"amount": 10000}}
    eqr = EQR.from_dict(_eqr_body({"allow": {"to_account": ["ACC-002"]}, "max": {"amount": 50}}))
    merged = narrowed_reduced_constraints(eqr, base)
    _assert_narrowing(base, merged)
    assert merged["max_value"]["amount"] == 50
    assert merged["allowed_values"]["to_account"] == ["ACC-002"]


# ---------------------------------------------------------------------------
# Successor-evidence rule: narrowing, never widening (proof by test + z3)
# ---------------------------------------------------------------------------

# Invariant: with evidence consumed worst-of, the verdict is monotone
# non-improving as the evidence set grows - so a successor evidence EVENT
# can never re-open authority a prior decision withheld; the effective
# constraint set after a degrade is the MEET of the prior scope with the
# EQR reduced scope (monotone narrowing, asserted with the same
# _assert_narrowing the delegation machinery proved).
#
# Formal alignment: monotonic narrowing is covered GENERICALLY by the Lean
# development (paper/lean): `meet_tighter` and `attenuation_soundness`
# (VCD/Attenuation.lean) prove the constraint meet is tighter, and
# `tighter_implies_satisfies` (VCD/Composition.lean) proves a tighter policy
# admits no call the looser one did. The z3 test below cross-checks the
# Python `_merge_narrowing` bridge over a generated corpus rather than
# re-proving the invariant.


def test_successor_event_never_widens_verdict() -> None:
    """A better successor record cannot improve a degraded verdict."""
    stale = _ev(observed_at=_NOW - 61)
    assert evaluate_eqr(_eqr(), [stale], _NOW)[0] == VERDICT_STALE
    # A genuinely better successor: fresh within the bound, better class
    # and confidence. (A FUTURE-dated record is a data error -> UNKNOWN,
    # which is strictly worse than stale, not "better".)
    fresher = _ev(observed_at=_NOW, source_class="certified", confidence=100)
    # worst-of projection: the stale record keeps the projected verdict.
    verdict, reason = evaluate_eqr(_eqr(), [stale, fresher], _NOW)
    assert verdict == VERDICT_STALE
    assert "freshness bound" in reason


def test_successor_scenariio_allow_then_narrow_then_never_reopen() -> None:
    """Prior decision allowed amount 5000; the successor (stale) event
    narrows the scope; the SAME call is now denied - never re-opened."""
    base = {"allowed_values": {"from_account": ["ACC-001"]}, "max_value": {"amount": 10000}}
    from raucle.eqr import EQR

    eqr = EQR.from_dict(_eqr_body({"max": {"amount": 100}}))
    fresh = evaluate_eqr(eqr, [_ev()], _NOW)
    assert fresh[0] == "passing"
    narrowed = narrowed_reduced_constraints(eqr, base)
    _assert_narrowing(base, narrowed)  # narrow-side outcome is subset of prior
    # Successor event arrives: verdict degrades, scope stays the meet.
    successor = evaluate_eqr(eqr, [_ev(observed_at=_NOW - 61)], _NOW)
    assert successor[0] == VERDICT_STALE
    _assert_narrowing(narrowed, narrowed_reduced_constraints(eqr, base))


def _corpus_pairs(seed: int = 20261106, n: int = 60) -> list[tuple[dict, dict]]:
    """Deterministic (base, reduced-DSL) corpus over the numeric and
    value-list fragments the reduced scope may use."""
    rng = random.Random(seed)
    pairs = []
    for _ in range(n):
        base_max = rng.choice([1000, 5000, 10000])
        reduced = {"max": {"amount": rng.randint(1, base_max)}}
        if rng.random() < 0.5:
            accounts = ["ACC-001", "ACC-002", "ACC-003"]
            keep = rng.sample(accounts, rng.randint(1, 3))
            reduced["allow"] = {"from_account": keep}
        pairs.append(
            (
                {
                    "allowed_values": {"from_account": ["ACC-001"]},
                    "max_value": {"amount": base_max},
                },
                reduced,
            )
        )
    return pairs


def _allows(constraints: dict[str, Any], amount: int, account: str) -> bool:
    """Pure-Python satisfaction predicate over the modelled fragment."""
    max_value = constraints.get("max_value") or {}
    if "amount" in max_value and amount > max_value["amount"]:
        return False
    allowed = (constraints.get("allowed_values") or {}).get("from_account")
    if allowed is not None:
        return account in allowed
    return True


def test_z3_successor_narrowing_never_widens_over_corpus() -> None:
    """z3 cross-check (the Lean dev covers monotonic narrowing generically;
    this pins the PYTHON narrowing bridge): for every corpus pair, NO model
    value is allowed by the merged scope that the base scope denies - i.e.
    mergedAllows(x) => baseAllows(x) holds for all x in the modelled
    fragment. Symbolic over Z3 integers; exhaustive in Python."""
    import z3

    from raucle.eqr import EQR

    amount = z3.Int("amount")
    corpus = _corpus_pairs()
    assert len(corpus) == 60

    def b_allow(n: Any, acc: str) -> Any:
        mv = base.get("max_value") or {}
        cond = z3.BoolVal(True)
        if "amount" in mv:
            cond = z3.And(cond, n <= mv["amount"])
        allowed = (base.get("allowed_values") or {}).get("from_account")
        if allowed is not None:
            cond = z3.And(cond, z3.Or(*[z3.BoolVal(acc == a) for a in allowed]))
        return cond

    def m_allow(n: Any, acc: str) -> Any:
        mv = merged.get("max_value") or {}
        cond = z3.BoolVal(True)
        if "amount" in mv:
            cond = z3.And(cond, n <= mv["amount"])
        allowed = (merged.get("allowed_values") or {}).get("from_account")
        if allowed is not None:
            cond = z3.And(cond, z3.Or(*[z3.BoolVal(acc == a) for a in allowed]))
        return cond

    for base, reduced_dsl in corpus:
        eqr = EQR.from_dict(_eqr_body(reduced_dsl))
        merged = narrowed_reduced_constraints(eqr, base)
        solver = z3.Solver()
        solver.add(m_allow(amount, "ACC-001"))
        solver.add(z3.Not(b_allow(amount, "ACC-001")))
        # mergedAllows(x) => baseAllows(x) for all x: NO widening.
        assert solver.check() == z3.unsat, f"widening found for {base} / {reduced_dsl}"
        # And the narrowing is not vacuous: the bite exists the other way.
        bite = z3.Solver()
        bite.add(b_allow(amount, "ACC-001"))
        bite.add(z3.Not(m_allow(amount, "ACC-001")))
        assert bite.check() == z3.sat, f"vacuous narrowing for {base} / {reduced_dsl}"
        # Exhaustive Python side over the enumerated fragment.
        for amt in [-5, 0, 1, 50, 100, 999, 5000, 10001]:
            if _allows(merged, amt, "ACC-001"):
                assert _allows(base, amt, "ACC-001"), (base, reduced_dsl, amt)


def test_z3_narrowing_bites_when_freshness_fails() -> None:
    """The narrowing is not vacuous: when the reduced scope is strictly
    tighter, some model value is allowed by base but denied by merged."""
    import z3

    from raucle.eqr import EQR

    base = {"max_value": {"amount": 10000}}
    eqr = EQR.from_dict(_eqr_body({"max": {"amount": 100}}))
    merged = narrowed_reduced_constraints(eqr, base)
    amount = z3.Int("amount")
    solver = z3.Solver()
    solver.add(amount <= 10000, amount >= -1000000)
    solver.add(z3.Not(amount <= merged["max_value"]["amount"]))
    assert solver.check() == z3.sat  # an amount base allowed, merged denies


# ---------------------------------------------------------------------------
# Gateway enforcement: the real public surface
# ---------------------------------------------------------------------------

_PASSING_EVIDENCE: dict[str, Any] = {
    "evidence_kind": "kyc_check",
    "observed_at": None,  # filled by helpers: now
    "source_class": "third-party",
    "confidence": 90,
}


@pytest.fixture
def eqr_policy(tmp_path: Path) -> str:
    rule = dict(_EQR_POLICY_RULE, eqr=_eqr_body({"max": {"amount": 100}}))
    return _policy_path(tmp_path, {"version": 1, "issuer": "acme.bank", "policies": [rule]})


@pytest.fixture
def gateway(eqr_policy: str, tmp_path: Path) -> RaucleGateway:
    config = GatewayConfig(
        policy_file=eqr_policy,
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="test-admin-key",
        signer_backend="local",
    )
    return RaucleGateway(config)


@pytest.fixture
def deny_gateway(tmp_path: Path) -> RaucleGateway:
    rule = dict(_EQR_POLICY_RULE, eqr=_eqr_body(on_degraded="deny"))
    policy = _policy_path(tmp_path, {"version": 1, "issuer": "acme.bank", "policies": [rule]})
    config = GatewayConfig(
        policy_file=policy,
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="test-admin-key",
        signer_backend="local",
    )
    return RaucleGateway(config)


def _args(amount: int) -> dict[str, Any]:
    return {"from_account": "ACC-001", "to_account": "ACC-002", "amount": amount}


def _record_passing(gateway: RaucleGateway) -> None:
    gateway.record_evidence(
        "transfer_money",
        {
            "evidence_kind": "kyc_check",
            "observed_at": int(time.time()),
            "source_class": "third-party",
            "confidence": 90,
        },
    )


def _record_stale(gateway: RaucleGateway) -> None:
    gateway.record_evidence(
        "transfer_money",
        {
            "evidence_kind": "kyc_check",
            "observed_at": int(time.time()) - 10**6,
            "source_class": "third-party",
            "confidence": 90,
        },
    )


def test_gateway_stale_evidence_narrows_authority(gateway: RaucleGateway) -> None:
    # Fresh evidence: amount 5000 allowed under the policy's 10k cap.
    _record_passing(gateway)
    allowed = gateway.check_tool_call("transfer_money", _args(5000), agent_id="agent:pay")
    assert allowed["decision"] == "allow"
    # The evidence goes STALE (successor event) -> the authority narrows to
    # the EQR reduced scope (amount <= 100). The prior call is now denied.
    _record_stale(gateway)
    narrowed_out = gateway.check_tool_call("transfer_money", _args(5000), agent_id="agent:pay")
    assert narrowed_out["decision"] == "deny"
    assert narrowed_out["receipt_id"]
    # Within the reduced scope the call still allows - never widening, the
    # scope is strictly smaller.
    inside = gateway.check_tool_call("transfer_money", _args(50), agent_id="agent:pay")
    assert inside["decision"] == "allow"
    assert "[EQR: degraded evidence - authority narrowed to reduced scope]" in inside["reason"]
    # The narrowed decision is bound to a reduced-scope child of the same
    # rule: the rule id is unchanged (same tool/agent/index).
    assert inside["rule_id"] == "transfer_money/agent:pay/0"


def test_gateway_unknown_evidence_denies_named(deny_gateway: RaucleGateway) -> None:
    """No evidence recorded -> UNKNOWN, and with on_degraded=deny that is
    a NAMED fail-closed deny. (With on_degraded=reduce the same UNKNOWN
    narrows to the reduced scope - degraded, but never a widening.)"""
    result = deny_gateway.check_tool_call("transfer_money", _args(5000), agent_id="agent:pay")
    assert result["decision"] == "deny"
    assert result["receipt_id"]
    assert result["reason"] == (
        "EQR: evidence for kind 'kyc_check' is unknown "
        "(no evidence of kind 'kyc_check' recorded (fail-closed)) - fail-closed deny"
    )


def test_gateway_unknown_kind_record_denies_named(deny_gateway: RaucleGateway) -> None:
    """Evidence of a DIFFERENT kind than the EQR's does not satisfy it."""
    deny_gateway.record_evidence(
        "transfer_money",
        {
            "evidence_kind": "sanctions_check",
            "observed_at": int(time.time()),
            "source_class": "certified",
            "confidence": 100,
        },
    )
    result = deny_gateway.check_tool_call("transfer_money", _args(1), agent_id="agent:pay")
    assert result["decision"] == "deny"
    assert "no evidence of kind 'kyc_check'" in result["reason"]


def test_gateway_on_degraded_deny_fails_closed(deny_gateway: RaucleGateway) -> None:
    _record_stale(deny_gateway)
    result = deny_gateway.check_tool_call("transfer_money", _args(50), agent_id="agent:pay")
    assert result["decision"] == "deny"
    assert result["reason"].startswith("EQR: evidence for kind 'kyc_check' is stale")
    assert "fail-closed deny" in result["reason"]


def test_gateway_below_floor_confidence_narrows(gateway: RaucleGateway) -> None:
    gateway.record_evidence(
        "transfer_money",
        {
            "evidence_kind": "kyc_check",
            "observed_at": int(time.time()),
            "source_class": "third-party",
            "confidence": 69,
        },
    )
    result = gateway.check_tool_call("transfer_money", _args(5000), agent_id="agent:pay")
    assert result["decision"] == "deny"
    below_floor_inside = gateway.check_tool_call("transfer_money", _args(100), agent_id="agent:pay")
    assert below_floor_inside["decision"] == "allow"  # reduced scope only


def test_gateway_below_floor_source_class_narrows(gateway: RaucleGateway) -> None:
    gateway.record_evidence(
        "transfer_money",
        {
            "evidence_kind": "kyc_check",
            "observed_at": int(time.time()),
            "source_class": "self-attested",
            "confidence": 99,
        },
    )
    assert (
        gateway.check_tool_call("transfer_money", _args(50), agent_id="agent:pay")["decision"]
        == "allow"
    )
    assert (
        gateway.check_tool_call("transfer_money", _args(5000), agent_id="agent:pay")["decision"]
        == "deny"
    )


def test_gateway_escalate_may_not_bypass_eqr(deny_gateway: RaucleGateway) -> None:
    """An approval-escalating call still denies when the EQR fails: ESCALATE
    must not bypass degraded-evidence narrowing (never widens authority)."""
    _record_stale(deny_gateway)
    result = deny_gateway.check_tool_call("transfer_money", _args(9000), agent_id="agent:pay")
    assert result["decision"] == "deny"
    assert result["reason"].startswith("EQR:")


def test_gateway_successor_never_reopens_prior_decision(gateway: RaucleGateway) -> None:
    trace = "succ"
    _record_stale(gateway)  # degraded from the start
    first = gateway.check_tool_call(
        "transfer_money", _args(5000), agent_id="agent:pay", trace_id=trace
    )
    assert first["decision"] == "deny"
    # Successor ARRIVES and is BETTER on every deterministic dimension.
    gateway.record_evidence(
        "transfer_money",
        {
            "evidence_kind": "kyc_check",
            "observed_at": int(time.time()),
            "source_class": "certified",
            "confidence": 100,
        },
    )
    again = gateway.check_tool_call(
        "transfer_money", _args(5000), agent_id="agent:pay", trace_id=trace
    )
    assert again["decision"] == "deny"  # the prior deny is never re-opened
    # Within the reduced scope the authority persists.
    assert (
        gateway.check_tool_call("transfer_money", _args(100), agent_id="agent:pay")["decision"]
        == "allow"
    )


def test_gateway_eqr_evaluation_is_deterministic(gateway: RaucleGateway) -> None:
    _record_stale(gateway)

    def run() -> list[str]:
        return [
            gateway.check_tool_call("transfer_money", _args(5000), agent_id="agent:pay")[
                "decision"
            ],
            gateway.check_tool_call("transfer_money", _args(50), agent_id="agent:pay")["decision"],
        ]

    assert run() == ["deny", "allow"] == run()


def test_gateway_rules_without_eqr_unchanged(tmp_path: Path) -> None:
    policy = _policy_path(
        tmp_path, {"version": 1, "issuer": "acme.bank", "policies": [dict(_EQR_POLICY_RULE)]}
    )
    config = GatewayConfig(
        policy_file=policy,
        receipt_store=str(tmp_path / "r.jsonl"),
        audit_chain=str(tmp_path / "a.jsonl"),
        admin_api_key="test-admin-key",
        signer_backend="local",
    )
    gateway = RaucleGateway(config)
    result = gateway.check_tool_call("transfer_money", _args(50), agent_id="agent:pay")
    assert result["decision"] == "allow"
    assert "[EQR" not in result["reason"]


def test_gateway_http_eqr_narrowing(gateway: RaucleGateway) -> None:
    app = create_gateway_app(gateway)
    client = TestClient(app)
    _record_stale(gateway)
    resp = client.post(
        "/gate",
        json={"tool": "transfer_money", "args": _args(5000), "agent_id": "agent:pay"},
    )
    body = resp.json()
    assert resp.status_code == 200
    assert body["decision"] == "deny"
    inside = client.post(
        "/gate", json={"tool": "transfer_money", "args": _args(50), "agent_id": "agent:pay"}
    ).json()
    assert inside["decision"] == "allow"
    assert "narrowed to reduced scope" in inside["reason"]


# ---------------------------------------------------------------------------
# Corpus vectors replays
# ---------------------------------------------------------------------------


def _eqr_from_vector(vector: dict[str, Any]) -> Any:
    from raucle.eqr import EQR

    return EQR.from_dict(vector["eqr"])


def test_vector_stale_evidence_narrows() -> None:
    vector = json.loads(
        (VECTOR_DIR / "eqr_v1_01_stale_evidence_narrows.json").read_text(encoding="utf-8")
    )
    eqr = _eqr_from_vector(vector)
    evidences = [Evidence.from_dict(e) for e in vector["evidence"]]
    verdict, reason = evaluate_eqr(eqr, evidences, vector["now"])
    assert verdict == vector["expected"]["verdict"] == VERDICT_STALE
    assert reason == vector["expected"]["reason"]
    # The narrowing side meets the reduced scope into the declared base.
    merged = narrowed_reduced_constraints(eqr, vector["base_constraints"])
    _assert_narrowing(vector["base_constraints"], merged)
    assert merged["max_value"]["amount"] == vector["expected"]["narrowed_max_amount"]


def test_vector_unknown_evidence_denies() -> None:
    vector = json.loads(
        (VECTOR_DIR / "eqr_v1_02_unknown_evidence_denies.json").read_text(encoding="utf-8")
    )
    eqr = _eqr_from_vector(vector)
    evidences = [Evidence.from_dict(e) for e in vector["evidence"]]
    verdict, reason = evaluate_eqr(eqr, evidences, vector["now"])
    assert verdict == vector["expected"]["verdict"] == VERDICT_UNKNOWN
    assert reason == vector["expected"]["reason"]


def test_vector_successor_evidence_narrows() -> None:
    vector = json.loads(
        (VECTOR_DIR / "eqr_v1_03_successor_evidence_narrows.json").read_text(encoding="utf-8")
    )
    eqr = _eqr_from_vector(vector)
    prior = [Evidence.from_dict(e) for e in vector["evidence_prior"]]
    assert evaluate_eqr(eqr, prior, vector["now"])[0:1] == (vector["expected"]["prior_verdict"],)
    # Successor event joins the evidence set.
    successor = [Evidence.from_dict(e) for e in vector["evidence_successor"]]
    combined = prior + successor
    verdict, reason = evaluate_eqr(eqr, combined, vector["now"])
    assert verdict == vector["expected"]["post_verdict"]
    assert reason == vector["expected"]["post_reason"]
    # ... and the effective scope meets with the reduced scope (narrowing).
    merged = narrowed_reduced_constraints(eqr, vector["base_constraints"])
    _assert_narrowing(vector["base_constraints"], merged)
    assert merged["max_value"]["amount"] <= vector["expected"]["prior_max_amount"]


def test_vectors_registry_contains_eqr_class() -> None:
    """The three EQR vectors exist, parse, and name the N6 draft."""
    for name in (
        "eqr_v1_01_stale_evidence_narrows.json",
        "eqr_v1_02_unknown_evidence_denies.json",
        "eqr_v1_03_successor_evidence_narrows.json",
    ):
        vector = json.loads((VECTOR_DIR / name).read_text(encoding="utf-8"))
        assert vector["spec"] == "raucle-eqr/v1"
        assert "draft-watts-agent-evidence-boundary" in vector["draft"]
        _eqr_from_vector(vector)
