"""RED-038: seam properties - the classes of bug the 2067-test suite missed.

Every finding in the 8 Nov review lived in a seam rather than in a rule the
suite already tested:

- a decision path that raised on a type it had not considered (RED-031)
- a persisted flag nobody wrote (RED-032)
- a value interpolated in the wrong context (RED-033)
- an index fed on one sink and not the other (RED-034)
- a boundary checked on the wrong field set (RED-035)

These are the invariants that generalise those: evaluators are total, a type
degradation cannot turn a deny into an allow, and every persisted store
survives a restart with its observable state intact.

Deliberately no Hypothesis: it is not in the dependency tree and a new
dev-dependency is a supply-chain decision. A fixed adversarial corpus covers
the failure class here, which is type confusion rather than deep input-space
exploration.
"""

from __future__ import annotations

from typing import Any

import pytest

from raucle.capability import _check_constraints
from raucle.policy import PolicyRule, check_approval_needed

# Every shape a JSON body can deliver, plus the ones that break naive code:
# bool-as-int, non-finite floats, numeric text, empty and huge strings,
# collections, and nesting.
VALUES: list[Any] = [
    None,
    True,
    False,
    0,
    1,
    -1,
    10**18,
    -(10**18),
    1.5,
    float("inf"),
    float("-inf"),
    float("nan"),
    "",
    "0",
    "1.5",
    "-1",
    "99999",
    "1e400",
    "0x10",
    "\x00",
    "a" * 4096,
    [],
    [1],
    ["1"],
    [None],
    {},
    {"a": 1},
    {"amount": "99999"},
    (1, 2),
    {1, 2},
]

CONSTRAINT_SETS: list[dict[str, Any]] = [
    {},
    {"max_value": {"amount": 5}},
    {"min_value": {"amount": 5}},
    {"allowed_values": {"amount": ["x"]}},
    {"forbidden_values": {"amount": ["x"]}},
    {"starts_with": {"amount": "ACC-"}},
    {"required_present": ["amount"]},
    {"forbidden_field_combinations": [["amount", "account"]]},
    {"forbidden_field_combinations": [["missing", "also_missing"]]},
    {
        "max_value": {"amount": 5},
        "min_value": {"amount": -5},
        "starts_with": {"account": "ACC-"},
        "allowed_values": {"kind": ["payment"]},
        "required_present": ["amount"],
    },
]


def _args_for(value: Any) -> list[dict[str, Any]]:
    return [
        {},
        {"amount": value},
        {"amount": value, "account": "ACC-001"},
        {"amount": value, "account": "ACC-001", "kind": "payment"},
        {"amount": value, "account": value, "kind": value},
    ]


class TestConstraintTotality:
    @pytest.mark.parametrize("constraints", CONSTRAINT_SETS)
    def test_never_raises_and_never_returns_an_empty_denial(self, constraints):
        for value in VALUES:
            for args in _args_for(value):
                reason = _check_constraints(constraints, args)
                assert reason is None or (isinstance(reason, str) and reason), (
                    f"non-total result for {constraints} / {args!r}: {reason!r}"
                )

    @pytest.mark.parametrize("value", VALUES)
    def test_non_numbers_never_satisfy_a_numeric_bound(self, value):
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            pytest.skip("numeric input; covered by the arithmetic tests")
        if isinstance(value, (list, tuple, set, frozenset, dict)):
            pytest.skip("collection; element-wise semantics covered separately")
        for constraint in ({"max_value": {"amount": 5}}, {"min_value": {"amount": -5}}):
            assert _check_constraints(constraint, {"amount": value}) is not None, (
                f"{value!r} satisfied {constraint} without being a number"
            )

    def test_numeric_bounds_are_one_sided_in_the_right_direction(self):
        assert _check_constraints({"max_value": {"amount": 5}}, {"amount": 5}) is None
        assert _check_constraints({"max_value": {"amount": 5}}, {"amount": 5.1}) is not None
        assert _check_constraints({"min_value": {"amount": 5}}, {"amount": 5}) is None
        assert _check_constraints({"min_value": {"amount": 5}}, {"amount": 4.9}) is not None

    def test_a_collection_is_checked_element_by_element(self):
        """FORALL semantics: one bad element denies the whole argument."""
        assert _check_constraints({"max_value": {"amount": 5}}, {"amount": [1, 2]}) is None
        assert _check_constraints({"max_value": {"amount": 5}}, {"amount": [1, 6]}) is not None
        assert _check_constraints({"allowed_values": {"amount": ["A"]}}, {"amount": ["A"]}) is None
        assert (
            _check_constraints({"allowed_values": {"amount": ["A"]}}, {"amount": ["A", "B"]})
            is not None
        )

    def test_a_forbidden_value_is_found_inside_a_collection(self):
        constraint = {"forbidden_values": {"to": ["evil@example.com"]}}
        assert _check_constraints(constraint, {"to": "evil@example.com"}) is not None
        assert (
            _check_constraints(constraint, {"to": ["good@example.com", "evil@example.com"]})
            is not None
        )
        assert _check_constraints(constraint, {"to": {"x": "evil@example.com"}}) is not None
        assert _check_constraints(constraint, {"to": ["good@example.com"]}) is None

    def test_a_stringified_number_never_slips_a_numeric_bound(self):
        """RED-031's class: the string form must not become an allow."""
        for bound, value in ((5, "6"), (5, "5.000001"), (5, "1e9"), (-5, "-6")):
            key = "max_value" if bound > 0 else "min_value"
            assert _check_constraints({key: {"amount": bound}}, {"amount": value}) is not None


class TestApprovalTotality:
    @pytest.mark.parametrize("value", VALUES)
    def test_never_raises(self, value):
        rule = PolicyRule(
            tool="pay",
            agent_id="agent:bot",
            require_approval_when={"amount_gt": 5000, "amount_eq": 10000},
        )
        assert isinstance(check_approval_needed(rule, {"amount": value}), bool)

    @pytest.mark.parametrize("operator", ["gt", "lt", "gte", "lte", "eq"])
    def test_every_operator_is_total_for_every_value(self, operator):
        rule = PolicyRule(
            tool="pay",
            agent_id="agent:bot",
            require_approval_when={f"amount_{operator}": 5000},
        )
        for value in VALUES:
            assert isinstance(check_approval_needed(rule, {"amount": value}), bool)

    def test_a_monotone_threshold_escalates_at_least_as_often_as_its_integer_case(self):
        """A larger numeric value must never need less scrutiny than a smaller
        one. This is the property an escalation rule exists to provide."""
        rule = PolicyRule(
            tool="pay",
            agent_id="agent:bot",
            require_approval_when={"amount_gt": 5000},
        )
        values = [5000, 5001, 10**6, 10**18]
        escalations = [check_approval_needed(rule, {"amount": v}) for v in values]
        assert escalations[0] is False
        assert all(escalations[1:]), escalations
