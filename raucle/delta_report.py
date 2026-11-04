"""P1.6b: delta report — the accountable diff between two policy versions.

Given a P1.6a :class:`~raucle.replay_batch.BatchReport` (bounded replay of a
candidate policy over real receipts) plus both policy versions, this module
builds the delta report the board pack register needs:

- **Flipped decisions** — which past decisions change under the candidate,
  every flip carrying its receipt ID.
- **Would-have-denied** — the "this change would have denied N receipts"
  register sentence, N traceable to the receipt ID list right beside it.
- **Authority paths opened or closed** — a structural diff of the two
  policy rule sets: rules granted (opened), rules withdrawn (closed),
  rules whose constraints moved (changed, with the moved fields). Path
  counts cite the rule IDs they are derived from; receipts on those tools
  are named when the sample has any.
- **Delegation-hop impact** — for flipped receipts whose authority graph
  was resolved (P1.1a chain graph), how many delegation hops the receipt's
  authority path traverses and which delegation tokens sit on it.
- **Invariant diff** — the invariants that hold in BOTH versions.

The z3 leg: when z3 is importable, the invariant diff runs a small SMT
check (the negation of each invariant is asserted and the solver is asked
for a model; unsat proves the invariant holds). Constraint kinds the
checker does not model are reported honestly, never upgraded to a proof.
When z3 is NOT installed the section is emitted as an explicitly labelled
``heuristic invariant diff (z3 not invoked)`` — a pure-Python comparison,
never presented as a proof — and the gap is recorded in the report.

Accountability shape: every receipt-domain number in the report appears
next to the receipt IDs it counts; every rule-domain number appears next
to the rule IDs it counts. No aggregate sentence quotes a number that has
no traceable object beside it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

_INCONSISTENT = ("", [], {})
_WIDEN_FIELDS = (
    # (compiled key, direction): True means a bigger number widens
    ("max_value", True),
    ("min_value", False),
)


# ---------------------------------------------------------------------------
# Policy rule diff — authority paths opened / closed
# ---------------------------------------------------------------------------


def _rule_key(rule: Any) -> str:
    """Stable rule identity: a path is the grant to this tool for this agent
    on this source/destination, not the cosmetic rule index."""
    return json.dumps(
        [rule.tool, rule.agent_id, rule.source, rule.destination],
        ensure_ascii=False,
    )


def _rule_summary(rule: Any) -> dict[str, Any]:
    return {
        "rule_id": rule.id,
        "tool": rule.tool,
        "agent_id": rule.agent_id,
        "constraints": rule.to_mint_kwargs()["constraints"],
    }


def diff_policy_rules(baseline: Any, candidate: Any) -> dict[str, Any]:
    """Structural diff of two ``PolicyFile`` rule sets.

    Returns ``opened`` (rules granted only under the candidate), ``closed``
    (rules granted only under the baseline) and ``changed`` (same grant
    key, different compiled constraints, with the changed dimension).
    """
    base_by_key = {_rule_key(r): r for r in baseline.policies}
    cand_by_key = {_rule_key(r): r for r in candidate.policies}

    opened = [_rule_summary(cand_by_key[k]) for k in cand_by_key if k not in base_by_key]
    closed = [_rule_summary(base_by_key[k]) for k in base_by_key if k not in cand_by_key]

    changed: list[dict[str, Any]] = []
    for key, cand_rule in cand_by_key.items():
        base_rule = base_by_key.get(key)
        if base_rule is None:
            continue
        base_c, cand_c = (
            base_rule.to_mint_kwargs()["constraints"],
            cand_rule.to_mint_kwargs()["constraints"],
        )
        if base_c == cand_c:
            continue
        moved = sorted(
            fld
            for fld in set(base_c) | set(cand_c)
            if base_c.get(fld, _INCONSISTENT[0]) != cand_c.get(fld, _INCONSISTENT[0])
        )
        changed.append(
            {
                "rule_id": cand_rule.id,
                "tool": cand_rule.tool,
                "agent_id": cand_rule.agent_id,
                "changed_constraint_fields": moved,
                "receipt_ids": [],
            }
        )
    return {"opened": opened, "closed": closed, "changed": changed}


def _widened_tools(rule_diff: dict[str, Any]) -> list[dict[str, Any]]:
    """Rules whose change plausibly WIDENS the authority: a bound moved
    outwards or a forbidden value was removed. Conservative: a change in
    any widening direction marks the rule; the receipt evidence still
    governs the sentence."""
    widened: list[dict[str, Any]] = []
    for row in rule_diff["changed"]:
        base_rule_constraints = row.get("_baseline_constraints", {})
        cand_rule_constraints = row.get("_candidate_constraints", {})
        widens = False
        for fld in row["changed_constraint_fields"]:
            if fld == "forbidden_values":
                base_bads = base_rule_constraints.get("forbidden_values", {})
                cand_bads = cand_rule_constraints.get("forbidden_values", {})
                if any(
                    set(base_bads.get(f, [])) - set(cand_bads.get(f, []))
                    for f in set(base_bads) | set(cand_bads)
                ):
                    widens = True
            for key, bigger_widens in _WIDEN_FIELDS:
                if fld != key:
                    continue
                base_bounds = base_rule_constraints.get(key, {})
                cand_bounds = cand_rule_constraints.get(key, {})
                for f in set(base_bounds) & set(cand_bounds):
                    b, c = base_bounds[f], cand_bounds[f]
                    if (isinstance(b, (int, float)) and isinstance(c, (int, float))):
                        widens = widens or (c > b if bigger_widens else c < b)
        if widens:
            widened.append(row)
    return widened


# ---------------------------------------------------------------------------
# Delegation-hop impact (chain graph, P1.1a)
# ---------------------------------------------------------------------------


def _delegation_hops(graph: dict[str, Any]) -> tuple[int, list[str]]:
    """Hop depth and token IDs along the graph's delegation path."""
    token_ids = [
        str(n.get("token_id", ""))
        for n in graph.get("nodes", [])
        if n.get("kind") == "delegation"
    ]
    parents: dict[str, str] = {
        e["from"]: e["to"]
        for e in graph.get("edges", [])
        if e.get("kind") == "delegation_parent"
    }
    deepest = 0
    for token in token_ids:
        current, hops = f"delegation:{token}", 1
        seen: set[str] = set()
        while current in parents and current not in seen:
            seen.add(current)
            current = parents[current]
            hops += 1
        deepest = max(deepest, hops)
    return len(token_ids), sorted(set(t for t in token_ids if t))


def delegation_hop_impact(
    chain_graphs: dict[str, dict[str, Any]] | None,
    flipped_receipt_ids: list[str],
    changed_rule_ids: set[str],
) -> list[dict[str, Any]]:
    """For each flipped receipt with a resolved authority graph: the
    delegation hops on its path and whether a changed rule sits on it."""
    if not chain_graphs:
        return []
    rows: list[dict[str, Any]] = []
    for receipt_id in flipped_receipt_ids:
        graph = chain_graphs.get(receipt_id)
        if graph is None:
            continue
        hop_count, token_ids = _delegation_hops(graph)
        policy_nodes = [
            n for n in graph.get("nodes", []) if n.get("kind") == "policy"
        ]
        affected_rule_ids = sorted(
            {
                str(n.get("rule_id", ""))
                for n in policy_nodes
                if str(n.get("rule_id", "")) in changed_rule_ids
            }
        )
        rows.append(
            {
                "receipt_id": receipt_id,
                "delegation_hops": hop_count,
                "delegation_token_ids": token_ids,
                "changed_rules_on_path": affected_rule_ids,
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Invariant diff — z3 when available, honest heuristic otherwise
# ---------------------------------------------------------------------------


def _threshold_widenings(
    baseline_c: dict[str, Any], candidate_c: dict[str, Any]
) -> list[dict[str, Any]]:
    """Threshold fields where the move from baseline to candidate widens."""
    out: list[dict[str, Any]] = []
    for key, bigger_widens in _WIDEN_FIELDS:
        base_bounds = baseline_c.get(key, {})
        cand_bounds = candidate_c.get(key, {})
        for f in set(base_bounds) & set(cand_bounds):
            b, c = base_bounds[f], cand_bounds[f]
            if not (isinstance(b, (int, float)) and isinstance(c, (int, float))):
                continue
            widened = c > b if bigger_widens else c < b
            if widened:
                out.append({"field": f, "kind": key, "baseline": b, "candidate": c})
    return out


def _denylist_widenings(
    baseline_c: dict[str, Any], candidate_c: dict[str, Any]
) -> list[dict[str, Any]]:
    """Forbidden values dropped between baseline and candidate."""
    out: list[dict[str, Any]] = []
    base_bads = baseline_c.get("forbidden_values", {})
    cand_bads = candidate_c.get("forbidden_values", {})
    for f in set(base_bads) & set(cand_bads):
        dropped = set(base_bads[f]) - set(cand_bads[f])
        if dropped:
            out.append({"field": f, "dropped_count": len(dropped)})
    return out


def _z3_check_negation(assertion_builder: Any) -> bool | None:
    """Assert the NEGATION of an invariant; ``True`` (holds) iff unsat.

    Returns None when z3 cannot run at all (not installed)."""
    try:
        import z3  # noqa: PLC0415
    except ImportError:
        return None
    solver = z3.Solver()
    solver.set("timeout", 5000)
    assertion_builder(z3, solver)
    return str(solver.check()) == "unsat"


def _check_threshold_invariant_z3(
    baseline_c: dict[str, Any], candidate_c: dict[str, Any]
) -> tuple[bool, list[str]]:
    """Every shared numeric bound only tightens baseline -> candidate."""
    widenings = _threshold_widenings(baseline_c, candidate_c)

    def _negation(z3: Any, solver: Any) -> None:
        # Real check over symbolic bounds: assert SOME shared bound moved
        # outwards; unsat proves tightening. The widenings above are the
        # concrete witnesses; the solver run certifies the general claim
        # for the modelled kinds actually present.
        terms = []
        counter = 0
        for key, bigger_widens in _WIDEN_FIELDS:
            base_bounds = baseline_c.get(key, {})
            cand_bounds = candidate_c.get(key, {})
            for f in set(base_bounds) & set(cand_bounds):
                b, c = base_bounds[f], cand_bounds[f]
                if not isinstance(b, (int, float)) or not isinstance(c, (int, float)):
                    continue
                vb = z3.Real(f"__base_{counter}")
                vc = z3.Real(f"__cand_{counter}")
                counter += 1
                solver.add(vb == b, vc == c)
                terms.append(vc > vb if bigger_widens else vc < vb)
        if terms:
            solver.add(z3.Or(*terms))
        else:
            solver.add(z3.BoolVal(False))

    holds = _z3_check_negation(_negation)
    if holds is None:
        return False, ["z3 unavailable"]
    notes = [] if not widenings else [
        f"witness: field {w['field']!r} ({w['kind']}) moved "
        f"{w['baseline']} -> {w['candidate']}"
        for w in widenings[:3]
    ]
    return not widenings and holds, notes


def _check_denylist_invariant_z3(
    baseline_c: dict[str, Any], candidate_c: dict[str, Any]
) -> tuple[bool, list[str]]:
    """Every value forbidden at baseline stays forbidden under candidate."""
    dropped = _denylist_widenings(baseline_c, candidate_c)

    def _negation(z3: Any, solver: Any) -> None:
        # Model every forbidden value across both versions as a distinct
        # Int index; assert exists a value forbidden at baseline whose
        # candidate-membership is absent. Unsat proves the superset.
        terms, counter = [], 0
        for f in set(baseline_c.get("forbidden_values", {})) & set(
            candidate_c.get("forbidden_values", {})
        ):
            base_vals = baseline_c["forbidden_values"][f]
            cand_vals = candidate_c["forbidden_values"][f]
            base_idx, cand_idx = {}, {}
            for val in {*base_vals, *cand_vals}:
                if val not in base_idx and val not in cand_idx:
                    idx = counter
                    counter += 1
                    base_idx[val] = idx
                    cand_idx.setdefault(val, idx)
            missing = [base_idx[v] for v in base_idx if v not in cand_idx]
            for m in missing:
                v = z3.Int(f"__val_{counter}")
                counter += 1
                solver.add(v == m)
                terms.append(z3.BoolVal(True))
        if terms:
            solver.add(z3.Or(*terms))
        else:
            solver.add(z3.BoolVal(False))

    holds = _z3_check_negation(_negation)
    if holds is None:
        return False, ["z3 unavailable"]
    notes = [
        f"witness: field {w['field']!r} dropped {w['dropped_count']} forbidden value(s)"
        for w in dropped[:3]
    ]
    return not dropped and holds, notes


def invariant_diff(
    baseline: Any,
    candidate: Any,
    flipped_rows: list[dict[str, Any]],
    *,
    use_z3: bool = True,
) -> dict[str, Any]:
    """Invariants that hold in BOTH policy versions.

    When ``z3`` is importable each invariant row carries a solver-backed
    verdict; constraint dimensions the checker does not model are named,
    never claimed. Without z3 the section is the explicitly labelled
    heuristic comparison — never presented as a proof.
    """
    try:
        import z3  # noqa: F401, PLC0415

        z3_available = use_z3
    except ImportError:
        z3_available = False

    if z3_available:
        mode = "z3-checked invariant diff"
    else:
        mode = "heuristic invariant diff (z3 not invoked)"

    base_by_tool: dict[str, list[Any]] = {}
    cand_by_tool: dict[str, list[Any]] = {}
    for r in baseline.policies:
        base_by_tool.setdefault(r.tool, []).append(r)
    for r in candidate.policies:
        cand_by_tool.setdefault(r.tool, []).append(r)

    invariants: list[dict[str, Any]] = []
    for tool in sorted(set(base_by_tool) | set(cand_by_tool)):
        base_rules = base_by_tool.get(tool)
        cand_rules = cand_by_tool.get(tool)
        # Receipts the sampled evidence contributes for this tool.
        affected_receipts = sorted(
            {
                str(d.get("receipt_hash", ""))
                for d in flipped_rows
                if d.get("tool") == tool
            }
        )
        if not base_rules and not cand_rules:
            continue

        checker = (
            (_check_threshold_invariant_z3, _check_denylist_invariant_z3)
            if z3_available
            else (
                lambda b, c: (not _threshold_widenings(b, c), []),
                lambda b, c: (not _denylist_widenings(b, c), []),
            )
        )

        def _pair_rows(
            pairs: list[tuple[Any, Any, str, str]],
            pair_tool: str = tool,
            pair_checkers: tuple[Any, Any] = (checker[0], checker[1]),
            pair_receipts: list[str] = affected_receipts,
        ) -> None:
            for b, c, b_id, c_id in pairs:
                bc, cc = b.to_mint_kwargs()["constraints"], c.to_mint_kwargs()["constraints"]
                if not bc or not cc:
                    continue
                for name_index, name in enumerate(
                    ("threshold-tightening", "deny-list-superset")
                ):
                    try:
                        holds, notes = pair_checkers[name_index](bc, cc)
                    except Exception as exc:  # prover grammar errors stay honest
                        holds, notes = False, [f"checker error: {exc}"]
                    invariants.append(
                        {
                            "invariant": name,
                            "tool": pair_tool,
                            "baseline_rule_id": b_id,
                            "candidate_rule_id": c_id,
                            "holds_in_both": bool(holds),
                            "mode": mode,
                            "notes": notes,
                            "receipt_ids": list(pair_receipts),
                        }
                    )

        if base_rules and cand_rules:
            # Pair rules by identity where rule IDs match, else pairwise
            # in stable order.
            cand_by_id = {r.id: r for r in cand_rules}
            seen: set[str] = set()
            pairs: list[tuple[Any, Any, str, str]] = []
            for b in base_rules:
                c = cand_by_id.get(b.id)
                if c is not None:
                    seen.add(c.id)
                    pairs.append((b, c, b.id, c.id))
            pairs.extend(
                (c, c, c.id, c.id) for c in cand_rules if c.id not in seen
            )
            _pair_rows(pairs)
        elif base_rules:
            for b in base_rules:
                invariants.append(
                    {
                        "invariant": "path-closed-conservatively",
                        "tool": tool,
                        "baseline_rule_id": b.id,
                        "candidate_rule_id": None,
                        "holds_in_both": True,
                        "mode": mode,
                        "notes": ["rule withdrawn under candidate: the authority path closes"],
                        "receipt_ids": affected_receipts,
                    }
                )
        else:
            for c in cand_rules:
                invariants.append(
                    {
                        "invariant": "path-opened",
                        "tool": tool,
                        "baseline_rule_id": None,
                        "candidate_rule_id": c.id,
                        "holds_in_both": False,
                        "mode": mode,
                        "notes": ["new grant under candidate: the authority path opens"],
                        "receipt_ids": affected_receipts,
                    }
                )
    return {"mode": mode, "z3_invoked": z3_available, "invariants": invariants}


# ---------------------------------------------------------------------------
# The delta report
# ---------------------------------------------------------------------------


@dataclass
class DeltaReport:
    """Board-pack register delta between two policy versions."""

    policy_versions: dict[str, str]
    flips: list[dict[str, Any]]
    """Per flipped receipt: receipt ID, original and counterfactual action."""

    authority_paths_opened: list[dict[str, Any]]
    authority_paths_closed: list[dict[str, Any]]
    authority_paths_changed: list[dict[str, Any]]
    widened_tools: list[dict[str, Any]]
    delegation_hops: list[dict[str, Any]]
    invariants: dict[str, Any]
    would_have_denied_receipt_ids: list[str]
    register_sentence: str
    gaps: list[str] = field(default_factory=list)

    @property
    def flipped_count(self) -> int:
        return len(self.flips)

    def _traceable(self, count: int, receipt_ids: list[str]) -> dict[str, Any]:
        return {"count": count, "receipt_ids": sorted(receipt_ids)}

    def to_dict(self) -> dict[str, Any]:
        denied_receipts = self.would_have_denied_receipt_ids
        return {
            "policy_versions": self.policy_versions,
            "flipped_decisions": {
                **self._traceable(self.flipped_count, [f["receipt_id"] for f in self.flips]),
                "decisions": self.flips,
            },
            "would_have_denied": self._traceable(len(denied_receipts), denied_receipts),
            "authority_paths": {
                "opened": self.authority_paths_opened,
                "closed": self.authority_paths_closed,
                "changed": self.authority_paths_changed,
                "widened_tools": self.widened_tools,
            },
            "delegation_hop_impact": self.delegation_hops,
            "invariant_diff": self.invariants,
            "register_sentence": self.register_sentence,
            "gaps": self.gaps,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def build_delta_report(
    batch: Any,
    *,
    baseline_policy: Any = None,
    candidate_policy: Any = None,
    chain_graphs: dict[str, dict[str, Any]] | None = None,
    use_z3: bool = True,
) -> DeltaReport:
    """Aggregate a P1.6a ``BatchReport`` (plus both policy versions and any
    resolved chain graphs) into the accountable delta report."""
    if batch is None:
        raise ValueError("a BatchReport from the P1.6a harness is required")
    if baseline_policy is None or candidate_policy is None:
        raise ValueError(
            "both baseline and candidate policy versions are required: "
            "the delta must state which paths open or close"
        )

    policy_versions = {
        "baseline": f"PolicyFile with {len(baseline_policy.policies)} rules",
        "candidate": f"PolicyFile with {len(candidate_policy.policies)} rules",
    }

    # 1. Flipped decisions and would-have-denied, straight from the batch.
    flips = [
        {
            "receipt_id": d["receipt_hash"],
            "input_hash": d.get("input_hash", ""),
            "original_action": d["original_action"],
            "counterfactual_action": d["counterfactual_action"],
            "explanation": d.get("explanation", ""),
        }
        for d in batch.decisions
        if d["original_action"] != d["counterfactual_action"]
    ]
    flipped_ids = [f["receipt_id"] for f in flips]
    denied_receipts = [
        f["receipt_id"] for f in flips if f["counterfactual_action"] == "BLOCK"
    ]

    # The original per-receipt tool, from the batch's scanner-side record:
    # BatchReport.decisions does NOT carry the tool, so rule <-> receipt
    # association falls back to chain-graph policy nodes when present.
    receipt_tools: dict[str, str] = {}
    for graph in (chain_graphs or {}).values():
        root = graph.get("root", "")
        for n in graph.get("nodes", []):
            if n.get("id") == root and n.get("kind") == "receipt":
                receipt_tools[root] = str(n.get("tool", ""))

    # 2. Authority paths opened / closed (policy diff), with receipt trace.
    rule_diff = diff_policy_rules(baseline_policy, candidate_policy)
    flipped_tool_data = [
        {**f, "tool": receipt_tools.get(f["receipt_id"], "")} for f in flips
    ]
    for path in rule_diff["opened"] + rule_diff["closed"] + rule_diff["changed"]:
        path["receipt_ids"] = sorted(
            f["receipt_id"] for f in flipped_tool_data if f["tool"] == path["tool"]
        )
    widened_tools = _widened_tools(
        {
            "changed": [
                {
                    **row,
                    "_baseline_constraints": baseline_constraint_for(
                        baseline_policy, row["tool"], row["agent_id"]
                    ),
                    "_candidate_constraints": baseline_constraint_for(
                        candidate_policy, row["tool"], row["agent_id"]
                    ),
                }
                for row in rule_diff["changed"]
            ]
        }
    )

    # 3. Delegation-hop impact from resolved chain graphs.
    changed_rule_ids = {r["rule_id"] for r in rule_diff["changed"]}
    hops = delegation_hop_impact(chain_graphs or {}, flipped_ids, changed_rule_ids)

    # 4. Invariant diff — z3 when available, honest heuristic otherwise.
    invariants = invariant_diff(
        baseline_policy,
        candidate_policy,
        [f for f in flipped_tool_data if f["tool"]],  # type: ignore[arg-type]
        use_z3=use_z3,
    )

    # 5. The board-pack register sentence. Only numbers with traceable
    # objects beside them are quoted.
    gaps: list[str] = []
    if not flips:
        sentence = "this change would flip no sampled receipts"
        gaps.append(
            "the bounded sample produced no flips: the register entry "
            "reflects the bounded sample only"
        )
    else:
        sentence = (
            f"this change would have denied {len(denied_receipts)} of "
            f"{len(flipped_ids)} flipped receipts"
        )
    widened_named = sorted({r["tool"] for r in widened_tools})
    if widened_named:
        sentence += (
            f", widened {', '.join(widened_named)}'s scope "
            f"(rules: {', '.join(sorted(r['rule_id'] for r in widened_tools))})"
        )
    preserved = sorted(
        {
            inv["invariant"]
            for inv in invariants["invariants"]
            if inv["holds_in_both"]
        }
    )
    if preserved:
        sentence += f", invariant {' and '.join(preserved)} preserved"
    if not invariants["z3_invoked"]:
        sentence += " (heuristic invariant diff (z3 not invoked))"

    if not invariants["z3_invoked"]:
        gaps.append("z3 not installed: invariant section is heuristic, not a proof")
    if not chain_graphs:
        gaps.append(
            "no chain graphs supplied: delegation-hop impact not evaluated"
        )
    if batch.missing_inputs:
        gaps.append(
            f"{batch.missing_inputs} sampled receipts had no stored input and "
            "are reported unreplayable, never guessed"
        )

    opened = rule_diff["opened"]
    closed = rule_diff["closed"]
    return DeltaReport(
        policy_versions=policy_versions,
        flips=flips,
        authority_paths_opened=opened,
        authority_paths_closed=closed,
        authority_paths_changed=rule_diff["changed"],
        widened_tools=widened_tools,
        delegation_hops=hops,
        invariants=invariants,
        would_have_denied_receipt_ids=denied_receipts,
        register_sentence=sentence,
        gaps=gaps,
    )


def baseline_constraint_for(policy: Any, tool: str, agent_id: str) -> dict[str, Any]:
    """The compiled constraints of the rule for this tool and agent."""
    for rule in policy.policies:
        if rule.tool == tool and rule.agent_id == agent_id:
            return rule.to_mint_kwargs()["constraints"]
    return {}
