"""I1: counterfactual replay - "would a stricter policy have prevented
this incident?"

The incident already happened: the receipts record what the gate allowed.
The counterfactual question is the one every incident review asks next:
under the policy we SHOULD have had, would those actions have gone
through?

The replay is deterministic, not statistical. Each recorded gate decision
with a stored input is re-run through the same gate machinery configured
with the ALTERNATIVE policy (authority held constant; the question is a
policy question). The answer per action: the alternative policy would have
allowed it, or would have denied it. The summary: how many of the
incident's allowed actions the alternative policy would have prevented.

The z3 leg adds a PROOF alongside the replay. A prevented action carries a
``proof`` field: PROVEN that the alternative policy's constraints exclude
the whole recorded argument CLASS (derive a JSON schema from the recorded
args' shapes - field names and primitive types only, never values - and
ask JSONSchemaProver.prove_exclusion whether any object of that shape can
satisfy the alternative constraints). REFUTED names the escaping FIELD,
never a value: the deny was value-specific, not structural. UNDECIDED is
honest: constraint kinds the prover does not model (allowed_values,
starts_with), argument shapes outside its grammar, an alternative policy
that denies by absence of grant rather than constraints, or z3 not
installed. UNDECIDED is never upgraded; the replay verdict stands on its
own either way.

Privacy shape unchanged: receipts carry only input hashes; the args come
from the input store kept alongside the chain (raucle.replay), and only
when the operator recorded them. A receipt without a stored input is
reported as unreplayable, never guessed. Bounded disclosure holds in the
report and in every proof row: no denial reasons, no arg values, no
constraint values; a counterexample contributes field NAMES only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_HASH_PREFIX = "sha256:"


def _receipt_decisions(chain_path: str | Path) -> list[dict[str, Any]]:
    """The gate decisions in a receipt chain, in order (envelope decoded)."""
    import base64

    decisions: list[dict[str, Any]] = []
    for line in Path(chain_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            envelope = json.loads(line)
            seg = envelope["jws"].split(".")
            payload = json.loads(base64.urlsafe_b64decode(seg[1] + "==" * (-len(seg[1]) % 4)))
        except (KeyError, ValueError):  # JSONDecodeError is a ValueError (S5713)
            continue
        block = payload.get("x_gate")
        if isinstance(block, dict) and block.get("decision"):
            decisions.append(
                {
                    "receipt_hash": envelope.get("receipt_hash", ""),
                    "input_hash": str(payload.get("input_hash", "")),
                    "decision": block.get("decision", ""),
                    "tool": block.get("tool", ""),
                    "agent_id": block.get("agent_id", ""),
                }
            )
    return decisions


def _lookup_input(store: Any, input_hash: str) -> str | None:
    """Receipts carry bare hex digests; the store keys with the sha256:
    prefix. Try both spellings, then verify the text hashes back."""
    for candidate in (input_hash, _HASH_PREFIX + input_hash):
        stored = store.get(candidate)
        if stored is not None:
            return stored.text
    return None


_JSON_TYPES: tuple[tuple[type, str], ...] = (
    (bool, "boolean"),
    (str, "string"),
    (int, "integer"),
    (float, "number"),
)


def _shape_schema(args: dict[str, Any]) -> dict[str, Any] | None:
    """Derive the recorded argument CLASS schema from the args' shapes.

    Field names and primitive JSON types only: recorded VALUES never enter
    the schema. Every recorded field is required and nothing else is
    admitted, so the class is exactly "calls with these fields, of these
    types". Returns None for shapes the constraint prover does not model
    (lists, nested objects, nulls, or no fields at all) - the caller
    reports that honestly as UNDECIDED, never guesses.
    """
    properties: dict[str, Any] = {}
    for name, value in args.items():
        # bool before int: bool is an int subclass in python
        for py_type, json_type in _JSON_TYPES:
            if isinstance(value, py_type):
                properties[name] = {"type": json_type}
                break
        else:
            return None
    if not properties:
        return None
    return {
        "type": "object",
        "properties": properties,
        "required": sorted(properties),
        "additionalProperties": False,
    }


def _find_alt_rule(alt_rules: Any, tool: str) -> Any:
    """The alternative-policy rule the replay gate itself used: first rule
    for the tool matching the replay's (empty) source/destination."""
    for rule in alt_rules.policies:
        if rule.tool == tool and rule.matches("", ""):
            return rule
    return None


def _prove_prevention(args: dict[str, Any], alt_rules: Any, tool: str) -> dict[str, Any]:
    """The z3 leg: prove the alternative policy's constraints exclude the
    recorded argument CLASS, not just the recorded values.

    Returns the bounded proof row. Bounded disclosure by construction:
    status, prover identity, the grammar/policy HASHES (which bind the
    material without disclosing it), honest notes, and - when REFUTED -
    the escaping field NAMES. Counterexample VALUES never leave the
    prover; recorded VALUES and constraint VALUES never enter the row.
    """
    from raucle.prove import JSONSchemaProver, UnsupportedGrammar

    rule = _find_alt_rule(alt_rules, tool)
    if rule is None:
        return {
            "status": "UNDECIDED",
            "notes": [
                f"no alternative-policy rule matches tool {tool!r}: the "
                f"counterfactual denial is by absence of grant, which the "
                f"constraint prover does not model"
            ],
        }

    schema = _shape_schema(args)
    if schema is None:
        return {
            "status": "UNDECIDED",
            "notes": [
                "the recorded args carry a shape the constraint prover does "
                "not model (non-primitive field or no fields); replay stands, "
                "no proof claim"
            ],
        }

    # the compiled constraint set is exactly what the gate enforced in the
    # replay; pass it through verbatim and let the prover's registry decide
    # what it can model (unmodelled kinds yield UNDECIDED, never a proof)
    policy = rule.to_mint_kwargs()["constraints"]
    try:
        result = JSONSchemaProver().prove_exclusion(schema, policy)
    except ImportError:
        return {
            "status": "UNDECIDED",
            "notes": [
                "z3 is not installed (pip install 'raucle[proof]'); the "
                "prover cannot run; replay stands, no proof claim"
            ],
        }
    except UnsupportedGrammar as exc:
        return {"status": "UNDECIDED", "notes": [f"unsupported grammar: {exc}"]}

    proof: dict[str, Any] = {
        "status": result.status,
        "prover": result.prover,
        "prover_version": result.prover_version,
        "grammar_hash": result.grammar_hash,
        "policy_hash": result.policy_hash,
        "notes": list(result.notes),
    }
    if result.counterexample is not None:
        # field NAMES only: the counterexample VALUES stay inside the prover
        proof["counterexample_fields"] = sorted(result.counterexample)
    return proof


def _count_proof_status(rows: list[dict[str, Any]], status: str) -> int:
    """How many replayed actions carry a proof of the given status."""
    return sum(1 for r in rows if r.get("proof", {}).get("status") == status)


def replay_counterfactual(
    chain_path: str | Path,
    *,
    input_store_path: str | Path,
    alternative_policy_path: str | Path,
) -> dict[str, Any]:
    """Replay every recorded decision against the alternative policy.

    Returns the report: per-action counterfactuals plus the summary
    verdict. Actions without a stored input are unreplayable, never
    guessed."""
    from raucle.gateway import GatewayConfig, RaucleGateway
    from raucle.policy import PolicyFile
    from raucle.replay import InputStore

    alt_rules = PolicyFile.load(alternative_policy_path)

    replayed: list[dict[str, Any]] = []
    unreplayable = 0
    prevented = 0
    still_allowed = 0
    would_have_denied_denies = 0

    with InputStore.open(input_store_path) as store:
        # a throwaway receipt store: the replay gateway must not append to
        # the incident chain
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            config = GatewayConfig(
                host="127.0.0.1",
                admin_api_key="replay",
                signer_backend="local",
                policy_file=str(alternative_policy_path),
                receipt_store=str(Path(td) / "replay-receipts.jsonl"),
                audit_chain=str(Path(td) / "replay-audit.jsonl"),
                registry_path=str(Path(td) / "registry.jsonl"),
                agent_credentials_file=str(Path(td) / "agent-credentials.jsonl"),
                emit_receipts=False,
            )
            config.gate_auth = "off"
            gateway = RaucleGateway(config)

            for rec in _receipt_decisions(chain_path):
                text = _lookup_input(store, rec["input_hash"])
                if text is None:
                    unreplayable += 1
                    continue
                try:
                    args = json.loads(text)
                except json.JSONDecodeError:
                    unreplayable += 1
                    continue
                if not isinstance(args, dict):
                    unreplayable += 1
                    continue

                alt = gateway.check_tool_call(rec["tool"], args, agent_id=rec["agent_id"])
                alt_decision = alt.get("decision", "")
                # bounded disclosure: no reasons in the report - the denial
                # reason can quote constraint VALUES. The receipt cites the
                # chain; the full reason lives there.
                row = {
                    "receipt_hash": rec["receipt_hash"],
                    "tool": rec["tool"],
                    "agent_id": rec["agent_id"],
                    "original_decision": rec["decision"],
                    "counterfactual_decision": alt_decision,
                }
                if rec["decision"] == "allow" and alt_decision == "deny":
                    prevented += 1
                    row["prevented"] = True
                    # the z3 leg: a PROOF alongside the replay verdict
                    row["proof"] = _prove_prevention(args, alt_rules, rec["tool"])
                else:
                    row["prevented"] = False
                    if rec["decision"] == "allow" and alt_decision == "allow":
                        still_allowed += 1
                    elif rec["decision"] == "deny" and alt_decision == "deny":
                        would_have_denied_denies += 1
                replayed.append(row)

    total_replayed = len(replayed)
    prevented_proven = _count_proof_status(replayed, "PROVEN")
    prevented_refuted = _count_proof_status(replayed, "REFUTED")
    prevented_undecided = _count_proof_status(replayed, "UNDECIDED")
    verdict = (
        f"the alternative policy would have prevented {prevented} of "
        f"{prevented + still_allowed} actions the original policy allowed"
        if (prevented + still_allowed) > 0
        else "no replayable allowed actions in the chain"
    )
    if prevented_proven > 0:
        # state the proof, not the replay alone; UNDECIDED and REFUTED never
        # upgrade the sentence
        verdict += (
            f"; {prevented_proven} proven to exclude the recorded argument class"
            f" (no call of that shape satisfies the alternative policy)"
        )
    return {
        "chain": str(chain_path),
        "alternative_policy": str(alternative_policy_path),
        "alternative_policy_rules": len(alt_rules.policies),
        "actions_replayed": total_replayed,
        "actions_unreplayable": unreplayable,
        "allowed_under_original": sum(1 for r in replayed if r["original_decision"] == "allow"),
        "prevented_by_alternative": prevented,
        "still_allowed_by_alternative": still_allowed,
        "denies_under_both": would_have_denied_denies,
        "prevented_proven": prevented_proven,
        "prevented_refuted": prevented_refuted,
        "prevented_undecided": prevented_undecided,
        "verdict": verdict,
        "actions": replayed,
    }
