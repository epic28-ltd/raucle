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

Privacy shape unchanged: receipts carry only input hashes; the args come
from the input store kept alongside the chain (raucle.replay), and only
when the operator recorded them. A receipt without a stored input is
reported as unreplayable, never guessed.
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
                else:
                    row["prevented"] = False
                    if rec["decision"] == "allow" and alt_decision == "allow":
                        still_allowed += 1
                    elif rec["decision"] == "deny" and alt_decision == "deny":
                        would_have_denied_denies += 1
                replayed.append(row)

    total_replayed = len(replayed)
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
        "verdict": (
            f"the alternative policy would have prevented {prevented} of "
            f"{prevented + still_allowed} actions the original policy allowed"
            if (prevented + still_allowed) > 0
            else "no replayable allowed actions in the chain"
        ),
        "actions": replayed,
    }
