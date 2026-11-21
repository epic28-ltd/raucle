"""I2: drift and scope-drift analytics over receipts.

Where I1 asked the counterfactual question ("would a stricter policy have
prevented it?"), this surface asks the longitudinal one: over the receipt
history, where did scope drift? Where did a tool's definition drift? Who
got widened? Where did the deny rate move, and where did a revocation
cascade through real activity?

The report is deterministic and derived ONLY from receipt fields: the
gate receipts' bound blocks (tool_definition, authorization) and the
revocation blocks. No policy is re-run, no input is replayed, no vault is
consulted, no new secret exists. Structural reads, never verification:
the offline verifier stays the trust decision; this tool reports what the
receipts claim, and every row cites the receipts it rests on so the
claims verify the same way the receipts do. A signal that cannot cite its
receipts is not emitted (honest states): a single definition digest is not
drift, a capability switch between two equally-attenuated children is
rotation rather than widening, a deny-rate shift on windows thinner than
the floor is not called, and a revocation of an authority nothing used is
an ending, not a cascade.

Bounded disclosure holds over the whole report: digests, identifiers,
names and counts only. Denial reasons can quote constraint values, so
they never enter any row; the receipts cited by a row are where the full
story lives.
"""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Any

#: The closed signal vocabulary, in report order. The counts section names
#: all five always, so the zero-signal case reads as an explicit zero
#: rather than an absence.
SIGNAL_NAMES: tuple[str, ...] = (
    "definition-drift",
    "authority-widening",
    "authority-narrowing",
    "deny-rate-delta",
    "revocation-cascade",
)

#: Default evidence floor for a deny-rate window: both halves of an
#: agent's decision sequence must carry at least this many receipts
#: before a delta is called drift. An operator can lower the floor, never
#: hide it: it is a CLI flag.
_DEFAULT_MIN_WINDOW = 4

#: Default absolute deny-rate delta that fires a signal (second window
#: minus first window).
_DEFAULT_DENY_DELTA = 0.5

_GATE_DECISIONS = frozenset({"allow", "deny"})


def _decode_line(line: str) -> tuple[str, dict[str, Any]] | None:
    """Decode one minimal envelope line to ``(receipt_hash, payload)``.

    Returns None for a line that is not a parsable
    ``{"receipt_hash", "jws"}`` envelope - the caller counts it
    unparsable, never guesses. Blank lines are skipped by the caller.
    """
    try:
        envelope = json.loads(line)
        seg = envelope["jws"].split(".")
        padded = seg[1] + "=" * (-len(seg[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except (KeyError, ValueError, IndexError, binascii.Error):
        return None
    if not isinstance(payload, dict):
        return None
    return str(envelope.get("receipt_hash", "")), payload


def _source_lines(source: str | Path) -> tuple[list[str], str]:
    """The receipt lines in deterministic order: a chain JSONL file reads
    top to bottom; a segmented store directory reads ``seg-*.jsonl`` in
    name order (the segment numbering is the write order), skipping the
    ``.meta`` sidecars."""
    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"receipt source {path} does not exist")
    if path.is_dir():
        lines: list[str] = []
        for segment in sorted(path.glob("seg-*.jsonl")):
            lines.extend(segment.read_text(encoding="utf-8").splitlines())
        return lines, "store"
    return path.read_text(encoding="utf-8").splitlines(), "chain"


def _gate_record(receipt_hash: str, payload: dict[str, Any], order: int) -> dict[str, Any] | None:
    """The bounded gate view one receipt contributes to analytics:
    identity, decision, time, and the optional W2/v1.1 blocks. No reason
    field ever enters this record (bounded disclosure: a denial reason
    can quote constraint values)."""
    x_gate = payload.get("x_gate")
    if not isinstance(x_gate, dict) or not x_gate.get("decision"):
        return None
    tool_definition = x_gate.get("tool_definition")
    authorization = x_gate.get("authorization")
    return {
        "order": order,
        "hash": receipt_hash,
        "iat": int(payload.get("iat", 0) or 0),
        "decision": str(x_gate.get("decision", "")),
        "tool": str(x_gate.get("tool", "")),
        "agent_id": str(x_gate.get("agent_id", "")),
        "tool_definition": tool_definition if isinstance(tool_definition, dict) else None,
        "authorization": authorization if isinstance(authorization, dict) else None,
    }


def _revocation_record(
    receipt_hash: str, payload: dict[str, Any], order: int
) -> dict[str, Any] | None:
    """The bounded revocation view: the v1.0 and v1.2 shapes both verify
    structurally here, versioned fields entering only when present
    (omit-when-absent, never a nulled placeholder)."""
    revocation = payload.get("x_revocation")
    if not isinstance(revocation, dict):
        return None
    revoked_ids = revocation.get("revoked_ids")
    if not isinstance(revoked_ids, list):
        return None
    record: dict[str, Any] = {
        "order": order,
        "hash": receipt_hash,
        "iat": int(payload.get("iat", 0) or 0),
        "revoked_ids": [str(rid) for rid in revoked_ids],
        "actor": str(revocation.get("actor", "")),
    }
    if revocation.get("root"):
        record["root"] = str(revocation.get("root"))
    if revocation.get("reason_class"):
        record["reason_class"] = str(revocation.get("reason_class"))
    if revocation.get("kind"):
        record["kind"] = str(revocation.get("kind"))
    return record


def _definition_rows(gates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """``definition-drift``: the W2 definition digest bound into x_gate
    changed for a tool between two receipts. Only citable receipts (an
    envelope carrying a receipt_hash) participate: a drift row must cite
    the receipt either side of the change or it is not emitted."""
    rows: list[dict[str, Any]] = []
    last: dict[str, dict[str, Any]] = {}
    for gate in gates:
        definition = gate["tool_definition"]
        if not definition:
            continue
        digest = definition.get("definition_digest")
        if not digest:
            continue
        tool = gate["tool"]
        previous = last.get(tool)
        if previous is not None and previous["digest"] != digest:
            row: dict[str, Any] = {
                "signal": "definition-drift",
                "tool": tool,
                "from_digest": previous["digest"],
                "to_digest": digest,
                "from_receipt": previous["hash"],
                "to_receipt": gate["hash"],
                "from_iat": previous["iat"],
                "to_iat": gate["iat"],
                "agents": sorted({previous["agent_id"], gate["agent_id"]}),
            }
            manifest = str(definition.get("definition_manifest") or "")
            if manifest:
                row["manifest"] = manifest
            rows.append(row)
        last[tool] = {
            "digest": digest,
            "hash": gate["hash"],
            "iat": gate["iat"],
            "agent_id": gate["agent_id"],
        }
    return rows


def _authority_transition_rows(gates: list[dict[str, Any]]) -> tuple[list, list]:
    """``authority-widening`` / ``authority-narrowing``: an agent's cited
    authority changed width. Widening fires when the agent moved from an
    attenuated (delegated, narrowed) capability onto a non-attenuated
    one - that is who got widened. Narrowing is the reverse. A switch at
    equal width (two attenuated children, or two root grants) is
    rotation, not drift, and emits nothing."""
    widened: list[dict[str, Any]] = []
    narrowed: list[dict[str, Any]] = []
    last: dict[str, dict[str, Any]] = {}
    for gate in gates:
        authorization = gate["authorization"]
        if not authorization:
            continue
        capability_id = str(authorization.get("capability_id", ""))
        if not capability_id:
            continue
        attenuated = bool(authorization.get("attenuated"))
        agent_id = gate["agent_id"]
        previous = last.get(agent_id)
        if previous is not None and previous["capability_id"] != capability_id:
            row: dict[str, Any] = {
                "agent_id": agent_id,
                "from_capability": previous["capability_id"],
                "to_capability": capability_id,
                "from_attenuated": previous["attenuated"],
                "to_attenuated": attenuated,
                "from_receipt": previous["hash"],
                "to_receipt": gate["hash"],
                "iat": gate["iat"],
            }
            chain_digest = str(authorization.get("chain_digest") or "")
            if chain_digest:
                row["chain_digest"] = chain_digest
            if previous["attenuated"] and not attenuated:
                row["signal"] = "authority-widening"
                widened.append(row)
            elif not previous["attenuated"] and attenuated:
                row["signal"] = "authority-narrowing"
                narrowed.append(row)
        last[agent_id] = {
            "capability_id": capability_id,
            "attenuated": attenuated,
            "hash": gate["hash"],
            "iat": gate["iat"],
        }
    return widened, narrowed


def _deny_rate(
    receipts: list[dict[str, Any]],
) -> tuple[list[str], list[str], float]:
    hashes = [g["hash"] for g in receipts]
    denies = [g["hash"] for g in receipts if g["decision"] == "deny"]
    rate = len(denies) / len(receipts) if receipts else 0.0
    return hashes, denies, rate


def _deny_rate_rows(
    gates: list[dict[str, Any]],
    *,
    min_window: int,
    deny_delta_threshold: float,
) -> list[dict[str, Any]]:
    """``deny-rate-delta``: an agent's allow/deny sequence split into two
    windows (first half, second half, by receipt order), each window
    citing every receipt hash it counts, so the rate re-derives from the
    row alone. Escalations sit outside both windows (neither allowed nor
    denied). Below the evidence floor, nothing is called."""
    by_agent: dict[str, list[dict[str, Any]]] = {}
    for gate in gates:
        if gate["decision"] in _GATE_DECISIONS:
            by_agent.setdefault(gate["agent_id"], []).append(gate)
    rows: list[dict[str, Any]] = []
    for agent_id in sorted(by_agent):
        sequence = by_agent[agent_id]
        half = len(sequence) // 2
        first, second = sequence[:half], sequence[half:]
        if len(first) < min_window or len(second) < min_window:
            continue
        first_hashes, first_denies, first_rate = _deny_rate(first)
        second_hashes, second_denies, second_rate = _deny_rate(second)
        delta = second_rate - first_rate
        if abs(delta) < deny_delta_threshold:
            continue
        rows.append(
            {
                "signal": "deny-rate-delta",
                "agent_id": agent_id,
                "delta": delta,
                "window_first": {
                    "receipts": first_hashes,
                    "denies": first_denies,
                    "deny_rate": first_rate,
                },
                "window_second": {
                    "receipts": second_hashes,
                    "denies": second_denies,
                    "deny_rate": second_rate,
                },
            }
        )
    return rows


def _revocation_rows(
    revocations: list[dict[str, Any]],
    gates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """``revocation-cascade``: a revocation of an authority the chain
    shows in real use. The row cites the revocation receipt, every prior
    gate receipt exercising the revoked authority (as the presented
    capability or as its parent - a child of a revoked capability lost
    its chain too), and the deny receipts the prior agents minted after
    the revocation line. A revocation with no prior use is an ending,
    not a cascade: nothing is emitted."""
    rows: list[dict[str, Any]] = []
    for revocation in revocations:
        if not revocation["hash"]:
            continue
        revoked = set(revocation["revoked_ids"])
        if not revoked:
            continue
        prior: list[dict[str, Any]] = []
        for gate in gates:
            authorization = gate["authorization"]
            if not authorization or gate["order"] >= revocation["order"]:
                continue
            cited = {authorization.get("capability_id"), authorization.get("parent_id")}
            cited.discard(None)
            if cited & revoked:
                prior.append(gate)
        if not prior:
            continue
        prior_agents = sorted({g["agent_id"] for g in prior})
        post_denials = [
            g["hash"]
            for g in gates
            if g["order"] > revocation["order"]
            and g["decision"] == "deny"
            and g["agent_id"] in prior_agents
            and g["hash"]
        ]
        row: dict[str, Any] = {
            "signal": "revocation-cascade",
            "revocation_receipt": revocation["hash"],
            "revoked_ids": revocation["revoked_ids"],
            "actor": revocation["actor"],
            "iat": revocation["iat"],
            "prior_use_receipts": [g["hash"] for g in prior],
            "prior_agents": prior_agents,
            "post_denial_receipts": post_denials,
        }
        for optional in ("root", "reason_class", "kind"):
            if optional in revocation:
                row[optional] = revocation[optional]
        rows.append(row)
    return rows


def collect_drift_signals(
    source: str | Path,
    *,
    min_window: int = _DEFAULT_MIN_WINDOW,
    deny_delta_threshold: float = _DEFAULT_DENY_DELTA,
) -> dict[str, Any]:
    """Collect the drift and scope-drift signals over a receipt source.

    ``source`` is either a receipt chain JSONL file or a segmented store
    directory. Returns the report: honest counts, the signal rows (each
    citing its receipts), and a plain-words verdict. Deterministic: the
    same source yields the same report bytes every run.
    """
    lines, source_kind = _source_lines(source)

    receipts_scanned = 0
    unparsable_lines = 0
    gates: list[dict[str, Any]] = []
    revocations: list[dict[str, Any]] = []
    for order, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        decoded = _decode_line(stripped)
        if decoded is None:
            unparsable_lines += 1
            continue
        receipt_hash, payload = decoded
        receipts_scanned += 1
        gate = _gate_record(receipt_hash, payload, order)
        if gate is not None:
            gates.append(gate)
            continue
        revocation = _revocation_record(receipt_hash, payload, order)
        if revocation is not None:
            revocations.append(revocation)

    # a receipt whose envelope carries no hash cannot be cited, so it
    # cannot back a signal: it is scanned (counted honestly) but never
    # participates in a derivation
    citable_gates = [g for g in gates if g["hash"]]

    definition_rows = _definition_rows(citable_gates)
    widened_rows, narrowed_rows = _authority_transition_rows(citable_gates)
    deny_rate_rows = _deny_rate_rows(
        citable_gates, min_window=min_window, deny_delta_threshold=deny_delta_threshold
    )
    revocation_rows = _revocation_rows(revocations, citable_gates)

    signals = [*definition_rows, *widened_rows, *narrowed_rows, *deny_rate_rows, *revocation_rows]
    signal_counts = {name: 0 for name in SIGNAL_NAMES}
    for row in signals:
        signal_counts[row["signal"]] += 1

    if signals:
        parts = ", ".join(
            f"{name} {signal_counts[name]}" for name in SIGNAL_NAMES if signal_counts[name]
        )
        verdict = f"{len(signals)} drift signals over {receipts_scanned} receipts scanned: {parts}"
    else:
        verdict = (
            f"no drift signals over {receipts_scanned} receipts scanned "
            f"({len(gates)} gate, {len(revocations)} revocation): no "
            "definition, authority, deny-rate or revocation pattern met a "
            "signal definition"
        )

    return {
        "source": str(source),
        "source_kind": source_kind,
        "receipts_scanned": receipts_scanned,
        "unparsable_lines": unparsable_lines,
        "gate_receipts": len(gates),
        "revocation_receipts": len(revocations),
        "signals": signals,
        "signal_counts": signal_counts,
        "verdict": verdict,
    }
