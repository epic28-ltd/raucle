"""N5: authority-history replay - recompute a chain's decisions from
retained evidence ALONE.

The operator is trusted for NOTHING. Every authorisation decision a
chains carries must be REPLAYABLY recomputable from the evidence the
chain itself retains: the receipt's argument digest (resolved through
the input store kept alongside the chain), the policy digest the
receipt binds (``ruleset_hash`` - the policy of record is the retained
policy artefact whose digest matches it), and the receipt's own
recorded decision. Nothing is inferred; nothing operator-supplied is
taken on faith.

Fail-closed by construction. When any decision input cannot be
evidenced - the stored args are missing or fail their own digest
recheck, no retained policy artefact matches the receipt's
``ruleset_hash`` - the item is named ``MISSING_EVIDENCE`` with the
missing kind, its status is ``unverified``, and no decision is guessed.
A tampered store or a rewritten policy produces a NAMED divergence
(``args_hash_mismatch``) or a NAMED missing-evidence kind, never a
pass.

Counterfactual integration: when an alternative policy file is
supplied, the existing counterfactual machinery
(:func:`raucle.counterfactual.replay_counterfactual`) runs once over
the same chain and its per-action verdicts are joined onto the
comparison table by receipt hash, giving three columns per decision:
RECEIPTED vs RECOMPUTED vs COUNTERFACTUAL.

Determinism: the report carries no wall-clock values (receipt ``iat``
and latency never enter), and :func:`deterministic_bytes` serialises
it canonically (sorted keys, no whitespace) so two honest replays of
the same chain are byte-identical.

Bounded disclosure: the comparison table carries field names, hashes
and decisions only - no argument VALUES, no denial REASONS (a reason
can quote constraint values). The receipt cites the chain; the full
reason lives there.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

_HASH_PREFIX = "sha256:"
# The digest a gate receipt binds when NO policy rule covered the tool:
# copied from RaucleGateway._policy_ruleset_hash's empty-rule branch.
_NO_POLICY_DIGEST = hashlib.sha256(b"no-policy").hexdigest()

# Named missing-evidence kinds (the only strings the fail-closed paths
# may emit; every unrecomputable item names exactly one).
ARGS_STORE_MISSING = "stored_args_missing"
ARGS_HASH_MISMATCH = "args_hash_mismatch"
ARGS_UNPARSABLE = "stored_args_unparsable"
POLICY_ARTIFACT_MISSING = "policy_artifact_not_retained"
POLICY_DIGEST_MISMATCH = "policy_digest_mismatch"
RECEIPT_MALFORMED = "receipt_malformed"

_DECISIONS = ("allow", "deny", "escalate")


def _b64d(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _canonical_json(obj: Any) -> bytes:
    from raucle.provenance import _canonical_json as _cj

    return _cj(obj)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _gate_decisions(chain_path: str | Path) -> list[dict[str, Any]]:
    """Every gate-decision receipt in the chain, decoded, in order.

    A line that cannot be decoded is SKIPPED here (it is not a gate
    decision we can see) but the caller counts the raw line total, so
    an undecodable receipt can never silently shrink the audited set.
    """
    import base64 as b64

    decisions: list[dict[str, Any]] = []
    for line in Path(chain_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            envelope = json.loads(line)
            seg = envelope["jws"].split(".")
            payload = json.loads(b64.urlsafe_b64decode(seg[1] + "==" * (-len(seg[1]) % 4)))
        except (KeyError, ValueError, TypeError):  # JSONDecodeError is a ValueError
            continue
        block = payload.get("x_gate")
        if isinstance(block, dict) and block.get("decision") in _DECISIONS:
            decisions.append({"envelope": envelope, "payload": payload, "x_gate": block})
    return decisions


def _resolve_args(store: Any, receipt_input_hash: str) -> dict[str, Any] | str:
    """Resolve the recorded arguments from retained evidence only.

    Returns the args dict, or a NAMED missing-evidence kind. The store's
    own hash recheck already treats a tampered text as missing; binding
    the args to the digest the RECEIPT itself carries (canonical JSON)
    happens in the caller, so a store that kept the wrong record is a
    named mismatch, not a silent reuse.
    """
    for candidate in (receipt_input_hash, _HASH_PREFIX + receipt_input_hash):
        stored = store.get(candidate)
        if stored is not None:
            break
    else:
        return ARGS_STORE_MISSING
    try:
        args = json.loads(stored.text)
    except json.JSONDecodeError:
        return ARGS_UNPARSABLE
    if not isinstance(args, dict):
        return ARGS_UNPARSABLE
    return args


class _PolicyOfRecord:
    """Resolves a receipt's ruleset digest to the retained policy artefact.

    The digest is computed exactly the way the live gate computes it
    (``RaucleGateway._policy_ruleset_hash``): sha256 over the canonical
    JSON of the policy rule in force for the tool. Matching is BY
    DIGEST, never by file name; a receipt whose digest no retained
    artefact reproduces is missing evidence, named - never approximated
    with whatever policy happens to be lying around.
    """

    def __init__(self, policy_dir: str | Path) -> None:
        self._files = sorted(Path(policy_dir).glob("*.yaml"))
        self._gateways: dict[Path, Any] = {}
        self._empty_gateway: Any = None

    def _gateway_for(self, path: Path) -> Any:
        if path not in self._gateways:
            import tempfile

            from raucle.gateway import GatewayConfig, RaucleGateway

            td = tempfile.mkdtemp(prefix="auth-history-")
            config = GatewayConfig(
                host="127.0.0.1",
                admin_api_key="replay",
                signer_backend="local",
                receipt_store=str(Path(td) / "receipts.jsonl"),
                audit_chain=str(Path(td) / "audit.jsonl"),
                registry_path=str(Path(td) / "registry.jsonl"),
                agent_credentials_file=str(Path(td) / "agent-credentials.jsonl"),
                emit_receipts=False,
            )
            config.policy_file = str(path)
            config.gate_auth = "off"
            self._gateways[path] = RaucleGateway(config)
        return self._gateways[path]

    def _empty(self) -> Any:
        """A gateway with an EMPTY (but well-formed) policy file: the
        recompute environment for decisions the gate made under
        'no policy configured'. Its digest is the no-policy digest."""
        if self._empty_gateway is None:
            import tempfile

            from raucle.gateway import GatewayConfig, RaucleGateway

            td = tempfile.mkdtemp(prefix="auth-history-no-policy-")
            empty = Path(td) / "empty-policy.yaml"
            empty.write_text("version: 1\nissuer: authority-history-replay\npolicies: []\n")
            config = GatewayConfig(
                host="127.0.0.1",
                admin_api_key="replay",
                signer_backend="local",
                receipt_store=str(Path(td) / "receipts.jsonl"),
                audit_chain=str(Path(td) / "audit.jsonl"),
                registry_path=str(Path(td) / "registry.jsonl"),
                agent_credentials_file=str(Path(td) / "agent-credentials.jsonl"),
                emit_receipts=False,
            )
            config.policy_file = str(empty)
            config.gate_auth = "off"
            self._empty_gateway = RaucleGateway(config)
        return self._empty_gateway

    def resolve(
        self,
        tool: str,
        ruleset_hash: str,
        source: str = "",
        destination: str = "",
    ) -> tuple[Any, bool, str]:
        """The recompute gateway whose content digest for the *tool*
        rule (selected by source/destination exactly as the gate
        selects) equals *ruleset_hash* with an empty unresolved kind, or
        ``(empty gateway, False, missing_kind)``
        when nothing retained matches (caller names MISSING_EVIDENCE).
        The empty gateway resolves the no-policy digest honestly."""
        if not self._files:
            return self._empty(), False, POLICY_ARTIFACT_MISSING
        if not ruleset_hash or ruleset_hash == _NO_POLICY_DIGEST:
            return (
                self._empty(),
                ruleset_hash == _NO_POLICY_DIGEST,
                ("" if ruleset_hash == _NO_POLICY_DIGEST else POLICY_ARTIFACT_MISSING),
            )
        for path in self._files:
            gateway = self._gateway_for(path)
            if str(gateway._policy_ruleset_hash(tool, source, destination)) == ruleset_hash:
                return gateway, True, ""
        return self._empty(), False, POLICY_DIGEST_MISMATCH


def _counterfactual_replay_rows(
    chain_path: str | Path,
    input_store_path: str | Path,
    counterfactual_policy_path: str | Path | None,
) -> tuple[dict[str, dict[str, Any]], str]:
    """Run the existing counterfactual machinery over the SAME chain and
    input store; its per-action rows join by receipt hash."""
    if counterfactual_policy_path is None:
        return {}, ""
    from raucle.counterfactual import replay_counterfactual

    cf = replay_counterfactual(
        chain_path,
        input_store_path=input_store_path,
        alternative_policy_path=counterfactual_policy_path,
    )
    note = ""
    if cf["actions_unreplayable"]:
        note = (
            f"{cf['actions_unreplayable']} action(s) unreplayable by the counterfactual "
            f"machinery (no stored input) - named there, not merged silently"
        )
    return {row["receipt_hash"]: row for row in cf["actions"]}, note


def _classify_replay_status(recomputed: str, receipted: str) -> str:
    """Fail-closed status: only an exact receipted match is verified."""
    if recomputed == receipted:
        return "verified"
    if recomputed in _DECISIONS:
        # an undecidable recompute cannot fake agreement
        return "divergent"
    return "unverified"


def _replay_row(
    store: Any,
    rec: dict[str, Any],
    counterfactual_by_receipt: dict[str, dict[str, Any]],
    policy_of_record: _PolicyOfRecord,
) -> tuple[dict[str, Any], str | None]:
    """Recompute one gate decision row from stored evidence alone.

    Returns the row plus the named missing-evidence kind when the
    decision inputs cannot be fully evidenced (never inferred, never
    guessed), or ``None`` when evidence is complete.
    """
    from raucle.provenance import _sha256_hex as _sh

    payload, x_gate = rec["payload"], rec["x_gate"]
    row: dict[str, Any] = {
        "receipt_hash": str(rec["envelope"].get("receipt_hash", "")),
        "tool": str(x_gate.get("tool", "")),
        "agent_id": str(x_gate.get("agent_id", "")),
        "receipted_decision": str(x_gate.get("decision", "")),
        "recomputed_decision": None,
        "counterfactual_decision": None,
        "ruleset_hash": str(payload.get("ruleset_hash", "")),
        "status": "unverified",
        "missing_evidence": None,
    }
    cf_row = counterfactual_by_receipt.get(row["receipt_hash"])
    if cf_row is not None:
        row["counterfactual_decision"] = str(cf_row["counterfactual_decision"])

    # every decision input must be evidenced; the receipt binds
    # the args by digest - the stored text must reproduce it
    args = _resolve_args(store, str(payload.get("input_hash", "")))
    if isinstance(args, str):
        return row, args
    # canonical form the live gate hashed: recompute the digest
    # over the stored args and bind before trusting them
    canonical = _canonical_json(args)
    if _sh(canonical) != str(payload.get("input_hash", "")).removeprefix(_HASH_PREFIX):
        return row, ARGS_HASH_MISMATCH

    gateway, resolved, unresolved_kind = policy_of_record.resolve(
        row["tool"],
        row["ruleset_hash"],
        str(x_gate.get("source", "") or ""),
        str(x_gate.get("destination", "") or ""),
    )
    if not resolved:
        return row, unresolved_kind

    recomputed = gateway.check_tool_call(
        row["tool"],
        args,
        agent_id=row["agent_id"],
        source=str(x_gate.get("source", "") or ""),
        destination=str(x_gate.get("destination", "") or ""),
    )["decision"]
    row["recomputed_decision"] = recomputed
    row["status"] = _classify_replay_status(recomputed, row["receipted_decision"])
    return row, None


def replay_authority_history(
    chain_path: str | Path,
    *,
    input_store_path: str | Path,
    policy_dir: str | Path,
    counterfactual_policy_path: str | Path | None = None,
) -> dict[str, Any]:
    """Recompute every gate decision in *chain_path* from retained
    evidence alone, fail-closed.

    Returns the comparison table (receipted vs recomputed vs
    counterfactual) plus the fail-closed summary. Any item whose
    evidence is incomplete is ``unverified`` with a named
    missing-evidence kind; it is never inferred, never guessed, and
    never counted as verified.
    """
    from raucle.replay import InputStore

    counterfactual_by_receipt, counterfactual_note = _counterfactual_replay_rows(
        chain_path,
        input_store_path,
        counterfactual_policy_path,
    )
    policy_of_record = _PolicyOfRecord(policy_dir)
    raw_lines = sum(
        1 for line in Path(chain_path).read_text(encoding="utf-8").splitlines() if line.strip()
    )
    items: list[dict[str, Any]] = []
    missing_counter: dict[str, int] = {}

    with InputStore.open(input_store_path) as store:
        for rec in _gate_decisions(chain_path):
            row, missing_kind = _replay_row(store, rec, counterfactual_by_receipt, policy_of_record)
            if missing_kind is not None:
                row["missing_evidence"] = missing_kind
                missing_counter[missing_kind] = missing_counter.get(missing_kind, 0) + 1
            items.append(row)

    status_counts = Counter(r["status"] for r in items)
    verified = status_counts["verified"]
    divergent = status_counts["divergent"]
    unverified = status_counts["unverified"]
    table_sorted = sorted(items, key=lambda r: r["receipt_hash"])
    counterfactual_policy = (
        str(counterfactual_policy_path) if counterfactual_policy_path is not None else ""
    )
    report = {
        "chain": str(chain_path),
        "policy_dir": str(policy_dir),
        "counterfactual_policy": counterfactual_policy,
        "chain_lines": raw_lines,
        "gate_decisions": len(items),
        "non_gate_lines": raw_lines - len(items),
        "verified": verified,
        "divergent": divergent,
        "unverified": unverified,
        "missing_evidence": dict(sorted(missing_counter.items())),
        "counterfactual_note": counterfactual_note,
        "operator_trusted_for_nothing": True,
        "derived_only_from_retained_evidence": True,
        "verdict": (
            f"{verified}/{len(items)} decisions recomputed from evidence alone; "
            f"{divergent} divergent; {unverified} unverified (fail-closed)"
        ),
        "items": table_sorted,
    }
    if divergent:
        report["verdict"] = f"EVIDENCE DIVERGENCE: {report['verdict']}"
    elif unverified:
        report["verdict"] = f"INCOMPLETE EVIDENCE: {report['verdict']}"
    return report


def deterministic_bytes(report: dict[str, Any]) -> bytes:
    """Canonical serialisation of a replay report: sorted keys, no
    whitespace - two honest replays of the same chain produce the SAME
    bytes. Never includes wall-clock values by construction."""
    return json.dumps(
        report,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


__all__ = [
    "ARGS_HASH_MISMATCH",
    "ARGS_STORE_MISSING",
    "ARGS_UNPARSABLE",
    "POLICY_ARTIFACT_MISSING",
    "POLICY_DIGEST_MISMATCH",
    "RECEIPT_MALFORMED",
    "deterministic_bytes",
    "replay_authority_history",
]
