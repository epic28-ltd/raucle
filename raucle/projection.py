"""H1b-1: the receipt-chain-to-audit-chain projection.

This module is a FORMAT BRIDGE ONLY. It never mints, alters, or re-signs
evidence: it re-encodes what the chains already carry. A gate receipt
chain (the JWS envelopes in receipts.jsonl) plus an operator's audit
chain are re-encoded into the audit-chain shape
``raucle.compliance_pack.build_pack`` consumes, so a caller holding both
chains (the operator portal) can build a compliance bundle in process
over exactly the evidence those chains already contain.

The bridge contract, pinned by tests:

- Re-encoding, never creation. Each projected decision row cites the
  receipt it came from (``receipt_id`` is the JWS receipt hash), so the
  auditor's strongest evidence still lives in the ORIGINAL chain and
  verifies there with the standard ProvenanceVerifier. The projected
  rows carry only the bounded fields the pack's extracts read: decision,
  agent_id, tool, timestamp, receipt_id, rule_id, authorization
  (capability_id, chain_digest, issuer). Never the call args, never the
  denial reason (it can quote constraint VALUES), never constraint sets.
- Never signed. The output container is always an UNSIGNED hash chain:
  the original chains stay the attribution source (the JWS signatures,
  the original audit checkpoints, which cannot survive re-chaining and
  are deliberately not carried). The module takes no signer; a pack built
  over the projection reports the container's unsigned mode honestly.
- Fail-closed on tampering. An envelope whose receipt_hash no longer
  binds its JWS is refused, not laundered into a pack; when the gate's
  public key is supplied, receipts the key does not authenticate are
  refused too. Malformed lines are skipped and counted, never guessed.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
from pathlib import Path
from typing import Any

_HASH_PREFIX = "sha256:"
_DECISIONS = {"allow", "deny"}
_AUTH_KEYS = ("capability_id", "chain_digest", "issuer")


def _decode_payload(jws: str) -> dict[str, Any]:
    """The decoded JWS payload of a receipt (the signed content)."""
    seg = jws.split(".")[1]
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def _receipt_rows(
    receipts_path: Path, public_pem: bytes | None
) -> tuple[list[tuple[str, str, dict[str, Any]]], int, int]:
    """The gate decision rows in the receipt chain, in order.

    Returns (rows, non_decision_receipts, malformed_lines). A row is
    (timestamp, receipt_hash, x_gate block). Fails closed on tampering: an envelope whose
    receipt_hash does not bind its JWS raises (the source chain is
    tampered and must not be laundered into a pack).
    """
    from raucle.provenance import ProvenanceReceipt, ProvenanceVerifier

    rows: list[tuple[str, str, dict[str, Any]]] = []
    non_decisions = 0
    malformed = 0
    verifiers: dict[str, ProvenanceVerifier] = {}

    for line_no, line in enumerate(receipts_path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            envelope = json.loads(line)
            jws = envelope["jws"]
            receipt_hash = str(envelope["receipt_hash"])
        except (json.JSONDecodeError, KeyError, TypeError):
            malformed += 1
            continue
        if _HASH_PREFIX + hashlib.sha256(jws.encode("ascii")).hexdigest() != receipt_hash:
            raise ValueError(
                f"receipt chain tampered: envelope receipt_hash does not "
                f"bind its JWS (line {line_no})"
            )
        try:
            receipt = ProvenanceReceipt.from_jws(jws, strict=True, validate_structure=False)
            payload = _decode_payload(jws)
        except (ValueError, KeyError):
            malformed += 1
            continue
        if public_pem is not None:
            kid = receipt.agent_key_id
            if kid not in verifiers:
                verifiers[kid] = ProvenanceVerifier(public_keys={kid: public_pem})
            if not verifiers[kid]._verify_signature(receipt):
                raise ValueError(
                    f"receipt chain signature verification failed for "
                    f"agent_key_id={kid} (line {line_no}): the supplied key "
                    "does not authenticate this source chain"
                )
        block = payload.get("x_gate")
        if not (isinstance(block, dict) and str(block.get("decision", "")).lower() in _DECISIONS):
            non_decisions += 1
            continue
        rows.append((_iso_timestamp(payload.get("iat")), receipt_hash, block))
    return rows, non_decisions, malformed


def _iso_timestamp(iat: Any) -> str:
    """The receipt's signed issue time, re-encoded as ISO 8601 UTC."""
    try:
        seconds = int(iat)
    except (TypeError, ValueError):
        return ""
    if seconds <= 0:
        return ""
    return _dt.datetime.fromtimestamp(seconds, tz=_dt.timezone.utc).isoformat()


def _gate_event(block: dict[str, Any], receipt_hash: str, timestamp: str) -> dict[str, Any]:
    """One bounded decision event re-encoded from a gate receipt.

    Exactly the fields the pack's extracts read. The receipt hash rides
    as receipt_id: the auditor's pull key back into the signed chain."""
    event: dict[str, Any] = {
        "decision": str(block.get("decision", "")).upper(),
        "agent_id": str(block.get("agent_id", "")),
        "tool": str(block.get("tool", "")),
        "timestamp": timestamp,
        "receipt_id": receipt_hash,
    }
    rule_id = str(block.get("rule_id", "") or "")
    if rule_id:
        event["rule_id"] = rule_id
    auth = block.get("authorization")
    if isinstance(auth, dict):
        bounded = {key: auth.get(key, "") for key in _AUTH_KEYS if auth.get(key)}
        if bounded:
            event["authorization"] = bounded
    return event


def _audit_rows(audit_path: Path) -> tuple[list[tuple[str, dict[str, Any]]], set[str]]:
    """The event rows in an audit chain (meta and checkpoint records aside),
    plus the receipt ids its decision rows already cite."""
    rows: list[tuple[str, dict[str, Any]]] = []
    cited: set[str] = set()
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or rec.get("chain_meta") or rec.get("checkpoint"):
            continue
        event = rec.get("event") if isinstance(rec.get("event"), dict) else rec
        if not isinstance(event, dict):
            continue
        timestamp = str(event.get("timestamp", "") or rec.get("timestamp", ""))
        rows.append((timestamp, dict(event)))
        if str(event.get("decision", "")).upper() in {"ALLOW", "DENY"} and event.get("receipt_id"):
            cited.add(str(event["receipt_id"]))
    return rows, cited


def _digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    return _HASH_PREFIX + hashlib.sha256(path.read_bytes()).hexdigest()


def project_pack_chain(
    receipts_path: str | Path,
    audit_chain_path: str | Path | None = None,
    *,
    out_path: str | Path = "projected-chain.jsonl",
    gateway_public_key_pem: bytes | None = None,
) -> dict[str, Any]:
    """Re-encode a gate receipt chain plus an audit chain into the
    audit-chain shape ``compliance_pack.build_pack`` consumes.

    A format bridge only: no minting, no altering, no re-signing. The
    receipt chain's gate decisions become bounded decision events citing
    their receipt hash; the audit chain's event rows ride through
    unchanged. A decision the audit chain already records (joined on
    receipt_id) is not duplicated. Rows merge in event-time order, stable
    on ties (audit rows first). The output is always a FRESH UNSIGNED
    hash chain: ``out_path`` must not exist, the module takes no signer,
    and the original chains remain the attribution source.

    ``gateway_public_key_pem`` (optional, the gate's public key)
    authenticates each receipt's signature before it is re-encoded; a
    receipt the key does not verify is refused. Without a key only the
    envelope hash binding is re-checked.

    Returns a summary dict (counts and the input digests) so callers can
    receipt what the projection was built from. Raises ValueError on a
    tampered source chain, an untrusted signature, or an existing
    out_path.
    """
    from raucle.audit import HashChainSink

    receipts_path = Path(receipts_path)
    audit_path = Path(audit_chain_path) if audit_chain_path is not None else None
    out_path = Path(out_path)
    if out_path.exists():
        raise ValueError(f"out_path already exists: {out_path} (a projection is a fresh container)")
    if not receipts_path.is_file() and (audit_path is None or not audit_path.is_file()):
        raise ValueError("no input chains on disk: nothing to project")

    projected: list[tuple[str, str, dict[str, Any]]] = []
    non_decisions = 0
    malformed = 0
    if receipts_path.is_file():
        rows, non_decisions, malformed = _receipt_rows(receipts_path, gateway_public_key_pem)
        projected = rows

    audit_events: list[tuple[str, dict[str, Any]]] = []
    cited: set[str] = set()
    if audit_path is not None and audit_path.is_file():
        audit_events, cited = _audit_rows(audit_path)

    duplicates = 0
    merged: list[tuple[str, int, int, dict[str, Any]]] = []
    for seq, (timestamp, event) in enumerate(audit_events):
        merged.append((timestamp, 0, seq, event))
    for seq, (timestamp, receipt_hash, block) in enumerate(projected):
        if receipt_hash in cited:
            duplicates += 1
            continue
        merged.append((timestamp, 1, seq, _gate_event(block, receipt_hash, timestamp)))
    # Event-time order, stable on ties; rows without a timestamp sort last.
    merged.sort(key=lambda row: (row[0] == "", row[0], row[1], row[2]))

    with HashChainSink(out_path) as sink:
        for _, _, _, event in merged:
            sink.append(event)

    return {
        "out": str(out_path),
        "projected_receipts": len(projected) - duplicates,
        "audit_events": len(audit_events),
        "duplicates_skipped": duplicates,
        "non_decision_receipts": non_decisions,
        "malformed_receipt_lines": malformed,
        "receipts_digest": _digest(receipts_path),
        "audit_chain_digest": _digest(audit_path) if audit_path is not None else None,
    }


__all__ = ["project_pack_chain"]
