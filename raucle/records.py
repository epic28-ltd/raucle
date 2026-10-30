"""G3: records management semantics - retention stamps and tamper-evident
disposal.

A government or regulated buyer must eventually DISPOSE of records (Public
Records Act review-and-dispose, retention schedules, data-minimisation). The
cohort has no answer: deletion destroys the audit story, so nobody deletes.
The raucle answer is the same one every other lifecycle event gets: disposal
is a signed receipt.

The destruction receipt (x_destruction) binds WHAT left: the time span, the
record count, and a digest over the removed records' hashes in order. The
surviving records are re-anchored as a fresh hash chain (a disposal produces
a new chain, not a broken one), and the destruction receipt is the bridge:
it proves the span existed, what it contained, when and by whose decision it
was destroyed, and that the surviving chain is the remainder.

Verification honesty: the span digest can only be RE-CHECKED against the
removed records themselves. When an escrow copy is available (a test, a
supervisor's copy, a WORM snapshot), verify_destruction re-computes it and
refuses a mismatch. Without the records, the destruction receipt still
proves the disposal event happened exactly as signed - tamper-evident, like
every other receipt. Neither mode upgrades bad evidence.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

_HASH_PREFIX = "sha256:"
_RECEIPT_TYP = "provenance-receipt/v1"
_RECEIPT_CRIT = "raucle/v1"


def _record_event_timestamp(rec: dict[str, Any]) -> str:
    event = rec.get("event") if isinstance(rec.get("event"), dict) else rec
    return str(event.get("timestamp", rec.get("timestamp", "")))


def _is_meta(rec: dict[str, Any]) -> bool:
    return bool(rec.get("chain_meta") or rec.get("checkpoint"))


def split_chain(
    chain_path: str | Path, *, from_ts: str, to_ts: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split the chain into (removed, retained) records by event timestamp
    span. Meta records (headers, checkpoints) are always retained."""
    removed: list[dict[str, Any]] = []
    retained: list[dict[str, Any]] = []
    for line in Path(chain_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or _is_meta(rec):
            retained.append(rec)
            continue
        ts = _record_event_timestamp(rec)
        if from_ts <= ts <= to_ts:
            removed.append(rec)
        else:
            retained.append(rec)
    return removed, retained


def _record_hash(rec: dict[str, Any]) -> str:
    """The audit chain's own record hash: sha256 over the canonical record
    WITHOUT its hash field (same formula as HashChainSink.append)."""
    from raucle.audit import _canonical_json, _sha256_hex

    body = {k: v for k, v in rec.items() if k != "hash"}
    return _sha256_hex(_canonical_json(body))


def span_evidence(removed: list[dict[str, Any]], *, recheck: bool = False) -> dict[str, Any]:
    """The tamper-evident summary of what is being destroyed.

    With recheck=True (the escrow verification path) each record's recorded
    hash is recomputed from its payload FIRST: a forged escrow record whose
    payload was edited after the fact fails here, before the digest is even
    compared."""
    if recheck:
        for r in removed:
            if str(r.get("hash", "")) != _record_hash(r):
                raise ValueError(
                    "escrow record fails its own hash: the payload was edited "
                    "after the fact (forged escrow)"
                )
    hashes = [str(r.get("hash", "")) for r in removed]
    return {
        "record_count": len(removed),
        "first_hash": hashes[0] if hashes else "",
        "last_hash": hashes[-1] if hashes else "",
        "span_digest": _HASH_PREFIX + hashlib.sha256("".join(hashes).encode("utf-8")).hexdigest(),
    }


def destruction_payload(
    *, from_ts: str, to_ts: str, reason: str, actor: str, evidence: dict[str, Any]
) -> dict[str, Any]:
    return {
        "iss": "raucle-records",
        "typ": _RECEIPT_TYP,
        "iat": int(time.time()),
        "operation": "guardrail_scan",
        "parents": [],
        "taint": ["gate:observed"],
        "input_hash": evidence["span_digest"].removeprefix(_HASH_PREFIX),
        "ruleset_hash": hashlib.sha256(f"{from_ts}|{to_ts}".encode()).hexdigest(),
        "guardrail_verdict": "records_destroyed",
        "x_destruction": {
            "action": "destroyed",
            "from": from_ts,
            "to": to_ts,
            "reason": reason,
            "actor": actor,
            "retained_count": None,  # filled by the caller
            **evidence,
            "destroyed_at": int(time.time()),
        },
    }


def build_destruction(
    chain_path: str | Path,
    *,
    from_ts: str,
    to_ts: str,
    reason: str,
    actor: str,
    operator_key_pem: bytes,
    out_dir: str | Path,
) -> dict[str, Any]:
    """Destroy the span: write the destruction receipt, the escrow copy of
    the removed records, and the re-anchored surviving chain."""
    from raucle.audit import HashChainSink
    from raucle.compliance_pack import _sign_certificate

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    removed, retained = split_chain(chain_path, from_ts=from_ts, to_ts=to_ts)
    if not removed:
        raise ValueError(
            f"no records fall inside the span {from_ts} .. {to_ts}; nothing to destroy"
        )
    evidence = span_evidence(removed)

    payload = destruction_payload(
        from_ts=from_ts, to_ts=to_ts, reason=reason, actor=actor, evidence=evidence
    )
    payload["x_destruction"]["retained_count"] = sum(0 if _is_meta(r) else 1 for r in retained)
    jws, receipt_hash, operator_pub_pem = _sign_certificate(payload, operator_key_pem)
    destruction = {
        "receipt_hash": receipt_hash,
        "jws": jws,
        "operator_public_key_pem": operator_pub_pem.decode("ascii"),
    }
    (out_dir / "destruction.json").write_text(
        json.dumps(destruction, indent=2) + "\n", encoding="utf-8"
    )

    # escrow copy of exactly what left (the supervisor's/WORM-side copy)
    with open(out_dir / "removed-records.jsonl", "w", encoding="utf-8") as fh:
        for rec in removed:
            fh.write(json.dumps(rec) + "\n")

    # the surviving records re-anchor as a fresh hash chain
    pruned_path = out_dir / "retained-chain.jsonl"
    if any(not _is_meta(r) for r in retained):
        with HashChainSink(pruned_path) as sink:
            for rec in retained:
                if _is_meta(rec):
                    continue
                event = rec.get("event")
                if isinstance(event, dict):
                    sink.append(event)
                elif rec:
                    sink.append(rec)
    else:
        pruned_path.write_text("", encoding="utf-8")

    return {
        "destruction": str(out_dir / "destruction.json"),
        "escrow": str(out_dir / "removed-records.jsonl"),
        "retained_chain": str(pruned_path),
        **evidence,
        "retained_count": payload["x_destruction"]["retained_count"],
    }


def verify_destruction(
    destruction_path: str | Path,
    *,
    escrow_path: str | Path | None = None,
    operator_public_pem: bytes | None = None,
) -> dict[str, Any]:
    """Verify a destruction receipt. Signature always; span digest when the
    escrow copy is available. Returns a report dict, never upgrades bad
    evidence."""
    import base64

    from raucle.provenance import ProvenanceVerifier

    d = json.loads(Path(destruction_path).read_text(encoding="utf-8"))
    jws = d["jws"]
    seg = jws.split(".")
    payload = json.loads(base64.urlsafe_b64decode(seg[1] + "==" * (-len(seg[1]) % 4)))
    block = payload.get("x_destruction", {})

    pub: bytes = operator_public_pem or d.get("operator_public_key_pem", "").encode("ascii")
    kid = hashlib.sha256(pub).hexdigest()[:16]
    # the one-receipt chain for the verifier is written to a throwaway
    # temporary directory, never beside the operator's files (no derived
    # sibling paths; SonarCloud S2083)
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        cert_file = Path(td) / "cert-line.jsonl"
        with open(cert_file, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"receipt_hash": d["receipt_hash"], "jws": jws}) + "\n")
        vreport = ProvenanceVerifier(public_keys={kid: pub}).verify_chain(cert_file)

    report: dict[str, Any] = {
        "valid": bool(vreport.valid),
        "signature_errors": list(vreport.errors),
        "span_digest_matches_escrow": None,
        "block": block,
    }

    if escrow_path is not None:
        removed = [
            json.loads(line)
            for line in Path(escrow_path).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        try:
            actual = span_evidence(removed, recheck=True)
        except ValueError as exc:
            report["span_digest_matches_escrow"] = False
            report["escrow_error"] = str(exc)
            report["valid"] = False
            return report
        actual = span_evidence(removed)
        report["span_digest_matches_escrow"] = actual["span_digest"] == block.get(
            "span_digest"
        ) and actual["record_count"] == block.get("record_count")
        report["valid"] = report["valid"] and bool(report["span_digest_matches_escrow"])
    return report
