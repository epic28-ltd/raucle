"""Demo-mode session behaviour plane (EPIC D item D16, Q-2 machinery).

Read-only demo endpoints backing the admin panel's Session behaviour
tab. Nothing here synthesises state: every view reads the same
machinery a live operator's deployment runs.

- ``/api/demo/session-rules`` reads the LIVE policy configuration the
  gateway enforces: the compiled session rules in declaration order
  (the deterministic evaluation order), the named malformed-config
  marker when compilation failed, and the configured window bounds.
- ``/api/demo/session-windows`` derives per-session views from the
  REAL receipt index (schema v3 ``active_session_ids`` /
  ``session_receipts`` query paths). Only sessions the callers
  themselves declared ever appear; the projection never fabricates
  continuity.
- ``/api/demo/session-findings`` reads the signed ``x_finding``
  receipts the session monitor emitted (harness ``session-monitor``).
  Each finding cites the gate receipt of the very call it cut off; the
  panel's offline verifier re-checks that claim against the chain, so
  a finding cannot lie about what happened and still verify.

Honest limits ride every response: v1 rules are deny-only; window
state is process memory replayed from the index on boot; the replay
undercounts gradual_extraction (rule_id and destination_class are not
indexed). Gating follows the demo key/session model: 404 whenever
``RAUCLE_DEMO_MODE`` is off, exactly like the other ``/api/demo/*``
routes. The findings listing is GET; the one write-shaped route is the
receipt verification POST, which mutates nothing (it re-verifies
offline). No other write path exists in this module.
"""

from __future__ import annotations

import base64 as _b64
import json
import os
import time
from typing import Any

from fastapi import Header, HTTPException

__all__ = [
    "FINDING_ROW_CAP",
    "SESSION_ROW_CAP",
    "build_session_findings",
    "build_session_rules",
    "build_session_windows",
    "register_demo_session_routes",
]

RULES_SCHEMA = "raucle.demo.session_rules/v1"
WINDOWS_SCHEMA = "raucle.demo.session_windows/v1"
FINDINGS_SCHEMA = "raucle.demo.session_findings/v1"

#: Sessions shown in the windows view, most recently active first.
SESSION_ROW_CAP = 20
#: Recent decision rows per session window (the index returns them in
#: call order; the view keeps the newest tail).
SESSION_EVENT_CAP = 8
#: Findings returned, newest first.
FINDING_ROW_CAP = 50
#: Receipt envelopes scanned newest-first while looking for findings;
#: the truncation is disclosed in the response, never silent.
FINDING_SCAN_CAP = 400

_HARNESS = "session-monitor"

_LIMITS = (
    "deny-only v1: a session rule can refuse a call, never widen one; "
    "escalation to approval is a named follow-up",
    "window state is process memory, replayed from the receipt index on "
    "boot; a restart mid-session bounds the reset to the indexed history",
    "replayed rows carry no destination_class, so gradual_extraction "
    "undercounts after a restart and can never fabricate a deny",
    "coverage exists only where callers declare a session id; the "
    "gateway never fabricates continuity",
)

_NO_INDEX_NOTE = (
    "session windows are unavailable on this deployment: the receipt "
    "index is not configured, and absence of a view is never a zero"
)


def _demo_mode_on() -> bool:
    return os.environ.get("RAUCLE_DEMO_MODE", "").lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# Views over the real gateway state
# ---------------------------------------------------------------------------


def build_session_rules(gateway: Any) -> dict[str, Any]:
    """The live session-rules configuration, read from the gateway.

    The rules render in declaration order because that IS the
    deterministic evaluation order (first declared rule wins). A
    malformed config is disclosed, never hidden: the marker names what
    failed and the fail-closed behaviour it forces.
    """
    rules = list(getattr(gateway, "_session_rules", None) or [])
    config = getattr(gateway, "config", None)
    windows = getattr(gateway, "_session_windows", None)
    return {
        "schema_version": RULES_SCHEMA,
        "label": "live policy configuration read from the gateway",
        "session_rules": [rule.to_dict() for rule in rules],
        "config_error": str(getattr(gateway, "_session_rule_config_error", "") or ""),
        "deny_only": True,
        "window": {
            "ttl_seconds": int(getattr(windows, "ttl_seconds", 0) or 0),
            "max_keys": int(getattr(config, "session_window_max_keys", 0) or 0),
            "max_entries": int(getattr(config, "session_window_max_entries", 0) or 0),
        },
        "limits": list(_LIMITS),
    }


def build_session_windows(gateway: Any) -> dict[str, Any]:
    """Per-session windows derived from the real receipt index (v3).

    The index is the durable authority for window state; this view is
    its read-only projection. Sessions appear most recently active
    first, bounded by the configured window TTL.
    """
    index = getattr(gateway, "_receipt_index", None)
    windows = getattr(gateway, "_session_windows", None)
    ttl = int(getattr(windows, "ttl_seconds", 0) or 0)
    since = int(time.time()) - max(1, ttl)
    payload: dict[str, Any] = {
        "schema_version": WINDOWS_SCHEMA,
        "label": "derived from the live receipt index (schema v3)",
        "index_schema_version": int(getattr(index, "SCHEMA_VERSION", 3) or 3),
        "window_ttl_seconds": ttl,
        "since": since,
        "limits": list(_LIMITS),
    }
    if index is None:
        payload.update({"available": False, "sessions": [], "unavailable_note": _NO_INDEX_NOTE})
        return payload
    sessions: list[dict[str, Any]] = []
    for session_id in index.active_session_ids(since, limit=SESSION_ROW_CAP):
        rows = index.session_receipts(session_id, since=since, limit=1000)
        if not rows:
            continue
        allows = sum(1 for r in rows if r.get("decision") == "allow")
        denies = sum(1 for r in rows if r.get("decision") == "deny")
        escalates = sum(1 for r in rows if r.get("decision") == "escalate")
        agents = sorted({str(r.get("agent_id") or "") for r in rows if r.get("agent_id")})
        sessions.append(
            {
                "session_id": session_id,
                "receipts": len(rows),
                "allows": allows,
                "denies": denies,
                "escalates": escalates,
                "agents": agents,
                "first_iat": int(rows[0].get("iat") or 0),
                "last_iat": int(rows[-1].get("iat") or 0),
                "recent": [
                    {
                        "iat": int(r.get("iat") or 0),
                        "decision": str(r.get("decision") or ""),
                        "tool": str(r.get("tool") or ""),
                        "agent_id": str(r.get("agent_id") or ""),
                        "trace_id": str(r.get("trace_id") or ""),
                        "receipt_hash": str(r.get("receipt_hash") or ""),
                    }
                    for r in rows[-SESSION_EVENT_CAP:]
                ],
            }
        )
    payload.update({"available": True, "sessions": sessions})
    return payload


def _decode_payload(record: dict[str, Any]) -> dict[str, Any]:
    part = str(record.get("jws", "")).split(".")[1]
    return json.loads(_b64.urlsafe_b64decode(part + "=" * ((4 - len(part) % 4) % 4)))


def build_finding_chain_verification(gateway: Any, receipt_hash: str) -> dict[str, Any]:
    """The REAL offline verification of one session-monitor finding.

    The single-record pattern the receipts tab uses cannot carry a
    finding: the verifier's anti-fabrication check requires the CITED
    gate receipt to sit in the chain it verifies. This endpoint scopes
    the same real verifier to the minimal honest chain: the cited gate
    receipt followed by the finding receipt. Both signatures are
    checked, both hashes are recomputed from the JWS bytes, and the
    finding's claim is re-checked against the cited receipt's recorded
    verdict. No network, no operator contact, exactly like the panel's
    other offline verification.

    Returns the response payload, or raises ``ValueError``/``KeyError``
    for the unknown-hash and not-a-session-finding cases the route
    translates into 404/400.
    """
    store = getattr(gateway, "_receipt_store", None)
    if store is None:
        raise KeyError("no-store")
    envelope = store.find_by_hash(receipt_hash)
    if envelope is None:
        raise KeyError(receipt_hash)
    payload = _decode_payload(envelope)
    finding = payload.get("x_finding") if isinstance(payload, dict) else None
    if not isinstance(finding, dict) or finding.get("harness") != _HARNESS:
        raise ValueError("not a session-monitor finding")
    cited = str(finding.get("cited_receipt") or "")
    cited_envelope = store.find_by_hash(cited) if cited else None
    if cited_envelope is None:
        raise LookupError(cited)

    from raucle.provenance import ProvenanceVerifier

    gate = gateway.gate_identity
    verifier = ProvenanceVerifier(public_keys={gate.key_id: gate.public_key_pem()})
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as td:
        chain_file = Path(td) / "chain.jsonl"
        chain_file.write_text(
            json.dumps(cited_envelope, ensure_ascii=False)
            + "\n"
            + json.dumps(envelope, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )
        report = verifier.verify_chain(chain_file)

    verified = bool(report.valid)
    return {
        "verdict": "valid" if verified else "failed",
        "signature_check": "Ed25519 JWS under the gate public key (both records)"
        if verified
        else "not checked to completion",
        "hash_linkage": {"recomputed_matches": verified},
        "receipt_count": 2,
        "cited_receipt": cited,
        "errors": list(report.errors or []),
        "offline": "This verification ran entirely offline. No operator network call was made.",
        "note": (
            "The chain verified here is the minimal honest chain for a "
            "finding: the cited gate receipt followed by the session-monitor "
            "finding, so the verifier re-checks the citation rather than "
            "skipping it."
        ),
    }


def build_session_findings(gateway: Any) -> dict[str, Any]:
    """The session-monitor findings, read from the signed receipt chain.

    Scans the newest receipt envelopes for ``x_finding`` receipts with
    harness ``session-monitor``, newest first, bounded and disclosed.
    Each row carries the finding receipt's own hash so the panel can
    run the offline verifier over it (the verifier re-checks the cited
    gate receipt and the reported decision against the chain).
    """
    store = getattr(gateway, "_receipt_store", None)
    records: list[dict[str, Any]] = []
    if store is not None:
        records = store.recent(FINDING_SCAN_CAP)
    findings: list[dict[str, Any]] = []
    truncated = False
    scanned = 0
    for record in records:
        scanned += 1
        try:
            payload = _decode_payload(record)
        except Exception:  # noqa: BLE001 - a malformed line is skipped, never served
            continue
        finding = payload.get("x_finding") if isinstance(payload, dict) else None
        if not isinstance(finding, dict) or finding.get("harness") != _HARNESS:
            continue
        repro = finding.get("repro") or {}
        findings.append(
            {
                "finding_id": str(finding.get("finding_id") or ""),
                "test_id": str(finding.get("test_id") or ""),
                "verdict": str(finding.get("verdict") or ""),
                "cited_receipt": str(finding.get("cited_receipt") or ""),
                "tool": str(repro.get("tool") or ""),
                "expected_decision": str(repro.get("expected_decision") or ""),
                "actual_decision": str(repro.get("actual_decision") or ""),
                "detected_at": int(finding.get("detected_at") or 0),
                "note": str(finding.get("note") or ""),
                "receipt_hash": str(record.get("receipt_hash") or ""),
            }
        )
        if len(findings) >= FINDING_ROW_CAP:
            truncated = True
            break
    findings.sort(key=lambda f: f["detected_at"], reverse=True)
    return {
        "schema_version": FINDINGS_SCHEMA,
        "label": "signed x_finding receipts from this deployment's chain",
        "harness": _HARNESS,
        "count": len(findings),
        "scanned": scanned,
        "truncated": truncated,
        "monitor_note": (
            "a finding is the monitor's claim; the offline verifier re-checks "
            "it against the cited gate receipt in the chain, so a finding "
            "citing a missing receipt or misreporting the decision fails "
            "verification"
        ),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def register_demo_session_routes(
    app: Any, gateway: Any, check_auth: Any, check_access: Any
) -> None:
    """Register the demo session behaviour endpoints on *app*.

        Gated exactly like the other ``/api/demo/*`` surfaces: the routes
        answer only when ``RAUCLE_DEMO_MODE`` is on, through the same
        authenticated, read-only resource gate, and answer 404 otherwise.
        GET for the listing; no mutation path exists in this module (the
    verify POST re-verifies, it does not mutate).
    """

    def _gate(authorization: str | None, x_totp: Any) -> Any:
        user = check_auth(authorization, x_totp)
        check_access(user, "stats")
        if not _demo_mode_on():
            raise HTTPException(404, "demo mode not configured")
        return user

    @app.get(
        "/api/demo/session-rules",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_session_rules(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        """The live session-rules configuration the gateway enforces."""
        _gate(authorization, x_totp)
        return build_session_rules(gateway)

    @app.get(
        "/api/demo/session-windows",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_session_windows(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        """Per-session windows derived from the real receipt index."""
        _gate(authorization, x_totp)
        return build_session_windows(gateway)

    @app.get(
        "/api/demo/session-findings",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_session_findings(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        """The session-monitor findings, each citing its gate receipt."""
        _gate(authorization, x_totp)
        return build_session_findings(gateway)

    @app.post(
        "/api/demo/session-findings/{receipt_hash}/offline-verify",
        responses={
            "400": {"description": "Receipt is not a session-monitor finding"},
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode off, unknown hash or no cited receipt"},
            "422": {"description": "Offline verification failed (verdict in detail)"},
            "501": {"description": "Receipt store not configured"},
        },
    )
    def demo_session_finding_verify(
        receipt_hash: str,
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        """Offline-verify one finding against its cited gate receipt.

        Runs the gateway's real offline verifier over the minimal
        honest chain (cited gate receipt + finding), so the
        anti-fabrication citation check executes instead of being
        skipped. A failed verification fails the response.
        """
        user = check_auth(authorization, x_totp)
        check_access(user, "receipts")
        if not _demo_mode_on():
            raise HTTPException(404, "demo mode not configured")
        try:
            result = build_finding_chain_verification(gateway, receipt_hash)
        except KeyError as exc:
            if str(exc) == "no-store":
                raise HTTPException(501, "receipt store not configured") from exc
            raise HTTPException(404, "unknown receipt hash") from exc
        except ValueError:
            raise HTTPException(400, "not a session-monitor finding") from None
        except LookupError:
            raise HTTPException(
                404, "the finding cites a receipt that is not in the chain"
            ) from None
        if result["verdict"] != "valid":
            raise HTTPException(422, detail=result)
        return result
