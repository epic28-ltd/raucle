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
- ``/api/demo/dlp-findings`` reads the signed ``x_dlp`` receipts the
  demo advisory redaction engine minted (EPIC D item D2, lanes Q-7a +
  Q-7c machinery). Each row carries digests, bounded pattern classes
  and span counts only (never content) and cites the gate receipt of
  the scanned call. ``run_demo_dlp_scan`` is the demo-plane driver the
  gateway app calls after a receipted demo gate decision: it runs the
  call's arguments through the REAL advisory redaction middleware
  (``raucle.middleware`` configured with the wired pattern classes)
  and mints the ``x_dlp`` receipt through the OSS emitter. It runs
  only when ``RAUCLE_DEMO_MODE`` is on: production gate traffic is
  never content-scanned by the gateway (the ``x_dlp`` emitter surface
  belongs to the enterprise content proxy, per
  ``docs/spec/provenance/v1.2/content-dlp.md``).

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
import contextlib
import json
import logging
import os
import time
import weakref
from typing import Any

from fastapi import Header, HTTPException

__all__ = [
    "DLP_DEMO_RULE_ID",
    "FINDING_ROW_CAP",
    "SESSION_ROW_CAP",
    "build_dlp_findings",
    "build_session_findings",
    "build_session_rules",
    "build_session_windows",
    "register_demo_session_routes",
    "run_demo_dlp_scan",
]

logger = logging.getLogger(__name__)

RULES_SCHEMA = "raucle.demo.session_rules/v1"
WINDOWS_SCHEMA = "raucle.demo.session_windows/v1"
FINDINGS_SCHEMA = "raucle.demo.session_findings/v1"
DLP_SCHEMA = "raucle.demo.dlp_findings/v1"

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
#: x_dlp scan rows returned, newest first.
DLP_ROW_CAP = 50
#: Receipt envelopes scanned newest-first while collecting x_dlp rows
#: and advisory findings; the truncation is disclosed, never silent.
DLP_SCAN_CAP = 400
#: The advisory session key the demo middleware leg uses when the call
#: declared no session id of its own.
DLP_ADVISORY_SESSION = "demo-dlp-advisory"
#: The advisory redaction policy rule the demo plane applies. The
#: action is always ``redacted`` in the demo (block classes belong to
#: the enterprise runtime, Q-7b): honestly never a block claim.
DLP_DEMO_RULE_ID = "demo-advisory-redact"

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

_NO_DLP_STORE_NOTE = (
    "x_dlp findings are unavailable on this deployment: the receipt "
    "store is not configured, and absence of a view is never a zero"
)

_DLP_EMPTY_NOTE = (
    "no x_dlp receipts yet: findings appear when demo traffic carries "
    "the canned patterns and the advisory redaction engine matches a "
    "span. A clean scan mints nothing, and the empty view never pads."
)

#: Honest limits riding every DLP response (bounded disclosure rules and
#: the deliberately narrow advisory coverage).
_DLP_LIMITS = (
    "the advisory engine wires a declared subset of the x_dlp "
    "vocabulary: pii_card, pii_email, pii_national_id and secret_bearer; "
    "pci_pan is deliberately not wired (issuer-aware PAN heuristics "
    "belong to the enterprise scanner)",
    "the demo scan runs only when RAUCLE_DEMO_MODE is on: production "
    "gate traffic is never content-scanned by the gateway",
    "rows carry digests, class names and span counts only; the scanned "
    "content never enters a receipt",
    "the action is always redacted in the demo: block classes belong "
    "to the enterprise runtime and are never claimed here",
)

#: One advisory middleware per gateway process (the demo plane drives
#: the same RaucleMiddleware an agent adapter configures; weak-keyed so
#: the cache never outlives the gateway it serves).
_DEMO_DLP_MIDDLEWARE: weakref.WeakKeyDictionary[Any, Any] = weakref.WeakKeyDictionary()


def _demo_dlp_middleware(gateway: Any) -> Any:
    """The demo gateway's advisory redaction middleware, built once.

    Configured with the wired advisory pattern classes and the gateway
    as the findings client, so the middleware's advisory findings mint
    through the real emitter exactly as they do in an adapter run.
    """
    mw = _DEMO_DLP_MIDDLEWARE.get(gateway)
    if mw is None:
        from raucle.middleware import RaucleMiddleware
        from raucle.redaction import wired_redaction_classes

        mw = RaucleMiddleware(redaction_classes=wired_redaction_classes(), gateway=gateway)
        with contextlib.suppress(TypeError):  # pragma: no cover - non-weakrefable gateway
            _DEMO_DLP_MIDDLEWARE[gateway] = mw
    return mw


def run_demo_dlp_scan(
    gateway: Any,
    *,
    tool: str,
    args: dict[str, Any],
    agent_id: str,
    destination: str,
    session_id: str,
    trace_id: str,
    gate_receipt_id: str,
    gate_decision: str,
) -> None:
    """D2: run one demo gate call through the real advisory redaction
    path and mint its ``x_dlp`` receipt.

    Two legs, both advisory and both fail-open (the gate decision is
    already made and returned; this layer never changes it):

    1. the REAL middleware path (``raucle.middleware``): the call is
       scanned, the argument text recorded into the advisory session
       window carries ``[REDACTED:<class>]`` collars, and the
       middleware's advisory findings mint citing the gate receipt.
    2. the ``x_dlp`` receipt, minted through the OSS emitter from the
       same engine pass over the same serialized argument text, so
       the digests in both receipts agree and the scan is
       replay-verifiable offline with the cited gate receipt in the
       chain.

    Nothing matched means no receipt: an honest clean scan mints no
    evidence (mirroring the enterprise proxy contract).
    """
    from raucle.redaction import redact_text, wired_redaction_classes

    try:
        mw = _demo_dlp_middleware(gateway)
        mw.clear_trace_receipt(trace_id)
        mw.record_trace_receipt(trace_id, gate_receipt_id, gate_decision)
        mw.pre_tool_call(
            tool,
            args,
            session_id=session_id or DLP_ADVISORY_SESSION,
            trace_id=trace_id,
        )
    except Exception:
        logger.warning(
            "demo DLP advisory middleware leg failed open (decision "
            "unchanged; this layer has no enforcement authority)",
            exc_info=True,
        )
    arg_text = " ".join(f"{k}={v}" for k, v in args.items())
    rr = redact_text(arg_text, wired_redaction_classes())
    if not rr.span_counts:
        return
    from raucle.provenance import _canonical_json, _sha256_hex

    digest_hex = _sha256_hex(
        _canonical_json({"cited": gate_receipt_id, "content": rr.content_sha256})
    )
    scan_id = "scan:" + digest_hex[:16]
    try:
        gateway.emit_dlp_finding(
            scan_id=scan_id,
            route={
                "source": str(agent_id),
                "destination": str(destination) or f"tool:{tool}",
            },
            direction="egress_to_tool",
            content_sha256=rr.content_sha256,
            matched_classes=rr.matched_classes,
            span_counts=dict(rr.span_counts),
            action="redacted",
            rule_id=DLP_DEMO_RULE_ID,
            redacted_content_sha256=rr.redacted_content_sha256,
            cited_receipt=gate_receipt_id,
        )
    except Exception:
        logger.warning(
            "demo x_dlp emission failed (advisory only, no receipt minted)",
            exc_info=True,
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


def _session_finding_row(finding: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    """One session-monitor finding row (moved verbatim from
    :func:`build_session_findings`' scan loop, S3776 helper)."""
    repro = finding.get("repro") or {}
    return {
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


def _scan_session_findings(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Scan the newest receipt envelopes for ``x_finding`` receipts with
    harness ``session-monitor``, newest first, bounded and disclosed.

    The scan loop of :func:`build_session_findings`, moved verbatim
    (S3776 helper); each row carries the finding receipt's own hash so
    the panel can run the offline verifier over it (the verifier
    re-checks the cited gate receipt and the reported decision against
    the chain). A malformed line is skipped, never served.
    """
    findings: list[dict[str, Any]] = []
    truncated = False
    scanned = 0
    for record in records:
        scanned += 1
        try:
            payload = _decode_payload(record)
        except Exception:  # a malformed line is skipped, never served
            continue
        finding = payload.get("x_finding") if isinstance(payload, dict) else None
        if not isinstance(finding, dict) or finding.get("harness") != _HARNESS:
            continue
        findings.append(_session_finding_row(finding, record))
        if len(findings) >= FINDING_ROW_CAP:
            truncated = True
            break
    findings.sort(key=lambda f: f["detected_at"], reverse=True)
    return {"findings": findings, "scanned": scanned, "truncated": truncated}


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
    scanned_scan = _scan_session_findings(records)
    findings = scanned_scan["findings"]
    return {
        "schema_version": FINDINGS_SCHEMA,
        "label": "signed x_finding receipts from this deployment's chain",
        "harness": _HARNESS,
        "count": len(findings),
        "scanned": scanned_scan["scanned"],
        "truncated": scanned_scan["truncated"],
        "monitor_note": (
            "a finding is the monitor's claim; the offline verifier re-checks "
            "it against the cited gate receipt in the chain, so a finding "
            "citing a missing receipt or misreporting the decision fails "
            "verification"
        ),
        "findings": findings,
    }


def _is_middleware_advisory_finding(decoded: dict[str, Any]) -> bool:
    """Whether one decoded record is a middleware-advisory ``x_finding``
    receipt (counted alongside the DLP scans)."""
    x_finding = decoded.get("x_finding")
    return isinstance(x_finding, dict) and x_finding.get("harness") == "middleware-advisory"


def _dlp_row(
    decoded: dict[str, Any], x_dlp: dict[str, Any], record: dict[str, Any]
) -> dict[str, Any]:
    """One ``x_dlp`` scan row (moved verbatim from
    :func:`build_dlp_findings`' scan loop, S3776 helper). Every row field
    comes from the signed extension: digests, bounded class names, span
    counts and route identifiers, never content."""
    route = x_dlp.get("route") if isinstance(x_dlp.get("route"), dict) else {}
    return {
        "scan_id": str(x_dlp.get("scan_id") or ""),
        "action": str(x_dlp.get("action") or ""),
        "direction": str(x_dlp.get("direction") or ""),
        "route": {
            "source": str(route.get("source") or ""),
            "destination": str(route.get("destination") or ""),
        },
        "content_sha256": str(x_dlp.get("content_sha256") or ""),
        "redacted_content_sha256": str(x_dlp.get("redacted_content_sha256") or ""),
        "matched_classes": sorted(str(c) for c in (x_dlp.get("matched_classes") or [])),
        "span_counts": {str(k): int(v) for k, v in (x_dlp.get("span_counts") or {}).items()},
        "rule_id": str(x_dlp.get("rule_id") or ""),
        "cited_receipt": str(x_dlp.get("cited_receipt") or ""),
        "detected_at": int(decoded.get("iat") or 0),
        "receipt_hash": str(record.get("receipt_hash") or ""),
    }


def _accumulate_span_counts(by_class: dict[str, int], span_counts: dict[str, int]) -> None:
    """Fold one row's span counts into the per-class totals (in place,
    as the scan loop did)."""
    for cls, count in span_counts.items():
        by_class[cls] = by_class.get(cls, 0) + count


def _scan_dlp_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Scan the newest receipt envelopes for ``x_dlp`` receipts and the
    advisory middleware findings from the same scan window.

    The scan loop of :func:`build_dlp_findings`, moved verbatim (S3776
    helper). A malformed line is skipped, never served; the screen never
    holds the values, only the signed extension's fields.
    """
    findings: list[dict[str, Any]] = []
    by_class: dict[str, int] = {}
    advisory = 0
    scanned = 0
    truncated = False
    for record in records:
        scanned += 1
        try:
            decoded = _decode_payload(record)
            if not isinstance(decoded, dict):
                continue
            x_dlp = decoded.get("x_dlp")
            if not isinstance(x_dlp, dict):
                if _is_middleware_advisory_finding(decoded):
                    advisory += 1
                continue
            row = _dlp_row(decoded, x_dlp, record)
            findings.append(row)
            _accumulate_span_counts(by_class, row["span_counts"])
            if len(findings) >= DLP_ROW_CAP:
                truncated = True
                break
        except Exception:  # a malformed line is skipped, never served
            continue
    findings.sort(key=lambda f: f["detected_at"], reverse=True)
    return {
        "findings": findings,
        "by_class": by_class,
        "advisory": advisory,
        "scanned": scanned,
        "truncated": truncated,
    }


def build_dlp_findings(gateway: Any) -> dict[str, Any]:
    """The x_dlp scan receipts, read from the signed receipt chain.

    Scans the newest receipt envelopes for ``x_dlp`` receipts (the
    demo advisory redaction engine's scans), newest first, bounded and
    disclosed. Every row field comes from the signed extension:
    digests, bounded class names, span counts and route identifiers,
    never content. The advisory middleware findings from the same scan
    window are counted alongside, so the screen can show both halves
    of the advisory story without ever holding the values.
    """
    from raucle.redaction import wired_redaction_classes

    store = getattr(gateway, "_receipt_store", None)
    payload: dict[str, Any] = {
        "schema_version": DLP_SCHEMA,
        "label": "signed x_dlp receipts from this deployment's chain",
        "wired_classes": wired_redaction_classes(),
        "rule_id": DLP_DEMO_RULE_ID,
        "limits": list(_DLP_LIMITS),
    }
    if store is None:
        payload.update(
            {
                "available": False,
                "findings": [],
                "by_class": {},
                "count": 0,
                "advisory_findings": 0,
                "unavailable_note": _NO_DLP_STORE_NOTE,
            }
        )
        return payload
    scan = _scan_dlp_records(store.recent(DLP_SCAN_CAP))
    findings = scan["findings"]
    payload.update(
        {
            "available": True,
            "findings": findings,
            "by_class": dict(sorted(scan["by_class"].items())),
            "count": len(findings),
            "scanned": scan["scanned"],
            "truncated": scan["truncated"],
            "advisory_findings": scan["advisory"],
            "empty_note": "" if findings else _DLP_EMPTY_NOTE,
            "monitor_note": (
                "every row is a signed x_dlp receipt; the offline verifier "
                "re-checks its structure, bounded vocabulary and citation "
                "against the chain, so a scan citing a missing receipt or "
                "carrying content fails verification"
            ),
        }
    )
    return payload


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

    @app.get(
        "/api/demo/dlp-findings",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_dlp_findings(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        """The x_dlp scan receipts the demo advisory redaction engine
        minted, each citing the gate receipt of the call it scanned."""
        _gate(authorization, x_totp)
        return build_dlp_findings(gateway)

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
