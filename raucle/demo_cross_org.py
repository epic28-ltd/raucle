"""EPIC G: cross-organisation receipt verification and conformance-without-disclosure.

Two read-only demo screens built on the REAL verification machinery:

- G4 cross-organisation receipt verification: Organisation A emits gate
  receipts under its own key in a disposable sandbox; Organisation B
  verifies them against the public key Organisation A PUBLISHES (the
  only material the two organisations ever exchange), with NO contact
  with the issuing operator. The verifier is
  :class:`raucle.provenance.ProvenanceVerifier` - the same verifier an
  auditor runs over an exported chain.
- G6 conformance-without-disclosure: the call arguments are committed
  with :mod:`raucle.conformance` (a Merkle tree over the canonical
  fields), only the fields the policy constraint touches are disclosed,
  and the verifier re-checks the policy against the commitment. What the
  verifier proves and what stays hidden are both rendered; undisclosed
  constraints read UNKNOWN (fail-closed), and hidden values never leave
  this module.

Everything is produced fresh per call by the real production code
paths, then labelled simulated. The screens are display-only.
"""

from __future__ import annotations

import os
from typing import Any

# ---------------------------------------------------------------------------
# Honest-labelling constants shared with the panel tests
# ---------------------------------------------------------------------------

_NOTE_SIMULATED = (
    "Simulated demonstration: the material below was produced in a "
    "disposable sandbox by the real verification machinery, running with "
    "the same enforcement code paths as a live deployment."
)

_CROSS_ORG_DESCRIPTION = (
    "Cross-organisation receipt verification: Organisation B verifies "
    "receipts that Organisation A issued, using only the public key "
    "Organisation A publishes. No connection to Organisation A is made at "
    "any point."
)

_CONF_DESCRIPTION = (
    "Conformance without disclosure: the verifier re-checks the policy "
    "constraint against a cryptographic commitment to the call arguments, "
    "disclosing only the fields the constraint touches. Everything else "
    "stays hidden from every party, including this panel."
)

#: Simulated Organisation A arguments for the conformance commitment. The
#: hidden values below deliberately NEVER appear in any response payload.
_CONF_ARGS = {
    "account_ref": "ACC-001",
    "amount": 1250,
    "beneficiary_reference": "GB29-NWBK-6016-1331-9264-19",
    "memo": "invoice settlement for March",
}

#: Hidden fields: those the demo does NOT disclose. Their VALUES (not the
#: field names) must appear nowhere in any response: bounded disclosure.
_CONF_HIDDEN_FIELDS = ["beneficiary_reference", "memo"]

#: Constraints the verifier re-checks, in the proof-side vocabulary of
#: :func:`raucle.conformance.recheck_constraints`. The ``starts_with``
#: constraint touches an undisclosed field on purpose: it must read
#: UNKNOWN, never conformance (fail-closed).
_CONF_CONSTRAINTS = {
    "allowed_values": {"account_ref": ["ACC-001"]},
    "max_value": {"amount": 5000},
    "starts_with": {"beneficiary_reference": ["GB"]},
}

#: The fields the demo discloses to the verifier.
_CONF_DISCLOSED_FIELDS = ["account_ref", "amount"]


def demo_cross_org_mode_on() -> bool:
    return os.environ.get("RAUCLE_DEMO_MODE", "").lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# G4: cross-organisation receipt verification
# ---------------------------------------------------------------------------


def _emit_org_a_receipts(org_a: Any) -> list[str]:
    """Organisation A issues a small set of gate receipts the real way."""
    from raucle.gateway import GateReceiptContext

    receipts: list[str] = []
    simulated_calls = (
        {
            "decision": "allow",
            "tool": "lookup_balance",
            "agent_id": "agent:org-a-payments",
            "args": {"account_ref": "ACC-001"},
            "reason": "demo: policy allows account lookup",
            "policy": "org-a:payments-allow",
        },
        {
            "decision": "deny",
            "tool": "transfer_funds",
            "agent_id": "agent:org-a-payments",
            "args": {"account_ref": "ACC-001", "amount": 99000},
            "reason": "demo: amount above the policy limit",
            "policy": "org-a:transfer-limit",
        },
    )
    for call in simulated_calls:
        receipt_hash = org_a._emit_gate_receipt(
            GateReceiptContext(
                decision=call["decision"],
                reason=call["reason"],
                tool=call["tool"],
                agent_id=call["agent_id"],
                args=call["args"],
                policy=call["policy"],
                latency_us=0,
                source="demo-simulated",
                destination="",
                trace_id="",
            )
        )
        if receipt_hash:
            receipts.append(receipt_hash)
    return receipts


def _decode_envelope_summary(envelope: dict[str, Any]) -> dict[str, Any]:
    """What the Organisation B verifier sees about one receipt, decoded
    from the JWS payload by Organisation B itself."""
    import base64
    import json

    seg = envelope["jws"].split(".")[1]
    payload = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    x_gate = payload.get("x_gate", {})
    return {
        "receipt_hash_prefix": envelope["receipt_hash"][:24],
        "decision": x_gate.get("decision", ""),
        "tool": x_gate.get("tool", ""),
        "agent_id": x_gate.get("agent_id", ""),
        "issued_at": payload.get("iat", 0),
        "signed_by_key_id": payload.get("agent_key_id", ""),
    }


def _verify_one_as_org_b(
    envelope: dict[str, Any], pinned_public_keys: dict[str, bytes]
) -> dict[str, Any]:
    """Organisation B runs the real offline verifier over one receipt's
    envelope, exactly like the admin panel's offline-verify endpoint."""
    import json as _json
    import tempfile as _tempfile
    from pathlib import Path as _Path

    from raucle.provenance import ProvenanceVerifier, _sha256_hex

    report = None
    with _tempfile.TemporaryDirectory(prefix="raucle-demo-xorg-") as td:
        chain_file = _Path(td) / "receipt.jsonl"
        chain_file.write_text(_json.dumps(envelope, ensure_ascii=False) + "\n", encoding="utf-8")
        report = ProvenanceVerifier(public_keys=pinned_public_keys).verify_chain(chain_file)

    recomputed = "sha256:" + _sha256_hex(envelope.get("jws", "").encode("ascii"))
    valid = bool(report.valid) and recomputed == envelope.get("receipt_hash")
    errors = list(report.errors or [])
    if valid:
        signature_check = "ok"
    elif report.signature_failures:
        signature_check = "failed"
    else:
        signature_check = "not checked to completion"
    return {
        "verdict": "verified" if valid else "failed",
        "signature_check": signature_check,
        "hash_linkage": {
            "recomputed_matches": valid,
            "recomputed_sha256_prefix": recomputed[:24] if valid else "",
        },
        "offline": "Verified without contacting the issuing operator.",
        "errors": errors[:3],
    }


def build_demo_cross_org() -> dict[str, Any]:
    """Run the two-organisation story once in a disposable sandbox.

    Organisation A: a throwaway gateway with its own gate identity, whose
    receipts are signed under Organisation A's pinned key. Organisation
    B: verification against the PINNED external key only. The pin is the
    public key Organisation A published - the sole exchanged material;
    no request ever reaches Organisation A.
    """
    import tempfile
    from pathlib import Path

    from raucle.gateway import GatewayConfig, RaucleGateway

    receipts_out: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []
    last_envelope: dict[str, Any] | None = None

    with tempfile.TemporaryDirectory(prefix="raucle-demo-xorg-") as td:
        root = Path(td)
        cfg = GatewayConfig(
            policy_file=str(root / "policies.yaml"),
            receipt_store=str(root / "receipts.jsonl"),
            audit_chain=str(root / "audit.jsonl"),
            signer_backend="local",
        )
        # Organisation A: a real gateway identity, real receipts.
        org_a = RaucleGateway(cfg)
        org_a_identity = org_a.gate_identity
        org_a_key_id = org_a_identity.key_id
        org_a_receipts = _emit_org_a_receipts(org_a)

        # The pin: the public key Organisation A published (out of band).
        # Organisation B holds ONLY this; it has no other connection.
        pinned = {org_a_key_id: org_a_identity.public_key_pem()}

        for receipt_hash in org_a_receipts:
            envelope = _find_envelope(cfg.receipt_store, receipt_hash)
            if envelope is None:
                continue
            last_envelope = envelope
            receipts_out.append(_decode_envelope_summary(envelope))
            verifications.append(
                {"receipt_hash_prefix": receipt_hash[:24], **_verify_one_as_org_b(envelope, pinned)}
            )

        # Fail-closed contrast: the same receipt verified against any key
        # that is NOT Organisation A's pin must fail.
        if last_envelope is not None:
            wrong_key_check: dict[str, Any] = _verify_against_stranger_key(last_envelope)
        else:
            wrong_key_check = {"verdict": "failed", "detail": "no receipts issued"}

    return {
        "note": _NOTE_SIMULATED,
        "simulated": True,
        "description": _CROSS_ORG_DESCRIPTION,
        "org_a": {
            "label": "Organisation A (issuer)",
            "key_id": org_a_key_id,
            "receipt_count": len(receipts_out),
        },
        "org_b": {
            "label": "Organisation B (verifier)",
            "pinned_key_source": (
                "the public key Organisation A publishes (the only exchanged material)"
            ),
            "pinned_key_id": org_a_key_id,
        },
        "contact": {
            "org_a_reached": False,
            "statement": "Organisation B verified with no contact with the issuing operator.",
        },
        "receipts": receipts_out,
        "verifications": verifications,
        "wrong_key_check": wrong_key_check,
        "offline": (
            "Verified without contacting the issuing operator. The pinned "
            "public key and the receipts themselves are the only inputs."
        ),
    }


def _find_envelope(store_path: str, receipt_hash: str) -> dict[str, Any] | None:
    import json

    with open(store_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("receipt_hash") == receipt_hash:
                return rec
    return None


def _verify_against_stranger_key(envelope: dict[str, Any]) -> dict[str, Any]:
    """Verify one receipt under a key that is NOT the pinned one.

    Deliberately fail-closed: a verifier that pinned the wrong key sees
    the receipt REFUSED, never passed. Any unexpected exception from the
    verifier counts as a failure too.
    """
    import json as _json
    import tempfile as _tempfile
    from pathlib import Path as _Path

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from raucle.provenance import ProvenanceVerifier

    stranger = Ed25519PrivateKey.generate()
    stranger_pem = stranger.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        with _tempfile.TemporaryDirectory(prefix="raucle-demo-xorg-") as td:
            chain_file = _Path(td) / "receipt.jsonl"
            chain_file.write_text(
                _json.dumps(envelope, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            report = ProvenanceVerifier(
                public_keys={"not-org-a-pinned-key": stranger_pem}
            ).verify_chain(chain_file)
            failed = not bool(report.valid)
            errors = list(report.errors or [])
    except Exception:
        failed = True
        errors = ["verification under the unpinned key raised; refused"]
    return {
        "verdict": "failed" if failed else "verified",
        "detail": (
            "A receipt verified under any key other than Organisation A's "
            "published key is refused: the pin binds the verification to "
            "the issuer."
        ),
        "errors": errors[:3],
    }


# ---------------------------------------------------------------------------
# G6: conformance without disclosure
# ---------------------------------------------------------------------------


def build_demo_conformance() -> dict[str, Any]:
    """Commit the (simulated) call arguments, disclose only what the
    policy constraint needs, verify the disclosure against the root and
    re-check the constraint with :mod:`raucle.conformance`."""
    from raucle.conformance import (
        commit_args,
        disclose_args,
        recheck_constraints,
        verify_disclosure,
    )

    root = commit_args(_CONF_ARGS)
    package = disclose_args(_CONF_ARGS, _CONF_DISCLOSED_FIELDS)
    verified = verify_disclosure(root, package)
    results = recheck_constraints(_CONF_CONSTRAINTS, verified)

    claims = [
        {
            "claim": "the call went to an approved account",
            "constraint_kind": "allowed_values",
            "field": "account_ref",
            "result": results.get("allowed_values", "UNKNOWN"),
            "disclosed_value": verified.get("account_ref"),
        },
        {
            "claim": "the amount was within the policy limit",
            "constraint_kind": "max_value",
            "field": "amount",
            "result": results.get("max_value", "UNKNOWN"),
            "disclosed_value": verified.get("amount"),
        },
        {
            "claim": "the beneficiary reference carried the approved routing prefix",
            "constraint_kind": "starts_with",
            "field": "beneficiary_reference",
            # Deliberate: the field stays hidden, so the verifier reports
            # UNKNOWN rather than conformance. Fail-closed is the point.
            "result": results.get("starts_with", "UNKNOWN"),
            "disclosed_value": None,
        },
    ]

    return {
        "note": _NOTE_SIMULATED,
        "simulated": True,
        "description": _CONF_DESCRIPTION,
        "simulated_traffic": {
            "note": "One simulated tool call, committed by the real conformance machinery.",
            "tool": "transfer_funds",
        },
        "proof_artifact": {
            "kind": "merkle_root_over_arguments",
            "identifier": root,
            "scheme": (
                "domain-separated SHA-256 Merkle tree over the canonical "
                "argument fields (raucle/d1)"
            ),
        },
        "disclosed": {
            "fields": list(verified.keys()),
            "values": verified,
            "note": "Disclosed values are simulated demo data.",
        },
        "hidden": {
            "fields": _CONF_HIDDEN_FIELDS,
            "note": (
                "Their values are not in this response and never reach the "
                "verifier: proof binds them through the commitment only."
            ),
        },
        "claims": claims,
        "constraint_results": results,
        "fail_closed_note": (
            "A constraint over a hidden field reads UNKNOWN, never "
            "conformance: undisclosed policy claims stay unproven."
        ),
    }


# ---------------------------------------------------------------------------
# Demo-mode gated, read-only endpoints
# ---------------------------------------------------------------------------


def register_demo_cross_org_routes(app: Any, check_auth: Any, check_access: Any) -> None:
    """Read-only demo endpoints for the two assurance screens.

    Gated by the demo mode environment flag like the other demo planes;
    on any other deployment the routes answer 404. Read-only by
    construction: both builders work on fresh throwaway material per
    call and touch nothing the panel stores.
    """
    from fastapi import Header, HTTPException

    @app.get(
        "/api/demo/cross-org",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_cross_org(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        user = check_auth(authorization, x_totp)
        check_access(user, "stats")
        if not demo_cross_org_mode_on():
            raise HTTPException(404, "demo mode not configured")
        return build_demo_cross_org()

    @app.get(
        "/api/demo/conformance",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_conformance(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        user = check_auth(authorization, x_totp)
        check_access(user, "stats")
        if not demo_cross_org_mode_on():
            raise HTTPException(404, "demo mode not configured")
        return build_demo_conformance()


__all__ = [
    "build_demo_conformance",
    "build_demo_cross_org",
    "demo_cross_org_mode_on",
    "register_demo_cross_org_routes",
]
