"""Emit the EP-AEC conformance corpus vector file for raucle/epaec.py.

Run:  python tools/make_epaec_vectors.py
Writes tests/vectors/epaec-v1.json.  Receipt signatures are ECDSA-issued once;
the stored chains are then statically valid, and consumers verify outcomes
deterministically (no signing is expected during verification).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from raucle import epaec
from raucle.nelson14 import _b64u


def make_key() -> tuple[dict, bytes]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64u(pub.x.to_bytes(32, "big")),
        "y": _b64u(pub.y.to_bytes(32, "big")),
    }
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return jwk, pem


def main() -> None:
    jwk, pem = make_key()
    action = {"operation": "deploy", "resource": "api://prod/payments", "method": "POST"}
    digest = epaec.canonical_action_digest(action)

    def receipt(binding_digest: str = digest) -> str:
        return epaec.sign_receipt_jws(
            {"receiptId": "ep-receipt:test-1", "actionDigest": binding_digest},
            pem,
            kid="ep-aec-test",
        )

    receipt_jws = receipt()
    other = epaec.canonical_action_digest({**action, "resource": "api://staging"})
    wrong_binding = receipt(other)

    def ev(jws: str) -> dict:
        return epaec.verify_receipt_jws(jws, jwk)

    # sanity: our own verifier accepts these receipts
    assert ev(receipt_jws)["actionDigest"] == digest
    assert ev(wrong_binding)["actionDigest"] == other

    def chain(requirement: str, components: list | None = None, **overrides) -> dict:
        c = {
            "@version": "EP-AEC-v1",
            "action": action,
            "action_digest": digest,
            "components": components
            if components is not None
            else [
                {"type": "ep-receipt", "label": "ep proof receipt", "evidence": receipt_jws},
                {
                    "type": "policy-permit",
                    "label": "policy permit",
                    "evidence": {"permitId": "pp-1", "actionDigest": digest},
                },
            ],
            "requirement": requirement,
        }
        c.update(overrides)
        return c

    verifier = epaec.make_receipt_verifier(lambda _e: jwk)

    def policy_verifier(e):
        return (
            isinstance(e, dict) and e.get("actionDigest") == digest,
            e.get("actionDigest") if isinstance(e, dict) else None,
        )

    verifiers = {"ep-receipt": verifier, "policy-permit": policy_verifier}

    vectors = []

    def record(name: str, ch: dict, note: str) -> None:
        res = epaec.verify_chain(ch, verifiers)
        vectors.append(
            {
                "name": name,
                "note": note,
                "chain": ch,
                "expected": {
                    "decision": res.decision,
                    "overall": res.overall,
                    "statuses": [c["status"] for c in res.components],
                    "reasons": [c["reason"] for c in res.components],
                    "requirement_error": res.requirement_error,
                },
            }
        )

    record(
        "valid_e2e",
        chain("ep-receipt AND policy-permit"),
        "required components verify and bind the same canonical action digest (Section 4 step 3c)",
    )
    record(
        "valid_or_expression",
        chain("(ep-receipt OR policy-permit) AND ep-receipt"),
        "parenthesised grouping, left-associative fold (Section 5)",
    )
    record(
        "tampered_digest",
        chain("ep-receipt AND policy-permit", action_digest="sha256:" + "0" * 64),
        "declared action_digest does not match recomputed digest -> DENY (Section 4 step 2)",
    )
    record(
        "cross_binding",
        chain(
            "ep-receipt AND policy-permit",
            components=[
                {"type": "ep-receipt", "evidence": wrong_binding},
                {"type": "policy-permit", "evidence": {"permitId": "pp-1", "actionDigest": digest}},
            ],
        ),
        "a valid receipt binding a different action is unsatisfied (Section 4 step 3c)",
    )
    record(
        "unknown_operator",
        chain("ep-receipt NOT policy-permit"),
        "token outside the Section 5 grammar (AND/OR/parens/IDENT only) after a term is unbalanced",
    )
    record(
        "unexpected_character",
        chain("ep-receipt AND policy-permit;"),
        "character outside the token grammar -> named BAD_REQUIREMENT_TOKEN, fail-closed",
    )
    record(
        "unknown_identifier_falsy",
        chain("ep-receipt AND ep-quorum"),
        "unregistered identifier evaluates false (Section 5), so an unknown requirement name DENYs",
    )
    record(
        "missing_verifier",
        chain(
            "ep-receipt AND ep-quorum",
            components=[
                {"type": "ep-receipt", "label": "ep proof receipt", "evidence": receipt_jws},
                {
                    "type": "ep-quorum",
                    "label": "human quorum",
                    "evidence": {"quorumId": "q-1", "actionDigest": digest},
                },
            ],
        ),
        "ep-quorum has no registered verifier -> UNVERIFIED, requirement fails (Section 4 step 3a)",
    )

    doc = {
        "profile": "EP-AEC-v1",
        "draft": "draft-schrock-ep-authorization-evidence-chain-00",
        "digest_of_action": digest,
        "action": action,
        "jwk": jwk,
        "vectors": vectors,
    }
    out = Path(__file__).resolve().parents[1] / "tests" / "vectors" / "epaec-v1.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f" wrote {out} with {len(vectors)} vectors")


if __name__ == "__main__":
    main()
