"""Unit tests for raucle/epaec.py — EP-AEC chain verification (N4).

Draft: draft-schrock-ep-authorization-evidence-chain-00.  Vector-level
end-to-end cases live in tests/vectors/epaec-v1.json (tests/test_epaec_vectors.py);
the tests here exercise the walker's structural/fail-closed surface directly.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import raucle.epaec as epaec
import raucle.nelson14 as nelson14


def _key():
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": nelson14._b64u(nums.x.to_bytes(32, "big")),
        "y": nelson14._b64u(nums.y.to_bytes(32, "big")),
    }
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return jwk, pem


@pytest.fixture(scope="module")
def keys():
    return _key()


def _action():
    return {"operation": "deploy", "resource": "api://prod/payments", "method": "POST"}


def _chain(**overrides):
    chain = {
        "@version": "EP-AEC-v1",
        "action": _action(),
        "components": [
            {
                "type": "ep-receipt",
                "label": "ep proof receipt",
                "evidence": {"ok": True, "actionDigest": epaec.canonical_action_digest(_action())},
            },
        ],
        "requirement": "ep-receipt",
    }
    chain.update(overrides)
    return chain


def _always_valid(evidence):
    digest = evidence.get("actionDigest") if isinstance(evidence, dict) else None
    return (isinstance(evidence, dict) and evidence.get("ok") is True, digest)


# --------------------------------------------------------------------------
# Section 4 step 1 — structural fail-closed
# --------------------------------------------------------------------------


def test_malformed_chains_deny(keys):
    jwk, _pem = keys
    verifiers = {"ep-receipt": _always_valid}
    base = _chain()
    assert base is not None and jwk is not None
    for name, chain in {
        "not_object": "hello",
        "bad_version": _chain(**{"@version": "EP-AEC-v2"}),
        "missing_version": {k: v for k, v in base.items() if k != "@version"},
        "missing_action": {k: v for k, v in base.items() if k != "action"},
        "empty_components": _chain(components=[]),
        "missing_requirement": {k: v for k, v in base.items() if k != "requirement"},
        "unknown_field": _chain(extra="x"),
        "duplicate_type": _chain(
            components=[
                {"type": "ep-receipt", "evidence": {}},
                {"type": "ep-receipt", "evidence": {}},
            ]
        ),
    }.items():
        res = epaec.verify_chain(chain, verifiers)
        assert (res.decision, res.overall) == ("DENY", "FAIL"), name


def test_malformed_chain_names_reason(keys):
    res = epaec.verify_chain(_chain(**{"@version": "nope"}), {})
    assert res.requirement_error == "BAD_VERSION"


# --------------------------------------------------------------------------
# Section 4 step 2 — canonical same-digest binding
# --------------------------------------------------------------------------


def test_tampered_action_digest_denied(keys):
    res = epaec.verify_chain(
        _chain(action_digest="sha256:" + "a" * 64), {"ep-receipt": _always_valid}
    )
    assert res.decision == "DENY"
    assert res.requirement_error == "ACTION_DIGEST_MISMATCH"


def test_tampered_action_bytes_denied_when_digest_pinned(keys):
    action = _action()
    action["resource"] = "api://prod/other-db"
    # pinned digest still describes the ORIGINAL action -> step 2 mismatch
    res = epaec.verify_chain(
        _chain(action=action, action_digest=epaec.canonical_action_digest(_action())),
        {"ep-receipt": _always_valid},
    )
    assert res.requirement_error == "ACTION_DIGEST_MISMATCH"
    # with no pinned digest the component itself binds a different action
    res2 = epaec.verify_chain(_chain(action=action), {"ep-receipt": _always_valid})
    assert res2.decision == "DENY"
    assert res2.components[0]["reason"] == "binds a different action"


def test_digest_recomputed_if_absent(keys):
    res = epaec.verify_chain(
        {k: v for k, v in _chain().items() if k != "action_digest"}, {"ep-receipt": _always_valid}
    )
    assert res.decision == "ALLOW"
    assert res.chain_digest == epaec.canonical_action_digest(_action())


def test_bad_digest_shape_denied(keys):
    res = epaec.verify_chain(_chain(action_digest="deadbeef"), {"ep-receipt": _always_valid})
    assert res.requirement_error == "BAD_ACTION_DIGEST"


# --------------------------------------------------------------------------
# Section 4 step 3 — component verdicts
# --------------------------------------------------------------------------


def test_cross_binding_denied(keys):
    other_digest = epaec.canonical_action_digest({**_action(), "method": "DELETE"})
    evidence = {"ok": True, "actionDigest": other_digest}
    res = epaec.verify_chain(
        _chain(requirement="ep-receipt", components=[{"type": "ep-receipt", "evidence": evidence}]),
        {"ep-receipt": _always_valid},
    )
    c = res.components[0]
    assert (c["status"], c["reason"]) == ("INVALID", "binds a different action")
    assert res.decision == "DENY"


def test_unregistered_type_unverified(keys):
    res = epaec.verify_chain(
        _chain(requirement="ep-quorum", components=[{"type": "ep-quorum", "evidence": {"x": 1}}]),
        {"ep-receipt": _always_valid},
    )
    c = res.components[0]
    assert c["status"] == epaec.UNVERIFIED
    assert c["reason"] == "no verifier registered for type"
    assert res.decision == "DENY"


def test_verifier_exception_fails_component_fails_closed(keys):
    def boom(_e):
        raise RuntimeError("unexpected")

    res = epaec.verify_chain(
        _chain(components=[{"type": "ep-receipt", "evidence": {}}]), {"ep-receipt": boom}
    )
    assert res.components[0]["status"] == epaec.INVALID
    assert res.components[0]["reason"].startswith("verifier raised")
    assert res.decision == "DENY"


def test_verifier_returning_none_digest_invalid(keys):
    res = epaec.verify_chain(_chain(), {"ep-receipt": lambda e: (True, None)})
    assert res.components[0]["status"] == epaec.INVALID
    assert res.decision == "DENY"


def test_label_and_type_join_satisfied_set(keys):
    res = epaec.verify_chain(
        _chain(
            requirement="ep-proof-receipt",
            components=[
                {
                    "type": "ep-receipt",
                    "label": "ep-proof-receipt",
                    "evidence": {
                        "ok": True,
                        "actionDigest": epaec.canonical_action_digest(_action()),
                    },
                }
            ],
        ),
        {"ep-receipt": _always_valid},
    )
    assert res.decision == "ALLOW"  # label is a first-class satisfied identifier
    assert "ep-proof-receipt" in res.satisfied


# --------------------------------------------------------------------------
# Section 4 steps 4-5 / Section 5 — bounded requirement evaluation
# --------------------------------------------------------------------------


def test_left_associative_mixed_precedence(keys):
    v = {"ep-receipt": _always_valid}
    digest = epaec.canonical_action_digest(_action())
    evidence = {"ok": True, "actionDigest": digest}
    comps = [{"type": "ep-receipt", "evidence": evidence}]
    # Grammar has flat left-associative fold: a OR b AND c == (a OR b) AND c.
    res = epaec.verify_chain(
        _chain(requirement="ep-quorum OR ep-audit AND ep-receipt", components=comps), v
    )
    assert res.decision == "DENY"  # (ep-quorum OR ep-audit) is false -> AND short-circuits
    res2 = epaec.verify_chain(
        _chain(requirement="(ep-quorum OR ep-audit) OR ep-receipt", components=comps), v
    )
    assert res2.decision == "ALLOW"


def test_unknown_operator_fails_named(keys):
    verifiers = {"ep-receipt": _always_valid}
    for req in (
        "ep-receipt NOT ep-audit",
        "ep-receipt XOR ep-audit",
        "ep-receipt AND",
        "AND ep-receipt",
        "ep-receipt AND (ep-audit",
    ):
        res = epaec.verify_chain(_chain(requirement=req), verifiers)
        assert res.decision == "DENY", req
        assert res.requirement_error in ("REQUIREMENT_UNBALANCED", "REQUIREMENT_PARSE_ERROR"), req


def test_bad_character_named(keys):
    res = epaec.verify_chain(
        _chain(requirement="ep-receipt; DROP TABLE"), {"ep-receipt": _always_valid}
    )
    assert res.requirement_error == "BAD_REQUIREMENT_TOKEN"


def test_unbounded_requirement_rejected(keys):
    res = epaec.verify_chain(
        _chain(requirement="a AND " * 500 + "a"), {"ep-receipt": _always_valid}
    )
    assert res.requirement_error == "REQUIREMENT_TOO_LONG"


def test_deep_nesting_rejected(keys):
    res = epaec.verify_chain(_chain(requirement="(" * 20 + "a" + ")" * 20), {})
    assert res.requirement_error == "REQUIREMENT_DEPTH_EXCEEDED"


# --------------------------------------------------------------------------
# Deterministic bytes for the verification object
# --------------------------------------------------------------------------


def test_result_bytes_deterministic_and_canonical(keys):
    verifiers = {"ep-receipt": _always_valid}
    r1 = epaec.verify_chain(_chain(), verifiers)
    r2 = epaec.verify_chain(_chain(), verifiers)
    b1, b2 = epaec.result_bytes(r1), epaec.result_bytes(r2)
    assert b1 == b2
    assert b1.decode("utf-8") == json.dumps(
        json.loads(b1), separators=(",", ":"), ensure_ascii=False
    )


# --------------------------------------------------------------------------
# JWS receipt profile — delegation to raucle.nelson14
# --------------------------------------------------------------------------


def test_receipt_jws_roundtrip(keys):
    jwk, pem = keys
    body = {"receiptId": "r-1", "actionDigest": epaec.canonical_action_digest(_action())}
    compact = epaec.sign_receipt_jws(body, pem, kid="k1")
    out = epaec.verify_receipt_jws(compact, jwk)
    assert out == body


def test_receipt_jws_rejects_bad_signature(keys):
    jwk, pem = keys
    other_pem = _key()[1]
    compact = epaec.sign_receipt_jws(
        {"receiptId": "r", "actionDigest": "sha256:" + "0" * 64}, other_pem, kid="k1"
    )
    with pytest.raises(epaec.AecError) as ei:
        epaec.verify_receipt_jws(compact, jwk)
    assert ei.value.code == "RECEIPT_JWS_INVALID"


def test_receipt_jws_rejects_non_canonical_payload(keys):
    jwk, pem = keys
    body = {"receiptId": "r", "actionDigest": "sha256:" + "0" * 64}  # non-JCS key order
    header = json.dumps(
        {"alg": "ES256", "typ": "ep-aec-receipt", "kid": "k"}, separators=(",", ":")
    )
    compact = (
        nelson14._b64u(header.encode())
        + "."
        + nelson14._b64u(json.dumps(body, separators=(",", ":")).encode())  # non-JCS key order
        + "."
        + nelson14._es256_sign(pem, b"unsigned")
    )
    with pytest.raises(epaec.AecError) as ei:
        epaec.verify_receipt_jws(compact, jwk)
    assert ei.value.code == "RECEIPT_NON_CANONICAL"


def test_drp_receipt_delegates_to_nelson14_verifier(keys):
    """A drp-receipt-typed receipt is verified by nelson14's strict check, not by us."""
    jwk, _pem = keys
    priv = ec.generate_private_key(ec.SECP256R1())
    import hashlib

    nums = priv.public_key().public_numbers()
    jwk2 = {
        "kty": "EC",
        "crv": "P-256",
        "x": nelson14._b64u(nums.x.to_bytes(32, "big")),
        "y": nelson14._b64u(nums.y.to_bytes(32, "big")),
    }
    body: dict[str, object] = {
        "delegationId": "d-1",
        "issuedAt": "2026-01-01T00:00:00Z",
        "scope": "s",
        "boundaries": "b",
        "timeWindow": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z"},
        "operatorInstructions": "do the thing",
        "instructionsHash": hashlib.sha256(
            nelson14.normalise_instructions("do the thing").encode("utf-8")
        ).hexdigest(),
        "signerPublicKey": jwk2,
        "nonce": "ep-aec-n4",  # DRP extension point carries the binding context
    }
    header = {"alg": "ES256", "typ": "drp-receipt", "kid": "k"}
    input_ = (
        nelson14._b64u(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + nelson14._b64u(nelson14.canonicalise_body(body).encode())
    )
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    signature = nelson14._es256_sign(priv_pem, input_.encode("ascii"))
    compact = input_ + "." + signature
    out = epaec.verify_receipt_jws(compact, jwk2)
    assert out == body
    # a body violating the DRP schema is rejected by nelson14 itself
    bad = dict(body)
    bad.pop("scope")
    input_bad = (
        nelson14._b64u(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + nelson14._b64u(nelson14.canonicalise_body(bad).encode())
    )
    sig_bad = nelson14._es256_sign(priv_pem, input_bad.encode("ascii"))
    with pytest.raises(epaec.AecError) as ei:
        epaec.verify_receipt_jws(input_bad + "." + sig_bad, jwk2)
    assert ei.value.code == "RECEIPT_JWS_INVALID"


def test_receipt_verifier_end_to_end(keys):
    jwk, pem = keys
    digest = epaec.canonical_action_digest(_action())
    receipt = epaec.sign_receipt_jws({"receiptId": "r-9", "actionDigest": digest}, pem, kid="k1")
    verifier = epaec.make_receipt_verifier(lambda _e: jwk)
    res = epaec.verify_chain(
        _chain(
            requirement="ep-receipt AND human-leg",
            components=[
                {"type": "ep-receipt", "evidence": receipt},
                {"type": "human-leg", "evidence": {"ok": True, "actionDigest": digest}},
            ],
        ),
        {"ep-receipt": verifier, "human-leg": _always_valid},
    )
    assert (res.decision, res.overall) == ("ALLOW", "PASS")
    assert res.components[0]["status"] == "VALID"
