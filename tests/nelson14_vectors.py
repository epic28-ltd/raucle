"""Nelson-14 delegation-receipt profile: test vectors per normative check.

Executable form of the published corpus
``docs/spec/nelson14-delegation-gate/v1/test-vectors.json``: every vector in
the corpus corresponds to a test here. The JSON carries bodies and expected
outcomes, not signatures — ECDSA is randomised per issuance, so the tests
re-sign live; the receiptId binds the artifact at issuance time.

Section numbers cited in comments refer to
draft-nelson-agent-delegation-receipts-14.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import raucle.nelson14 as nelson14
from raucle.nelson14 import Nelson14Error

REPO_ROOT = Path(nelson14.__file__).resolve().parent.parent
CORPUS_PATH = REPO_ROOT / "docs" / "spec" / "nelson14-delegation-gate" / "v1" / "test-vectors.json"


# ---------------------------------------------------------------------------
# Issuance helpers
# ---------------------------------------------------------------------------


def make_key():
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    nums = priv.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": nelson14._b64u(nums.x.to_bytes(32, "big")),
        "y": nelson14._b64u(nums.y.to_bytes(32, "big")),
    }
    return priv_pem, jwk


def instructions_text() -> str:
    return "Draft the daily summary, then review the agenda"


def root_body(jwk, **overrides):
    body = {
        "delegationId": "auth-1730000000000-ab12d",
        "issuedAt": "2026-11-06T09:00:00.000Z",
        "scope": "Read calendar events and draft daily summaries",
        "boundaries": "Never send email; never touch payment systems",
        "timeWindow": {"start": "2026-11-06T00:00:00.000Z", "end": "2026-11-07T00:00:00.000Z"},
        "operatorInstructions": instructions_text(),
        "instructionsHash": hashlib.sha256(
            nelson14.normalise_instructions(instructions_text()).encode("utf-8")
        ).hexdigest(),
        "signerPublicKey": dict(jwk),
        "revocationRequired": False,
    }
    for key, value in overrides.items():
        if value is None and key in body:
            del body[key]
        else:
            body[key] = value
    return body


def signed_body(body, pem, *, kid="nelson14"):
    return nelson14.issue_receipt(body, pem, kid=kid)


def receipt_id(compact):
    return nelson14.compute_receipt_id(compact)


class NullRegistry:
    def check(self, receipt_id):
        return {"revoked": False, "checked": True}


class RecordingRegistry:
    def __init__(self):
        self.revoked: dict[str, dict] = {}

    def check(self, receipt_id):
        if receipt_id in self.revoked:
            return {"revoked": True, "checked": True, **self.revoked[receipt_id]}
        return {"revoked": False, "checked": True}


class MemoryStore:
    def __init__(self):
        self.slots: set[str] = set()

    def was_consumed(self, key):
        return key in self.slots

    def consume(self, key):
        self.slots.add(key)
        return True


_PARENT_SCOPE = {
    "version": "1.0",
    "allowedActions": [
        {"operation": "read", "resource": "calendar/*"},
        {"operation": "read", "resource": "files/*"},
        {"operation": "draft", "resource": "summary/*"},
        {"operation": "index", "resource": "search/*"},
    ],
    "deniedActions": [{"operation": "send", "resource": "email/*"}],
}

_CHILD_SCOPE = {
    "version": "1.0",
    "allowedActions": [
        {"operation": "read", "resource": "calendar/*"},
        {"operation": "draft", "resource": "summary/*"},
    ],
    "deniedActions": [{"operation": "send", "resource": "email/*"}],
}


def build_pair(*, child_scope=None, revoke_parent=False, require_registry_on_root=False):
    """Root receipt plus one attenuated sub-receipt; returns a bundle."""
    parent_pem, parent_jwk = make_key()
    parent_overrides = {"revocationRequired": require_registry_on_root}
    if child_scope is not None:
        parent_overrides["scopeSchema"] = _PARENT_SCOPE
    parent = root_body(parent_jwk, **parent_overrides)
    parent_compact = nelson14.issue_receipt(parent, parent_pem, kid="root")
    parent_id = receipt_id(parent_compact)
    child_pem, child_jwk = make_key()
    overrides = {"parentReceiptId": parent_id}
    if child_scope is not None:
        overrides["scopeSchema"] = child_scope
    child = root_body(child_jwk, **overrides)
    child_compact = nelson14.issue_receipt(child, child_pem, kid="child")
    child_id = receipt_id(child_compact)
    # §4.4: the binding signer is the sub-receipt's own signerPublicKey holder —
    # the orchestrator is the holder of the parent delegation.
    orch = nelson14.sign_orchestrator_binding(parent_id, child_id, child_pem)
    bundle = {
        "parent_pem": parent_pem,
        "parent": parent,
        "parent_compact": parent_compact,
        "parent_id": parent_id,
        "child_pem": child_pem,
        "child": child,
        "child_compact": child_compact,
        "child_id": child_id,
        "orch": orch,
    }
    bundle["keymap"] = {parent_id: parent_jwk, child_id: child_jwk}
    bundle["registry"] = RecordingRegistry()
    if revoke_parent:
        bundle["registry"].revoked[parent_id] = {
            "reason": "key compromise",
            "revokedAt": 1730000000001,
        }
    return bundle


_UNSET = object()


def walk_child(bundle, *, registry=_UNSET, consumption_store=None, extra_attachments=None):
    attachments = {bundle["child_id"]: bundle["orch"]}
    if extra_attachments:
        attachments.update(extra_attachments)
    return nelson14.verify(
        bundle["child_compact"],
        key_for=lambda c: bundle["keymap"][receipt_id(c)],
        parent_lookup=lambda pid: bundle["parent_compact"] if pid == bundle["parent_id"] else None,
        registry=bundle["registry"] if registry is _UNSET else registry,
        consumption_store=consumption_store if consumption_store is not None else MemoryStore(),
        attachments=attachments,
    )


def expect_error(fn, code):
    with pytest.raises(Nelson14Error) as exc:
        fn()
    assert exc.value.code == code, f"expected {code}, got {exc.value.code} ({exc.value.detail})"


# ---------------------------------------------------------------------------
# §6/§5: JWS profile and canonicalisation vectors
# ---------------------------------------------------------------------------


def test_vector_valid_receipt_verifies():
    pem, jwk = make_key()
    compact = signed_body(root_body(jwk), pem)
    verdict = nelson14.verify(
        compact,
        key_for=lambda c: jwk,
        parent_lookup=lambda p: None,
        registry=NullRegistry(),
        consumption_store=MemoryStore(),
    )
    assert verdict.receipt_id == receipt_id(compact)
    assert verdict.consume_key is None


def test_vector_receipt_id_is_sha256_of_compact():
    pem, jwk = make_key()
    compact = signed_body(root_body(jwk), pem)
    assert receipt_id(compact) == hashlib.sha256(compact.encode("ascii")).hexdigest()


def test_vector_typ_must_be_drp_receipt():
    _, jwk = make_key()
    pem, _ = make_key()
    body = root_body(jwk)
    header = {"alg": "ES256", "typ": "JWT", "kid": "k"}
    input_ = _compact_input(header, body)
    compact = input_ + "." + nelson14._es256_sign(pem, input_.encode("ascii"))
    expect_error(lambda: nelson14.verify_jws(compact, jwk), "TYP_MISMATCH")


def _compact_input(header, body):
    return (
        nelson14._b64u(json.dumps(header).encode("ascii"))
        + "."
        + nelson14._b64u(nelson14.canonicalise_body(body).encode("utf-8"))
    )


def test_vector_alg_none_prohibited():
    _, jwk = make_key()
    body = root_body(jwk)
    header = {"alg": "none", "typ": "drp-receipt"}
    input_ = _compact_input(header, body)
    compact = input_ + "." + "AA"  # empty-ish signature slot
    expect_error(lambda: nelson14.verify_jws(compact, jwk), "ALG_PROHIBITED")


def test_vector_alg_not_in_profile_rejected():
    _, jwk = make_key()
    body = root_body(jwk)
    header = {"alg": "RS256", "typ": "drp-receipt"}
    pem, _ = make_key()
    input_ = _compact_input(header, body)
    compact = input_ + "." + nelson14._es256_sign(pem, input_.encode("ascii"))
    expect_error(lambda: nelson14.verify_jws(compact, jwk), "ALG_NOT_IN_PROFILE")


def test_vector_der_signature_rejected():
    from cryptography.hazmat.primitives import hashes

    _, jwk = make_key()
    body = root_body(jwk)
    header = {"alg": "ES256", "typ": "drp-receipt", "kid": "k"}
    pem, _ = make_key()
    input_ = _compact_input(header, body)
    key = serialization.load_pem_private_key(pem, password=None)
    der = key.sign(input_.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    compact = input_ + "." + nelson14._b64u(der)
    expect_error(lambda: nelson14.verify_jws(compact, jwk), "DER_SIGNATURE_REJECTED")


def test_vector_signature_invalid_on_modified_body():
    pem, jwk = make_key()
    compact = signed_body(root_body(jwk), pem)
    head, _, sig = compact.split(".")
    body2 = root_body(jwk, agentId="agent-b")
    bad = head + "." + nelson14._b64u(nelson14.canonicalise_body(body2).encode("utf-8")) + "." + sig
    expect_error(lambda: nelson14.verify_jws(bad, jwk), "SIGNATURE_INVALID")


def test_vector_non_canonical_payload_rejected():
    """§5: the signing input must BE the JCS form of the recognised body."""
    pem, jwk = make_key()
    body = root_body(jwk, metadata={"z": "astral \U0001f511 key", "a": 1})
    canon = nelson14.canonicalise_body(body)
    # byte-stability across re-parse and UTF-16 code-unit key ordering
    assert canon == nelson14.canonicalise_body(json.loads(json.dumps(body)))
    i_metadata = canon.index('"metadata"')
    i_a = canon.index('"a"', i_metadata)
    i_z = canon.index('"z"', i_metadata)
    assert i_metadata < i_a < i_z  # nested keys sort too (UTF-16 code units)
    # insertion-order serialization signed with the real key is still invalid
    header = {"alg": "ES256", "typ": "drp-receipt", "kid": "k"}
    rogue = json.dumps(body, sort_keys=False, separators=(",", ":"))
    input_ = (
        nelson14._b64u(json.dumps(header).encode("ascii"))
        + "."
        + nelson14._b64u(rogue.encode("utf-8"))
    )
    compact = input_ + "." + nelson14._es256_sign(pem, input_.encode("ascii"))
    expect_error(lambda: nelson14.verify_jws(compact, jwk), "NON_CANONICAL_PAYLOAD")


def test_vector_detached_not_accepted_this_profile_pins_compact():
    pem, jwk = make_key()
    body = root_body(jwk)
    header = {"alg": "ES256", "typ": "drp-receipt", "b64": False, "crit": ["b64"]}
    input_ = _compact_input(header, body)
    compact = input_ + "." + nelson14._es256_sign(pem, input_.encode("ascii"))
    expect_error(lambda: nelson14.verify_jws(compact, jwk), "DETACHED_NOT_SUPPORTED")


def test_vector_undefined_header_parameter_rejected():
    pem, jwk = make_key()
    body = root_body(jwk)
    header = {
        "alg": "ES256",
        "typ": "drp-receipt",
        "kid": "k",
        "jku": "https://attacker.invalid/jwks",
    }
    input_ = _compact_input(header, body)
    compact = input_ + "." + nelson14._es256_sign(pem, input_.encode("ascii"))
    expect_error(lambda: nelson14.verify_jws(compact, jwk), "BAD_HEADER")


def test_vector_wrong_signer_key_denied():
    pem, jwk = make_key()
    other_pem, _ = make_key()
    compact = nelson14.issue_receipt(root_body(jwk), other_pem, kid="k")
    expect_error(lambda: nelson14.verify_jws(compact, jwk), "SIGNATURE_INVALID")


def test_vector_jwk_with_private_member_rejected():
    _, jwk = make_key()
    body = root_body(jwk, signerPublicKey={**jwk, "d": "AA"})
    expect_error(lambda: nelson14.validate_body(body), "BAD_FIELD_VALUE")


# ---------------------------------------------------------------------------
# §4: body-field vectors
# ---------------------------------------------------------------------------


def test_vector_unknown_body_field_rejected():
    _, jwk = make_key()
    body = root_body(jwk, escalationToken="grant everything")
    expect_error(lambda: nelson14.validate_body(body), "UNKNOWN_BODY_FIELD")


def test_vector_unknown_metadata_fields_are_extension_point():
    _, jwk = make_key()
    body = root_body(jwk, metadata={"displayLabel": "internal only", "any": [1, 2]})
    assert nelson14.validate_body(body) is body


def test_vector_missing_required_field_rejected():
    _, jwk = make_key()
    body = root_body(jwk)
    del body["boundaries"]
    expect_error(lambda: nelson14.validate_body(body), "MISSING_REQUIRED_FIELD")


def test_vector_instructions_hash_mismatch():
    pem, jwk = make_key()
    body = root_body(jwk, operatorInstructions="   Whispered   contrary, instructions. ")
    expect_error(lambda: nelson14.issue_receipt(body, pem, kid="k"), "INSTRUCTIONS_HASH_MISMATCH")


def test_vector_instruction_normalisation_is_lossy_by_design():
    """Drift in commas/periods/case/spacing does NOT change the hash (§4.2)."""
    a = nelson14.normalise_instructions("Draft, the summary.")
    b = nelson14.normalise_instructions(" draft   the summary ")
    c = nelson14.normalise_instructions('Draft the summary."')
    d = nelson14.normalise_instructions("Draft \u201cthe\u201d summary.")
    assert a == b == c == d


# ---------------------------------------------------------------------------
# §8: chain, attenuation, depth vectors
# ---------------------------------------------------------------------------


def test_vector_valid_chain_verifies_with_all_checks():
    bundle = build_pair(child_scope=_CHILD_SCOPE)
    verdict = walk_child(bundle)
    assert verdict.receipt_id == bundle["child_id"]
    for check in (
        "attenuation",
        "orchestrator_binding",
        "window_containment",
        "cascade_revocation",
    ):
        assert any(check in c for c in verdict.checks), verdict.checks


def test_vector_scope_widened_rejected():
    _, jwk = make_key()
    parent = root_body(jwk, scopeSchema=_PARENT_SCOPE)
    child = dict(parent)
    child["scopeSchema"] = {
        "allowedActions": _PARENT_SCOPE["allowedActions"]
        + [{"operation": "send", "resource": "email/*"}],
        "deniedActions": list(_PARENT_SCOPE["deniedActions"]),
    }
    expect_error(lambda: nelson14.check_attenuation(parent, child), "SCOPE_WIDENED")


def test_vector_equal_scope_rejected_delegation_must_narrow():
    _, jwk = make_key()
    parent = root_body(jwk, scopeSchema=_PARENT_SCOPE)
    expect_error(lambda: nelson14.check_attenuation(parent, dict(parent)), "NARROWING_REQUIRED")


def test_vector_literal_wildcard_is_not_expanded():
    """§8.5 note: read::calendar/events is NOT covered by read::calendar/*."""
    _, jwk = make_key()
    parent = root_body(
        jwk,
        scopeSchema={
            "allowedActions": [{"operation": "read", "resource": "calendar/*"}],
            "version": "1.0",
        },
    )
    child = dict(parent)
    child["scopeSchema"] = {
        "allowedActions": [{"operation": "read", "resource": "calendar/events"}],
        "version": "1.0",
    }
    expect_error(lambda: nelson14.check_attenuation(parent, child), "SCOPE_WIDENED")


def test_vector_dropped_denial_rejected_child_may_only_add():
    _, jwk = make_key()
    parent = root_body(
        jwk,
        scopeSchema={
            "allowedActions": _CHILD_SCOPE["allowedActions"],
            "deniedActions": [
                {"operation": "send", "resource": "email/*"},
                {"operation": "post", "resource": "social/*"},
            ],
        },
    )
    child = dict(parent)
    child["scopeSchema"] = {
        "allowedActions": _CHILD_SCOPE["allowedActions"],
        "deniedActions": [{"operation": "send", "resource": "email/*"}],
    }
    expect_error(lambda: nelson14.check_attenuation(parent, child), "DENIED_ACTION_DROPPED")


def test_vector_child_may_add_denials():
    _, jwk = make_key()
    parent = root_body(
        jwk,
        scopeSchema={
            "allowedActions": [
                {"operation": "read", "resource": "calendar/*"},
                {"operation": "read", "resource": "files/*"},
            ]
        },
    )
    child = dict(parent)
    child["scopeSchema"] = {
        "allowedActions": [{"operation": "read", "resource": "calendar/*"}],
        "deniedActions": [{"operation": "send", "resource": "email/*"}],
    }
    nelson14.check_attenuation(parent, child)


def test_vector_schema_parity_required():
    _, jwk = make_key()
    parent = root_body(jwk, scopeSchema=_PARENT_SCOPE)
    child = dict(parent)
    del child["scopeSchema"]
    expect_error(lambda: nelson14.check_attenuation(parent, child), "SCHEMA_PARITY")


def test_vector_text_only_scope_is_advisory():
    """§8.4: with no scopeSchema on either side there is no machine check."""
    _, jwk = make_key()
    parent = root_body(jwk)
    child = dict(parent)
    nelson14.check_attenuation(parent, child)  # passes; never presented as enforced


def test_vector_window_containment_enforced():
    _, jwk = make_key()
    parent = root_body(jwk)
    child = dict(parent)
    child["timeWindow"] = {"start": "2026-11-05T00:00:00.000Z", "end": "2026-11-07T00:00:00.000Z"}
    expect_error(lambda: nelson14._child_window_in_parent(child, parent), "WINDOW_NOT_CONTAINED")


def test_vector_unknown_parent_fails_closed():
    bundle = build_pair(child_scope=_CHILD_SCOPE)
    expect_error(
        lambda: nelson14.verify(
            bundle["child_compact"],
            key_for=lambda c: bundle["keymap"][receipt_id(c)],
            parent_lookup=lambda pid: None,
            registry=NullRegistry(),
            consumption_store=MemoryStore(),
            attachments={bundle["child_id"]: bundle["orch"]},
        ),
        "UNKNOWN_PARENT",
    )


def test_vector_missing_orchestrator_binding_fails_closed():
    bundle = build_pair(child_scope=_CHILD_SCOPE)
    expect_error(
        lambda: nelson14.verify(
            bundle["child_compact"],
            key_for=lambda c: bundle["keymap"][receipt_id(c)],
            parent_lookup=lambda pid: bundle["parent_compact"],
            registry=NullRegistry(),
            consumption_store=MemoryStore(),
            attachments=None,
        ),
        "ORCHESTRATOR_BINDING_MISSING",
    )


def test_vector_orchestrator_binding_wrong_pair_rejected():
    bundle = build_pair(child_scope=_CHILD_SCOPE)
    rogue = nelson14.sign_orchestrator_binding(
        bundle["parent_id"] + "x", bundle["child_id"], bundle["parent_pem"]
    )
    expect_error(
        lambda: nelson14.verify(
            bundle["child_compact"],
            key_for=lambda c: bundle["keymap"][receipt_id(c)],
            parent_lookup=lambda pid: bundle["parent_compact"],
            registry=NullRegistry(),
            consumption_store=MemoryStore(),
            attachments={bundle["child_id"]: rogue},
        ),
        "ORCHESTRATOR_BINDING_MISMATCH",
    )


def test_vector_orchestrator_key_must_be_the_sub_receipt_signer():
    """§4.4 (-13): the parent's key signing is NOT sufficient."""
    sub_pem, sub_jwk = make_key()
    rogue_pem, _ = make_key()
    body = root_body(sub_jwk, parentReceiptId="0" * 64)
    compact = signed_body(body, sub_pem)
    parsed = nelson14.verify_jws(compact, sub_jwk)
    rogue_binding = nelson14.sign_orchestrator_binding("0" * 64, receipt_id(compact), rogue_pem)
    expect_error(
        lambda: nelson14.verify_orchestrator_binding(rogue_binding, parsed, receipt_id(compact)),
        "SIGNATURE_INVALID",
    )
    good_binding = nelson14.sign_orchestrator_binding("0" * 64, receipt_id(compact), sub_pem)
    nelson14.verify_orchestrator_binding(good_binding, parsed, receipt_id(compact))


# ---------------------------------------------------------------------------
# §9: revocation cascade, offline fail-closed, one-time-use vectors
# ---------------------------------------------------------------------------


def test_vector_cascade_revocation_denies_descendants():
    """§9.3: revoke the parent; the child denies with ANCESTOR_REVOKED."""
    bundle = build_pair(child_scope=_CHILD_SCOPE, revoke_parent=True)
    expect_error(lambda: walk_child(bundle), "ANCESTOR_REVOKED")


def test_vector_leaf_revocation_reported_at_leaf():
    bundle = build_pair(child_scope=_CHILD_SCOPE)
    bundle["registry"].revoked[bundle["child_id"]] = {
        "reason": "misuse",
        "revokedAt": 1730000000002,
    }
    expect_error(lambda: walk_child(bundle), "RECEIPT_REVOKED")


def test_vector_uncascade_parent_revocation_cascades_through_chains():
    """A receipt revoked through ANY path still denies its children (§9.3)."""
    bundle = build_pair(child_scope=_CHILD_SCOPE)
    bundle["registry"] = RecordingRegistry()
    bundle["registry"].revoked = {bundle["parent_id"]: {}}
    expect_error(lambda: walk_child(bundle), "ANCESTOR_REVOKED")


def test_vector_offline_with_revocation_required_fails_closed():
    """§9.4: no registry + revocationRequired -> REVOCATION_CHECK_REQUIRED."""
    pem, jwk = make_key()
    compact = signed_body(root_body(jwk, revocationRequired=True), pem)
    expect_error(
        lambda: nelson14.verify(
            compact,
            key_for=lambda c: jwk,
            parent_lookup=lambda p: None,
            registry=None,
            consumption_store=MemoryStore(),
        ),
        "REVOCATION_CHECK_REQUIRED",
    )


def test_vector_offline_ancestor_revocation_required_fails_closed():
    """§9.4: an ancestor carrying the flag denies the whole subtree offline."""
    bundle = build_pair(child_scope=_CHILD_SCOPE, require_registry_on_root=True)
    expect_error(lambda: walk_child(bundle, registry=None), "ANCESTOR_REVOCATION_CHECK_REQUIRED")


def test_vector_registry_reached_but_receipt_not_checked_fails_closed():
    """§9.4: 'unknown' is never 'not revoked' when the flag demands a check."""

    class NoCheckRegistry:
        def check(self, receipt_id):
            return {"revoked": False, "checked": False}

    pem, jwk = make_key()
    compact = signed_body(root_body(jwk, revocationRequired=True), pem)
    expect_error(
        lambda: nelson14.verify(
            compact,
            key_for=lambda c: jwk,
            parent_lookup=lambda p: None,
            registry=NoCheckRegistry(),
            consumption_store=MemoryStore(),
        ),
        "REVOCATION_CHECK_REQUIRED",
    )


def test_vector_one_time_use_requires_durable_store():
    """§9.5: no consumption store is CONSUMPTION_STORE_REQUIRED (fail closed)."""
    pem, jwk = make_key()
    compact = signed_body(root_body(jwk, oneTimeUse=True), pem)
    expect_error(
        lambda: nelson14.verify(
            compact,
            key_for=lambda c: jwk,
            parent_lookup=lambda p: None,
            registry=NullRegistry(),
            consumption_store=None,
        ),
        "CONSUMPTION_STORE_REQUIRED",
    )


def test_vector_replay_after_consume_denied():
    pem, jwk = make_key()
    compact = signed_body(root_body(jwk, oneTimeUse=True), pem)
    store = MemoryStore()
    v = nelson14.verify(
        compact,
        key_for=lambda c: jwk,
        parent_lookup=lambda p: None,
        registry=NullRegistry(),
        consumption_store=store,
    )
    assert v.consume_key == receipt_id(compact)
    store.consume(v.consume_key)
    expect_error(
        lambda: nelson14.verify(
            compact,
            key_for=lambda c: jwk,
            parent_lookup=lambda p: None,
            registry=NullRegistry(),
            consumption_store=store,
        ),
        "RECEIPT_ALREADY_CONSUMED",
    )


def test_vector_nonce_scopes_the_consumption_key():
    """§9.5: 'receiptId:nonce' — the same receiptId may consume once per nonce."""
    pem, jwk = make_key()
    compact_a = signed_body(root_body(jwk, oneTimeUse=True, nonce="n1"), pem)
    compact_b = signed_body(root_body(jwk, oneTimeUse=True, nonce="n2"), pem)
    rid_a, rid_b = receipt_id(compact_a), receipt_id(compact_b)
    assert rid_a != rid_b  # distinct artifacts; nonce check verified via consume_key
    assert nelson14.consume_key(root_body(jwk, oneTimeUse=True, nonce="n1"), rid_a) == f"{rid_a}:n1"
    assert nelson14.consume_key(root_body(jwk, oneTimeUse=True), rid_a) == rid_a


def test_vector_denied_receipt_never_burns_a_consumption_slot():
    """§9.5: consumption is attempted only AFTER every other check passes."""
    pem, jwk = make_key()
    compact = signed_body(root_body(jwk, oneTimeUse=True, revocationRequired=True), pem)
    store = MemoryStore()
    expect_error(
        lambda: nelson14.verify(
            compact,
            key_for=lambda c: jwk,
            parent_lookup=lambda p: None,
            registry=None,
            consumption_store=store,
        ),
        "REVOCATION_CHECK_REQUIRED",
    )
    assert store.slots == set()  # the slot was not burned


def test_vector_depth_limit_enforced():
    pems, compacts, ids, bodies = [], [], [], []
    for depth in range(3):
        pem, jwk = make_key()
        if depth == 0:
            body = root_body(jwk, revocationRequired=False)
        else:
            body = root_body(jwk, parentReceiptId=ids[-1], revocationRequired=False)
        compact = nelson14.issue_receipt(body, pem, kid=f"d{depth}")
        pems.append(pem)
        compacts.append(compact)
        bodies.append(body)
        ids.append(receipt_id(compact))
    # wire parents, orchestrator bindings, and keys
    bindings = {}
    for depth in range(1, 3):
        # §4.4: binding signer = the sub-receipt's own signerPublicKey holder
        bindings[ids[depth]] = nelson14.sign_orchestrator_binding(
            ids[depth - 1], ids[depth], pems[depth]
        )
    keys = {}
    for depth in range(3):
        nums = serialization.load_pem_private_key(pems[depth], password=None)
        pub = nums.public_key().public_numbers()
        keys[ids[depth]] = {
            "kty": "EC",
            "crv": "P-256",
            "x": nelson14._b64u(pub.x.to_bytes(32, "big")),
            "y": nelson14._b64u(pub.y.to_bytes(32, "big")),
        }

    # each body must carry the signer's own JWK — re-issue child bodies with it
    def verify_at(depth):
        if depth == 0:
            return nelson14.verify(
                compacts[0],
                key_for=lambda c: keys[ids[0]],
                parent_lookup=lambda p: None,
                registry=NullRegistry(),
                consumption_store=MemoryStore(),
            )
        return nelson14.verify(
            compacts[depth],
            key_for=lambda c: keys[receipt_id(c)],
            parent_lookup=lambda pid: compacts[ids.index(pid)] if pid in ids else None,
            registry=NullRegistry(),
            consumption_store=MemoryStore(),
            attachments=dict(bindings),
        )

    verdict_1 = verify_at(1)
    assert verdict_1.receipt_id == ids[1]
    # third level would make the walked depth reach the maximum (§8.6)
    pem3, jwk3 = make_key()
    body3 = root_body(jwk3, parentReceiptId=ids[2], revocationRequired=False)
    compact3 = nelson14.issue_receipt(body3, pem3, kid="d3")
    ids3 = receipt_id(compact3)
    keymap3 = {
        **keys,
        ids3: {"kty": "EC", "crv": "P-256", "x": _pub_jwk(pem3)["x"], "y": _pub_jwk(pem3)["y"]},
    }
    bindings3 = {**bindings, ids3: nelson14.sign_orchestrator_binding(ids[2], ids3, pem3)}
    expect_error(
        lambda: nelson14.verify(
            compact3,
            key_for=lambda c: keymap3[receipt_id(c)],
            parent_lookup={ids[0]: compacts[0], ids[1]: compacts[1], ids[2]: compacts[2]}.get,
            registry=NullRegistry(),
            consumption_store=MemoryStore(),
            attachments=bindings3,
        ),
        "CHAIN_DEPTH_EXCEEDED",
    )


def _pub_jwk(priv_pem):
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    pub = priv.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": nelson14._b64u(pub.x.to_bytes(32, "big")),
        "y": nelson14._b64u(pub.y.to_bytes(32, "big")),
    }


def test_vector_verify_ignores_undelivered_binding_values():
    """Binding material inside a signed body would be unknown field material."""
    _, jwk = make_key()
    body = root_body(jwk, orchestratorSignature="x.y.z")
    expect_error(lambda: nelson14.validate_body(body), "UNKNOWN_BODY_FIELD")


# ---------------------------------------------------------------------------
# Corpus publication
# ---------------------------------------------------------------------------


def test_corpus_publishes_vectors_for_n10():
    """The JSON corpus exists, parses, and covers every normative check class."""
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    assert corpus["meta"]["profile"] == "python"
    assert corpus["meta"]["draft"] == "draft-nelson-agent-delegation-receipts-14"
    assert (
        corpus["meta"]["draft_cose_profile"] == nelson14.COSE_PROFILE_STATUS == "UNIMPLEMENTED-PH"
    )
    classes = {v["class"] for v in corpus["vectors"]}
    for required in (
        "valid",
        "unknown_body_field",
        "alg_prohibited",
        "der_signature",
        "non_canonical_payload",
        "instructions_hash_mismatch",
        "scope_widened",
        "narrowing_required",
        "denied_action_dropped",
        "schema_parity",
        "window_not_contained",
        "chain_depth",
        "cascade_revocation",
        "revocation_required",
        "consumption",
        "replay_after_consume",
        "consumption_not_burned_on_deny",
    ):
        assert required in classes, f"corpus missing vector class {required}"


def test_corpus_vectors_are_valid_bodies():
    """Every 'valid' vector body in the corpus validates structurally."""
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    for vector in corpus["vectors"]:
        if vector["class"] == "valid":
            for body in vector.get("bodies", []):
                nelson14.validate_body(body)


def test_corpus_bodies_embed_signer_jwks_deterministically():
    """Corpus bodies use a fixed P-256 vector key so bodies are reproducible."""
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    assert corpus["meta"]["signer_keys"]["root"]["kty"] == "EC"
    assert corpus["meta"]["signer_keys"]["root"]["crv"] == "P-256"
