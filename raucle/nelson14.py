"""Nelson-14 delegation-receipt verifier (Python profile).

Implements the normative checks of ``draft-nelson-agent-delegation-receipts-14``
(Nelson, 15 October 2026) as a self-contained, additive module. This is a
PROFILE implementation: it implements the semantics the draft defines, makes no
compliance claim, and does not add a receipt schema to the rest of raucle —
existing receipt payloads are untouched.

Draft sections implemented here (all failures are named, fail-closed):

- §4.1  closed top-level body field set; ``metadata`` is the only extension
        point; unknown top-level body fields are rejected (UNKNOWN_BODY_FIELD).
- §4.2/§4.3  required/optional field validation; ``instructionsHash`` is
        SHA-256 over the §4.2 normalisation of ``operatorInstructions``.
- §5    signing input is the RFC 8785 (JCS) canonical form of the body. Object
        keys are ordered by UTF-16 code unit via the shared Raucle canonical
        JSON machinery (``raucle._canon``) — composed with it, not
        reimplemented. Numbers are restricted to integers: the §4 body carries
        none beyond counts and the IEEE 754 shortest-round-trip form is out of
        this profile's scope.
- §6.1/§6.3/§6.5  JWS Compact serialization pinned: ``alg`` MUST be ES256
        (``none`` is PROHIBITED, RS256/PS256 are not accepted by this
        profile); signatures are the raw ``R||S`` 64-byte form, DER encoded
        signatures are rejected; ``typ`` MUST be ``drp-receipt`` (this profile
        pins the draft's SHOULD); ``kid`` MAY be present; undefined header
        parameters are rejected except ``crit`` handling deferred to callers.
- §6.6  ``receiptId`` = lowercase hex SHA-256 of the ASCII compact JWS bytes.
- §8.5  attenuation: on literal ``operation::resource`` keys a child's
        allowed actions MUST be a strict proper subset of its parent's, and
        the parent's ``deniedActions`` must all be carried (children may add
        denials, never drop them). Delegated grants may only NARROW. Composes
        with raucle's own capability-narrowing machinery (``raucle.capability``
        chain digests); this is the draft's literal-key rule for delegated
        receipts.
- §8.6  chain depth limit (default 3; CHAIN_DEPTH_EXCEEDED when the walked
        depth would reach the maximum).
- §8.7  sub-receipt checks: parent signature, ``orchestratorSignature`` over
        the exact binding string
        ``orchestrator-delegation:<parentReceiptId>:<receiptId>`` verified
        against the SUB-receipt's ``signerPublicKey``, child window contained
        in parent window, schema parity across hops.
- §9.3  cascade revocation: the verifier walks every ancestor via
        ``parentReceiptId`` and consults the registry for each; any revoked
        ancestor denies the child (ANCESTOR_REVOKED).
- §9.4  offline fail-closed: ``revocationRequired`` with no registry denies
        (REVOCATION_CHECK_REQUIRED / ANCESTOR_REVOCATION_CHECK_REQUIRED).
- §9.5  one-time-use: requires a durable shared consumption store, else
        CONSUMPTION_STORE_REQUIRED (fail closed); already-consumed receipts
        deny with RECEIPT_ALREADY_CONSUMED; consumption is only attempted
        after every other check has passed, so no slot is burned on a receipt
        denied for another reason (the verdict carries the key to claim).
- §7    COSE profile: named UNIMPLEMENTED-PH stub, see
        ``COSE_PROFILE_STATUS``.

Test vectors: ``docs/spec/nelson14-delegation-gate/v1/test-vectors.json``
(machine-readable corpus for N10) and ``tests/nelson14_vectors.py``
(executable form asserting the corpus).
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from ._canon import reorder_keys_utf16

__all__ = [
    "COSE_PROFILE_STATUS",
    "ChainVerdict",
    "ConsumptionStore",
    "Nelson14Error",
    "RevocationRegistry",
    "canonicalise_body",
    "check_attenuation",
    "check_instructions",
    "compute_receipt_id",
    "consume_key",
    "issue_receipt",
    "normalise_instructions",
    "orchestrator_binding",
    "sign_orchestrator_binding",
    "validate_body",
    "verify",
    "verify_jws",
    "verify_orchestrator_binding",
]

#: §7 follow-up stub — the COSE_Sign1 profile is deliberately not implemented
#: here. The name is machine-greppable for the corpus and the spec document.
COSE_PROFILE_STATUS = "UNIMPLEMENTED-PH"

_ALG_REQUIRED = "ES256"
_HEADER_ALLOWED = {"alg", "typ", "kid", "crit"}


class Nelson14Error(ValueError):
    """A named, draft-sourced verification failure (§10 gate style)."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64d(seg: str) -> bytes:
    pad = (4 - len(seg) % 4) % 4
    return base64.urlsafe_b64decode(seg + "=" * pad)


# --------------------------------------------------------------------------
# §5 canonicalisation (JCS, integers only)
# --------------------------------------------------------------------------


def canonicalise_body(obj: Any) -> str:
    """JCS (RFC 8785) canonical form restricted to §4 body shapes.

    UTF-16 code-unit key order via ``raucle._canon`` (shared machinery),
    no insignificant whitespace, ``ensure_ascii=False`` per JCS §3.2.2.2
    serialization of strings. Integers only — JCS shortest-round-trip number
    serialisation is out of profile scope and refusal keeps the failure named.
    """
    if obj is None or isinstance(obj, bool):
        return json.dumps(obj)
    if isinstance(obj, float):
        raise Nelson14Error("NON_INTEGER_NUMBER", "JCS number form out of this profile's scope")
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, int):
        return json.dumps(obj)
    if isinstance(obj, list):
        return "[" + ",".join(canonicalise_body(v) for v in obj) + "]"
    if isinstance(obj, dict):
        return "{" + ",".join(
            f"{json.dumps(k, ensure_ascii=False)}:{canonicalise_body(v)}"
            for k, v in reorder_keys_utf16(obj).items()
        ) + "}"
    raise Nelson14Error("UNSUPPORTED_VALUE_TYPE", type(obj).__name__)


# --------------------------------------------------------------------------
# §4.1/§4.2/§4.3 body validation
# --------------------------------------------------------------------------

_REQUIRED_FIELDS = (
    "delegationId", "issuedAt", "scope", "boundaries", "timeWindow",
    "operatorInstructions", "instructionsHash", "signerPublicKey",
)
_OPTIONAL_FIELDS = (
    "agentId", "metadata", "toolSchemaHash", "trustedSources", "toolOutputHash",
    "programHash", "revocationRequired", "oneTimeUse", "parentReceiptId",
    "authorityStateCommitment", "reauthPolicy", "scopeSchema", "nonce",
)
_STRING_FIELDS = (
    "delegationId", "issuedAt", "scope", "boundaries", "agentId",
    "toolSchemaHash", "toolOutputHash", "programHash", "authorityStateCommitment",
    "parentReceiptId", "nonce", "instructionsHash", "operatorInstructions",
)
_HEX64 = set("0123456789abcdef")
_JWK_MEMBERS = {"kty", "crv", "x", "y"}
_HEX64_FIELDS = ("toolSchemaHash", "toolOutputHash", "programHash",
                 "authorityStateCommitment")


def _is_hex64(v: Any, name: str) -> None:
    if not (isinstance(v, str) and len(v) == 64 and set(v) <= _HEX64):
        raise Nelson14Error("BAD_FIELD_VALUE", f"{name} is not a lowercase 64-hex digest")


def validate_body(body: Any) -> dict:
    """§4.1/§4.2/§4.3 structural validation of a receipt body."""
    if not isinstance(body, dict):
        raise Nelson14Error("BAD_BODY_TYPE", "receipt body must be a JSON object")
    missing = [n for n in _REQUIRED_FIELDS if n not in body]
    if missing:
        raise Nelson14Error("MISSING_REQUIRED_FIELD", ",".join(missing))
    unknown = sorted(set(body) - set(_REQUIRED_FIELDS) - set(_OPTIONAL_FIELDS))
    if unknown:  # §4.1: verifiers MUST reject, never silently ignore
        raise Nelson14Error("UNKNOWN_BODY_FIELD", ",".join(unknown))
    for name in _STRING_FIELDS:
        if name in body and not isinstance(body[name], str):
            raise Nelson14Error("BAD_FIELD_TYPE", name)
    for name in _HEX64_FIELDS:
        if name in body:
            _is_hex64(body[name], name)
    for name in ("revocationRequired", "oneTimeUse"):
        if name in body and not isinstance(body[name], bool):
            raise Nelson14Error("BAD_FIELD_TYPE", name)
    tw = body["timeWindow"]
    if not (isinstance(tw, dict) and isinstance(tw.get("start"), str)
            and isinstance(tw.get("end"), str) and set(tw) == {"start", "end"}):
        raise Nelson14Error("BAD_FIELD_TYPE",
                            "timeWindow must be an object with exactly start and end")
    _is_hex64(body["instructionsHash"], "instructionsHash")
    jwk = body["signerPublicKey"]
    if not (isinstance(jwk, dict) and jwk.get("kty") == "EC" and jwk.get("crv") == "P-256"
            and isinstance(jwk.get("x"), str) and isinstance(jwk.get("y"), str)
            and set(jwk) <= _JWK_MEMBERS):
        raise Nelson14Error("BAD_FIELD_VALUE",
                            "signerPublicKey must be an EC P-256 JWK with exactly kty/crv/x/y")
    if "metadata" in body and not isinstance(body["metadata"], dict):
        raise Nelson14Error("BAD_FIELD_TYPE", "metadata must be an object (§4.1 extension point)")
    if "trustedSources" in body:
        ts = body["trustedSources"]
        if not (isinstance(ts, list) and all(isinstance(v, str) for v in ts)):
            raise Nelson14Error("BAD_FIELD_TYPE", "trustedSources must be an array of string")
    if "scopeSchema" in body:
        ss = body["scopeSchema"]
        if not (isinstance(ss, dict) and isinstance(ss.get("allowedActions"), list)):
            raise Nelson14Error("BAD_FIELD_TYPE", "scopeSchema.allowedActions must be an array")
        for entry in ss.get("allowedActions", []) + ss.get("deniedActions", []):
            if not (isinstance(entry, dict) and isinstance(entry.get("operation"), str)
                    and isinstance(entry.get("resource"), str)):
                raise Nelson14Error("BAD_FIELD_TYPE",
                                    "allowedActions/deniedActions entry needs "
                                    "operation and resource strings")
    return body


def normalise_instructions(text: str) -> str:
    """§4.2 normalisation: trim, lowercase, collapse whitespace, remove
    commas, sentence-final periods and straight/curly quotes."""
    out = " ".join(text.split()).lower()
    for ch in (",", ".", "\u201c", "\u201d", '"', "'"):
        out = out.replace(ch, "")
    return out


def check_instructions(body: dict) -> None:
    """§4.2: recompute ``instructionsHash`` from the claimed instructions."""
    expected = hashlib.sha256(
        normalise_instructions(body["operatorInstructions"]).encode("utf-8")
    ).hexdigest()
    if expected != body["instructionsHash"]:
        raise Nelson14Error("INSTRUCTIONS_HASH_MISMATCH")


# --------------------------------------------------------------------------
# §6 JWS profile (compact, ES256, raw R||S)
# --------------------------------------------------------------------------


def parse_jws(compact: str) -> tuple[dict, bytes, bytes]:
    """Decode a compact JWS into (protected header, payload, signature)."""
    parts = compact.split(".")
    if len(parts) != 3 or not all(parts):
        raise Nelson14Error("BAD_JWS_FORMAT",
                            "compact serialization must have exactly three non-empty segments")
    header = json.loads(_b64d(parts[0]))
    if not isinstance(header, dict):
        raise Nelson14Error("BAD_HEADER", "protected header must be an object")
    return header, _b64d(parts[1]), _b64d(parts[2])


def _signing_input(compact: str) -> bytes:
    return compact.rsplit(".", 1)[0].encode("ascii")


def verify_jws(compact: str, jwk: dict) -> dict:
    """§6.1/§6.3/§6.5 — verify one compact JWS and return its validated body.

    §5 is enforced exactly: the payload bytes must BE the JCS form of the
    recognised body; a receipt whose bytes do not match the canonical form of
    its recognised fields is rejected (NON_CANONICAL_PAYLOAD).
    """
    header, payload, signature = parse_jws(compact)
    alg = header.get("alg")
    if alg is None:
        raise Nelson14Error("BAD_HEADER", "alg is required")
    if "b64" in header:
        raise Nelson14Error("DETACHED_NOT_SUPPORTED", "this profile pins the compact serialization")
    if alg == "none":
        raise Nelson14Error("ALG_PROHIBITED", "unsecured JWS is prohibited (§6.5)")
    if alg != _ALG_REQUIRED:
        raise Nelson14Error("ALG_NOT_IN_PROFILE", str(alg))
    if header.get("typ") != "drp-receipt":
        raise Nelson14Error("TYP_MISMATCH", str(header.get("typ")))
    extra = sorted(set(header) - _HEADER_ALLOWED)
    if extra:
        raise Nelson14Error("BAD_HEADER", "undefined header parameters: " + ",".join(extra))
    try:
        body = json.loads(payload)
    except json.JSONDecodeError as e:
        raise Nelson14Error("BAD_PAYLOAD", f"payload is not JSON: {e}") from e
    validate_body(body)
    if canonicalise_body(body) != payload.decode("utf-8"):
        raise Nelson14Error("NON_CANONICAL_PAYLOAD",
                            "signing input must be the exact JCS form (§5)")
    _es256_verify(jwk, _signing_input(compact), signature)
    return body


def _es256_verify(jwk: dict, signing_input: bytes, signature: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    if len(signature) != 64:
        code = "DER_SIGNATURE_REJECTED" if _looks_der(signature) else "BAD_SIGNATURE_LENGTH"
        raise Nelson14Error(code, "P-256 JWS signatures are the raw R||S form (§6.3)")
    x = int.from_bytes(_b64d(jwk["x"]), "big")
    y = int.from_bytes(_b64d(jwk["y"]), "big")
    pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"),
                               int.from_bytes(signature[32:], "big"))
    try:
        pub.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Nelson14Error("SIGNATURE_INVALID") from None
    except ValueError as e:
        # malformed R/S coordinates (e.g. not on the curve)
        raise Nelson14Error("SIGNATURE_INVALID", str(e)) from None


def _looks_der(sig: bytes) -> bool:
    return len(sig) > 8 and sig[0] == 0x30 and sig[2] in (0x02, 0x03)


def compute_receipt_id(compact: str) -> str:
    """§6.6 — lowercase hex SHA-256 of the compact serialization's ASCII bytes."""
    return hashlib.sha256(compact.encode("ascii")).hexdigest()


def jwk_to_pem(jwk: dict) -> bytes:
    """Serialise a P-256 JWK to PEM (for tests and deployments bridging raucle keys)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    x = int.from_bytes(_b64d(jwk["x"]), "big")
    y = int.from_bytes(_b64d(jwk["y"]), "big")
    pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    return pub.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


# --------------------------------------------------------------------------
# Issuance (§10 computation order: body → sign → compact → receiptId)
# --------------------------------------------------------------------------


def _es256_sign(priv_pem: bytes, signing_input: bytes) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    key = serialization.load_pem_private_key(priv_pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise ValueError("signature issuance in this profile is P-256 (ES256)")
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return _b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def issue_receipt(body: dict, signer_priv_pem: bytes, *, kid: str = "nelson14") -> str:
    """Issue a receipt (§10 computation order): validate the body, JCS-\
canonicalise and sign, assemble the compact serialization — the receiptId
    follows from the bytes, and no step consumes a later value.

    For sub-receipts add ``parentReceiptId`` to the body and attach the
    ``orchestratorSignature`` afterwards via :func:`sign_orchestrator_binding`
    (the binding is computed over the child's receiptId, which only exists
    after this step completes).
    """
    validate_body(body)
    check_instructions(body)
    return compact_from_body(body, signer_priv_pem, kid=kid)


def compact_from_body(body: dict, signer_priv_pem: bytes, *, kid: str) -> str:
    """Assemble the compact JWS for an already-validated body."""
    header = {"alg": "ES256", "typ": "drp-receipt", "kid": kid}
    input_ = f"{_b64u(json.dumps(header).encode()):s}." \
             f"{_b64u(canonicalise_body(body).encode('utf-8')):s}"
    return input_ + "." + _es256_sign(signer_priv_pem, input_.encode("ascii"))


# --------------------------------------------------------------------------
# §4.4 orchestrator binding (attached value; never signed-body material)
# --------------------------------------------------------------------------


def orchestrator_binding(parent_receipt_id: str, receipt_id: str) -> str:
    """The exact ASCII binding string from §4.4."""
    return f"orchestrator-delegation:{parent_receipt_id}:{receipt_id}"


def sign_orchestrator_binding(parent_receipt_id: str, receipt_id: str,
                              orchestrator_priv_pem: bytes) -> str:
    """Produce the attached ``orchestratorSignature`` JWS for a sub-receipt.

    §8.7 step 4: the binding is signed only after the child receiptId exists;
    §4.4: the sub-receipt's own key signs (the orchestrator holds the parent).
    """
    payload = orchestrator_binding(parent_receipt_id, receipt_id)
    header = {"alg": "ES256", "typ": "drp-receipt"}
    input_ = f"{_b64u(json.dumps(header).encode()):s}.{_b64u(payload.encode('utf-8')):s}"
    return input_ + "." + _es256_sign(orchestrator_priv_pem, input_.encode("ascii"))


def verify_orchestrator_binding(orchestrator_signature: str, sub_body: dict,
                                receipt_id: str) -> None:
    """§8.7/§4.4: the binding must verify against the SUB-receipt's key."""
    header, payload, signature = parse_jws(orchestrator_signature)
    if header.get("alg") != _ALG_REQUIRED or header.get("typ") != "drp-receipt":
        raise Nelson14Error("ORCHESTRATOR_BAD_HEADER")
    expected = orchestrator_binding(sub_body.get("parentReceiptId", ""), receipt_id)
    if payload != expected.encode("utf-8"):
        raise Nelson14Error("ORCHESTRATOR_BINDING_MISMATCH")
    _es256_verify(sub_body["signerPublicKey"],
                  orchestrator_signature.rsplit(".", 1)[0].encode("ascii"), signature)


# --------------------------------------------------------------------------
# §8.5 monotonic narrowing (attenuation) — literal operation::resource keys
# --------------------------------------------------------------------------


def _scope_key(entry: dict) -> str:
    return f"{entry['operation']}::{entry['resource']}"


def check_attenuation(parent: dict, child: dict, *, strict: bool = True) -> None:
    """§8.5: a delegated grant may only NARROW.

    Literal keys only; wildcard patterns compare as literal strings, never
    expanded (§8.5 note). ``strict`` is the issuance-time rule (child MUST
    have strictly fewer allowedActions); the verifier walk uses the same
    strictness. Composes with, and is kept distinct from, raucle's capability
    chain machinery: no silent reimplementation of that narrowing.
    """
    ps = parent.get("scopeSchema")
    cs = child.get("scopeSchema")
    if (ps is None) != (cs is None):
        raise Nelson14Error("SCHEMA_PARITY",
                            "a sub-receipt carries scopeSchema only when the parent does (§8.7)")
    if ps is None:
        return  # §8.4: text scope is advisory only; nothing machine-checked
    parent_keys = {_scope_key(e) for e in ps["allowedActions"]}
    child_keys = {_scope_key(e) for e in cs["allowedActions"]}
    # §8.5 rule 3 first: a child MUST NOT drop any parent denial
    dropped = {_scope_key(e) for e in ps.get("deniedActions", [])} - \
        {_scope_key(e) for e in cs.get("deniedActions", [])}
    if dropped:
        raise Nelson14Error("DENIED_ACTION_DROPPED", ",".join(sorted(dropped)))
    widened = child_keys - parent_keys
    if widened:
        raise Nelson14Error("SCOPE_WIDENED", ",".join(sorted(widened)))
    if strict and len(child_keys) >= len(parent_keys):
        raise Nelson14Error("NARROWING_REQUIRED",
                            "delegation MUST narrow: equal scope is rejected (§8.5 rule 2)")


# ---------------------------------------------------------------------------
# §9.3/§9.4/§9.5 stores
# ---------------------------------------------------------------------------


class RevocationRegistry(Protocol):
    """§9.1 registry surface: ``check(receiptId)`` → mapping with ``revoked``."""

    def check(self, receipt_id: str) -> dict: ...


class ConsumptionStore(Protocol):
    """§9.5 durable shared store (durable = not per-instance or in-memory)."""

    def was_consumed(self, key: str) -> bool: ...

    def consume(self, key: str) -> bool: ...


def consume_key(receipt: dict, receipt_id: str) -> str:
    """§9.5: ``receiptId``, or ``receiptId:nonce`` when a nonce is carried."""
    nonce = receipt.get("nonce")
    return f"{receipt_id}:{nonce}" if nonce else receipt_id


def _child_window_in_parent(child: dict, parent: dict) -> None:
    if not (parent["timeWindow"]["start"] <= child["timeWindow"]["start"]
            and parent["timeWindow"]["end"] >= child["timeWindow"]["end"]):
        raise Nelson14Error("WINDOW_NOT_CONTAINED",
                            "child timeWindow must be inside the parent window (§4.2)")


@dataclass
class ChainVerdict:
    """Outcome of a chain walk.

    ``consume_key`` is set only when the leaf carries ``oneTimeUse`` and every
    other check has passed — the caller claims the slot atomically now; a
    denial for any other reason never burns a slot (§9.5).
    """

    receipt_id: str
    checks: list[str] = field(default_factory=list)
    consume_key: str | None = None


def verify(
    compact: str,
    *,
    key_for: Callable[[str], dict],
    parent_lookup: Callable[[str], str | None],
    registry: RevocationRegistry | None,
    consumption_store: ConsumptionStore | None,
    attachments: dict[str, str] | None = None,
    max_depth: int = 3,
) -> ChainVerdict:
    """Walk one receipt plus its ancestry with every §8.7/§9 check applied.

    ``key_for(compact)`` supplies the verifying JWK for each receipt artifact
    (deployments pin keys; the body's ``signerPublicKey`` is cross-checked by
    the caller's resolver). ``parent_lookup`` maps a ``parentReceiptId`` to
    the parent's compact JWS, ``None`` if unknown. ``attachments`` carries the
    ``orchestratorSignature`` JWS of any sub-receipt key (the binding is an
    attached value, never body material); a sub-receipt without one fails
    closed.
    """
    checks: list[str] = []
    current = compact
    current_id = compute_receipt_id(compact)
    chain: list[tuple[dict, str]] = []
    depth = 0
    while True:
        body = verify_jws(current, key_for(current))
        checks.append(f"signature:{current_id[:12]}")
        check_instructions(body)
        checks.append("instructions_hash")
        chain.append((body, current_id))
        parent_id = body.get("parentReceiptId")
        if parent_id is None:
            break
        if depth + 1 >= max_depth:
            raise Nelson14Error("CHAIN_DEPTH_EXCEEDED",
                                f"walked depth {depth + 1} has reached the configured maximum "
                                f"{max_depth} (§8.6)")
        parent_compact = parent_lookup(parent_id)
        if parent_compact is None:
            raise Nelson14Error("UNKNOWN_PARENT", parent_id)
        parent = verify_jws(parent_compact, key_for(parent_compact))
        checks.append(f"parent_signature:{parent_id[:12]}")
        _child_window_in_parent(body, parent)
        checks.append("window_containment")
        check_attenuation(parent, body)
        checks.append("attenuation")
        orch = ((attachments or {}).get(current_id)
                or (attachments or {}).get(parent_id))
        if orch is None:
            raise Nelson14Error("ORCHESTRATOR_BINDING_MISSING",
                                "the binding is an attached value; sub-receipt checks "
                                "fail closed without it")
        verify_orchestrator_binding(orch, body, current_id)
        checks.append("orchestrator_binding")
        current = parent_compact
        current_id = parent_id
        depth += 1
    # §9.3 / §9.4 cascade revocation and fail-closed offline behaviour
    for body, rid in chain:
        required = body.get("revocationRequired", False)
        leaf = rid == chain[0][1]
        if registry is None:
            if required:
                raise Nelson14Error(
                    "REVOCATION_CHECK_REQUIRED" if leaf
                else "ANCESTOR_REVOCATION_CHECK_REQUIRED", rid)
            continue
        state = registry.check(rid)
        if state.get("revoked"):
            raise Nelson14Error("RECEIPT_REVOKED" if leaf else "ANCESTOR_REVOKED", rid)
        if required and not state.get("checked"):
            raise Nelson14Error(
                "REVOCATION_CHECK_REQUIRED" if leaf else "ANCESTOR_REVOCATION_CHECK_REQUIRED", rid)
    checks.append("cascade_revocation")
    # §9.5 last of all — a denial for any other reason never burns a slot
    leaf_body, leaf_id = chain[0]
    if leaf_body.get("oneTimeUse"):
        if consumption_store is None:
            raise Nelson14Error("CONSUMPTION_STORE_REQUIRED",
                                "oneTimeUse requires a durable shared consumption store (§9.5)")
        key = consume_key(leaf_body, leaf_id)
        if consumption_store.was_consumed(key):
            raise Nelson14Error("RECEIPT_ALREADY_CONSUMED", key)
        return ChainVerdict(receipt_id=leaf_id, checks=checks, consume_key=key)
    return ChainVerdict(receipt_id=leaf_id, checks=checks)
