"""EP-AEC (Authorization Evidence Chain) verifier for OTHER implementers' chains.

Implements verification of chains composed per
``draft-schrock-ep-authorization-evidence-chain-00``:

  * Section 3 — the chain object: ``@version`` (``EP-AEC-v1``), ``action``,
    optional ``action_digest``, non-empty ``components`` (each ``type``,
    ``evidence``, optional ``label``), and a Boolean ``requirement``.
  * Section 4 — the fail-closed verification algorithm: malformed chains,
    digest mismatches, unregistered component types, verification
    exceptions and evaluation errors all yield DENY, never an exception
    escaping to the caller.
  * Section 5 — the bounded requirement-expression parser: AND/OR over
    identifiers and parentheses, left-associative, no general-purpose
    evaluator; unknown identifiers evaluate false.

Composition discipline: this module does not reimplement JWS or
canonical-JSON verification.  Signature checks reuse
``raucle.nelson14`` (parse_jws / verify_jws / ES256 machinery) and
canonicalisation reuses ``raucle._canon`` + ``raucle.nelson14.canonicalise_body``
(the shared RFC 8785 JCS profile).  No compliance claims are made here;
see docs/spec/epaec-verifier-v1.md for the check-to-draft-section mapping.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from raucle._canon import reject_lone_surrogates, reorder_keys_utf16
from raucle.nelson14 import (
    Nelson14Error,
    _b64d,
    _b64u,
    _es256_sign,
    _es256_verify,
    canonicalise_body,
    parse_jws,
    verify_jws,
)

__all__ = [
    "AEC_VERSION",
    "AecResult",
    "AecError",
    "canonical_action_digest",
    "verify_chain",
    "make_receipt_verifier",
    "sign_receipt_jws",
    "result_bytes",
]

AEC_VERSION = "EP-AEC-v1"

VERIFIED = "VALID"
INVALID = "INVALID"
UNVERIFIED = "UNVERIFIED"

PASS = "PASS"
FAIL = "FAIL"

_ALLOW = "ALLOW"
_DENY = "DENY"

# Section 5 bounded-parser limits.  A requirement longer or nested deeper
# than these is rejected outright, not evaluated.
_MAX_REQUIREMENT_LEN = 1024
_MAX_DEPTH = 16

_DIGEST_PREFIX = "sha256:"

# A component verifier: given the ``evidence`` object (or string), return
# ``(valid, action_digest)`` — ``action_digest`` is the digest the evidence
# binds (``None`` when it binds nothing).  Any exception is caught by the
# chain walk and fails the component (Section 4 step 5 / step 3b).
ComponentVerifier = Callable[[Any], "tuple[bool, str | None]"]


class AecError(ValueError):
    """Malformed chain or structural problem raised at parse time only.

    Inside :func:`verify_chain` structural errors are captured into the
    result (fail-closed DENY); raising is reserved for callers that parse a
    chain outside the walker.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# Canonical action digest (Section 3 / Section 4 step 2)
# --------------------------------------------------------------------------


def canonical_action_digest(action: Any) -> str:
    """Canonical action digest: sha256 over the JCS form of ``action``.

    Reuses ``raucle.nelson14.canonicalise_body`` (the shared JCS
    canonicaliser) so the digest is byte-identical with every other
    implementation of the Raucle canonical JSON profile.  Anything that is
    not a JSON object fails loudly — the chain walk treats that as DENY.
    """
    if not isinstance(action, dict):
        raise AecError("BAD_ACTION", "action must be a JSON object (Section 3)")
    try:
        canonical = canonicalise_body(action)
    except Nelson14Error as e:
        raise AecError("BAD_ACTION", f"action is not canonically representable: {e.code}") from e
    except (TypeError, ValueError) as e:
        raise AecError("BAD_ACTION", f"action is not canonically representable: {e}") from e
    return _DIGEST_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Structural validation (Section 4 step 1)
# --------------------------------------------------------------------------


def _validate_chain_components(components: Any) -> None:
    """Section 4 step 1 component checks (shared helper of :func:`validate_chain`)."""
    if not isinstance(components, list) or not components:
        raise AecError("BAD_COMPONENTS", "components must be a non-empty array")
    seen_types: set[str] = set()
    for i, comp in enumerate(components):
        if not isinstance(comp, dict):
            raise AecError("BAD_COMPONENT", f"component [{i}] must be an object")
        ctype = comp.get("type")
        if not isinstance(ctype, str) or not ctype:
            raise AecError("BAD_COMPONENT", f"component [{i}].type must be a non-empty string")
        if ctype in seen_types:
            raise AecError("DUPLICATE_COMPONENT_TYPE", ctype)
        seen_types.add(ctype)
        if "evidence" not in comp:
            raise AecError("BAD_COMPONENT", f"component [{i}] ({ctype}) has no evidence")
        if comp.get("label") is not None and not isinstance(comp.get("label"), str):
            raise AecError("BAD_COMPONENT", f"component [{i}].label must be a string")


def _validate_unknown_fields(chain: dict[str, Any]) -> None:
    """Unknown top-level fields are rejected, never silently ignored."""
    unknown = sorted(
        set(chain)
        - {"@version", "action", "action_digest", "components", "requirement"}
        - {key for key in chain if key.startswith("@")}
    )
    if unknown:
        raise AecError("UNKNOWN_CHAIN_FIELD", ",".join(unknown))


def validate_chain(chain: Any) -> dict[str, Any]:
    """Section 4 step 1 structural checks.  Raises :class:`AecError` if malformed."""
    if not isinstance(chain, dict):
        raise AecError("BAD_CHAIN_TYPE", "chain must be a JSON object")
    if chain.get("@version") != AEC_VERSION:
        raise AecError("BAD_VERSION", "@version must be exactly " + AEC_VERSION)
    if not isinstance(chain.get("action"), dict):
        raise AecError("BAD_ACTION", "action is required and must be an object")
    _validate_chain_components(chain.get("components"))
    req = chain.get("requirement")
    if not isinstance(req, str) or not req.strip():
        raise AecError("BAD_REQUIREMENT", "requirement is required and must be a non-empty string")
    _validate_unknown_fields(chain)
    return chain


# --------------------------------------------------------------------------
# Requirement expressions (Section 5)
# --------------------------------------------------------------------------


def _tokenize_requirement(text: str) -> list[str]:
    if len(text) > _MAX_REQUIREMENT_LEN:
        raise AecError("REQUIREMENT_TOO_LONG", f"{len(text)} > {_MAX_REQUIREMENT_LEN}")
    tokens: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch.isspace():
            i += 1
        elif ch in "()":
            tokens.append(ch)
            i += 1
        elif ch.isalnum() or ch in "-_.@":
            j = i
            while j < len(text) and (text[j].isalnum() or text[j] in "-_.@"):
                j += 1
            tokens.append(text[i:j])
            i = j
        else:
            raise AecError("BAD_REQUIREMENT_TOKEN", f"unexpected character {ch!r} at offset {i}")
    return tokens


def _parse_requirement(
    tokens: list[str], pos: int, depth: int, satisfied: set[str]
) -> tuple[bool, int, str | None]:
    """Recursive-descent over:

        expr := term (('AND' | 'OR') term)*
        term := '(' expr ')' | IDENT

    Left-associative flat fold of mixed AND/OR (the grammar has no
    precedence between them).  Unknown identifiers evaluate false
    (Section 5).  Returns (value, next_pos, error_code_or_None).
    """
    if depth > _MAX_DEPTH:
        return False, pos, "REQUIREMENT_DEPTH_EXCEEDED"
    term_value, pos, err = _parse_term(tokens, pos, depth, satisfied)
    if err:
        return False, pos, err
    while pos < len(tokens) and tokens[pos] in ("AND", "OR"):
        op = tokens[pos]
        pos += 1
        rhs, pos, err = _parse_term(tokens, pos, depth, satisfied)
        if err:
            return False, pos, err
        term_value = (term_value and rhs) if op == "AND" else (term_value or rhs)
    return term_value, pos, None


def _parse_term(
    tokens: list[str], pos: int, depth: int, satisfied: set[str]
) -> tuple[bool, int, str | None]:
    if pos >= len(tokens):
        return False, pos, "REQUIREMENT_PARSE_ERROR"
    tok = tokens[pos]
    if tok == "(":
        val, pos, err = _parse_requirement(tokens, pos + 1, depth + 1, satisfied)
        if err:
            return False, pos, err
        if pos >= len(tokens) or tokens[pos] != ")":
            return False, pos, "REQUIREMENT_UNBALANCED"
        return val, pos + 1, None
    if tok in ("AND", "OR", ")"):
        return False, pos, "REQUIREMENT_PARSE_ERROR"
    # IDENT: bounded parser only — no general-purpose evaluator (Section 5).
    return (tok in satisfied), pos + 1, None


def evaluate_requirement(
    requirement: str, satisfied: set[str]
) -> tuple[bool, None] | tuple[bool, str]:
    """Evaluate a requirement over the satisfied set, fail-closed.

    Returns ``(value, None)`` on success or ``(False, error_code)`` when the
    expression is unparseable / out of bounds — the caller then DENYs the
    chain with the named reason.
    """
    try:
        tokens = _tokenize_requirement(requirement)
    except AecError as e:
        return False, e.code
    if not tokens:
        return False, "REQUIREMENT_PARSE_ERROR"
    try:
        value, pos, err = _parse_requirement(tokens, 0, 0, satisfied)
    except AecError as e:  # pragma: no cover - parser signals errors via codes
        return False, e.code
    if err:
        return False, err
    if pos != len(tokens):  # leftover tokens (e.g. trailing ')')
        return False, "REQUIREMENT_UNBALANCED"
    return value, None


# --------------------------------------------------------------------------
# Reference component verifier over the JWS receipt profile
# --------------------------------------------------------------------------


def verify_receipt_jws(compact: str, jwk: dict[str, Any]) -> dict[str, Any]:
    """Verify one component-receipt compact JWS and return its validated body.

    Composition rule: the signature machinery is **not** reimplemented —
    ``drp-receipt``-typed receipts are delegated verbatim to
    ``raucle.nelson14.verify_jws`` (strict header / alg / JCS / §6 checks).
    Other receipts of this profile must still be ES256-signed with a JCS
    payload; they are verified with the same ES256 primitive
    (``raucle.nelson14``) but without the DRP body schema.  The body's
    ``actionDigest`` (``sha256:<hex>``) is the digest the receipt binds.
    """
    try:
        header, _payload_b64, _sig = parse_jws(compact)
    except Nelson14Error as e:
        raise AecError("BAD_RECEIPT_JWS", e.code) from e
    if header.get("typ") == "drp-receipt":
        try:
            return verify_jws(compact, jwk)
        except Nelson14Error as e:
            raise AecError("RECEIPT_JWS_INVALID", e.code) from e
    # Non-DRP receipt: ES256 over the compact signing input, JCS-checked.
    try:
        alg = header.get("alg")
        if alg is None:
            raise AecError("BAD_RECEIPT_JWS", "alg is required")
        if alg != "ES256":
            raise AecError("RECEIPT_ALG_NOT_IN_PROFILE", str(alg))
        parts = compact.split(".")
        if len(parts) != 3:
            raise AecError("BAD_RECEIPT_JWS", "compact serialization must have three segments")
        body_b = _b64d(parts[1])
        try:
            body = json.loads(body_b)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise AecError("BAD_RECEIPT_JWS", "payload is not JSON") from e
        if not isinstance(body, dict):
            raise AecError("BAD_RECEIPT_JWS", "payload must be a JSON object")
        if canonicalise_body(body) != body_b.decode("utf-8"):
            raise AecError("RECEIPT_NON_CANONICAL", "signing input must be the exact JCS form")
        try:
            _es256_verify(jwk, compact.rsplit(".", 1)[0].encode("ascii"), _b64d(parts[2]))
        except Nelson14Error as e:
            raise AecError("RECEIPT_JWS_INVALID", e.code) from e
    except AecError:
        raise
    except Exception as e:  # pragma: no cover - defensive
        raise AecError("BAD_RECEIPT_JWS", str(e)) from e
    return body


def sign_receipt_jws(
    body: dict[str, Any], priv_pem: bytes, *, kid: str, typ: str = "ep-aec-receipt"
) -> str:
    """Sign a component-receipt body as a compact JWS (test/issuer helper).

    The payload is the exact JCS form of ``body``; the signature is ES256
    produced by the shared ``raucle.nelson14`` primitive.
    """
    header = {"alg": "ES256", "typ": typ}
    if typ != "drp-receipt":
        header["kid"] = kid
    signing_input = _b64u(
        json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    signing_input += "." + _b64u(canonicalise_body(body).encode("utf-8"))
    sig = _es256_sign(priv_pem, signing_input.encode("ascii"))
    return signing_input + "." + sig


def _receipt_action_digest(body: dict[str, Any]) -> str | None:
    digest = body.get("actionDigest")
    if isinstance(digest, str) and digest.startswith(_DIGEST_PREFIX):
        return digest
    return None


def make_receipt_verifier(jwk_for: Callable[[str], dict[str, Any]]) -> ComponentVerifier:
    """Build a component verifier for ``ep-receipt``-style JWS evidence.

    ``jwk_for`` maps an evidence item to the trusted verifying JWK
    (relying parties pin keys explicitly — Section 7, verifier trust).
    """

    def verify(evidence: Any) -> tuple[bool, str | None]:
        if not isinstance(evidence, str):
            return False, None
        jwk = jwk_for(evidence)
        if not isinstance(jwk, dict):
            return False, None
        body = verify_receipt_jws(evidence, jwk)
        digest = _receipt_action_digest(body)
        if digest is None:
            return False, None
        return True, digest

    return verify


# --------------------------------------------------------------------------
# The chain walk (Section 4, fail-closed)
# --------------------------------------------------------------------------


@dataclass
class AecResult:
    """Deterministic verification object.

    ``components`` carries per-component ``status`` (VALID / INVALID /
    UNVERIFIED) plus a ``reason`` for anything not VALID, per draft Section 4
    ("with a reason for any failure, to support audit").  ``decision`` is the
    draft's ALLOW/DENY; ``overall`` (PASS/FAIL) is the aggregate of the walk
    (structural soundness + cryptographic validity of every evaluated
    component + requirement satisfied).  ``satisfied`` lists the type and
    label identifiers added by step 3d.
    """

    decision: str
    overall: str
    chain_digest: str
    components: list[dict[str, Any]] = field(default_factory=list)
    satisfied: list[str] = field(default_factory=list)
    requirement: str = ""
    requirement_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "overall": self.overall,
            "chain_digest": self.chain_digest,
            "requirement": self.requirement,
            "satisfied": list(self.satisfied),
            "components": [
                {
                    "index": c["index"],
                    "type": c["type"],
                    "label": c.get("label"),
                    "status": c["status"],
                    "reason": c.get("reason"),
                }
                for c in self.components
            ],
        }


def result_bytes(result: AecResult) -> bytes:
    """Deterministic byte serialization of a result (JCS key order, UTF-8)."""
    reject_lone_surrogates(json.dumps(result.to_dict(), ensure_ascii=False))
    ordered = reorder_keys_utf16(result.to_dict())
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False, sort_keys=False).encode(
        "utf-8"
    )


def _fail(
    decision_reason: str, error: str, chain_digest: str = "", requirement: str = ""
) -> AecResult:
    return AecResult(
        decision=_DENY,
        overall=FAIL,
        chain_digest=chain_digest,
        requirement=requirement,
        requirement_error=error if error != decision_reason else None,
    )


def _check_declared_digest(chain: dict[str, Any], chain_digest: str) -> AecResult | None:
    """Section 4 step 2: a present action_digest MUST equal the recomputed one.

    Returns a DENY result on mismatch/malformation, ``None`` when OK.
    """
    if "action_digest" not in chain:
        return None
    declared = chain["action_digest"]
    if not isinstance(declared, str) or not declared.startswith(_DIGEST_PREFIX):
        return _fail(
            "action_digest must be a 'sha256:<hex>' string", "BAD_ACTION_DIGEST", chain_digest
        )
    if declared != chain_digest:
        return _fail(
            "declared action_digest does not match the recomputed canonical digest",
            "ACTION_DIGEST_MISMATCH",
            chain_digest,
        )
    return None


def _walk_components(
    chain: dict[str, Any], verifiers: dict[str, ComponentVerifier], chain_digest: str
) -> tuple[set[str], list[dict[str, Any]], bool]:
    """Section 4 step 3: walk components, fail-closed per component.

    Returns ``(satisfied, component_summaries, any_invalid)``.
    """
    satisfied: set[str] = set()
    summaries: list[dict[str, Any]] = []
    any_invalid = False
    for i, comp in enumerate(chain["components"]):
        ctype = comp["type"]
        label = comp.get("label")
        status, reason, invalid = _verify_component(comp, ctype, verifiers, chain_digest)
        if status == VERIFIED:
            # Step 3d: add type (and label) to the satisfied set.
            satisfied.add(ctype)
            if isinstance(label, str) and label:
                satisfied.add(label)
        any_invalid = any_invalid or bool(invalid)
        summaries.append(
            {
                "index": i,
                "type": ctype,
                "label": label if isinstance(label, str) else None,
                "status": status,
                "reason": reason,
            }
        )
    return satisfied, summaries, any_invalid


def _verify_component(
    comp: dict[str, Any],
    ctype: str,
    verifiers: dict[str, ComponentVerifier],
    chain_digest: str,
) -> tuple[str, str | None, bool]:
    """Determine ``(status, reason, invalid)`` for a single component."""
    verifier = verifiers.get(ctype)
    if verifier is None or not callable(verifier):
        # Step 3a: no verifier registered -> unsatisfied, never assumed.
        return UNVERIFIED, "no verifier registered for type", False
    try:
        valid, bound_digest = verifier(comp["evidence"])
    except AecError as e:
        return INVALID, f"receipt rejected: {e.code}", True
    except Exception as e:  # step 3b: any exception marks unsatisfied
        return INVALID, "verifier raised: " + type(e).__name__, True
    if valid and bound_digest == chain_digest:
        return VERIFIED, None, False  # step 3c: verified AND bound
    if valid:
        return INVALID, "binds a different action", True
    return INVALID, "verifier returned invalid", True


def verify_chain(chain: Any, verifiers: dict[str, ComponentVerifier]) -> AecResult:
    """Verify an EP-AEC chain, fail-closed (draft Section 4 steps 1-5).

    ``verifiers`` maps component ``type`` to a verifier returning
    ``(valid, bound_digest)``.  Every error path returns a DENY result with a
    named reason; an unexpected exception at any step is also DENY
    (Section 4 step 5).
    """
    if not isinstance(verifiers, dict):  # defensive: bad configuration
        return _fail("bad verifier configuration", "BAD_VERIFIER_CONFIG")
    try:
        validate_chain(chain)
    except AecError as e:
        return _fail("malformed chain: " + e.detail, e.code)

    try:
        chain_digest = canonical_action_digest(chain["action"])
    except AecError as e:
        return _fail("action digest: " + e.detail, e.code)

    # Section 4 step 2: a present action_digest MUST equal the recomputed one.
    digest_fail = _check_declared_digest(chain, chain_digest)
    if digest_fail is not None:
        return digest_fail

    requirement = chain["requirement"]
    satisfied, components, any_invalid = _walk_components(chain, verifiers, chain_digest)

    # Section 4 step 4: evaluate the bounded requirement expression.
    value, req_err = evaluate_requirement(requirement, satisfied)

    decision = _ALLOW if (value and req_err is None) else _DENY
    overall = PASS if (decision == _ALLOW and not any_invalid) else FAIL
    return AecResult(
        decision=decision,
        overall=overall,
        chain_digest=chain_digest,
        components=components,
        satisfied=sorted(satisfied),
        requirement=requirement,
        requirement_error=req_err,
    )
