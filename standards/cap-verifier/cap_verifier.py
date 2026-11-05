#!/usr/bin/env python3
"""cap-verifier — minimal reference verifier for the cap:v1 profile.

A deliberately tiny, dependency-free (modulo `cryptography`) implementation of
the eight-check gate from standards/owasp-ai-exchange/01-capability-token.md.
Intended for:
  - shipping with the OWASP standards submission as proof the spec is
    implementable by anyone in ~150 lines;
  - dropping into CI pipelines as a yes/no token-validity check;
  - cross-validating the main `raucle.capability` implementation
    by an independent code path.

Usage:
    cap-verifier verify token.json --pubkey issuer.pub.pem
    cap-verifier verify token.json --pubkey issuer.pub.pem \\
        --tool transfer_funds --agent agent:billing \\
        --args call_args.json
    cap-verifier hash token.json    # print the token_id we compute

Exit codes:
    0  token verified, all checks pass
    1  token failed verification (signature, hash, time, scope, or constraints)
    2  usage / file / format error
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import re
import sys
import time
import unicodedata
from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical-JSON serialisation (mirrors §"Canonical-JSON serialisation"
# of standards/owasp-ai-exchange/01-capability-token.md).
# ---------------------------------------------------------------------------


def _utf16_key(s):
    """RFC 8785 / JCS §3.2.3 ordering: by UTF-16 code unit (UTF-16-BE byte
    comparison == unsigned-16-bit code-unit comparison). Rejects lone surrogates
    explicitly first (R8) so the constraint pre-sort fails on the clean
    ValueError, not the incidental UnicodeEncodeError from the encode."""
    _reject_lone_surrogates(s)
    return s.encode("utf-16-be")


def _value_sort_key(v):
    """Deterministic key for allow/deny list values: strings by UTF-16 code
    unit; non-strings ranked by type name then value (bool never collides with
    an equal int)."""
    if isinstance(v, str):
        _reject_lone_surrogates(v)  # R8: clean ValueError on any sort path
        return (0, "str", v.encode("utf-16-be"))
    return (1, type(v).__name__, v)


def _reorder_keys_utf16(obj):
    """Recursively reorder object keys by UTF-16 code unit, preserving arrays."""
    if isinstance(obj, dict):
        return {k: _reorder_keys_utf16(obj[k]) for k in sorted(obj, key=_utf16_key)}
    if isinstance(obj, (list, tuple)):
        return [_reorder_keys_utf16(v) for v in obj]
    return obj


def _reject_lone_surrogates(s) -> None:
    """Reject any unpaired UTF-16 surrogate (U+D800..U+DFFF) in a string or key.
    Such material cannot encode to UTF-8 and the five reference implementations
    disagree on it, so it is rejected at sign/verify (Profile R8). This mirrors
    raucle._canon.reject_lone_surrogates, inlined here so this verifier
    stays self-contained (no package import)."""
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise ValueError(
                "canonical JSON: lone surrogate "
                f"U+{ord(ch):04X} is not permitted in v1 signed/hashed material "
                "(unpaired surrogates are not cross-implementation stable)"
            )


def _reject_floats(obj) -> None:
    """Reject any float, or any string/key carrying a lone surrogate, in signed
    token material (cap:v1 numeric constraints are integer-only; Profile R8),
    mirroring raucle.capability._reject_floats. bool is an int subclass and
    is allowed. Float bounds / NaN would otherwise serialize and verify here while
    the real gate denies them."""
    if isinstance(obj, float):
        raise ValueError(
            "capability token: float numeric values are not permitted "
            "(cap:v1 constraints are integer-only)"
        )
    if isinstance(obj, str):
        _reject_lone_surrogates(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                _reject_lone_surrogates(k)
            _reject_floats(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_floats(v)


def canonical_json(obj) -> bytes:
    """Canonical JSON: object keys ordered by UTF-16 code unit (§4.3.1 / RFC
    8785), no whitespace, UTF-8, ensure_ascii=False, integer-only (floats and
    NaN/Infinity rejected). Matches the raucle capability signer so
    token_ids/signatures are byte-identical and the same material is rejected."""
    _reject_floats(obj)
    return json.dumps(
        _reorder_keys_utf16(obj),
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


# ---------------------------------------------------------------------------
# Spec validation regexes (mirrors cap:v1 §"Field semantics").
# ---------------------------------------------------------------------------


# Canonical agent_id regex (provenance spec §5 / capability AGENT-ID-REGEX): a
# dot is a hierarchy separator and MUST be followed by an alphanumeric, so a
# TRAILING dot and CONSECUTIVE dots ("..") are forbidden. A loose class like
# [a-z0-9_\-./] would admit "agent:a..evil", which can over-authorise descendants
# (a token for "agent:a" must NOT cover "agent:a..evil").
_AGENT_ID_RE = re.compile(r"^agent:[a-z0-9](?:[a-z0-9_\-]|\.(?=[a-z0-9])){0,126}[a-z0-9]?$")
_TOOL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-./]{0,127}$")


# ---------------------------------------------------------------------------
# Token body extraction.
# Excludes `token_id` and `signature` from the canonical body for hashing/sig.
# ---------------------------------------------------------------------------


_BODY_FIELDS = (
    "version",
    "agent_id",
    "tool",
    "constraints",
    "issuer",
    "key_id",
    "issued_at",
    "not_before",
    "expires_at",
    "parent_id",
    "policy_proof_hash",
    "grammar_hash",
    "policy_hash",
)


def token_body(token: dict) -> dict:
    """Build the canonical body, applying default values consistent with raucle's encoding."""
    out = {}
    # Constraints are normalised before hashing (mirrors raucle.capability._normalise_constraints).
    if "constraints" in token:
        out["constraints"] = _normalise_constraints(token["constraints"])
    for f in _BODY_FIELDS:
        if f == "constraints":
            continue
        if f == "version":
            # version is implicit in cap:v1; not part of the hashed body in the
            # reference implementation. We accept its presence but exclude it
            # from the canonical bytes for cross-implementation compatibility.
            continue
        if f in token:
            out[f] = token[f]
        else:
            # These optional fields are always present (as null when unset) in
            # Capability.body(), so they MUST be emitted as null here too or the
            # signed/hashed bytes diverge from the minting implementation.
            if f in ("parent_id", "policy_proof_hash", "grammar_hash", "policy_hash"):
                out[f] = None
    return out


def _require_int_bound(kind: str, fld: str, bound) -> None:
    """A numeric bound MUST be a non-bool int (mirrors capability._require_int_bound).
    bool is an int subclass, so True/False would otherwise pass as 1/0 bounds."""
    if isinstance(bound, bool) or not isinstance(bound, int):
        raise ValueError(
            f"{kind}[{fld!r}] bound must be an integer, got {type(bound).__name__} {bound!r}"
        )


def _require_value_list(kind: str, fld: str, v):
    """A value-set constraint MUST be a list of JSON scalars (str/int/bool) —
    not a bare string (which would sort into characters), not a float/None/
    container member. Mirrors capability._as_value_list + _require_json_scalar."""
    if not isinstance(v, list):
        raise ValueError(
            f"{kind}[{fld!r}] must be a list (JSON array), got {type(v).__name__} {v!r}"
        )
    for m in v:
        if not isinstance(m, (str, int)):  # bool is an int subclass (allowed)
            raise ValueError(f"{kind}[{fld!r}] member {m!r} is not a JSON scalar (str/int/bool)")
    return sorted(v, key=_value_sort_key)


def _field_mapping(kind: str, c: dict) -> dict:
    """Return c[kind] after asserting it is a dict whose field names are
    non-empty strings that remain DISTINCT under Unicode NFC normalisation
    (mirrors capability._validate_field_keys). A non-dict shape (e.g. a list)
    must fail closed as invalid signed material, not crash on .items()."""
    m = c[kind]
    if not isinstance(m, dict):
        raise ValueError(f"{kind} must be an object mapping field -> value, got {type(m).__name__}")
    seen: dict = {}
    for key in m:
        if not isinstance(key, str) or not key:
            raise ValueError(f"{kind} field name must be a non-empty string, got {key!r}")
        norm = unicodedata.normalize("NFC", key)
        if norm in seen and seen[norm] != key:
            raise ValueError(
                f"{kind} field names {seen[norm]!r} and {key!r} collide under Unicode NFC"
            )
        seen[norm] = key
    return m


def _normalise_constraints(c: dict) -> dict:
    """Normalisation logic mirroring raucle.capability._normalise_constraints.
    Raises ValueError on invalid signed material (unknown kinds, non-dict mappings,
    NFC-colliding field names, malformed value shapes, non-int numeric bounds) so
    verify_token DENIES (fail-closed) rather than silently accepting or crashing."""
    if not isinstance(c, dict):
        raise ValueError(f"constraints must be an object, got {type(c).__name__}")
    for kind in c:
        if kind not in _KNOWN_CONSTRAINT_KINDS:
            raise ValueError(f"unknown constraint kind {kind!r}")
    out: dict = {}
    if "forbidden_values" in c:
        m = _field_mapping("forbidden_values", c)
        out["forbidden_values"] = {
            k: _require_value_list("forbidden_values", k, v) for k, v in m.items()
        }
    if "allowed_values" in c:
        m = _field_mapping("allowed_values", c)
        out["allowed_values"] = {
            k: _require_value_list("allowed_values", k, v) for k, v in m.items()
        }
    if "starts_with" in c:
        m = _field_mapping("starts_with", c)
        for fld, prefix in m.items():
            if not isinstance(prefix, str):
                raise ValueError(
                    f"starts_with[{fld!r}] prefix must be a string, got "
                    f"{type(prefix).__name__} {prefix!r}"
                )
        out["starts_with"] = dict(m)
    if "max_value" in c:
        m = _field_mapping("max_value", c)
        for fld, bound in m.items():
            _require_int_bound("max_value", fld, bound)
        out["max_value"] = dict(m)
    if "min_value" in c:
        m = _field_mapping("min_value", c)
        for fld, bound in m.items():
            _require_int_bound("min_value", fld, bound)
        out["min_value"] = dict(m)
    if "required_present" in c:
        rp = c["required_present"]
        if not isinstance(rp, list) or not all(isinstance(x, str) and x for x in rp):
            raise ValueError("required_present must be a list of non-empty field-name strings")
        # Field names must stay distinct under NFC (mirrors capability's
        # _require_field_name_list), like the mapping-constraint keys.
        seen: dict = {}
        for name in rp:
            norm = unicodedata.normalize("NFC", name)
            if norm in seen and seen[norm] != name:
                raise ValueError(
                    f"required_present field names {seen[norm]!r} and {name!r} collide under Unicode NFC"
                )
            seen[norm] = name
        out["required_present"] = sorted(rp, key=_utf16_key)
    if "forbidden_field_combinations" in c:
        combos = c["forbidden_field_combinations"]
        if not isinstance(combos, list):
            raise ValueError("forbidden_field_combinations must be a list of field-name lists")
        for combo in combos:
            if not isinstance(combo, list) or not all(isinstance(x, str) and x for x in combo):
                raise ValueError(
                    f"forbidden_field_combinations entry {combo!r} must be a list of "
                    f"non-empty field-name strings"
                )
        out["forbidden_field_combinations"] = sorted(
            (sorted(combo, key=_utf16_key) for combo in combos),
            key=lambda combo: [_utf16_key(x) for x in combo],
        )
    return out


# ---------------------------------------------------------------------------
# Eight-check gate (mirrors cap:v1 §"Verification (gate-side)").
# ---------------------------------------------------------------------------


def verify_token(
    token: dict,
    pubkey_pem: str,
    *,
    tool: str | None = None,
    agent_id: str | None = None,
    args: dict | None = None,
    now: int | None = None,
) -> tuple[bool, str, str | None]:
    """Run the eight cap:v1 checks. Returns (allowed, reason, deny_check).

    Fail-closed wrapper: ANY unexpected error on attacker-controlled token JSON
    is converted to a DENY, so a malformed token can never crash the verifier
    (or be mistaken for an allow)."""
    try:
        return _verify_token_impl(
            token, pubkey_pem, tool=tool, agent_id=agent_id, args=args, now=now
        )
    except Exception as exc:  # noqa: BLE001 — fail-closed on any malformed input
        return False, f"malformed token: {type(exc).__name__}: {exc}", "format"


def _verify_token_impl(
    token: dict,
    pubkey_pem: str,
    *,
    tool: str | None = None,
    agent_id: str | None = None,
    args: dict | None = None,
    now: int | None = None,
) -> tuple[bool, str, str | None]:
    from cryptography.hazmat.primitives import serialization

    ts = now if now is not None else int(time.time())

    # Field-shape sanity: the body fields the gate ALWAYS signs must be present
    # with the right JSON types, else this is invalid signed material (DENY).
    if not isinstance(token, dict):
        return False, "token must be a JSON object", "format"
    # Identity fields must be NON-EMPTY strings (matches Capability.from_dict);
    # an empty string is invalid signed material, not merely a failed regex.
    for f in ("agent_id", "tool", "issuer", "key_id", "token_id"):
        if not isinstance(token.get(f), str) or not token.get(f):
            return False, f"{f} must be a non-empty string", "format"
    # signature is string-only (an empty signature is denied at the signature
    # check, not here — parity with from_dict).
    if not isinstance(token.get("signature"), str):
        return False, "signature must be a string", "format"
    for f in ("issued_at", "not_before", "expires_at"):
        if isinstance(token.get(f), bool) or not isinstance(token.get(f), int):
            return False, f"{f} must be an integer", "format"
    if token.get("parent_id") is not None and not isinstance(token["parent_id"], str):
        return False, "parent_id must be a string or null", "format"
    # The gate always signs a `constraints` object (possibly empty); a token
    # lacking it is malformed signed material.
    if not isinstance(token.get("constraints"), dict):
        return False, "constraints must be present and an object", "format"
    if not _AGENT_ID_RE.match(token["agent_id"]):
        return False, "agent_id malformed", "format"
    if not _TOOL_RE.match(token["tool"]):
        return False, "tool malformed", "format"

    # Canonicalisation rejects non-integer / non-finite numeric material (cap:v1
    # is integer-only), exactly as the minting signer does — a token carrying a
    # float/NaN bound is invalid signed material and must DENY, not crash.
    try:
        body_bytes = canonical_json(token_body(token))
    except ValueError as exc:
        return False, f"invalid signed material: {exc}", "format"

    # Check 1: issuer pinning (caller passes the pubkey explicitly here;
    # in a fuller deployment this would look up key_id in a trusted map).
    if "key_id" not in token:
        return False, "missing key_id", "issuer_pinning"

    # Check 2: signature
    try:
        pub = serialization.load_pem_public_key(pubkey_pem.encode("ascii"))
        sig = b64url_decode(token["signature"])
        pub.verify(sig, body_bytes)
    except Exception as exc:
        return False, f"signature: {exc}", "signature"

    # Check 3: token_id binding
    expected_id = "cap:" + sha256_hex(body_bytes)[:24]
    if token.get("token_id") != expected_id:
        return False, f"token_id mismatch (expected {expected_id})", "token_id_binding"

    # Check 4: time bounds
    if ts < token["not_before"]:
        return False, "not yet valid", "time_bounds"
    if ts >= token["expires_at"]:
        return False, "expired", "time_bounds"

    # Check 5: tool match
    if tool is not None and tool != token["tool"]:
        return False, f"tool mismatch (token says {token['tool']!r})", "tool_match"

    # Check 6: agent scope. The caller agent_id MUST itself be well-formed
    # (mirrors CapabilityGate, which validates the caller id before scope) so a
    # malformed id like "agent:a..evil" cannot masquerade as a sub-scope.
    if agent_id is not None:
        if not _AGENT_ID_RE.match(agent_id):
            return False, f"malformed caller agent_id {agent_id!r}", "agent_scope"
        if agent_id != token["agent_id"] and not agent_id.startswith(token["agent_id"] + "."):
            return (
                False,
                f"agent {agent_id!r} not a sub-scope of {token['agent_id']!r}",
                "agent_scope",
            )

    # Check 7 — chain resolution (fundamental, so checked before constraints).
    # This minimal verifier resolves single tokens only. A token that cites a
    # parent MUST be DENIED (fail-closed), never silently accepted: its
    # attenuation chain cannot be verified here.
    if token.get("parent_id") is not None:
        return (
            False,
            "token cites parent_id; attenuation-chain resolution is out of scope "
            "for this minimal verifier (fail-closed)",
            "chain",
        )

    # Check 8: constraints. Run regardless of args so token-level invariants
    # (e.g. an unmodelled constraint kind that survived into a signed token) are
    # enforced even on a presence-only verification; arg-dependent checks are
    # no-ops when args is None.
    reason = _check_constraints(token.get("constraints", {}), args or {})
    if reason:
        return False, f"constraint: {reason}", "constraint"

    return True, "ok", None


def _flatten_scalars(val):
    """Yield every scalar in *val*, recursing into list/tuple/set/dict (dict keys
    included). Mirrors raucle.capability._flatten_scalars so a forbidden
    value hidden inside a collection cannot slip past."""
    if isinstance(val, dict):
        for k, v in val.items():
            yield k
            yield from _flatten_scalars(v)
    elif isinstance(val, (list, tuple, set, frozenset)):
        for v in val:
            yield from _flatten_scalars(v)
    else:
        yield val


def _is_number(v) -> bool:
    """A finite, non-bool int/float. bool is excluded (subclasses int); non-finite
    floats (NaN/+inf/-inf) are rejected exactly like the gate — a NaN compares
    False to every bound and would otherwise slip past both max_value and
    min_value (GATE-NaN parity)."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    if isinstance(v, float):
        return math.isfinite(v)
    return False


# Constraint kinds the cap:v1 profile understands. Anything else MUST fail
# closed at the gate (defence in depth), mirroring CapabilityGate's registry
# guard — an unmodelled kind that reached a signed token must DENY, not be
# silently ignored.
_KNOWN_CONSTRAINT_KINDS = frozenset(
    {
        "forbidden_values",
        "allowed_values",
        "starts_with",
        "max_value",
        "min_value",
        "required_present",
        "forbidden_field_combinations",
    }
)


def _check_constraints(c: dict, args: dict) -> str | None:
    """Faithful port of raucle.capability CapabilityGate constraint
    semantics: forbidden = EXISTS_DENY over flattened scalars; allowed/starts_with/
    max/min REQUIRE the field present (absence denies) and check every flattened
    scalar; empty collections deny; numeric bounds require finite non-bool numbers;
    required_present + forbidden_field_combinations are presence checks."""
    # Fail-closed: any constraint kind outside the cap:v1 vocabulary that reached
    # a signed token must DENY, never be silently ignored (mirrors the gate's
    # registry guard — defence in depth at the trust boundary).
    for kind in c:
        if kind not in _KNOWN_CONSTRAINT_KINDS:
            return f"unmodelled constraint kind {kind!r} reached the gate (deny)"
    # forbidden_values — EXISTS_DENY (incl. nested in collections).
    for fld, bads in c.get("forbidden_values", {}).items():
        if fld not in args:
            continue
        for scalar in _flatten_scalars(args[fld]):
            if scalar in bads:
                return f"{fld}={scalar!r} in forbidden_values"
    # allowed_values — field MUST be present; empty denies; every scalar in set.
    for fld, oks in c.get("allowed_values", {}).items():
        if fld not in args:
            return f"allowed_values field {fld!r} is absent from the call"
        scalars = list(_flatten_scalars(args[fld]))
        if not scalars:
            return f"allowed_values field {fld!r} carries no value to check"
        for scalar in scalars:
            if scalar not in oks:
                return f"{fld}={scalar!r} not in allowed_values"
    # starts_with — field MUST be present and be a string with the prefix.
    for fld, prefix in c.get("starts_with", {}).items():
        if fld not in args:
            return f"starts_with field {fld!r} is absent from the call"
        if not (isinstance(args[fld], str) and args[fld].startswith(prefix)):
            return f"{fld}={args[fld]!r} does not start with {prefix!r}"
    # max_value / min_value — field MUST be present; every scalar a number in bound.
    for fld, bound in c.get("max_value", {}).items():
        if fld not in args:
            return f"max_value field {fld!r} is absent from the call"
        scalars = list(_flatten_scalars(args[fld]))
        if not scalars:
            return f"max_value field {fld!r} carries no value to check"
        for scalar in scalars:
            if not _is_number(scalar):
                return f"{fld} contains {scalar!r} which is not a number (max_value)"
            if scalar > bound:
                return f"{fld}={scalar!r} > max_value {bound}"
    for fld, bound in c.get("min_value", {}).items():
        if fld not in args:
            return f"min_value field {fld!r} is absent from the call"
        scalars = list(_flatten_scalars(args[fld]))
        if not scalars:
            return f"min_value field {fld!r} carries no value to check"
        for scalar in scalars:
            if not _is_number(scalar):
                return f"{fld} contains {scalar!r} which is not a number (min_value)"
            if scalar < bound:
                return f"{fld}={scalar!r} < min_value {bound}"
    # required_present / forbidden_field_combinations — PRESENCE only.
    for fld in c.get("required_present", []):
        if fld not in args:
            return f"required field {fld!r} missing"
    for combo in c.get("forbidden_field_combinations", []):
        if all(field in args for field in combo):
            return f"forbidden field combination {combo!r} all present"
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cap-verifier", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="Run the eight-check gate against a token")
    v.add_argument("token", type=Path, help="cap:v1 token JSON")
    v.add_argument("--pubkey", type=Path, required=True, help="Issuer Ed25519 PEM")
    v.add_argument("--tool", help="Tool the caller is invoking (optional)")
    v.add_argument("--agent", help="Caller agent_id (optional)")
    v.add_argument("--args", type=Path, help="Call-args JSON (optional)")
    v.add_argument("--now", type=int, help="Override clock for testing")

    h = sub.add_parser("hash", help="Print the token_id we compute for the body")
    h.add_argument("token", type=Path)

    args = p.parse_args(argv)

    try:
        token = json.loads(args.token.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read token: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "hash":
        print("cap:" + sha256_hex(canonical_json(token_body(token)))[:24])
        return 0

    try:
        pubkey = args.pubkey.read_text()
    except OSError as exc:
        print(f"error: cannot read pubkey: {exc}", file=sys.stderr)
        return 2

    call_args = None
    if args.args:
        call_args = json.loads(args.args.read_text())

    allowed, reason, check = verify_token(
        token,
        pubkey,
        tool=args.tool,
        agent_id=args.agent,
        args=call_args,
        now=args.now,
    )
    if allowed:
        print(f"OK  token_id={token.get('token_id')}")
        return 0
    print(f"DENY ({check}): {reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
