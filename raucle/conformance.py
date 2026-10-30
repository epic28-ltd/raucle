"""Field-level argument commitments with selective disclosure.

The conformance re-verification layer: lets an operator prove that a receipt's
hidden call arguments satisfy specific policy constraints, disclosing only the
fields the verifier asks for.

The commitment scheme is a Merkle tree over the top-level fields of the call
arguments:

- leaves hash the field name and the RFC 8785 canonical encoding of its value,
- internal nodes hash the raw 32-byte child digests,
- leaves are ordered by UTF-16 code unit of the field name, matching the
  cross-language canonicalisation discipline of the receipt body,
- all hashing is domain-separated SHA-256, chosen deliberately because SHA-256
  is the well-trodden path in zk proof systems: the scheme is zkVM-portable
  without exotic primitives.

See docs/spec/provenance/v1/conformance-reverification.md for the design and
threat model.
"""

from __future__ import annotations

import hashlib
from typing import Any

from raucle.provenance import _canonical_json

#: Domain separator prefix for every hash in this module (spec d1).
_D = b"raucle/d1\x00"

#: Leaf marker.
_LEAF = b"l\x00"

#: Internal node marker.
_NODE = b"n\x00"


HASH_PREFIX = "sha256:"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _utf16_key(field: str) -> bytes:
    """Sort key: UTF-16 code unit order (RFC 8785 / JCS §3.2.3)."""
    return field.encode("utf-16-be")


def _leaf(field: str, value: Any) -> bytes:
    payload = field.encode("utf-8") + b"\x00" + _canonical_json(value)
    return _sha256(_D + _LEAF + payload)


def _node(left: bytes, right: bytes) -> bytes:
    return _sha256(_D + _NODE + left + b"\x00" + right)


def _fold_level(level: list[bytes]) -> list[bytes]:
    """Fold one level of the Merkle tree. Odd node pairs with itself."""
    next_level: list[bytes] = []
    for i in range(0, len(level), 2):
        left = level[i]
        right = level[i + 1] if i + 1 < len(level) else left
        next_level.append(_node(left, right))
    return next_level


def commit_args(args: dict[str, Any]) -> str:
    """Commit to the call arguments.

    Returns the Merkle root as ``"sha256:<hex>"``, the same shape as other
    receipt digests. Empty args commit to a fixed empty-tree digest.
    """
    if not args:
        return HASH_PREFIX + _sha256(_D + b"empty").hex()
    level = [_leaf(f, args[f]) for f in sorted(args, key=_utf16_key)]
    while len(level) > 1:
        level = _fold_level(level)
    return "sha256:" + level[0].hex()


def disclosure_path(args: dict[str, Any], field: str) -> list[tuple[bool, str]] | None:
    """Merkle path for one field, as (is_right_sibling, sibling_hex) pairs.

    Returns None when the field is absent from args.
    """
    if field not in args:
        return None
    order = sorted(args, key=_utf16_key)
    index = order.index(field)
    level = [_leaf(f, args[f]) for f in order]
    path: list[tuple[bool, str]] = []
    while len(level) > 1:
        if index % 2 == 0:
            sib = level[index + 1] if index + 1 < len(level) else level[index]
            path.append((False, HASH_PREFIX + sib.hex()))
        else:
            path.append((True, "sha256:" + level[index - 1].hex()))
        level = _fold_level(level)
        index //= 2
    return path


def disclose_args(
    args: dict[str, Any],
    fields: list[str],
) -> dict[str, Any]:
    """Produce a disclosure package for the requested fields.

    The package contains, per disclosed field, the value and its Merkle path.
    The operator sends this to the verifier; the verifier pins it against the
    committed root with :func:`verify_disclosure`.
    """
    disclosures: dict[str, Any] = {}
    for field in fields:
        if field not in args:
            continue
        path = disclosure_path(args, field)
        disclosures[field] = {
            "value": args[field],
            "path": path,
        }
    return {"fields": disclosures}


def verify_disclosure(root: str, disclosure: dict[str, Any]) -> dict[str, Any]:
    """Verify a disclosure package against a committed root.

    Fails closed: any leaf mismatch, bad path shape, or root disagreement
    raises ValueError. Returns the verified field-value mapping.
    """
    if not root.startswith(HASH_PREFIX):
        raise ValueError(f"bad root format: {root[:16]!r}")
    expected_root = bytes.fromhex(root[len(HASH_PREFIX) :])
    verified: dict[str, Any] = {}
    fields = disclosure.get("fields")
    if not isinstance(fields, dict):
        raise ValueError("disclosure missing 'fields' object")
    for field, entry in fields.items():
        if not isinstance(entry, dict):
            raise ValueError(f"disclosure for {field!r} is malformed")
        value = entry.get("value")
        path = entry.get("path")
        if path is None:
            raise ValueError(f"disclosure for {field!r} missing path")
        digest = _leaf(field, value)
        for is_right, sib_str in path:
            if not (isinstance(sib_str, str) and sib_str.startswith(HASH_PREFIX)):
                raise ValueError(f"bad sibling digest in {field!r} path")
            sib = bytes.fromhex(sib_str[len(HASH_PREFIX) :])
            if len(sib) != 32:
                raise ValueError(f"bad sibling length in {field!r} path")
            digest = _node(sib, digest) if is_right else _node(digest, sib)
        if digest != expected_root:
            raise ValueError(f"disclosure for {field!r} does not match root")
        verified[field] = value
    return verified


# ---------------------------------------------------------------------------
# Partial constraint re-check (verifier-side, independent of the gate)
# ---------------------------------------------------------------------------


def _value_in(value: Any, allowed: list[Any]) -> bool:
    return value in allowed


def _value_not_in(value: Any, forbidden: list[Any]) -> bool:
    return value not in forbidden


def _le(value: Any, bound: Any) -> bool:
    return value <= bound


def _ge(value: Any, bound: Any) -> bool:
    return value >= bound


def _starts_with_any(value: Any, prefixes: list[str]) -> bool:
    return isinstance(value, str) and any(
        value.startswith(p) for p in prefixes if isinstance(p, str)
    )


#: Constraint kind -> evaluator. Evaluators receive (constraint_value,
#: disclosed_fields) and return a per-field tri-state: True = passes,
#: False = violates, None = field not disclosed (UNKNOWN).
_EVALUATORS: dict[str, Any] = {
    "allowed_values": lambda c, d: {
        f: (_value_in(d[f], allowed) if f in d else None) for f, allowed in c.items()
    },
    "forbidden_values": lambda c, d: {
        f: (_value_not_in(d[f], forbidden) if f in d else None) for f, forbidden in c.items()
    },
    "max_value": lambda c, d: {f: (_le(d[f], bound) if f in d else None) for f, bound in c.items()},
    "min_value": lambda c, d: {f: (_ge(d[f], bound) if f in d else None) for f, bound in c.items()},
    "starts_with": lambda c, d: {
        f: (_starts_with_any(d[f], prefixes) if f in d else None) for f, prefixes in c.items()
    },
}


def recheck_constraints(
    constraints: dict[str, Any],
    disclosed_fields: dict[str, Any],
) -> dict[str, str]:
    """Re-check gate constraints against cryptographically disclosed fields.

    Returns a per-constraint-kind result:

    - ``SATISFIED``: every field the constraint touches was disclosed and
      the values pass.
    - ``VIOLATED``: at least one disclosed value fails the constraint.
    - ``UNKNOWN``: the constraint touches at least one undisclosed field.
      Fail-closed: never counted as conformance.

    This re-derives decisions from the constraint spec independently of the
    operator's runtime, mirroring the verifier-side checks the receipt
    verifier already performs for capability conformance.
    """
    results: dict[str, str] = {}

    for kind, evaluator in _EVALUATORS.items():
        if kind not in constraints:
            continue
        c = constraints[kind]
        if not isinstance(c, dict):
            continue
        per_field = evaluator(c, disclosed_fields)
        if not per_field:
            # Empty constraint object: vacuously satisfied.
            results[kind] = "SATISFIED"
            continue
        vals = list(per_field.values())
        if any(v is False for v in vals):
            results[kind] = "VIOLATED"
        elif any(v is None for v in vals):
            results[kind] = "UNKNOWN"
        else:
            results[kind] = "SATISFIED"

    # required_present: every named field must have been disclosed.
    required = constraints.get("required_present")
    if isinstance(required, list) and required:
        if all(f in disclosed_fields for f in required):
            results["required_present"] = "SATISFIED"
        else:
            results["required_present"] = "UNKNOWN"

    # forbidden_field_combinations: a combination is violated only if ALL
    # its fields are disclosed; any undisclosed field leaves it UNKNOWN.
    combos = constraints.get("forbidden_field_combinations")
    if isinstance(combos, list) and combos:
        combo_results = []
        for combo in combos:
            if not isinstance(combo, list):
                continue
            if all(f in disclosed_fields for f in combo):
                combo_results.append(
                    "VIOLATED" if all(disclosed_fields[f] for f in combo) else "SATISFIED"
                )
            else:
                combo_results.append("UNKNOWN")
        if any(r == "VIOLATED" for r in combo_results):
            results["forbidden_field_combinations"] = "VIOLATED"
        elif all(r == "SATISFIED" for r in combo_results):
            results["forbidden_field_combinations"] = "SATISFIED"
        else:
            results["forbidden_field_combinations"] = "UNKNOWN"

    return results


__all__ = [
    "commit_args",
    "disclosure_path",
    "disclose_args",
    "verify_disclosure",
    "recheck_constraints",
]
