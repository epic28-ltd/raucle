"""Capability-based agent permissions -- unforgeable tool handles.

Every prompt-injection mitigation in 2026 asks an LLM, in English, not
to misuse its tools. This module replaces that polite request with an
OS-style capability discipline: a tool simply refuses to execute unless
the caller presents a valid signed ``Capability`` token whose constraints
are satisfied by the actual call arguments.

The attacker can inject any prompt they want. The agent can decide to
call any tool it wants. The gate doesn't care: without an unforgeable
token, no tool runs.

Three pieces:

- :class:`Capability` -- the token. Ed25519-signed; binds
  ``(agent_id, tool, constraints, nbf, exp, parent_id)``.
- :class:`CapabilityIssuer` -- mints fresh tokens, attenuates parents
  into more-restricted children.
- :class:`CapabilityGate` -- the choke point. ``check(token, tool, args)``
  returns ``GateDecision.ALLOW`` or ``GateDecision.DENY`` with a reason.
  Failing closed is the default.

Attenuation is the killer property. A platform-level token can mint a
session-scoped child carrying extra constraints; the child can mint a
single-task grandchild. Children can only *narrow* permissions, never
broaden. The chain is verifiable end-to-end -- every link Ed25519-signed
by the issuer that minted it.

Composition with the rest of the stack:

- Constraint shape matches :class:`raucle.prove.JSONSchemaProver`'s
  policy schema. A token can carry a ``policy_proof_hash`` from a v0.9.0
  proof, claiming "these constraints are formally complete over the
  declared schema for this tool."
- Every :meth:`CapabilityGate.check` decision emits a structured record
  consumable by the v0.4.0 audit chain and v0.5.0 verdict receipts.

Usage::

    from raucle.capability import CapabilityIssuer, CapabilityGate

    issuer = CapabilityIssuer.generate(issuer="platform.example")
    issuer.save_private_key("issuer.key.pem")

    root = issuer.mint(
        agent_id="agent:billing",
        tool="transfer_funds",
        constraints={
            "max_value": {"amount": 100},
            "forbidden_values": {"to": ["attacker@evil.example"]},
        },
        ttl_seconds=3600,
    )

    gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
    decision = gate.check(root, tool="transfer_funds",
                          args={"to": "alice@example", "amount": 50})
    if not decision.allowed:
        raise PermissionError(decision.reason)
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
import math
import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from raucle._paths import validate_path

from . import registry as _registry
from ._canon import reject_lone_surrogates as _reject_lone_surrogates
from ._canon import reorder_keys_utf16 as _reorder_keys_utf16
from ._canon import utf16_key as _utf16_key
from ._canon import value_sort_key as _value_sort_key

if TYPE_CHECKING:
    from raucle.prove import ProofResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonicalisation + crypto helpers (mirrors feed.py / provenance.py)
# ---------------------------------------------------------------------------

#: JS safe-integer range — values outside this are not exactly representable
#: in all five reference implementations (parity with provenance.py).
_MAX_SAFE_INT = 2**53 - 1
_MIN_SAFE_INT = -(2**53 - 1)


def _reject_floats(obj: Any) -> None:
    """Raise on any float, integer outside the JS safe-integer range, or any
    string/key carrying a lone surrogate, in signed token material.

    cap:v1 numeric constraints are integers (see the standards doc). Floats are
    rejected — not serialised — so token canonicalisation stays deterministic and
    integer-only, consistent with the provenance receipt encoder. Integers are
    bounded to the JS safe-integer range [-2^53+1, 2^53-1] so every value is
    exactly representable in all five reference implementations (parity with
    provenance.py's _reject_floats). ``bool`` is an ``int`` subclass and is
    allowed. (Only used on the token body, never on call arguments, so float
    call-arg values still compare against integer bounds.)

    Lone UTF-16 surrogates are rejected *explicitly* here (Profile R8) rather
    than incidentally via the later ``.encode("utf-8")``, so capability tokens
    reject the same cross-language-unstable material as provenance receipts and
    on the same clean ``ValueError``.
    """
    if isinstance(obj, float):
        raise ValueError(
            "capability token: float numeric values are not permitted (cap:v1 "
            "constraints are integer-only)"
        )
    if isinstance(obj, bool):
        pass  # bool is an int subclass but serialises as a JSON boolean
    elif isinstance(obj, int) and not (_MIN_SAFE_INT <= obj <= _MAX_SAFE_INT):
        raise ValueError(
            f"capability token: integer {obj} is outside the portable safe-integer "
            f"range [{_MIN_SAFE_INT}, {_MAX_SAFE_INT}] (not representable in all "
            f"reference implementations)"
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


def _canonical_json(obj: Any) -> bytes:
    # allow_nan rejects NaN/Infinity; _reject_floats rejects ALL floats so signed
    # token material is integer-only and deterministic. Object keys are ordered by
    # UTF-16 code unit (§4.3.1 / RFC 8785), not Python's native code-point order,
    # for cross-language byte-identity parity with the provenance canonicaliser.
    _reject_floats(obj)
    return json.dumps(
        _reorder_keys_utf16(obj),
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _now() -> int:
    return int(dt.datetime.now(dt.timezone.utc).timestamp())


def _require_crypto() -> Any:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "raucle.capability requires the [compliance] extra: pip install 'raucle[compliance]'"
        ) from exc
    return serialization, ed25519, InvalidSignature


# Must start and end with [a-z0-9]. Interior chars are [a-z0-9_-] or a single
# dot used strictly as a separator: every '.' must be both preceded and
# followed by [a-z0-9], forbidding a trailing '.' and consecutive '..'. This
# stops a token for 'agent:billing.' over-authorising 'agent:billing..evil'
# (AGENT-ID-REGEX). Length is bounded to keep parity with the prior 0..127
# tail budget (full id capped at 134 chars: 'agent:' + 1 + up to 127).
# Upper bound on a freshly-minted token's lifetime. Capabilities are meant to
# be short-lived; one year is a generous ceiling that still rejects obvious
# units bugs (e.g. passing milliseconds) and accidental "forever" tokens.
_MAX_TTL_SECONDS = 366 * 24 * 60 * 60

_AGENT_ID_RE = re.compile(r"^agent:[a-z0-9](?:[a-z0-9_\-]|\.(?=[a-z0-9])){0,126}[a-z0-9]?$")
_TOOL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-./]{0,127}$")


def _validate_agent_id(agent_id: str) -> None:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError(f"agent_id {agent_id!r} must match {_AGENT_ID_RE.pattern!r}")


def _validate_tool(tool: str) -> None:
    if not _TOOL_RE.match(tool):
        raise ValueError(f"tool {tool!r} must match {_TOOL_RE.pattern!r}")


# ---------------------------------------------------------------------------
# Capability token
# ---------------------------------------------------------------------------


@dataclass
class Capability:
    """An unforgeable signed permission to invoke ``tool`` with constrained args.

    Constraint schema mirrors :class:`raucle.prove.JSONSchemaProver`'s
    policy keys:

    - ``forbidden_values`` -- ``{field: [bad, ...]}`` (**best-effort denylist**)
    - ``max_value`` / ``min_value`` -- ``{field: bound}``
    - ``required_present`` -- ``[field, ...]``
    - ``forbidden_field_combinations`` -- ``[[a, b], ...]``
    - ``allowed_values`` -- ``{field: [ok, ...]}`` (whitelist)

    .. warning::
       ``forbidden_values`` is a **best-effort denylist**: the gate enforces it
       on the argument *names* the policy declares and cannot see the tool's full
       parameter schema, so a forbidden value supplied under a different
       parameter name is not caught. For security-critical fields prefer the
       fail-closed positive constraints — ``allowed_values`` (whitelist),
       ``required_present``, and ``max_value``/``min_value`` bounds.
    """

    token_id: str
    agent_id: str
    tool: str
    constraints: dict[str, Any]
    issuer: str
    key_id: str
    issued_at: int
    not_before: int
    expires_at: int
    parent_id: str | None = None
    policy_proof_hash: str | None = None
    # Structural binding of the cited proof. When set, downstream
    # verifiers can confirm the proof referenced by ``policy_proof_hash``
    # was actually over this schema/policy without trusting the issuer.
    # Both are nullable and default-absent for backward compatibility.
    grammar_hash: str | None = None
    policy_hash: str | None = None
    signature: str = ""
    # Quantum-ready hybrid tokens (raucle/pq1): the ML-DSA-65 component.
    # Both default to None (classical-only token, unchanged wire shape);
    # when pq_key_id is set, the gate requires a valid pq_signature over
    # the SAME canonical body, verified against the issuer's published
    # ML-DSA-65 key. Stripping these fields from a hybrid token makes it
    # classical-only - detectable only via gate policy (the verifier
    # pins which issuers must be quantum-safe), documented in the spec.
    pq_key_id: str | None = None
    pq_signature: str | None = None

    def body(self) -> dict[str, Any]:
        # NB: token_id is derived from this body and is NOT a member of it.
        return {
            "agent_id": self.agent_id,
            "tool": self.tool,
            "constraints": _normalise_constraints(self.constraints),
            "issuer": self.issuer,
            "key_id": self.key_id,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "parent_id": self.parent_id,
            "policy_proof_hash": self.policy_proof_hash,
            "grammar_hash": self.grammar_hash,
            "policy_hash": self.policy_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.body()
        d["token_id"] = self.token_id
        d["signature"] = self.signature
        if self.pq_key_id is not None:
            d["pq_key_id"] = self.pq_key_id
            d["pq_signature"] = self.pq_signature or ""
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Capability:
        # The token must be a JSON object; a non-object (list/str/number/null)
        # is invalid signed material and must fail closed with a ValueError, not
        # an AttributeError on the .get() calls below.
        if not isinstance(d, dict):
            raise ValueError(f"capability token: must be a JSON object, got {type(d).__name__}")

        # Independently re-validate signed-token shape at the parse boundary
        # (defence in depth): mint() enforces these, but a token reaches the gate
        # as untrusted JSON, and the cap-verifier reference rejects the same
        # malformed shapes — so the gate path must too, not just trust the field.
        # Every check raises ValueError (never KeyError/TypeError) so a malformed
        # token fails closed with a clear reason instead of crashing the caller.
        def _req_str(name: str) -> str:
            v = d.get(name)
            if not isinstance(v, str) or not v:
                raise ValueError(
                    f"capability token: {name} must be a non-empty string, got "
                    f"{type(v).__name__} {v!r}"
                )
            return v

        for _f in ("token_id", "agent_id", "tool", "issuer", "key_id"):
            _req_str(_f)
        _validate_agent_id(d["agent_id"])
        _validate_tool(d["tool"])
        if not isinstance(d.get("constraints"), dict):
            raise ValueError(
                "capability token: constraints must be present and a JSON object "
                "(Capability.body always signs a constraints object, possibly empty)"
            )
        # parent_id is the chain link: it MUST be either absent/null (a root) or
        # a non-empty string token-id. A falsy-but-non-null value ("" / [] / {})
        # would otherwise slip past the gate's chain check (truthiness) and skip
        # attenuation verification.
        _pid = d.get("parent_id")
        if _pid is not None and (not isinstance(_pid, str) or not _pid):
            raise ValueError(
                f"capability token: parent_id must be a non-empty string or null, "
                f"got {type(_pid).__name__} {_pid!r}"
            )
        # A parsed token is signed material: signature MUST be present and a
        # string (matches the cap-verifier reference, which type-checks it as a
        # required field). An empty string is tolerated here — the signature
        # check denies it on verify — but a missing/non-string value fails closed
        # at the parse boundary rather than defaulting to "".
        if not isinstance(d.get("signature"), str):
            raise ValueError("capability token: signature must be present and a string")

        def _ts(name: str) -> int:
            # Timestamps are signed material and MUST be canonical integers.
            # Do NOT coerce floats/strings via int() (a non-canonical encoding
            # would re-sign to different bytes, and would also disagree with the
            # cap-verifier reference, which rejects non-int timestamps) and do
            # NOT crash on a missing/None value — reject fail-closed instead.
            v = d.get(name)
            if isinstance(v, bool) or not isinstance(v, int):
                raise ValueError(
                    f"capability token: {name} must be an integer, got {type(v).__name__} {v!r}"
                )
            return v

        return cls(
            token_id=d["token_id"],
            agent_id=d["agent_id"],
            tool=d["tool"],
            constraints=d.get("constraints", {}),
            issuer=d["issuer"],
            key_id=d["key_id"],
            issued_at=_ts("issued_at"),
            not_before=_ts("not_before"),
            expires_at=_ts("expires_at"),
            parent_id=d.get("parent_id"),
            policy_proof_hash=d.get("policy_proof_hash"),
            grammar_hash=d.get("grammar_hash"),
            policy_hash=d.get("policy_hash"),
            signature=d["signature"],
            pq_key_id=d.get("pq_key_id"),
            pq_signature=d.get("pq_signature"),
        )

    def save(self, path: str | Path) -> None:
        p = validate_path(path, must_exist=False)
        p.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False))

    @classmethod
    def load(cls, path: str | Path) -> Capability:
        return cls.from_dict(json.loads(validate_path(path).read_text()))


# Derived from the Modelled Language Registry (§8.1) — the single source of
# truth. Do not hand-maintain this set; add a constraint kind in registry.py
# (which forces every semantic column to be filled in). The drift test
# (tests/test_registry_drift.py) fails if this diverges from the registry.
_KNOWN_CONSTRAINT_KEYS = _registry.KNOWN_CONSTRAINT_KEYS


def _require_json_scalar(kind: str, field: str, v: Any) -> None:
    """Reject a value-list member that is not a JSON scalar (§8.5).

    Permitted: ``str``, ``int``, ``bool``. Rejected: floats (not cross-impl
    stable), ``None``, ``bytes``, and any nested container (list/dict/set/tuple)
    — none of which are valid, comparable members of a constraint value set.
    ``bool`` is permitted (an ``int`` subclass) since it serialises as a JSON
    boolean and compares unambiguously.
    """
    # bool is an int subclass, so (str, int) already admits True/False.
    if isinstance(v, (str, int)):
        return
    raise ValueError(
        f"{kind}[{field!r}] contains {type(v).__name__} {v!r}; members must be "
        f"JSON scalars (str/int/bool) — floats, None, bytes and nested "
        f"containers are not permitted (§8.5)"
    )


def _validate_field_keys(kind: str, mapping: dict[str, Any]) -> None:
    """Field-name (constraint key) validation (§8.5).

    Keys must be non-empty strings, and must remain distinct after Unicode NFC
    normalisation — otherwise two visually/semantically equal field names (e.g.
    a precomposed vs decomposed accented form) could collide at the tool
    boundary while appearing distinct in the signed token.
    """
    seen: dict[str, str] = {}
    for key in mapping:
        if not isinstance(key, str) or not key:
            raise ValueError(f"{kind} field name must be a non-empty string, got {key!r} (§8.5)")
        norm = unicodedata.normalize("NFC", key)
        if norm in seen and seen[norm] != key:
            raise ValueError(
                f"{kind} field names {seen[norm]!r} and {key!r} collide under "
                f"Unicode NFC normalisation (§8.5)"
            )
        seen[norm] = key


def _require_int_bound(kind: str, field: str, bound: Any) -> None:
    """Reject a numeric-bound value that is not a real integer (§8.5).

    ``bool`` is an ``int`` subclass in Python, so ``True``/``False`` would
    otherwise be accepted as a bound and compared numerically (``True == 1``) —
    an ambiguous, error-prone token. Floats are rejected here too with a clear
    message (the canonical encoder also rejects them at sign-time, but a
    validator error at mint is far more actionable). Strings/None/collections
    are likewise rejected.
    """
    if isinstance(bound, bool) or not isinstance(bound, int):
        raise ValueError(
            f"{kind}[{field!r}] bound must be an integer, got "
            f"{type(bound).__name__} {bound!r} (§8.5 — cap:v1 bounds are "
            f"integer-only; bool is not a number)"
        )


def _as_value_list(kind: str, field: str, v: Any) -> list[Any]:
    """Validate that a value-set constraint is a real list/tuple, not a scalar.

    A bare string would otherwise be ``sorted()`` into its characters — e.g.
    ``forbidden_values={'role': 'admin'}`` becomes ``['a','d','i','m','n']`` and
    the intended value ``'admin'`` is no longer blacklisted. Reject the malformed
    shape at mint/normalise rather than silently weakening (and signing) the
    policy.
    """
    # §8.5: accept ONLY a JSON array (list). A set/frozenset is unordered (its
    # serialisation is non-deterministic) and a tuple/bytes/str is not a JSON
    # array — none may be silently coerced into signed token material.
    if not isinstance(v, list):
        raise ValueError(
            f"{kind}[{field!r}] must be a list (JSON array) of values, got "
            f"{type(v).__name__} {v!r} — wrap a single value in a list, e.g. [{v!r}] "
            f"(sets/tuples/strings are not accepted; §8.5)"
        )
    for member in v:
        _require_json_scalar(kind, field, member)
    return list(v)


def _normalise_constraints(c: dict[str, Any]) -> dict[str, Any]:
    """Canonical form so attenuation comparisons are exact.

    Raises
    ------
    ValueError
        If ``c`` contains an unrecognised constraint key. This is a guard
        against silently dropping a rule because of a typo or wrong case
        (e.g. ``allowedValues`` instead of ``allowed_values``) — an unknown
        key would otherwise be ignored, minting a token that enforces less
        than the operator intended.
    """
    unknown = set(c) - _KNOWN_CONSTRAINT_KEYS
    if unknown:
        raise ValueError(
            f"unknown constraint key(s): {sorted(unknown)}. "
            f"Constraint keys are snake_case; valid keys are "
            f"{sorted(_KNOWN_CONSTRAINT_KEYS)}."
        )
    out: dict[str, Any] = {}
    _normalise_value_list_constraint(c, "forbidden_values", out)
    _normalise_value_list_constraint(c, "allowed_values", out)
    _normalise_starts_with(c, out)
    _normalise_int_bound(c, "max_value", out)
    _normalise_int_bound(c, "min_value", out)
    _normalise_required_present(c, out)
    _normalise_forbidden_field_combinations(c, out)
    return out


def _normalise_value_list_constraint(c: dict[str, Any], key: str, out: dict[str, Any]) -> None:
    if key not in c:
        return
    _validate_field_keys(key, c[key])
    out[key] = {
        k: sorted(_as_value_list(key, k, v), key=_value_sort_key) for k, v in c[key].items()
    }


def _normalise_starts_with(c: dict[str, Any], out: dict[str, Any]) -> None:
    if "starts_with" not in c:
        return
    _validate_field_keys("starts_with", c["starts_with"])
    for fld, prefix in c["starts_with"].items():
        if not isinstance(prefix, str):
            raise ValueError(
                f"starts_with[{fld!r}] prefix must be a string, got "
                f"{type(prefix).__name__} {prefix!r} (§8.5)"
            )
    out["starts_with"] = dict(c["starts_with"])


def _normalise_int_bound(c: dict[str, Any], key: str, out: dict[str, Any]) -> None:
    if key not in c:
        return
    _validate_field_keys(key, c[key])
    for fld, bound in c[key].items():
        _require_int_bound(key, fld, bound)
    out[key] = dict(c[key])


def _normalise_required_present(c: dict[str, Any], out: dict[str, Any]) -> None:
    if "required_present" not in c:
        return
    out["required_present"] = sorted(
        _require_field_name_list("required_present", c), key=_utf16_key
    )


def _normalise_forbidden_field_combinations(c: dict[str, Any], out: dict[str, Any]) -> None:
    if "forbidden_field_combinations" not in c:
        return
    combos = c["forbidden_field_combinations"]
    if not isinstance(combos, list):
        raise ValueError("forbidden_field_combinations must be a list of field-name lists (§8.5)")
    norm_combos = []
    for combo in combos:
        if not isinstance(combo, list):
            raise ValueError(
                f"forbidden_field_combinations entry {combo!r} must be a list of field names (§8.5)"
            )
        for fld in combo:
            if not isinstance(fld, str) or not fld:
                raise ValueError(
                    f"forbidden_field_combinations field name must be a non-empty "
                    f"string, got {fld!r} (§8.5)"
                )
        norm_combos.append(sorted(combo, key=_utf16_key))
    # Sort the outer list of combos by their UTF-16-ordered field names too,
    # so the signed canonical form is deterministic and code-point/UTF-16
    # consistent for non-BMP field names.
    out["forbidden_field_combinations"] = sorted(
        norm_combos, key=lambda combo: [_utf16_key(x) for x in combo]
    )


def _require_field_name_list(kind: str, c: dict[str, Any]) -> list[str]:
    """Validate a field-name list constraint (required_present): a JSON list of
    non-empty strings, distinct under Unicode NFC (§8.5)."""
    val = c[kind]
    if not isinstance(val, list):
        raise ValueError(
            f"{kind} must be a JSON list of field names, got {type(val).__name__} (§8.5)"
        )
    seen: dict[str, str] = {}
    for fld in val:
        if not isinstance(fld, str) or not fld:
            raise ValueError(f"{kind} field name must be a non-empty string, got {fld!r} (§8.5)")
        norm = unicodedata.normalize("NFC", fld)
        if norm in seen and seen[norm] != fld:
            raise ValueError(
                f"{kind} field names {seen[norm]!r} and {fld!r} collide under Unicode NFC (§8.5)"
            )
        seen[norm] = fld
    return val


# ---------------------------------------------------------------------------
# Issuer
# ---------------------------------------------------------------------------


class CapabilityIssuer:
    """Holds an Ed25519 private key; mints and attenuates Capability tokens.

    Parameters
    ----------
    issuer
        The issuer identifier (e.g. ``"acme.bank.kyc"``).
    private_key
        The Ed25519 private key. Use :meth:`generate` /
        :meth:`load_private_key` rather than constructing one directly
        unless you have a key already in hand.
    require_proof
        Strict mint mode. When ``True``, :meth:`mint` refuses to issue
        any capability unless a ``PROVEN`` :class:`~raucle.prove.ProofResult`
        is supplied. Defaults to ``False`` for backward compatibility;
        also reads the ``RAUCLE_REQUIRE_PROOF`` environment variable
        (``"1"`` / ``"true"`` enables strict mode without changing
        construction sites).
    """

    def __init__(
        self,
        issuer: str,
        private_key: Any,
        *,
        require_proof: bool | None = None,
        remote_signer: Any = None,
        pq_private: Any = None,
    ) -> None:
        if not issuer:
            raise ValueError("issuer must not be empty")
        self.issuer = issuer
        self._priv = private_key
        self._remote_signer = remote_signer
        # Quantum-ready minting (raucle/pq1): an optional ML-DSA-65 key.
        # When present, mint(..., quantum=True) signs the token body with
        # BOTH keys. The token's token_id derivation is unchanged (the PQ
        # signature is not part of body()), so hybrid tokens stay
        # content-addressed by the same body hash.
        self._pq_priv: Any = None
        self._pq_key_id: str | None = None
        if pq_private is not None:
            from cryptography.hazmat.primitives.asymmetric.mldsa import (
                MLDSA65PrivateKey,
            )

            if not isinstance(pq_private, MLDSA65PrivateKey):
                raise TypeError(
                    "pq_private must be an MLDSA65PrivateKey (generate with "
                    "raucle.pq.pq_generate and persist the seed)"
                )
            from raucle.pq import pq_key_id_from_public_key

            self._pq_priv = pq_private
            self._pq_key_id = pq_key_id_from_public_key(pq_private.public_key())
        if remote_signer is not None:
            # KMS/HSM mode: public key comes from the remote signer
            self.public_key_pem = remote_signer.public_key_pem().decode("ascii")
        else:
            serialization, _ed25519, _invalid_sig = _require_crypto()
            pub_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self.public_key_pem = pub_pem.decode("ascii")
        self.key_id = _sha256_hex(self.public_key_pem.encode("ascii"))[:16]
        # Env-var fallback: the kwarg always wins when explicitly set;
        # otherwise consult ``RAUCLE_REQUIRE_PROOF``.
        if require_proof is None:
            env = os.environ.get("RAUCLE_REQUIRE_PROOF", "").strip().lower()
            self._require_proof = env in {"1", "true", "yes", "on"}
        else:
            self._require_proof = require_proof

    @property
    def require_proof(self) -> bool:
        """True when this issuer is in strict-mint mode."""
        return self._require_proof

    @classmethod
    def generate(cls, issuer: str, *, require_proof: bool | None = None) -> CapabilityIssuer:
        _, ed25519, _ = _require_crypto()
        return cls(
            issuer=issuer,
            private_key=ed25519.Ed25519PrivateKey.generate(),
            require_proof=require_proof,
        )

    @classmethod
    def load_private_key(
        cls,
        issuer: str,
        path: str | Path,
        *,
        require_proof: bool | None = None,
        password: bytes | str | None = None,
    ) -> CapabilityIssuer:
        """Load an issuer from a PEM private key on disk.

        ``password`` supports encrypted PKCS8 PEMs. Pass ``None`` for
        unencrypted keys (the default, preserving backward compatibility).
        In regulated deployments, private keys at rest should be encrypted.
        """
        serialization, _ed, _invalid_sig = _require_crypto()
        pw = password.encode("utf-8") if isinstance(password, str) else password
        key_path = Path(path).resolve()
        if not key_path.is_file():
            raise ValueError(f"private key file not found: {key_path}")
        priv = serialization.load_pem_private_key(key_path.read_bytes(), password=pw)
        return cls(issuer=issuer, private_key=priv, require_proof=require_proof)

    @classmethod
    def from_signer(
        cls,
        issuer: str,
        signer: Any,
        *,
        require_proof: bool | None = None,
    ) -> CapabilityIssuer:
        """Create an issuer backed by a remote signer (KMS/HSM).

        The signer must implement the :class:`~raucle.kms.Signer` protocol:
        ``sign(data: bytes) -> bytes`` and ``public_key_pem() -> bytes``.

        The private key never leaves the KMS/HSM. All signing is delegated
        to the remote service.

        Example::

            from raucle.kms import AWSSigner
            signer = AWSSigner(key_id="alias/raucle-issuing-key")
            issuer = CapabilityIssuer.from_signer("acme.bank", signer)
        """
        # Create with a dummy private key (not used) and the remote signer.
        return cls(
            issuer=issuer,
            private_key=None,  # type: ignore[arg-type]
            require_proof=require_proof,
            remote_signer=signer,
        )

    def save_private_key(self, path: str | Path) -> None:
        if self._remote_signer is not None:
            raise NotImplementedError(
                "save_private_key is not available when using a remote signer "
                "(KMS/HSM). The private key is held by the remote service."
            )
        serialization, _ed, _invalid_sig = _require_crypto()
        pem = self._priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Write the PKCS8 private key with owner-only permissions (0600).
        # os.open with mode 0o600 creates the file restricted from the start
        # rather than briefly exposing it world-readable at the default umask
        # (KEY-PERMS). chmod afterwards covers a pre-existing file too.
        p = os.fspath(path)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(pem)
        finally:
            os.chmod(p, 0o600)

    def _sign(self, data: bytes) -> bytes:
        """Sign data with Ed25519, delegating to KMS/HSM if configured."""
        if self._remote_signer is not None:
            return self._remote_signer.sign(data)
        return self._priv.sign(data)

    def mint(
        self,
        *,
        agent_id: str,
        tool: str,
        constraints: dict[str, Any] | None = None,
        ttl_seconds: int = 3600,
        not_before_offset: int = 0,
        policy_proof_hash: str | None = None,
        proof_result: ProofResult | None = None,
        grammar_hash: str | None = None,
        policy_hash: str | None = None,
        quantum: bool = False,
    ) -> Capability:
        """Mint a fresh capability token.

        When ``proof_result`` is supplied, the resulting token binds
        ``policy_proof_hash``, ``grammar_hash`` and ``policy_hash`` to
        the proof's values. Downstream verifiers can then confirm —
        without trusting the issuer — that the cited proof was actually
        over this schema and policy.

        In strict mode (``require_proof=True`` on the issuer, or
        ``RAUCLE_REQUIRE_PROOF=1`` in the environment), a
        ``ProofResult`` whose status is ``"PROVEN"`` is required;
        anything else (absent, ``REFUTED``, ``UNDECIDED``) raises
        :class:`~raucle.errors.PolicyUnproven`.

        Backward-compatible default (``require_proof=False``,
        ``proof_result=None``) preserves existing behaviour: a token is
        minted with whatever ``policy_proof_hash`` / ``grammar_hash`` /
        ``policy_hash`` the caller supplied (typically all ``None``).

        Parameters
        ----------
        proof_result
            Optional. When supplied, ``policy_proof_hash`` is forced to
            ``proof_result.hash`` and the grammar/policy hashes are
            taken from the proof. Supplying both ``proof_result`` and a
            conflicting ``policy_proof_hash`` is a ``ValueError``.
        grammar_hash, policy_hash
            Optional explicit values, for callers that want to bind
            hashes without producing a ``ProofResult``. Ignored when
            ``proof_result`` is supplied (the proof's hashes win).
        """
        from raucle.errors import PolicyUnproven

        _validate_agent_id(agent_id)
        _validate_tool(tool)

        # ── TTL sanity guard (TTL-LOW) ──────────────────────────────
        # A token must live for a positive, bounded span. Zero/negative
        # ttl would mint an already-dead token; an absurdly large ttl
        # (years/centuries) defeats the short-lived-credential model and
        # is almost always a units bug (ms vs s) at the call site.
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
            raise ValueError(f"ttl_seconds must be an int; got {ttl_seconds!r}")
        if ttl_seconds <= 0:
            raise ValueError(f"ttl_seconds must be positive; got {ttl_seconds}")
        if ttl_seconds > _MAX_TTL_SECONDS:
            raise ValueError(
                f"ttl_seconds {ttl_seconds} exceeds the maximum {_MAX_TTL_SECONDS} "
                f"(~{_MAX_TTL_SECONDS // 86400} days); capabilities are short-lived"
            )

        # ── Strict-mode validation ──────────────────────────────────
        if self._require_proof:
            if proof_result is None:
                raise PolicyUnproven(
                    "CapabilityIssuer(require_proof=True): mint() requires a "
                    "ProofResult; none was supplied"
                )
            if proof_result.status != "PROVEN":
                raise PolicyUnproven(
                    f"CapabilityIssuer(require_proof=True): mint() requires a "
                    f"PROVEN ProofResult; got status {proof_result.status!r}"
                )

        # ── Derive the bound hashes from the proof when present ─────
        if proof_result is not None:
            policy_proof_hash, grammar_hash, policy_hash = self._bind_proof_hashes(
                proof_result, policy_proof_hash, grammar_hash, policy_hash
            )

        now = _now()
        cap = Capability(
            token_id="",
            agent_id=agent_id,
            tool=tool,
            constraints=_normalise_constraints(constraints or {}),
            issuer=self.issuer,
            key_id=self.key_id,
            issued_at=now,
            not_before=now + not_before_offset,
            expires_at=now + ttl_seconds,
            parent_id=None,
            policy_proof_hash=policy_proof_hash,
            grammar_hash=grammar_hash,
            policy_hash=policy_hash,
        )
        cap.token_id = "cap:" + _sha256_hex(_canonical_json(cap.body()))[:24]
        # Re-canonicalise with token_id included.
        signing_bytes = _canonical_json(cap.body())
        cap.signature = _b64(self._sign(signing_bytes))
        if quantum:
            if self._pq_priv is None:
                raise ValueError(
                    "quantum=True requires the issuer to hold an ML-DSA-65 key "
                    "(pass pq_private when constructing CapabilityIssuer)"
                )
            from raucle.pq import _b64url

            pq_sig = self._pq_priv.sign(signing_bytes)
            cap.pq_key_id = self._pq_key_id
            cap.pq_signature = _b64url(pq_sig)
        return cap

    @staticmethod
    def _bind_proof_hashes(
        proof_result: Any,
        policy_proof_hash: str | None,
        grammar_hash: str | None,
        policy_hash: str | None,
    ) -> tuple[str | None, str | None, str | None]:
        """Derive the bound hashes from the proof when present.

        Even outside strict mode: binding a non-PROVEN proof to a capability
        is nonsensical. Refuse it explicitly.
        """
        from raucle.errors import PolicyUnproven

        if proof_result.status != "PROVEN":
            raise PolicyUnproven(
                f"mint(): refuse to bind a non-PROVEN ProofResult "
                f"(status={proof_result.status!r}) to a capability"
            )
        if policy_proof_hash is not None and policy_proof_hash != proof_result.hash:
            raise ValueError(
                "policy_proof_hash conflicts with proof_result.hash; "
                "pass one or the other, not both"
            )
        policy_proof_hash = proof_result.hash
        # Cross-check caller-supplied hashes against the proof's
        # if the caller asserted them — surface mismatches loudly.
        if grammar_hash is not None and grammar_hash != proof_result.grammar_hash:
            raise PolicyUnproven(
                f"grammar_hash {grammar_hash!r} does not match "
                f"ProofResult.grammar_hash {proof_result.grammar_hash!r}"
            )
        if policy_hash is not None and policy_hash != proof_result.policy_hash:
            raise PolicyUnproven(
                f"policy_hash {policy_hash!r} does not match "
                f"ProofResult.policy_hash {proof_result.policy_hash!r}"
            )
        grammar_hash = proof_result.grammar_hash
        policy_hash = proof_result.policy_hash
        return policy_proof_hash, grammar_hash, policy_hash

    def attenuate(
        self,
        parent: Capability,
        *,
        extra_constraints: dict[str, Any] | None = None,
        narrower_ttl_seconds: int | None = None,
        narrower_agent_id: str | None = None,
    ) -> Capability:
        """Derive a more-restricted child token from ``parent``.

        The child:

        - Must target the same ``tool`` (cannot broaden tool scope).
        - May target the same or a narrower ``agent_id``.
        - Inherits parent constraints plus any additional ``extra_constraints``.
        - Must expire no later than the parent.
        - Carries ``parent_id`` so the chain is reconstructible.

        Raises ``ValueError`` if the requested attenuation would broaden
        permissions in any dimension.

        .. warning::

            **Strict proof mode (round-3 #15):** the child inherits the
            parent's ``policy_proof_hash`` but NOT ``grammar_hash`` /
            ``policy_hash`` (the child's constraint set differs from the proven
            parent's, so the parent's proof does not bind to it). A
            :class:`CapabilityGate` constructed with ``require_proof=True`` will
            therefore DENY an attenuated child (fail-closed). To use attenuated
            tokens under strict proof enforcement, mint the child directly with
            its own ``ProofResult`` rather than deriving it via ``attenuate``.
        """
        if not parent.signature:
            raise ValueError("parent token is unsigned")
        if parent.expires_at <= _now():
            raise ValueError("parent token has expired")

        child_agent = narrower_agent_id or parent.agent_id
        if narrower_agent_id and narrower_agent_id != parent.agent_id:
            _validate_agent_id(narrower_agent_id)
            # Narrowing is allowed only if the child agent_id is *more specific*,
            # interpreted as a prefix-extension of the parent's id (e.g.
            # agent:billing -> agent:billing.invoice).
            if not (
                narrower_agent_id == parent.agent_id
                or narrower_agent_id.startswith(parent.agent_id + ".")
            ):
                raise ValueError(
                    f"narrower_agent_id {narrower_agent_id!r} is not a sub-scope of "
                    f"parent {parent.agent_id!r}"
                )

        merged = _merge_narrowing(parent.constraints, extra_constraints or {})

        now = _now()
        ttl = (
            narrower_ttl_seconds if narrower_ttl_seconds is not None else (parent.expires_at - now)
        )
        new_exp = now + ttl
        if new_exp > parent.expires_at:
            raise ValueError("child token cannot outlive its parent")

        child = Capability(
            token_id="",
            agent_id=child_agent,
            tool=parent.tool,
            constraints=merged,
            issuer=self.issuer,
            key_id=self.key_id,
            issued_at=now,
            not_before=max(now, parent.not_before),
            expires_at=new_exp,
            parent_id=parent.token_id,
            policy_proof_hash=parent.policy_proof_hash,
        )
        child.token_id = "cap:" + _sha256_hex(_canonical_json(child.body()))[:24]
        child.signature = _b64(self._sign(_canonical_json(child.body())))
        return child


def _vid(v: Any):
    """JSON identity for value-list dedup. ``bool`` is an ``int`` subclass, so a
    plain ``set`` collapses ``True`` and ``1`` (distinct JSON values) into one,
    silently dropping a constraint value. Keying on (type-name, value) keeps them
    distinct (codex R7 P2). Non-hashable members (dict/list — never valid in a
    value list) are keyed by repr so dedup does not raise TypeError before
    _normalise_constraints emits the proper validation error (codex R8 P3)."""
    try:
        hash(v)
    except TypeError:
        return (type(v).__name__, repr(v))
    return (type(v).__name__, v)


def _union_values(a, b):
    """Order-insensitive union preserving JSON-distinct values (no bool/int
    collapse). Final ordering is applied by _normalise_constraints."""
    seen: dict = {}
    for v in list(a) + list(b):
        seen.setdefault(_vid(v), v)
    return list(seen.values())


def _intersect_values(a, b):
    """Intersection preserving JSON-distinct values (no bool/int collapse)."""
    b_ids = {_vid(v) for v in b}
    seen: dict = {}
    for v in a:
        if _vid(v) in b_ids:
            seen.setdefault(_vid(v), v)
    return list(seen.values())


def _merge_starts_with(out: dict[str, Any], fld: str, prefix: str) -> None:
    """Merge a starts_with prefix into the output, enforcing narrowing."""
    existing = out.get(fld)
    if existing is None:
        out[fld] = prefix
    elif prefix.startswith(existing):
        # Child extends the parent's prefix → strictly narrower. Keep child's.
        out[fld] = prefix
    elif existing.startswith(prefix):
        # Child's prefix is broader than the parent's → would broaden. Refuse.
        raise ValueError(
            f"attenuation cannot broaden starts_with[{fld!r}]: "
            f"{prefix!r} is broader than parent {existing!r}"
        )
    else:
        raise ValueError(
            f"attenuation starts_with[{fld!r}] {prefix!r} is disjoint from "
            f"parent {existing!r} — no non-empty narrowing exists"
        )


def _merge_narrowing(parent: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    """Combine two constraint sets, taking the tighter bound on every key.

    Final value-list ordering is canonicalised by _normalise_constraints (UTF-16),
    so the intermediate operations here only need to preserve the correct SET of
    values — which means avoiding Python ``set`` for value lists (it collapses
    bool/int, see _vid)."""
    import copy

    out: dict[str, Any] = copy.deepcopy(parent)

    for fld, vals in extra.get("forbidden_values", {}).items():
        out.setdefault("forbidden_values", {})
        out["forbidden_values"][fld] = _union_values(out["forbidden_values"].get(fld, []), vals)

    for fld, vals in extra.get("allowed_values", {}).items():
        out.setdefault("allowed_values", {})
        if fld in out["allowed_values"]:
            # Intersecting is tighter
            out["allowed_values"][fld] = _intersect_values(out["allowed_values"][fld], vals)
        else:
            out["allowed_values"][fld] = _union_values(vals, [])

    for fld, prefix in extra.get("starts_with", {}).items():
        out.setdefault("starts_with", {})
        _merge_starts_with(out["starts_with"], fld, prefix)

    for fld, bound in extra.get("max_value", {}).items():
        out.setdefault("max_value", {})
        existing = out["max_value"].get(fld)
        out["max_value"][fld] = min(existing, bound) if existing is not None else bound

    for fld, bound in extra.get("min_value", {}).items():
        out.setdefault("min_value", {})
        existing = out["min_value"].get(fld)
        out["min_value"][fld] = max(existing, bound) if existing is not None else bound

    if "required_present" in extra:
        out.setdefault("required_present", [])
        out["required_present"] = sorted(
            set(out["required_present"]) | set(extra["required_present"])
        )

    if "forbidden_field_combinations" in extra:
        out.setdefault("forbidden_field_combinations", [])
        merged = {tuple(sorted(c)) for c in out["forbidden_field_combinations"]}
        merged.update(tuple(sorted(c)) for c in extra["forbidden_field_combinations"])
        out["forbidden_field_combinations"] = sorted(sorted(c) for c in merged)

    return _normalise_constraints(out)


def _attenuation_violation(child: Capability, parent: Capability) -> str | None:
    """Return why *child* is NOT a valid attenuation of *parent*, or None if valid.

    Attenuation soundness (Theorem 1) is enforced at mint by ``attenuate`` — but
    a verifier walking a presented chain must re-check it independently, else a
    mis-minted or hostile child that merely *cites* a parent_id could carry
    BROADER permissions than its parent and still pass (round-6 F3). A valid
    child has: the same tool; an agent_id equal to or a dot-delimited descendant
    of the parent's; expiry no later than the parent's; not_before no earlier;
    and constraints at least as tight as the parent on every dimension.

    The constraint check reuses the narrowing meet: ``child ⊑ parent`` exactly
    when merging the parent with the child yields the child unchanged (the merge
    takes the tighter bound per dimension, so a looser child would be tightened
    back toward the parent and differ).
    """
    if child.tool != parent.tool:
        return f"child tool {child.tool!r} != parent tool {parent.tool!r}"
    if not (child.agent_id == parent.agent_id or child.agent_id.startswith(parent.agent_id + ".")):
        return f"child agent_id {child.agent_id!r} is not a descendant of {parent.agent_id!r}"
    if child.expires_at > parent.expires_at:
        return "child token outlives its parent"
    if child.not_before < parent.not_before:
        return "child not_before precedes its parent"
    try:
        merged = _merge_narrowing(parent.constraints, child.constraints)
    except ValueError as exc:
        return f"child constraints broaden the parent: {exc}"
    if merged != _normalise_constraints(child.constraints):
        return "child constraints are not a narrowing of the parent's"
    return None


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


@dataclass
class GateDecision:
    """Outcome of :meth:`CapabilityGate.check`."""

    allowed: bool
    reason: str
    token_id: str | None = None
    chain: list[str] = field(default_factory=list)

    @property
    def denied(self) -> bool:
        return not self.allowed


class CapabilityGate:
    """The choke point. No token, no tool execution.

    Parameters
    ----------
    trusted_issuers
        Mapping of ``key_id -> public_key_pem``. Tokens signed by any other
        key are rejected. There is no global root.
    parent_resolver
        Callable ``(token_id) -> Capability | None`` that resolves a token's
        ancestors so the gate can re-verify the whole attenuation chain
        (signatures, narrowing, revocation depth) independently of mint.

        **Fail-closed (§8.7):** a token that carries a ``parent_id`` but is
        presented to a gate with **no** ``parent_resolver`` is DENIED — the gate
        cannot verify the chain, so it does not trust that the issuer minted it
        correctly. Supply a resolver to use attenuated/derived tokens. Root
        tokens (no ``parent_id``) are unaffected.
    """

    def __init__(
        self,
        *,
        trusted_issuers: dict[str, str],
        parent_resolver: Any = None,
        proof_enforcement_mode: str = "off",
        trusted_proofs: dict[str, ProofResult] | None = None,
        revoked_token_ids: set[str] | None = None,
        pq_public_keys: dict[str, str] | None = None,
    ) -> None:
        """Construct a CapabilityGate.

        Parameters
        ----------
        trusted_issuers
            ``{key_id: public_key_pem}``. Required.
        parent_resolver
            Optional. See class docstring.
        proof_enforcement_mode
            Defence-in-depth at gate time. One of:

            * ``"off"``     — default; ``policy_proof_hash`` on the
              token is informational. Gate behaviour unchanged.
            * ``"lenient"`` — if the token has a ``policy_proof_hash``
              and the proof is in ``trusted_proofs``, the gate verifies
              the proof is ``PROVEN`` and that the token's ``grammar_hash`` /
              ``policy_hash`` match the proof's. Missing proofs are
              logged at ``WARNING`` and the call is allowed to proceed.
            * ``"strict"``  — token MUST carry ``policy_proof_hash``,
              the proof MUST be in ``trusted_proofs``, it MUST be
              ``PROVEN``, and ``grammar_hash`` / ``policy_hash`` MUST
              match. Any miss is a DENY with an explicit reason.

            [DECIDE: gate-time proof enforcement] — the gate uses an
            in-memory ``trusted_proofs`` cache. Fetching proofs from a
            published policy registry at runtime (with TTL caching and
            signature verification on the manifest) is a phase-2 feature
            scoped separately; until that lands, operators that want
            lenient / strict mode supply the cache themselves at boot.
        trusted_proofs
            Optional. ``{proof_hash: ProofResult}`` cache consulted in
            ``"lenient"`` / ``"strict"`` modes. Ignored when mode is
            ``"off"``.
        """
        if not trusted_issuers:
            raise ValueError("CapabilityGate requires at least one trusted issuer")
        if proof_enforcement_mode not in {"off", "lenient", "strict"}:
            raise ValueError(
                f"proof_enforcement_mode must be 'off' | 'lenient' | 'strict'; "
                f"got {proof_enforcement_mode!r}"
            )
        self._issuers = dict(trusted_issuers)
        self._resolver = parent_resolver
        self._proof_mode = proof_enforcement_mode
        self._trusted_proofs: dict[str, ProofResult] = dict(trusted_proofs or {})
        self._revoked: set[str] = set(revoked_token_ids or ())
        # ML-DSA-65 keys for hybrid tokens: pq_key_id -> PEM string. A token
        # carrying pq_key_id fails closed when it cannot be verified here.
        self._pq_public_keys: dict[str, Any] = {}
        for kid, pem in (pq_public_keys or {}).items():
            try:
                from raucle.pq import pq_public_key_from_pem

                self._pq_public_keys[kid] = pq_public_key_from_pem(pem)
            except Exception:
                self._pq_public_keys[kid] = None

    def revoke(self, token_id: str) -> None:
        """Add a token id to this gate's revocation denylist.

        A revoked token (or any child that cites it as ``parent_id``) is
        DENY'd even if its signature and expiry are still valid. This is
        the early-revocation path that complements short TTLs; for fleets
        of gates, distribute the denylist out of band (a phase-2 signed
        revocation feed is scoped separately).

        .. important::

            **Revocation depth requires a ``parent_resolver`` (round-3 #17).**
            Without one, the gate can only check the token itself and its
            *immediate* ``parent_id`` against the denylist — revoking a
            grandparent does NOT deny a grandchild, because the gate cannot
            walk past the direct parent. Construct the gate with a
            ``parent_resolver`` to make revocation reach the whole ancestor
            chain. Deep revocation is bounded in its absence only by token TTL,
            so keep TTLs short if you rely on revocation without a resolver.
        """
        self._revoked.add(token_id)

    def _check_revocation(self, token: Capability) -> GateDecision | None:
        """Return a DENY decision if the token or its parent is revoked."""
        if token.token_id in self._revoked:
            return GateDecision(False, f"token {token.token_id} is revoked", token.token_id)
        if token.parent_id is not None and token.parent_id in self._revoked:
            return GateDecision(False, f"parent token {token.parent_id} is revoked", token.token_id)
        return None

    def _check_agent_id(self, token: Capability, agent_id: str) -> GateDecision | None:
        """Return a DENY decision if the caller agent_id is invalid."""
        if not _AGENT_ID_RE.match(agent_id):
            return GateDecision(False, f"malformed caller agent_id {agent_id!r}", token.token_id)
        if agent_id != token.agent_id and not agent_id.startswith(token.agent_id + "."):
            return GateDecision(
                False,
                f"agent_id {agent_id!r} does not match token's {token.agent_id!r}",
                token.token_id,
            )
        return None

    def check(
        self,
        token: Capability,
        *,
        tool: str,
        agent_id: str | None = None,
        args: dict[str, Any] | None = None,
        now: int | None = None,
    ) -> GateDecision:
        ts = now if now is not None else _now()
        args = args or {}

        # 1) Issuer pinned?
        pem = self._issuers.get(token.key_id)
        if pem is None:
            return GateDecision(False, f"unknown key_id {token.key_id!r}", token.token_id)

        # 2) Signature valid?
        try:
            self._verify_signature(token, pem)
        except ValueError as exc:
            return GateDecision(False, f"bad signature: {exc}", token.token_id)

        # 2.5) Quantum hybrid component (raucle/pq1). When the token carries
        # a pq_key_id, the ML-DSA-65 signature over the SAME canonical body
        # must verify too - fail-closed, no classical-only acceptance of a
        # hybrid token (the AND rule; mirrors pq1 receipts and checkpoints).
        if token.pq_key_id is not None:
            pq_key = self._pq_public_keys.get(token.pq_key_id)
            if pq_key is None:
                return GateDecision(
                    False,
                    f"token carries pq_key_id {token.pq_key_id!r} but the gate "
                    "has no matching ML-DSA-65 key; hybrid token cannot be "
                    "verified (fail-closed)",
                    token.token_id,
                )
            try:
                from raucle.pq import _b64url_decode

                pq_sig = _b64url_decode(token.pq_signature or "")
                if len(pq_sig) != 3309:
                    raise ValueError(f"ML-DSA-65 signature must be 3309 bytes, got {len(pq_sig)}")
                pq_key.verify(pq_sig, _canonical_json(token.body()))
            except Exception as exc:
                return GateDecision(
                    False,
                    f"hybrid ML-DSA-65 component failed verification: {exc}",
                    token.token_id,
                )

        # 3) token_id matches body?
        expected_id = "cap:" + _sha256_hex(_canonical_json(token.body()))[:24]
        if expected_id != token.token_id:
            return GateDecision(False, "token_id does not match body", token.token_id)

        # 3.5) Revocation denylist (early revocation before expiry).
        # A revoked token, or any child that cites a revoked token as its
        # parent, is refused.
        revocation = self._check_revocation(token)
        if revocation is not None:
            return revocation

        # 4) Time bounds.
        if ts < token.not_before:
            return GateDecision(False, "token not yet valid", token.token_id)
        if ts >= token.expires_at:
            return GateDecision(False, "token expired", token.token_id)

        # 5) Tool match.
        if token.tool != tool:
            return GateDecision(
                False, f"token bound to tool {token.tool!r}, called {tool!r}", token.token_id
            )

        # 6) Agent match (when supplied). A caller's agent_id must equal the
        # token's, or be a *dot-delimited descendant* of it. The delimiter is
        # required so that 'agent:billing' does NOT authorise 'agent:billing-evil'
        # (a bare prefix check would — CVE-class privilege escalation).
        if agent_id is not None:
            agent_decision = self._check_agent_id(token, agent_id)
            if agent_decision is not None:
                return agent_decision

        # 7) Argument constraints. Fail closed: any unexpected error while
        # evaluating constraints is a DENY, never a propagated exception — the
        # gate is a choke point and must never crash open.
        try:
            why = _check_constraints(token.constraints, args)
        except Exception:  # pragma: no cover - defensive
            # Full traceback goes to the server-side log only; the decision
            # reason is caller-visible and must not leak evaluation internals.
            logger.exception("constraint evaluation raised for token %s; denying", token.token_id)
            return GateDecision(False, "constraint evaluation error (deny)", token.token_id)
        if why:
            return GateDecision(False, f"constraint violated: {why}", token.token_id)

        # 7.5) Proof enforcement (defence-in-depth at gate time).
        # In "off" mode this is a no-op. In "lenient" / "strict" the
        # gate consults the in-memory ``trusted_proofs`` cache and
        # verifies the cited proof is PROVEN and that the token's bound
        # grammar/policy hashes match.
        if self._proof_mode != "off":
            proof_decision = self._check_proof_binding(token)
            if proof_decision is not None:
                return proof_decision

        # 8) Chain verification. A token that cites a parent_id MUST have its
        # ancestry verified; with no parent_resolver configured the gate cannot
        # do so and must fail closed rather than silently trust that the issuer
        # minted the chain correctly (§8.7 — unresolved-chain DENY). Otherwise a
        # hostile child citing a parent_id it never had to justify slips through
        # whenever the deployment forgot to wire a resolver.
        chain: list[str] = []
        if token.parent_id is not None and self._resolver is None:
            return GateDecision(
                False,
                f"token cites parent {token.parent_id!r} but no parent_resolver "
                f"is configured to verify the chain (deny)",
                token.token_id,
            )
        if token.parent_id is not None and self._resolver is not None:
            chain_decision = self._verify_ancestor_chain(token, chain)
            if chain_decision is not None:
                return chain_decision

        return GateDecision(True, "ok", token.token_id, chain)

    def _verify_ancestor_chain(self, token: Capability, chain: list[str]) -> GateDecision | None:
        """Walk the ancestor chain, verifying each link.

        Returns a DENY GateDecision on the first failure, or None if the
        entire chain is valid (``chain`` is updated in place).
        """
        current = token
        while current.parent_id:
            parent = self._resolver(current.parent_id)
            if parent is None:
                return GateDecision(
                    False,
                    f"unresolved parent {current.parent_id!r}",
                    token.token_id,
                    chain,
                )
            pem2 = self._issuers.get(parent.key_id)
            if pem2 is None:
                return GateDecision(
                    False,
                    f"parent {parent.token_id} signed by untrusted key",
                    token.token_id,
                    chain,
                )
            try:
                self._verify_signature(parent, pem2)
            except ValueError as exc:
                return GateDecision(
                    False,
                    f"parent {parent.token_id} bad signature: {exc}",
                    token.token_id,
                    chain,
                )
            # Revocation must reach the whole ancestor chain, not just the
            # token's direct parent. Revoking any ancestor denies every
            # descendant when a resolver is present (REVOKE-DEPTH).
            if parent.token_id in self._revoked:
                return GateDecision(
                    False,
                    f"ancestor token {parent.token_id} is revoked",
                    token.token_id,
                    chain,
                )
            # Attenuation soundness: every link must be a valid narrowing of
            # its parent — a child that cites a parent but broadens tool /
            # agent scope / expiry / constraints is rejected (round-6 F3).
            att = _attenuation_violation(current, parent)
            if att is not None:
                return GateDecision(
                    False,
                    f"invalid attenuation of {parent.token_id}: {att}",
                    token.token_id,
                    chain,
                )
            chain.append(parent.token_id)
            current = parent
        return None

    def _check_proof_binding(self, token: Capability) -> GateDecision | None:
        """Gate-time proof enforcement. Returns ``None`` to allow, or a
        DENY :class:`GateDecision` to reject.

        Behaviour depends on ``self._proof_mode``:

        * ``"lenient"`` — missing proof is logged at ``WARNING`` and
          allowed. Present-but-invalid (REFUTED / UNDECIDED / hash
          mismatch) is denied.
        * ``"strict"`` — missing proof, missing binding, or any
          discrepancy is denied.
        """
        strict = self._proof_mode == "strict"

        if not token.policy_proof_hash:
            if strict:
                return GateDecision(
                    False,
                    "strict proof mode: token has no policy_proof_hash",
                    token.token_id,
                )
            return None  # lenient: no proof to check

        proof = self._trusted_proofs.get(token.policy_proof_hash)
        if proof is None:
            msg = f"policy_proof_hash {token.policy_proof_hash!r} not in trusted_proofs cache"
            if strict:
                return GateDecision(False, f"strict proof mode: {msg}", token.token_id)
            logger.warning("lenient proof mode: %s", msg)
            return None

        mismatch = self._check_proof_hash_mismatch(token, proof)
        if mismatch is not None:
            return mismatch

        if strict and not (token.grammar_hash and token.policy_hash):
            return GateDecision(
                False,
                "strict proof mode: token missing grammar_hash or policy_hash binding",
                token.token_id,
            )
        # Bind the PROOF to what the gate actually ENFORCES. Without this, a
        # token could cite a PROVEN proof over an unrelated policy while
        # carrying entirely different constraints — making "formally proven"
        # decorative. In strict mode the token's policy_hash MUST equal the
        # hash of its own (normalised) constraints, which the prior checks
        # already tie to the proof's policy_hash. (The proof must therefore be
        # generated over the capability's normalised constraints — the
        # documented, correct usage.)
        if strict:
            enforced_hash = "sha256:" + _sha256_hex(
                _canonical_json(_normalise_constraints(token.constraints))
            )
            if token.policy_hash != enforced_hash:
                return GateDecision(
                    False,
                    "strict proof mode: token.policy_hash does not match the hash of the "
                    "constraints the gate enforces — the proof is not bound to this token's policy",
                    token.token_id,
                )
        return None

    @staticmethod
    def _check_proof_hash_mismatch(token: Capability, proof: Any) -> GateDecision | None:
        """Check proof status and hash binding. Returns a DENY decision or None."""
        if proof.status != "PROVEN":
            return GateDecision(
                False,
                f"proof for {token.policy_proof_hash!r} is {proof.status!r}, not PROVEN",
                token.token_id,
            )
        if token.grammar_hash and token.grammar_hash != proof.grammar_hash:
            return GateDecision(
                False,
                f"token grammar_hash {token.grammar_hash!r} does not match "
                f"proof grammar_hash {proof.grammar_hash!r}",
                token.token_id,
            )
        if token.policy_hash and token.policy_hash != proof.policy_hash:
            return GateDecision(
                False,
                f"token policy_hash {token.policy_hash!r} does not match "
                f"proof policy_hash {proof.policy_hash!r}",
                token.token_id,
            )
        return None

    @staticmethod
    def _verify_signature(token: Capability, pem: str) -> None:
        serialization, _ed, _invalid_sig = _require_crypto()
        pub = serialization.load_pem_public_key(pem.encode("ascii"))
        try:
            pub.verify(_b64d(token.signature), _canonical_json(token.body()))
        except _invalid_sig as exc:
            raise ValueError(str(exc)) from exc
        except (ValueError, TypeError) as exc:
            # Decode errors (bad base64, malformed key) — fail closed but with
            # a controlled ValueError rather than letting the raw exception
            # propagate. Unexpected exceptions are NOT caught here: they
            # surface as bugs rather than silent verification failures.
            raise ValueError(str(exc)) from exc


def _is_number(v: Any) -> bool:
    # bool is a subclass of int — exclude it so True/False can't pass numeric bounds.
    # Reject non-finite floats (NaN / +inf / -inf): NaN comparisons are always
    # False, so a NaN argument would otherwise satisfy BOTH max_value and
    # min_value bounds, slipping past every numeric guard (GATE-NaN).
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    if isinstance(v, float):
        return math.isfinite(v)
    return False


def _flatten_scalars(val: Any) -> Any:
    """Yield every scalar contained in *val*, recursing into list/tuple/set/dict.

    A ``forbidden_values`` blacklist must catch a forbidden value wherever it
    appears in an argument — including hidden inside a collection. Without this,
    ``to=["attacker@evil"]`` (a list) or ``to={"x":"attacker@evil"}`` (a dict)
    would slip past a scalar ``args[fld] in bads`` check (capability-constraint
    bypass). Dict keys are included too (fail-safe).
    """
    if isinstance(val, dict):
        for k, v in val.items():
            yield k
            yield from _flatten_scalars(v)
    elif isinstance(val, (list, tuple, set, frozenset)):
        for v in val:
            yield from _flatten_scalars(v)
    else:
        yield val


def _check_constraints(c: dict[str, Any], args: dict[str, Any]) -> str | None:
    """Return a non-empty reason string on violation, or None on pass.

    Security model: **positive and bound constraints fail closed**. A field
    named by an ``allowed_values`` / ``starts_with`` / ``max_value`` /
    ``min_value`` constraint that is *absent* from the call is a violation —
    an absent field cannot be shown to satisfy the constraint, and allowing
    it would let a caller bypass the rule by omitting (or aliasing) the
    argument name. Numeric bounds additionally reject non-numeric values
    (and booleans) with a DENY rather than raising.

    Caveat (documented limitation): the gate enforces on the argument *names*
    declared in the policy. It does not know the tool's parameter schema, so a
    ``forbidden_values`` blacklist can still be evaded if the tool reads the
    forbidden value under a different parameter name. Prefer ``allowed_values``
    whitelists (which fail closed) over ``forbidden_values`` blacklists for
    security-critical fields; binding the gate to the tool's declared schema is
    tracked as a future hardening.
    """
    # Registry-driven fail-closed guard: any constraint kind that is not in the
    # Modelled Language Registry must DENY rather than be silently ignored. The
    # mint/normalise path already rejects unknown keys, but the gate is the
    # trust boundary and re-checks independently (defence in depth).
    for kind in c:
        if kind not in _registry.CONSTRAINT_REGISTRY:
            return f"unmodelled constraint kind {kind!r} reached the gate (deny)"

    # Collection-arg semantics are EXACT per §8.6 (registry rows). The shared
    # principle: a collection value can never be used to smuggle a value past a
    # check — blacklists deny on ANY contained scalar (exists), positive/bound
    # constraints require ALL contained scalars to satisfy (for-all).

    checkers = [
        _check_forbidden_values,
        _check_allowed_values,
        _check_starts_with,
        _check_max_value,
        _check_min_value,
        _check_required_present,
        _check_forbidden_combinations,
    ]
    for checker in checkers:
        reason = checker(c, args)
        if reason:
            return reason
    return None


def _check_forbidden_values(c: dict[str, Any], args: dict[str, Any]) -> str | None:
    """forbidden_values — EXISTS_DENY: a present, forbidden scalar anywhere in
    the argument (incl. nested in a list/dict, keys included) is a violation."""
    for fld, bads in c.get("forbidden_values", {}).items():
        if fld not in args:
            continue
        for scalar in _flatten_scalars(args[fld]):
            if scalar in bads:
                return f"{fld}={scalar!r} is in forbidden_values"
    return None


def _check_allowed_values(c: dict[str, Any], args: dict[str, Any]) -> str | None:
    """allowed_values — FORALL_ALLOW: field MUST be present and EVERY contained
    scalar must be in the allowed set."""
    for fld, oks in c.get("allowed_values", {}).items():
        if fld not in args:
            return f"allowed_values field {fld!r} is absent from the call"
        scalars = list(_flatten_scalars(args[fld]))
        if not scalars:
            return f"allowed_values field {fld!r} carries no value to check"
        for scalar in scalars:
            if scalar not in oks:
                return f"{fld} contains {scalar!r} which is not in allowed_values"
    return None


def _check_starts_with(c: dict[str, Any], args: dict[str, Any]) -> str | None:
    """starts_with — STRING_ONLY: field MUST be present and be a string with the
    prefix. Any non-string (including any collection) is denied."""
    for fld, prefix in c.get("starts_with", {}).items():
        if fld not in args:
            return f"starts_with field {fld!r} is absent from the call"
        if not (isinstance(args[fld], str) and args[fld].startswith(prefix)):
            return f"{fld}={args[fld]!r} does not start with {prefix!r}"
    return None


def _check_max_value(c: dict[str, Any], args: dict[str, Any]) -> str | None:
    """max_value — FORALL_NUMERIC: field MUST be present and EVERY contained
    scalar must be a finite non-bool number satisfying the upper bound."""
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
                return f"{fld} contains {scalar!r} exceeding max_value {bound!r}"
    return None


def _check_min_value(c: dict[str, Any], args: dict[str, Any]) -> str | None:
    """min_value — FORALL_NUMERIC: field MUST be present and EVERY contained
    scalar must be a finite non-bool number satisfying the lower bound."""
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
                return f"{fld} contains {scalar!r} below min_value {bound!r}"
    return None


def _check_required_present(c: dict[str, Any], args: dict[str, Any]) -> str | None:
    """required_present — PRESENCE: only the field's presence matters."""
    for fld in c.get("required_present", []):
        if fld not in args:
            return f"required field {fld!r} missing"
    return None


def _check_forbidden_combinations(c: dict[str, Any], args: dict[str, Any]) -> str | None:
    """forbidden_field_combinations — PRESENCE: deny if all fields in a
    forbidden combination are present."""
    for combo in c.get("forbidden_field_combinations", []):
        if all(c2 in args for c2 in combo):
            return f"forbidden field combination {combo!r} all present"
    return None
