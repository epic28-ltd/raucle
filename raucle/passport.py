"""Agent passport (P3) — a portable, registry-anchored agent identity.

An agent's :class:`~raucle.provenance.CapabilityStatement` already binds
``agent_id -> public key -> allowed tools/models``. But it is *self-signed*: it
says what the agent claims about itself. A **passport** adds the missing vouch —
the **issuing organisation countersigns it** with its issuer key, and that issuer
is resolvable in the shared :mod:`~raucle.trust_registry`. So a verifier in
any org, in any framework, can check one portable artifact and learn:

    "Org X (an issuer known to the registry) vouches that agent:Y holds key K and
     may use tools/models Z, until time T."

That is the cross-framework identity primitive: one signed file an agent carries,
verifiable offline against the registry, that any integration (LangChain, CrewAI,
Agent Framework, MCP, A2A) can anchor on before enforcing the agent's scope.

Verification is **fail-closed**: an issuer whose key is unknown or revoked in the
registry, a bad signature, or an expired passport all yield an invalid verdict.

Usage::

    from raucle.passport import issue_passport, verify_passport
    passport = issue_passport(identity.statement, issuer_signer=org_signer, issuer="Org X")
    verdict = verify_passport(passport.to_dict(), registry=shared_registry)
    if verdict.valid:
        # trust verdict.agent_id <-> verdict.key_id and verdict.allowed_tools

CLI: ``raucle passport issue|verify``.
"""

from __future__ import annotations

import base64 as _base64
import datetime as _dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raucle._paths import validate_path
from raucle.audit import Ed25519Signer, _canonical_json, _sha256_hex
from raucle.provenance import CapabilityStatement
from raucle.trust_registry import _MAX_CLOCK_SKEW_SECONDS

#: Passport format identifier.
PASSPORT_VERSION = "agent-passport/v1"


def _now() -> int:
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp())


def _b64(data: bytes) -> str:
    return _base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return _base64.urlsafe_b64decode(data + padding)


def _issuer_key_id(public_pem: bytes) -> str:
    return _sha256_hex(public_pem)[:16]


@dataclass
class AgentPassport:
    """An issuer-countersigned, registry-anchorable agent identity document."""

    statement: dict[str, Any]  # the subject's CapabilityStatement (.to_dict())
    issuer: str
    issuer_key_id: str
    issued_at: int
    expires_at: int | None = None
    issuer_signature: str = ""
    version: str = PASSPORT_VERSION

    def body(self) -> dict[str, Any]:
        """Canonical body the issuer signs (excludes the signature).

        ``version`` is part of the signed body (read from the field, not a
        constant), so a tampered version either fails the version check or
        breaks the signature.
        """
        return {
            "version": self.version,
            "statement": self.statement,
            "issuer": self.issuer,
            "issuer_key_id": self.issuer_key_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.body()
        d["issuer_signature"] = self.issuer_signature
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AgentPassport:
        return cls(
            statement=d["statement"],
            issuer=d["issuer"],
            issuer_key_id=d["issuer_key_id"],
            issued_at=int(d["issued_at"]),
            expires_at=d.get("expires_at"),
            issuer_signature=d.get("issuer_signature", ""),
            version=d.get("version", PASSPORT_VERSION),
        )

    def save(self, path: str | Path) -> None:
        validate_path(path, must_exist=False).write_text(
            json.dumps(self.to_dict(), indent=2), encoding="utf-8"
        )

    @classmethod
    def load(cls, path: str | Path) -> AgentPassport:
        return cls.from_dict(json.loads(validate_path(path).read_text(encoding="utf-8")))


@dataclass
class PassportVerdict:
    """Outcome of verifying a passport against the registry."""

    valid: bool
    reason: str = ""
    agent_id: str = ""
    key_id: str = ""
    issuer: str = ""
    allowed_tools: list[str] = field(default_factory=list)
    allowed_models: list[str] = field(default_factory=list)


def issue_passport(
    statement: Any,
    *,
    issuer_signer: Ed25519Signer,
    issuer: str,
    ttl_seconds: int | None = None,
) -> AgentPassport:
    """Issue (countersign) a passport for an agent's capability statement.

    ``statement`` is a ``CapabilityStatement`` (or its ``.to_dict()``). The
    issuing org signs the passport body with ``issuer_signer``; that issuer key
    must be published to the trust registry for verifiers to resolve it.

    ``ttl_seconds`` must be a POSITIVE integer when given (Q10, a second
    external review of the main branch, P1): ``0`` never means "no expiry"
    (it is refused by name, because the old ``if ttl_seconds else None``
    shape silently turned it into a never-expiring passport) and a negative
    ttl is refused rather than minting an already-expired passport. ``None``
    is the documented no-expiry mode (the CLI's ``--ttl`` default) and keeps
    its meaning.
    """
    stmt = statement.to_dict() if hasattr(statement, "to_dict") else dict(statement)
    issued_at = _now()
    if ttl_seconds is not None and (
        isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds <= 0
    ):
        raise ValueError(
            f"ttl_seconds must be a positive integer number of seconds, got "
            f"{ttl_seconds!r}; pass None for the documented no-expiry mode"
        )
    passport = AgentPassport(
        statement=stmt,
        issuer=issuer,
        issuer_key_id=_issuer_key_id(issuer_signer.public_key_pem()),
        issued_at=issued_at,
        expires_at=(issued_at + ttl_seconds) if ttl_seconds is not None else None,
    )
    passport.issuer_signature = _b64(issuer_signer.sign(_canonical_json(passport.body())))
    return passport


def _parse_passport(passport: dict[str, Any] | AgentPassport) -> AgentPassport | PassportVerdict:
    """Parse and validate the passport shape, fail-closed (codex #7)."""
    try:
        p = passport if isinstance(passport, AgentPassport) else AgentPassport.from_dict(passport)
        if not isinstance(p.statement, dict) or not isinstance(p.issuer_key_id, str):
            return PassportVerdict(False, "malformed passport (bad statement/issuer_key_id)")
        # Strict expiry type: a numeric STRING would pass int() coercion and
        # signature verification, then crash the ts >= expires_at comparison —
        # a verifier DoS instead of fail-closed (codex r9). bool is an int
        # subclass, so exclude it explicitly.
        if p.expires_at is not None and (
            not isinstance(p.expires_at, int) or isinstance(p.expires_at, bool)
        ):
            return PassportVerdict(False, "malformed passport (expires_at must be an integer)")
        return p
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return PassportVerdict(False, f"malformed passport: {type(exc).__name__}")


def _verify_passport_signature(p: AgentPassport, pem: str) -> PassportVerdict | None:
    """Verify the issuer signature. Returns a failure verdict or None on success."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        loaded = serialization.load_pem_public_key(pem.encode())
        if not isinstance(loaded, Ed25519PublicKey):
            return PassportVerdict(False, "issuer key is not Ed25519")
        loaded.verify(_b64d(p.issuer_signature), _canonical_json(p.body()))
    except (InvalidSignature, ValueError, TypeError):
        return PassportVerdict(False, "issuer signature did not verify")
    return None


def verify_passport(
    passport: dict[str, Any] | AgentPassport,
    *,
    registry: Any,
    now: int | None = None,
) -> PassportVerdict:
    """Verify a passport **fail-closed** against the shared trust registry.

    Checks, in order: known version → the vouched statement passes structural
    validation (the production ``CapabilityStatement`` parser, Q10) → issuer
    key resolves to an *active* key in the registry (unknown/revoked →
    invalid) → issuer signature verifies → issued_at not in the future beyond
    the clock-skew allowance (Q10) → not expired. On success the verdict
    carries the vouched agent identity and its allowed tools/models, ready
    for a framework integration to enforce.
    """
    # Fail-closed on ANY malformed input — a parse/shape error must yield an
    # invalid verdict, never an exception (codex #7).
    parsed = _parse_passport(passport)
    if isinstance(parsed, PassportVerdict):
        return parsed
    p = parsed

    if p.body().get("version") != PASSPORT_VERSION:
        return PassportVerdict(False, f"unknown passport version {p.body().get('version')!r}")

    # Structural validation of the vouched statement (Q10, P1): reuse the
    # production ``CapabilityStatement`` parser rather than re-implementing
    # it. A statement with unknown fields or wrong shapes fails with a named
    # reason DISTINCT from unknown statements/issuers.
    try:
        CapabilityStatement.from_dict(p.statement)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        return PassportVerdict(False, f"passport statement failed structural validation: {exc}")

    # Resolve the registry RECORD (not just the key) so we can check the
    # authoritative issuer identity, not the passport's self-asserted one.
    record = registry.resolve(p.issuer_key_id)
    if record is None or record.revoked:
        why = "revoked" if (record is not None and record.revoked) else "unknown"
        return PassportVerdict(False, f"issuer key_id {p.issuer_key_id} is {why} in the registry")

    sig_verdict = _verify_passport_signature(p, record.public_key_pem)
    if sig_verdict is not None:
        return sig_verdict

    # Anti-impersonation: the issuer NAME the passport claims must match the
    # registry's authoritative record for this key. Otherwise a registered org
    # could sign a passport claiming to be a DIFFERENT org (codex #2).
    if p.issuer != record.issuer:
        return PassportVerdict(
            False,
            f"issuer mismatch: passport claims {p.issuer!r} but key {p.issuer_key_id} "
            f"is registered to {record.issuer!r}",
        )

    ts = now if now is not None else _now()
    # issued_at must not sit in the future beyond a small clock-skew
    # allowance (Q10, P1): the same allowance the trust registry applies
    # to signed heads, so warm clocks do not fail closed.
    if p.issued_at > ts + _MAX_CLOCK_SKEW_SECONDS:
        return PassportVerdict(
            False,
            f"passport issued_at {p.issued_at} is in the future (now {ts}, "
            f"allowed skew {_MAX_CLOCK_SKEW_SECONDS}s)",
        )
    if p.expires_at is not None and ts >= p.expires_at:
        return PassportVerdict(False, f"passport expired at {p.expires_at}")

    stmt = p.statement
    return PassportVerdict(
        valid=True,
        reason="passport verified against registry",
        agent_id=stmt.get("agent_id", ""),
        key_id=stmt.get("key_id", ""),
        issuer=p.issuer,
        allowed_tools=list(stmt.get("allowed_tools") or []),
        allowed_models=list(stmt.get("allowed_models") or []),
    )


__all__ = [
    "PASSPORT_VERSION",
    "AgentPassport",
    "PassportVerdict",
    "issue_passport",
    "verify_passport",
]
