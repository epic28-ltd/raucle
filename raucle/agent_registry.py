"""Agent registry: enrolment schema and signed descriptor (P1.4a, F4).

An agent identity carrying attestation metadata, published as a signed
descriptor that a verifier can check **offline** (one Ed25519 signature over
the canonical descriptor body, no registry lookup, no network).

Additive reuse, not a fork: this module sits beside the existing identity
machinery rather than replacing it.

- The signing primitives (:class:`Ed25519Signer`, canonical JSON, SHA-256)
  come from :mod:`raucle.audit`, the same ones behind passports,
  provenance receipts and the trust registry.
- The descriptor's ``operator_binding`` names the agent's *operator*
  identity; enrolment through :meth:`AgentRegistry.enrol` can bind the
  enrolment to an :class:`~raucle.agent_credentials.AgentCredentialStore`
  record (the ``rak_`` credential the gate already authenticates), so the
  registry and the gate credential store resolve the same ``agent_id``
  rather than the registry introducing a second credential namespace.
- Revocation-style state changes follow the trust registry's append-only
  discipline: an update or a retire is a NEW signed descriptor appended to
  the store; nothing is ever rewritten, so history is auditable.

Schema versioning discipline (mirrors :mod:`raucle.registry` and
``PASSPORT_VERSION``): the descriptor carries ``version`` inside the SIGNED
body; verification fails closed on an unknown version and on any top-level
field outside the allowlist, so an unregistered field can never ride a
signature through.

Honest scope: the descriptor records the attested agent-card/manifest
**hash** and signs over it. What that signature vouches for is "the operator
enrolled this hash", nothing more; whether the manifest itself is sound is
the admission story (P1.4c), not this module.

CLI: ``raucle agent-registry enrol|retire|list|resolve|verify`` (see
:mod:`raucle.cli`).
"""

from __future__ import annotations

import base64 as _base64
import datetime as _dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raucle._canon import make_duplicate_key_rejecter
from raucle.audit import Ed25519Signer, _canonical_json, _sha256_hex

#: Descriptor format version, stamped inside the signed body. Bumping this
#: requires an explicit verifier-side entry in ``KNOWN_VERSIONS`` below;
#: anything else is refused (fail-closed versioning discipline).
DESCRIPTOR_VERSION = "agent-descriptor/v1"

#: Versions this build's verifier accepts. v1 only: there are no registered
#: migrations yet, so an unknown version fails verification rather than being
#: best-effort parsed (the same rule as the receipt envelope's crit check).
KNOWN_VERSIONS: frozenset[str] = frozenset({DESCRIPTOR_VERSION})

#: Hash prefix required on ``attested_manifest_hash`` (byte-comparable
#: attestation: the digest is checked for shape at enrolment and again at
#: verification, so a freetext "manifest" cannot ride the signed body).
_MANIFEST_HASH_PREFIX = "sha256:"

#: Attestation source kinds accepted at enrolment. An unknown kind is
#: rejected: the descriptor is vouching for a specific kind of artefact.
MANIFEST_KINDS: frozenset[str] = frozenset({"agent-card", "manifest", "agent-json"})

#: Top-level fields of a descriptor body (everything the issuer signs
#: except the signature itself). Verification rejects any field outside
#: this set; new fields arrive via a version bump only.
DESCRIPTOR_BODY_FIELDS: frozenset[str] = frozenset(
    {
        "version",
        "agent_id",
        "operator",
        "operator_binding",
        "status",
        "attested_manifest_hash",
        "attested_manifest_kind",
        "framework",
        "framework_version",
        "delegation_ceilings",
        "issued_at",
        "issuer_key_id",
    }
)

#: Allowed keys inside ``delegation_ceilings``. max_hops: the maximum number
#: of delegation hops between the operator's root grant and the agent's
#: token. max_scope: the maximum number of tools a delegation may carry.
#: lease_ceilings: lease-model ceilings the delegated receipt machinery
#: enforces (max_ttl_seconds, max_active_leases). Unknown keys fail closed.
CEILING_FIELDS: frozenset[str] = frozenset({"max_hops", "max_scope", "lease_ceilings"})

#: Lease ceiling sub-keys (optional, integers when present).
LEASE_CEILING_FIELDS: frozenset[str] = frozenset({"max_ttl_seconds", "max_active_leases"})

#: Enrolment lifecycle states. ``retired`` is fail-closed: a retired agent
#: resolves to an explicitly-retired record, never to a silently-active one.
STATUS_VALUES: frozenset[str] = frozenset({"enrolled", "retired"})

_reject_duplicate_keys = make_duplicate_key_rejecter("agent descriptor (JSON ambiguity)")


def _now() -> int:
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp())


def _b64(data: bytes) -> str:
    return _base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return _base64.urlsafe_b64decode(data + padding)


def _issuer_key_id(public_key_pem: bytes | str) -> str:
    """Canonical key_id: first 16 hex of SHA-256 over the PEM (cap:v1)."""
    pem = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
    return _sha256_hex(pem)[:16]


class DescriptorError(ValueError):
    """The descriptor is unusable or fails verification (no detail text
    beyond the check that failed)."""


@dataclass(frozen=True)
class Attestation:
    """The attested metadata an enrolled agent carries (P1.4a AC)."""

    # The sha256 digest of the agent-card/manifest the operator attested.
    # Byte-comparable: enrolment and verification both require the
    # ``sha256:`` prefix and 64 hex digits.
    attested_manifest_hash: str
    # What kind of artefact the hash digests.
    attested_manifest_kind: str
    # The agent framework and its version (free strings, non-empty).
    framework: str
    framework_version: str

    def validate(self) -> None:
        h = self.attested_manifest_hash
        if (
            not isinstance(h, str)
            or not h.startswith(_MANIFEST_HASH_PREFIX)
            or len(h) != len(_MANIFEST_HASH_PREFIX) + 64
            or any(c not in "0123456789abcdef" for c in h[len(_MANIFEST_HASH_PREFIX) :])
        ):
            raise DescriptorError(
                "attested_manifest_hash must be 'sha256:' + 64 lowercase hex digits"
            )
        if self.attested_manifest_kind not in MANIFEST_KINDS:
            raise DescriptorError("unknown attested_manifest_kind")
        for name in ("framework",):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise DescriptorError(f"{name} must be a non-empty string")
        if not isinstance(self.framework_version, str):
            raise DescriptorError("framework_version must be a string")


@dataclass(frozen=True)
class DelegationCeilings:
    """Delegation ceilings carried on the descriptor (P1.4a AC).

    These are the registry-side ceilings that admission (P1.4c) and the
    delegated receipt/lease machinery read; they mirror the constraint
    kinds the capability layer already models (hop counts, scope breadth,
    lease TTL) but live on the identity, not on a single token.
    """

    max_hops: int | None = None
    max_scope: int | None = None
    lease_ceilings: dict[str, int] = field(default_factory=dict)

    def validate(self) -> None:
        for name in ("max_hops", "max_scope"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                raise DescriptorError(f"{name} must be a non-negative integer")
        if not isinstance(self.lease_ceilings, dict):
            raise DescriptorError("lease_ceilings must be a mapping")
        for key, value in self.lease_ceilings.items():
            if key not in LEASE_CEILING_FIELDS:
                raise DescriptorError(f"unknown lease ceiling {key!r}")
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise DescriptorError(f"lease ceiling {key!r} must be a non-negative integer")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.max_hops is not None:
            out["max_hops"] = self.max_hops
        if self.max_scope is not None:
            out["max_scope"] = self.max_scope
        if self.lease_ceilings:
            out["lease_ceilings"] = dict(self.lease_ceilings)
        return out

    @classmethod
    def from_dict(cls, d: Any) -> DelegationCeilings:
        if not isinstance(d, dict):
            raise DescriptorError("delegation_ceilings must be a mapping")
        unknown = set(d) - CEILING_FIELDS
        if unknown:
            raise DescriptorError(f"unknown delegation ceiling fields: {sorted(unknown)}")
        return cls(
            max_hops=d.get("max_hops"),
            max_scope=d.get("max_scope"),
            lease_ceilings=dict(d.get("lease_ceilings") or {}),
        )


@dataclass
class AgentDescriptor:
    """One signed, offline-verifiable agent enrolment record."""

    agent_id: str
    operator: str
    operator_binding: str
    status: str
    attestation: Attestation
    ceilings: DelegationCeilings
    issued_at: int
    issuer_key_id: str
    version: str = DESCRIPTOR_VERSION
    issuer_signature: str = ""

    def body(self) -> dict[str, Any]:
        """The canonical signed body (the signature never signs itself)."""
        return {
            "version": self.version,
            "agent_id": self.agent_id,
            "operator": self.operator,
            "operator_binding": self.operator_binding,
            "status": self.status,
            "attested_manifest_hash": self.attestation.attested_manifest_hash,
            "attested_manifest_kind": self.attestation.attested_manifest_kind,
            "framework": self.attestation.framework,
            "framework_version": self.attestation.framework_version,
            "delegation_ceilings": self.ceilings.to_dict(),
            "issued_at": self.issued_at,
            "issuer_key_id": self.issuer_key_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "issuer_signature": self.issuer_signature}

    def save(self, path: str | Path) -> None:
        """One self-contained JSON file: the offline-verification unit."""
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def issue_descriptor(
    agent_id: str,
    *,
    operator: str,
    operator_binding: str,
    status: str,
    attestation: Attestation,
    ceilings: DelegationCeilings,
    signer: Ed25519Signer,
    issued_at: int = 0,
) -> AgentDescriptor:
    """Build, validate and sign one descriptor. Raises DescriptorError on
    any malformed field: an unusable record is never signed."""
    if not isinstance(agent_id, str) or not agent_id.strip():
        raise DescriptorError("agent_id must be a non-empty string")
    if not isinstance(operator, str) or not operator.strip():
        raise DescriptorError("operator must be a non-empty string")
    if not isinstance(operator_binding, str) or not operator_binding.strip():
        raise DescriptorError("operator_binding must be a non-empty string")
    if status not in STATUS_VALUES:
        raise DescriptorError("unknown status")
    attestation.validate()
    ceilings.validate()
    descriptor = AgentDescriptor(
        agent_id=agent_id,
        operator=operator,
        operator_binding=operator_binding,
        status=status,
        attestation=attestation,
        ceilings=ceilings,
        issued_at=int(issued_at) or _now(),
        issuer_key_id=_issuer_key_id(signer.public_key_pem()),
    )
    descriptor.issuer_signature = _b64(signer.sign(_canonical_json(descriptor.body())))
    return descriptor


@dataclass(frozen=True)
class DescriptorVerdict:
    """The offline-verification result (fail-closed shape)."""

    valid: bool
    reason: str = ""
    descriptor: AgentDescriptor | None = None


def parse_descriptor(d: Any) -> AgentDescriptor:
    """Rebuild a descriptor from its dict form with allowlist checks.
    Unknown top-level fields or an unknown version fail closed (the
    versioned-schema discipline)."""
    if not isinstance(d, dict):
        raise DescriptorError("descriptor must be a mapping")
    unknown = set(d) - DESCRIPTOR_BODY_FIELDS - {"issuer_signature"}
    if unknown:
        raise DescriptorError(f"unknown descriptor fields: {sorted(unknown)}")
    for required in ("version", "agent_id", "issuer_signature"):
        if required not in d:
            raise DescriptorError(f"missing field {required!r}")
    if d["version"] not in KNOWN_VERSIONS:
        raise DescriptorError(f"unsupported descriptor version {d['version']!r}")
    ceilings = DelegationCeilings.from_dict(d.get("delegation_ceilings") or {})
    attestation = Attestation(
        attested_manifest_hash=d.get("attested_manifest_hash", ""),
        attested_manifest_kind=d.get("attested_manifest_kind", ""),
        framework=d.get("framework", ""),
        framework_version=d.get("framework_version", ""),
    )
    return AgentDescriptor(
        agent_id=d["agent_id"],
        operator=d.get("operator", ""),
        operator_binding=d.get("operator_binding", ""),
        status=d.get("status", ""),
        attestation=attestation,
        ceilings=ceilings,
        issued_at=int(d.get("issued_at", 0)),
        issuer_key_id=d.get("issuer_key_id", ""),
        version=d["version"],
        issuer_signature=d["issuer_signature"],
    )


def verify_descriptor(
    descriptor: dict[str, Any] | AgentDescriptor,
    issuer_public_pem: bytes | str,
) -> DescriptorVerdict:
    """Verify one descriptor offline: body re-serialised canonically, the
    Ed25519 signature checked against the supplied issuer public key.

    Fail-closed on: unknown version, unknown fields, malformed attestation
    or ceilings, wrong signature, wrong issuer_key_id (the key must digest
    to the key_id inside the signed body). No registry access, no network.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        parsed = (
            descriptor if isinstance(descriptor, AgentDescriptor) else parse_descriptor(descriptor)
        )
        attestation = parsed.attestation
        parsed.ceilings.validate()
        attestation.validate()
        if parsed.status not in STATUS_VALUES:
            raise DescriptorError("unknown status")
    except DescriptorError as exc:
        return DescriptorVerdict(valid=False, reason=str(exc))

    pem = issuer_public_pem.encode() if isinstance(issuer_public_pem, str) else issuer_public_pem
    try:
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, Ed25519PublicKey):
            return DescriptorVerdict(valid=False, reason="issuer key is not Ed25519")
    except Exception:
        return DescriptorVerdict(valid=False, reason="issuer key is not parseable")

    verifying_pem = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # The signed body's key_id must be the real digest of the verifying key:
    # otherwise a foreign key could impersonate the issuer identity.
    if parsed.issuer_key_id != _issuer_key_id(verifying_pem):
        return DescriptorVerdict(valid=False, reason="issuer_key_id does not match key")
    try:
        key.verify(
            _b64d(parsed.issuer_signature),
            _canonical_json(parsed.body()),
        )
    except (InvalidSignature, ValueError):
        return DescriptorVerdict(valid=False, reason="signature invalid")
    return DescriptorVerdict(valid=True, descriptor=parsed)


class AgentRegistry:
    """Append-only store of signed descriptors over one JSONL file.

    Every state change (enrol, update, retire) appends a NEW signed
    descriptor; nothing is ever mutated in place, so history is fully
    auditable and any single entry verifies offline on its own (it
    carries no chain state). ``resolve`` folds to the latest entry for an
    agent; a retired agent resolves to its retirement record, fail-closed.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else None
        self._entries: list[dict[str, Any]] = []
        if self._path is not None and self._path.exists():
            self._load()

    def _load(self) -> None:
        assert self._path is not None
        text = self._path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                self._entries.append(json.loads(line, object_pairs_hook=_reject_duplicate_keys))
            except (json.JSONDecodeError, ValueError) as exc:
                raise DescriptorError(
                    f"agent registry {self._path} is corrupt (line {lineno})"
                ) from exc

    def _append(self, descriptor: AgentDescriptor) -> dict[str, Any]:
        record = descriptor.to_dict()
        self._entries.append(record)
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        return record

    def enrol(
        self,
        agent_id: str,
        *,
        operator: str,
        operator_binding: str,
        attestation: Attestation,
        ceilings: DelegationCeilings | None = None,
        signer: Ed25519Signer,
        credential_store: Any = None,
    ) -> tuple[dict[str, Any], str | None]:
        """Enrol (or re-enrol) an agent with attestation metadata.

        When ``credential_store`` (an AgentCredentialStore) is supplied the
        enrolment Binds to the gate credential namespace: the agent must
        hold an active ``rak_`` credential there, and the returned second
        value is a freshly issued key when the agent had none (the caller
        hands it to the agent exactly once; only its hash is stored).

        Returns (descriptor record, credential or None).
        """
        credential: str | None = None
        if credential_store is not None and not credential_store.has(agent_id):
            credential = credential_store.issue(agent_id)
        record = self._append(
            issue_descriptor(
                agent_id,
                operator=operator,
                operator_binding=operator_binding,
                status="enrolled",
                attestation=attestation,
                ceilings=ceilings or DelegationCeilings(),
                signer=signer,
            )
        )
        return record, credential

    def update(
        self,
        agent_id: str,
        *,
        operator: str,
        operator_binding: str,
        attestation: Attestation,
        ceilings: DelegationCeilings | None = None,
        signer: Ed25519Signer,
    ) -> dict[str, Any]:
        """A new signed version of the agent's descriptor (e.g. a manifest
        rotation). History is never rewritten."""
        return self._append(
            issue_descriptor(
                agent_id,
                operator=operator,
                operator_binding=operator_binding,
                status="enrolled",
                attestation=attestation,
                ceilings=ceilings or DelegationCeilings(),
                signer=signer,
            )
        )

    def retire(
        self, agent_id: str, *, operator: str, operator_binding: str, signer: Ed25519Signer
    ) -> dict[str, Any]:
        """Retirement is a signed record with an empty attestation payload,
        so it verifies offline like any other entry."""
        return self._append(
            issue_descriptor(
                agent_id,
                operator=operator,
                operator_binding=operator_binding,
                status="retired",
                attestation=Attestation(
                    attested_manifest_hash=_MANIFEST_HASH_PREFIX + "0" * 64,
                    attested_manifest_kind="manifest",
                    framework="retired",
                    framework_version="",
                ),
                ceilings=DelegationCeilings(),
                signer=signer,
            )
        )

    def resolve(self, agent_id: str) -> AgentDescriptor | None:
        """The agent's current state (latest entry wins) or None. A
        retired agent resolves to its retirement record - callers check
        ``status``, and nothing here ever masks a retirement."""
        latest = self.history(agent_id)
        return latest[-1] if latest else None

    def history(self, agent_id: str) -> list[AgentDescriptor]:
        """Every signed descriptor for the agent, oldest first."""
        out = []
        for e in self._entries:
            if e.get("agent_id") == agent_id:
                out.append(parse_descriptor(e))
        return out

    def agent_ids(self) -> list[str]:
        return sorted({e.get("agent_id", "") for e in self._entries})

    def verify_all(self, issuer_public_pem: bytes | str) -> list[DescriptorVerdict]:
        """Offline-verify every stored descriptor against one operator key."""
        return [verify_descriptor(e, issuer_public_pem) for e in self._entries]


__all__ = [
    "DESCRIPTOR_VERSION",
    "KNOWN_VERSIONS",
    "MANIFEST_KINDS",
    "DESCRIPTOR_BODY_FIELDS",
    "CEILING_FIELDS",
    "LEASE_CEILING_FIELDS",
    "STATUS_VALUES",
    "Attestation",
    "DelegationCeilings",
    "AgentDescriptor",
    "DescriptorVerdict",
    "DescriptorError",
    "issue_descriptor",
    "parse_descriptor",
    "verify_descriptor",
    "AgentRegistry",
]
