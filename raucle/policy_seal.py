"""Operator-signed sidecar seals for control-plane files (RAU-02, M5/R5).

The policy file and the revocation/delegation registries are unsigned
control-plane artefacts today: filesystem write access to the enforcement
directory equals enforcement control. This module introduces the named
seal mechanism the threat model's M5 row calls for: a sidecar
``<file>.meta`` (the :mod:`raucle.receipt_store` sidecar precedent)
carrying the file's canonical SHA-256, the operator signer's Ed25519
signature over the FILE BYTES (never a wrapper document), the signer's
key id and a ``sealed_at`` epoch.

Loading (the gateway boot and reload paths) verifies the seal against
the current bytes and refuses with the named
:class:`raucle.errors.PolicySealRefused` when the seal is present and
does not match. The migration knob ``RAUCLE_POLICY_SEALING``
(``required`` | ``advisory`` | ``off``, default ``advisory``) governs ONE
case only: a file with NO seal at all. Under ``advisory`` the unsealed
file loads and the boot logs a named advisory; under ``required`` it
refuses; under ``off`` the mechanism is entirely inactive. A PRESENT
seal that diverges from the bytes is tamper evidence and refuses in
every mode except ``off`` (the explicit operator opt-out).

Contract notes an assessor should read:

- The sidecar is strict: unknown fields refuse, so a future field
  (rotation chains, cross-signatures) must be added deliberately to both
  writer and verifier.
- ``key_id`` in the sidecar is attribution metadata; the trust anchor is
  the verification key set the operator configures via
  ``RAUCLE_POLICY_SEAL_PUBLIC_KEY`` (a path, or several paths separated
  by the OS path separator). A seal signed by a key that is not in the
  configured set refuses by name.
- Key ids follow the house convention: the first 16 hex of
  sha256(public PEM bytes) (:meth:`raucle.audit.Ed25519Signer.key_id`).
- Verification is honest about state: ``verified``, ``unsealed`` and
  ``refused`` are distinct verdicts, so callers can log the unsealed
  case (advisory) without pretending a refusal happened - and neither
  state is ever presented as the other.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from raucle.errors import ConfigurationError

#: The sidecar suffix: the receipt store's ``.meta`` precedent, reused so
#: the suite has exactly one sidecar convention.
SEAL_SIDECAR_SUFFIX = ".meta"

#: The closed sidecar field set. Unknown fields refuse.
_META_FIELDS = frozenset({"content_sha256", "key_id", "sealed_at", "signature"})

#: The closed sealing-mode vocabulary for ``RAUCLE_POLICY_SEALING``.
SEALING_MODES = ("required", "advisory", "off")

_MODE_ENV = "RAUCLE_POLICY_SEALING"
_KEY_ENV = "RAUCLE_POLICY_SEAL_PUBLIC_KEY"

_HEX_DIGEST_LENGTH = 64


@dataclass(frozen=True)
class SealVerdict:
    """The outcome of verifying one file's sidecar seal.

    ``state`` is one of ``verified``, ``unsealed`` (no sidecar exists:
    the mode knob decides what that means) and ``refused`` (a sidecar
    exists and fails verification: tamper evidence). ``reason`` carries
    the named refusal text for the ``refused`` state.
    """

    state: str
    reason: str = ""
    content_sha256: str = ""


@dataclass(frozen=True)
class SealRecord:
    """The in-memory view of a seal that was just written."""

    path: str
    content_sha256: str
    key_id: str
    sealed_at: int


def seal_path(data_path: str | Path) -> Path:
    """The sidecar path for *data_path*: ``<name><SEAL_SIDECAR_SUFFIX>``."""
    path = Path(data_path)
    return path.with_name(path.name + SEAL_SIDECAR_SUFFIX)


def sealing_mode() -> str:
    """Resolve ``RAUCLE_POLICY_SEALING`` (default ``advisory``).

    Unknown values refuse with :class:`ConfigurationError`: a mode the
    loader cannot interpret must fail closed at boot, not fall back to
    the default silently.
    """
    raw = (os.environ.get(_MODE_ENV) or "").strip().lower()
    if not raw:
        return "advisory"
    if raw not in SEALING_MODES:
        raise ConfigurationError(
            f"invalid {_MODE_ENV} {raw!r}: expected one of "
            + ", ".join(SEALING_MODES)
            + " (unknown values refuse at boot; the value may also come from "
            "a deployment overlay, so a typo must not pick the default)"
        )
    return raw


def public_key_id(pem: bytes) -> str:
    """The house key id: sha256(public PEM)[:16] (audit signer convention)."""
    return hashlib.sha256(pem).hexdigest()[:16]


def seal_public_keys_from_env() -> dict[str, bytes]:
    """Load the trusted seal verification keys from ``_KEY_ENV``.

    The env value holds one or more PEM-file paths (separated by the OS
    path separator, so a rotation keeps the old and the new key trusted
    side by side). Each key is parsed at load: an unreadable or
    unparseable configured key is explicitly-configured-but-broken and
    raises :class:`ConfigurationError` instead of quietly weakening
    verification. Returns ``{key_id: public_pem_bytes}``; an unset env
    returns ``{}`` - callers then refuse any PRESENT seal (the trust
    anchor is unknown) and treat ABSENT seals per the sealing mode.
    """
    raw = (os.environ.get(_KEY_ENV) or "").strip()
    if not raw:
        return {}
    keys: dict[str, bytes] = {}
    for part in [p.strip() for p in raw.split(os.pathsep) if p.strip()]:
        try:
            pem = Path(part).read_bytes()
        except OSError as exc:
            raise ConfigurationError(
                f"{_KEY_ENV} names a seal verification key that cannot be read "
                f"({part}): {exc.__class__.__name__}"
            ) from exc
        try:
            from cryptography.hazmat.primitives import serialization

            serialization.load_pem_public_key(pem)
        except Exception as exc:
            raise ConfigurationError(
                f"{_KEY_ENV} names a file that is not a PEM public key ({part}): "
                f"{exc.__class__.__name__}"
            ) from exc
        keys[public_key_id(pem)] = pem
    return keys


def seal_file(data_path: str | Path, signer: Any) -> SealRecord:
    """Seal *data_path* with the operator *signer* and write the sidecar.

    The signature covers the file's bytes exactly as they are on disk at
    sealing time - never a wrapper document, never a normalised form -
    so verification has no canonicalisation opinion to disagree with.
    The sidecar is persisted atomically (temporary file + ``os.replace``
    on the same directory), mirroring the receipt store's ``.meta``
    writes.
    """
    path = Path(data_path)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    record = {
        "content_sha256": digest,
        "key_id": signer.key_id(),
        "sealed_at": int(time.time()),
        "signature": base64.b64encode(signer.sign(data)).decode("ascii"),
    }
    sidecar = seal_path(path)
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(sidecar.parent), prefix=f".{sidecar.name}.")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(json.dumps(record, sort_keys=True, indent=2).encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, sidecar)
    except BaseException:
        with suppress(OSError):
            os.unlink(tmp_name)
        raise
    return SealRecord(
        path=str(path),
        content_sha256=digest,
        key_id=record["key_id"],
        sealed_at=record["sealed_at"],
    )


def _refused(reason: str) -> SealVerdict:
    return SealVerdict(state="refused", reason=reason)


def verify_bytes(data_path: str | Path, data: bytes, keys: dict[str, bytes]) -> SealVerdict:
    """Verify the sidecar seal for *data* over the bytes already read.

    The load path uses THIS entry point: the same single read that is
    hashed is what the signature covers, so there is no re-read and no
    window between verification and parse.
    """
    path = Path(data_path)
    sidecar = seal_path(path)
    if not sidecar.exists():
        return SealVerdict(
            state="unsealed",
            reason="",
            content_sha256=hashlib.sha256(data).hexdigest(),
        )
    try:
        meta = json.loads(sidecar.read_text(encoding="utf-8"))
    except OSError as exc:
        return _refused(f"seal sidecar unreadable ({path.name}.meta): {exc.__class__.__name__}")
    except ValueError as exc:
        return _refused(f"seal sidecar is corrupt ({path.name}.meta): {exc}")
    if not isinstance(meta, dict):
        return _refused(f"seal sidecar is not a mapping ({path.name}.meta)")
    unknown = sorted(set(meta) - _META_FIELDS)
    if unknown:
        return _refused(f"seal sidecar carries unknown field(s) {', '.join(unknown)}")
    missing = sorted(_META_FIELDS - set(meta))
    if missing:
        return _refused(f"seal sidecar is missing field(s) {', '.join(missing)}")
    digest_recorded = meta["content_sha256"]
    key_id = meta["key_id"]
    sealed_at = meta["sealed_at"]
    signature_b64 = meta["signature"]
    if not isinstance(digest_recorded, str) or len(digest_recorded) != _HEX_DIGEST_LENGTH:
        return _refused(f"seal sidecar field 'content_sha256' is malformed ({path.name}.meta)")
    if not isinstance(key_id, str) or not key_id:
        return _refused(f"seal sidecar field 'key_id' is malformed ({path.name}.meta)")
    if isinstance(sealed_at, bool) or not isinstance(sealed_at, int):
        return _refused(
            f"seal sidecar field 'sealed_at' must be an integer epoch, got "
            f"{type(sealed_at).__name__}"
        )
    if not isinstance(signature_b64, str) or not signature_b64:
        return _refused(f"seal sidecar field 'signature' is malformed ({path.name}.meta)")
    key_pem = keys.get(key_id)
    if key_pem is None:
        return _refused(
            f"seal signed by key id '{key_id}' which is not among the configured "
            f"verification keys ({_KEY_ENV}); refusing"
        )
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        return _refused(f"seal signature is not valid base64 ({path.name}.meta): {exc}")
    digest_current = hashlib.sha256(data).hexdigest()
    if digest_current != digest_recorded:
        return _refused(
            f"sealed content diverges from the current bytes ({path.name}): sealed "
            f"sha256 {digest_recorded} != current {digest_current} (tampered in place?)"
        )
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        return _refused(
            f"seal verification unavailable ({path.name}): the cryptography "
            f"extra is not installed: {exc.__class__.__name__}"
        )
    try:
        public_key = serialization.load_pem_public_key(key_pem)
        if not isinstance(public_key, Ed25519PublicKey):
            return _refused(
                f"configured verification key for seal key id '{key_id}' is not an "
                "Ed25519 public key"
            )
        public_key.verify(signature, data)
    except InvalidSignature:
        return _refused(
            f"seal signature does not verify over the current bytes ({path.name}, key id {key_id})"
        )
    except Exception as exc:  # unreadable key material at verify time
        return _refused(
            f"seal verification could not load the configured key for key id "
            f"'{key_id}': {exc.__class__.__name__}"
        )
    return SealVerdict(state="verified", reason="", content_sha256=digest_current)


def verify_file_seal(data_path: str | Path, keys: dict[str, bytes]) -> SealVerdict:
    """Read *data_path* and verify its sidecar seal against the bytes.

    A data file that cannot be read at all is a REFUSED verdict, not an
    exception, so CLI callers report it in the same verdict vocabulary;
    the load-path callers refuse before this point (their read failure
    is the load error).
    """
    path = Path(data_path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        return _refused(f"data file unreadable ({path.name}): {exc.__class__.__name__}")
    return verify_bytes(path, data, keys)


__all__ = [
    "SEAL_SIDECAR_SUFFIX",
    "SEALING_MODES",
    "SealRecord",
    "SealVerdict",
    "seal_file",
    "seal_path",
    "seal_public_keys_from_env",
    "sealing_mode",
    "public_key_id",
    "verify_bytes",
    "verify_file_seal",
]
