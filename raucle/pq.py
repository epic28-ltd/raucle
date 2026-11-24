"""Hybrid post-quantum signatures for provenance receipts (``raucle/pq1``).

A receipt minted under the ``raucle/pq1`` profile is signed by BOTH an
Ed25519 key and an ML-DSA-65 key (FIPS 204, category 3). The receipt is
valid only if both signatures verify. This is the standard migration
construction (NIST SP 1800-38; IETF LAMPS composite drafts): classical
security does not depend on lattice assumptions, and post-quantum security
does not depend on any classical implementation defect.

Why receipts need this: a receipt is an evidence artefact whose entire
value is long-horizon verifiability. A captured receipt archive that
becomes forgeable once a cryptographically relevant quantum computer
exists is an archive worth capturing today ("harvest now, forge later").
Migrating emission to hybrid signatures before capture closes that
window.

Wire format (see docs/spec/provenance/v1/pq1-hybrid.md):

- Header gains ``"raucle/pq1": "ml-dsa-65"`` and the ``crit`` list gains
  ``"raucle/pq1"`` (a verifier that does not know the profile MUST
  reject, not guess).
- Header gains ``"pqk"``: the ML-DSA-65 key id (first 16 hex chars of
  sha256 over the raw public key bytes).
- The JWS signature slot carries ONE base64url segment over the raw
  concatenation of the two signature byte strings: Ed25519 (fixed 64
  bytes) then ML-DSA-65 (fixed 3309 bytes, FIPS 204). Both lengths are
  constants, so the framing is deterministic with no length prefix and
  no delimiter. This keeps the receipt a conformant Compact JWS
  (RFC 7515): a standard JOSE parser sees a valid three-segment JWS and
  rejects on the unknown ``raucle/pq1`` crit entry - the RFC-correct
  behaviour for an unrecognised critical profile - while pq1 verifiers
  split the decoded bytes by the constant lengths.
- The previous two-segment dot form (``<ed>.<mldsa>``) was not
  Compact-conformant. :func:`parse_hybrid_signature` accepts BOTH forms
  during a deprecation window; every legacy acceptance logs the named
  marker :data:`LEGACY_DOT_FORM_DEPRECATION` and removal is scheduled
  with the pq1 vector freeze.

Verification is fail-closed: a pq1 receipt with a missing or invalid
ML-DSA segment is INVALID. There is no downgrade path by design.

Requires ``cryptography>=47`` with an ML-DSA-capable backend (AWS-LC or
BoringSSL; wheels ship AWS-LC since 48). ``verify_hybrid`` raises
``PQUnavailable`` with a clear message when the runtime cannot support
ML-DSA, so callers can distinguish "not built for PQ" from "bad receipt".
"""

from __future__ import annotations

import base64
import hashlib
import logging
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

try:  # pragma: no cover - import availability is backend-dependent
    from cryptography.hazmat.primitives.asymmetric import mldsa

    _HAS_MLDSA = True
except ImportError:  # pragma: no cover
    mldsa = None  # type: ignore[assignment]
    _HAS_MLDSA = False

_logger = logging.getLogger(__name__)


def _mldsa_mod() -> Any:
    """Return the mldsa module or raise PQUnavailable (typed accessor)."""
    if not _HAS_MLDSA or mldsa is None:
        raise PQUnavailable(
            "ML-DSA is unavailable: install 'cryptography>=47' built with "
            "AWS-LC or BoringSSL (wheels since 48 include it). The pq1 "
            "profile cannot sign or verify without ML-DSA-65."
        )
    return mldsa


#: The PQ profile marker placed in the JOSE header + crit list.
PQ1_PROFILE = "raucle/pq1"

#: The PQ algorithm identifier for the profile (RFC 9964 name).
PQ1_ALG = "ml-dsa-65"

#: Ed25519 signature length in bytes (fixed by RFC 8032).
ED25519_SIG_LEN = 64

#: ML-DSA-65 signature length in bytes (fixed by FIPS 204).
ML_DSA_65_SIG_LEN = 3309

#: Total raw bytes of the current pq1 signature slot payload
#: (``ED25519_SIG_LEN + ML_DSA_65_SIG_LEN``). Constant component lengths
#: make the framing deterministic: no length prefix, no delimiter.
PQ1_CONCAT_LEN = ED25519_SIG_LEN + ML_DSA_65_SIG_LEN

#: Named deprecation marker logged on EVERY acceptance of the legacy
#: two-segment dot form. The dot form was not Compact-JWS-conformant
#: (RFC 7515: the signature component is exactly one segment); it stays
#: acceptable for verification during the deprecation window and its
#: removal is scheduled with the pq1 vector freeze.
LEGACY_DOT_FORM_DEPRECATION = (
    "pq1 signature slot uses the legacy two-segment dot form (deprecated): "
    "accepted for verification only during the deprecation window; "
    "emission switched to the single-segment concatenation form and "
    "removal is scheduled with the pq1 vector freeze"
)


class PQUnavailable(RuntimeError):
    """The runtime cannot support ML-DSA (old cryptography/backend)."""


class HybridVerificationError(ValueError):
    """A pq1 receipt failed hybrid verification (fail-closed)."""


def pq_available() -> bool:
    """True when ML-DSA-65 can be used in this runtime."""
    if not _HAS_MLDSA:
        return False
    try:
        _mldsa_mod().MLDSA65PrivateKey.generate()
        return True
    except PQUnavailable:
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# PQ key id + (de)serialisation helpers
# ---------------------------------------------------------------------------


def pq_key_id_from_public_key(public_key: Any) -> str:
    """Derive the ML-DSA key id: first 16 hex chars of sha256(raw pubkey).

    Same construction as the Ed25519 key id (16 hex chars), so registry
    entries look uniform and ids never collide between the two key types
    (different key material, different hashes).
    """
    raw = public_key.public_bytes_raw()
    return hashlib.sha256(raw).hexdigest()[:16]


def pq_generate() -> tuple[Any, Any, str]:
    """Generate an ML-DSA-65 keypair.

    Returns ``(private_key, public_key, pq_key_id)``.
    """
    m = _mldsa_mod()
    private_key = m.MLDSA65PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key, pq_key_id_from_public_key(public_key)


def pq_public_key_pem(public_key: Any) -> str:
    """Serialise an ML-DSA public key to PEM (SPKI) for registry storage.

    Uses the generic serialization path (SubjectPublicKeyInfo), which
    round-trips through :func:`pq_public_key_from_pem` and stays
    interchangeable with how Ed25519 registry keys are stored.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def pq_public_key_from_pem(pem: str) -> Any:
    """Load an ML-DSA public key from PEM (SPKI).

    The mldsa module has no PEM loader of its own; load via the generic
    serialization API and confirm the result is an ML-DSA-65 key so a
    swapped-in Ed25519/other key cannot masquerade as the PQ key.
    """
    m = _mldsa_mod()
    loaded = serialization.load_pem_public_key(pem.encode("ascii") if isinstance(pem, str) else pem)
    if not isinstance(loaded, m.MLDSA65PublicKey):
        raise PQUnavailable(
            "the PEM does not contain an ML-DSA-65 public key; refusing to "
            "treat a foreign key type as the PQ component"
        )
    return loaded


def pq_public_key_hex(public_key: Any) -> str:
    """Raw ML-DSA public key bytes as hex (1952 bytes -> 3904 chars)."""
    return public_key.public_bytes_raw().hex()


def pq_public_key_from_hex(hexstr: str) -> Any:
    """Load an ML-DSA public key from raw hex bytes."""
    m = _mldsa_mod()
    return m.MLDSA65PublicKey.from_public_bytes(bytes.fromhex(hexstr))


def pq_private_key_pem(private_key: Any) -> str:
    """Serialise an ML-DSA private key to PKCS8 PEM (local keystore files only)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def pq_private_key_from_pem(pem: str) -> Any:
    """Load an ML-DSA private key from PKCS8 PEM via the generic path."""
    m = _mldsa_mod()
    loaded = serialization.load_pem_private_key(
        pem.encode("ascii") if isinstance(pem, str) else pem, password=None
    )
    if not isinstance(loaded, m.MLDSA65PrivateKey):
        raise PQUnavailable("the PEM does not contain an ML-DSA-65 private key")
    return loaded


# ---------------------------------------------------------------------------
# HybridSigner: holds both keys, signs any bytes with both
# ---------------------------------------------------------------------------


@dataclass
class HybridSigner:
    """Signs the receipt signing input with Ed25519 AND ML-DSA-65.

    Attributes
    ----------
    ed25519_private
        The existing identity key. Unchanged: v1 receipts keep signing
        with it exactly as before.
    pq_private
        The ML-DSA-65 private key for the pq1 profile.
    pq_key_id
        Derived 16-hex-char id, pinned in the JOSE header as ``pqk``.
    """

    ed25519_private: Any
    pq_private: Any
    pq_key_id: str

    @classmethod
    def from_ed25519(cls, ed25519_private: Any) -> HybridSigner:
        """Wrap an existing Ed25519 identity with a fresh ML-DSA-65 key.

        The normal adoption path: load the agent identity exactly as
        today, then upgrade it to quantum-safe emission.
        """
        if not isinstance(ed25519_private, Ed25519PrivateKey):
            raise TypeError("ed25519_private must be an Ed25519PrivateKey")
        pq_private, _, pq_kid = pq_generate()
        return cls(ed25519_private=ed25519_private, pq_private=pq_private, pq_key_id=pq_kid)

    def sign_both(self, signing_input: bytes) -> str:
        """Sign *signing_input* with both keys; return the pq1 signature
        slot content.

        The slot is ONE base64url segment over the RAW concatenation
        ``ed25519 signature || ml_dsa_65 signature`` (64 + 3309 bytes):
        Compact-JWS-conformant (RFC 7515) because the signature component
        is exactly one segment, and unambiguously framed because both
        component lengths are constants (no length prefix, no delimiter).
        """
        ed_sig = self.ed25519_private.sign(signing_input)
        pq_sig = self.pq_private.sign(signing_input)
        return _b64url(ed_sig + pq_sig)


# ---------------------------------------------------------------------------
# Verification (fail-closed)
# ---------------------------------------------------------------------------


def _require_component_lengths(ed_sig: bytes, pq_sig: bytes) -> None:
    """Enforce the fixed component lengths (fail-closed framing)."""
    if len(ed_sig) != ED25519_SIG_LEN:
        raise HybridVerificationError(f"Ed25519 signature must be 64 bytes, got {len(ed_sig)}")
    if len(pq_sig) != ML_DSA_65_SIG_LEN:
        raise HybridVerificationError(f"ML-DSA-65 signature must be 3309 bytes, got {len(pq_sig)}")


def parse_hybrid_signature(signature_slot: str) -> tuple[bytes, bytes]:
    """Split a pq1 signature slot into (ed25519_sig, mldsa_sig).

    Two shapes are accepted during the deprecation window:

    - Current emission: ONE base64url segment whose decoded bytes are the
      raw concatenation ``ed25519 (64) || ml_dsa_65 (3309)``. Constant
      component lengths make the framing deterministic the instant the
      slot decodes: split by the constants, no length prefix or delimiter.
    - Legacy dot form: ``<b64url(ed)>.<b64url(ml_dsa)>`` - the pre-JOSE
      conformance wire shape, verify-only. Every legacy acceptance logs
      :data:`LEGACY_DOT_FORM_DEPRECATION` on the ``raucle.pq`` logger.

    Fail-closed: wrong segment count, wrong length and undecodable
    base64url all raise :class:`HybridVerificationError`.
    """
    if not isinstance(signature_slot, str):
        raise HybridVerificationError("pq1 signature slot must be a string")
    if "." in signature_slot:
        # Legacy two-segment dot form (verify-only window).
        parts = signature_slot.split(".")
        if len(parts) != 2:
            raise HybridVerificationError(
                f"pq1 signature slot (legacy dot form) must hold exactly two "
                f"segments, got {len(parts)}"
            )
        ed_b64, pq_b64 = parts
        try:
            ed_sig = _b64url_decode(ed_b64)
            pq_sig = _b64url_decode(pq_b64)
        except Exception as exc:
            raise HybridVerificationError(
                f"pq1 signature segments are not valid base64url: {exc}"
            ) from exc
        _require_component_lengths(ed_sig, pq_sig)
        _logger.warning(LEGACY_DOT_FORM_DEPRECATION)
        return ed_sig, pq_sig
    # Current emission: one segment over the raw concatenation.
    try:
        raw = _b64url_decode(signature_slot)
    except Exception as exc:
        raise HybridVerificationError(f"pq1 signature slot is not valid base64url: {exc}") from exc
    if len(raw) != PQ1_CONCAT_LEN:
        raise HybridVerificationError(
            f"pq1 signature slot must decode to exactly {PQ1_CONCAT_LEN} raw bytes "
            f"({ED25519_SIG_LEN} Ed25519 + {ML_DSA_65_SIG_LEN} ML-DSA-65), got "
            f"{len(raw)}"
        )
    return raw[:ED25519_SIG_LEN], raw[ED25519_SIG_LEN:]


def verify_hybrid(
    signing_input: bytes,
    signature_slot: str,
    ed25519_public: Any,
    pq_public: Any,
) -> None:
    """Verify BOTH signatures over *signing_input*; raise on any failure.

    This is the pq1 contract: the receipt is quantum-valid only if the
    Ed25519 signature AND the ML-DSA-65 signature verify over the same
    canonical bytes. Either alone is INVALID - no downgrade path, so a
    future attacker cannot strip the PQ component and present the receipt
    as fully valid.
    """
    ed_sig, pq_sig = parse_hybrid_signature(signature_slot)

    if not isinstance(ed25519_public, Ed25519PublicKey):
        raise HybridVerificationError("ed25519_public must be an Ed25519PublicKey")
    try:
        ed25519_public.verify(ed_sig, signing_input)
    except Exception as exc:
        raise HybridVerificationError(
            f"hybrid receipt failed the Ed25519 component: {exc}"
        ) from exc

    m = _mldsa_mod()
    if not isinstance(pq_public, m.MLDSA65PublicKey):
        raise HybridVerificationError("pq_public must be an MLDSA65PublicKey")
    try:
        pq_public.verify(pq_sig, signing_input)
    except Exception as exc:
        raise HybridVerificationError(
            f"hybrid receipt failed the ML-DSA-65 component: {exc}"
        ) from exc


def header_is_pq1(header: dict[str, Any]) -> bool:
    """True when the JOSE header declares the pq1 profile."""
    return header.get(PQ1_PROFILE) == PQ1_ALG


def pq1_header(
    base_header: dict[str, Any],
    pq_key_id: str,
) -> dict[str, Any]:
    """Build the pq1 JOSE header from a v1 base header.

    Adds ``raucle/pq1`` to both the header and the ``crit`` list, and
    pins ``pqk``. The caller serialises the result with the canonical
    JCS pipeline exactly as for v1.
    """
    crit = list(base_header.get("crit", []))
    if PQ1_PROFILE not in crit:
        crit.append(PQ1_PROFILE)
    header = dict(base_header)
    header["raucle/pq1"] = PQ1_ALG
    header["crit"] = crit
    header["pqk"] = pq_key_id
    return header


# ---------------------------------------------------------------------------
# base64url helpers (match the provenance module's encoding exactly)
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    import base64

    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


__all__ = [
    "PQ1_PROFILE",
    "PQ1_ALG",
    "ED25519_SIG_LEN",
    "ML_DSA_65_SIG_LEN",
    "PQ1_CONCAT_LEN",
    "LEGACY_DOT_FORM_DEPRECATION",
    "PQUnavailable",
    "HybridVerificationError",
    "HybridSigner",
    "pq_available",
    "pq_generate",
    "pq_key_id_from_public_key",
    "pq_public_key_pem",
    "pq_public_key_from_pem",
    "pq_public_key_hex",
    "pq_public_key_from_hex",
    "pq_private_key_pem",
    "pq_private_key_from_pem",
    "parse_hybrid_signature",
    "verify_hybrid",
    "header_is_pq1",
    "pq1_header",
    "HybridRecordSigner",
    "verify_record_hybrid",
]


# ---------------------------------------------------------------------------
# Hybrid record signatures for chain surfaces (checkpoints, registry entries)
# ---------------------------------------------------------------------------
#
# The receipt profile packs both signatures into the JWS signature slot; chain
# records (audit checkpoints, trust-registry entries) are plain JSON with named
# fields, so the hybrid form carries them as separate fields:
#
#   "signature":  base64(Ed25519 sig over the canonical record)
#   "pq_key_id":  16-hex ML-DSA key id
#   "pq_signature": base64(ML-DSA-65 sig over the SAME canonical record)
#
# Fail-closed rule: a record with "pq_key_id" MUST carry a "pq_signature" that
# verifies; a record without "pq_key_id" verifies classically (migration window).


class HybridRecordSigner:
    """Signs chain records with both keys, in the named-field form.

    Wraps an existing Ed25519Signer-compatible object (``.sign(bytes)`` +
    ``.key_id()``) plus an ML-DSA-65 private key. Used by audit checkpoints
    and trust-registry operator signatures.
    """

    def __init__(self, classical_signer: Any, pq_private: Any) -> None:
        m = _mldsa_mod()
        if not isinstance(pq_private, m.MLDSA65PrivateKey):
            raise TypeError("pq_private must be an MLDSA65PrivateKey")
        self._classical = classical_signer
        self._pq_private = pq_private
        self._pq_key_id = pq_key_id_from_public_key(pq_private.public_key())

    def key_id(self) -> str:
        return self._classical.key_id()

    def pq_key_id(self) -> str:
        return self._pq_key_id

    def public_key_pem(self) -> bytes:
        """The classical (Ed25519) public key PEM - mirrors Ed25519Signer,
        so existing surfaces that read the operator's public key keep
        working unchanged when the signer is upgraded to hybrid."""
        return self._classical.public_key_pem()

    def pq_public_key(self) -> Any:
        """The ML-DSA-65 PUBLIC key of the hybrid pair.

        Named accessor for surfaces that need the PQ public key (the trust
        registry verifies the ML-DSA-65 operator signature component
        against it); callers must not reach into the private
        ``_pq_private`` attribute to derive it.
        """
        return self._pq_private.public_key()

    def sign(self, data: bytes) -> bytes:
        """Classical-only signing, mirroring Ed25519Signer.sign. Surfaces
        that have not migrated to hybrid records keep working; hybrid
        surfaces use sign_record() instead."""
        return self._classical.sign(data)

    def sign_record(self, body_bytes: bytes) -> dict[str, str]:
        """Return {"signature": ..., "pq_key_id": ..., "pq_signature": ...}.

        Both signatures are over *body_bytes* (the canonical record bytes,
        exactly as the classical-only path would sign them).
        """
        classical_sig = self._classical.sign(body_bytes)
        pq_sig = self._pq_private.sign(body_bytes)
        return {
            "signature": base64.b64encode(classical_sig).decode("ascii"),
            "pq_key_id": self._pq_key_id,
            "pq_signature": base64.b64encode(pq_sig).decode("ascii"),
        }


def verify_record_hybrid(
    record: dict[str, Any],
    signing_bytes: bytes,
    classical_verify: Any,
    pq_public_keys: dict[str, Any] | None = None,
) -> bool:
    """Verify a chain record's signatures, enforcing the fail-closed rule.

    ``classical_verify`` is a callable ``(record) -> bool`` that performs the
    surface's existing Ed25519 verification (each surface has its own key
    resolution). The PQ component is checked here when the record declares
    ``pq_key_id``:

    - no ``pq_key_id``: classical verdict alone (migration window)
    - ``pq_key_id`` present: BOTH must pass. Unknown key id -> False.
      Missing/tampered ``pq_signature`` -> False. No PQ keys supplied at
      all -> False (a verifier that cannot check the PQ half of a hybrid
      record must not accept it).
    """
    pq_key_id = record.get("pq_key_id")
    if not pq_key_id:
        return classical_verify(record)
    if not pq_public_keys:
        return False
    pq_key = pq_public_keys.get(pq_key_id)
    if pq_key is None:
        return False
    pq_sig_b64 = record.get("pq_signature")
    if not isinstance(pq_sig_b64, str) or not pq_sig_b64:
        return False
    try:
        pq_sig = base64.b64decode(pq_sig_b64, validate=True)
    except ValueError:
        # binascii.Error subclasses ValueError: one catch covers both
        return False
    if len(pq_sig) != 3309:
        return False
    if not classical_verify(record):
        return False
    try:
        pq_key.verify(pq_sig, signing_bytes)
        return True
    except Exception:
        return False
