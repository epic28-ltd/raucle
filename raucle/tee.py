"""TEE / confidential-computing signer path (EPIC H3, slice 1).

The gap this closes: every receipt raucle emits is only as trustworthy as
the process that signs it, and nothing in the base product proves WHICH
code signed it. A TEE (Trusted Execution Environment) attestation binds
the receipt-signing key to a measured enclave image, so an offline
verifier can check that the signing key was produced by known code
running on validated hardware rather than trust the operator's word for
it. The design lives in ``docs/proposals/tee-gate.md``; the binding the
receipt signer identity carries is the spec v1 §5.1 ``attestation``
statement field.

Slice 1 scope (stated honestly):

- :class:`TEESigner`, the adapter behind the existing
  :class:`raucle.kms.Signer` protocol. It NEVER holds key material:
  signing is delegated across a named enclave boundary callable
  (``sign_fn``, the same shape the KMS signers use for a remote service)
  and the only bytes that cross back are signatures, the public key and
  attestation documents. This part is production contract code.
- :class:`SimulatedNitroEnclave`, the mock boundary, after the MCP demo
  pattern: an in-process simulated enclave that produces the same
  external contract (public half, signatures, attestation document) with
  the private key living only inside the simulated enclave closure. Every
  document and view this produces is explicitly labelled ``simulated``.
  This is CI and development machinery, not a hardware guarantee.
- Real attestation providers (AWS Nitro Enclaves ``/dev/nsm`` and KMRA,
  Azure attestation, generic vTPM/SEV-SNP contracts) are named follow-up
  slices. A real provider only has to satisfy
  :class:`TEEAttestationProvider`; no speculative device-call code ships
  in this slice.

Fail-closed rule: a simulated attestation is never applied silently.
``create_signer(backend="tee")`` requires EITHER an explicitly wired
enclave signer (sign_fn + public key + provider) OR an explicit
acknowledgement of the mock boundary (``RAUCLE_TEE_SIMULATED=1``).
"""

from __future__ import annotations

import base64
import hashlib
import time
from typing import Any, Protocol, runtime_checkable

from raucle.provenance import _canonical_json

__all__ = [
    "TEEUnavailableError",
    "TEEAttestationProvider",
    "TEEAttestationBinding",
    "TEESigner",
    "SimulatedNitroEnclave",
    "ATTESTATION_STATEMENT_KEYS",
]


class TEEUnavailableError(RuntimeError):
    """The enclave boundary is not reachable, so attestation must not proceed."""


#: The exact key set the receipt signer identity may carry for an
#: attestation binding (``raucle.provenance.CapabilityStatement.attestation``).
#: A different key set makes the binding unserialisable into a signed
#: statement, so it is pinned here and by the shared contract test.
ATTESTATION_STATEMENT_KEYS = frozenset({"platform", "measurement", "attestation_ref", "simulated"})


@runtime_checkable
class TEEAttestationProvider(Protocol):
    """A source of enclave attestation documents.

    Real providers wrap the platform's attestation device or service (for
    example the Nitro NSM device or the EnclaveImage's vsock bridge); mock
    providers produce self-consistent documents labelled ``simulated``.
    """

    platform: str
    """The attestation platform, e.g. ``"aws-nitro"``."""

    measurement: str
    """The measured-image digest reference, e.g. ``"sha384:<hex>"``."""

    simulated: bool
    """True when this provider is a mock boundary, never real hardware."""

    def attestation_document(self, user_data: bytes, nonce: bytes = b"") -> bytes:
        """Return the raw, provider-signed attestation document bytes.

        ``user_data`` is the public key material (or its digest) the
        document must bind; ``nonce`` is the freshness challenge. The
        exact encoding is provider-specific (Nitro documents are CBOR);
        the adapter only records the bytes and hashes them.
        """
        ...


@runtime_checkable
class _HasSimulated(Protocol):
    simulated: bool


class TEEAttestationBinding:
    """The attested binding of the receipt-signing key to a TEE measurement.

    Built by :class:`TEESigner` from its provider's document; never
    contains key material - digests and the document bytes only.
    """

    __slots__ = ("platform", "measurement", "document", "attested_public_key_sha256", "simulated")

    def __init__(
        self,
        *,
        platform: str,
        measurement: str,
        document: bytes,
        public_key_pem: bytes,
        simulated: bool,
    ) -> None:
        self.platform = platform
        self.measurement = measurement
        self.document = document
        self.attested_public_key_sha256 = "sha256:" + hashlib.sha256(public_key_pem).hexdigest()
        self.simulated = simulated

    @property
    def attestation_ref(self) -> str:
        """The attestation statement reference: sha256 over the document bytes."""
        return "sha256:" + hashlib.sha256(self.document).hexdigest()

    @property
    def document_b64(self) -> str:
        """The raw attestation document, base64 (standard alphabet)."""
        return base64.b64encode(self.document).decode("ascii")

    def to_statement_dict(self) -> dict[str, Any]:
        """The serialisable shape the receipt signer identity carries.

        Exactly :data:`ATTESTATION_STATEMENT_KEYS`; the compact reference
        form. The full document (document_b64) stays with the deployment's
        attestation record - the statement cites it by digest, and a
        verifier re-hashes the fetched bytes against ``attestation_ref``.
        """
        return {
            "platform": self.platform,
            "measurement": self.measurement,
            "attestation_ref": self.attestation_ref,
            "simulated": self.simulated,
        }


class TEESigner:
    """Ed25519 signer behind a confidential-computing boundary.

    Constructor contract (the same shape a real enclave signing service
    exposes, whether the transport is a device call, vsock or a local
    loopback bridge):

    - ``sign_fn``: the enclave signing boundary - bytes in (the message),
      64-byte Ed25519 signature out. Every signature request crosses this
      boundary; the gateway process never sees key material.
    - ``public_key_pem``: the enclave key's public half (PEM,
      SubjectPublicKeyInfo). It backs the identity statement receipt
      verification stays offline.
    - ``attestation_provider``: a :class:`TEEAttestationProvider`.

    Example::

        signer = TEESigner(
            sign_fn=enclave_dispatch,          # the TEE boundary.
            public_key_pem=enclave_public_pem,
            attestation_provider=enclave_provider,
        )
        sig = signer.sign(b"canonical bytes")
        binding = signer.attestation_binding()
    """

    def __init__(
        self,
        *,
        sign_fn: Any,
        public_key_pem: bytes,
        attestation_provider: TEEAttestationProvider,
    ) -> None:
        if not callable(sign_fn):
            raise TypeError("TEESigner: sign_fn must be callable(bytes) -> bytes")
        if not isinstance(public_key_pem, bytes) or b"BEGIN PUBLIC KEY" not in public_key_pem:
            raise TypeError(
                "TEESigner: public_key_pem must be PEM public key bytes (never private material)"
            )
        # Duck-typed, not isinstance(): runtime_checkable data Protocols
        # only support isinstance() from 3.12 and CI still runs 3.11.
        provider = attestation_provider
        for attr in ("platform", "measurement"):
            if not isinstance(getattr(provider, attr, None), str):
                raise TypeError(f"TEESigner: attestation_provider.{attr} must be a string")
        if not isinstance(getattr(provider, "simulated", None), bool):
            raise TypeError(
                "TEESigner: attestation_provider.simulated must be a bool "
                "(True marks the mock boundary; real hardware labels itself False)"
            )
        if not callable(getattr(provider, "attestation_document", None)):
            raise TypeError(
                "TEESigner: attestation_provider must expose "
                "attestation_document(user_data, nonce) -> bytes"
            )
        self._sign_fn = sign_fn
        self._public_pem = public_key_pem
        self._provider = provider
        self._binding: TEEAttestationBinding | None = None

    def sign(self, data: bytes) -> bytes:
        """Sign *data* across the enclave boundary (64-byte Ed25519)."""
        sig = self._sign_fn(data)
        if not isinstance(sig, bytes) or len(sig) != 64:
            kind = f"{type(sig).__name__}" if not isinstance(sig, bytes) else "bytes"
            raise TEEUnavailableError(
                f"TEESigner: the enclave signing boundary returned an invalid "
                f"signature ({kind}, len={len(sig) if isinstance(sig, bytes) else 'n/a'})"
            )
        return sig

    def public_key_pem(self) -> bytes:
        """The enclave key's PUBLIC half (SubjectPublicKeyInfo PEM)."""
        return self._public_pem

    def attestation_binding(self) -> TEEAttestationBinding:
        """Fetch (once) and hold the provider's attestation of this key.

        The document request binds the signer's own public key as
        ``user_data``, following the documented Nitro pattern (the
        enclave embeds the public key it generated), so the binding names
        this sign key, not a neighbour's.
        """
        if self._binding is None:
            document = self._provider.attestation_document(user_data=self._public_pem)
            if not isinstance(document, bytes) or not document:
                raise TEEUnavailableError(
                    "TEESigner: the attestation provider returned no document"
                )
            self._binding = TEEAttestationBinding(
                platform=str(self._provider.platform),
                measurement=str(self._provider.measurement),
                document=document,
                public_key_pem=self._public_pem,
                simulated=bool(self._provider.simulated),
            )
        return self._binding

    def attestation_statement(self) -> dict[str, Any]:
        """The binding as the receipt signer identity carries it (spec §5.1)."""
        return self.attestation_binding().to_statement_dict()


class SimulatedNitroEnclave:
    """The mock boundary: a simulated AWS Nitro enclave (MCP-demo pattern).

    Same external contract as a real enclave signing service:

    - a private Ed25519 key generated at construction and held ONLY here;
      the signing method is the boundary callable :class:`TEESigner`
      wraps, and nothing else in the process can sign for this key,
    - the public half, signatures and an attestation document of the
      Nitro shape as the only exports,
    - every document carries ``"simulated": true`` and the attestation
      platform label stays exact (``aws-nitro``) while ``module_id``
      marks the simulation, so the binding is never presented as
      hardware-backed.

    Not for production assurance. The documents are signed by the
    simulated enclave's own key, NOT by a vendor root.
    """

    #: The synthetic image tag hashed into the measurement. Deterministic
    #: so a binding is stable across processes for the same document.
    IMAGE_TAG = b"raucle/gate:simulated-image@v1"
    MODULE_ID = "raucle-mock-tee"
    PLATFORM = "aws-nitro"

    def __init__(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._private = Ed25519PrivateKey.generate()
        self._public_pem: bytes = self._private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.platform = self.PLATFORM
        self.measurement = "sha384:" + hashlib.sha384(self.IMAGE_TAG).hexdigest()
        self.simulated = True
        self.sign_requests = 0

    # -- the enclave boundary callable (used as TEESigner's sign_fn) ------
    def sign(self, data: bytes) -> bytes:
        """Sign INSIDE the simulated enclave: the private key never leaves."""
        self.sign_requests += 1
        return self._private.sign(data)

    def public_key_pem(self) -> bytes:
        """The public half; the only key material that ever crosses out."""
        return self._public_pem

    def attestation_document(self, user_data: bytes = b"", nonce: bytes = b"") -> bytes:
        """A Nitro-shaped attestation document binding ``user_data``.

        The private half signs the canonical body inside the simulated
        enclave; the document is a signed JSON mock, not a vendor-
        attested CBOR document.
        """
        body: dict[str, Any] = {
            "platform": self.PLATFORM,
            "module_id": self.MODULE_ID,
            "digest": "SHA384",
            "pcrs": {"PCR0": self.measurement.split(":", 1)[1]},
            "public_key_pem": self._public_pem.decode("ascii"),
            "user_data": base64.b64encode(user_data).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "issued_at": int(time.time()),
            "simulated": True,
        }
        sig = self._private.sign(_canonical_json(body))
        document = dict(body)
        document["signature"] = base64.b64encode(sig).decode("ascii")
        return _canonical_json(document)

    def signer(self) -> TEESigner:
        """The :class:`TEESigner` adapter over this simulated enclave."""
        return TEESigner(
            sign_fn=self.sign,
            public_key_pem=self._public_pem,
            attestation_provider=self,
        )
