"""Remote signer abstraction for KMS/HSM-backed key management.

Regulated enterprises (banks, healthcare, government) cannot store private
keys as unencrypted PEM files on disk. They use HSMs (Thales, Utimaco) or
cloud KMS (AWS KMS, Azure Key Vault, HashiCorp Vault) where the private key
never leaves the hardware boundary.

This module provides:

- :class:`Signer` — a Protocol that any signer (local or remote) implements.
- :class:`Ed25519Signer` — the existing local signer (re-exported for
  convenience; the class lives in :mod:`raucle.audit`).
- :class:`KMSSigner` — a remote signer that delegates Ed25519 signing to an
  external signing service via a simple callable interface.
- :class:`AWSSigner` — AWS KMS signer using the ``boto3`` SDK.
- :class:`AzureSigner` — Azure Key Vault signer using the ``azure-keyvault-keys``
  SDK.
- :class:`VaultSigner` — HashiCorp Vault signer using the ``hvac`` SDK.

All remote signers implement the same interface as :class:`~raucle.audit.Ed25519Signer`:

    >>> signer = AWSSigner(key_id="alias/raucle-issuing-key", region="eu-west-1")
    >>> signature = signer.sign(b"canonical bytes")
    >>> public_pem = signer.public_key_pem()

The :func:`create_signer` factory reads environment variables and returns the
appropriate signer, making it trivial to switch between local development
(local Ed25519) and production (KMS-backed) without code changes::

    RAUCLE_SIGNER=aws
    RAUCLE_KMS_KEY_ID=alias/raucle-issuing-key
    AWS_REGION=eu-west-1

    signer = create_signer()  # returns AWSSigner

    # Or for local development:
    RAUCLE_SIGNER=local
    signer = create_signer()  # returns Ed25519Signer.generate()
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Signer Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Signer(Protocol):
    """The signing interface every raucle signer implements.

    Both the local :class:`~raucle.audit.Ed25519Signer` and the remote
    KMS-backed signers in this module satisfy this protocol. Any code that
    accepts a ``Signer`` can use either local or remote keys transparently.
    """

    def sign(self, data: bytes) -> bytes:
        """Sign *data* with Ed25519 and return the 64-byte signature."""
        ...

    def public_key_pem(self) -> bytes:
        """Return the Ed25519 public key in PEM (SubjectPublicKeyInfo) format."""
        ...


# ---------------------------------------------------------------------------
# Generic KMS signer (bring-your-own callable)
# ---------------------------------------------------------------------------


class KMSSigner:
    """Remote signer that delegates Ed25519 signing to a callable.

    Use this when you have a signing service, custom HSM connector, or
    Lambda function that returns Ed25519 signatures. The callable must:

    - Accept ``bytes`` (the data to sign) and return ``bytes`` (the 64-byte
      Ed25519 signature).
    - The public key must be provided separately as PEM bytes.

    Example::

        signer = KMSSigner(
            sign_fn=my_hsm_connector.sign,
            public_key_pem=open("raucle-pub.pem", "rb").read(),
        )
    """

    def __init__(
        self,
        sign_fn: Callable[[bytes], bytes],
        public_key_pem: bytes,
    ) -> None:
        self._sign_fn = sign_fn
        self._public_pem = public_key_pem

    def sign(self, data: bytes) -> bytes:
        return self._sign_fn(data)

    def public_key_pem(self) -> bytes:
        return self._public_pem


# ---------------------------------------------------------------------------
# AWS KMS signer
# ---------------------------------------------------------------------------


class AWSSigner:
    """Ed25519 signer backed by AWS Key Management Service (KMS).

    The private key never leaves AWS KMS. Signing is performed via the
    ``Sign`` API call. The public key is fetched once via ``GetPublicKey``
    and cached.

    Requires ``boto3``: ``pip install boto3``

    Environment variables:
        - ``RAUCLE_KMS_KEY_ID`` — the KMS key ID or alias (e.g.
          ``"alias/raucle-issuing-key"``).
        - ``AWS_REGION`` — the AWS region (e.g. ``"eu-west-1"``).

    Example::

        signer = AWSSigner(key_id="alias/raucle-issuing-key", region="eu-west-1")
        sig = signer.sign(b"canonical bytes")  # signs in KMS
        pub = signer.public_key_pem()          # fetched from KMS
    """

    def __init__(
        self,
        key_id: str | None = None,
        region: str | None = None,
    ) -> None:
        try:
            import boto3  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError("AWSSigner requires boto3: pip install boto3") from exc

        self._key_id = key_id or os.environ.get("RAUCLE_KMS_KEY_ID", "")
        if not self._key_id:
            raise ValueError(
                "AWSSigner: key_id is required (set RAUCLE_KMS_KEY_ID or pass key_id=)"
            )

        self._region = region or os.environ.get("AWS_REGION", "eu-west-1")
        self._client = boto3.client("kms", region_name=self._region)
        self._public_pem: bytes | None = None

    def sign(self, data: bytes) -> bytes:
        resp = self._client.sign(
            KeyId=self._key_id,
            Message=data,
            SigningAlgorithm="ED25519",
            MessageType="RAW",
        )
        return resp["Signature"]

    def public_key_pem(self) -> bytes:
        if self._public_pem is None:
            resp = self._client.get_public_key(KeyId=self._key_id)
            # KMS returns DER-encoded SubjectPublicKeyInfo; convert to PEM.
            import base64

            der = resp["PublicKey"]
            b64 = base64.encodebytes(der).decode("ascii")
            self._public_pem = (
                b"-----BEGIN PUBLIC KEY-----\n"
                + b64.encode("ascii")
                + b"-----END PUBLIC KEY-----\n"
            )
        return self._public_pem


# ---------------------------------------------------------------------------
# Azure Key Vault signer
# ---------------------------------------------------------------------------


class AzureSigner:
    """Ed25519 signer backed by Azure Key Vault.

    Requires ``azure-keyvault-keys`` and ``azure-identity``:
    ``pip install azure-keyvault-keys azure-identity``

    Environment variables:
        - ``RAUCLE_KV_URL`` — the Key Vault URL (e.g.
          ``"https://raucle-vault.vault.azure.net"``).
        - ``RAUCLE_KV_KEY_NAME`` — the key name in Key Vault.
        - ``RAUCLE_KV_KEY_VERSION`` — (optional) specific key version.

    Example::

        signer = AzureSigner(
            vault_url="https://raucle-vault.vault.azure.net",
            key_name="raucle-issuing-key",
        )
    """

    def __init__(
        self,
        vault_url: str | None = None,
        key_name: str | None = None,
        key_version: str | None = None,
    ) -> None:
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore
            from azure.keyvault.keys import KeyClient  # type: ignore
            from azure.keyvault.keys.crypto import CryptographyClient  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "AzureSigner requires: pip install azure-keyvault-keys azure-identity"
            ) from exc

        self._vault_url = vault_url or os.environ.get("RAUCLE_KV_URL", "")
        if not self._vault_url:
            raise ValueError("AzureSigner: vault_url is required")

        self._key_name = key_name or os.environ.get("RAUCLE_KV_KEY_NAME", "")
        if not self._key_name:
            raise ValueError("AzureSigner: key_name is required")

        self._key_version = key_version or os.environ.get("RAUCLE_KV_KEY_VERSION")

        credential = DefaultAzureCredential()
        self._key_client = KeyClient(vault_url=self._vault_url, credential=credential)

        # Get the key to find the full ID for the crypto client
        key = self._key_client.get_key(self._key_name)
        self._key_id = key.id

        self._crypto = CryptographyClient(key, credential=credential)
        self._public_pem: bytes | None = None

    def sign(self, data: bytes) -> bytes:
        from azure.keyvault.keys.crypto import SignatureAlgorithm  # type: ignore

        result = self._crypto.sign(
            algorithm=SignatureAlgorithm.es256k,  # Ed25519 in Azure KV
            data=data,
        )
        return result.signature

    def public_key_pem(self) -> bytes:
        if self._public_pem is None:
            import base64

            key = self._key_client.get_key(self._key_name)
            # Key Vault returns JWK; extract the public key components
            jwk = key.key
            if hasattr(jwk, "x") and jwk.x:
                # Ed25519 public key is the x coordinate (32 bytes)
                der = base64.urlsafe_b64decode(jwk.x + "===")
                # Wrap in SubjectPublicKeyInfo
                self._public_pem = self._ed25519_public_to_pem(der)
        return self._public_pem or b""

    @staticmethod
    def _ed25519_public_to_pem(public_bytes: bytes) -> bytes:
        import base64

        # Ed25519 OID: 1.3.101.112
        # SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { OID }, BIT STRING { pubkey } }
        # This is a minimal DER encoder for Ed25519 public keys.
        oid = bytes([0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70])
        bit_string = bytes([0x03, len(public_bytes) + 1, 0x00]) + public_bytes
        der = bytes([0x30, len(oid) + len(bit_string)]) + oid + bit_string
        b64 = base64.encodebytes(der).decode("ascii")
        return b"-----BEGIN PUBLIC KEY-----\n" + b64.encode("ascii") + b"-----END PUBLIC KEY-----\n"


# ---------------------------------------------------------------------------
# HashiCorp Vault signer
# ---------------------------------------------------------------------------


class VaultSigner:
    """Ed25519 signer backed by HashiCorp Vault's Transit Engine.

    Requires ``hvac``: ``pip install hvac``

    Environment variables:
        - ``RAUCLE_VAULT_URL`` — Vault URL (e.g. ``"https://vault.example.com:8200"``).
        - ``RAUCLE_VAULT_TOKEN`` — Vault token (or use ``VAULT_TOKEN``).
        - ``RAUCLE_VAULT_KEY_NAME`` — the transit key name.

    Example::

        signer = VaultSigner(
            vault_url="https://vault.example.com:8200",
            token="s.xxxxx",
            key_name="raucle-issuing-key",
        )
    """

    def __init__(
        self,
        vault_url: str | None = None,
        token: str | None = None,
        key_name: str | None = None,
    ) -> None:
        try:
            import hvac  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError("VaultSigner requires hvac: pip install hvac") from exc

        self._vault_url = vault_url or os.environ.get("RAUCLE_VAULT_URL", "")
        if not self._vault_url:
            raise ValueError("VaultSigner: vault_url is required")

        self._token = (
            token or os.environ.get("RAUCLE_VAULT_TOKEN") or os.environ.get("VAULT_TOKEN", "")
        )
        self._key_name = key_name or os.environ.get("RAUCLE_VAULT_KEY_NAME", "")
        if not self._key_name:
            raise ValueError("VaultSigner: key_name is required")

        self._client = hvac.Client(url=self._vault_url, token=self._token)
        self._public_pem: bytes | None = None

    def sign(self, data: bytes) -> bytes:
        import base64

        resp = self._client.secrets.transit.sign_data(
            name=self._key_name,
            hash_input=base64.b64encode(data).decode("ascii"),
            algorithm="ed25519",
        )
        sig_b64 = resp["data"]["signature"]
        # Vault returns "vault:v1:<base64>" format; extract the raw signature
        parts = sig_b64.split(":")
        if len(parts) >= 3:
            return base64.b64decode(parts[-1])
        return base64.b64decode(sig_b64)

    def public_key_pem(self) -> bytes:
        if self._public_pem is None:
            import base64

            resp = self._client.secrets.transit.read_key(name=self._key_name)
            # Get the latest version's public key
            latest = resp["data"]["latest_version"]
            keys = resp["data"]["keys"]
            pub_b64 = keys[str(latest)]["public_key"]
            pub_bytes = base64.b64decode(pub_b64)
            self._public_pem = AzureSigner._ed25519_public_to_pem(pub_bytes)
        return self._public_pem


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_signer(
    *,
    backend: str | None = None,
    **kwargs: Any,
) -> Signer:
    """Create a signer from environment variables or explicit parameters.

    Args:
        backend: The signer backend. One of ``"local"``, ``"aws"``,
            ``"azure"``, ``"vault"``, ``"kms"``, or ``"tee"``. If ``None``,
            reads ``RAUCLE_SIGNER`` env var, defaulting to ``"local"``.
        **kwargs: Passed through to the signer constructor.

    Returns:
        A :class:`Signer` instance.

    Environment variables:

        ``RAUCLE_SIGNER``
            The backend: ``local``, ``aws``, ``azure``, ``vault``, ``kms``,
            ``tee``.

        ``RAUCLE_TEE_SIMULATED``
            (tee) Explicit acknowledgement of the clearly-labelled mock
            boundary for the confidential-computing signer path. Without
            it (or explicit ``sign_fn=`` wiring), ``backend="tee"`` fails
            closed: a simulated attestation is never applied silently.

        ``RAUCLE_KMS_KEY_ID``
            (AWS) The KMS key ID or alias.

        ``RAUCLE_KV_URL``, ``RAUCLE_KV_KEY_NAME``
            (Azure) Key Vault URL and key name.

        ``RAUCLE_VAULT_URL``, ``RAUCLE_VAULT_TOKEN``, ``RAUCLE_VAULT_KEY_NAME``
            (Vault) Vault connection details.

    Example::

        # Local development:
        os.environ["RAUCLE_SIGNER"] = "local"
        signer = create_signer()  # Ed25519Signer.generate()

        # Production with AWS KMS:
        os.environ["RAUCLE_SIGNER"] = "aws"
        os.environ["RAUCLE_KMS_KEY_ID"] = "alias/raucle-issuing-key"
        signer = create_signer()  # AWSSigner

        # Mock-boundary TEE path (explicitly acknowledged, CI/development):
        os.environ["RAUCLE_TEE_SIMULATED"] = "1"
        signer = create_signer(backend="tee")  # raucle.tee.SimulatedNitroEnclave signer
    """
    backend = backend or os.environ.get("RAUCLE_SIGNER", "local")

    if backend == "local":
        from raucle.audit import Ed25519Signer

        return Ed25519Signer.generate()

    if backend == "aws":
        return AWSSigner(**kwargs)

    if backend == "azure":
        return AzureSigner(**kwargs)

    if backend == "vault":
        return VaultSigner(**kwargs)

    if backend == "kms":
        # Generic KMS signer — requires sign_fn and public_key_pem
        return KMSSigner(**kwargs)

    if backend == "tee":
        # EPIC H3 (slice 1): the confidential-computing boundary. Either an
        # explicitly wired enclave signing service (sign_fn + public key +
        # attestation provider), or an EXPLICITLY acknowledged mock
        # boundary via RAUCLE_TEE_SIMULATED=1. A simulated attestation is
        # never applied silently.
        from raucle.tee import SimulatedNitroEnclave, TEESigner

        if kwargs:
            return TEESigner(**kwargs)
        if os.environ.get("RAUCLE_TEE_SIMULATED", "").lower() in ("1", "true", "yes"):
            return SimulatedNitroEnclave().signer()
        raise ValueError(
            "create_signer: backend 'tee' requires an explicitly wired enclave "
            "signing service (sign_fn=, public_key_pem=, attestation_provider=), "
            "or RAUCLE_TEE_SIMULATED=1 to acknowledge the clearly-labelled mock "
            "boundary. Refusing to fall back to a simulated attestation silently."
        )

    raise ValueError(
        f"create_signer: unknown backend {backend!r}. "
        f"Use 'local', 'aws', 'azure', 'vault', 'kms', or 'tee'."
    )


__all__ = [
    "Signer",
    "KMSSigner",
    "AWSSigner",
    "AzureSigner",
    "VaultSigner",
    "create_signer",
]
