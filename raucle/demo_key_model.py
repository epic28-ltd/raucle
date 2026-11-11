"""G5: the key model / never-exported keys demo plane (read-only).

Driven by the SAME live signer configuration the receipts key-family
card reads: the signer backend in force, the key id of the key that
actually signs receipts, and the type of its key material. On top of
that it shows what the code itself can prove about enrolment and
export:

- the gate identity statement is a signed capability statement; the
  module re-checks the two enrolment properties the provenance verifier
  enforces (key id binds to the key material, statement signature
  verifies) rather than narrating them,
- every rotation sentence names the function that does the work
  (:meth:`raucle.trust_registry.TrustRegistry.publish`,
  :meth:`~raucle.trust_registry.TrustRegistry.revoke`,
  :meth:`raucle.agent_credentials.AgentCredentialStore.issue`,
  :meth:`raucle.agent_registry.AgentRegistry.retire`, the boot-time
  local signer persistence, and
  :func:`raucle.kms.create_signer`), as documented in
  ``docs/security/key-operations.md`` and pinned by
  ``tests/test_key_rotation_e2e.py``.

Nothing here exports or displays key material: the only bytes this
plane touches are the public key half and the signer configuration.
"""

from __future__ import annotations

import os
import stat
from typing import Any

KEY_MODEL_NOTE = (
    "Simulated demonstration of real configuration: everything below is "
    "read from this deployment's live signer machinery the moment the "
    "panel loads. The private half of the receipt-signing key is never "
    "shown on this screen, returned by any panel route, or exported; "
    "what an operator can see anywhere in the product is the public key "
    "and its derived id."
)

_ROTATION_STORY = [
    {
        "layer": "Trust-registry keys (capability issuers)",
        "functions": "TrustRegistry.publish, TrustRegistry.revoke (raucle.trust_registry)",
        "story": (
            "The registry holds one ACTIVE classical key per issuer name: "
            "publishing a second key under the same name is refused as an "
            "impersonation. Zero-downtime rotation therefore mints the new "
            "generation under a versioned issuer identity, runs a dual-trust "
            "window in which both generations verify, then revokes the old "
            "key id. Revocation removes the trust, not the math: receipts "
            "signed before the rotation still verify against the archived "
            "public key."
        ),
    },
    {
        "layer": "Gateway receipt-signing key (agent:gate identity)",
        "functions": "gateway boot: _load_or_create_local_signer, _signer_key_path",
        "story": (
            "The local key persists at a host path (0600) and is loaded on "
            "every boot, so receipts verify across restarts and a restart "
            "keeps the same key id. Rotation is a deliberate restart "
            "procedure - archive the PEM, remove it, boot - and the new boot "
            "carries a new identity while the archived public key keeps "
            "verifying every old receipt offline. Corrupt key material is "
            "never silently regenerated: the gateway refuses to boot, "
            "because a fresh key would orphan the old receipts."
        ),
    },
    {
        "layer": "Agent API keys (credential store)",
        "functions": "AgentCredentialStore.issue, AgentCredentialStore.revoke",
        "story": (
            "Issuing a new key for an agent that already holds one replaces "
            "the active key; the old key stops verifying immediately and only "
            "its SHA-256 hash is ever written to disk. Re-enrolment is the "
            "same path: the plaintext replacement is shown once at issue "
            "time."
        ),
    },
    {
        "layer": "Agent identity descriptors",
        "functions": "AgentRegistry.enrol, update_descriptor, retire (raucle.agent_registry)",
        "story": (
            "Every state change - enrol, a manifest-key rotation via "
            "update_descriptor, retire - appends a NEW signed record; the "
            "history is never rewritten and the previous generation stays "
            "verifiable by its public key."
        ),
    },
]


def _demo_mode_on() -> bool:
    return os.environ.get("RAUCLE_DEMO_MODE", "").lower() in ("1", "true", "yes")


def _gate_enrolment_checks(gateway: Any) -> dict[str, Any]:
    """Re-check the gate identity's enrolment properties from its bytes."""
    import base64 as _base64
    import hashlib as _hashlib

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from raucle.provenance import _canonical_json

    gate = gateway.gate_identity
    stmt = gate.statement
    pem = gate.public_key_pem()
    if isinstance(pem, bytes):
        pem = pem.decode("ascii")
    key_id = getattr(gate, "key_id", None) or stmt.key_id
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError(f"gate public key is {type(key).__name__}, not Ed25519")
        key.verify(_base64.b64decode(stmt.signature), _canonical_json(stmt.body()))
        signature_ok = True
    except Exception:
        key = None
        signature_ok = False
    derived = _hashlib.sha256(pem.encode("ascii")).hexdigest()[:16]
    return {
        "key_id_binds_to_key_material": derived == key_id and derived == stmt.key_id,
        "identity_statement_signature_verified": signature_ok,
        "statement_key_type": type(key).__name__ if key is not None else "unverified",
    }


def _export_posture(gateway: Any) -> dict[str, Any]:
    """What this deployment's backend says about key material and export."""
    backend = str(gateway.config.signer_backend)
    if backend == "local":
        path = gateway._signer_key_path()
        exists = path.exists()
        mode = None
        if exists:
            mode = stat.S_IMODE(path.stat().st_mode)
        return {
            "backend": "local",
            "key_material_location": (
                "the gateway host: a 0600 Ed25519 PEM file next to the "
                "receipt store, loaded on boot, never served by any panel "
                "or API route"
            ),
            "signing_key_persisted": exists,
            "signing_key_permission": f"{mode:04o}" if mode is not None else None,
            "private_material_exported": False,
        }
    # KMS/HSM backends sign through the remote signer: key material is
    # never exported by the gateway at all - only the public half and
    # the signing handle travel with the deployment.
    return {
        "backend": backend,
        "key_material_location": (
            "the configured remote signing service (raucle.kms.create_signer): "
            "the gateway sends signatures requests, not key bytes, and the "
            "private key never leaves the provider boundary"
        ),
        "signing_key_local_file": False,
        "signing_key_permission": None,
        "private_material_exported": False,
    }


def build_demo_key_model(gateway: Any, pq_available: bool) -> dict[str, Any]:
    """Compose the deployment's real key model for the demo panel."""
    from cryptography.hazmat.primitives import serialization

    from raucle.gateway_app import _observed_signing_families

    pem = gateway.gate_identity.public_key_pem()
    if isinstance(pem, bytes):
        pem = pem.decode("ascii")
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    return {
        "note": KEY_MODEL_NOTE,
        "simulated": True,
        "signer_backend": gateway.config.signer_backend,
        "receipt_signing_key_id": getattr(gateway.gate_identity, "key_id", None)
        or gateway.gate_identity.statement.key_id,
        "key_material_type": type(key).__name__,
        "agent_id": gateway.gate_identity.agent_id,
        "gate_enrolment": _gate_enrolment_checks(gateway),
        "ml_dsa_available": bool(pq_available),
        "observed_signature_families_on_receipts": _observed_signing_families(gateway),
        "key_export_posture": _export_posture(gateway),
        "rotation_story": _ROTATION_STORY,
    }


def register_demo_key_model_routes(
    app: Any, check_auth: Any, check_access: Any, gateway_provider: Any
) -> None:
    """Register the read-only demo key-model endpoint on *app*."""

    from fastapi import Header, HTTPException

    from raucle.pq import pq_available

    @app.get(
        "/api/demo/key-model",
        responses={
            "401": {"description": "MFA required or missing Authorization header"},
            "403": {"description": "Invalid API key or insufficient role"},
            "404": {"description": "Demo mode not configured"},
        },
    )
    def demo_key_model(
        authorization: str | None = Header(None),
        x_totp: str | None = Header(None, alias="X-TOTP"),
    ) -> dict[str, Any]:
        user = check_auth(authorization, x_totp)
        check_access(user, "receipts")
        if not _demo_mode_on():
            raise HTTPException(404, "demo mode not configured")
        return build_demo_key_model(gateway_provider(), pq_available())
