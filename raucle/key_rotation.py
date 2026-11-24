"""Receipted rotation of the operator plane's signing keys (X3 slice 3).

The operator's signing key is the persistent Ed25519 key the gateway
loads at boot and signs every gate and admin-plane receipt with. Until
this module it rotated only through hand-work: generate a key, move the
old file by hand, re-publish by hand, and hope the receipts minted before
the move still verify. ``raucle operator rotate-keys`` is the product
form of that rotation, on the J1 discipline (receipted, never deletes,
named fail-closed refusals).

The transition, in order:

1. Generate the new keypair.
2. Re-register the new public key in the operator key registry (the
   Trust Registry's own append discipline: hash-chained entries,
   operator-signed when the registry is signed). The old key RETIRES, a
   registry state distinct from revocation: a retired key still resolves,
   so every receipt it signed keeps verifying, while it stops holding
   the issuer name so the successor may publish under it. The registry
   holds BOTH keys across the transition: retired + active.
3. Archive the old key file as retired-but-verifiable: a rename to
   ``<key>.retired-<date>`` in the same directory, NEVER a delete, the
   digest printed and recorded in the receipt.
4. Update the local key store (the new private key, 0600 from creation).
5. Mint the boundary receipt: a new link in the chain of record, signed
   by the NEW key (the first receipt pinned to it), carrying both key
   ids, the archived key digest, the registry head after the update, the
   operator identity and the reason. Prior links are never rewritten.
6. Verify a fresh boot signs with the new key, and that the canary it
   signs verifies against the registry's active entry.

Nothing requires re-signing history: every receipt stays pinned to the
key id that signed it, and the verification path resolves that id
through the registry (retired or active). Revocation of the retired key
is a separate operator act (``raucle registry revoke``), the trust cut,
never part of the rotation.

Crash window, stated honestly: the registry update lands before the key
store moves. A crash between the two leaves the registry AHEAD of the
store; the boot's split-brain guard refuses that state with a named
restart-required error, and a re-run of rotate-keys recovers without
wedging: the crashed attempt's public-only key retires visibly and a
fresh key takes the name.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from raucle.errors import KeyRotationRefusedError, KeyStoreRegistryMismatch

if TYPE_CHECKING:
    from raucle.gateway import GatewayConfig

logger = logging.getLogger(__name__)

#: The operator command the guard, the refusals and the receipt name.
ROTATE_COMMAND = "raucle operator rotate-keys"

# Receipt vocabulary constants, mirroring the gateway's own (the same
# local-copy discipline as chain_rotation: no import cycle with the
# gateway that consumes this module at boot).
_RECEIPT_TYP = "provenance-receipt/v1"
_RECEIPT_CRIT = "raucle/v1"
_GATE_AGENT_ID = "agent:gate"

_HASH_PREFIX = "sha256:"


def _utc_today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def key_store_path(config: GatewayConfig) -> Path:
    """Where the local signing key persists (the boot's own derivation)."""
    if config.signer_key_path:
        return Path(config.signer_key_path)
    return Path(config.receipt_store).parent / "gateway-signing-key.pem"


def retired_key_name(path: str | Path, date: str | None = None) -> Path:
    """The dated retirement path for a key file, in the same directory.

    ``gateway-signing-key.pem`` -> ``gateway-signing-key.pem.retired-<date>``.
    The retirement is a rename: same parent directory, dated suffix, never
    a delete and never a cross-device move (the rotate-chain archive
    discipline, named for what a key retirement is).
    """
    resolved = Path(path)
    return resolved.with_name(resolved.name + f".retired-{date or _utc_today()}")


def _registry_declares_signed(path: Path) -> bool:
    """The registry's own header says whether its entries are signed."""
    first = path.read_text(encoding="utf-8").splitlines()[0]
    return bool(json.loads(first).get("signed"))


def _mint_key_rotation_receipt(
    config: GatewayConfig,
    *,
    operator: str,
    reason: str,
    rotated_at: str,
    old_key_id: str,
    new_signer: Any,
    archived_key: dict[str, Any],
    registry: dict[str, Any],
    parents: list[str],
) -> dict[str, str]:
    """Sign the key-rotation receipt and append it to the chain of record.

    Same GUARDRAIL_SCAN-shaped provenance receipt as the gate's authority
    receipts (verifiable through the standard chain verifier), signed by
    the NEW key so the boundary link is the first receipt pinned to it,
    with an ``x_key_rotation`` extension binding both key ids, the
    archived key digest, the registry head and the operator identity.
    """
    from raucle.provenance import _b64url_encode, _canonical_json, _sha256_hex

    new_key_id = new_signer.key_id()
    extension = {
        "kind": "key_rotation",
        "operator": operator,
        "reason": reason,
        "rotated_at": rotated_at,
        "rotate_command": ROTATE_COMMAND,
        "old_key_id": old_key_id,
        "new_key_id": new_key_id,
        "archived_key": archived_key,
        "registry": registry,
    }
    payload: dict[str, Any] = {
        "iss": "raucle-gateway",
        "typ": _RECEIPT_TYP,
        "iat": int(time.time()),
        "agent_id": _GATE_AGENT_ID,
        "agent_key_id": new_key_id,
        "operation": "guardrail_scan",
        "parents": parents,
        "taint": ["gate:observed"],
        "input_hash": _sha256_hex(_canonical_json(extension)),
        "ruleset_hash": _sha256_hex(_canonical_json(extension)),
        "guardrail_verdict": "allowed",
        "x_key_rotation": extension,
    }
    header = {
        "alg": "EdDSA",
        "typ": _RECEIPT_TYP,
        "kid": new_key_id,
        "crit": [_RECEIPT_CRIT],
        _RECEIPT_CRIT: "provenance",
    }
    signing_input = (
        _b64url_encode(_canonical_json(header)) + "." + _b64url_encode(_canonical_json(payload))
    ).encode("ascii")
    signature = new_signer.sign(signing_input)
    jws = signing_input.decode("ascii") + "." + _b64url_encode(signature)
    receipt_hash = _HASH_PREFIX + _sha256_hex(jws.encode("ascii"))
    line = json.dumps({"receipt_hash": receipt_hash, "jws": jws}, ensure_ascii=False)

    if config.receipt_store_dir:
        from raucle.receipt_store import SegmentedReceiptStore

        store = SegmentedReceiptStore(base_dir=config.receipt_store_dir)
        store.append_line(line)
        receipt_path = str(
            Path(config.receipt_store_dir) / (store.active_segment or "seg-000000.jsonl")
        )
    else:
        path = Path(config.receipt_store)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        receipt_path = str(path)
    return {"receipt_hash": receipt_hash, "path": receipt_path}


def rotate_keys(
    config: GatewayConfig,
    *,
    operator: str = "",
    reason: str = "",
    registry_signer: Any = None,
) -> dict[str, Any]:
    """The receipted operator key rotation behind ``raucle operator rotate-keys``.

    For a gateway deployment whose signing key is registered in the
    operator key registry, this rotates the key end to end: it generates
    the successor, re-registers it through the registry's append
    discipline (the old key retiring, still verifiable), archives the old
    key file (never deletes, digest printed), updates the local key store,
    records the boundary as a signed ``x_key_rotation`` receipt in the
    chain of record and verifies a fresh boot signs with the new key.

    ``registry_signer`` is the registry's own operator key (an
    :class:`~raucle.audit.Ed25519Signer`), required when the registry is
    signed so the rotation's entries are signed like every other entry;
    omitted is valid only for an unsigned (integrity-only) registry.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from raucle.chain_rotation import _digest_file, _gate_signer, _store_tail_receipt_hash
    from raucle.trust_registry import RegistryIntegrityError, TrustRegistry, _canon_issuer

    # -- refusals, all before any side effect (all-or-nothing) ------------
    operator = operator.strip() or os.environ.get("RAUCLE_OPERATOR", "").strip()
    if not operator:
        raise KeyRotationRefusedError(
            "key rotation refused: no operator identity. Pass --operator or set "
            "RAUCLE_OPERATOR; the rotation receipt must attribute the action to "
            "a named operator."
        )
    reg_path = (config.operator_key_registry or "").strip()
    if not reg_path:
        raise KeyRotationRefusedError(
            "key rotation refused: no operator key registry configured. The "
            "rotation re-registers the signing key through it (set "
            "RAUCLE_OPERATOR_KEY_REGISTRY); without a registry, receipts "
            "minted before a rotation could not verify afterwards."
        )
    if not Path(reg_path).is_file():
        raise KeyRotationRefusedError(
            f"key rotation refused: the operator key registry {reg_path} does not "
            "exist (fail-closed). Initialise it and publish the current key "
            "first (raucle registry init / raucle registry publish), or unset "
            "RAUCLE_OPERATOR_KEY_REGISTRY."
        )
    key_path = key_store_path(config)
    if not key_path.is_file():
        raise KeyRotationRefusedError(
            f"nothing to rotate: no signing key at {key_path} (the gateway boot "
            "creates it on first start; rotate after the gateway has signed at "
            "least once)."
        )
    retired = retired_key_name(key_path)
    if retired.exists():
        raise KeyRotationRefusedError(
            f"key rotation refused: {retired} already exists (a key retired "
            f"today is present); a same-day retirement must never be "
            "overwritten. Inspect or move it, or rotate after midnight UTC."
        )
    if _registry_declares_signed(Path(reg_path)) and registry_signer is None:
        raise KeyRotationRefusedError(
            f"key rotation refused: {reg_path} is a signed registry; supply the "
            "registry operator key (--registry-key or RAUCLE_REGISTRY_OPERATOR_KEY) "
            "so the rotation's entries are signed like every other entry. An "
            "unsigned append would break the registry's own verification."
        )

    old_signer = _gate_signer(config)
    old_key_id = old_signer.key_id()
    try:
        registry = TrustRegistry(reg_path, operator_signer=registry_signer)
    except RegistryIntegrityError as exc:
        raise KeyRotationRefusedError(
            f"key rotation refused: the operator key registry {reg_path} fails "
            f"integrity verification ({exc}); a rotation must never build on a "
            "registry that cannot be verified. Restore a verifiable registry "
            "first, then rotate."
        ) from exc
    old_record = registry.resolve(old_key_id)
    if old_record is None:
        raise KeyRotationRefusedError(
            f"key rotation refused: the signing key {old_key_id} is not "
            f"registered in {reg_path}. Publish the current key first "
            "(raucle registry publish --issuer <name>), then rotate: the "
            "rotation re-registers what the registry vouches for, never "
            "registers a key it has never seen."
        )
    if old_record.revoked:
        raise KeyRotationRefusedError(
            f"key rotation refused: the signing key {old_key_id} is revoked in "
            f"{reg_path}. Rotation is not the un-revoke path; publish a fresh "
            "key by hand or restore a published one."
        )
    crash_recovery = old_record.retired
    if crash_recovery:
        logger.warning(
            "key rotation: the local key %s is RETIRED in %s (a previous "
            "rotation's registry update landed without its key-store update, "
            "or the old key was hand-restored). Rotating again; the crashed "
            "attempt's public-only key retires visibly.",
            old_key_id,
            reg_path,
        )
    issuer_name = old_record.issuer

    # -- 1. the successor keypair ------------------------------------------
    new_private = Ed25519PrivateKey.generate()
    new_public_pem = new_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    new_key_id = hashlib.sha256(new_public_pem).hexdigest()[:16]

    # -- 2. the receipted registry update (append discipline) ---------------
    # The crashed attempt's key, when the registry moved ahead of the
    # store, retires visibly: it holds the issuer name but its private
    # half is presumed lost with the crashed run.
    retired_others: list[str] = []
    if crash_recovery:
        for other in registry.records():
            if other.key_id in (old_key_id, new_key_id) or other.revoked or other.retired:
                continue
            if _canon_issuer(other.issuer) == _canon_issuer(issuer_name):
                registry.retire(
                    other.key_id,
                    reason=f"superseded: {ROTATE_COMMAND} retry after crash window",
                )
                retired_others.append(other.key_id)
    if not old_record.retired:
        registry.retire(old_key_id, reason=reason or "operator key rotation")
    registry.publish(new_public_pem, issuer=issuer_name)
    head = registry.head()
    # Guardrail: the registry we just appended to still verifies.
    if registry_signer is not None:
        registry.verify_integrity(operator_public_pem=registry_signer.public_key_pem())
    else:
        registry.verify_integrity()
    registry_report = {
        "path": str(reg_path),
        "head_index": head["index"],
        "head_hash": head["hash"],
    }
    if retired_others:
        registry_report["retired_others"] = retired_others

    # -- 3. archive the old key retired-but-verifiable (never deletes) ------
    archived_key = _digest_file(key_path)
    archived_key["retired_path"] = str(retired)
    os.rename(key_path, retired)
    logger.info(
        "rotate-keys retired the old key %s (%s, %d bytes) to %s",
        old_key_id,
        archived_key["sha256"],
        archived_key["bytes"],
        retired,
    )

    # -- 4. the local key store holds the new key (0600 from creation) ------
    new_private_pem = new_private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(new_private_pem)
        fh.flush()
        os.fsync(fh.fileno())

    # -- 5. the boundary receipt, signed by the NEW key ---------------------
    new_signer = _gate_signer(config)  # the boot's own load path: proves 4 landed
    receipt = _mint_key_rotation_receipt(
        config,
        operator=operator,
        reason=reason,
        rotated_at=datetime.now(timezone.utc).isoformat(),
        old_key_id=old_key_id,
        new_signer=new_signer,
        archived_key=archived_key,
        registry=registry_report,
        parents=[tail] if (tail := _store_tail_receipt_hash(config)) else [],
    )

    # -- 6. verify: a fresh boot signs with the new key ----------------------
    boot_key_id = new_signer.key_id()
    if boot_key_id != new_key_id:
        raise RuntimeError(
            f"key rotation verification failed: the key store holds {boot_key_id} "
            f"after the rotation wrote {new_key_id}; the boot would sign with "
            "an unexpected key. Inspect the key store and the registry."
        )
    canary = f"{ROTATE_COMMAND} verification canary".encode("ascii")
    signature = new_signer.sign(canary)
    resolved_pem = registry.public_key(new_key_id)
    if resolved_pem is None:
        raise RuntimeError(
            f"key rotation verification failed: the new key {new_key_id} does "
            f"not resolve in {reg_path}; the registry update did not land."
        )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    loaded = serialization.load_pem_public_key(resolved_pem.encode("ascii"))
    if not isinstance(loaded, Ed25519PublicKey):
        raise RuntimeError(
            f"key rotation verification failed: the registry entry for "
            f"{new_key_id} is not an Ed25519 public key."
        )
    loaded.verify(signature, canary)

    logger.info(
        "rotate-keys complete: old key %s retired (verifiable), new key %s "
        "active, receipt %s, fresh boot verified",
        old_key_id,
        new_key_id,
        receipt["receipt_hash"],
    )
    return {
        "rotated_on": _utc_today(),
        "old_key_id": old_key_id,
        "new_key_id": new_key_id,
        "issuer": issuer_name,
        "archived_key": archived_key,
        "key_store": str(key_path),
        "registry": registry_report,
        "receipt_hash": receipt["receipt_hash"],
        "receipt_path": receipt["path"],
        "boot": {"signer_key_id": boot_key_id, "canary_verified": True},
    }


def verify_boot_key_against_registry(config: GatewayConfig, signer: Any) -> None:
    """The boot's split-brain guard (X3 slice 3).

    When an operator key registry is configured, the local signing key
    must be the registry's vouched-for ACTIVE entry. The boot refuses,
    with a named restart-required :class:`KeyStoreRegistryMismatch`, when

    * the registry file is missing, unparseable, or fails integrity
      verification (Q10: the tampered-HISTORY class too - reordered
      entries, swapped key material - not just unparseable bytes),
    * the registry moved backward or sideways against the head the guard
      last served on (Q10: a truncated or rolled-back tail verifies on
      its own, so the guard records the head it served on in a
      ``<registry>.head-pin`` file and refuses a shorter or changed one),
    * the registry never saw the key, or it retired or revoked it.

    Receipts must never split from the registry state that vouches for
    them, and the guard binds at construction, so every reconcile names
    the restart.
    """
    from raucle.trust_registry import RegistryIntegrityError, TrustRegistry

    path = config.operator_key_registry
    key_id = signer.key_id()
    if not Path(path).is_file():
        raise KeyStoreRegistryMismatch(
            f"the operator key registry {path} is configured "
            f"(RAUCLE_OPERATOR_KEY_REGISTRY) but does not exist; the boot cannot "
            f"vouch for the signing key {key_id}. Initialise the registry and "
            "publish the current key (raucle registry init / publish), or unset "
            "the variable, then restart the gateway."
        )
    try:
        registry = TrustRegistry.load(path)
    except (RegistryIntegrityError, ValueError, OSError) as exc:
        raise KeyStoreRegistryMismatch(
            f"the operator key registry {path} failed verification: {exc}. "
            "Restore a verifiable registry, then restart the gateway."
        ) from exc
    head = _check_recorded_head(path, registry)
    record = registry.resolve(key_id)
    if record is None:
        raise KeyStoreRegistryMismatch(
            f"the local signing key {key_id} is not registered in the operator "
            f"key registry {path}; the boot refuses to serve receipts on a key "
            "the registry does not vouch for. Publish the current key "
            f"(raucle registry publish), rotate with '{ROTATE_COMMAND}' after "
            "publishing, then restart the gateway."
        )
    if record.revoked:
        raise KeyStoreRegistryMismatch(
            f"the local signing key {key_id} is revoked in the operator key "
            f"registry {path}; the boot refuses to serve receipts on a "
            "revoked key. Publish a fresh key and rotate, then restart the "
            "gateway."
        )
    if record.retired:
        raise KeyStoreRegistryMismatch(
            f"the local signing key {key_id} is RETIRED in the operator key "
            f"registry {path}: the registry moved ahead of the key store (a "
            "rotation's registry update landed without its key-store update, "
            f"or an old key was hand-restored). Re-run '{ROTATE_COMMAND}' to "
            "finish the transition, then restart the gateway; receipts must "
            "never split from the registry state that vouches for them."
        )
    logger.info(
        "operator key registry %s vouches for the active signing key %s",
        path,
        key_id,
    )
    # The guard served on this head: record it, so a later truncation or
    # rollback (a prefix that verifies on its own) is refused at boot.
    _write_head_pin(registry_head_pin_path(path), head)


def registry_head_pin_path(registry_path: str | Path) -> Path:
    """The guard's recorded consumer anchor for an operator key registry:
    the file holding the head (``index`` + ``hash``) the guard last served
    on, written beside the registry itself."""
    return Path(str(registry_path) + ".head-pin")


def _read_head_pin(pin_path: Path) -> dict[str, Any] | None:
    """The recorded head, or None when the guard has never served on this
    registry. An unreadable pin is a named restart-required refusal: it is
    trust state, never silently discarded."""
    if not pin_path.is_file():
        return None
    try:
        pin = json.loads(pin_path.read_text(encoding="utf-8"))
        if (
            not isinstance(pin, dict)
            or not isinstance(pin.get("index"), int)
            or not isinstance(pin.get("hash"), str)
        ):
            raise ValueError("the pin is not an index/hash object")
    except (OSError, ValueError) as exc:
        raise KeyStoreRegistryMismatch(
            f"the operator key registry's recorded head pin {pin_path.name} is "
            f"unreadable ({type(exc).__name__}): the boot cannot tell a truncation "
            "from an honest registry. Restore the pin file from the registry's "
            "last verified head, or remove it ONLY after confirming no rollback "
            "happened, then restart the gateway."
        ) from None
    return pin


def _write_head_pin(pin_path: Path, head: dict[str, Any]) -> None:
    """Record the head the guard just served on (atomic write, so a crash
    mid-write never leaves a half pin). A failure to record is a warning,
    not a refusal: the pin deepens the guard, it does not gate it."""
    tmp = pin_path.with_suffix(pin_path.suffix + ".tmp")
    try:
        tmp.write_text(json.dumps({"index": head["index"], "hash": head["hash"]}), encoding="utf-8")
        os.replace(tmp, pin_path)
    except OSError:
        logger.warning(
            "could not record the operator key registry head pin at %s: the next "
            "boot cannot detect a truncated or rolled-back registry",
            pin_path,
        )


def _check_recorded_head(path: str, registry: Any) -> dict[str, Any]:
    """Refuse a registry that moved BACKWARD or SIDEWAYS relative to the
    head the guard last served on (Q10): a truncated or rolled-back TAIL
    verifies on its own (every remaining entry is chain-legal), so chain
    verification alone cannot see it. Forward growth is honest and re-records
    the head; the same index with a different hash is tampering.

    Returns the head (for pin recording). Raises KeyStoreRegistryMismatch on
    a refusal; the remedy for a legitimately re-initialised registry is the
    documented consumer reset (delete the pin file, restart)."""
    head = registry.head()
    pin_path = registry_head_pin_path(path)
    pin = _read_head_pin(pin_path)
    if pin is None:
        return head
    if head["index"] < pin["index"]:
        raise KeyStoreRegistryMismatch(
            f"the operator key registry {path} moved BACKWARD: its head index "
            f"{head['index']} is below the recorded pin ({pin['index']}). A shorter "
            "registry prefix verifies on its own (a truncated or rolled-back tail), "
            "so the boot refuses it as tampering or a rollback. Restore the fuller "
            "registry, or - only after confirming it was legitimately "
            f"re-initialised - remove the recorded pin ({pin_path}) and restart "
            "the gateway."
        )
    if head["index"] == pin["index"] and head["hash"] != pin["hash"]:
        raise KeyStoreRegistryMismatch(
            f"the operator key registry {path} moved SIDEWAYS: the head hash at "
            f"index {head['index']} differs from the recorded pin. Same-length "
            "history with different content is tampering the chain cannot see on "
            "its own. Restore the registry the boot served on, or - only after "
            "confirming it was legitimately re-initialised - remove the recorded "
            f"pin ({pin_path}) and restart the gateway."
        )
    return head


__all__ = [
    "ROTATE_COMMAND",
    "KeyStoreRegistryMismatch",
    "key_store_path",
    "registry_head_pin_path",
    "retired_key_name",
    "rotate_keys",
    "verify_boot_key_against_registry",
]
