"""X3 slice 3: receipted rotation of the operator plane's signing keys.

The operator's signing key (the persistent Ed25519 key that signs every
gate and admin-plane receipt) rotated until now only through hand-work:
generate a key, move the old file, re-publish by hand. These tests pin the
product form of that rotation, ``raucle operator rotate-keys``, on the J1
discipline (receipted, never deletes, fail-closed refusals):

* the Trust Registry holds BOTH keys across the transition: the old key
  RETIRED (still verifiable, so receipts minted before the rotation keep
  verifying) and the new key ACTIVE;
* every receipt stays pinned to the key id that signed it, and the
  verification path resolves that id through the registry, so nothing
  needs re-signing;
* revocation of the retired key stays a separate operator act (the trust
  cut), never part of the rotation;
* the gateway boot refuses a key-store/registry mismatch with a named
  restart-required error (the split-brain guard).
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.key_rotation import key_store_path


def _utc_today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _config(tmp_path: Path, *, segmented: bool = True) -> GatewayConfig:
    """Env-shaped config: the same store layout the gateway boots on, plus
    the operator key registry the rotation and the boot guard bind to."""
    return GatewayConfig(
        host="127.0.0.1",
        signer_backend="local",
        policy_file="",
        signer_key_path=str(tmp_path / "gateway-signing-key.pem"),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        receipt_store_dir=str(tmp_path / "receipts") if segmented else "",
        audit_chain=str(tmp_path / "audit.jsonl"),
        audit_persist=True,
        audit_log_file=str(tmp_path / "gateway-audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        operator_key_registry=str(tmp_path / "operator-registry.jsonl"),
    )


def _retired_key_name(config: GatewayConfig) -> Path:
    return Path(str(config.signer_key_path) + f".retired-{_utc_today()}")


def _registry_signer_pem_path(tmp_path: Path):
    """The registry's own operator key as a PEM file: the trust anchor for
    the operator key registry, deliberately NOT the rotating gateway key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from raucle.audit import Ed25519Signer

    private = Ed25519PrivateKey.generate()
    path = tmp_path / "registry-operator-key.pem"
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path, Ed25519Signer.from_pem(path.read_bytes())


def _bootstrap(tmp_path: Path, config: GatewayConfig, *, signed: bool = True):
    """The pre-rotation world, in the documented bootstrap order: the
    gateway boots first WITHOUT the registry discipline (its first boot
    creates the signing key), the operator then initialises the operator
    key registry and publishes that key, and every boot after binds to it
    (the split-brain guard passes because the registry vouches for the
    active key)."""
    from raucle.trust_registry import TrustRegistry

    registry_path = config.operator_key_registry
    config.operator_key_registry = ""
    gateway = RaucleGateway(config)
    old_kid = gateway._signer.key_id()
    gateway._sign_and_store_receipt(_gate_payload(gateway))
    config.operator_key_registry = registry_path

    pem_path, signer = _registry_signer_pem_path(tmp_path)
    reg = TrustRegistry(config.operator_key_registry, operator_signer=signer if signed else None)
    reg.publish(gateway._signer.public_key_pem(), issuer="raucle-gateway")
    # Prove the enrolment: a fresh boot passes the guard.
    assert RaucleGateway(config)._signer.key_id() == old_kid
    return gateway, old_kid, reg, signer, pem_path


def _gate_payload(gateway: RaucleGateway, *, parents: list[str] | None = None) -> dict:
    """A GUARDRAIL_SCAN-shaped receipt payload, the shape every gate and
    authority receipt carries (root-legal, taint-carrying, key-pinned)."""
    return {
        "iss": "raucle-gateway",
        "typ": "provenance-receipt/v1",
        "iat": 1,
        "agent_id": "agent:gate",
        "agent_key_id": gateway._signer.key_id(),
        "operation": "guardrail_scan",
        "parents": parents or [],
        "taint": ["gate:observed"],
        "input_hash": "sha256:" + "ab" * 32,
        "ruleset_hash": "sha256:" + "cd" * 32,
        "guardrail_verdict": "allowed",
    }


def _store_envelopes(config: GatewayConfig) -> list[dict]:
    """Every envelope in the receipt store, oldest first."""
    if config.receipt_store_dir:
        from raucle.receipt_store import SegmentedReceiptStore

        store = SegmentedReceiptStore(base_dir=config.receipt_store_dir)
        out = [store.find_by_hash(r["receipt_hash"]) for r in store.recent(limit=100)]
        return [rec for rec in reversed(out) if rec is not None]
    with open(config.receipt_store, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _chain_path(config: GatewayConfig) -> Path:
    if config.receipt_store_dir:
        from raucle.receipt_store import SegmentedReceiptStore

        store = SegmentedReceiptStore(base_dir=config.receipt_store_dir)
        return Path(config.receipt_store_dir) / (store.active_segment or "seg-000000.jsonl")
    return Path(config.receipt_store)


def _jws_payload(jws: str) -> dict:
    part = jws.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * ((4 - len(part) % 4) % 4)))


def _jws_header(jws: str) -> dict:
    part = jws.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(part + "=" * ((4 - len(part) % 4) % 4)))


def _b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * ((4 - len(part) % 4) % 4))


def _sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _verify_store_via_registry(config: GatewayConfig, reg) -> object:
    """The verification path the transition relies on: the verifier's key
    set resolved from the registry by key id, then the standard chain
    verifier over the WHOLE chain of record (every segment concatenated
    oldest-first, so cross-segment parent links resolve)."""
    from raucle.provenance import ProvenanceVerifier

    keys = {kid: pem.encode("ascii") for kid, pem in reg.as_issuer_map().items()}
    verifier = ProvenanceVerifier(public_keys=keys)
    if config.receipt_store_dir:
        from raucle.receipt_store import SegmentedReceiptStore

        store = SegmentedReceiptStore(base_dir=config.receipt_store_dir)
        paths = sorted(store.segments())
    else:
        paths = [Path(config.receipt_store)]
    lines: list[str] = []
    for path in paths:
        lines.extend(ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip())
    chain_file = Path(config.receipt_store).parent / "chain-for-verify.jsonl"
    chain_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return verifier.verify_chain(chain_file)


class TestRotateKeys:
    def test_rotation_round_trip(self, tmp_path):
        from raucle.key_rotation import ROTATE_COMMAND, rotate_keys

        config = _config(tmp_path)
        gateway, old_kid, _reg, signer, _pem = _bootstrap(tmp_path, config)
        old_key_pem = gateway._signer.public_key_pem()
        old_receipt_hash = _store_envelopes(config)[0]["receipt_hash"]

        result = rotate_keys(
            config, operator="craig", reason="quarterly rotation", registry_signer=signer
        )

        # The local key store now holds the NEW key (a fresh boot signs with it).
        assert result["old_key_id"] == old_kid
        assert result["new_key_id"] != old_kid
        assert result["boot"]["signer_key_id"] == result["new_key_id"]
        assert result["boot"]["canary_verified"] is True

        # The old key is archived retired-but-verifiable: never deleted,
        # digest printed (recorded in the result and in the receipt).
        retired = _retired_key_name(config)
        assert retired.is_file()
        assert result["archived_key"]["retired_path"] == str(retired)
        # D3 assert-close (checker 23 Nov): the new private key lands 0600
        # from creation (O_CREAT|O_EXCL with 0o600), matching the boot-
        # created key pin in tests/test_gateway_persistence.py.
        new_key_path = Path(key_store_path(config))
        assert new_key_path.is_file()
        assert (os.stat(new_key_path).st_mode & 0o777) == 0o600
        assert result["archived_key"]["sha256"] == _sha256_file(retired)
        assert result["archived_key"]["bytes"] == retired.stat().st_size

        # The registry update is receipted through the registry's own append
        # discipline: the old key retired, the new key active, same issuer.
        assert result["registry"]["path"] == config.operator_key_registry
        assert result["issuer"] == "raucle-gateway"
        reg2 = _reload_registry(config, signer)
        assert reg2.is_retired(old_kid)
        assert not reg2.is_revoked(old_kid)
        assert reg2.public_key(old_kid) == old_key_pem.decode("ascii")
        assert not reg2.is_retired(result["new_key_id"])
        assert reg2.verify_integrity(operator_public_pem=signer.public_key_pem())

        # The boundary receipt: a new link in the chain of record, signed by
        # the NEW key, parents the last receipt the old key signed.
        envelopes = _store_envelopes(config)
        assert len(envelopes) == 2
        receipt = envelopes[1]
        assert result["receipt_hash"] == receipt["receipt_hash"]
        header = _jws_header(receipt["jws"])
        assert header["kid"] == result["new_key_id"]
        payload = _jws_payload(receipt["jws"])
        assert payload["agent_key_id"] == result["new_key_id"]
        assert payload["parents"] == [old_receipt_hash]
        x = payload["x_key_rotation"]
        assert x["kind"] == "key_rotation"
        assert x["operator"] == "craig"
        assert x["reason"] == "quarterly rotation"
        assert x["rotate_command"] == ROTATE_COMMAND
        assert x["old_key_id"] == old_kid
        assert x["new_key_id"] == result["new_key_id"]
        assert x["archived_key"]["sha256"] == _sha256_file(retired)
        assert x["registry"]["head_hash"] == result["registry"]["head_hash"]

    def test_old_receipts_verify_post_rotation_and_new_receipts_carry_new_key_id(self, tmp_path):
        """The transition semantics: nothing re-signs. The receipt minted
        before the rotation verifies against the RETIRED key entry; the
        receipts minted after it carry the NEW key id; both resolve through
        the registry."""
        from raucle.key_rotation import rotate_keys

        config = _config(tmp_path)
        gateway, old_kid, reg, signer, _pem = _bootstrap(tmp_path, config)
        old_receipt = _store_envelopes(config)[0]
        assert _jws_header(old_receipt["jws"])["kid"] == old_kid

        rotate_keys(config, operator="craig", reason="transition", registry_signer=signer)

        # A FRESH boot signs with the new key: the gateway reboots clean and
        # its next receipt carries the new key id.
        gateway2 = RaucleGateway(config)
        assert gateway2._signer.key_id() != old_kid
        gateway2._sign_and_store_receipt(_gate_payload(gateway2))
        envelopes = _store_envelopes(config)
        assert len(envelopes) == 3
        assert _jws_header(envelopes[0]["jws"])["kid"] == old_kid
        assert _jws_header(envelopes[1]["jws"])["kid"] != old_kid
        assert _jws_header(envelopes[2]["jws"])["kid"] == gateway2._signer.key_id()

        # The whole chain verifies with keys resolved from the registry
        # alone: the old key is retired but resolvable, the new one active.
        reg2 = _reload_registry(config, signer)
        report = _verify_store_via_registry(config, reg2)
        assert report.valid, report.errors
        assert report.receipt_count == 3

    def test_dual_key_registry_window(self, tmp_path):
        """The registry holds BOTH keys during the transition: retired +
        active under one issuer name, and the registry still verifies."""
        from raucle.key_rotation import rotate_keys

        config = _config(tmp_path)
        gateway, old_kid, _reg, signer, _pem = _bootstrap(tmp_path, config)
        old_pem = gateway._signer.public_key_pem().decode("ascii")

        result = rotate_keys(config, operator="craig", reason="window", registry_signer=signer)

        reg = _reload_registry(config, signer)
        issuer_map = reg.as_issuer_map()
        assert old_kid in issuer_map
        assert result["new_key_id"] in issuer_map
        assert issuer_map[old_kid] == old_pem
        recs = {r.key_id: r for r in reg.records()}
        assert recs[old_kid].retired and not recs[old_kid].revoked
        assert not recs[result["new_key_id"]].retired
        active = [r.key_id for r in recs.values() if not r.retired and not r.revoked]
        assert active == [result["new_key_id"]]
        reg.verify_integrity(operator_public_pem=signer.public_key_pem())

    def test_revocation_of_retired_key_is_separate_from_rotation(self, tmp_path):
        """Rotation retires, never revokes. The trust cut is the operator's
        own later act, and it stops the old receipts verifying."""
        from raucle.key_rotation import rotate_keys
        from raucle.trust_registry import TrustRegistry

        config = _config(tmp_path)
        gateway, old_kid, reg, signer, _pem = _bootstrap(tmp_path, config)
        rotate_keys(config, operator="craig", reason="cut later", registry_signer=signer)

        reg = _reload_registry(config, signer)
        assert not reg.is_revoked(old_kid)
        assert reg.public_key(old_kid) is not None
        report = _verify_store_via_registry(config, reg)
        assert report.valid, report.errors

        # The separate act: revoking the retired key cuts it, and the old
        # receipt stops verifying (fail-closed, by name).
        reg2 = TrustRegistry(config.operator_key_registry, operator_signer=signer)
        reg2.revoke(old_kid, reason="operator decision after rotation")
        report = _verify_store_via_registry(config, reg2)
        assert not report.valid
        # The gateway itself is unaffected: its key is the active successor.
        assert RaucleGateway(config)._signer.key_id() != old_kid

    def test_fail_closed_on_registry_absence(self, tmp_path):
        from raucle.key_rotation import KeyRotationRefusedError, rotate_keys

        config = _config(tmp_path)
        gateway, old_kid, _reg, signer, _pem = _bootstrap(tmp_path, config)
        Path(config.operator_key_registry).unlink()

        with pytest.raises(KeyRotationRefusedError, match="operator key registry"):
            rotate_keys(config, operator="craig", reason="absent", registry_signer=signer)

        # All-or-nothing: the refusal touched nothing.
        assert gateway._signer.key_id() == old_kid
        assert Path(config.signer_key_path).is_file()
        assert not _retired_key_name(config).exists()
        assert len(_store_envelopes(config)) == 1

    def test_refuses_when_no_registry_configured(self, tmp_path):
        from raucle.key_rotation import KeyRotationRefusedError, rotate_keys

        config = _config(tmp_path)
        _bootstrap(tmp_path, config)
        # A deployment that never bound the registry: the rotation refuses
        # rather than mint keys an unbound registry cannot vouch for.
        config.operator_key_registry = ""

        with pytest.raises(KeyRotationRefusedError, match="RAUCLE_OPERATOR_KEY_REGISTRY"):
            rotate_keys(config, operator="craig", reason="unconfigured")

    def test_refuses_when_signing_key_not_registered(self, tmp_path):
        """Bootstrap honesty: the rotation only rotates a REGISTERED key; a
        registry that never vouched for the current key is a named refusal
        pointing at the bootstrap, not a silent first registration."""
        from raucle.key_rotation import KeyRotationRefusedError, rotate_keys

        config = _config(tmp_path)
        _gateway, _old_kid, _reg, signer, _pem = _bootstrap(tmp_path, config)
        # A SECOND, empty registry: configured but never shown this key.
        config.operator_key_registry = str(tmp_path / "other-registry.jsonl")
        from raucle.trust_registry import TrustRegistry

        TrustRegistry(config.operator_key_registry, operator_signer=signer)

        with pytest.raises(KeyRotationRefusedError, match="publish"):
            rotate_keys(config, operator="craig", reason="bootstrap", registry_signer=signer)

    def test_signed_registry_requires_its_operator_key(self, tmp_path):
        """A signed registry fails closed without its signing key: appending
        unsigned entries to a signed log would break every later verify."""
        from raucle.key_rotation import KeyRotationRefusedError, rotate_keys

        config = _config(tmp_path)
        _bootstrap(tmp_path, config)

        with pytest.raises(KeyRotationRefusedError, match="registry operator key"):
            rotate_keys(config, operator="craig", reason="unsigned append")

        assert not _retired_key_name(config).exists()
        assert len(_store_envelopes(config)) == 1

    def test_unsigned_registry_rotates_without_a_signer(self, tmp_path):
        from raucle.key_rotation import rotate_keys

        config = _config(tmp_path)
        _gateway, old_kid, _reg, _signer, _pem = _bootstrap(tmp_path, config, signed=False)

        result = rotate_keys(config, operator="craig", reason="unsigned registry")

        reg = _reload_registry(config)
        assert reg.is_retired(old_kid)
        assert not reg.is_retired(result["new_key_id"])
        reg.verify_integrity()

    def test_operator_identity_is_required_with_named_refusal(self, tmp_path, monkeypatch):
        from raucle.key_rotation import KeyRotationRefusedError, rotate_keys

        config = _config(tmp_path)
        _gateway, _old_kid, _reg, signer, _pem = _bootstrap(tmp_path, config)
        monkeypatch.delenv("RAUCLE_OPERATOR", raising=False)

        with pytest.raises(KeyRotationRefusedError, match="RAUCLE_OPERATOR"):
            rotate_keys(config, operator="", reason="who did this")

        monkeypatch.setenv("RAUCLE_OPERATOR", "env-operator")
        result = rotate_keys(config, operator="", reason="env identity", registry_signer=signer)
        receipt = _store_envelopes(config)[1]
        assert _jws_payload(receipt["jws"])["x_key_rotation"]["operator"] == "env-operator"
        assert result["receipt_hash"] == receipt["receipt_hash"]

    def test_second_rotation_same_day_refuses_idempotent_safe(self, tmp_path):
        from raucle.key_rotation import KeyRotationRefusedError, rotate_keys

        config = _config(tmp_path)
        _gateway, _old, _reg, signer, _pem = _bootstrap(tmp_path, config)
        rotate_keys(config, operator="craig", reason="first", registry_signer=signer)

        with pytest.raises(KeyRotationRefusedError, match="retired-"):
            rotate_keys(config, operator="craig", reason="second", registry_signer=signer)

        assert len(_store_envelopes(config)) == 2

    def test_refuses_when_nothing_to_rotate(self, tmp_path):
        from raucle.key_rotation import KeyRotationRefusedError, rotate_keys
        from raucle.trust_registry import TrustRegistry

        config = _config(tmp_path)
        signer = _registry_signer_pem_path(tmp_path)[1]
        TrustRegistry(config.operator_key_registry, operator_signer=signer)

        with pytest.raises(KeyRotationRefusedError, match="nothing to rotate"):
            rotate_keys(config, operator="craig", reason="no key", registry_signer=signer)

    def test_crash_window_registry_ahead_of_store_recovers(self, tmp_path):
        """A rotation that died between the registry update and the key
        store update leaves the registry AHEAD. The boot guard refuses that
        state (pinned below), and a re-run must not wedge: it rotates again,
        retiring the crashed attempt's public-only key visibly."""
        from raucle.key_rotation import rotate_keys

        config = _config(tmp_path)
        gateway, old_kid, reg, signer, _pem = _bootstrap(tmp_path, config)

        # Simulate the crash window: registry updated, store untouched.
        reg.retire(old_kid, reason="rotation attempt")
        from raucle.audit import Ed25519Signer

        crashed = Ed25519Signer.generate()
        reg.publish(crashed.public_key_pem(), issuer="raucle-gateway")

        result = rotate_keys(
            config, operator="craig", reason="retry after crash", registry_signer=signer
        )

        reg2 = _reload_registry(config, signer)
        assert reg2.is_retired(old_kid)
        assert reg2.is_retired(_key_id_for(crashed.public_key_pem())), (
            "the crashed attempt's key must retire visibly"
        )
        assert not reg2.is_retired(result["new_key_id"])
        active = [r.key_id for r in reg2.records() if not r.retired and not r.revoked]
        assert active == [result["new_key_id"]]
        assert result["boot"]["signer_key_id"] == result["new_key_id"]


def _reload_registry(config: GatewayConfig, signer=None):
    from raucle.trust_registry import TrustRegistry

    return TrustRegistry(config.operator_key_registry, operator_signer=signer)


def _key_id_for(public_pem: bytes) -> str:
    import hashlib

    return hashlib.sha256(public_pem).hexdigest()[:16]


class TestBootKeyRegistryGuard:
    """The split-brain guard: when an operator key registry is configured,
    the boot refuses a key store the registry does not vouch for, with a
    named restart-required error. Unset, the boot is exactly as before."""

    def _guarded_config(self, tmp_path):
        config = _config(tmp_path)
        _gateway, _old_kid, _reg, _signer, _pem = _bootstrap(tmp_path, config)
        return config

    def test_boot_passes_when_registry_matches(self, tmp_path):
        config = self._guarded_config(tmp_path)
        assert RaucleGateway(config)._signer.key_id()

    def test_boot_refuses_when_registry_moved_ahead(self, tmp_path):
        """The crash window / hand-restored old key: the local key is the
        RETIRED one, the registry's active key is elsewhere."""
        from raucle.key_rotation import KeyStoreRegistryMismatch
        from raucle.trust_registry import TrustRegistry

        config = self._guarded_config(tmp_path)
        signer = _registry_signer_pem_path(tmp_path)[1]
        reg = TrustRegistry(config.operator_key_registry, operator_signer=signer)
        local_kid = RaucleGateway(config)._signer.key_id()
        reg.retire(local_kid, reason="rotation landed, store did not")

        with pytest.raises(KeyStoreRegistryMismatch) as excinfo:
            RaucleGateway(config)
        message = str(excinfo.value)
        assert "restart" in message
        assert "raucle operator rotate-keys" in message

    def test_boot_refuses_unregistered_local_key(self, tmp_path):
        from raucle.key_rotation import KeyStoreRegistryMismatch

        config = self._guarded_config(tmp_path)
        config.operator_key_registry = str(tmp_path / "empty-registry.jsonl")
        from raucle.trust_registry import TrustRegistry

        TrustRegistry(config.operator_key_registry)

        with pytest.raises(KeyStoreRegistryMismatch, match="rotate-keys"):
            RaucleGateway(config)

    def test_boot_refuses_corrupted_registry(self, tmp_path):
        """D1 close (checker 23 Nov): a registry that exists but fails
        verification (tampered/corrupt bytes) is a named
        KeyStoreRegistryMismatch at boot with the restart-required guard."""
        from raucle.key_rotation import KeyStoreRegistryMismatch

        config = self._guarded_config(tmp_path)
        config.operator_key_registry = str(tmp_path / "corrupt-registry.jsonl")
        # A file exists, holds bytes, and fails TrustRegistry.load.
        Path(config.operator_key_registry).write_text("{not json at all", encoding="utf-8")

        with pytest.raises(KeyStoreRegistryMismatch, match="failed verification"):
            RaucleGateway(config)

    def test_boot_refuses_missing_registry_file(self, tmp_path):
        from raucle.key_rotation import KeyStoreRegistryMismatch

        config = self._guarded_config(tmp_path)
        Path(config.operator_key_registry).unlink()

        with pytest.raises(KeyStoreRegistryMismatch, match="RAUCLE_OPERATOR_KEY_REGISTRY"):
            RaucleGateway(config)

    def test_boot_refuses_revoked_local_key(self, tmp_path):
        from raucle.key_rotation import KeyStoreRegistryMismatch
        from raucle.trust_registry import TrustRegistry

        config = self._guarded_config(tmp_path)
        signer = _registry_signer_pem_path(tmp_path)[1]
        reg = TrustRegistry(config.operator_key_registry, operator_signer=signer)
        local_kid = RaucleGateway(config)._signer.key_id()
        reg.revoke(local_kid, reason="compromised")

        with pytest.raises(KeyStoreRegistryMismatch, match="revoked"):
            RaucleGateway(config)

    def test_boot_without_configured_registry_is_unchanged(self, tmp_path):
        """Opt-in: no operator key registry configured, no new refusal.
        Existing deployments boot exactly as before."""
        config = _config(tmp_path)
        config.operator_key_registry = ""
        assert RaucleGateway(config)._signer.key_id()

    def test_env_bonds_operator_key_registry(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAUCLE_OPERATOR_KEY_REGISTRY", str(tmp_path / "op-reg.jsonl"))
        assert GatewayConfig.from_env().operator_key_registry == str(tmp_path / "op-reg.jsonl")
        monkeypatch.delenv("RAUCLE_OPERATOR_KEY_REGISTRY")
        assert GatewayConfig.from_env().operator_key_registry == ""

    def test_kms_and_tee_backends_skip_the_guard(self, tmp_path):
        """The guard binds the LOCAL key store; KMS and TEE signers keep
        their own key lifecycle (named follow-up, not silently checked)."""
        config = self._guarded_config(tmp_path)
        config.signer_backend = "tee"
        config.tee_simulated = True
        # The simulated enclave generates its own key: the guard must not
        # refuse it against a registry that never saw it.
        assert RaucleGateway(config)._signer is not None


class TestRotateKeysCli:
    def test_cli_rotates_keys(self, tmp_path, monkeypatch, capsys):
        from raucle import cli

        config = _config(tmp_path, segmented=False)
        monkeypatch.setenv("RAUCLE_SIGNER", "local")
        monkeypatch.setenv("RAUCLE_POLICY_FILE", "")
        monkeypatch.setenv("RAUCLE_SIGNER_KEY_PATH", config.signer_key_path)
        monkeypatch.setenv("RAUCLE_RECEIPT_STORE", config.receipt_store)
        monkeypatch.setenv("RAUCLE_AUDIT_CHAIN", config.audit_chain)
        monkeypatch.setenv("RAUCLE_REGISTRY_PATH", config.registry_path)
        # First boot without the registry discipline (the documented
        # bootstrap order), then enrol the key, then bond the CLI to it.
        monkeypatch.delenv("RAUCLE_OPERATOR_KEY_REGISTRY", raising=False)
        registry_path = config.operator_key_registry
        config.operator_key_registry = ""
        gateway = RaucleGateway(config)
        gateway._sign_and_store_receipt(_gate_payload(gateway))
        config.operator_key_registry = registry_path
        pem_path, signer = _registry_signer_pem_path(tmp_path)
        from raucle.trust_registry import TrustRegistry

        TrustRegistry(config.operator_key_registry, operator_signer=signer).publish(
            gateway._signer.public_key_pem(), issuer="raucle-gateway"
        )
        monkeypatch.setenv("RAUCLE_OPERATOR_KEY_REGISTRY", config.operator_key_registry)
        monkeypatch.setenv("RAUCLE_REGISTRY_OPERATOR_KEY", str(pem_path))

        code = cli.main(["operator", "rotate-keys", "--operator", "craig", "--reason", "quarterly"])
        assert code == 0
        out = capsys.readouterr().out
        assert f".retired-{_utc_today()}" in out
        assert "sha256 " in out  # the archived key digest is printed
        assert "key rotation complete" in out

        # The env-bonded second run refuses same-day (idempotent-safe).
        code = cli.main(["operator", "rotate-keys", "--operator", "craig"])
        assert code == 1
        assert "already exists" in capsys.readouterr().err

    def test_cli_requires_operator_identity(self, tmp_path, monkeypatch, capsys):
        from raucle import cli

        config = _config(tmp_path, segmented=False)
        monkeypatch.setenv("RAUCLE_POLICY_FILE", "")
        monkeypatch.setenv("RAUCLE_SIGNER_KEY_PATH", config.signer_key_path)
        monkeypatch.setenv("RAUCLE_RECEIPT_STORE", config.receipt_store)
        monkeypatch.setenv("RAUCLE_AUDIT_CHAIN", config.audit_chain)
        monkeypatch.delenv("RAUCLE_OPERATOR_KEY_REGISTRY", raising=False)
        monkeypatch.delenv("RAUCLE_OPERATOR", raising=False)
        registry_path = config.operator_key_registry
        config.operator_key_registry = ""
        gateway = RaucleGateway(config)
        config.operator_key_registry = registry_path
        pem_path, signer = _registry_signer_pem_path(tmp_path)
        from raucle.trust_registry import TrustRegistry

        TrustRegistry(config.operator_key_registry, operator_signer=signer).publish(
            gateway._signer.public_key_pem(), issuer="raucle-gateway"
        )
        monkeypatch.setenv("RAUCLE_OPERATOR_KEY_REGISTRY", config.operator_key_registry)

        code = cli.main(["operator", "rotate-keys", "--reason", "anonymous"])
        assert code == 1
        assert "RAUCLE_OPERATOR" in capsys.readouterr().err
