"""F (Q11): signed audit production strict mode.

Pre-Q11: HashChainSink warns and continues when constructed without a
signer, a checkpoint that cannot be generated is a silent log-only skip,
and nothing in the health readiness payload says whether the audit chain
is attributed. These tests pin the close:

- RAUCLE_REQUIRE_SIGNED_AUDIT=1: boot refuses by name when the signer is
  unavailable (HashChainSink, sink_from_env and the gateway boot),
- the checkpoint failure surfaces through the sink's named status/refusal
  channel, not only a log line,
- the signature status is an honest field in the boot readiness payload,
- operator key rotation keeps historical records verifiable: the
  old-signed archive verifies with the old public key, the new-signed
  chain verifies with the new public key, both through the existing
  verifier paths.
"""

from __future__ import annotations

import json

import pytest

from raucle.audit import ENV_AUDIT_REQUIRE_SIGNED, AuditVerifier, Ed25519Signer, HashChainSink
from raucle.errors import ConfigurationError
from raucle.gateway import GatewayConfig, RaucleGateway

# A minimal VALID policy file for the gateway fixtures (the loader schema)
POLICY = """
version: 1
issuer: test.bank
policies: []
"""


def _receipt_config(tmp_path) -> GatewayConfig:
    # A minimal VALID policy file (the schema is a mapping: version, issuer
    # and an optional policies list): policy_file="" falls through to Path("."),
    # which exists as a directory, and the loader logs an IsADirectoryError
    # on every construction.
    policy_path = tmp_path / "policies.yaml"
    policy_path.write_text(POLICY, encoding="utf-8")
    return GatewayConfig(
        host="127.0.0.1",
        signer_backend="local",
        policy_file=str(policy_path),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        receipt_store_dir=str(tmp_path / "receipts"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        audit_log_file=str(tmp_path / "gateway-audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
    )


def _write_key(path, private_key) -> None:
    from cryptography.hazmat.primitives import serialization

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    import os

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)


class TestStrictSignedBoot:
    def test_boot_refuses_when_require_signed_without_signer(self, tmp_path):
        """The named strict mode refuses an unattributed audit chain at
        boot instead of warning and continuing."""
        path = str(tmp_path / "audit.jsonl")
        with pytest.raises(ConfigurationError) as excinfo:
            HashChainSink(path, require_signed=True)
        msg = str(excinfo.value)
        assert "RAUCLE_REQUIRE_SIGNED_AUDIT" in msg
        assert "signer" in msg
        # The refusal happens before any bytes land on disk.
        import os

        assert not os.path.exists(path)

    def test_boot_constructs_with_a_signer_under_strict(self, tmp_path):
        path = str(tmp_path / "audit.jsonl")
        signer = Ed25519Signer.generate()
        sink = HashChainSink(path, signer=signer, require_signed=True)
        sink.append({"ok": True})
        sink.close()
        assert sink.status()["signed"] is True
        assert sink.status()["key_id"] == signer.key_id()

    def test_sink_from_env_stricts_without_a_key(self, tmp_path, monkeypatch):
        from raucle.audit import sink_from_env

        path = str(tmp_path / "audit.jsonl")
        monkeypatch.setenv("RAUCLE_AUDIT_PATH", path)
        monkeypatch.setenv(ENV_AUDIT_REQUIRE_SIGNED, "1")
        with pytest.raises(ConfigurationError) as excinfo:
            sink_from_env()
        assert "RAUCLE_REQUIRE_SIGNED_AUDIT" in str(excinfo.value)

    def test_sink_from_env_strict_accepts_a_valid_key(self, tmp_path, monkeypatch):
        from cryptography.hazmat.primitives import serialization

        from raucle.audit import sink_from_env

        signer = Ed25519Signer.generate()
        pem = signer._private_key.private_bytes(  # noqa: SLF001 - test-only export
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        monkeypatch.setenv("RAUCLE_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
        monkeypatch.setenv(ENV_AUDIT_REQUIRE_SIGNED, "1")
        monkeypatch.setenv("RAUCLE_AUDIT_PRIVATE_KEY_PEM", pem.decode("ascii"))
        sink = sink_from_env()
        assert sink is not None
        assert sink.status()["signed"] is True
        sink.close()

    def test_gateway_boot_refuses_unsigned_audit_chain_in_strict_mode(self, tmp_path):
        """The gateway under the strict flag refuses to boot on an audit
        chain whose genesis is unsigned (the writer's key cannot attest
        it), naming the flag and the rotate path."""
        config = _receipt_config(tmp_path)
        # Seed an unsigned genesis the strict boot must refuse.
        HashChainSink(config.audit_chain).close()
        config.require_signed_audit = True
        with pytest.raises(Exception) as excinfo:
            RaucleGateway(config)
        msg = str(excinfo.value)
        assert "RAUCLE_REQUIRE_SIGNED_AUDIT" in msg
        assert str(config.audit_chain) in msg
        assert "rotate-chain" in msg

    def test_gateway_boot_refuses_when_the_signer_is_unavailable(self, tmp_path):
        """A corrupt signing key is an unavailable signer: the strict
        boot refuses by name (the non-strict boot already fails closed;
        the strict refusal names the mode)."""
        config = _receipt_config(tmp_path)
        key_path = tmp_path / "gateway-signing-key.pem"
        key_path.write_bytes(b"this is not a pem key")
        config.signer_key_path = str(key_path)
        config.require_signed_audit = True
        from raucle.audit import ENV_AUDIT_REQUIRE_SIGNED

        with pytest.raises(Exception) as excinfo:
            RaucleGateway(config)
        msg = str(excinfo.value)
        assert ENV_AUDIT_REQUIRE_SIGNED in msg
        assert "signer" in msg or "signing key" in msg


class TestStatusChannel:
    def test_checkpoint_failure_surfaces_named_advisory(self, tmp_path, caplog):
        """A checkpoint that cannot be generated surfaces through the
        sink's named status/refusal channel, not a silent skip."""
        path = str(tmp_path / "audit.jsonl")
        signer = Ed25519Signer.generate()
        first = HashChainSink(path, signer=signer, checkpoint_every=1)
        first.append({"a": 1})
        first.close()
        # Delete the frontier sidecar: the resumed sink cannot anchor.
        import os

        os.remove(path + ".frontier.json")
        resumed = HashChainSink(path, signer=signer)
        result = resumed.emit_checkpoint()
        assert result is None
        advisories = resumed.status()["advisories"]
        checkpoint_refusals = [a for a in advisories if a.get("kind") == "checkpoint_skipped"]
        assert checkpoint_refusals, "checkpoint failure was silent"
        assert "frontier" in checkpoint_refusals[0].get("detail", "")

    def test_foreign_head_adoption_names_itself_and_keeps_the_chain_valid(self, tmp_path):
        """A writer that slept while another advanced the disk chain
        adopts the true head by name; checkpoint anchoring degrades with
        a named refusal rather than emitting an unverifiable checkpoint."""
        path = str(tmp_path / "audit.jsonl")
        signer = Ed25519Signer.generate()
        a = HashChainSink(path, signer=signer, checkpoint_every=1000)
        a.append({"writer": "a", "seq": 0})
        b = HashChainSink(path)
        b.append({"writer": "b", "seq": 0})
        record = a.append({"writer": "a", "seq": 1})
        assert record["index"] == 2

        adoption = [
            x for x in a.status()["advisories"] if x.get("kind") == "head_adopted_from_disk"
        ]
        assert adoption, "foreign head adoption was silent"

        result = a.emit_checkpoint()
        assert result is None
        refusals = [x for x in a.status()["advisories"] if x.get("kind") == "checkpoint_skipped"]
        assert refusals, "degraded checkpoint was silent"

        b.close()
        a.close()
        report = AuditVerifier().verify_chain(path)
        assert report.valid, report.errors
        assert report.event_count == 3

    def test_status_reports_signing_state(self, tmp_path):
        path = str(tmp_path / "audit.jsonl")
        unsigned = HashChainSink(path)
        assert unsigned.status()["signed"] is False
        assert unsigned.status()["key_id"] is None
        unsigned.close()
        signed = HashChainSink(path + "-signed", signer=Ed25519Signer.generate())
        assert signed.status()["signed"] is True
        signed.close()


class TestReadinessField:
    def test_boot_readiness_carries_the_audit_chain_signing_flag(self):
        from raucle.boot_stream import BootReadiness

        br = BootReadiness()
        snapshot = br.snapshot()
        assert snapshot["audit_chain"]["state"] == "pending"
        assert snapshot["audit_chain"]["key_id"] is None
        br.set_audit_chain(state="signed", key_id="0123456789abcdef")
        snapshot = br.snapshot()
        assert snapshot["audit_chain"] == {"state": "signed", "key_id": "0123456789abcdef"}
        br.set_audit_chain(state="unsigned", key_id=None)
        assert br.snapshot()["audit_chain"]["state"] == "unsigned"

    def test_gateway_health_payload_reports_the_actual_chain_state(self, tmp_path):
        """The readiness payload on /health reports what the audit chain
        on disk actually is (an honest field, not the config's wish)."""
        config = _receipt_config(tmp_path)
        HashChainSink(config.audit_chain).close()  # unsigned genesis on disk
        config.receipt_index_path = str(tmp_path / "index.sqlite")
        gateway = RaucleGateway(config)
        from raucle.gateway_app import _health_payload

        payload = _health_payload(gateway)
        readiness = payload["readiness"]
        assert readiness["audit_chain"]["state"] == "unsigned"
        assert readiness["audit_chain"]["key_id"] is None


class TestKeyRotation:
    def test_rotation_keeps_old_signed_and_new_signed_records_verifiable(self, tmp_path):
        """Rotate the operator key: the archived chain (old-signed) and
        the fresh chain (new-signed) each verify through the existing
        verifier paths, and the old key cannot verify the new chain."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from raucle.chain_rotation import rotate_chain

        config = _receipt_config(tmp_path)
        key_path = tmp_path / "gateway-signing-key.pem"
        config.signer_key_path = str(key_path)

        # 1. Old era: the operator key A signs the audit chain.
        key_a = Ed25519PrivateKey.generate()
        _write_key(key_path, key_a)
        signer_a = Ed25519Signer(key_a)
        chain_writer = HashChainSink(config.audit_chain, signer=signer_a, checkpoint_every=2)
        chain_writer.append({"era": "old", "seq": 0})
        chain_writer.append({"era": "old", "seq": 1})
        chain_writer.append({"era": "old", "seq": 2})
        chain_writer.close()

        # 2. Rotation: the operator key file now holds key B, and the
        #    operator runs the receipted chain rotation.
        key_b = Ed25519PrivateKey.generate()
        _write_key(key_path, key_b)
        signer_b = Ed25519Signer(key_b)
        result = rotate_chain(config, operator="craig", reason="operator key rotation")
        assert result.get("rotated"), result

        # 3. New era: new-signed records land in the fresh chain.
        new_writer = HashChainSink(config.audit_chain, signer=signer_b)
        new_writer.append({"era": "new", "seq": 0})
        new_writer.close()

        # 4. The old-signed archive verifies with the OLD public key.
        import glob

        archives = glob.glob(str(config.audit_chain) + ".archived-*")
        assert len(archives) == 1, archives
        old_pub = key_a.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        old_report = AuditVerifier(public_key_pem=old_pub).verify_chain(archives[0])
        assert old_report.valid, old_report.errors
        assert old_report.signed_mode == "signed"
        assert old_report.event_count == 3
        assert old_report.chain_key_id == signer_a.key_id()

        # 5. The new-signed chain verifies with the NEW public key.
        new_pub = key_b.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        new_report = AuditVerifier(public_key_pem=new_pub).verify_chain(config.audit_chain)
        assert new_report.valid, new_report.errors
        assert new_report.signed_mode == "signed"
        assert new_report.event_count == 1
        assert new_report.chain_key_id == signer_b.key_id()

        # 6. Splicing defence holds: the OLD key cannot verify the NEW
        #    chain (different key_id pinned by the fresh genesis).
        mixed = AuditVerifier(public_key_pem=old_pub).verify_chain(config.audit_chain)
        assert not mixed.valid

        # The boundary receipt is receipted in the chain of record.
        receipt_path = tmp_path / "receipts" / "seg-000000.jsonl"
        receipt_lines = receipt_path.read_text(encoding="utf-8").strip().splitlines()
        assert receipt_lines, "no boundary receipt in the chain of record"
        envelope = json.loads(receipt_lines[-1])
        assert envelope["receipt_hash"] == result["receipt_hash"]
