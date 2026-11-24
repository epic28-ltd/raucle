"""Lane Q13 (RAU-02): signed sidecar seals for control-plane files.

Third external review residual plus the threat model's own M5/R5 row:
the policy file and the revocation/delegation registries are unsigned
control-plane artefacts, so filesystem write access to the enforcement
directory is enforcement control. The mechanism introduced here is an
operator-signed ``.meta`` sidecar (the receipt store's sidecar
precedent): the file's canonical SHA-256, an Ed25519 signature over the
FILE BYTES (never a wrapper document), the signer's key id and a
sealed_at epoch. Loading verifies the seal against the current bytes
and refuses with a named ``PolicySealRefused``; the migration mode
``RAUCLE_POLICY_SEALING`` (required|advisory|off, default advisory)
governs only the unsealed case, because a PRESENT seal that diverges
from the bytes is tamper evidence and refuses in every mode.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest

from raucle.audit import Ed25519Signer
from raucle.errors import ConfigurationError, PolicySealRefused
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.policy_seal import (
    seal_file,
    seal_path,
    seal_public_keys_from_env,
    sealing_mode,
    verify_file_seal,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write_policy(tmp_path: Path) -> Path:
    path = tmp_path / "policies.yaml"
    path.write_text(
        """version: 1
issuer: test.bank
policies:
  - tool: pay
    agent_id: agent:bot
    ttl_seconds: 300
    constraints:
      allow:
        account: ["ACC-001"]
""",
        encoding="utf-8",
    )
    return path


def _config(tmp_path: Path, **kw) -> GatewayConfig:
    values: dict = dict(
        policy_file=str(_write_policy(tmp_path)),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        signer_key_path=str(tmp_path / "signer.pem"),
        gate_auth="off",
        signer_backend="local",
    )
    values.update(kw)
    return GatewayConfig(**values)


@pytest.fixture
def signer():
    return Ed25519Signer.generate()


@pytest.fixture
def pubkey_env(monkeypatch, tmp_path, signer):
    """Point RAUCLE_POLICY_SEAL_PUBLIC_KEY at the signer's public PEM file."""
    pub = tmp_path / "seal-public.pem"
    pub.write_bytes(signer.public_key_pem())
    monkeypatch.setenv("RAUCLE_POLICY_SEAL_PUBLIC_KEY", str(pub))
    return pub


@pytest.fixture
def clean_mode(monkeypatch):
    """No explicit sealing mode: the migration default applies."""
    monkeypatch.delenv("RAUCLE_POLICY_SEALING", raising=False)


def _decode_receipt_payload(store_path: str, receipt_id: str) -> dict:
    with open(store_path, encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            if rec.get("receipt_hash") == receipt_id:
                b64 = rec["jws"].split(".")[1]
                return json.loads(base64.urlsafe_b64decode(b64 + "=="))
    raise AssertionError(f"receipt {receipt_id} not found in {store_path}")


# ---------------------------------------------------------------------------
# The mechanism: seal, verify, refuse by name
# ---------------------------------------------------------------------------


class TestPolicySealMechanism:
    def test_seal_file_writes_sidecar_bound_to_the_bytes(self, tmp_path, signer):
        policy = _write_policy(tmp_path)
        seal = seal_file(policy, signer)
        sidecar = seal_path(policy)
        assert sidecar.exists()
        raw = json.loads(sidecar.read_text(encoding="utf-8"))
        content = policy.read_bytes()
        assert raw["content_sha256"] == hashlib.sha256(content).hexdigest()
        assert raw["key_id"] == signer.key_id()
        assert isinstance(raw["sealed_at"], int)
        # the signature covers the POLICY BYTES, not a wrapper document
        assert base64.b64decode(raw["signature"]) == signer.sign(content)
        assert seal.content_sha256 == raw["content_sha256"]

    def test_seal_verifies_clean(self, tmp_path, signer, pubkey_env):
        policy = _write_policy(tmp_path)
        seal_file(policy, signer)
        verdict = verify_file_seal(policy, seal_public_keys_from_env())
        assert verdict.state == "verified"
        assert verdict.content_sha256 == hashlib.sha256(policy.read_bytes()).hexdigest()

    def test_unsealed_file_reports_unsealed_not_refused(self, tmp_path, pubkey_env):
        policy = _write_policy(tmp_path)
        verdict = verify_file_seal(policy, seal_public_keys_from_env())
        assert verdict.state == "unsealed"

    def test_tampered_bytes_against_valid_seal_refuse(self, tmp_path, signer, pubkey_env):
        policy = _write_policy(tmp_path)
        seal_file(policy, signer)
        policy.write_text(
            policy.read_text(encoding="utf-8").replace("ACC-001", "ACC-999"),
            encoding="utf-8",
        )
        verdict = verify_file_seal(policy, seal_public_keys_from_env())
        assert verdict.state == "refused"
        assert "diverge" in verdict.reason

    def test_forged_signature_refuses(self, tmp_path, signer, pubkey_env):
        policy = _write_policy(tmp_path)
        seal_file(policy, signer)
        sidecar = seal_path(policy)
        record = json.loads(sidecar.read_text(encoding="utf-8"))
        record["signature"] = base64.b64encode(b"not-a-signature" * 4).decode("ascii")
        sidecar.write_text(json.dumps(record), encoding="utf-8")
        verdict = verify_file_seal(policy, seal_public_keys_from_env())
        assert verdict.state == "refused"
        assert "signature" in verdict.reason

    def test_unknown_signing_key_refuses(self, tmp_path, signer):
        other = Ed25519Signer.generate()
        policy = _write_policy(tmp_path)
        seal_file(policy, other)
        pub = tmp_path / "other-public.pem"
        pub.write_bytes(signer.public_key_pem())
        os.environ["RAUCLE_POLICY_SEAL_PUBLIC_KEY"] = str(pub)
        try:
            verdict = verify_file_seal(policy, seal_public_keys_from_env())
        finally:
            del os.environ["RAUCLE_POLICY_SEAL_PUBLIC_KEY"]
        assert verdict.state == "refused"
        assert other.key_id() in verdict.reason

    def test_seal_without_any_configured_key_refuses(self, tmp_path, signer, monkeypatch):
        policy = _write_policy(tmp_path)
        seal_file(policy, signer)
        monkeypatch.delenv("RAUCLE_POLICY_SEAL_PUBLIC_KEY", raising=False)
        verdict = verify_file_seal(policy, seal_public_keys_from_env())
        assert verdict.state == "refused"
        assert "RAUCLE_POLICY_SEAL_PUBLIC_KEY" in verdict.reason

    def test_malformed_sidecar_refuses(self, tmp_path, signer, pubkey_env):
        policy = _write_policy(tmp_path)
        seal_file(policy, signer)
        seal_path(policy).write_text("{not json", encoding="utf-8")
        verdict = verify_file_seal(policy, seal_public_keys_from_env())
        assert verdict.state == "refused"

    def test_unknown_sidecar_fields_refuse(self, tmp_path, signer, pubkey_env):
        policy = _write_policy(tmp_path)
        seal_file(policy, signer)
        sidecar = seal_path(policy)
        record = json.loads(sidecar.read_text(encoding="utf-8"))
        record["sneaky"] = "field"
        sidecar.write_text(json.dumps(record), encoding="utf-8")
        verdict = verify_file_seal(policy, seal_public_keys_from_env())
        assert verdict.state == "refused"

    def test_float_sealed_at_refuses(self, tmp_path, signer, pubkey_env):
        policy = _write_policy(tmp_path)
        seal_file(policy, signer)
        sidecar = seal_path(policy)
        record = json.loads(sidecar.read_text(encoding="utf-8"))
        record["sealed_at"] = 1764000000.5
        sidecar.write_text(json.dumps(record), encoding="utf-8")
        verdict = verify_file_seal(policy, seal_public_keys_from_env())
        assert verdict.state == "refused"
        assert "sealed_at" in verdict.reason


# ---------------------------------------------------------------------------
# The mode knob
# ---------------------------------------------------------------------------


class TestSealingMode:
    def test_default_is_advisory(self, monkeypatch):
        monkeypatch.delenv("RAUCLE_POLICY_SEALING", raising=False)
        assert sealing_mode() == "advisory"

    def test_explicit_required(self, monkeypatch):
        monkeypatch.setenv("RAUCLE_POLICY_SEALING", "required")
        assert sealing_mode() == "required"

    def test_unknown_value_fails_closed(self, monkeypatch):
        monkeypatch.setenv("RAUCLE_POLICY_SEALING", "strict")
        with pytest.raises(ConfigurationError) as exc:
            sealing_mode()
        assert "strict" in str(exc.value)
        assert "required" in str(exc.value) and "advisory" in str(exc.value)


# ---------------------------------------------------------------------------
# Gateway boot and reload (fail-closed load path)
# ---------------------------------------------------------------------------


class TestGatewayPolicySeal:
    def test_required_mode_refuses_unsigned_policy_at_boot(
        self, tmp_path, signer, pubkey_env, monkeypatch
    ):
        monkeypatch.setenv("RAUCLE_POLICY_SEALING", "required")
        config = _config(tmp_path)
        with pytest.raises(PolicySealRefused) as exc:
            RaucleGateway(config)
        assert "policies.yaml" in str(exc.value)
        assert "required" in str(exc.value)

    def test_advisory_default_boots_and_logs_named_advisory(
        self, tmp_path, signer, pubkey_env, clean_mode, caplog
    ):
        config = _config(tmp_path)
        gateway = RaucleGateway(config)
        assert (
            gateway.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot")["decision"]
            == "allow"
        )
        assert any("POLICY SEAL ADVISORY" in rec.message for rec in caplog.records), [
            rec.message for rec in caplog.records
        ]

    def test_sealed_clean_path_gates_normally(
        self, tmp_path, signer, pubkey_env, clean_mode, caplog
    ):
        config = _config(tmp_path)
        seal_file(Path(config.policy_file), signer)
        gateway = RaucleGateway(config)
        assert (
            gateway.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot")["decision"]
            == "allow"
        )
        assert not any("POLICY SEAL ADVISORY" in rec.message for rec in caplog.records)

    def test_tampered_bytes_against_valid_seal_refuse_at_boot(
        self, tmp_path, signer, pubkey_env, clean_mode
    ):
        config = _config(tmp_path)
        policy = Path(config.policy_file)
        seal_file(policy, signer)
        policy.write_text(
            policy.read_text(encoding="utf-8").replace("ACC-001", "ACC-999"),
            encoding="utf-8",
        )
        with pytest.raises(PolicySealRefused) as exc:
            RaucleGateway(config)
        assert "policies.yaml" in str(exc.value)

    def test_required_mode_missing_seal_refuses_on_reload(
        self, tmp_path, signer, pubkey_env, monkeypatch
    ):
        monkeypatch.setenv("RAUCLE_POLICY_SEALING", "required")
        config = _config(tmp_path)
        seal_file(Path(config.policy_file), signer)
        gateway = RaucleGateway(config)
        # an operator drops the seal out of band; the reload must refuse
        # and keep enforcing the previously verified rules
        seal_path(Path(config.policy_file)).unlink()
        result = gateway.reload_policies()
        assert result["status"] == "error"
        assert "PolicySealRefused" in result["message"] or "sealed" in result["message"]
        assert (
            gateway.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot")["decision"]
            == "allow"
        )

    def test_off_mode_disables_the_seal_entirely(self, tmp_path, signer, pubkey_env, monkeypatch):
        monkeypatch.setenv("RAUCLE_POLICY_SEALING", "off")
        config = _config(tmp_path)
        policy = Path(config.policy_file)
        seal_file(policy, signer)
        policy.write_text(
            policy.read_text(encoding="utf-8").replace("ACC-001", "ACC-999"),
            encoding="utf-8",
        )
        gateway = RaucleGateway(config)
        assert (
            gateway.check_tool_call("pay", {"account": "ACC-999"}, agent_id="agent:bot")["decision"]
            == "allow"
        )


# ---------------------------------------------------------------------------
# Receipts: policy_hash binds the sealed policy that made the decision
# ---------------------------------------------------------------------------


class TestReceiptPolicyHash:
    def test_policy_hash_rides_the_receipt_and_the_receipt_verifies(
        self, tmp_path, signer, pubkey_env, clean_mode
    ):
        from raucle.provenance import ProvenanceVerifier

        config = _config(tmp_path)
        policy = Path(config.policy_file)
        expected = hashlib.sha256(policy.read_bytes()).hexdigest()
        seal_file(policy, signer)
        gateway = RaucleGateway(config)
        result = gateway.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot")
        assert result["decision"] == "allow"
        payload = _decode_receipt_payload(config.receipt_store, result["receipt_id"])
        assert payload["x_gate"]["policy_hash"] == expected
        verifier = ProvenanceVerifier(
            public_keys={gateway._gate_identity.key_id: gateway._gate_identity.public_key_pem()}
        )
        report = verifier.verify_chain(config.receipt_store)
        assert report.valid, report.errors

    def test_constraint_deny_receipt_carries_the_policy_hash_too(
        self, tmp_path, signer, pubkey_env, clean_mode
    ):
        config = _config(tmp_path)
        policy = Path(config.policy_file)
        expected = hashlib.sha256(policy.read_bytes()).hexdigest()
        seal_file(policy, signer)
        gateway = RaucleGateway(config)
        result = gateway.check_tool_call("pay", {"account": "ACC-666"}, agent_id="agent:bot")
        assert result["decision"] == "deny"
        payload = _decode_receipt_payload(config.receipt_store, result["receipt_id"])
        assert payload["x_gate"]["policy_hash"] == expected

    def test_unsealed_policy_receipt_keeps_the_legacy_shape(
        self, tmp_path, signer, pubkey_env, clean_mode
    ):
        config = _config(tmp_path)
        gateway = RaucleGateway(config)
        result = gateway.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot")
        payload = _decode_receipt_payload(config.receipt_store, result["receipt_id"])
        assert "policy_hash" not in payload["x_gate"]

    def test_no_rule_deny_receipt_has_no_policy_hash(
        self, tmp_path, signer, pubkey_env, clean_mode
    ):
        config = _config(tmp_path)
        seal_file(Path(config.policy_file), signer)
        gateway = RaucleGateway(config)
        result = gateway.check_tool_call("unknown_tool", {}, agent_id="agent:bot")
        assert result["decision"] == "deny"
        payload = _decode_receipt_payload(config.receipt_store, result["receipt_id"])
        assert "policy_hash" not in payload["x_gate"]


# ---------------------------------------------------------------------------
# Registries: revocation list and delegation ledger ride the same seal
# ---------------------------------------------------------------------------


class TestRegistrySeal:
    def test_sealed_revocations_tamper_refuses_the_load(
        self, tmp_path, signer, pubkey_env, clean_mode
    ):
        revocations = tmp_path / "revocations.jsonl"
        revocations.write_text(
            json.dumps({"token_id": "tok-1", "reason": "test"}) + "\n", encoding="utf-8"
        )
        seal_file(revocations, signer)
        revocations.write_text(
            json.dumps({"token_id": "tok-2", "reason": "swapped"}) + "\n", encoding="utf-8"
        )
        config = _config(tmp_path, revocations_file=str(revocations), gate_auth="token")
        gateway = RaucleGateway(config)
        with pytest.raises(PolicySealRefused):
            gateway._load_revoked_ids()

    def test_sealed_delegation_ledger_tamper_refuses_the_gate_build(
        self, tmp_path, signer, pubkey_env, clean_mode
    ):
        ledger = tmp_path / "delegations.jsonl"
        ledger.write_text(
            json.dumps({"record_hash": "a" * 64, "token_id": "tok-1"}) + "\n",
            encoding="utf-8",
        )
        seal_file(ledger, signer)
        ledger.write_text(
            json.dumps({"record_hash": "b" * 64, "token_id": "tok-1"}) + "\n",
            encoding="utf-8",
        )
        config = _config(tmp_path, delegations_file=str(ledger), gate_auth="token")
        gateway = RaucleGateway(config)
        with pytest.raises(PolicySealRefused):
            gateway._ensure_caller_gate()

    def test_unmarked_registries_load_unchanged_even_under_required(
        self, tmp_path, signer, pubkey_env, monkeypatch
    ):
        monkeypatch.setenv("RAUCLE_POLICY_SEALING", "required")
        revocations = tmp_path / "revocations.jsonl"
        revocations.write_text(
            json.dumps({"token_id": "tok-1", "reason": "test"}) + "\n", encoding="utf-8"
        )
        config = _config(tmp_path, revocations_file=str(revocations), gate_auth="token")
        # required mode needs the POLICY sealed too; the claim under test is
        # that an UNMARKED registry still loads unchanged under required -
        # the mode obliges policy files, not registries.
        seal_file(Path(config.policy_file), signer)
        gateway = RaucleGateway(config)
        assert gateway._load_revoked_ids() == {"tok-1"}

    def test_clean_sealed_revocations_load_normally(self, tmp_path, signer, pubkey_env, clean_mode):
        revocations = tmp_path / "revocations.jsonl"
        revocations.write_text(
            json.dumps({"token_id": "tok-1", "reason": "test"}) + "\n", encoding="utf-8"
        )
        seal_file(revocations, signer)
        config = _config(tmp_path, revocations_file=str(revocations), gate_auth="token")
        gateway = RaucleGateway(config)
        assert gateway._load_revoked_ids() == {"tok-1"}


# ---------------------------------------------------------------------------
# CLI mint path
# ---------------------------------------------------------------------------


class TestPolicySealCli:
    def test_seal_and_verify_round_trip(self, tmp_path, signer, monkeypatch, capsys):
        from raucle import cli

        priv = tmp_path / "operator-private.pem"
        from cryptography.hazmat.primitives import serialization

        priv.write_bytes(
            signer._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        pub = tmp_path / "operator-public.pem"
        pub.write_bytes(signer.public_key_pem())
        policy = _write_policy(tmp_path)

        assert cli.main(["policy", "seal", str(policy), "--key", str(priv)]) == 0
        assert seal_path(policy).exists()

        monkeypatch.delenv("RAUCLE_POLICY_SEAL_PUBLIC_KEY", raising=False)
        assert cli.main(["policy", "verify", str(policy), "--pubkey", str(pub)]) == 0

        policy.write_text(
            policy.read_text(encoding="utf-8").replace("ACC-001", "ACC-999"),
            encoding="utf-8",
        )
        assert cli.main(["policy", "verify", str(policy), "--pubkey", str(pub)]) == 2
