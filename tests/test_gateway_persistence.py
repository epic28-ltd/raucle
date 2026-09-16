"""Persistence tests: gateway signing key (A2) and admin users (A3)."""

import pytest

from raucle.gateway import GatewayConfig, RaucleGateway, UserManager


@pytest.fixture()
def base_config(tmp_path):
    return GatewayConfig(
        host="127.0.0.1",
        admin_api_key="test-admin-key",
        signer_backend="local",
        policy_file="",
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
    )


class TestSignerPersistence:
    def test_key_id_stable_across_restart(self, base_config):
        """Two gateway instances, same data dir: same signing key."""
        gw1 = RaucleGateway(base_config)
        kid1 = gw1._signer.key_id()
        pem1 = gw1._signer.public_key_pem()
        gw2 = RaucleGateway(base_config)
        assert gw2._signer.key_id() == kid1
        assert gw2._signer.public_key_pem() == pem1

    def test_key_file_created_with_0600(self, base_config, tmp_path):
        RaucleGateway(base_config)
        key_path = tmp_path / "gateway-signing-key.pem"
        assert key_path.exists()
        assert (key_path.stat().st_mode & 0o777) == 0o600

    def test_corrupt_key_fails_closed(self, base_config, tmp_path):
        RaucleGateway(base_config)  # creates the key
        key_path = tmp_path / "gateway-signing-key.pem"
        key_path.write_bytes(b"-----BEGIN PRIVATE KEY-----\ngarbage\n")
        with pytest.raises(ValueError, match="corrupt"):
            RaucleGateway(base_config)

    def test_non_ed25519_key_rejected(self, base_config, tmp_path):
        # An RSA key in the Ed25519 slot must fail closed, not sign wrongly
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        key_path = tmp_path / "gateway-signing-key.pem"
        key_path.write_bytes(pem)
        with pytest.raises(ValueError, match="not an Ed25519"):
            RaucleGateway(base_config)

    def test_signer_survives_restart_and_old_tokens_verify(self, base_config, tmp_path):
        """The restart test a CTO runs: token minted by boot 1 verifies at boot 2."""
        from raucle.capability import CapabilityGate

        gw1 = RaucleGateway(base_config)
        token = gw1._issuer.mint(agent_id="agent:svc", tool="lookup_balance", ttl_seconds=3600)
        gate1 = CapabilityGate(trusted_issuers={gw1._issuer.key_id: gw1._issuer.public_key_pem})
        assert gate1.check(token, tool="lookup_balance", agent_id="agent:svc").allowed

        gw2 = RaucleGateway(base_config)
        gate2 = CapabilityGate(trusted_issuers={gw2._issuer.key_id: gw2._issuer.public_key_pem})
        # The token from boot 1 must still verify against boot 2's identity
        assert gate2.check(token, tool="lookup_balance", agent_id="agent:svc").allowed


class TestUserPersistence:
    def test_users_survive_reload(self, tmp_path):
        users_file = tmp_path / "users.jsonl"
        um1 = UserManager(persist_path=users_file)
        um1.add_user("admin-key-1", "admin", "Admin")
        um1.add_user("aud-key-1", "auditor", "Auditor")
        um2 = UserManager(persist_path=users_file)
        assert um2.get_user("admin-key-1") is not None
        assert um2.get_user("admin-key-1").role == "admin"
        assert um2.get_user("aud-key-1").role == "auditor"

    def test_removed_user_stays_removed(self, tmp_path):
        users_file = tmp_path / "users.jsonl"
        um1 = UserManager(persist_path=users_file)
        um1.add_user("key-1", "admin", "Admin")
        um1.remove_user("key-1")
        um2 = UserManager(persist_path=users_file)
        assert um2.get_user("key-1") is None

    def test_mfa_secret_persists(self, tmp_path):
        users_file = tmp_path / "users.jsonl"
        um1 = UserManager(persist_path=users_file)
        um1.add_user("admin-key-1", "admin", "Admin")
        provisioning = um1.setup_mfa("admin-key-1")
        assert provisioning is not None
        um2 = UserManager(persist_path=users_file)
        user = um2.get_user("admin-key-1")
        assert user.totp_secret  # the secret survived the reload

    def test_no_persist_path_is_pure_memory(self, tmp_path):
        """Default construction keeps the historical in-memory behaviour."""
        um = UserManager()
        um.add_user("key-1", "admin", "Admin")
        assert not list(tmp_path.iterdir())  # nothing written anywhere

    def test_corrupt_users_file_fails_closed(self, tmp_path):
        users_file = tmp_path / "users.jsonl"
        users_file.write_text("{broken json\n", encoding="utf-8")
        with pytest.raises(ValueError, match="corrupt"):
            UserManager(persist_path=users_file)
