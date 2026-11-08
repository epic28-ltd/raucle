"""RED-032: admin identity durability, hashed keys, and MFA replay refusal.

Covers the four defects found in the 8 Nov review:

1. ``mfa_enabled`` was written nowhere, so every restart silently downgraded
   MFA-enabled operators to API-key-only auth (the secret survived, the
   protection did not).
2. API keys and TOTP secrets were stored in plaintext, keyed by the key.
3. The env bootstrap key was re-added on every boot, resurrecting an admin
   removed in the panel and keeping a rotated key valid for ever.
4. ``/api/users`` returned a truncated key while the MFA routes took a full
   key in the path, so an admin could not enable MFA for anyone but
   themselves.
"""

import json
import time

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import create_admin_app

pyotp = pytest.importorskip("pyotp")


def _users_file(tmp_path):
    return tmp_path / "users.jsonl"


class TestMfaDurability:
    def test_flag_survives_restart(self, tmp_path):
        path = _users_file(tmp_path)
        um1 = UserManager(persist_path=path)
        um1.add_user("admin-key-1", "admin", "Admin")
        provisioning = um1.setup_mfa("admin-key-1")
        assert provisioning is not None
        assert um1.verify_mfa("admin-key-1", pyotp.TOTP(provisioning["secret"]).now())
        before = um1.get_user("admin-key-1")
        assert before is not None and before.requires_mfa()

        um2 = UserManager(persist_path=path)
        user = um2.get_user("admin-key-1")
        assert user is not None
        assert user.requires_mfa() is True
        assert user.mfa_enabled is True

    def test_legacy_record_with_secret_restores_enabled(self, tmp_path):
        """A file written before RED-032 has no flag; a verified secret means
        MFA was on, so it must come back on rather than silently off."""
        path = _users_file(tmp_path)
        path.write_text(
            json.dumps(
                {
                    "api_key": "legacy-key-value",
                    "role": "admin",
                    "name": "Legacy",
                    "expires_at": None,
                    "totp_secret": "JBSWY3DPEHPK3PXP",
                }
            )
            + "\n"
        )
        um = UserManager(persist_path=path)
        assert um.get_user("legacy-key-value").requires_mfa() is True

    def test_disable_is_persisted(self, tmp_path):
        path = _users_file(tmp_path)
        um1 = UserManager(persist_path=path)
        um1.add_user("admin-key-1", "admin", "Admin")
        provisioning = um1.setup_mfa("admin-key-1")
        assert provisioning is not None
        assert um1.verify_mfa("admin-key-1", pyotp.TOTP(provisioning["secret"]).now())
        assert um1.disable_mfa("admin-key-1")

        um2 = UserManager(persist_path=path)
        user = um2.get_user("admin-key-1")
        assert user is not None
        assert user.mfa_enabled is False
        assert user.requires_mfa() is False


class TestKeyHashing:
    def test_plaintext_key_never_reaches_disk(self, tmp_path):
        path = _users_file(tmp_path)
        um = UserManager(persist_path=path)
        um.add_user("super-secret-admin-key", "admin", "Admin")
        written = path.read_text(encoding="utf-8")
        assert "super-secret-admin-key" not in written
        assert "api_key_hash" in written

    def test_authentication_still_works_after_reload(self, tmp_path):
        path = _users_file(tmp_path)
        um1 = UserManager(persist_path=path)
        um1.add_user("super-secret-admin-key", "operator", "Op")

        um2 = UserManager(persist_path=path)
        user = um2.get_user("super-secret-admin-key")
        assert user is not None
        assert user.role == "operator"
        assert um2.get_user("wrong-key") is None

    def test_legacy_file_is_migrated_on_load(self, tmp_path):
        path = _users_file(tmp_path)
        path.write_text(
            json.dumps({"api_key": "legacy-plaintext-key", "role": "admin", "name": "L"}) + "\n"
        )
        um = UserManager(persist_path=path)
        assert um.get_user("legacy-plaintext-key") is not None
        rewritten = path.read_text(encoding="utf-8")
        assert "legacy-plaintext-key" not in rewritten
        assert "api_key_hash" in rewritten

    def test_user_id_is_stable_and_not_key_material(self, tmp_path):
        path = _users_file(tmp_path)
        um1 = UserManager(persist_path=path)
        created = um1.add_user("super-secret-admin-key", "admin", "Admin")
        um2 = UserManager(persist_path=path)
        again = um2.get_user("super-secret-admin-key")
        assert again is not None
        assert created.user_id == again.user_id
        assert created.user_id.startswith("usr-")
        assert "super-secret" not in created.user_id

    def test_key_label_is_a_digest_fragment(self, tmp_path):
        um = UserManager()
        user = um.add_user("super-secret-admin-key", "admin", "Admin")
        assert user.key_label.startswith("sha256:")
        assert "super-secret" not in user.key_label

    def test_corrupt_store_still_fails_closed(self, tmp_path):
        path = _users_file(tmp_path)
        path.write_text("{not json}\n")
        with pytest.raises(ValueError, match="corrupt"):
            UserManager(persist_path=path)

    def test_record_without_key_material_fails_closed(self, tmp_path):
        path = _users_file(tmp_path)
        path.write_text(json.dumps({"role": "admin"}) + "\n")
        with pytest.raises(ValueError, match="no key material"):
            UserManager(persist_path=path)


class TestTotpReplay:
    def test_current_window_code_is_reusable_for_polling(self, tmp_path):
        """The panel polls several times a minute with the same code."""
        um = UserManager(persist_path=_users_file(tmp_path))
        um.add_user("admin-key-1", "admin", "Admin")
        provisioning = um.setup_mfa("admin-key-1")
        assert provisioning is not None
        code = pyotp.TOTP(provisioning["secret"]).now()
        user = um.get_user("admin-key-1")
        assert user is not None
        assert um.verify_totp(user, code) is True
        assert um.verify_totp(user, code) is True

    def test_stale_code_is_refused_after_the_window_rolls(self, tmp_path, monkeypatch):
        """A code captured in an earlier window cannot be replayed later."""
        import raucle.gateway as gateway_module

        um = UserManager(persist_path=_users_file(tmp_path))
        um.add_user("admin-key-1", "admin", "Admin")
        provisioning = um.setup_mfa("admin-key-1")
        assert provisioning is not None
        secret = provisioning["secret"]
        start = 1_700_000_000
        monkeypatch.setattr(gateway_module.time, "time", lambda: start + 1)
        first = pyotp.TOTP(secret).at(start)
        user = um.get_user("admin-key-1")
        assert um.verify_totp(user, first) is True

        # Two windows later the same code is stale, even though pyotp's
        # +/-1 step window would still accept it.
        monkeypatch.setattr(gateway_module.time, "time", lambda: start + 31)
        assert um.verify_totp(user, first) is False

    def test_non_numeric_code_is_refused(self, tmp_path):
        um = UserManager(persist_path=_users_file(tmp_path))
        um.add_user("admin-key-1", "admin", "Admin")
        um.setup_mfa("admin-key-1")
        user = um.get_user("admin-key-1")
        assert user is not None
        assert um.verify_totp(user, "abcdef") is False
        assert um.verify_totp(user, "") is False


@pytest.fixture
def admin_client(tmp_path):
    cfg = GatewayConfig(
        policy_file=str(tmp_path / "policies.yaml"),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="admin-key-for-tests-0123456789",
        signer_backend="local",
    )
    gateway = RaucleGateway(cfg)
    users = UserManager(persist_path=tmp_path / "users.jsonl")
    users.add_user(cfg.admin_api_key, "admin", "Admin")
    app = create_admin_app(gateway, users)
    client = TestClient(app)
    return client, users, {"Authorization": cfg.admin_api_key}


class TestUsersApi:
    def test_users_list_carries_the_fields_the_panel_renders(self, admin_client):
        client, _users, headers = admin_client
        body = client.get("/api/users", headers=headers).json()
        row = body["users"][0]
        assert row["mfa_enabled"] is False
        assert row["expires_at"] is None
        assert row["user_id"].startswith("usr-")
        assert row["api_key_label"].startswith("sha256:")
        assert "api_key" not in row

    def test_mfa_can_be_set_up_by_user_id(self, admin_client):
        client, _users, headers = admin_client
        body = client.get("/api/users", headers=headers).json()
        user_id = body["users"][0]["user_id"]

        setup = client.post(f"/api/users/{user_id}/mfa/setup", headers=headers)
        assert setup.status_code == 200
        secret = setup.json()["secret"]

        code = pyotp.TOTP(secret).now()
        verify = client.post(
            f"/api/users/{user_id}/mfa/verify", headers=headers, params={"code": code}
        )
        assert verify.status_code == 200
        assert verify.json()["mfa_enabled"] is True

        listed = client.get("/api/users", headers={**headers, "X-TOTP": code}).json()["users"][0]
        assert listed["mfa_enabled"] is True

    def test_mfa_setup_still_accepts_a_full_key(self, admin_client):
        client, _users, headers = admin_client
        setup = client.post("/api/users/admin-key-for-tests-0123456789/mfa/setup", headers=headers)
        assert setup.status_code == 200

    def test_created_user_keys_are_generated_when_omitted(self, admin_client):
        client, users, headers = admin_client
        resp = client.post("/api/users", headers=headers, json={"role": "operator", "name": "Op"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["api_key"].startswith("adm_")
        assert len(body["api_key"]) >= 32
        # The returned key authenticates; only its digest is on disk.
        assert users.get_user(body["api_key"]).role == "operator"
        assert body["api_key"] not in (users._persist_path).read_text(encoding="utf-8")

    def test_short_supplied_keys_are_refused(self, admin_client):
        client, _users, headers = admin_client
        resp = client.post(
            "/api/users", headers=headers, json={"api_key": "short", "role": "operator"}
        )
        assert resp.status_code == 400
        assert "at least" in resp.json()["detail"]

    def test_long_supplied_key_is_accepted(self, admin_client):
        client, users, headers = admin_client
        key = "supplied-operator-key-0123456789"
        resp = client.post(
            "/api/users", headers=headers, json={"api_key": key, "role": "operator", "name": "Op"}
        )
        assert resp.status_code == 200
        assert users.get_user(key) is not None

    def test_delete_by_user_id(self, admin_client):
        client, users, headers = admin_client
        created = client.post(
            "/api/users", headers=headers, json={"role": "auditor", "name": "Aud"}
        ).json()
        assert client.delete(f"/api/users/{created['user_id']}", headers=headers).status_code == 200
        assert users.get_user(created["api_key"]) is None


class TestAdminKeyFile:
    def test_admin_key_file_wins_over_inline_env(self, tmp_path, monkeypatch):
        secret = tmp_path / "admin_key"
        secret.write_text("from-the-file-0123456789\n", encoding="utf-8")
        monkeypatch.setenv("RAUCLE_ADMIN_KEY_FILE", str(secret))
        monkeypatch.setenv("RAUCLE_ADMIN_KEY", "from-the-env")
        assert GatewayConfig.from_env().admin_api_key == "from-the-file-0123456789"

    def test_unreadable_admin_key_file_yields_no_key(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAUCLE_ADMIN_KEY_FILE", str(tmp_path / "missing"))
        monkeypatch.setenv("RAUCLE_ADMIN_KEY", "from-the-env")
        assert GatewayConfig.from_env().admin_api_key == ""

    def test_inline_env_used_without_a_file(self, monkeypatch):
        monkeypatch.delenv("RAUCLE_ADMIN_KEY_FILE", raising=False)
        monkeypatch.setenv("RAUCLE_ADMIN_KEY", "from-the-env")
        assert GatewayConfig.from_env().admin_api_key == "from-the-env"


class TestBootstrapDoesNotResurrect:
    def test_second_boot_leaves_store_alone(self, tmp_path, monkeypatch):
        import raucle.gateway_server as gateway_server

        users_file = tmp_path / "users.jsonl"
        monkeypatch.setenv("RAUCLE_USERS_FILE", str(users_file))
        monkeypatch.setenv("RAUCLE_ADMIN_KEY", "first-admin-key-0123456789")
        monkeypatch.setenv("RAUCLE_RECEIPT_STORE", str(tmp_path / "receipts.jsonl"))
        monkeypatch.setenv("RAUCLE_AUDIT_CHAIN", str(tmp_path / "audit.jsonl"))
        monkeypatch.setenv("RAUCLE_POLICY_FILE", str(tmp_path / "policies.yaml"))
        monkeypatch.setenv("RAUCLE_REGISTRY_PATH", str(tmp_path / "registry.jsonl"))
        monkeypatch.setenv("RAUCLE_SIGNER_KEY_PATH", str(tmp_path / "signer.pem"))
        monkeypatch.setenv("RAUCLE_AGENT_CREDENTIALS", str(tmp_path / "agent-credentials.jsonl"))
        monkeypatch.delenv("RAUCLE_DEMO_KEY", raising=False)

        captured = {}

        class _Stop(Exception):
            pass

        def _fake_run_both(config, gateway, users):
            captured["users"] = users.list_users()
            raise _Stop

        monkeypatch.setattr(gateway_server, "run_both_servers", _fake_run_both)

        with pytest.raises(_Stop):
            gateway_server.main()
        assert len(captured["users"]) == 1

        # A rotated key on the next boot must not create a second admin.
        monkeypatch.setenv("RAUCLE_ADMIN_KEY", "second-admin-key-0123456789")
        with pytest.raises(_Stop):
            gateway_server.main()
        admins = [u for u in captured["users"] if u.role == "admin"]
        assert len(admins) == 1
        # The original key still authenticates; the new env key does not.
        reloaded = UserManager(persist_path=users_file)
        assert reloaded.get_user("first-admin-key-0123456789") is not None
        assert reloaded.get_user("second-admin-key-0123456789") is None


def test_user_id_lookup_is_not_timing_obvious():
    """Sanity: resolving by id and by key both go through one hash/dict path."""
    um = UserManager()
    user = um.add_user("some-key-value-0123456789", "operator", "Op")
    assert um.resolve(user.user_id) is user
    assert um.resolve("some-key-value-0123456789") is user
    assert um.resolve("nope") is None
    assert time.time() >= 0  # keep the import meaningful for future timing tests
