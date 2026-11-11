"""RED-038: every persisted store survives a restart.

RED-032 was a persistence bug with a one-line cause: a field was written by
the save path and never read by the load path. The suite had a test that
asserted the *secret* survived and none that asserted the *flag* did, so the
defect sat behind a green suite.

The rule this file enforces: for each store that writes to disk, create it,
mutate it, construct a new instance over the same path, and assert the
observable behaviour (not the internals) is unchanged.
"""

from __future__ import annotations

import json

import pytest

from raucle.agent_credentials import AgentCredentialStore
from raucle.capability import Capability, CapabilityIssuer, DelegationLedger
from raucle.gateway import UserManager
from raucle.receipt_index import ReceiptIndex

pyotp = pytest.importorskip("pyotp")


class TestUserManagerRoundTrip:
    def test_role_name_and_expiry_survive(self, tmp_path):
        path = tmp_path / "users.jsonl"
        first = UserManager(persist_path=path)
        first.add_user("key-one-for-tests", "operator", "Op One", expires_at=None)
        first.add_user("key-two-for-tests", "auditor", "Aud Two", expires_at=4_000_000_000)

        second = UserManager(persist_path=path)
        one = second.get_user("key-one-for-tests")
        two = second.get_user("key-two-for-tests")
        assert one is not None
        assert two is not None
        assert (one.role, one.name, one.expires_at) == ("operator", "Op One", None)
        assert (two.role, two.name, two.expires_at) == ("auditor", "Aud Two", 4_000_000_000)

    def test_mfa_state_survives_including_the_enabled_flag(self, tmp_path):
        path = tmp_path / "users.jsonl"
        first = UserManager(persist_path=path)
        first.add_user("key-one-for-tests", "admin", "Admin")
        provisioning = first.setup_mfa("key-one-for-tests")
        assert provisioning is not None
        code = pyotp.TOTP(provisioning["secret"]).now()
        assert first.verify_mfa("key-one-for-tests", code)

        second = UserManager(persist_path=path)
        reloaded = second.get_user("key-one-for-tests")
        assert reloaded is not None
        assert reloaded.mfa_enabled is True
        assert reloaded.requires_mfa() is True
        assert second.verify_totp(reloaded, pyotp.TOTP(provisioning["secret"]).now()) is True

    def test_removal_survives(self, tmp_path):
        path = tmp_path / "users.jsonl"
        first = UserManager(persist_path=path)
        first.add_user("key-one-for-tests", "admin", "Admin")
        first.add_user("key-two-for-tests", "auditor", "Aud")
        assert first.remove_user("key-two-for-tests")
        assert UserManager(persist_path=path).get_user("key-two-for-tests") is None


class TestAgentCredentialRoundTrip:
    def test_issued_key_still_verifies(self, tmp_path):
        path = tmp_path / "creds.jsonl"
        first = AgentCredentialStore(path)
        key = first.issue("agent:bot")
        second = AgentCredentialStore(path)
        assert second.verify(key) == "agent:bot"
        assert second.list_agents() == ["agent:bot"]

    def test_revocation_survives(self, tmp_path):
        path = tmp_path / "creds.jsonl"
        first = AgentCredentialStore(path)
        key = first.issue("agent:bot")
        assert first.revoke("agent:bot")
        assert AgentCredentialStore(path).verify(key) is None

    def test_rotation_leaves_one_active_key(self, tmp_path):
        path = tmp_path / "creds.jsonl"
        first = AgentCredentialStore(path)
        old = first.issue("agent:bot")
        new = first.issue("agent:bot")
        second = AgentCredentialStore(path)
        assert second.verify(old) is None
        assert second.verify(new) == "agent:bot"
        assert len(second.list_agents()) == 1


class TestDelegationLedgerRoundTrip:
    def test_a_registered_token_resolves_after_reload(self, tmp_path):
        path = tmp_path / "delegations.jsonl"
        issuer = CapabilityIssuer.generate("acme.test")
        parent = issuer.mint(agent_id="agent:bot", tool="pay", ttl_seconds=300)
        first = DelegationLedger(path)
        first.register(parent, verifying_key=issuer)

        second = DelegationLedger(path)
        resolved = second.resolver()(parent.token_id)
        assert resolved is not None
        assert resolved.token_id == parent.token_id
        assert isinstance(resolved, Capability)

    def test_an_attenuated_child_resolves_to_its_parent(self, tmp_path):
        path = tmp_path / "delegations.jsonl"
        issuer = CapabilityIssuer.generate("acme.test")
        parent = issuer.mint(agent_id="agent:bot", tool="pay", ttl_seconds=300)
        child = issuer.attenuate(parent, narrower_ttl_seconds=60)
        first = DelegationLedger(path)
        first.register(parent, verifying_key=issuer)
        first.register(child, verifying_key=issuer)

        resolver = DelegationLedger(path).resolver()
        resolved = resolver(child.token_id)
        assert resolved is not None
        assert resolved.parent_id == parent.token_id


class TestReceiptIndexRoundTrip:
    def test_a_rebuilt_index_serves_the_same_rows(self, tmp_path, monkeypatch):
        from raucle.gateway import GatewayConfig, RaucleGateway

        policy = tmp_path / "policies.yaml"
        policy.write_text(
            """
version: 1
issuer: test.bank
policies:
  - tool: pay
    agent_id: agent:bot
    ttl_seconds: 300
    constraints:
      allow:
        account: ["ACC-001"]
"""
        )
        cfg = GatewayConfig(
            policy_file=str(policy),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            receipt_index_path=str(tmp_path / "index.sqlite"),
            registry_path=str(tmp_path / "registry.jsonl"),
            signer_key_path=str(tmp_path / "signer.pem"),
            agent_credentials_file=str(tmp_path / "creds.jsonl"),
            gate_auth="off",
            signer_backend="local",
        )
        gateway = RaucleGateway(cfg)
        gateway.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot")
        index = gateway._receipt_index
        assert index is not None
        before = index.query(limit=10)
        assert len(before) == 1

        # A fresh projection over the same chain must agree with the old one.
        rebuilt = ReceiptIndex(sqlite_path=str(tmp_path / "index2.sqlite"))
        try:
            assert rebuilt.rebuild_from_flat_file(str(tmp_path / "receipts.jsonl")) == 1
            after = rebuilt.query(limit=10)
            assert after[0]["receipt_hash"] == before[0]["receipt_hash"]
            assert after[0]["decision"] == before[0]["decision"]
        finally:
            rebuilt.close()

    def test_an_undecodable_envelope_is_skipped_not_fatal(self, tmp_path):
        """A projection never rejects chain content; it only fails to index it."""
        path = tmp_path / "chain.jsonl"
        path.write_text(
            json.dumps({"receipt_hash": "sha256:aa", "jws": "a.b.c"}) + "\n", encoding="utf-8"
        )
        index = ReceiptIndex(sqlite_path=str(tmp_path / "i.sqlite"))
        try:
            assert index.rebuild_from_flat_file(str(path)) == 0
            assert index.count() == 0
        finally:
            index.close()
