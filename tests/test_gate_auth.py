"""Tests for gateway agent authentication (Task A1: credential store + auth modes)."""

import pytest

from raucle.agent_credentials import AgentCredentialStore


@pytest.fixture()
def store_path(tmp_path):
    return tmp_path / "agent-credentials.jsonl"


class TestAgentCredentialStore:
    def test_issue_verify_roundtrip(self, store_path):
        store = AgentCredentialStore(path=store_path)
        key = store.issue(agent_id="agent:pay")
        assert key.startswith("rak_")
        assert len(key) > 20
        assert store.verify(key) == "agent:pay"

    def test_unknown_key_rejected(self, store_path):
        store = AgentCredentialStore(path=store_path)
        store.issue(agent_id="agent:pay")
        assert store.verify("rak_0000000000000000000000000000") is None
        assert store.verify("not-even-a-key") is None
        assert store.verify("") is None

    def test_revoked_key_rejected(self, store_path):
        store = AgentCredentialStore(path=store_path)
        key = store.issue(agent_id="agent:pay")
        assert store.verify(key) == "agent:pay"
        store.revoke(agent_id="agent:pay")
        assert store.verify(key) is None

    def test_persistence_across_store_reload(self, store_path):
        store1 = AgentCredentialStore(path=store_path)
        key = store1.issue(agent_id="agent:pay")
        # A new instance (fresh process) must see the same credential
        store2 = AgentCredentialStore(path=store_path)
        assert store2.verify(key) == "agent:pay"

    def test_revocation_persists_across_reload(self, store_path):
        store1 = AgentCredentialStore(path=store_path)
        key = store1.issue(agent_id="agent:pay")
        store1.revoke(agent_id="agent:pay")
        store2 = AgentCredentialStore(path=store_path)
        assert store2.verify(key) is None

    def test_reissue_replaces_key(self, store_path):
        store = AgentCredentialStore(path=store_path)
        key1 = store.issue(agent_id="agent:pay")
        key2 = store.issue(agent_id="agent:pay")
        assert key1 != key2
        assert store.verify(key1) is None  # old key dead
        assert store.verify(key2) == "agent:pay"

    def test_list_agents(self, store_path):
        store = AgentCredentialStore(path=store_path)
        store.issue(agent_id="agent:pay")
        store.issue(agent_id="agent:hr")
        agents = store.list_agents()
        assert set(agents) == {"agent:pay", "agent:hr"}

    def test_multiple_agents_independent(self, store_path):
        store = AgentCredentialStore(path=store_path)
        k1 = store.issue(agent_id="agent:pay")
        k2 = store.issue(agent_id="agent:hr")
        assert store.verify(k1) == "agent:pay"
        assert store.verify(k2) == "agent:hr"

    def test_corrupt_store_fails_closed_on_load(self, store_path):
        store_path.write_text("not json at all\n{broken", encoding="utf-8")
        with pytest.raises(ValueError, match="corrupt"):
            AgentCredentialStore(path=store_path)

    def test_key_hash_not_stored_plaintext(self, store_path):
        store = AgentCredentialStore(path=store_path)
        key = store.issue(agent_id="agent:pay")
        raw = store_path.read_text(encoding="utf-8")
        assert key not in raw  # only the SHA-256 of the key may touch disk
        assert "agent:pay" in raw
