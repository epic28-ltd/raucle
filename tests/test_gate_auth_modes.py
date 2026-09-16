"""Gate authentication mode tests (Task A1.3/A1.4): off / apikey / token."""

import json

import pytest
from fastapi.testclient import TestClient

from raucle.capability import CapabilityIssuer
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.gateway_app import create_gateway_app
from raucle.trust_registry import TrustRegistry

POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-002"]
"""


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
        agent_credentials_file=str(tmp_path / "agent-credentials.jsonl"),
    )


@pytest.fixture()
def policy_file(tmp_path):
    path = tmp_path / "policies.yaml"
    path.write_text(POLICY)
    return str(path)


def _client(gateway):
    return TestClient(create_gateway_app(gateway))


class TestAuthOffMode:
    def test_off_trusts_declared_identity(self, base_config, policy_file):
        """A1.2: off mode is a no-op - declared agent_id trusted, no headers."""
        base_config.policy_file = policy_file
        base_config.gate_auth = "off"
        gw = RaucleGateway(base_config)
        client = _client(gw)
        resp = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:svc",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "allow"


class TestAuthApikeyMode:
    def test_missing_key_denied(self, base_config, policy_file):
        base_config.policy_file = policy_file
        base_config.gate_auth = "apikey"
        gw = RaucleGateway(base_config)
        client = _client(gw)
        resp = client.post("/gate", json={"tool": "lookup_balance", "args": {"account": "ACC-001"}})
        assert resp.json()["decision"] == "deny"
        assert "api key required" in resp.json()["reason"]

    def test_valid_key_allows(self, base_config, policy_file):
        base_config.policy_file = policy_file
        base_config.gate_auth = "apikey"
        gw = RaucleGateway(base_config)
        key = gw._agent_creds.issue(agent_id="agent:svc")
        client = _client(gw)
        resp = client.post(
            "/gate",
            json={"tool": "lookup_balance", "args": {"account": "ACC-001"}},
            headers={"X-Api-Key": key},
        )
        assert resp.json()["decision"] == "allow"
        # authenticated identity is used, not any declared one
        assert resp.json()["agent_id"] == "agent:svc"

    def test_wrong_key_denied(self, base_config, policy_file):
        base_config.policy_file = policy_file
        base_config.gate_auth = "apikey"
        gw = RaucleGateway(base_config)
        gw._agent_creds.issue(agent_id="agent:svc")
        client = _client(gw)
        resp = client.post(
            "/gate",
            json={"tool": "lookup_balance", "args": {"account": "ACC-001"}},
            headers={"X-Api-Key": "rak_0000000000000000000000000000000"},
        )
        assert resp.json()["decision"] == "deny"
        assert "invalid or revoked" in resp.json()["reason"]

    def test_revoked_key_denied(self, base_config, policy_file):
        base_config.policy_file = policy_file
        base_config.gate_auth = "apikey"
        gw = RaucleGateway(base_config)
        key = gw._agent_creds.issue(agent_id="agent:svc")
        gw._agent_creds.revoke("agent:svc")
        client = _client(gw)
        resp = client.post(
            "/gate",
            json={"tool": "lookup_balance", "args": {"account": "ACC-001"}},
            headers={"X-Api-Key": key},
        )
        assert resp.json()["decision"] == "deny"


class TestAuthTokenMode:
    def _registry_and_token(self, tmp_path, agent_id="agent:svc", tool="lookup_balance"):
        """Issue a token whose issuer is registered in the trust registry."""
        issuer = CapabilityIssuer.generate(issuer="test-issuer")
        token = issuer.mint(
            agent_id=agent_id,
            tool=tool,
            constraints={"allowed_values": {"account": ["ACC-001"]}},
            ttl_seconds=300,
        )
        reg = TrustRegistry(path=tmp_path / "registry.jsonl")
        reg.publish(
            issuer.public_key_pem.decode()
            if isinstance(issuer.public_key_pem, bytes)
            else issuer.public_key_pem,
            issuer="test-issuer",
        )
        return issuer, token, reg

    def test_valid_token_allows(self, base_config, policy_file, tmp_path):
        base_config.policy_file = policy_file
        base_config.gate_auth = "token"
        issuer, token, reg = self._registry_and_token(tmp_path)
        base_config.registry_path = str(tmp_path / "registry.jsonl")
        gw = RaucleGateway(base_config)
        client = _client(gw)
        resp = client.post(
            "/gate",
            json={"tool": "lookup_balance", "args": {"account": "ACC-001"}},
            headers={"X-Capability-Token": json.dumps(token.to_dict())},
        )
        assert resp.json()["decision"] == "allow"
        assert resp.json()["agent_id"] == "agent:svc"

    def test_missing_token_denied(self, base_config, policy_file, tmp_path):
        base_config.policy_file = policy_file
        base_config.gate_auth = "token"
        gw = RaucleGateway(base_config)
        client = _client(gw)
        resp = client.post("/gate", json={"tool": "lookup_balance", "args": {}})
        assert resp.json()["decision"] == "deny"
        assert "capability token required" in resp.json()["reason"]

    def test_mismatch_declared_denied(self, base_config, policy_file, tmp_path):
        base_config.policy_file = policy_file
        base_config.gate_auth = "token"
        issuer, token, reg = self._registry_and_token(tmp_path)
        base_config.registry_path = str(tmp_path / "registry.jsonl")
        gw = RaucleGateway(base_config)
        client = _client(gw)
        resp = client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
                "agent_id": "agent:imposter",
            },
            headers={"X-Capability-Token": json.dumps(token.to_dict())},
        )
        assert resp.json()["decision"] == "deny"
        assert "mismatch" in resp.json()["reason"]

    def test_expired_token_denied(self, base_config, policy_file, tmp_path):
        import time as _time

        base_config.policy_file = policy_file
        base_config.gate_auth = "token"
        issuer = CapabilityIssuer.generate(issuer="test-issuer")
        token = issuer.mint(agent_id="agent:svc", tool="lookup_balance", ttl_seconds=1)
        reg = TrustRegistry(path=tmp_path / "registry.jsonl")
        pem = issuer.public_key_pem
        reg.publish(pem.decode() if isinstance(pem, bytes) else pem, issuer="test-issuer")
        base_config.registry_path = str(tmp_path / "registry.jsonl")
        gw = RaucleGateway(base_config)
        client = _client(gw)
        _time.sleep(1.2)
        resp = client.post(
            "/gate",
            json={"tool": "lookup_balance", "args": {"account": "ACC-001"}},
            headers={"X-Capability-Token": json.dumps(token.to_dict())},
        )
        assert resp.json()["decision"] == "deny"
        assert "expired" in resp.json()["reason"]

    def test_revoked_issuer_denied(self, base_config, policy_file, tmp_path):
        """Registry revocation propagates to gate auth (per-call rebuild)."""
        base_config.policy_file = policy_file
        base_config.gate_auth = "token"
        issuer = CapabilityIssuer.generate(issuer="test-issuer")
        token = issuer.mint(agent_id="agent:svc", tool="lookup_balance", ttl_seconds=300)
        reg = TrustRegistry(path=tmp_path / "registry.jsonl")
        pem = issuer.public_key_pem
        reg.publish(pem.decode() if isinstance(pem, bytes) else pem, issuer="test-issuer")
        base_config.registry_path = str(tmp_path / "registry.jsonl")
        gw = RaucleGateway(base_config)
        client = _client(gw)
        r1 = client.post(
            "/gate",
            json={"tool": "lookup_balance", "args": {"account": "ACC-001"}},
            headers={"X-Capability-Token": json.dumps(token.to_dict())},
        )
        assert r1.json()["decision"] == "allow"
        # Revoke the issuer key in the registry; next call must deny
        kid = issuer.key_id
        reg.revoke(kid, reason="compromised")
        r2 = client.post(
            "/gate",
            json={"tool": "lookup_balance", "args": {"account": "ACC-001"}},
            headers={"X-Capability-Token": json.dumps(token.to_dict())},
        )
        assert r2.json()["decision"] == "deny"


class TestAuthConfigValidation:
    def test_invalid_mode_fails_fast(self, base_config):
        base_config.gate_auth = "magic"
        with pytest.raises(ValueError, match="RAUCLE_GATE_AUTH"):
            RaucleGateway(base_config)
