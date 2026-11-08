"""Tests for the Raule Gateway - admin panel, stats, SIEM, user management."""

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, GatewayStats, RaucleGateway, SIEMForwarder, UserManager
from raucle.gateway_app import create_admin_app, create_gateway_app

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def gateway_config(tmp_path):
    """Create a gateway config with temp paths."""
    return GatewayConfig(
        policy_file=str(tmp_path / "policies.yaml"),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="test-admin-key",
        signer_backend="local",
    )


@pytest.fixture
def policy_file(tmp_path):
    """Create a test policy file."""
    content = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-002"]
  - tool: transfer_money
    agent_id: agent:pay
    ttl_seconds: 300
    constraints:
      allow:
        from_account: ["ACC-001"]
        to_account: ["ACC-002"]
      max:
        amount: 10000
    require_approval_when:
      amount_gt: 5000
"""
    path = tmp_path / "policies.yaml"
    path.write_text(content)
    return str(path)


@pytest.fixture
def gateway_with_policies(gateway_config, policy_file):
    """Create a gateway with a loaded policy file."""
    gateway_config.policy_file = policy_file
    return RaucleGateway(gateway_config)


@pytest.fixture
def gateway_no_policies(gateway_config):
    """Create a gateway with no policy file."""
    return RaucleGateway(gateway_config)


@pytest.fixture
def admin_app(gateway_with_policies):
    """Create an admin app with test users."""
    users = UserManager()
    users.add_user("admin-key", "admin", "Admin")
    users.add_user("operator-key", "operator", "Operator")
    users.add_user("auditor-key", "auditor", "Auditor")
    return create_admin_app(gateway_with_policies, users)


@pytest.fixture
def gateway_app(gateway_with_policies):
    """Create a gateway API app."""
    return create_gateway_app(gateway_with_policies)


@pytest.fixture
def admin_client(admin_app):
    return TestClient(admin_app)


@pytest.fixture
def gateway_client(gateway_app):
    return TestClient(gateway_app)


# ---------------------------------------------------------------------------
# GatewayConfig
# ---------------------------------------------------------------------------


class TestGatewayConfig:
    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("RAUCLE_GATEWAY_PORT", "9999")
        monkeypatch.setenv("RAUCLE_ADMIN_PORT", "9998")
        monkeypatch.setenv("RAUCLE_ADMIN_KEY", "secret")
        config = GatewayConfig.from_env()
        assert config.port == 9999
        assert config.admin_port == 9998
        assert config.admin_api_key == "secret"

    def test_defaults(self):
        config = GatewayConfig()
        assert config.port == 8080
        assert config.admin_port == 8081
        assert config.signer_backend == "local"


# ---------------------------------------------------------------------------
# GatewayStats
# ---------------------------------------------------------------------------


class TestGatewayStats:
    def test_record_allow(self):
        stats = GatewayStats()
        stats.record("lookup", "allow", 100)
        assert stats.total_requests == 1
        assert stats.allowed == 1
        assert stats.by_tool["lookup"]["allow"] == 1

    def test_record_deny(self):
        stats = GatewayStats()
        stats.record("transfer", "deny", 50)
        assert stats.denied == 1

    def test_record_escalate(self):
        stats = GatewayStats()
        stats.record("transfer", "escalate", 75)
        assert stats.escalated == 1

    def test_summary(self):
        stats = GatewayStats()
        stats.record("lookup", "allow", 100)
        stats.record("transfer", "deny", 50)
        s = stats.summary()
        assert s["total_requests"] == 2
        assert s["allowed"] == 1
        assert s["denied"] == 1
        assert s["avg_latency_us"] == 75.0


# ---------------------------------------------------------------------------
# SIEMForwarder
# ---------------------------------------------------------------------------


class TestSIEMForwarder:
    def test_disabled_buffers_events(self, gateway_config):
        forwarder = SIEMForwarder(gateway_config)
        forwarder.forward({"event": "test"})
        assert len(forwarder.buffered_events()) == 1

    def test_enabled_sends(self, gateway_config):
        gateway_config.siem_enabled = True
        gateway_config.siem_backend = "elastic"
        gateway_config.siem_url = "http://localhost:9200/raucle/_doc"
        forwarder = SIEMForwarder(gateway_config)
        # Will fail silently (no real endpoint) and buffer
        forwarder.forward({"event": "test"})
        assert len(forwarder.buffered_events()) == 1


# ---------------------------------------------------------------------------
# UserManager
# ---------------------------------------------------------------------------


class TestUserManager:
    def test_add_and_get_user(self):
        mgr = UserManager()
        user = mgr.add_user("key123", "admin", "Test")
        assert mgr.get_user("key123") == user

    def test_remove_user(self):
        mgr = UserManager()
        mgr.add_user("key123", "admin")
        assert mgr.remove_user("key123")
        assert mgr.get_user("key123") is None

    def test_admin_can_access_all(self):
        mgr = UserManager()
        mgr.add_user("admin-key", "admin")
        assert mgr.can_access("admin-key", "policies")
        assert mgr.can_access("admin-key", "users")
        assert mgr.can_access("admin-key", "stats")

    def test_operator_cannot_access_users(self):
        mgr = UserManager()
        mgr.add_user("op-key", "operator")
        assert mgr.can_access("op-key", "policies")
        assert not mgr.can_access("op-key", "users")

    def test_auditor_can_only_read(self):
        mgr = UserManager()
        mgr.add_user("aud-key", "auditor")
        assert mgr.can_access("aud-key", "stats")
        assert mgr.can_access("aud-key", "receipts")
        assert not mgr.can_access("aud-key", "policies")
        assert not mgr.can_access("aud-key", "config")

    def test_unknown_key_denied(self):
        mgr = UserManager()
        assert not mgr.can_access("nonexistent", "stats")


# ---------------------------------------------------------------------------
# RaucleGateway
# ---------------------------------------------------------------------------


class TestRaucleGateway:
    def test_no_policies_denies_all(self, gateway_no_policies):
        result = gateway_no_policies.check_tool_call("any_tool", {})
        assert result["decision"] == "deny"
        assert "no policy" in result["reason"]

    def test_allowed_call(self, gateway_with_policies):
        result = gateway_with_policies.check_tool_call("lookup_balance", {"account": "ACC-001"})
        assert result["decision"] == "allow"

    def test_denied_call(self, gateway_with_policies):
        result = gateway_with_policies.check_tool_call("lookup_balance", {"account": "ACC-999"})
        assert result["decision"] == "deny"

    def test_transfer_within_limit(self, gateway_with_policies):
        result = gateway_with_policies.check_tool_call(
            "transfer_money",
            {"from_account": "ACC-001", "to_account": "ACC-002", "amount": 5000},
        )
        assert result["decision"] == "allow"

    def test_transfer_over_limit_denied(self, gateway_with_policies):
        result = gateway_with_policies.check_tool_call(
            "transfer_money",
            {"from_account": "ACC-001", "to_account": "ACC-002", "amount": 50000},
        )
        assert result["decision"] == "deny"

    def test_transfer_requires_approval(self, gateway_with_policies):
        result = gateway_with_policies.check_tool_call(
            "transfer_money",
            {"from_account": "ACC-001", "to_account": "ACC-002", "amount": 7500},
        )
        assert result["decision"] == "escalate"

    def test_stats_recorded(self, gateway_with_policies):
        gateway_with_policies.check_tool_call("lookup_balance", {"account": "ACC-001"})
        gateway_with_policies.check_tool_call("lookup_balance", {"account": "ACC-999"})
        stats = gateway_with_policies.get_stats()
        assert stats["total_requests"] == 2
        assert stats["allowed"] == 1
        assert stats["denied"] == 1

    def test_reload_policies(self, gateway_with_policies):
        result = gateway_with_policies.reload_policies()
        assert result["status"] == "ok"


@pytest.fixture
def approval_only_gateway(tmp_path):
    """A rule whose only human gate is an approval threshold (no numeric
    ceiling), so a type-confused argument reaches the threshold evaluator."""
    path = tmp_path / "approval-policies.yaml"
    path.write_text(
        """
version: 1
issuer: test.bank
policies:
  - tool: pay
    agent_id: agent:pay
    ttl_seconds: 300
    require_approval_when:
      amount_gt: 5000
  - tool: refund
    agent_id: agent:pay
    ttl_seconds: 300
    require_approval_when:
      amount_eq: 10000
"""
    )
    cfg = GatewayConfig(
        policy_file=str(path),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="test-admin-key",
        signer_backend="local",
    )
    return RaucleGateway(cfg)


class TestApprovalThresholdGatePath:
    """RED-031: the gate-path consequences of type-confused thresholds."""

    def test_numeric_text_escalates_instead_of_crashing(self, approval_only_gateway):
        result = approval_only_gateway.check_tool_call("pay", {"amount": "99999"})
        assert result["decision"] == "escalate"
        assert result["receipt_id"]

    def test_numeric_text_matches_eq_threshold(self, approval_only_gateway):
        """Previously: "10000" == 10000 is False, so the call was ALLOWED."""
        result = approval_only_gateway.check_tool_call("refund", {"amount": "10000"})
        assert result["decision"] == "escalate"

    def test_decision_path_fault_is_a_receipted_deny(self, approval_only_gateway, monkeypatch):
        def _boom(*_args, **_kwargs):
            raise RuntimeError("simulated internal failure")

        monkeypatch.setattr(approval_only_gateway._approvals, "consume", _boom)
        result = approval_only_gateway.check_tool_call(
            "pay", {"amount": 7500}, approval_id="appr-1"
        )
        assert result["decision"] == "deny"
        assert result["reason"].startswith("gate_fault:")
        assert "simulated internal failure" not in result["reason"]
        assert result["receipt_id"]


# ---------------------------------------------------------------------------
# Admin Panel API
# ---------------------------------------------------------------------------


class TestAdminAPI:
    def test_health_no_auth(self, admin_client):
        resp = admin_client.get("/health")
        assert resp.status_code == 200

    def test_stats_requires_auth(self, admin_client):
        resp = admin_client.get("/api/stats")
        assert resp.status_code == 401

    def test_stats_with_admin(self, admin_client):
        resp = admin_client.get("/api/stats", headers={"Authorization": "admin-key"})
        assert resp.status_code == 200
        data = resp.json()
        assert "total_requests" in data

    def test_stats_with_auditor(self, admin_client):
        resp = admin_client.get("/api/stats", headers={"Authorization": "auditor-key"})
        assert resp.status_code == 200

    def test_policies_with_admin(self, admin_client):
        resp = admin_client.get("/api/policies", headers={"Authorization": "admin-key"})
        assert resp.status_code == 200
        assert "content" in resp.json()

    def test_policies_with_auditor_denied(self, admin_client):
        resp = admin_client.get("/api/policies", headers={"Authorization": "auditor-key"})
        assert resp.status_code == 403

    def test_validate_policy_valid(self, admin_client):
        resp = admin_client.post(
            "/api/policies/validate",
            json={"content": "version: 1\nissuer: test\npolicies: []"},
            headers={"Authorization": "admin-key"},
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_validate_policy_invalid(self, admin_client):
        resp = admin_client.post(
            "/api/policies/validate",
            json={"content": "version: 1\npolicies: []"},
            headers={"Authorization": "admin-key"},
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    def test_receipts(self, admin_client):
        resp = admin_client.get("/api/receipts", headers={"Authorization": "admin-key"})
        assert resp.status_code == 200
        assert "receipts" in resp.json()

    def test_siem_config(self, admin_client):
        resp = admin_client.get("/api/siem", headers={"Authorization": "admin-key"})
        assert resp.status_code == 200
        assert "enabled" in resp.json()

    def test_users_list(self, admin_client):
        resp = admin_client.get("/api/users", headers={"Authorization": "admin-key"})
        assert resp.status_code == 200
        users = resp.json()["users"]
        assert len(users) == 3

    def test_users_create(self, admin_client):
        resp = admin_client.post(
            "/api/users",
            json={"api_key": "new-operator-key-0123456789", "role": "operator", "name": "New Op"},
            headers={"Authorization": "admin-key"},
        )
        assert resp.status_code == 200

    def test_users_operator_denied(self, admin_client):
        resp = admin_client.get("/api/users", headers={"Authorization": "operator-key"})
        assert resp.status_code == 403

    def test_config(self, admin_client):
        resp = admin_client.get("/api/config", headers={"Authorization": "admin-key"})
        assert resp.status_code == 200
        assert "signer_backend" in resp.json()

    def test_admin_panel_html(self, admin_client):
        resp = admin_client.get("/")
        assert resp.status_code == 200
        assert "Raucle" in resp.text


# ---------------------------------------------------------------------------
# Gateway API
# ---------------------------------------------------------------------------


class TestGatewayAPI:
    def test_health(self, gateway_client):
        resp = gateway_client.get("/health")
        assert resp.status_code == 200

    def test_gate_allow(self, gateway_client):
        resp = gateway_client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "allow"

    def test_gate_deny(self, gateway_client):
        resp = gateway_client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-999"},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "deny"

    def test_gate_unknown_tool(self, gateway_client):
        resp = gateway_client.post(
            "/gate",
            json={
                "tool": "nonexistent",
                "args": {},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "deny"

    def test_gate_escalate(self, gateway_client):
        resp = gateway_client.post(
            "/gate",
            json={
                "tool": "transfer_money",
                "args": {"from_account": "ACC-001", "to_account": "ACC-002", "amount": 7500},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "escalate"

    def test_gate_includes_latency(self, gateway_client):
        resp = gateway_client.post(
            "/gate",
            json={
                "tool": "lookup_balance",
                "args": {"account": "ACC-001"},
            },
        )
        data = resp.json()
        assert "latency_us" in data
        assert data["latency_us"] >= 0
