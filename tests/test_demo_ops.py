"""Demo operational surfaces: the Users / SIEM / Config demo views.

Covers:
- /api/demo/users: the simulated operator roster (demo gating, labelling,
  determinism, mixed MFA states),
- /api/demo/siem: the real forwarding configuration beside the simulated
  forwarder example (endpoint shape, event counts, no credential material),
- /api/demo/config: the real gateway configuration rendered read-only with
  secret fields excluded,
- the panel additions: demo-only cards, loader branching and the MCP
  auto-select that lands the scanner on a finding-bearing manifest.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from raucle.demo_ops import (
    CONFIG_LABEL,
    DEMO_OPERATORS,
    SIMULATED_LABEL,
    build_demo_config,
    build_demo_operators,
    build_demo_siem,
)
from raucle.demo_scenarios import DEMO_MANIFESTS
from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import ADMIN_PANEL_HTML, create_admin_app
from raucle.mcp_scanner import scan_manifest

POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
"""

SECRET_FIELD_NAMES = ("admin_api_key", "siem_token", "health_check_token")


@pytest.fixture
def demo_stack(tmp_path, monkeypatch) -> tuple[TestClient, str, str]:
    """Admin app with the demo credential registered and demo mode on."""
    monkeypatch.setenv("RAUCLE_DEMO_MODE", "1")
    monkeypatch.setenv("RAUCLE_DEMO_KEY", "demo-key-sim")
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    config = GatewayConfig(
        policy_file=str(policy),
        policy_dir=str(tmp_path / "policies"),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="admin-key-0123456789",
        signer_backend="local",
    )
    gateway = RaucleGateway(config)
    users = UserManager()
    users.add_user("admin-key-0123456789", "admin", "Admin")
    # The real demo key is an auditor (read-only): the resource gate is stats.
    users.add_user("demo-key-sim", "auditor", "Demo (read-only)")
    client = TestClient(create_admin_app(gateway, users))
    return client, "demo-key-sim", "admin-key-0123456789"


@pytest.fixture
def plain_stack(tmp_path, monkeypatch) -> tuple[TestClient, str]:
    """Admin app with demo mode off entirely."""
    monkeypatch.delenv("RAUCLE_DEMO_MODE", raising=False)
    monkeypatch.delenv("RAUCLE_DEMO_KEY", raising=False)
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    config = GatewayConfig(
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="admin-key-0123456789",
        signer_backend="local",
    )
    gateway = RaucleGateway(config)
    users = UserManager()
    users.add_user("admin-key-0123456789", "admin", "Admin")
    client = TestClient(create_admin_app(gateway, users))
    return client, "admin-key-0123456789"


# ---------------------------------------------------------------------------
# Roster: builder
# ---------------------------------------------------------------------------


class TestDemoRoster:
    def test_roster_carries_four_simulated_operators(self):
        body = build_demo_operators()
        users = body["users"]
        assert 3 <= len(users) <= 4
        for user in users:
            assert user["name"]
            assert user["role"] in ("admin", "operator", "auditor")
            assert isinstance(user["mfa_enabled"], bool)

    def test_roster_shows_both_mfa_states(self):
        states = {user["mfa_enabled"] for user in DEMO_OPERATORS}
        assert states == {True, False}

    def test_roster_is_labelled_simulated(self):
        body = build_demo_operators()
        assert SIMULATED_LABEL in body["note"]
        assert body["simulated"] is True

    def test_roster_is_deterministic(self):
        first = build_demo_operators()
        second = build_demo_operators()
        assert first == second


# ---------------------------------------------------------------------------
# SIEM: real config + simulated forwarder
# ---------------------------------------------------------------------------


class TestDemoSiemBuilder:
    def test_exposes_the_real_forwarding_configuration(self):
        config = GatewayConfig(
            policy_file="p.yaml",
            receipt_store="r.jsonl",
            audit_chain="a.jsonl",
            admin_api_key="admin-key-0123456789",
            signer_backend="local",
            siem_enabled=True,
            siem_backend="elastic",
            siem_url="https://logs.demo-siem.test:9200/raucle-gate/_doc",
            siem_token="token-value-000",
        )
        gateway = RaucleGateway(config)
        body = build_demo_siem(gateway)
        conf = body["configured"]
        assert conf["enabled"] is True
        assert conf["backend"] == "elastic"
        assert conf["url"].endswith("/_doc")
        assert conf["token_configured"] is True
        assert conf["buffered_events"] == 0
        # The credential itself never enters the response.
        assert "token-value-000" not in str(body)

    def test_forwarder_example_is_simulated_and_complete(self):
        config = GatewayConfig(
            policy_file="p.yaml",
            receipt_store="r.jsonl",
            audit_chain="a.jsonl",
            admin_api_key="admin-key-0123456789",
            signer_backend="local",
        )
        gateway = RaucleGateway(config)
        sim = build_demo_siem(gateway)["simulated"]
        assert SIMULATED_LABEL in sim["label"]
        shape = sim["endpoint_shape"]
        assert shape["transport"].startswith("HTTP POST")
        assert ".test" in shape["url_example"], "example endpoints stay in the .test space"
        # Event shape matches the real SIEMForwarder gate-decision payload.
        assert set(sim["event_sample"]) == {
            "event",
            "tool",
            "decision",
            "reason",
            "timestamp",
        }
        assert sim["event_sample"]["event"] == "gate_decision"

    def test_activity_covers_the_window_and_ties_out(self):
        config = GatewayConfig(
            policy_file="p.yaml",
            receipt_store="r.jsonl",
            audit_chain="a.jsonl",
            admin_api_key="admin-key-0123456789",
            signer_backend="local",
        )
        gateway = RaucleGateway(config)
        sim = build_demo_siem(gateway)["simulated"]
        buckets = sim["activity"]
        assert len(buckets) == 12
        assert all(b["events"] > 0 for b in buckets)
        assert sum(b["events"] for b in buckets) == sim["events_forwarded_total"]
        assert all(b["status"] for b in buckets)

    def test_siem_view_is_deterministic(self):
        config = GatewayConfig(
            policy_file="p.yaml",
            receipt_store="r.jsonl",
            audit_chain="a.jsonl",
            admin_api_key="admin-key-0123456789",
            signer_backend="local",
        )
        gateway = RaucleGateway(config)
        first = build_demo_siem(gateway)
        assert first == build_demo_siem(gateway)


# ---------------------------------------------------------------------------
# Config: real values, read-only, secrets out
# ---------------------------------------------------------------------------


class TestDemoConfigBuilder:
    def test_profile_lists_the_deployment_fields(self, tmp_path):
        config = GatewayConfig(
            policy_file=str(tmp_path / "policies.yaml"),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            admin_api_key="admin-key-0123456789",
            signer_backend="local",
        )
        gateway = RaucleGateway(config)
        profile = build_demo_config(gateway)["profile"]
        labels = {row["label"] for row in profile}
        for expected in (
            "Host",
            "Gateway port",
            "Admin panel port",
            "Signer backend",
            "Policy file",
            "Receipt store",
            "Audit chain",
        ):
            assert expected in labels
        by_label = {row["label"]: row["value"] for row in profile}
        assert by_label["Signer backend"] == "local"
        assert by_label["Gateway port"] == config.port

    def test_label_says_real_not_simulated_and_is_read_only(self, tmp_path):
        config = GatewayConfig(
            policy_file="p.yaml",
            receipt_store="r.jsonl",
            audit_chain="a.jsonl",
            admin_api_key="admin-key-0123456789",
            signer_backend="local",
        )
        gateway = RaucleGateway(config)
        body = build_demo_config(gateway)
        assert body["label"] == CONFIG_LABEL
        assert "Simulated" not in body["label"]
        assert body["read_only"] is True

    def test_no_secret_field_reaches_the_profile(self, tmp_path):
        config = GatewayConfig(
            policy_file="p.yaml",
            receipt_store="r.jsonl",
            audit_chain="a.jsonl",
            admin_api_key="admin-key-0123456789",
            signer_backend="local",
            health_check_token="health-token-000",
        )
        gateway = RaucleGateway(config)
        body = build_demo_config(gateway)
        for secret in ("admin-key-0123456789", "health-token-000"):
            assert secret not in str(body)
        assert all(name not in str(body) for name in SECRET_FIELD_NAMES)


# ---------------------------------------------------------------------------
# Endpoints: demo gating
# ---------------------------------------------------------------------------


class TestDemoOpsEndpoints:
    @pytest.mark.parametrize("path", ["/api/demo/users", "/api/demo/siem", "/api/demo/config"])
    def test_demo_reader_can_read_every_surface(self, demo_stack, path):
        client, demo_key, _admin = demo_stack
        r = client.get(path, headers={"Authorization": demo_key})
        assert r.status_code == 200

    @pytest.mark.parametrize("path", ["/api/demo/users", "/api/demo/siem", "/api/demo/config"])
    def test_surfaces_are_closed_without_demo_mode(self, plain_stack, path):
        client, admin_key = plain_stack
        assert client.get(path, headers={"Authorization": admin_key}).status_code == 404

    @pytest.mark.parametrize("path", ["/api/demo/users", "/api/demo/siem", "/api/demo/config"])
    def test_surfaces_require_credentials(self, demo_stack, path):
        client, *_ = demo_stack
        assert client.get(path).status_code == 401

    def test_roster_endpoint_response_is_simulated(self, demo_stack):
        client, demo_key, _admin = demo_stack
        body = client.get("/api/demo/users", headers={"Authorization": demo_key}).json()
        assert SIMULATED_LABEL in body["note"]
        assert len(body["users"]) == len(DEMO_OPERATORS)

    def test_siem_endpoint_carries_real_config_and_simulated_example(self, demo_stack):
        client, demo_key, _admin = demo_stack
        body = client.get("/api/demo/siem", headers={"Authorization": demo_key}).json()
        assert set(body["configured"]) >= {"enabled", "backend", "url", "token_configured"}
        assert SIMULATED_LABEL in body["simulated"]["label"]

    def test_config_endpoint_is_read_only_text_of_real_values(self, demo_stack):
        client, demo_key, _admin = demo_stack
        r = client.get("/api/demo/config", headers={"Authorization": demo_key})
        body = r.json()
        assert body["read_only"] is True
        assert body["profile"], "a deployment profile with no rows renders nothing"
        for secret in SECRET_FIELD_NAMES:
            assert secret not in r.text

    def test_demo_plane_registers_no_mutation_routes(self, plain_stack):
        client, _admin = plain_stack
        mutations = [
            (route.path, method)
            for route in client.app.routes
            for path in ("/api/demo/users", "/api/demo/siem", "/api/demo/config")
            if getattr(route, "path", "") == path
            for method in getattr(route, "methods", set())
            if method != "GET"
        ]
        assert mutations == []

    @pytest.mark.parametrize("path", ["/api/demo/users", "/api/demo/siem", "/api/demo/config"])
    def test_surfaces_stay_deterministic(self, demo_stack, path):
        client, demo_key, _admin = demo_stack
        first = client.get(path, headers={"Authorization": demo_key}).content
        second = client.get(path, headers={"Authorization": demo_key}).content
        assert first == second


# ---------------------------------------------------------------------------
# Panel integration
# ---------------------------------------------------------------------------


class TestDemoOpsPanel:
    def test_demo_replacement_cards_hidden_outside_demo_mode(self):
        for card_id in ("#demoUsersCard", "#demoSiemCard", "#demoConfigCard"):
            assert f"body:not(.demo) {card_id}" in ADMIN_PANEL_HTML

    def test_edit_surfaces_hidden_inside_demo_mode(self):
        for card_id in ("#usersAddCard", "#usersTableCard", "#siemConfigCard", "#configEditCard"):
            assert f"body.demo {card_id}" in ADMIN_PANEL_HTML

    def test_demo_mode_no_longer_hides_the_privileged_tabs(self):
        # The whole point: a demo visitor can reach SIEM, Users and Config.
        for tab_id in ("siem", "users", "config"):
            rule = f'body.demo [data-tab-id="{tab_id}"]'
            assert rule not in ADMIN_PANEL_HTML, rule

    def test_loaders_branch_on_demo_mode(self):
        for fn in ("loadUsers", "loadSIEM", "loadConfig"):
            assert (
                f"typeof demoMode!=='undefined'&&demoMode){{{'loadDemo' + fn[4:]}()"
                in ADMIN_PANEL_HTML
            ), fn

    def test_demo_loaders_render_textcontent_only(self):
        script = "".join(re.findall(r"<script[^>]*>(.*?)</script>", ADMIN_PANEL_HTML, re.S))
        start = script.find("DEMO OPERATIONS")
        end = script.find("// ================= DEMO FINDINGS", start)
        assert start != -1
        assert end != -1
        assert end > start
        section = script[start:end]
        assert "innerHTML" not in section
        assert section.count("textContent") >= 5

    def test_demo_404_fallbacks_message_like_the_mcp_tab(self):
        count = ADMIN_PANEL_HTML.count("Demo mode is not configured on this deployment.")
        assert count >= 4, "users, siem, config loaders plus the mcp list must fall back cleanly"

    def test_mcp_auto_select_is_wired(self):
        assert "autoMcpSelect();" in ADMIN_PANEL_HTML
        script = "".join(re.findall(r"<script[^>]*>(.*?)</script>", ADMIN_PANEL_HTML, re.S))
        block = script[script.find("function autoMcpSelect()") : script.find("function mcpPick(")]
        assert len(block) > 0, "auto-select block must sit beside the pick handler"
        # Never overrides a selection the visitor already made, and the scan
        # route (the real scanner) produces the first findings table.
        assert "if(mcpSelected)return;" in block
        assert "mcpScan();" in block
        assert "throw 0" in block

    def test_featured_demo_manifest_scans_to_findings_on_the_real_engine(self):
        featured = [m for m in DEMO_MANIFESTS if m.get("featured")]
        assert len(featured) == 1
        findings = scan_manifest(featured[0]["manifest"])
        assert findings, "the auto-selected manifest must render findings on arrival"

    def test_tab_entry_still_routes_to_the_demo_loaders(self):
        for call in (
            "if(t==='siem')loadSIEM()",
            "if(t==='users')loadUsers()",
            "if(t==='config')loadConfig()",
        ):
            assert call in ADMIN_PANEL_HTML
