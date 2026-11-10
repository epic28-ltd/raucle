"""D5/D6 demo endpoint tests: the MCP scanner routes and the capability
scenario plumbing.

The scanner endpoints must always run the real ``raucle.mcp_scanner`` engine,
stay closed without demo mode, and stay open for the read-only demo key
(auditor role) exactly like the rest of the demo-mode surface.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from raucle.demo_scenarios import (
    BENIGN_MANIFEST,
    DEMO_MANIFESTS,
    OVERSIZED_MANIFEST,
    POISONED_MANIFEST,
)
from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import create_admin_app
from raucle.mcp_scanner import Severity, scan_manifest

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


@pytest.fixture
def stack(tmp_path, monkeypatch) -> tuple[TestClient, str]:
    """Admin app with a demo key registered and demo mode on."""
    monkeypatch.setenv("RAUCLE_DEMO_MODE", "1")
    monkeypatch.setenv("RAUCLE_DEMO_KEY", "demo-key")
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    config = GatewayConfig(
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="admin-key",
        signer_backend="local",
    )
    gateway = RaucleGateway(config)
    users = UserManager()
    users.add_user("admin-key", "admin", "Admin")
    users.add_user("demo-key", "auditor", "Demo (read-only)")
    client = TestClient(create_admin_app(gateway, users))
    return client, "demo-key"


def test_demo_manifests_catalogue_is_well_formed():
    names = [m["name"] for m in DEMO_MANIFESTS]
    assert "benign-weather" in names
    assert "poisoned-helper" in names
    assert "oversized-archiver" in names
    assert all(m["simulated"] is True for m in DEMO_MANIFESTS)


def test_scanner_flags_the_poisoned_demo_manifest():
    findings = scan_manifest(POISONED_MANIFEST)
    cats = {f.category for f in findings}
    assert "hidden_instruction" in cats or "prompt_injection" in cats
    assert "credential_exposure" in cats
    assert "ssrf_target" in cats
    assert any(f.severity == Severity.CRITICAL for f in findings)
    tools = {f.tool for f in findings}
    assert "web_search" in tools


def test_scanner_flags_the_oversized_demo_manifest():
    findings = scan_manifest(OVERSIZED_MANIFEST)
    # The hidden payload deep inside the oversized description is still found.
    assert any(f.category == "hidden_instruction" for f in findings)


def test_scanner_reports_no_findings_for_the_benign_demo_manifest():
    # A benign manifest may still leave zero findings in total: assert the
    # scan itself runs and emits nothing from the seeded sample.
    findings = scan_manifest(BENIGN_MANIFEST)
    assert findings == []


def test_scan_route_closed_without_demo_mode(tmp_path, monkeypatch):
    monkeypatch.delenv("RAUCLE_DEMO_MODE", raising=False)
    monkeypatch.delenv("RAUCLE_DEMO_KEY", raising=False)
    policy = tmp_path / "policies.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    config = GatewayConfig(
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="admin-key",
        signer_backend="local",
    )
    gateway = RaucleGateway(config)
    users = UserManager()
    users.add_user("admin-key", "admin", "Admin")
    client = TestClient(create_admin_app(gateway, users))
    r = client.get("/api/demo/mcp/manifests", headers={"Authorization": "admin-key"})
    assert r.status_code == 404
    r = client.post(
        "/api/demo/mcp/scan",
        headers={"Authorization": "admin-key"},
        json={"manifest": BENIGN_MANIFEST},
    )
    assert r.status_code == 404


def test_manifest_list_requires_auth(stack):
    client, _ = stack
    assert client.get("/api/demo/mcp/manifests").status_code == 401


def test_demo_key_can_list_and_fetch_manifests(stack):
    client, demo_key = stack
    r = client.get("/api/demo/mcp/manifests", headers={"Authorization": demo_key})
    assert r.status_code == 200
    names = [m["name"] for m in r.json()["manifests"]]
    assert "benign-weather" in names
    r = client.get("/api/demo/mcp/manifests/poisoned-helper", headers={"Authorization": demo_key})
    assert r.status_code == 200
    assert r.json()["simulated"] is True
    assert r.json()["manifest"] == POISONED_MANIFEST


def test_demo_key_can_scan_pasted_manifest_and_gets_real_findings(stack):
    client, demo_key = stack
    r = client.post(
        "/api/demo/mcp/scan",
        headers={"Authorization": demo_key},
        json={"manifest": POISONED_MANIFEST},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["scanner"] == "raucle.mcp_scanner"
    assert body["count"] == len(body["findings"]) > 0
    # The findings shape is the Finding.to_dict contract of the real engine.
    f = body["findings"][0]
    for field in (
        "rule_id",
        "category",
        "severity",
        "tool",
        "field",
        "message",
        "evidence",
        "location",
    ):
        assert field in f


def test_scan_route_round_trips_the_benign_manifest(stack):
    client, demo_key = stack
    r = client.post(
        "/api/demo/mcp/scan",
        headers={"Authorization": demo_key},
        json={"manifest": BENIGN_MANIFEST},
    )
    assert r.status_code == 200
    assert r.json()["count"] == 0


def test_scan_route_rejects_missing_and_oversized_manifests(stack):
    client, demo_key = stack
    r = client.post("/api/demo/mcp/scan", headers={"Authorization": demo_key}, json={})
    assert r.status_code == 422
    big = {"tools": [{"name": "t", "description": "x" * (300 * 1024)}]}
    r = client.post(
        "/api/demo/mcp/scan",
        headers={"Authorization": demo_key},
        json={"manifest": big},
    )
    assert r.status_code == 422


def test_unknown_manifest_name_is_a_404(stack):
    client, demo_key = stack
    r = client.get("/api/demo/mcp/manifests/nope", headers={"Authorization": demo_key})
    assert r.status_code == 404


def test_demo_agents_capability_scenario_wiring():
    # D6: the generator must expose the capability scenario under 'all'.
    import scripts.demo_agents as da

    assert {"banking", "government", "health", "capability"} <= set(da.SCENARIOS)
    cap = da.SCENARIOS["capability"]
    agents = [a["agent_id"] for a in cap["agents"]]
    assert any("redaction" in a for a in agents)
    assert any("prompt" in a for a in agents)
    assert any("shadow" in a for a in agents)
    assert any("mcp" in a for a in agents)
    # Every scenario entry needs an injection pool the worker can draw from.
    for spec in da.SCENARIOS.values():
        assert spec["injections"]
        assert spec["agents"]
