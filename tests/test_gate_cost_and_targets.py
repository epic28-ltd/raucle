"""RED-036: per-call cost, export memory, SIEM target, match portability.

Four bounded fixes from the 8 Nov review:

1. Operator registries (revocations, quarantine, lease suspensions, trust
   registry, delegation ledger) were re-read and re-parsed on every gate call.
   They are append-only and unbounded, so gate cost grew with their length.
2. The receipt export buffered the whole chain in memory despite claiming to
   be bounded.
3. The SIEM URL was posted to verbatim, which is an SSRF primitive on the
   gateway host.
4. Rule matching used ``fnmatch``, which lowercases on Windows only, so one
   policy could match differently per host.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway, UserManager, siem_target_allowed
from raucle.gateway_app import create_admin_app

ADMIN_KEY = "admin-key-for-tests-0123456789"


def _policy(tmp_path):
    path = tmp_path / "policies.yaml"
    path.write_text(
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
    return path


def _config(tmp_path, **kw) -> GatewayConfig:
    return GatewayConfig(
        policy_file=str(_policy(tmp_path)),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        signer_key_path=str(tmp_path / "signer.pem"),
        agent_credentials_file=str(tmp_path / "creds.jsonl"),
        gate_auth="off",
        signer_backend="local",
        **kw,
    )


class TestRegistryCache:
    def test_revocations_are_read_once_then_invalidated(self, tmp_path, monkeypatch):
        revocations = tmp_path / "revocations.jsonl"
        revocations.write_text("")
        gateway = RaucleGateway(_config(tmp_path, revocations_file=str(revocations)))
        reads = {"n": 0}
        original = gateway._read_revoked_ids

        def counting(path):
            reads["n"] += 1
            return original(path)

        monkeypatch.setattr(gateway, "_read_revoked_ids", counting)
        assert gateway._load_revoked_ids() == set()
        assert gateway._load_revoked_ids() == set()
        assert reads["n"] == 1  # second call served from the cache

        revocations.write_text(
            json.dumps({"token_id": "cap:deadbeef", "reason": "test"}) + "\n", encoding="utf-8"
        )
        assert gateway._load_revoked_ids() == {"cap:deadbeef"}
        assert reads["n"] == 2  # a write invalidates the entry

    def test_quarantine_registry_is_cached_per_id_field(self, tmp_path):
        quarantine = tmp_path / "quarantine.jsonl"
        quarantine.write_text(json.dumps({"trace_id": "t-1", "state": "quarantined"}) + "\n")
        gateway = RaucleGateway(_config(tmp_path, trace_quarantine_file=str(quarantine)))
        first = gateway.check_tool_call(
            "pay", {"account": "ACC-001"}, agent_id="agent:bot", trace_id="t-1"
        )
        assert first["decision"] == "deny"
        assert "quarantine" in first["reason"]
        # the refusal survives a cache hit
        second = gateway.check_tool_call(
            "pay", {"account": "ACC-001"}, agent_id="agent:bot", trace_id="t-1"
        )
        assert second["decision"] == "deny"

    def test_deleted_registry_falls_back_to_absent_state(self, tmp_path):
        quarantine = tmp_path / "quarantine.jsonl"
        quarantine.write_text(json.dumps({"trace_id": "t-1", "state": "quarantined"}) + "\n")
        gateway = RaucleGateway(_config(tmp_path, trace_quarantine_file=str(quarantine)))
        gateway.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot", trace_id="t-1")
        quarantine.unlink()
        allowed = gateway.check_tool_call(
            "pay", {"account": "ACC-001"}, agent_id="agent:bot", trace_id="t-1"
        )
        assert allowed["decision"] == "allow"


class TestExportStreaming:
    @pytest.fixture
    def client(self, tmp_path):
        gateway = RaucleGateway(_config(tmp_path))
        users = UserManager()
        users.add_user(ADMIN_KEY, "admin", "Admin")
        return TestClient(create_admin_app(gateway, users)), gateway, tmp_path

    def test_export_is_a_stream_not_a_buffer(self, client):
        http, gateway, _tmp = client
        for _ in range(3):
            gateway.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot")
        resp = http.get("/api/receipts/export", headers={"Authorization": ADMIN_KEY})
        assert resp.status_code == 200
        lines = [ln for ln in resp.text.splitlines() if ln.strip()]
        assert len(lines) == 3
        for line in lines:
            assert "jws" in json.loads(line)

    def test_export_respects_the_time_window(self, client):
        http, gateway, _tmp = client
        gateway.check_tool_call("pay", {"account": "ACC-001"}, agent_id="agent:bot")
        future = 4_000_000_000
        resp = http.get(
            f"/api/receipts/export?since={future}", headers={"Authorization": ADMIN_KEY}
        )
        assert resp.status_code == 200
        assert resp.text.strip() == ""


class TestSiemTarget:
    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8088/services/collector",
            "http://10.0.0.5:8088/",
            "http://localhost:8088/",
            "file:///etc/passwd",
            "gopher://example.com/",
            "",
        ],
    )
    def test_private_and_non_http_targets_are_refused(self, url, monkeypatch):
        monkeypatch.delenv("RAUCLE_SIEM_ALLOW_PRIVATE", raising=False)
        assert siem_target_allowed(url) is False

    def test_public_https_is_allowed(self, monkeypatch):
        monkeypatch.delenv("RAUCLE_SIEM_ALLOW_PRIVATE", raising=False)
        assert siem_target_allowed("https://splunk.example.com:8088/services/collector")

    def test_private_allowed_by_explicit_opt_in(self, monkeypatch):
        monkeypatch.setenv("RAUCLE_SIEM_ALLOW_PRIVATE", "1")
        assert siem_target_allowed("http://10.0.0.5:8088/")

    def test_config_write_rejects_a_metadata_endpoint(self, tmp_path, monkeypatch):
        monkeypatch.delenv("RAUCLE_SIEM_ALLOW_PRIVATE", raising=False)
        gateway = RaucleGateway(_config(tmp_path))
        users = UserManager()
        users.add_user(ADMIN_KEY, "admin", "Admin")
        http = TestClient(create_admin_app(gateway, users))
        resp = http.put(
            "/api/siem",
            headers={"Authorization": ADMIN_KEY},
            json={"enabled": True, "backend": "splunk", "url": "http://169.254.169.254/"},
        )
        assert resp.status_code == 400


class TestRuleMatchPortability:
    def test_matching_is_case_sensitive_on_every_platform(self):
        from raucle.policy import PolicyRule

        rule = PolicyRule(tool="pay", agent_id="agent:bot", source="agent:bot")
        assert rule.matches("agent:bot", "pay") is True
        assert rule.matches("Agent:Bot", "pay") is False

    def test_wildcard_still_matches(self):
        from raucle.policy import PolicyRule

        rule = PolicyRule(tool="pay", agent_id="agent:bot", destination="*.bank.example")
        assert rule.matches("agent:bot", "api.bank.example") is True
        assert rule.matches("agent:bot", "api.other.example") is False
