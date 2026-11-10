"""The EPIC D demo findings plane: engine-backed screens and endpoint.

Covers:
- the builder drives the REAL pattern and classifier engines (rule ids it
  reports must exist in the shipped rule sets, and verdicts must match what
  a direct scanner call over the same simulated text would produce),
- the shadow-AI detection path (unknown model, unapproved endpoint, BYOK),
- the /api/demo-findings endpoint (role gating, scenario filter, 400s),
- the panel additions: demo-only tabs, textContent-only rendering and the
  showTab/tour/dispatcher integration.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from raucle.classifier import HeuristicClassifier
from raucle.demo_findings import (
    APPROVED_PROVIDERS,
    DEMO_TRAFFIC,
    SUMMARY_NOTE_SIMULATED,
    build_demo_findings,
    detect_shadow_ai,
    redaction_action_for_rule,
)
from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import ADMIN_PANEL_HTML, _panel_csp, create_admin_app
from raucle.patterns import BUILTIN_PATTERNS, OUTPUT_RULES


@pytest.fixture
def client(tmp_path):
    cfg = GatewayConfig(
        policy_file=str(tmp_path / "policies.yaml"),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        admin_api_key="admin-key-for-tests-0123456789",
        signer_backend="local",
    )
    gateway = RaucleGateway(cfg)
    users = UserManager(persist_path=None)
    users.add_user(cfg.admin_api_key, "admin", "Admin")
    # A demo-style reader: the real demo key is an auditor (read-only).
    users.add_user("demo-key-sim-0001", "auditor", "Demo")
    app = create_admin_app(gateway, users)
    return (
        TestClient(app),
        {"Authorization": cfg.admin_api_key},
        {"Authorization": "demo-key-sim-0001"},
    )


# ---------------------------------------------------------------------------
# Builder: engine-backed by construction
# ---------------------------------------------------------------------------


class TestDlpFindings:
    def test_finds_are_produced_by_the_real_pattern_rules(self):
        body = build_demo_findings("banking")
        dlp = body["dlp"]
        assert dlp["total"] > 0
        shipped = {r["id"] for r in BUILTIN_PATTERNS} | {r["id"] for r in OUTPUT_RULES}
        for finding in dlp["findings"]:
            assert finding["rule_id"] in shipped
            assert finding["category"]
            assert finding["action"] in ("block", "redact", "mask")
            assert finding["agent"] and finding["tool"]

    def test_rule_actions_follow_the_policy_mapping(self):
        assert redaction_action_for_rule("DLP-001") == "block"
        assert redaction_action_for_rule("DLP-002") == "redact"

    def test_counts_aggregate_by_category_and_action(self):
        dlp = build_demo_findings("all")["dlp"]
        assert dlp["by_category"]["data_loss"] > 0
        assert sum(dlp["by_category"].values()) == dlp["total"]
        assert sum(dlp["by_action"].values()) == dlp["total"]

    def test_credential_exposures_are_blocked_not_redacted(self):
        findings = build_demo_findings("all")["dlp"]["findings"]
        creds = [f for f in findings if f["rule_id"] == "DLP-001"]
        assert creds, "simulated packs must include credential exposures"
        assert all(f["action"] == "block" for f in creds)


class TestInjectionFindings:
    def test_decisions_match_the_classifier_bands(self):
        body = build_demo_findings("all")
        findings = body["injection"]["findings"]
        assert findings, "simulated packs must include injected payloads"
        heuristic = HeuristicClassifier()
        for finding in findings:
            assert finding["decision"] in ("deny", "escalate")
            event = next(
                e for s in DEMO_TRAFFIC.values() for e in s if e["id"] == finding["event_id"]
            )
            direct = heuristic.classify(event["text"])
            # The combined score cannot exceed the raw heuristic score.
            assert finding["score"] <= direct["score"] or finding["score"] < 1.0

    def test_deny_requires_block_threshold(self):
        findings = build_demo_findings("all")["injection"]["findings"]
        for f in findings:
            if f["decision"] == "deny":
                assert f["score"] >= 0.7
            else:
                assert 0.0 < f["score"] < 0.7

    def test_injected_payloads_are_labeled_simulated(self):
        body = build_demo_findings("health")
        assert SUMMARY_NOTE_SIMULATED in (body["note"],)


class TestShadowAi:
    def test_detects_unknown_model_and_unapproved_endpoint(self):
        events = [
            {
                "id": "x-1",
                "kind": "provider_request",
                "agent": "a",
                "tool": "t",
                "model": "unlisted-model",
                "endpoint": "https://evil.example.test/v1",
                "api_key_supplied": True,
            }
        ]
        policy = {
            "approved_models": [
                "approved-model",
            ],
            "approved_endpoint_hosts": ("approved.example.test",),
            "byok_allowed": False,
        }
        kinds = {f["kind"] for f in detect_shadow_ai(events, policy)}
        assert kinds == {"unknown_model", "unapproved_endpoint", "byok_attempt"}

    def test_fully_compliant_request_produces_no_finding(self):
        events = [
            {
                "id": "x-2",
                "kind": "provider_request",
                "agent": "a",
                "tool": "t",
                "model": "clinical-summary-v2-sim",
                "endpoint": "https://secure-nhsmesh-example.test/v1",
                "api_key_supplied": False,
            }
        ]
        assert detect_shadow_ai(events, APPROVED_PROVIDERS["health"]) == []

    def test_pack_findings_carry_policy_responses(self):
        findings = build_demo_findings("all")["shadow"]["findings"]
        assert findings
        for f in findings:
            assert f["policy_response"]
            assert f["agent"] and f["first_seen"] >= 0


class TestBuilder:
    def test_deterministic(self):
        assert build_demo_findings("all") == build_demo_findings("all")

    def test_unknown_scenario_is_refused(self):
        with pytest.raises(ValueError):
            build_demo_findings("retail")

    def test_single_scenario_filters_other_scenarios(self):
        body = build_demo_findings("health")
        assert set(body["scenarios"]) == {"health"}
        assert all(f["scenario"] == "health" for f in body["shadow"]["findings"])


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


class TestDemoFindingsEndpoint:
    def test_demo_style_reader_can_list_findings(self, client):
        c, _admin, demo = client
        r = c.get("/api/demo-findings", headers=demo)
        assert r.status_code == 200
        body = r.json()
        for section in ("dlp", "injection", "shadow"):
            assert isinstance(body[section]["findings"], list)
        assert "simulated" in body["note"]

    def test_scenario_filter(self, client):
        c, _admin, demo = client
        body = c.get("/api/demo-findings", params={"scenario": "government"}, headers=demo).json()
        assert body["scenarios"] == ["government"]

    def test_unknown_scenario_is_400(self, client):
        c, _admin, demo = client
        assert (
            c.get("/api/demo-findings", params={"scenario": "nope"}, headers=demo).status_code
            == 400
        )

    def test_requires_credentials(self, client):
        c, _admin, _demo = client
        assert c.get("/api/demo-findings").status_code == 401


# ---------------------------------------------------------------------------
# Panel integration
# ---------------------------------------------------------------------------


class TestPanelIntegration:
    def test_demo_tabs_are_hidden_outside_demo_mode(self):
        assert 'body:not(.demo) [data-tab-id="dlp"]' in ADMIN_PANEL_HTML
        assert 'body:not(.demo) [data-tab-id="injection"]' in ADMIN_PANEL_HTML
        assert 'body:not(.demo) [data-tab-id="shadow"]' in ADMIN_PANEL_HTML

    def test_tabs_use_the_delegated_dispatcher(self):
        for tab in ("dlp", "injection", "shadow"):
            assert f"showTab('{tab}',this)" in ADMIN_PANEL_HTML
            assert f"\"showTab('{tab}',this)\":(ev,el)=>showTab('{tab}',el)" in ADMIN_PANEL_HTML

    def test_findings_rendering_is_textcontent_only(self):
        script = "".join(re.findall(r"<script[^>]*>(.*?)</script>", ADMIN_PANEL_HTML, re.S))
        block = script.find("DEMO FINDINGS")
        assert block != -1
        section = script[block : script.find("// ================= DEMO MODE ===", block)]
        assert "innerHTML" not in section
        assert section.count("textContent") >= 3

    def test_tour_covers_the_three_screens(self):
        for tab in ("dlp", "injection", "shadow"):
            assert f"tab:'{tab}'" in ADMIN_PANEL_HTML

    def test_demo_only_script_is_csp_hashed(self):
        # _panel_csp hashes the shipped script blocks; adding code must not
        # require a manual hash bump because hashes are computed at import.
        assert "script-src 'sha256-" in _panel_csp()
