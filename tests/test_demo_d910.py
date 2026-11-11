"""The D9/D10 demo planes: read-only operator screens over real machinery.

Covers:
- D9 builder: the containment story is produced by the REAL containment
  machinery (verdict sequence, M-of-N quorum, receipts decode), labelled
  simulated;
- D9 endpoint: demo-mode gate, role gating, unauthenticated 401;
- D10 builder: preset sim runs through the REAL simulate path, the
  outcome is deterministic and the receipt is the real signed output;
- D10 endpoint: presets + run, unknown preset 400, no apply route;
- panel: demo-only tab wiring, dispatcher entries, textContent-only
  rendering, tour steps.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from raucle.demo_policy_sim import demo_presets, run_demo_policy_sim
from raucle.demo_stop import build_demo_stop
from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import ADMIN_PANEL_HTML, create_admin_app


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("RAUCLE_DEMO_MODE", "1")
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
    # the real demo key is an auditor (read-only)
    users.add_user("demo-key-sim-0001", "auditor", "Demo")
    app = create_admin_app(gateway, users)
    return (
        TestClient(app),
        {"Authorization": cfg.admin_api_key},
        {"Authorization": "demo-key-sim-0001"},
    )


# ---------------------------------------------------------------------------
# D9: emergency authority stop demo surface
# ---------------------------------------------------------------------------


class TestDemoStopBuilder:
    def test_tells_the_whole_operator_story_with_real_receipts(self):
        body = build_demo_stop()
        assert body["simulated"] is True
        assert "simulated" in body["note"].lower()
        assert list(body["scopes"]) == ["global", "agent", "chain"]
        assert body["quorum"]["global"] == 2
        assert body["button_default"]["armed"] is False
        verdicts = [r["verdict"] for r in body["receipts"]]
        assert verdicts == [
            "containment_button_arm",
            "containment_button_disarm",
            "containment_hold_pending",
            "containment_hold_approval",
            "containment_hold_approval",
            "containment_hold",
            "containment_resume",
        ]

    def test_quorum_receipts_carry_two_distinct_approvers(self):
        body = build_demo_stop()
        holds = [r for r in body["receipts"] if r["verdict"] == "containment_hold"]
        assert len(holds) == 1
        assert holds[0]["approvers"] == ["demo-approver-1", "demo-approver-2"]
        assert holds[0]["min_approvers"] == 2
        approvals = [r for r in body["receipts"] if r["verdict"].endswith("_approval")]
        assert len(approvals) == 2

    def test_every_receipt_carries_an_id_and_the_story_steps(self):
        body = build_demo_stop()
        assert len(body["story"]) == 7
        assert all(r["receipt_id"] for r in body["receipts"])
        steps = [s["step"] for s in body["story"]]
        assert "Arm" in steps and "Resume" in steps

    def test_no_write_targets_leak_outside_the_sandbox(self):
        body = build_demo_stop()
        assert "raucle-demo-stop-" not in repr(body)


class TestDemoStopEndpoint:
    def test_demo_reader_can_read_the_story(self, client):
        c, _admin, demo = client
        r = c.get("/api/demo/stop", headers=demo)
        assert r.status_code == 200
        body = r.json()
        assert body["simulated"] is True
        assert body["receipt_count"] == 7

    def test_requires_credentials(self, client):
        c, _admin, _demo = client
        assert c.get("/api/demo/stop").status_code == 401

    def test_refuses_without_demo_mode(self, monkeypatch, tmp_path):
        monkeypatch.delenv("RAUCLE_DEMO_MODE", raising=False)
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
        c = TestClient(create_admin_app(gateway, users))
        assert (
            c.get("/api/demo/stop", headers={"Authorization": cfg.admin_api_key}).status_code == 404
        )


# ---------------------------------------------------------------------------
# D10: policy-simulate showpiece
# ---------------------------------------------------------------------------


class TestDemoSimBuilder:
    def test_three_presets_listed_with_labels(self):
        names = {p["name"] for p in demo_presets()}
        assert names == {"narrow-export", "block-export", "no-change"}
        assert all(p["label"] and p["description"] for p in demo_presets())

    def test_narrowing_moves_a_call_to_deny(self):
        body = run_demo_policy_sim("narrow-export")
        o = body["outcome"]
        assert o["current"]["allow"] == 2
        assert o["candidate"]["deny"] == 1
        assert len(o["changed_decisions"]) == 1
        assert o["changed_decisions"][0]["current_decision"] == "allow"
        assert o["changed_decisions"][0]["candidate_decision"] == "deny"

    def test_removing_the_rule_is_the_fail_closed_story(self):
        body = run_demo_policy_sim("block-export")
        o = body["outcome"]
        assert o["candidate"]["deny"] == 2
        assert len(o["changed_decisions"]) == 2

    def test_no_change_preset_is_honest_about_it(self):
        body = run_demo_policy_sim("no-change")
        o = body["outcome"]
        assert o["candidate"] == o["current"]
        assert len(o["changed_decisions"]) == 0

    def test_signed_receipt_is_the_real_deterministic_output(self):
        body = run_demo_policy_sim("narrow-export")
        jws = body["jws"]
        parts = jws.split(".")
        assert len(parts) == 3
        assert parts[0].startswith("eyJ")
        import hashlib

        assert body["receipt_hash"] == "sha256:" + hashlib.sha256(jws.encode("ascii")).hexdigest()
        assert body["simulated_input"] is True
        assert "simulated" in body["note"].lower()

    def test_deterministic_within_the_demo_session(self):
        first = run_demo_policy_sim("narrow-export")["jws"]
        second = run_demo_policy_sim("narrow-export")["jws"]
        assert first == second

    def test_unknown_preset_refused_named(self):
        with pytest.raises(ValueError, match="unknown demo preset"):
            run_demo_policy_sim("nope")


class TestDemoSimEndpoint:
    def test_demo_reader_can_list_presets(self, client):
        c, _admin, demo = client
        r = c.get("/api/demo/policy-simulate/presets", headers=demo)
        assert r.status_code == 200
        assert {p["name"] for p in r.json()["presets"]} == {
            "narrow-export",
            "block-export",
            "no-change",
        }

    def test_demo_reader_can_run_the_real_simulate_path(self, client):
        c, _admin, demo = client
        r = c.post(
            "/api/demo/policy-simulate",
            json={"preset": "narrow-export"},
            headers=demo,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["jws"].count(".") == 2
        assert body["simulated_input"] is True

    def test_unknown_preset_is_400(self, client):
        c, _admin, demo = client
        r = c.post("/api/demo/policy-simulate", json={"preset": "nope"}, headers=demo)
        assert r.status_code == 400

    def test_requires_credentials(self, client):
        c, _admin, _demo = client
        assert (
            c.post("/api/demo/policy-simulate", json={"preset": "narrow-export"}).status_code == 401
        )

    def test_refuses_without_demo_mode(self, monkeypatch, tmp_path):
        monkeypatch.delenv("RAUCLE_DEMO_MODE", raising=False)
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
        c = TestClient(create_admin_app(gateway, users))
        r = c.post(
            "/api/demo/policy-simulate",
            json={"preset": "narrow-export"},
            headers={"Authorization": cfg.admin_api_key},
        )
        assert r.status_code == 404

    def test_no_apply_route_on_the_demo_plane(self, client):
        c, _admin, demo = client
        r = c.post("/api/demo/policy-simulate/apply", json={}, headers=demo)
        assert r.status_code == 404  # demo visitors never get a flip path


# ---------------------------------------------------------------------------
# Panel integration
# ---------------------------------------------------------------------------


class TestPanelIntegration:
    def test_stop_tab_and_sim_card_hidden_outside_demo_mode(self):
        assert 'body:not(.demo) [data-tab-id="stop"]' in ADMIN_PANEL_HTML
        assert "body:not(.demo) #simDemoCard" in ADMIN_PANEL_HTML

    def test_editor_card_hidden_inside_demo_mode(self):
        # the real editor and its Save & Deploy stay on the operator plane
        assert "body.demo #policyEditorCard{display:none}" in ADMIN_PANEL_HTML

    def test_stop_tab_uses_the_delegated_dispatcher(self):
        assert "data-hi=\"showTab('stop',this)\"" in ADMIN_PANEL_HTML
        assert "\"showTab('stop',this)\":(ev,el)=>showTab('stop',el)" in ADMIN_PANEL_HTML

    def test_sim_controls_have_dispatcher_entries(self):
        # the run button is static HTML; the preset chips gain data-hi in JS
        assert 'data-hi="simRun()"' in ADMIN_PANEL_HTML
        assert "chip.setAttribute('data-hi','simPick(event)')" in ADMIN_PANEL_HTML
        for hi in ("simRun()", "simPick(event)"):
            assert f'"{hi}":(ev,el)=>' in ADMIN_PANEL_HTML

    def test_new_rendering_is_textcontent_only(self):
        script = "".join(re.findall(r"<script[^>]*>(.*?)</script>", ADMIN_PANEL_HTML, re.S))
        stop_start = script.find("// ================= EMERGENCY AUTHORITY STOP SCREEN")
        sim_start = script.find("// ================= POLICY SIMULATE SHOWPIECE")
        mcp_start = script.find("// ================= MCP SCANNER (D5)")
        stop_block = script[stop_start:mcp_start]
        sim_block = script[sim_start:stop_start]
        for block in (stop_block, sim_block):
            assert "innerHTML" not in block

    def test_simulation_never_touches_the_apply_path_in_js(self):
        assert "policy-simulate/apply" not in ADMIN_PANEL_HTML

    def test_tour_covers_both_new_screens(self) -> None:
        # G7 re-arc: the simulated policy tweak stays in the tour; the stop
        # screen is demo-visible but no longer a tour step.
        assert "target:'#simDemoCard'" in ADMIN_PANEL_HTML
        assert 'data-tab-id="stop"' in ADMIN_PANEL_HTML
