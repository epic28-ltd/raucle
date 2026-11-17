"""D16: the demo session behaviour plane, read from the real machinery.

The admin panel's Session behaviour tab is backed by three demo-gated
endpoints. None of them synthesise anything: the rules view reads the
live policy configuration the gateway actually enforces, the windows
view derives per-session views from the REAL receipt index (schema v3
``session_receipts`` / ``active_session_ids`` query paths), and the
findings view reads the signed ``x_finding`` receipts the session
monitor emitted (harness ``session-monitor``), each citing the gate
receipt of the very call it cut off.

The fixture drives a scripted runaway loop through the real POST /gate
with a declared session_id - the same traffic shape the demo sidecar
generates - so every assertion lands on live gateway state.
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import create_admin_app, create_gateway_app

DEMO_POLICY = """version: 1
issuer: demo.bank
session_rules:
  - id: demo-runaway-export-loop
    kind: runaway_tool_loop
    threshold: 3
    window_seconds: 600
    tool_patterns: ["batch_report_export"]
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001"]
"""

RULE_ID = "demo-runaway-export-loop"
LOOP_TOOL = "batch_report_export"
HEALTHY_SESSION = "sess-demo-healthy-001"
LOOP_SESSION = "sess-demo-runaway-001"


@pytest.fixture
def plane(tmp_path, monkeypatch):
    """A gateway with session rules + both apps; demo mode ON."""
    monkeypatch.setenv("RAUCLE_DEMO_MODE", "1")
    policy = tmp_path / "policies.yaml"
    policy.write_text(DEMO_POLICY)
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="admin-key-0123456789abcdef",
        signer_backend="local",
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        receipt_store_dir=str(tmp_path / "segments"),
        receipt_index_path=str(tmp_path / "index.sqlite"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        emit_receipts=True,
    )
    gw = RaucleGateway(config)
    users = UserManager()
    users.add_user(config.admin_api_key, "admin", "Admin")
    gate_client = TestClient(create_gateway_app(gw))
    admin_client = TestClient(create_admin_app(gw, users))
    auth = {"Authorization": config.admin_api_key}
    return gw, gate_client, admin_client, auth


def _drive_runaway_loop(gate_client: TestClient) -> list[str]:
    """The scripted runaway-loop demo scenario: a session whose tool is
    never allowed, so calls pile up denied until the session rule cuts
    the loop. Returns the receipt id of every receipted decision."""
    receipt_ids: list[str] = []
    for _ in range(2):
        body = gate_client.post(
            "/gate",
            json={
                "tool": LOOP_TOOL,
                "args": {"batch_ref": "RPT-2026-001"},
                "agent_id": "agent:svc",
                "session_id": LOOP_SESSION,
            },
        ).json()
        assert body["decision"] == "deny", body
        # the tool policy denied it; no session rule fired yet
        assert body.get("rule_id") != RULE_ID, body
        receipt_ids.append(body["receipt_id"])
    # the third call without a receipted success trips the loop rule
    body = gate_client.post(
        "/gate",
        json={
            "tool": LOOP_TOOL,
            "args": {"batch_ref": "RPT-2026-001"},
            "agent_id": "agent:svc",
            "session_id": LOOP_SESSION,
        },
    ).json()
    assert body["decision"] == "deny", body
    assert body.get("rule_id") == RULE_ID, body
    assert "runaway_tool_loop" in body["reason"], body
    receipt_ids.append(body["receipt_id"])
    return receipt_ids


def _drive_healthy_session(gate_client: TestClient) -> str:
    body = gate_client.post(
        "/gate",
        json={
            "tool": "lookup_balance",
            "args": {"account": "ACC-001"},
            "agent_id": "agent:svc",
            "session_id": HEALTHY_SESSION,
        },
    ).json()
    assert body["decision"] == "allow", body
    return body["receipt_id"]


def _store_payloads(gw: RaucleGateway):
    for seg in gw._receipt_store.segments():  # noqa: SLF001
        with open(seg, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                part = rec["jws"].split(".")[1]
                yield (
                    rec,
                    json.loads(base64.urlsafe_b64decode(part + "=" * ((4 - len(part) % 4) % 4))),
                )


class TestSessionRulesView:
    def test_shipped_demo_policy_compiles_into_the_gateway(self, tmp_path):
        """The session-behavioural example policy the demo deployment
        loads is valid gateway config: exactly one runnable session
        rule, no config error, no tool rules leaking in."""
        from pathlib import Path

        from raucle.gateway import GatewayConfig, RaucleGateway

        policy = (
            Path(__file__).resolve().parent.parent
            / "policies"
            / "examples"
            / "session-behavioural.yaml"
        )
        assert policy.is_file(), policy
        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file=str(policy),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
        )
        gw = RaucleGateway(config)
        assert gw._session_rule_config_error == ""  # noqa: SLF001
        assert [r.id for r in gw._session_rules] == ["demo-runaway-batch-export"]  # noqa: SLF001
        assert gw._session_rules[0].kind == "runaway_tool_loop"  # noqa: SLF001

    def test_reads_the_real_policy_configuration(self, plane):
        _gw, _gate, admin, auth = plane
        resp = admin.get("/api/demo/session-rules", headers=auth)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["schema_version"] == "raucle.demo.session_rules/v1"
        assert data["config_error"] == ""
        ids = [r["id"] for r in data["session_rules"]]
        assert ids == [RULE_ID]
        rule = data["session_rules"][0]
        assert rule["kind"] == "runaway_tool_loop"
        assert rule["threshold"] == 3
        assert rule["window_seconds"] == 600
        # the window bounds are the live gateway configuration
        assert data["window"]["ttl_seconds"] == 900
        assert data["window"]["max_keys"] == 1024
        assert data["window"]["max_entries"] == 10000
        # v1 honesty: deny-only, with the documented limits stated
        assert data["deny_only"] is True
        joined = " ".join(data["limits"])
        assert "deny-only" in joined
        assert "process memory" in joined
        assert "gradual_extraction" in joined

    def test_config_error_is_disclosed_not_hidden(self, plane, tmp_path):
        gw, _gate, _admin, _auth = plane
        bad = tmp_path / "policies.yaml"
        bad.write_text(DEMO_POLICY.replace("kind: runaway_tool_loop", "kind: no_such_kind"))
        gw.config.policy_file = str(bad)
        gw._load_policies()  # noqa: SLF001
        assert gw._session_rule_config_error  # noqa: SLF001

    def test_off_demo_answers_404(self, plane, monkeypatch):
        _gw, _gate, admin, auth = plane
        monkeypatch.delenv("RAUCLE_DEMO_MODE")
        for path in (
            "/api/demo/session-rules",
            "/api/demo/session-windows",
            "/api/demo/session-findings",
        ):
            assert admin.get(path, headers=auth).status_code == 404, path


class TestSessionWindowsView:
    def test_derives_from_the_real_receipt_index(self, plane):
        gw, gate, admin, auth = plane
        _drive_runaway_loop(gate)
        healthy = _drive_healthy_session(gate)
        resp = admin.get("/api/demo/session-windows", headers=auth)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["schema_version"] == "raucle.demo.session_windows/v1"
        assert data["index_schema_version"] == 3
        assert data["available"] is True
        sessions = {s["session_id"]: s for s in data["sessions"]}
        assert LOOP_SESSION in sessions, data["sessions"]
        loop = sessions[LOOP_SESSION]
        assert loop["receipts"] == 3
        assert loop["denies"] == 3
        assert loop["allows"] == 0
        assert "agent:svc" in loop["agents"]
        # recent rows carry real receipt hashes from the index
        recent_hashes = {row["receipt_hash"] for row in loop["recent"]}
        assert len(recent_hashes) == 3
        assert healthy  # the healthy session is in the index too
        assert sessions[HEALTHY_SESSION]["allows"] == 1

    def test_events_ride_the_session_rows(self, plane):
        _gw, gate, admin, auth = plane
        _drive_runaway_loop(gate)
        data = admin.get("/api/demo/session-windows", headers=auth).json()
        loop = next(s for s in data["sessions"] if s["session_id"] == LOOP_SESSION)
        decisions = [row["decision"] for row in loop["recent"]]
        assert decisions == ["deny", "deny", "deny"]
        tools = {row["tool"] for row in loop["recent"]}
        assert tools == {LOOP_TOOL}

    def test_no_index_answers_unavailable_never_fabricated(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAUCLE_DEMO_MODE", "1")
        policy = tmp_path / "policies.yaml"
        policy.write_text(DEMO_POLICY)
        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="admin-key-0123456789abcdef",
            signer_backend="local",
            policy_file=str(policy),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            emit_receipts=True,
        )
        gw = RaucleGateway(config)
        users = UserManager()
        users.add_user(config.admin_api_key, "admin", "Admin")
        admin = TestClient(create_admin_app(gw, users))
        resp = admin.get(
            "/api/demo/session-windows", headers={"Authorization": config.admin_api_key}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["available"] is False
        assert data["sessions"] == []
        assert "unavailable" in data["unavailable_note"].lower()


class TestSessionFindingsView:
    def test_findings_cite_the_real_gate_receipt(self, plane):
        gw, gate, admin, auth = plane
        receipt_ids = _drive_runaway_loop(gate)
        resp = admin.get("/api/demo/session-findings", headers=auth)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["schema_version"] == "raucle.demo.session_findings/v1"
        assert data["harness"] == "session-monitor"
        findings = data["findings"]
        assert findings, "the runaway loop must leave a session-monitor finding"
        finding = findings[0]
        assert finding["test_id"] == RULE_ID
        assert finding["verdict"] == "confirmed"
        assert finding["cited_receipt"] in receipt_ids
        assert finding["expected_decision"] == "deny"
        assert finding["actual_decision"] == "deny"
        assert finding["tool"] == LOOP_TOOL
        # the finding is itself a receipted, offline-verifiable artefact
        assert finding["receipt_hash"]

    def test_finding_receipt_verifies_offline_through_the_panel_endpoint(self, plane):
        _gw, gate, admin, auth = plane
        _drive_runaway_loop(gate)
        data = admin.get("/api/demo/session-findings", headers=auth).json()
        finding_hash = data["findings"][0]["receipt_hash"]
        # the finding verifies offline WITH its cited gate receipt: the
        # minimal honest chain (cited + finding) lets the verifier run
        # the anti-fabrication citation check instead of skipping it
        resp = admin.post(f"/api/demo/session-findings/{finding_hash}/offline-verify", headers=auth)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["verdict"] == "valid"
        assert body["cited_receipt"] == data["findings"][0]["cited_receipt"]
        assert body["receipt_count"] == 2
        assert "offline" in body["offline"].lower()

    def test_non_finding_receipt_is_refused_with_a_named_reason(self, plane):
        _gw, gate, admin, auth = plane
        receipt_ids = _drive_runaway_loop(gate)
        cited = admin.get("/api/demo/session-findings", headers=auth).json()["findings"][0]
        # the CITED gate receipt is a real receipt but not a finding
        resp = admin.post(
            f"/api/demo/session-findings/{cited['cited_receipt']}/offline-verify",
            headers=auth,
        )
        assert resp.status_code == 400
        assert "session-monitor" in resp.json()["detail"]
        # unknown hashes 404, never verify
        resp = admin.post("/api/demo/session-findings/sha256:deadbeef/offline-verify", headers=auth)
        assert resp.status_code == 404
        assert receipt_ids

    def test_findings_newest_first_and_bounded(self, plane):
        _gw, gate, admin, auth = plane
        _drive_runaway_loop(gate)
        # the window still holds the denies, so two further calls of the
        # same tool trip the rule again: more findings accumulate
        for _ in range(2):
            body = gate.post(
                "/gate",
                json={
                    "tool": LOOP_TOOL,
                    "args": {"batch_ref": "RPT-2026-001"},
                    "agent_id": "agent:svc",
                    "session_id": LOOP_SESSION,
                },
            ).json()
            assert body.get("rule_id") == RULE_ID, body
        data = admin.get("/api/demo/session-findings", headers=auth).json()
        assert data["count"] == 3
        iats = [f["detected_at"] for f in data["findings"]]
        assert iats == sorted(iats, reverse=True)
        assert len(data["findings"]) <= 50

    def test_store_payloads_agree_with_the_view(self, plane):
        gw, gate, admin, auth = plane
        _drive_runaway_loop(gate)
        data = admin.get("/api/demo/session-findings", headers=auth).json()
        in_store = [
            payload["x_finding"]
            for _rec, payload in _store_payloads(gw)
            if payload.get("x_finding", {}).get("harness") == "session-monitor"
        ]
        assert in_store, "the finding must exist as a signed receipt in the chain"
        assert data["count"] == len(in_store)
        assert {f["finding_id"] for f in data["findings"]} == {f["finding_id"] for f in in_store}
