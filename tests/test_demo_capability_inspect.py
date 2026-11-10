"""EPIC E demo plane items E1 and E2: capability-token inspection and the
post-quantum receipts badge.

Covers:
- the demo capability inspector backed by the REAL raucle.capability
  machinery: the endpoints return token envelopes minted live by the
  gateway's own CapabilityIssuer (issuer, agent binding, tool scope,
  constraints, expiry, signature presence), attenuation chains rendered
  parent-to-child, and verify verdicts that come from
  ``CapabilityGate.check`` - allow, deny and the fail-closed tamper probe
  are the gate's actual decisions,
- demo-mode gating (404 outside demo mode) and the read-only shape,
- E2: the receipts surface - each row's signing family read from its own
  signed JWS bytes (classical Ed25519 vs pq1 hybrid), the key-family card
  endpoint driven by the live signer configuration, and the per-row PQ
  hybrid badge drawn only from confirmed signing material.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

import raucle.pq as _pq_mod
from raucle.demo_capabilities import (
    DEMO_CAPABILITY_CALLS,
    VERIFY_NOTE,
    build_demo_chain,
    verify_demo_call,
)
from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import ADMIN_PANEL_HTML, create_admin_app
from raucle.provenance import AgentIdentity, ProvenanceLogger

COMPLIANCE_WORDS = ("compliant", "compliance", "certif", "soc 2", "iso 27001", "gdpr")


@pytest.fixture
def client(tmp_path, monkeypatch):
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
    users.add_user("demo-key-sim-0001", "auditor", "Demo")
    app = create_admin_app(gateway, users)
    return (
        TestClient(app),
        gateway,
        {"Authorization": cfg.admin_api_key},
        {"Authorization": "demo-key-sim-0001"},
    )


# ---------------------------------------------------------------------------
# E1: engine-backed by construction
# ---------------------------------------------------------------------------


class TestRealMachinery:
    def test_chain_is_minted_by_the_real_issuer(self, client):
        _, gateway, _, _ = client
        issuer = gateway._issuer
        call = DEMO_CAPABILITY_CALLS[0]
        tokens = build_demo_chain(issuer, call)
        assert len(tokens) == 2
        parent, child = tokens
        assert parent.parent_id is None
        assert child.parent_id == parent.token_id
        assert child.tool == parent.tool  # tool scope never broadens
        assert child.expires_at <= parent.expires_at  # expiry never extends
        assert child.agent_id != parent.agent_id  # agent binding narrowed
        for token in tokens:
            assert token.signature, "every minted token is signed"

    def test_narrowed_constraints_appear_on_the_child(self, client):
        _, gateway, _, _ = client
        from raucle.demo_capabilities import chain_view

        view = chain_view(build_demo_chain(gateway._issuer, DEMO_CAPABILITY_CALLS[0]))
        child = view[1]
        assert child["role"] == "attenuated-1"
        assert child["narrowed"]
        joined = " | ".join(child["narrowed"])
        assert "agent binding narrowed" in joined
        assert "constraints narrowed [max_value]" in joined

    def test_overstep_call_is_denied_by_the_real_gate(self, client):
        _, gateway, _, _ = client
        report = verify_demo_call(gateway._issuer, DEMO_CAPABILITY_CALLS[1])
        assert report["decision"]["verdict"] == "deny"
        assert "amount" in report["decision"]["reason"] or report["decision"]["attributable"]

    def test_tamper_probe_fails_closed(self, client):
        _, gateway, _, _ = client
        for call in DEMO_CAPABILITY_CALLS:
            report = verify_demo_call(gateway._issuer, call)
            probe = report["tamper_probe"]
            assert probe["verdict"] == "deny"
            assert probe["simulated_tamper"] is True

    def test_within_bounds_call_verifies(self, client):
        _, gateway, _, _ = client
        report = verify_demo_call(gateway._issuer, DEMO_CAPABILITY_CALLS[0])
        assert report["decision"]["verdict"] == "allow"
        assert report["decision"]["token_id"] == report["chain"][-1]


# ---------------------------------------------------------------------------
# E1: endpoints
# ---------------------------------------------------------------------------


class TestDemoCapabilityEndpoints:
    def test_demo_reader_can_list_the_chains(self, client):
        c, _, _, demo = client
        r = c.get("/api/demo/capabilities", headers=demo)
        assert r.status_code == 200
        body = r.json()
        assert body["simulated"] is True
        assert "simulated" in body["note"].lower()
        for call in body["calls"]:
            assert call["chain"][0]["parent_id"] is None
            for token in call["chain"]:
                assert token["signature_present"] is True
                assert token["issuer"]
                assert token["expires_at"] > token["issued_at"]

    def test_verify_endpoint_returns_the_real_decision(self, client):
        c, _, _, demo = client
        r = c.post("/api/demo/capabilities/cap-refund-banking/verify", headers=demo)
        assert r.status_code == 200
        body = r.json()
        assert body["decision"]["verdict"] == "allow"
        assert body["tamper_probe"]["verdict"] == "deny"
        assert "simulated" in body["note"].lower()
        assert body["note"] == VERIFY_NOTE

    def test_unknown_call_is_404(self, client):
        c, _, _, demo = client
        assert c.post("/api/demo/capabilities/cap-nope/verify", headers=demo).status_code == 404

    def test_requires_credentials(self, client):
        c, _, _, _ = client
        assert c.get("/api/demo/capabilities").status_code == 401
        assert c.post("/api/demo/capabilities/cap-refund-banking/verify").status_code == 401

    def test_off_demo_mode_the_routes_answer_404(self, client, monkeypatch):
        c, _, _, demo = client
        monkeypatch.delenv("RAUCLE_DEMO_MODE", raising=False)
        assert c.get("/api/demo/capabilities", headers=demo).status_code == 404
        assert (
            c.post("/api/demo/capabilities/cap-refund-banking/verify", headers=demo).status_code
            == 404
        )


# ---------------------------------------------------------------------------
# E2: receipt signing families from the receipt's own signed bytes
# ---------------------------------------------------------------------------


class TestSigningFamilies:
    def test_classical_emissions_read_as_classical(self, client):
        c, gateway, admin, _ = client
        receipt_hash = None
        for _ in range(10):
            receipt_hash = gateway._emit_authority_receipt(
                verdict="allow", extension_key="x_admission", extension={"reason": "demo"}
            )
            if receipt_hash:
                break
        assert receipt_hash, "gate receipts must be emitted outside fault drills"
        rows = c.get("/api/receipts", headers=admin).json()["receipts"]
        row = next(r for r in rows if r["receipt_hash"] == receipt_hash)
        assert row["signing_family"] == "classical-ed25519"

    def test_pq1_hybrid_rows_carry_the_hybrid_family(self, client, tmp_path):
        if not _pq_mod.pq_available():
            pytest.skip("ML-DSA-65 unavailable in this build")
        c, gateway, admin, _ = client
        store = tmp_path / "store.jsonl"
        identity = AgentIdentity.generate(agent_id="agent:pq-badge-demo")
        logger = ProvenanceLogger(agent=identity, sink_path=str(store), quantum_mode="strict")
        logger.record_user_input(text="simulated hybrid receipt")
        logger.close()
        lines = [json.loads(ln) for ln in store.read_text().splitlines() if ln.strip()]
        assert all(len(rec["jws"].split(".")) == 4 for rec in lines)
        with open(gateway.config.receipt_store, "a", encoding="utf-8") as fh:
            for rec in lines:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        rows = c.get("/api/receipts", headers=admin).json()["receipts"]
        families = {r["signing_family"] for r in rows}
        assert "pq1-hybrid" in families
        # every family is a confirmed real family: no row invents one
        assert families <= {"classical-ed25519", "pq1-hybrid"}

    def test_unconfirmable_material_carries_no_family(self, client):
        c, gateway, admin, _ = client
        receipt_hash = None
        for _ in range(10):
            receipt_hash = gateway._emit_authority_receipt(
                verdict="allow", extension_key="x_admission", extension={"reason": "demo"}
            )
            if receipt_hash:
                break
        assert receipt_hash
        from raucle.gateway_app import _envelope_signing_family

        assert _envelope_signing_family("not-a-jws") is None
        assert _envelope_signing_family("") is None
        rows = c.get("/api/receipts", headers=admin).json()["receipts"]
        row = next(r for r in rows if r["receipt_hash"] == receipt_hash)
        assert row["signing_family"] == "classical-ed25519"

    def test_key_family_endpoint_reflects_live_config(self, client):
        c, gateway, admin, _ = client
        r = c.get("/api/receipts/key-family", headers=admin)
        assert r.status_code == 200
        body = r.json()
        assert body["signer_backend"] == gateway.config.signer_backend
        assert body["key_id"] == gateway.gate_identity.key_id
        assert body["issuer_key_type"].endswith("Ed25519PublicKey")
        assert isinstance(body["pq_available"], bool)
        observed = body["observed_families"]
        assert observed["classical-ed25519"] >= 0

    def test_key_family_requires_credentials(self, client):
        c, _, _, _ = client
        assert c.get("/api/receipts/key-family").status_code == 401


# ---------------------------------------------------------------------------
# Panel integration
# ---------------------------------------------------------------------------


class TestPanelCapabilityInspector:
    def test_tab_is_demo_only_and_dispatched(self):
        assert 'data-tab-id="capdemo"' in ADMIN_PANEL_HTML
        assert 'body:not(.demo) [data-tab-id="capdemo"]' in ADMIN_PANEL_HTML
        entry = "\"showTab('capdemo',this)\":(ev,el)=>showTab('capdemo',el)"
        assert ADMIN_PANEL_HTML.count(entry) == 1

    def test_screen_labels_simulated_without_compliance_words(self):
        idx = ADMIN_PANEL_HTML.index('id="tab-capdemo"')
        region = ADMIN_PANEL_HTML[idx : idx + 1600]
        assert "Simulated capability chains" in region
        assert "real capability gate" in region
        low = region.lower()
        for word in COMPLIANCE_WORDS:
            assert word not in low, word

    def test_rendering_is_textcontent_only(self):
        view = ADMIN_PANEL_HTML.index("function capDemoLoad()")
        fn = ADMIN_PANEL_HTML[view : ADMIN_PANEL_HTML.index("function loadSIEM()")]
        assert "capEnvelopeView" in fn
        assert "innerHTML" not in fn
        assert fn.count("textContent") >= 3

    def test_verify_action_is_wired_through_the_shared_map(self):
        assert "b.setAttribute('data-hi','capDemoPick(event)')" in ADMIN_PANEL_HTML
        assert ADMIN_PANEL_HTML.count('"capDemoPick(event)":(ev,el)=>capDemoPick(ev)') == 1
        assert ADMIN_PANEL_HTML.count('"capDemoVerify()":(ev,el)=>capDemoVerify()') == 1
        assert ADMIN_PANEL_HTML.count('data-hi="capDemoVerify()"') == 1

    def test_tour_covers_the_inspector(self):
        assert "tab:'capdemo'" in ADMIN_PANEL_HTML


class TestPanelPqBadgeAndKeyFamily:
    def test_badge_is_conditional_on_the_family(self):
        marker = "r.signing_family==='pq1-hybrid'"
        assert marker in ADMIN_PANEL_HTML
        assert "PQ hybrid</span>" in ADMIN_PANEL_HTML

    def test_key_family_card_present_and_labelled(self):
        assert 'id="rcpt-keyfamily"' in ADMIN_PANEL_HTML
        assert 'id="keyFamilyView"' in ADMIN_PANEL_HTML
        idx = ADMIN_PANEL_HTML.index('id="rcpt-keyfamily"')
        region = ADMIN_PANEL_HTML[idx : idx + 900]
        assert "Real signing configuration" in region
        assert "signed header, never a fixed label" in region

    def test_key_family_loader_is_textcontent_only_and_wired(self):
        idx = ADMIN_PANEL_HTML.index("function loadKeyFamily()")
        fn = ADMIN_PANEL_HTML[idx : ADMIN_PANEL_HTML.index("function loadSIEM()")]
        assert "innerHTML" not in fn
        assert fn.count("textContent") >= 2
        assert "if(t==='receipts'){loadReceipts();loadKeyFamily();}" in ADMIN_PANEL_HTML

    def test_no_compliance_claims_on_the_receipts_additions(self):
        idx = ADMIN_PANEL_HTML.index('id="rcpt-keyfamily"')
        region = ADMIN_PANEL_HTML[idx : idx + 1200]
        low = region.lower()
        for word in COMPLIANCE_WORDS:
            assert word not in low, word
