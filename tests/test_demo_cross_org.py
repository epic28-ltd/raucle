"""EPIC G: cross-organisation receipt verification (G4) and
conformance-without-disclosure (G6) demo surfaces.

Covers:
- /api/demo/cross-org: Organisation A emits gate receipts under its own
  key in a disposable sandbox (the real gate receipt path), and
  Organisation B verifies each one against the public key Organisation A
  publishes - the only exchanged material - with the REAL
  :class:`raucle.provenance.ProvenanceVerifier` and no contact with the
  issuing operator. Verifying under any other key fails closed.
- /api/demo/conformance: the real conformance re-verification layer
  (:mod:`raucle.conformance`) commits the simulated call arguments,
  discloses only what the policy constraint touches, and re-checks the
  policy over the commitment. Undisclosed constraints read UNKNOWN.
  Bounded disclosure: hidden values never appear in any response.
- demo-mode gating, role access, honest simulated-labelling, and the
  panel view (esc-safe textContent rendering, tour step, single shared
  data-hi map entries).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import ADMIN_PANEL_HTML, create_admin_app

#: The hidden simulated values. If any of these ever reach a response,
#: the bounded-disclosure contract has been breached.
HIDDEN_VALUES = (
    "GB29-NWBK-6016-1331-9264-19",
    "invoice settlement for March",
)


@pytest.fixture
def env(monkeypatch, tmp_path):
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
# Endpoint: /api/demo/cross-org (G4)
# ---------------------------------------------------------------------------


class TestCrossOrgEndpoint:
    def test_org_b_verifies_org_a_receipts_offline(self, env):
        client, _, _, auditor = env
        r = client.get("/api/demo/cross-org", headers=auditor)
        assert r.status_code == 200
        d = r.json()
        assert d["simulated"] is True
        # Organisation A really signed its own receipts under its own key.
        assert d["org_a"]["receipt_count"] >= 1
        assert d["org_a"]["key_id"]
        # The pin Organisation B holds is exactly Organisation A's
        # published key - and nothing else travels between them.
        assert d["org_b"]["pinned_key_id"] == d["org_a"]["key_id"]
        # Every verification is the real result, offline.
        assert d["verifications"], "verifier must see the receipts"
        for v in d["verifications"]:
            assert v["verdict"] == "verified"
            assert v["signature_check"] == "ok"
            assert v["hash_linkage"]["recomputed_matches"] is True
            assert "without contacting" in v["offline"]
        assert d["contact"]["org_a_reached"] is False
        assert "no contact" in d["contact"]["statement"].lower()

    def test_receipts_carry_what_the_verifier_sees(self, env):
        client, _, _, auditor = env
        d = client.get("/api/demo/cross-org", headers=auditor).json()
        for receipt in d["receipts"]:
            assert receipt["receipt_hash_prefix"].startswith("sha256:")
            assert receipt["decision"] in ("allow", "deny")
            assert receipt["signed_by_key_id"] == d["org_a"]["key_id"]

    def test_wrong_key_fails_closed(self, env):
        client, _, _, auditor = env
        d = client.get("/api/demo/cross-org", headers=auditor).json()
        assert d["wrong_key_check"]["verdict"] == "failed"

    def test_requires_authorization(self, env):
        client, _, _, _ = env
        assert client.get("/api/demo/cross-org").status_code == 401

    def test_auditor_role_may_view(self, env):
        """The demo key is an auditor (read-only); the screens read only."""
        client, _, _, auditor = env
        assert client.get("/api/demo/cross-org", headers=auditor).status_code == 200


# ---------------------------------------------------------------------------
# Endpoint: /api/demo/conformance (G6)
# ---------------------------------------------------------------------------


class TestConformanceEndpoint:
    def test_policy_claim_proven_over_commitment(self, env):
        client, _, _, auditor = env
        r = client.get("/api/demo/conformance", headers=auditor)
        assert r.status_code == 200
        d = r.json()
        assert d["simulated"] is True
        # The proof artefact identifier is the Merkle root.
        assert d["proof_artifact"]["identifier"].startswith("sha256:")
        # Disclosed constraints are SATISFIED; the hidden one is UNKNOWN.
        results = d["constraint_results"]
        assert results["allowed_values"] == "SATISFIED"
        assert results["max_value"] == "SATISFIED"
        assert results["starts_with"] == "UNKNOWN"
        claims = {c["constraint_kind"]: c for c in d["claims"]}
        assert claims["allowed_values"]["result"] == "SATISFIED"
        assert claims["starts_with"]["result"] == "UNKNOWN"

    def test_hidden_fields_and_values_stay_hidden(self, env):
        """Bounded disclosure: the response names WHAT stays hidden, and
        the hidden VALUES appear nowhere in it."""
        client, _, _, auditor = env
        text = client.get("/api/demo/conformance", headers=auditor).text
        d = client.get("/api/demo/conformance", headers=auditor).json()
        assert set(d["hidden"]["fields"]) >= {"beneficiary_reference", "memo"}
        for value in HIDDEN_VALUES:
            assert value not in text, value

    def test_labels_simulated_without_compliance_claims(self, env):
        client, _, _, auditor = env
        text = client.get("/api/demo/conformance", headers=auditor).text.lower()
        assert "simulated" in text
        for word in ("compliant", "compliance", "certif", "soc 2", "iso 27001", "gdpr"):
            assert word not in text, word

    def test_requires_authorization(self, env):
        client, _, _, _ = env
        assert client.get("/api/demo/conformance").status_code == 401


# ---------------------------------------------------------------------------
# Demo-mode gating (both endpoints)
# ---------------------------------------------------------------------------


class TestDemoModeGating:
    def test_off_without_demo_mode(self, monkeypatch, tmp_path):
        monkeypatch.setenv("RAUCLE_DEMO_MODE", "")
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
        client = TestClient(create_admin_app(gateway, users))
        headers = {"Authorization": cfg.admin_api_key}
        assert client.get("/api/demo/cross-org", headers=headers).status_code == 404
        assert client.get("/api/demo/conformance", headers=headers).status_code == 404


# ---------------------------------------------------------------------------
# Panel view: tab, esc-safe rendering, tour step, data-hi map
# ---------------------------------------------------------------------------


def _load_assure_js() -> str:
    start = ADMIN_PANEL_HTML.index("function loadAssure()")
    end = ADMIN_PANEL_HTML.index("function offlineVerify(e){")
    return ADMIN_PANEL_HTML[start:end]


class TestPanelAssureView:
    def test_tab_present_and_demo_gated(self):
        assert 'data-tab-id="assure"' in ADMIN_PANEL_HTML
        assert 'id="tab-assure"' in ADMIN_PANEL_HTML
        # Hidden outside demo mode, exactly like the stop screen.
        css = ADMIN_PANEL_HTML.index('body:not(.demo) [data-tab-id="assure"]')
        rest = ADMIN_PANEL_HTML[css : css + 120]
        assert "display:none" in rest

    def test_view_renders_textcontent_only(self):
        js = _load_assure_js()
        assert "innerHTML" not in js
        assert "textContent" in js

    def test_view_labels_the_two_stories_and_simulated(self):
        assert "Cross-organisation receipt verification" in ADMIN_PANEL_HTML
        assert "Conformance without disclosure" in ADMIN_PANEL_HTML
        assert "no contact is made with the issuing operator" in ADMIN_PANEL_HTML.lower()
        assert "Simulated two-organisation story" in ADMIN_PANEL_HTML

    def test_single_shared_data_hi_entries(self):
        assert ADMIN_PANEL_HTML.count('"loadAssure()":(ev,el)=>loadAssure(),') == 1
        assert ADMIN_PANEL_HTML.count('''data-hi="showTab('assure',this)"''') == 1
        assert (
            ADMIN_PANEL_HTML.count(""""showTab('assure',this)":(ev,el)=>showTab('assure',el),""")
            == 1
        )
        # the tab delegation stays unique like every other tab entry
        assert ADMIN_PANEL_HTML.count('''data-hi="showTab('assure',this)"''') == 1

    def test_tour_step_present(self):
        assert "{tab:'assure', target:'#tab-assure'" in ADMIN_PANEL_HTML
        assert "Proof across organisations" in ADMIN_PANEL_HTML
