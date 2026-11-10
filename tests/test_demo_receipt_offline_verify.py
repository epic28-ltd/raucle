"""D7/D11: enterprise capability strip and the offline verifier cameo.

Covers:
- the Dashboard "Enterprise capabilities in this demo" strip: one entry per
  capability screen, each delegating through the shared data-hi map to its
  showTab('...' ,this) call, with the honest one-line simulated-traffic note
  and no compliance wording,
- the receipts-tab offline verification cameo: a one-click action on each
  receipt row that calls the REAL offline verification endpoint,
- the /api/receipts/{receipt_hash}/offline-verify endpoint: it runs
  :class:`raucle.provenance.ProvenanceVerifier` (the same verifier an
  auditor runs on an exported chain) over the selected envelope, so a
  verified response means the Ed25519 JWS signature checked under the gate
  key and the receipt hash recomputed from the JWS bytes; tampered or
  unknown receipts fail closed (422/404),
- role gating and the simulated-receipt labelling.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import ADMIN_PANEL_HTML, OFFLINE_VERIFY_NOTE, create_admin_app

D7_STRIP_ENTRIES = (
    ("AI gateway", "connections"),
    ("Policy editor", "policies"),
    ("Learn mode", "learn"),
    ("Data loss prevention", "dlp"),
    ("Prompt injection detection", "injection"),
    ("Shadow AI discovery", "shadow"),
    ("MCP tool scanning", "mcp"),
    ("Receipts with offline verification", "receipts"),
    ("SIEM forwarding", "siem"),
    ("Users and MFA", "users"),
)


@pytest.fixture
def env(tmp_path):
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


def _find_envelope(gateway, receipt_hash):
    """Read the raw envelope line for receipt_hash from the demo store."""
    import json as _json

    with open(gateway.config.receipt_store, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = _json.loads(line)
            if rec.get("receipt_hash") == receipt_hash:
                return rec
    raise AssertionError(f"envelope not found: {receipt_hash}")


def _emit_receipt(gateway):
    """Sign and store one demo-style gate receipt the real way."""
    receipt_hash = gateway._emit_authority_receipt(
        verdict="allow",
        extension_key="x_admission",
        extension={"decision_source": "demo-simulated", "reason": "demo"},
    )
    assert receipt_hash
    return receipt_hash


# ---------------------------------------------------------------------------
# Endpoint: the real offline verification path
# ---------------------------------------------------------------------------


class TestOfflineVerifyEndpoint:
    def test_verifies_a_real_gate_receipt_offline(self, env):
        client, gateway, _, auditor = env
        receipt_hash = _emit_receipt(gateway)
        r = client.post(f"/api/receipts/{receipt_hash}/offline-verify", headers=auditor)
        assert r.status_code == 200
        d = r.json()
        assert d["verdict"] == "verified"
        assert d["signature_check"] == "ok"
        assert d["hash_linkage"]["recomputed_matches"] is True
        assert d["receipt_count"] == 1
        # What an auditor sees, without contacting the operator.
        assert "without contacting the operator" in d["offline"]
        assert d["note"] == OFFLINE_VERIFY_NOTE
        assert "simulated" in d["note"].lower()

    def test_verdict_covers_signature_and_hash(self, env):
        """The verify step is the REAL ProvenanceVerifier: a tampered
        signature must fail closed with a 422, not a soft pass."""
        client, gateway, _, admin = env
        receipt_hash = _emit_receipt(gateway)
        # Tamper the JWS in the store directly (simulated demo data).
        import base64 as _base64
        import json as _json

        envelope = _find_envelope(gateway, receipt_hash)
        assert envelope is not None

        segs = envelope["jws"].split(".")
        payload = bytearray(_base64.urlsafe_b64decode(segs[1] + "=="))
        payload[len(payload) // 2] ^= 0x01
        tampered = {
            "receipt_hash": receipt_hash,
            "jws": segs[0]
            + "."
            + _base64.urlsafe_b64encode(bytes(payload)).decode().rstrip("=")
            + "."
            + segs[2],
        }
        store_file = gateway.config.receipt_store
        with open(store_file, encoding="utf-8") as fh:
            lines = [line for line in fh if line.strip()]
        with open(store_file, "w", encoding="utf-8") as fh:
            for line in lines:
                rec = _json.loads(line)
                if rec.get("receipt_hash") == receipt_hash:
                    fh.write(_json.dumps(tampered, ensure_ascii=False) + "\n")
                else:
                    fh.write(line)
        r = client.post(f"/api/receipts/{receipt_hash}/offline-verify", headers=admin)
        assert r.status_code == 422
        d = r.json()["detail"]
        assert d["verdict"] == "failed"
        assert d["hash_linkage"]["recomputed_matches"] is False

    def test_unknown_receipt_hash_is_404(self, env):
        client, _, _, auditor = env
        r = client.post("/api/receipts/sha256:%s/offline-verify" % ("0" * 64), headers=auditor)
        assert r.status_code == 404

    def test_requires_authorization(self, env):
        client, gateway, _, _ = env
        receipt_hash = _emit_receipt(gateway)
        assert client.post(f"/api/receipts/{receipt_hash}/offline-verify").status_code == 401

    def test_auditor_role_may_verify(self, env):
        """The demo key is an auditor (read-only); verification reads only."""
        client, gateway, _, auditor = env
        receipt_hash = _emit_receipt(gateway)
        assert (
            client.post(f"/api/receipts/{receipt_hash}/offline-verify", headers=auditor).status_code
            == 200
        )


# ---------------------------------------------------------------------------
# Panel: D7 strip + D11 one-click action
# ---------------------------------------------------------------------------


class TestPanelD7Strip:
    def test_strip_card_present_with_title(self):
        assert "Enterprise capabilities in this demo" in ADMIN_PANEL_HTML
        assert 'id="enterpriseStrip"' in ADMIN_PANEL_HTML

    def test_every_capability_links_to_its_tab(self):
        for label, tab in D7_STRIP_ENTRIES:
            attr = f"data-hi=\"showTab('{tab}',this)\""
            assert attr in ADMIN_PANEL_HTML, label
            # the strip carries the label next to that delegation
            idx = ADMIN_PANEL_HTML.index("enterpriseStrip")
            region = ADMIN_PANEL_HTML[idx : idx + 4000]
            assert label in region, label
            assert attr in region, label

    def test_honest_labelling_note(self):
        idx = ADMIN_PANEL_HTML.index("enterpriseStrip")
        region = ADMIN_PANEL_HTML[idx : idx + 2500]
        assert "simulated traffic" in region
        assert "same enforcement code paths as a live deployment" in region
        # no compliance claims and no vendor names
        low = region.lower()
        for word in ("compliant", "compliance", "certif", "soc 2", "iso 27001", "gdpr"):
            assert word not in low, word

    def test_strip_does_not_add_new_delegation_keys(self):
        for _label, tab in D7_STRIP_ENTRIES:
            assert ADMIN_PANEL_HTML.count(f"\"showTab('{tab}',this)\":") == 1


class TestPanelOfflineVerifyCameo:
    def test_receipt_rows_carry_one_click_verify(self):
        assert ADMIN_PANEL_HTML.count('data-hi="offlineVerify(event)"') == 1
        assert ADMIN_PANEL_HTML.count('"offlineVerify(event)":(ev,el)=>offlineVerify(ev)') == 1

    def test_offline_card_renders_textcontent_only(self):
        assert 'id="rcpt-offline"' in ADMIN_PANEL_HTML
        assert 'id="offlineView"' in ADMIN_PANEL_HTML
        view = ADMIN_PANEL_HTML.index("function offlineVerify(e)")
        fn = ADMIN_PANEL_HTML[view : view + 1600]
        # textContent rendering, esc-safe (data attributes, no HTML injection)
        assert "textContent" in fn
        assert "innerHTML" not in fn

    def test_offline_card_labels_simulated(self):
        idx = ADMIN_PANEL_HTML.index('id="rcpt-offline"')
        region = ADMIN_PANEL_HTML[idx : idx + 1500]
        assert "Simulated demo receipts" in region
        assert "without contacting the operator" in region

    def test_endpoint_note_matches_card_labelling(self):
        idx = ADMIN_PANEL_HTML.index('id="rcpt-offline"')
        region = ADMIN_PANEL_HTML[idx : idx + 1500]
        # the honest-note wording is shared between the endpoints and the card
        assert "real offline verifier" in region
        assert "simulated" in region.lower()
        # the endpoint labels every verified response with the same note constant
        assert OFFLINE_VERIFY_NOTE.endswith(
            "with the same enforcement code paths as a live deployment."
        )
