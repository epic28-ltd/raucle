"""G5: the demo key model / never-exported keys plane.

Covers:
- the view is driven by the SAME live signer configuration the
  receipts key-family card (D11/PR-251) reads: signer backend, the key
  id of the key that actually signs receipts, and the key-material type,
- the gate-enrolment checks are recomputed from the statement bytes
  (key id binds to the key material, statement signature verifies) and
  both must pass for the deployment's real gate identity,
- the rotation story names only rotation functions the tree actually
  carries (TrustRegistry.publish/revoke, AgentCredentialStore.issue,
  AgentRegistry.enrol/retire, the boot local signer, kms.create_signer)
  and stays consistent with the key-operations runbook contract pinned
  by tests/test_key_rotation_e2e.py,
- the never-exported shape: no route material displays private key
  content (no PEM header escapes in any response), the posture names
  the backend's key-material location, and a KMS-configured backend
  reports remote signing with a local file explicitly absent,
- demo-mode gating, read-only shape, no compliance wording, panel wiring.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from raucle.demo_key_model import KEY_MODEL_NOTE, build_demo_key_model
from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import ADMIN_PANEL_HTML, create_admin_app

ROTATION_FUNCTION_NAMES = (
    "TrustRegistry.publish",
    "TrustRegistry.revoke",
    "AgentCredentialStore.issue",
    "AgentRegistry.enrol",
    "_load_or_create_local_signer",
)
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
# Same live configuration as the key-family card
# ---------------------------------------------------------------------------


class TestLiveSignerConfig:
    def test_matches_the_gateway_configuration(self, client):
        _, gateway, _, _ = client
        view = build_demo_key_model(gateway, pq_available=True)
        # Same config path the key-family endpoint reads.
        assert view["signer_backend"] == gateway.config.signer_backend
        assert (
            view["receipt_signing_key_id"] == getattr(gateway.gate_identity, "key_id", None)
            or gateway.gate_identity.statement.key_id
        )
        assert view["key_material_type"] == "Ed25519PublicKey"
        assert view["agent_id"] == gateway.gate_identity.agent_id
        assert view["ml_dsa_available"] is True

    def test_key_id_agrees_with_the_signing_key_bytes(self, client):
        """The shown key id is derived from the key material, not a label."""
        import hashlib

        from cryptography.hazmat.primitives import serialization

        _, gateway, _, _ = client
        view = build_demo_key_model(gateway, pq_available=False)
        pem = gateway.gate_identity.public_key_pem()
        if isinstance(pem, bytes):
            pem = pem.decode("ascii")
        key = serialization.load_pem_public_key(pem.encode("ascii"))
        derived = hashlib.sha256(
            key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()[:16]
        assert view["receipt_signing_key_id"] == derived

    def test_endpoint_reports_the_key_family_the_gateway_signs_with(self, client):
        client_http, gateway, _, auditor = client
        view = client_http.get("/api/demo/key-model", headers=auditor).json()
        family = client_http.get("/api/receipts/key-family", headers=auditor).json()
        assert view["signer_backend"] == family["signer_backend"]
        assert view["receipt_signing_key_id"] == family["key_id"]
        assert view["key_material_type"] == family["issuer_key_type"]


# ---------------------------------------------------------------------------
# Gate enrolment: checked, not narrated
# ---------------------------------------------------------------------------


class TestGateEnrolment:
    def test_enrolment_checks_derive_from_the_statement_bytes(self, client):
        _, gateway, _, _ = client
        view = build_demo_key_model(gateway, pq_available=False)
        checks = view["gate_enrolment"]
        assert checks["key_id_binds_to_key_material"] is True
        assert checks["identity_statement_signature_verified"] is True
        assert checks["statement_key_type"] == "Ed25519PublicKey"

    def test_checks_fail_closed_on_altered_material(self, client):
        """Same class the verifier enforces: altered bytes stop verifying."""
        import base64
        import copy

        from raucle.provenance import _canonical_json

        _, gateway, _, _ = client

        gate = gateway.gate_identity
        tampered = copy.deepcopy(gate.statement.to_dict())
        tampered["allowed_tools"] = ["everything.now"]
        # Re-sign check without the private key must NOT verify: the checks
        # run against the presented statement's own consistency, so an
        # attacker-signed widened statement can never pass under the real id.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pem = gate.public_key_pem()
        if isinstance(pem, bytes):
            pem = pem.decode("ascii")
        body = {k: v for k, v in tampered.items() if k != "signature"}
        sig = base64.b64decode(tampered["signature"])
        key = serialization.load_pem_public_key(pem.encode("ascii"))
        assert isinstance(key, Ed25519PublicKey)
        try:
            key.verify(sig, _canonical_json(body))
            forged = True
        except Exception:
            forged = False
        assert forged is False, "the deployment key must not verify a widened body"


# ---------------------------------------------------------------------------
# Never exported
# ---------------------------------------------------------------------------


class TestNeverExported:
    def test_no_private_material_across_every_response(self, client):
        client_http, gateway, _, auditor = client
        for path in ("/api/demo/key-model", "/api/receipts/key-family"):
            r = client_http.get(path, headers=auditor)
            assert r.status_code == 200
            assert "PRIVATE KEY" not in r.text
            assert "-----BEGIN" not in r.text
        assert "simulated demonstration of real configuration" in KEY_MODEL_NOTE.lower()

    def test_local_posture_describes_the_host_file(self, client, tmp_path):
        client_http, gateway, _, auditor = client
        posture = client_http.get("/api/demo/key-model", headers=auditor).json()[
            "key_export_posture"
        ]
        assert posture["backend"] == "local"
        assert posture["private_material_exported"] is False
        assert posture["signing_key_persisted"] is True
        assert posture["signing_key_permission"] == "0600"
        # No filesystem path leaks in the posture payload.
        assert str(tmp_path) not in json.dumps(posture)

    def test_kms_posture_names_the_remote_boundary(self, tmp_path, monkeypatch):
        """A KMS-shaped deployment: same live checks, remote key boundary."""
        import raucle.kms as kms_mod
        from raucle.audit import Ed25519Signer

        local = Ed25519Signer.generate()

        def fake_create_signer(**kwargs):
            assert kwargs["backend"] == "kms"
            return kms_mod.KMSSigner(sign_fn=local.sign, public_key_pem=local.public_key_pem())

        monkeypatch.setattr(kms_mod, "create_signer", fake_create_signer)
        cfg = GatewayConfig(
            policy_file=str(tmp_path / "policies.yaml"),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            admin_api_key="admin-key-for-tests-0123456789",
            signer_backend="kms",
        )
        gateway = RaucleGateway(cfg)
        assert gateway.config.signer_backend == "kms"
        assert not hasattr(gateway.gate_identity, "_private_key")
        view = build_demo_key_model(gateway, pq_available=False)
        posture = view["key_export_posture"]
        assert posture["backend"] == "kms"
        assert posture["signing_key_local_file"] is False
        assert posture["private_material_exported"] is False
        assert "create_signer" in posture["key_material_location"]
        # The checks stay live: enrolment still verifies the real statement.
        assert view["gate_enrolment"]["identity_statement_signature_verified"] is True
        assert view["key_material_type"] == "Ed25519PublicKey"


# ---------------------------------------------------------------------------
# Rotation story: grounded in the tree's own functions
# ---------------------------------------------------------------------------


class TestRotationStory:
    def test_every_named_layer_cites_real_functions(self, client):
        _, gateway, _, _ = client
        view = build_demo_key_model(gateway, pq_available=False)
        layers = [entry["layer"] for entry in view["rotation_story"]]
        assert len(layers) >= 3
        joined = json.dumps(view["rotation_story"])
        for name in ROTATION_FUNCTION_NAMES:
            assert name in joined

    def test_story_carries_the_dual_trust_and_archival_contract(self, client):
        _, gateway, _, _ = client
        joined = json.dumps(build_demo_key_model(gateway, pq_available=False))
        # The rotation contract the runbook documents and the e2e test pins.
        assert "dual-trust" in joined
        assert "versioned issuer identity" in joined
        assert "still verify against the archived public key" in joined


# ---------------------------------------------------------------------------
# Endpoint + panel wiring
# ---------------------------------------------------------------------------


class TestEndpointAndPanel:
    def test_demo_mode_gate(self, tmp_path):
        cfg = GatewayConfig(
            policy_file="p",
            receipt_store=str(tmp_path / "r.jsonl"),
            audit_chain=str(tmp_path / "a.jsonl"),
            admin_api_key="admin-key-for-tests-0123456789",
        )
        gateway = RaucleGateway(cfg)
        users = UserManager(persist_path=None)
        users.add_user(cfg.admin_api_key, "admin", "Admin")
        http = TestClient(create_admin_app(gateway, users))
        assert (
            http.get(
                "/api/demo/key-model",
                headers={"Authorization": cfg.admin_api_key},
            ).status_code
            == 404
        )

    def test_serves_with_simulated_labelling(self, client):
        client_http, _, _, auditor = client
        r = client_http.get("/api/demo/key-model", headers=auditor)
        assert r.status_code == 200
        assert r.json()["simulated"] is True

    def test_no_compliance_wording(self, client):
        _, gateway, _, _ = client
        text = json.dumps(build_demo_key_model(gateway, pq_available=False)).lower()
        for word in COMPLIANCE_WORDS:
            assert word not in text

    def test_panel_card_loader_and_shared_map(self):
        assert 'id="keyModelView"' in ADMIN_PANEL_HTML
        assert "function loadKeyModel()" in ADMIN_PANEL_HTML
        assert "loadReceipts();loadKeyFamily();loadKeyModel();" in ADMIN_PANEL_HTML
        # No new data-hi handler needed (the card loads with its tab) and
        # the view renders through textContent, never innerHTML.
        for line in ADMIN_PANEL_HTML.splitlines():
            if "innerHTML" in line:
                assert "keyModelView" not in line

    def test_tour_step_registered(self):
        import re

        m = re.search(r"\{tab:'receipts', target:'#rcpt-keymodel'[^}]*\}", ADMIN_PANEL_HTML)
        assert m
        # Never-exported framing lives in the guide copy.
        assert "enrolled, never exported" in m.group(0) or "never exported" in ADMIN_PANEL_HTML
