"""G3: the demo assurance packet plane.

Covers:
- the engine-backed packet: a build collects the deployment's REAL
  receipt chain, assembles a pack with :func:`raucle.audit_pack.
  build_pack` and verifies it offline with :func:`~raucle.audit_pack.
  verify_pack`, so every digest on screen is the built PACK.json's,
  every sha-pinned input is the signed manifest's, and the offline
  verdict is the real PackVerdict,
- determinism: with the same ``generated_at`` the manifest's sha-pinned
  inputs and the non-signed members rebuild byte-identically (the pack's
  own reproducibility check is the honest contract),
- the demo-mode gate, the read-only sandbox (nothing written outside the
  TemporaryDirectory), the ephemeral pack-signing key (no private key
  material in the response, no pack signer key persisted), and the
  boundary naming the agent-assurance product's crosswalk export,
- the panel wiring: card, loader, one shared data-hi entry, tour step.
"""

from __future__ import annotations

import hashlib
import json
import re

import pytest
from fastapi.testclient import TestClient

from raucle.demo_assurance_packet import (
    PACK_BOUNDARY,
    PACK_NOTE,
    build_demo_assurance_packet,
    collect_chain_lines,
)
from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
from raucle.gateway_app import ADMIN_PANEL_HTML, create_admin_app

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


def _emit_receipts(gateway, count=3):
    receipt_hashes = []
    for i in range(count):
        receipt_hashes.append(
            gateway._emit_authority_receipt(
                verdict="allow" if i % 2 == 0 else "deny",
                extension_key="x_admission",
                extension={"decision_source": "demo-simulated", "reason": "demo"},
            )
        )
    return receipt_hashes


def _sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Engine-backed by construction
# ---------------------------------------------------------------------------


class TestRealPacketMachinery:
    def test_collects_the_real_demo_chain(self, client):
        _, gateway, _, _ = client
        receipt_hashes = _emit_receipts(gateway)
        lines = collect_chain_lines(gateway)
        assert len(lines) == len(receipt_hashes)
        for line, receipt_hash in zip(lines, receipt_hashes, strict=False):
            record = json.loads(line)
            assert record["receipt_hash"] == receipt_hash
            # The envelope is the store's own bytes: receipt_hash recomputed
            # from the JWS must match what was returned at emission.
            payload_hash = hashlib.sha256(record["jws"].encode("ascii")).hexdigest()
            assert "sha256:" + payload_hash == receipt_hash

    def test_members_and_verdict_come_from_the_built_pack(self, client):
        _, gateway, _, _ = client
        _emit_receipts(gateway)
        packet = build_demo_assurance_packet(gateway, generated_at=1_234_567)
        assert packet["pack_kind"] == "raucle-audit-pack/v1"
        roles = {m["role"]: m["path"] for m in packet["index"]["members"]}
        assert roles["receipt-chain"] == "chain.jsonl"
        assert roles["signed-manifest"] == "manifest.json"
        assert roles["human-report"] == "report.html"
        for member in packet["index"]["members"]:
            assert member["sha256"].startswith("sha256:")
        verdict = packet["offline_verdict"]
        assert verdict["ok"] is True
        assert verdict["integrity_ok"] is True
        assert verdict["manifest_signature_ok"] is True
        assert verdict["chain_valid"] is True
        assert verdict["reproducible"] is True
        assert verdict["index_signature_ok"] is True
        assert verdict["receipt_count"] == 3
        assert verdict["reasons"] == []

    def test_manifest_inputs_are_sha_pinned_from_the_real_bytes(self, client):
        _, gateway, _, _ = client
        _emit_receipts(gateway)
        packet = build_demo_assurance_packet(gateway, generated_at=1_234_567)
        inputs = packet["manifest"]["input_hashes"]
        chain_member = next(m for m in packet["index"]["members"] if m["role"] == "receipt-chain")
        assert inputs["chain_sha256"] == chain_member["sha256"]
        key_id = getattr(gateway.gate_identity, "key_id", None) or (
            gateway.gate_identity.statement.key_id
        )
        pem = gateway.gate_identity.public_key_pem()
        if isinstance(pem, bytes):
            pem = pem.decode("ascii")
        assert inputs["public_keys"][key_id] == _sha256_prefixed(pem.encode("ascii"))
        # The manifest is signed by the pack's ephemeral audit key, so the
        # manifest key id is that signer - a pack custodian id, not the
        # receipt-signing gate key.
        assert packet["manifest"]["signed"] is True
        assert packet["manifest"]["manifest_key_id"] == packet["index"]["audit_key_id"]

    def test_deterministic_rebuild_matches_sha_pinned_inputs_and_members(self, client):
        _, gateway, _, _ = client
        _emit_receipts(gateway)
        first = build_demo_assurance_packet(gateway, generated_at=42)
        second = build_demo_assurance_packet(gateway, generated_at=42)
        assert first["manifest"]["input_hashes"] == second["manifest"]["input_hashes"]
        # The chain and public-key members are content copies of the real
        # inputs: they rebuild byte-identically. The signed manifest and the
        # rendered report depend on the (fresh, ephemeral) pack key, and the
        # pack's own reproducibility check already binds them to the signed
        # inputs WITHIN a pack - verified above.
        members_without_manifest = [
            m
            for m in first["index"]["members"]
            if not m["path"].endswith(("manifest.json", "report.html"))
        ]
        assert {m["path"]: m["sha256"] for m in members_without_manifest} == {
            m["path"]: m["sha256"]
            for m in second["index"]["members"]
            if not m["path"].endswith(("manifest.json", "report.html"))
        }

    def test_no_receipt_chain_degenerates_honestly(self, client):
        _, gateway, _, _ = client
        packet = build_demo_assurance_packet(gateway)
        assert packet["receipts"] == 0
        assert packet["note"] == PACK_NOTE


# ---------------------------------------------------------------------------
# Boundary, label and read-only shape
# ---------------------------------------------------------------------------


class TestBoundaryAndShape:
    def test_boundary_names_the_assurance_product(self):
        assert "agent-assurance" in PACK_BOUNDARY
        assert "crosswalk" in PACK_BOUNDARY
        for word in COMPLIANCE_WORDS:
            assert word not in PACK_BOUNDARY.lower()
        assert "simulated" in PACK_NOTE.lower()

    def test_no_private_key_material_in_the_response(self, client):
        _, gateway, _, _ = client
        _emit_receipts(gateway)
        packet = build_demo_assurance_packet(gateway, generated_at=7)
        text = json.dumps(packet)
        assert "PRIVATE KEY" not in text
        assert "-----BEGIN" not in text
        # The ephemeral pack signer id is shown, its private half is not.
        assert packet["index"]["audit_key_id"]

    def test_nothing_persisted_outside_the_sandbox(self, client, tmp_path):
        _, gateway, _, _ = client
        _emit_receipts(gateway)
        build_demo_assurance_packet(gateway, generated_at=7)
        # The deployment's own chain is untouched by a pack build.
        assert len(collect_chain_lines(gateway)) == 3
        assert not list(tmp_path.rglob("PACK.json"))

    def test_compliance_words_absent_from_payload(self, client):
        _, gateway, _, _ = client
        _emit_receipts(gateway)
        packet = build_demo_assurance_packet(gateway, generated_at=7)
        text = json.dumps(packet).lower()
        for word in COMPLIANCE_WORDS:
            assert word not in text


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


class TestEndpoints:
    def test_route_serves_the_real_packet(self, client):
        client_http, gateway, _, auditor = client
        _emit_receipts(gateway)
        r = client_http.get("/api/demo/assurance-packet", headers=auditor)
        assert r.status_code == 200
        d = r.json()
        assert d["offline_verdict"]["ok"] is True
        assert d["receipts"] == 3
        assert d["boundary"] == PACK_BOUNDARY

    def test_demo_mode_gate(self, tmp_path):
        """Outside demo mode the route answers 404 like the other planes."""
        cfg = GatewayConfig(
            policy_file="p",
            receipt_store=str(tmp_path / "r.jsonl"),
            audit_chain=str(tmp_path / "a.jsonl"),
            admin_api_key="admin-key-for-tests-0123456789",
        )
        gateway = RaucleGateway(cfg)
        users = UserManager(persist_path=None)
        users.add_user(cfg.admin_api_key, "admin", "Admin")
        app = create_admin_app(gateway, users)
        http = TestClient(app)
        r = http.get(
            "/api/demo/assurance-packet",
            headers={"Authorization": cfg.admin_api_key},
        )
        assert r.status_code == 404

    def test_requires_authentication(self, client):
        client_http, _, _, _ = client
        assert client_http.get("/api/demo/assurance-packet").status_code in (401, 403)


# ---------------------------------------------------------------------------
# Panel wiring
# ---------------------------------------------------------------------------


class TestPanelWiring:
    def test_packet_card_and_loader_present(self):
        assert 'id="assurancePacketView"' in ADMIN_PANEL_HTML
        assert "function loadAssurancePacket()" in ADMIN_PANEL_HTML
        assert 'data-hi="loadAssurancePacket()"' in ADMIN_PANEL_HTML
        # Single shared data-hi map: extend never duplicate.
        assert ADMIN_PANEL_HTML.count('"loadAssurancePacket()":(ev,el)=>loadAssurancePacket()') == 1

    def test_boundary_named_in_the_ui(self):
        assert "agent-assurance" in ADMIN_PANEL_HTML

    def test_tour_step_registered(self):
        m = re.search(r"\{tab:'assure', target:'#assurancePacketView'[^}]*\}", ADMIN_PANEL_HTML)
        assert m, "assurance packet tour step must exist"


def test_chain_collection_is_empty_without_receipts(client):
    """An unseen deployment reports no chain rather than a fake one."""
    _, gateway, _, _ = client
    assert collect_chain_lines(gateway) == []


def test_index_signature_actually_verifies(client):
    """The ephemeral pack key signs the index; the pack bytes verify."""
    _, gateway, _, _ = client
    _emit_receipts(gateway)
    packet = build_demo_assurance_packet(gateway, generated_at=5)
    signer_id = packet["index"]["audit_key_id"]
    assert len(signer_id) == 16
    assert all(c in "0123456789abcdef" for c in signer_id)
    # The offline verdict's trust anchor is that same derived id.
    assert packet["offline_verdict"]["signer_key_id"] == signer_id
    # And the chain member rides base64 within the JSONL export (the
    # JWS envelope), matching the receipts the gateway really signed.
    assert packet["manifest"]["chain_verdict"]["valid"] is True
