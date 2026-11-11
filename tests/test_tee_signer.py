"""H3 slice 1: the TEE / hardware-attested signer path.

Covers:
- ``raucle.tee.TEESigner`` satisfies the existing ``raucle.kms.Signer``
  protocol and signs across a boundary callable without ever holding or
  exporting key material,
- the attestation binding: the document's digest reference, the public-key
  binding inside the document, and the exact statement shape, labelled
  simulated by the mock boundary,
- the capability statement's OPTIONAL ``attestation`` field: byte-identical
  body when unset (statements signed before the field keep verifying),
  strict parsing when set, and the statement signature covering it,
- the ``create_signer(backend="tee")`` factory: fail-closed, never silently
  simulated; explicit enclave wiring or explicit mock acknowledgement,
- gateway boot with the mock boundary: receipts mint, verify offline, the
  gate identity statement carries the binding, and the demo key-model view
  (the PR-258 surface) serialises it with an honest export posture.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from raucle.capability import CapabilityIssuer
from raucle.demo_key_model import build_demo_key_model
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.kms import Signer, create_signer
from raucle.provenance import CapabilityStatement, ProvenanceVerifier, _canonical_json

POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-002"]
"""

STATEMENT_ATTESTATION_KEYS = {"platform", "measurement", "attestation_ref", "simulated"}
V1_STATEMENT_BODY_KEYS = {
    "agent_id",
    "key_id",
    "public_key_pem",
    "allowed_models",
    "allowed_tools",
    "data_classifications",
    "issuer",
    "issued_at",
    "expires_at",
}


def _sim_enclave():
    from raucle.tee import SimulatedNitroEnclave

    return SimulatedNitroEnclave()


def _sim_signer():
    return _sim_enclave().signer()


def _sim_binding_attestation() -> dict[str, object]:
    return {
        "platform": "aws-nitro",
        "measurement": "sha384:" + "ab" * 24,
        "attestation_ref": "sha256:" + "cd" * 32,
        "simulated": True,
    }


def _issuer() -> CapabilityIssuer:
    return CapabilityIssuer(issuer="raucle-gateway", private_key=Ed25519PrivateKey.generate())


def _statement(issuer: CapabilityIssuer, attestation=None) -> CapabilityStatement:
    stmt = CapabilityStatement(
        agent_id="agent:tee-gate",
        key_id=issuer.key_id,
        public_key_pem=issuer.public_key_pem,
        allowed_models=[],
        allowed_tools=[],
        data_classifications=[],
        issuer="raucle-gateway",
        issued_at=1730000000,
        expires_at=None,
        attestation=attestation,
    )
    sig = issuer._priv.sign(_canonical_json(stmt.body()))
    stmt.signature = base64.b64encode(sig).decode("ascii")
    return stmt


def _ed25519_from_pem(pem_bytes: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem_bytes)
    assert isinstance(key, Ed25519PublicKey)
    return key


def _read_receipts(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _payload_of(receipt: dict) -> dict:
    part = receipt["jws"].split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


# ---------------------------------------------------------------------------
# TEESigner adapter contract
# ---------------------------------------------------------------------------


class TestTEESignerContract:
    def test_satisfies_the_existing_signer_protocol(self):
        assert isinstance(_sim_signer(), Signer)

    def test_signature_verifies_against_the_returned_public_key(self):
        signer = _sim_signer()
        sig = signer.sign(b"canonical receipt bytes")
        pem = signer.public_key_pem()

        _ed25519_from_pem(pem).verify(sig, b"canonical receipt bytes")
        assert len(sig) == 64

    def test_sign_bytes_cross_the_named_boundary(self):
        """The adapter dispatches to the enclave call; it never signs itself."""
        from raucle.tee import TEESigner

        raw = Ed25519PrivateKey.generate()
        seen: list[bytes] = []

        def enclave_boundary(data: bytes) -> bytes:
            seen.append(data)
            return raw.sign(data)

        signer = TEESigner(
            sign_fn=enclave_boundary,
            public_key_pem=_pem(raw),
            attestation_provider=_sim_enclave(),
        )
        sig = signer.sign(b"payload")
        assert seen == [b"payload"]
        _ed25519_from_pem(_pem(raw)).verify(sig, b"payload")

    def test_public_surface_exports_no_private_material(self):
        signer = _sim_signer()
        assert b"PRIVATE" not in signer.public_key_pem()
        for name in vars(signer):
            assert "private" not in name.lower()

    def test_attestation_binding_references_the_document_bytes(self):
        signer = _sim_signer()
        binding = signer.attestation_binding()
        doc = base64.b64decode(binding.document_b64)
        assert binding.attestation_ref == "sha256:" + hashlib.sha256(doc).hexdigest()
        assert binding.platform == "aws-nitro"
        assert binding.measurement.startswith("sha384:")
        assert binding.simulated is True

    def test_attestation_document_binds_the_signing_key(self):
        signer = _sim_signer()
        binding = signer.attestation_binding()
        doc = json.loads(base64.b64decode(binding.document_b64))
        assert doc["simulated"] is True
        assert doc["public_key_pem"] == signer.public_key_pem().decode("ascii")
        assert base64.b64decode(doc["user_data"]) == signer.public_key_pem()
        assert doc["module_id"]

    def test_statement_shape_matches_the_statement_contract(self):
        signer = _sim_signer()
        statement = signer.attestation_statement()
        assert set(statement) == STATEMENT_ATTESTATION_KEYS
        binding = signer.attestation_binding()
        for field_name in ("platform", "measurement"):
            assert statement[field_name] == getattr(binding, field_name)
        assert statement["attestation_ref"] == binding.attestation_ref
        assert statement["simulated"] is True

    def test_gateway_issuer_mints_through_the_tee_signer(self):
        issuer = CapabilityIssuer.from_signer("raucle-gateway", _sim_signer())
        token = issuer.mint(
            agent_id="agent:svc",
            tool="lookup_balance",
            constraints={"allowed_values": {"account": ["ACC-001"]}},
            ttl_seconds=60,
        )
        assert token.token_id.startswith("cap:")

        from raucle.capability import CapabilityGate

        gate = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
        decision = gate.check(
            token, tool="lookup_balance", agent_id="agent:svc", args={"account": "ACC-001"}
        )
        assert decision.allowed, decision.reason


def _pem(raw: Ed25519PrivateKey) -> bytes:
    return raw.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ---------------------------------------------------------------------------
# Capability statement attestation field
# ---------------------------------------------------------------------------


class TestStatementAttestationBinding:
    def test_statement_without_attestation_keeps_the_v1_body_shape(self):
        stmt = _statement(_issuer())
        assert set(stmt.body()) == V1_STATEMENT_BODY_KEYS
        assert "attestation" not in stmt.to_dict()

    def test_roundtrip_through_the_statement_parser(self):
        issuer = _issuer()
        attestation = _sim_binding_attestation()
        stmt = _statement(issuer, attestation)
        rebuilt = CapabilityStatement.from_dict(stmt.to_dict())
        assert rebuilt.attestation == attestation
        assert stmt.to_dict() == rebuilt.to_dict()

    def test_statement_signature_covers_the_binding(self):
        issuer = _issuer()
        stmt = _statement(issuer, _sim_binding_attestation())
        _ed25519_from_pem(_pem(issuer._priv)).verify(
            base64.b64decode(stmt.signature), _canonical_json(stmt.body())
        )

    @pytest.mark.parametrize(
        "bad",
        [
            {
                "platform": "",
                "measurement": "sha384:x",
                "attestation_ref": "sha256:x",
                "simulated": False,
            },
            {
                "platform": "aws-nitro",
                "measurement": "",
                "attestation_ref": "sha256:x",
                "simulated": False,
            },
            {
                "platform": "aws-nitro",
                "measurement": "sha384:x",
                "attestation_ref": "",
                "simulated": False,
            },
            {
                "platform": "aws-nitro",
                "measurement": "sha384:x",
                "attestation_ref": "sha256:x",
                "simulated": "no",
            },
            {"platform": "aws-nitro", "measurement": "sha384:x", "attestation_ref": "sha256:x"},
            {
                "platform": "aws-nitro",
                "measurement": "sha384:x",
                "attestation_ref": "sha256:x",
                "simulated": True,
                "extra": 1,
            },
        ],
    )
    def test_parser_rejects_bad_attestation_shapes(self, bad):
        issuer = _issuer()
        stmt = _statement(issuer)
        d = stmt.to_dict()
        d["attestation"] = bad
        with pytest.raises(ValueError):
            CapabilityStatement.from_dict(d)

    def test_parser_rejects_non_object_attestation(self):
        issuer = _issuer()
        d = _statement(issuer).to_dict()
        d["attestation"] = "aws-nitro"
        with pytest.raises(ValueError):
            CapabilityStatement.from_dict(d)

    def test_parser_still_rejects_unknown_statement_fields(self):
        issuer = _issuer()
        d = _statement(issuer).to_dict()
        d["unrelated"] = 1
        with pytest.raises(ValueError):
            CapabilityStatement.from_dict(d)


# ---------------------------------------------------------------------------
# create_signer(backend="tee") factory: fail-closed
# ---------------------------------------------------------------------------


class TestTeeFactory:
    def test_no_silent_simulation(self, monkeypatch):
        monkeypatch.delenv("RAUCLE_TEE_SIMULATED", raising=False)
        with pytest.raises(ValueError, match="RAUCLE_TEE_SIMULATED"):
            create_signer(backend="tee")

    def test_acknowledged_mock_is_simulated(self, monkeypatch):
        monkeypatch.setenv("RAUCLE_TEE_SIMULATED", "1")
        signer = create_signer(backend="tee")
        assert isinstance(signer, Signer)
        assert signer.attestation_binding().simulated is True

    def test_explicit_enclave_wiring_needs_no_mock_ack(self, monkeypatch):
        from raucle.tee import TEESigner

        monkeypatch.delenv("RAUCLE_TEE_SIMULATED", raising=False)
        raw = Ed25519PrivateKey.generate()
        signer = create_signer(
            backend="tee",
            sign_fn=raw.sign,
            public_key_pem=_pem(raw),
            attestation_provider=_sim_enclave(),
        )
        assert isinstance(signer, TEESigner)
        sig = signer.sign(b"x")
        _ed25519_from_pem(_pem(raw)).verify(sig, b"x")

    def test_unknown_backend_error_lists_tee(self):
        with pytest.raises(ValueError, match="tee"):
            create_signer(backend="teleporter")


# ---------------------------------------------------------------------------
# Gateway boot with the mock boundary (end-to-end)
# ---------------------------------------------------------------------------


def _tee_config(tmp_path, tee_simulated: bool = True) -> GatewayConfig:
    policy = tmp_path / "policies.yaml"
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text(POLICY)
    config = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="tee",
        tee_simulated=tee_simulated,
        policy_file=str(policy),
        receipt_store=str(tmp_path / "receipts.jsonl"),
        audit_chain=str(tmp_path / "audit.jsonl"),
        registry_path=str(tmp_path / "registry.jsonl"),
        emit_receipts=True,
        boot_selftest=False,
    )
    return config


@pytest.fixture
def tee_gw(tmp_path):
    return RaucleGateway(_tee_config(tmp_path))


class TestGatewayTeeBoot:
    def test_boot_refuses_tee_without_the_mock_acknowledgement(self, tmp_path):
        cfg = _tee_config(tmp_path, tee_simulated=False)
        with pytest.raises(ValueError, match="RAUCLE_TEE_SIMULATED"):
            RaucleGateway(cfg)

    def test_mock_boundary_mints_receipts_that_verify_offline(self, tee_gw, tmp_path):
        decision = tee_gw.check_tool_call(
            tool="lookup_balance", args={"account": "ACC-001"}, agent_id="agent:svc"
        )
        assert decision["decision"] == "allow"
        assert decision["receipt_id"]

        receipts = _read_receipts(tee_gw.config.receipt_store)
        assert receipts, "no receipts in store"
        verifier = ProvenanceVerifier(
            public_keys={tee_gw.gate_identity.key_id: tee_gw.gate_identity.public_key_pem()}
        )
        report = verifier.verify_chain(tee_gw.config.receipt_store)
        assert report.valid, report.errors

        gate_receipts = [r for r in receipts if r["receipt_hash"] == decision["receipt_id"]]
        assert len(gate_receipts) == 1
        payload = _payload_of(gate_receipts[0])
        assert payload["agent_key_id"] == tee_gw.gate_identity.key_id
        assert payload["agent_key_id"] == tee_gw.gate_identity.statement.key_id

    def test_gate_statement_carries_the_attestation_binding(self, tee_gw):
        stmt = tee_gw.gate_identity.statement
        attestation = stmt.attestation
        assert attestation is not None
        assert set(attestation) <= STATEMENT_ATTESTATION_KEYS
        assert attestation["simulated"] is True
        assert attestation["platform"] == "aws-nitro"
        assert attestation["measurement"].startswith("sha384:")
        # the binding rides the signed statement: signature covers it
        _ed25519_from_pem(stmt.public_key_pem.encode("ascii")).verify(
            base64.b64decode(stmt.signature), _canonical_json(stmt.body())
        )
        # the identity self-consistency: the binding names THIS key
        assert stmt.key_id == tee_gw.gate_identity.key_id

    def test_receipts_verify_with_the_statement_supplied(self, tee_gw):
        tee_gw.check_tool_call(
            tool="lookup_balance", args={"account": "ACC-001"}, agent_id="agent:svc"
        )
        verifier = ProvenanceVerifier(
            public_keys={tee_gw.gate_identity.key_id: tee_gw.gate_identity.public_key_pem()},
            capabilities={tee_gw.gate_identity.key_id: tee_gw.gate_identity.statement},
        )
        report = verifier.verify_chain(tee_gw.config.receipt_store)
        assert report.valid, report.errors

    def test_mock_identity_is_ephemeral_per_boot(self, tmp_path):
        gw_a = RaucleGateway(_tee_config(tmp_path / "a"))
        gw_b = RaucleGateway(_tee_config(tmp_path / "b"))
        assert gw_a.gate_identity.key_id != gw_b.gate_identity.key_id

    def test_key_model_serialises_the_attestation_binding(self, tee_gw):
        view = build_demo_key_model(tee_gw, pq_available=False)
        attestation = view["receipt_signing_attestation"]
        assert attestation["platform"] == "aws-nitro"
        assert attestation["simulated"] is True
        assert (
            attestation["attestation_ref"]
            == (tee_gw.gate_identity.statement.attestation["attestation_ref"])
        )
        assert attestation["attestation_ref_is_digest"] is True

    def test_key_model_non_tee_backend_has_no_attestation(self, tmp_path):
        cfg = _tee_config(tmp_path)
        cfg_signer = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file=cfg.policy_file,
            receipt_store=str(tmp_path / "local-receipts.jsonl"),
            audit_chain=str(tmp_path / "local-audit.jsonl"),
            registry_path=str(tmp_path / "local-registry.jsonl"),
            emit_receipts=True,
            boot_selftest=False,
        )
        gw = RaucleGateway(cfg_signer)
        view = build_demo_key_model(gw, pq_available=False)
        assert view["receipt_signing_attestation"] is None

    def test_tee_export_posture_is_honest(self, tee_gw):
        view = build_demo_key_model(tee_gw, pq_available=False)
        posture = view["key_export_posture"]
        assert posture["backend"] == "tee"
        assert posture["signing_key_local_file"] is False
        assert posture["private_material_exported"] is False
        location = posture["key_material_location"]
        assert "SIMULATED" in location
        assert "not a real TEE" in location
        joined = json.dumps(view)
        assert "PRIVATE" not in joined
