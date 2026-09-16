"""Tests for quantum-ready hybrid signatures on the chain surfaces.

Covers the three surfaces beyond receipts (see pq1-hybrid.md roadmap):
- Audit chain checkpoints + chain_meta headers (HybridRecordSigner)
- Trust registry operator signatures + dual-key publish/resolve
- Capability tokens (issuer PQ key, hybrid mint, gate verification)

All tests skip automatically when ML-DSA is unavailable.
"""

import base64
import json
import os
import tempfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from raucle.audit import AuditVerifier, Ed25519Signer, HashChainSink
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.pq import (
    HybridRecordSigner,
    pq_generate,
    pq_public_key_pem,
)
from raucle.provenance import AgentIdentity, ProvenanceLogger, ProvenanceVerifier
from raucle.trust_registry import RegistryIntegrityError, TrustRegistry

pytestmark = pytest.mark.skipif(
    not __import__("raucle.pq", fromlist=["pq_available"]).pq_available(),
    reason="ML-DSA-65 unavailable in this cryptography build",
)


def _fresh_path(suffix: str = ".jsonl") -> str:
    fd, p = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    os.unlink(p)
    return p


@pytest.fixture()
def hybrid_signer():
    return HybridRecordSigner(Ed25519Signer.generate(), pq_generate()[0])


@pytest.fixture()
def pq_keys():
    priv, pub, kid = pq_generate()
    return priv, pub, kid


class TestAuditHybridCheckpoints:
    def test_hybrid_chain_verifies(self, hybrid_signer):
        # The verifier's PQ key must be the SIGNER's key (the fixtures are
        # independent keypairs), resolved from the signer itself.
        pq_pub = hybrid_signer._pq_private.public_key()
        pq_kid = hybrid_signer.pq_key_id()
        chain = _fresh_path()
        sink = HashChainSink(chain, signer=hybrid_signer, checkpoint_every=2)
        for i in range(4):
            sink.append({"event": "gate", "i": i})
        sink.close()
        v = AuditVerifier(
            public_key_pem=hybrid_signer.public_key_pem(),
            pq_public_keys={pq_kid: pq_public_key_pem(pq_pub)},
        )
        report = v.verify_chain(chain)
        assert report.valid
        assert report.valid_signatures == 3  # meta + 2 checkpoints
        os.unlink(chain)

    def test_checkpoint_carries_pq_fields(self, hybrid_signer):
        chain = _fresh_path()
        sink = HashChainSink(chain, signer=hybrid_signer, checkpoint_every=1)
        sink.append({"event": "x"})
        sink.close()
        found = False
        with open(chain, encoding="utf-8") as fh:
            for line in fh:
                rec = json.loads(line)
                if rec.get("checkpoint"):
                    assert rec.get("pq_key_id") == hybrid_signer.pq_key_id()
                    assert len(base64.b64decode(rec["pq_signature"])) == 3309
                    found = True
        assert found
        os.unlink(chain)

    def test_downgrade_stripped_chain_rejected_in_strict_mode(self, hybrid_signer, pq_keys):
        """Field-stripping leaves no in-band trace; require_pq closes it."""
        _, pq_pub, pq_kid = pq_keys
        chain = _fresh_path()
        sink = HashChainSink(chain, signer=hybrid_signer, checkpoint_every=1)
        sink.append({"event": "x"})
        sink.close()
        lines = []
        with open(chain, encoding="utf-8") as fh:
            for line in fh:
                rec = json.loads(line)
                rec.pop("pq_key_id", None)
                rec.pop("pq_signature", None)
                lines.append(json.dumps(rec))
        stripped = chain + ".stripped"
        with open(stripped, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        strict = AuditVerifier(
            public_key_pem=hybrid_signer.public_key_pem(),
            pq_public_keys={pq_kid: pq_public_key_pem(pq_pub)},
            require_pq=True,
        )
        report = strict.verify_chain(stripped)
        assert not report.valid
        os.unlink(chain)
        os.unlink(stripped)

    def test_hybrid_chain_without_verifier_pq_keys_fails_closed(self, hybrid_signer):
        chain = _fresh_path()
        sink = HashChainSink(chain, signer=hybrid_signer, checkpoint_every=1)
        sink.append({"event": "x"})
        sink.close()
        v = AuditVerifier(public_key_pem=hybrid_signer.public_key_pem())
        report = v.verify_chain(chain)
        assert not report.valid
        os.unlink(chain)

    def test_classical_chain_still_verifies(self):
        ed = Ed25519Signer.generate()
        chain = _fresh_path()
        sink = HashChainSink(chain, signer=ed, checkpoint_every=1)
        sink.append({"event": "x"})
        sink.close()
        v = AuditVerifier(public_key_pem=ed.public_key_pem())
        report = v.verify_chain(chain)
        assert report.valid
        os.unlink(chain)


class TestTrustRegistryHybrid:
    def _build(self, hybrid_signer, pq_keys):
        _, pq_pub, pq_kid = pq_keys
        reg_path = _fresh_path()
        reg = TrustRegistry(path=reg_path, operator_signer=hybrid_signer)
        agent = Ed25519PrivateKey.generate()
        agent_pem = (
            agent.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        reg.publish(agent_pem, issuer="acme.bank")
        pq_published = reg.publish_pq_key(pq_public_key_pem(pq_pub), issuer="acme.bank")
        return reg, reg_path, pq_published, pq_pub

    def test_publish_and_resolve_pq_key(self, hybrid_signer, pq_keys):
        reg, reg_path, pq_kid, pq_pub = self._build(hybrid_signer, pq_keys)
        assert reg.resolve_pq_key(pq_kid) == pq_public_key_pem(pq_pub)
        reg.verify_integrity()
        os.unlink(reg_path)

    def test_revoke_pq_key_fails_closed(self, hybrid_signer, pq_keys):
        reg, reg_path, pq_kid, pq_pub = self._build(hybrid_signer, pq_keys)
        reg.revoke(pq_kid, reason="rotated")
        assert reg.resolve_pq_key(pq_kid) is None
        reg.verify_integrity()
        os.unlink(reg_path)

    def test_wrong_operator_pq_key_rejected(self, hybrid_signer, pq_keys):
        reg, reg_path, pq_kid, pq_pub = self._build(hybrid_signer, pq_keys)
        other_pub = pq_generate()[1]
        with pytest.raises(RegistryIntegrityError):
            reg.verify_integrity(
                operator_public_pem=hybrid_signer.public_key_pem(),
                operator_pq_public_pem=pq_public_key_pem(other_pub),
            )
        os.unlink(reg_path)

    def test_issuer_uniqueness_allows_hybrid_pair(self, hybrid_signer, pq_keys):
        """Same issuer's Ed25519 + ML-DSA keys coexist (the hybrid design);
        two different classical keys under one name still collide."""
        reg, reg_path, pq_kid, pq_pub = self._build(hybrid_signer, pq_keys)
        reg.verify_integrity()  # classical + PQ under 'acme.bank' is fine
        with pytest.raises(ValueError):
            other = Ed25519PrivateKey.generate()
            other_pem = (
                other.public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode()
            )
            reg.publish(other_pem, issuer="acme.bank")
        os.unlink(reg_path)

    def test_receipt_verified_via_registry_resolved_pq_key(self, hybrid_signer, pq_keys):
        """Full circle: hybrid receipt verified with the PQ key resolved from
        the registry alone."""
        reg, reg_path, pq_kid, pq_pub = self._build(hybrid_signer, pq_keys)
        ident = AgentIdentity.generate(agent_id="agent:circle")
        chain = _fresh_path()
        log = ProvenanceLogger(
            agent=ident,
            sink_path=chain,
            quantum_mode="strict",
            pq_private_key=pq_keys[0],
        )
        log.record_user_input(text="registry circle")
        log.close()
        verifier = ProvenanceVerifier(
            public_keys={ident.key_id: ident.public_key_pem()},
            pq_public_keys={pq_kid: reg.resolve_pq_key(pq_kid)},
        )
        report = verifier.verify_chain(chain)
        assert report.valid
        os.unlink(reg_path)
        os.unlink(chain)


class TestHybridCapabilityTokens:
    def _issuer_and_gate(self, pq_keys):
        pq_priv, pq_pub, pq_kid = pq_keys
        ed = Ed25519PrivateKey.generate()
        issuer = CapabilityIssuer(issuer="acme.bank", private_key=ed, pq_private=pq_priv)
        gate = CapabilityGate(
            trusted_issuers={issuer.key_id: issuer.public_key_pem},
            pq_public_keys={pq_kid: pq_public_key_pem(pq_pub)},
        )
        gate_classical = CapabilityGate(trusted_issuers={issuer.key_id: issuer.public_key_pem})
        return issuer, gate, gate_classical

    def _hybrid_token(self, issuer):
        return issuer.mint(
            agent_id="agent:pay",
            tool="transfer_money",
            constraints={"allowed_values": {"account": ["ACC-1"]}},
            ttl_seconds=600,
            quantum=True,
        )

    def test_hybrid_token_gate_allows(self, pq_keys):
        issuer, gate, _ = self._issuer_and_gate(pq_keys)
        cap = self._hybrid_token(issuer)
        decision = gate.check(
            cap, tool="transfer_money", agent_id="agent:pay", args={"account": "ACC-1"}
        )
        assert decision.allowed

    def test_serialization_preserves_pq_fields(self, pq_keys):
        issuer, gate, _ = self._issuer_and_gate(pq_keys)
        cap = self._hybrid_token(issuer)
        d = cap.to_dict()
        assert "pq_key_id" in d and "pq_signature" in d
        cap2 = type(cap).from_dict(d)
        assert cap2.pq_key_id == cap.pq_key_id
        decision = gate.check(
            cap2, tool="transfer_money", agent_id="agent:pay", args={"account": "ACC-1"}
        )
        assert decision.allowed

    def test_hybrid_token_without_gate_pq_keys_fails_closed(self, pq_keys):
        issuer, _, gate_classical = self._issuer_and_gate(pq_keys)
        cap = self._hybrid_token(issuer)
        decision = gate_classical.check(
            cap, tool="transfer_money", agent_id="agent:pay", args={"account": "ACC-1"}
        )
        assert not decision.allowed
        assert "ML-DSA-65" in decision.reason

    def test_pq_signature_tamper_rejected(self, pq_keys):
        issuer, gate, _ = self._issuer_and_gate(pq_keys)
        cap = self._hybrid_token(issuer)
        d = cap.to_dict()
        d["pq_signature"] = (
            ("B" + d["pq_signature"][1:])
            if d["pq_signature"][0] != "B"
            else ("C" + d["pq_signature"][1:])
        )
        cap2 = type(cap).from_dict(d)
        decision = gate.check(
            cap2, tool="transfer_money", agent_id="agent:pay", args={"account": "ACC-1"}
        )
        assert not decision.allowed

    def test_classical_token_unchanged(self, pq_keys):
        issuer, gate, gate_classical = self._issuer_and_gate(pq_keys)
        cap = issuer.mint(agent_id="agent:pay", tool="transfer_money", ttl_seconds=600)
        assert cap.pq_key_id is None
        assert gate.check(cap, tool="transfer_money", agent_id="agent:pay").allowed
        assert gate_classical.check(cap, tool="transfer_money", agent_id="agent:pay").allowed

    def test_quantum_without_issuer_pq_key_rejected(self):
        issuer = CapabilityIssuer.generate(issuer="no.pq")
        with pytest.raises(ValueError, match="ML-DSA-65"):
            issuer.mint(agent_id="agent:x", tool="t_tool", quantum=True)

    def test_foreign_pq_key_type_rejected(self, pq_keys):
        with pytest.raises(TypeError, match="MLDSA65PrivateKey"):
            CapabilityIssuer(
                issuer="bad.type",
                private_key=Ed25519PrivateKey.generate(),
                pq_private=Ed25519PrivateKey.generate(),
            )
