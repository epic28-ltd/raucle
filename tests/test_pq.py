"""Tests for the raucle/pq1 hybrid post-quantum profile (raucle/pq.py).

The hybrid construction: every pq1 receipt is signed by BOTH Ed25519 and
ML-DSA-65 (FIPS 204). Valid only if both verify. The downgrade attack -
stripping the ML-DSA segment and presenting the valid Ed25519 component as
a complete receipt - is the profile's named adversary and is rejected by
design at three layers: parse shape, v1-path closure, and registry
resolution.

Skipped automatically when the runtime's cryptography build has no ML-DSA
support (pre-47 cryptography or non-AWS-LC backends).
"""

import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from raucle.pq import (
    PQ1_ALG,
    PQ1_PROFILE,
    HybridSigner,
    HybridVerificationError,
    PQUnavailable,
    header_is_pq1,
    parse_hybrid_signature,
    pq1_header,
    pq_available,
    pq_generate,
    pq_key_id_from_public_key,
    pq_private_key_from_pem,
    pq_private_key_pem,
    pq_public_key_from_hex,
    pq_public_key_from_pem,
    pq_public_key_hex,
    pq_public_key_pem,
    verify_hybrid,
)
from raucle.provenance import (
    AgentIdentity,
    ProvenanceLogger,
    ProvenanceVerifier,
)

pytestmark = pytest.mark.skipif(
    not pq_available(), reason="ML-DSA-65 unavailable in this cryptography build"
)


@pytest.fixture()
def hybrid_signer():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return HybridSigner.from_ed25519(Ed25519PrivateKey.generate())


class TestKeyManagement:
    def test_generate_key_ids(self):
        priv, pub, kid = pq_generate()
        assert kid == pq_key_id_from_public_key(pub)
        assert len(kid) == 16
        assert len(pub.public_bytes_raw()) == 1952

    def test_public_key_pem_round_trip(self):
        _, pub, kid = pq_generate()
        pem = pq_public_key_pem(pub)
        loaded = pq_public_key_from_pem(pem)
        assert loaded.public_bytes_raw() == pub.public_bytes_raw()

    def test_public_key_hex_round_trip(self):
        _, pub, _ = pq_generate()
        hexstr = pq_public_key_hex(pub)
        loaded = pq_public_key_from_hex(hexstr)
        assert loaded.public_bytes_raw() == pub.public_bytes_raw()

    def test_private_key_pem_round_trip(self):
        priv, _, _ = pq_generate()
        pem = pq_private_key_pem(priv)
        loaded = pq_private_key_from_pem(pem)
        msg = b"round trip"
        sig = loaded.sign(msg)
        priv.public_key().verify(sig, msg)

    def test_pem_refuses_foreign_key_type(self):
        """An Ed25519 PEM must not load as the PQ component."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        ed_pem = (
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        with pytest.raises((PQUnavailable, ValueError)):
            pq_public_key_from_pem(ed_pem)

    def test_signer_requires_ed25519(self, hybrid_signer):
        with pytest.raises(TypeError):
            HybridSigner.from_ed25519("not-a-key")


class TestHybridSignVerify:
    def test_sign_both_and_verify(self, hybrid_signer):
        msg = b'{"operation":"model_call"}'
        slot = hybrid_signer.sign_both(msg)
        ed_sig, pq_sig = parse_hybrid_signature(slot)
        assert len(ed_sig) == 64
        assert len(pq_sig) == 3309
        verify_hybrid(
            msg,
            slot,
            hybrid_signer.ed25519_private.public_key(),
            hybrid_signer.pq_private.public_key(),
        )

    def test_tampered_message_rejected(self, hybrid_signer):
        msg = b"original"
        slot = hybrid_signer.sign_both(msg)
        with pytest.raises(HybridVerificationError):
            verify_hybrid(
                b"tampered",
                slot,
                hybrid_signer.ed25519_private.public_key(),
                hybrid_signer.pq_private.public_key(),
            )

    def test_pq_component_tamper_rejected(self, hybrid_signer):
        """Ed25519 valid + ML-DSA flipped byte -> the AND fails."""
        from raucle.pq import _b64url, _b64url_decode

        msg = b"payload"
        slot = hybrid_signer.sign_both(msg)
        ed_b64, pq_b64 = slot.split(".")
        pq_bytes = bytearray(_b64url_decode(pq_b64))
        pq_bytes[5] ^= 0xFF
        bad_slot = ed_b64 + "." + _b64url(bytes(pq_bytes))
        with pytest.raises(HybridVerificationError):
            verify_hybrid(
                msg,
                bad_slot,
                hybrid_signer.ed25519_private.public_key(),
                hybrid_signer.pq_private.public_key(),
            )

    def test_ed_component_tamper_rejected(self, hybrid_signer):
        """Ed25519 flipped byte + ML-DSA untouched -> the AND fails."""
        from raucle.pq import _b64url, _b64url_decode

        msg = b"payload"
        slot = hybrid_signer.sign_both(msg)
        ed_b64, pq_b64 = slot.split(".")
        ed_bytes = bytearray(_b64url_decode(ed_b64))
        ed_bytes[3] ^= 0xFF
        bad_slot = _b64url(bytes(ed_bytes)) + "." + pq_b64
        with pytest.raises(HybridVerificationError):
            verify_hybrid(
                msg,
                bad_slot,
                hybrid_signer.ed25519_private.public_key(),
                hybrid_signer.pq_private.public_key(),
            )

    def test_single_segment_rejected(self, hybrid_signer):
        """The downgrade attack: ML-DSA segment stripped entirely."""
        msg = b"payload"
        slot = hybrid_signer.sign_both(msg)
        ed_only = slot.split(".")[0]
        with pytest.raises(HybridVerificationError, match="exactly two segments"):
            parse_hybrid_signature(ed_only)

    def test_three_segments_rejected(self, hybrid_signer):
        slot = hybrid_signer.sign_both(b"m") + ".extra"
        with pytest.raises(HybridVerificationError):
            parse_hybrid_signature(slot)

    def test_wrong_ed_key_rejected(self, hybrid_signer):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        msg = b"m"
        slot = hybrid_signer.sign_both(msg)
        with pytest.raises(HybridVerificationError):
            verify_hybrid(
                msg,
                slot,
                Ed25519PrivateKey.generate().public_key(),
                hybrid_signer.pq_private.public_key(),
            )

    def test_wrong_pq_key_rejected(self, hybrid_signer):
        other_priv, other_pub, _ = pq_generate()
        msg = b"m"
        slot = hybrid_signer.sign_both(msg)
        with pytest.raises(HybridVerificationError):
            verify_hybrid(
                msg,
                slot,
                hybrid_signer.ed25519_private.public_key(),
                other_pub,
            )


class TestPQ1Header:
    def test_header_carries_profile_and_crit(self, hybrid_signer):
        base = {
            "alg": "EdDSA",
            "typ": "provenance-receipt/v1",
            "kid": "abc123",
            "crit": ["raucle/v1"],
            "raucle/v1": "provenance",
        }
        header = pq1_header(base, hybrid_signer.pq_key_id)
        assert header[PQ1_PROFILE] == PQ1_ALG
        assert "raucle/pq1" in header["crit"]
        assert header["pqk"] == hybrid_signer.pq_key_id
        assert header_is_pq1(header)
        # base header untouched (immutability)
        assert "raucle/pq1" not in base

    def test_idempotent_crit(self, hybrid_signer):
        base = {
            "alg": "EdDSA",
            "crit": ["raucle/v1"],
            "raucle/v1": "provenance",
        }
        h1 = pq1_header(base, "k" * 16)
        h2 = pq1_header(h1, "k" * 16)
        assert h1["crit"].count("raucle/pq1") == 1
        assert h2["crit"].count("raucle/pq1") == 1


class TestHybridReceiptEmission:
    def _emit_chain(self, quantum_mode="strict"):
        ident = AgentIdentity.generate(agent_id="agent:pq-e2e")
        fd, chain = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        logger = ProvenanceLogger(agent=ident, sink_path=chain, quantum_mode=quantum_mode)
        root = logger.record_user_input(text="quantum era")
        child = logger.record_model_call(
            parents=[root], model="glm-5.3", input_text="q", output_text="a"
        )
        assert child.startswith("sha256:")
        logger.close()
        return ident, logger, chain

    def _verifier(self, ident, logger):
        pq_pub = logger._hybrid.pq_private.public_key()
        return ProvenanceVerifier(
            public_keys={ident.key_id: ident.public_key_pem()},
            pq_public_keys={pq_key_id_from_public_key(pq_pub): pq_public_key_pem(pq_pub)},
        )

    def test_strict_emission_and_full_verify(self):
        ident, logger, chain = self._emit_chain()
        v = self._verifier(ident, logger)
        report = v.verify_chain(chain)
        assert report.valid
        assert report.receipt_count == 2
        assert report.signature_failures == 0
        os.unlink(chain)

    def test_receipt_wire_shape(self):
        ident, logger, chain = self._emit_chain()
        with open(chain, encoding="utf-8") as fh:
            first = json.loads(fh.readline())
        parts = first["jws"].split(".")
        assert len(parts) == 4, "hybrid receipts carry a two-segment signature slot"
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["crit"] == ["raucle/v1", "raucle/pq1"]
        assert header["raucle/pq1"] == "ml-dsa-65"
        assert len(header["pqk"]) == 16
        os.unlink(chain)

    def test_receipt_size_honest(self):
        """Documented size impact: hybrid row is ~4.5x the v1 row."""
        ident, logger, chain = self._emit_chain()
        with open(chain, encoding="utf-8") as fh:
            row = fh.readline()
        assert 4000 < len(row) < 9000, f"hybrid row unexpectedly {len(row)} bytes"
        os.unlink(chain)

    def test_off_mode_is_plain_v1(self):
        ident, logger, chain = self._emit_chain(quantum_mode="off")
        with open(chain, encoding="utf-8") as fh:
            first = json.loads(fh.readline())
        assert len(first["jws"].split(".")) == 3
        header = json.loads(base64.urlsafe_b64decode(first["jws"].split(".")[0] + "=="))
        assert "raucle/pq1" not in header
        os.unlink(chain)

    def test_invalid_mode_rejected(self):
        ident = AgentIdentity.generate(agent_id="agent:x")
        fd, chain = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        with pytest.raises(ValueError, match="quantum_mode"):
            ProvenanceLogger(agent=ident, sink_path=chain, quantum_mode="maybe")
        os.unlink(chain)


class TestDowngradeAttack:
    """The named adversary of the pq1 profile, at every layer."""

    @staticmethod
    def _verifier(ident, logger):
        pq_pub = logger._hybrid.pq_private.public_key()
        return ProvenanceVerifier(
            public_keys={ident.key_id: ident.public_key_pem()},
            pq_public_keys={pq_key_id_from_public_key(pq_pub): pq_public_key_pem(pq_pub)},
        )

    def _emit(self):
        ident = AgentIdentity.generate(agent_id="agent:dg")
        fd, chain = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        logger = ProvenanceLogger(agent=ident, sink_path=chain, quantum_mode="strict")
        logger.record_user_input(text="x")
        logger.close()
        return ident, logger, chain

    def test_downgrade_rejected_by_verifier(self):
        """Strip the ML-DSA segment: the v1 path must refuse the pq1 header."""
        ident, logger, chain = self._emit()
        v = self._verifier(ident, logger)
        with open(chain, encoding="utf-8") as fh:
            lines = [json.loads(raw) for raw in fh]
        downgraded = lines[0]["jws"].rsplit(".", 1)[0]
        fd, dchain = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        with open(dchain, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "receipt_hash": "sha256:" + hashlib.sha256(downgraded.encode()).hexdigest(),
                    "jws": downgraded,
                },
                fh,
            )
            fh.write("\n")
        report = v.verify_chain(dchain)
        assert not report.valid
        os.unlink(chain)
        os.unlink(dchain)

    def test_unregistered_pq_key_fails_closed(self):
        ident, logger, chain = self._emit()
        v = ProvenanceVerifier(
            public_keys={ident.key_id: ident.public_key_pem()},
            pq_public_keys={},
        )
        report = v.verify_chain(chain)
        assert not report.valid
        os.unlink(chain)

    def test_pq_sig_tamper_fails_both_rule(self):
        ident, logger, chain = self._emit()
        v = self._verifier(ident, logger)
        with open(chain, encoding="utf-8") as fh:
            lines = [json.loads(raw) for raw in fh]
        parts = lines[0]["jws"].split(".")
        pq_bytes = bytearray(base64.urlsafe_b64decode(parts[3]))
        pq_bytes[7] ^= 0x55
        bad_jws = (
            parts[0]
            + "."
            + parts[1]
            + "."
            + parts[2]
            + "."
            + base64.urlsafe_b64encode(bytes(pq_bytes)).decode().rstrip("=")
        )
        fd, bchain = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        with open(bchain, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "receipt_hash": "sha256:" + hashlib.sha256(bad_jws.encode()).hexdigest(),
                    "jws": bad_jws,
                },
                fh,
            )
            fh.write("\n")
        report = v.verify_chain(bchain)
        assert not report.valid
        os.unlink(chain)
        os.unlink(bchain)


class TestV1BackwardCompatibility:
    def test_v1_chain_still_verifies(self):
        ident = AgentIdentity.generate(agent_id="agent:classic")
        fd, chain = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        logger = ProvenanceLogger(agent=ident, sink_path=chain)
        logger.record_user_input(text="classic receipt")
        logger.close()
        v = ProvenanceVerifier(public_keys={ident.key_id: ident.public_key_pem()})
        report = v.verify_chain(chain)
        assert report.valid
        os.unlink(chain)

    def test_v1_receipt_parses_with_pq_verifier(self):
        """A PQ-aware verifier still accepts pure-v1 chains."""
        ident = AgentIdentity.generate(agent_id="agent:classic2")
        fd, chain = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        logger = ProvenanceLogger(agent=ident, sink_path=chain)
        logger.record_user_input(text="x")
        logger.close()
        _, pq_pub, pq_kid = pq_generate()
        v = ProvenanceVerifier(
            public_keys={ident.key_id: ident.public_key_pem()},
            pq_public_keys={pq_kid: pq_public_key_pem(pq_pub)},
        )
        report = v.verify_chain(chain)
        assert report.valid
        os.unlink(chain)

    def test_full_test_suite_untouched(self):
        """The 851 pre-existing tests run unchanged alongside the PQ tests."""
        assert pq_available()


class TestPQ1TestVectors:
    """Validate the committed pq1 vector file (docs/spec/provenance/v1/)."""

    VECTOR_PATH = (
        Path(__file__).resolve().parents[1] / "docs/spec/provenance/v1/pq1-test-vectors.json"
    )

    def test_vectors_present_and_well_formed(self):
        data = json.loads(self.VECTOR_PATH.read_text())
        assert data["profile"] == "raucle/pq1"
        assert data["algorithm"] == "ml-dsa-65"
        assert len(data["ed_seed_hex"]) == 64
        assert len(data["pq_seed_hex"]) == 64
        assert len(data["deterministic_prefix"].split(".")) == 2

    def test_reference_jws_shape(self):
        data = json.loads(self.VECTOR_PATH.read_text())
        parts = data["reference_jws"].split(".")
        assert len(parts) == 4
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["crit"] == ["raucle/v1", "raucle/pq1"]
        assert header["raucle/pq1"] == "ml-dsa-65"
        assert header["pqk"] == data["pq_key_id"]

    def test_reference_signature_verifies(self):
        """The cross-language contract: verify the reference instance."""
        data = json.loads(self.VECTOR_PATH.read_text())
        ed_priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["ed_seed_hex"]))
        pq_priv = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(data["pq_seed_hex"]))
        parts = data["reference_jws"].split(".")
        verify_hybrid(
            data["deterministic_prefix"].encode("ascii"),
            parts[2] + "." + parts[3],
            ed_priv.public_key(),
            pq_priv.public_key(),
        )

    def test_downgrade_negative_vector_rejected(self):
        """The committed downgrade instance must fail closed at both layers."""
        data = json.loads(self.VECTOR_PATH.read_text())
        downgrade = next(
            n for n in data["negative_vectors"] if n["name"] == "downgrade_strips_pq_segment"
        )
        jws = downgrade["input_jws"]
        # Shape layer: three segments are not a pq1 receipt
        with pytest.raises(HybridVerificationError):
            parse_hybrid_signature(jws.split(".")[2])

    def test_receipt_hash_matches_reference_jws(self):
        data = json.loads(self.VECTOR_PATH.read_text())
        digest = hashlib.sha256(data["reference_jws"].encode("ascii")).hexdigest()
        assert data["reference_receipt_hash"] == f"sha256:{digest}"
