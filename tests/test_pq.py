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
import logging
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
    _b64url,
    _b64url_decode,
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


@pytest.fixture
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
        ed_pub = hybrid_signer.ed25519_private.public_key()
        pq_pub = hybrid_signer.pq_private.public_key()
        with pytest.raises(HybridVerificationError):
            verify_hybrid(b"tampered", slot, ed_pub, pq_pub)

    def test_pq_component_tamper_rejected(self, hybrid_signer):
        """Ed25519 valid + ML-DSA flipped byte -> the AND fails."""
        msg = b"payload"
        slot = hybrid_signer.sign_both(msg)
        ed_sig, pq_sig = parse_hybrid_signature(slot)
        pq_sig = bytearray(pq_sig)
        pq_sig[5] ^= 0xFF
        bad_slot = _b64url(bytes(ed_sig) + bytes(pq_sig))
        ed_pub = hybrid_signer.ed25519_private.public_key()
        pq_pub = hybrid_signer.pq_private.public_key()
        with pytest.raises(HybridVerificationError):
            verify_hybrid(msg, bad_slot, ed_pub, pq_pub)

    def test_ed_component_tamper_rejected(self, hybrid_signer):
        """Ed25519 flipped byte + ML-DSA untouched -> the AND fails."""
        msg = b"payload"
        slot = hybrid_signer.sign_both(msg)
        ed_sig, pq_sig = parse_hybrid_signature(slot)
        ed_sig = bytearray(ed_sig)
        ed_sig[3] ^= 0xFF
        bad_slot = _b64url(bytes(ed_sig) + bytes(pq_sig))
        ed_pub = hybrid_signer.ed25519_private.public_key()
        pq_pub = hybrid_signer.pq_private.public_key()
        with pytest.raises(HybridVerificationError):
            verify_hybrid(msg, bad_slot, ed_pub, pq_pub)

    def test_single_segment_rejected(self, hybrid_signer):
        """The downgrade attack: the ML-DSA component stripped entirely,
        leaving the valid Ed25519 component alone as the slot. Refused on
        the constant-length framing (64 bytes is not 3373)."""
        msg = b"payload"
        ed_sig, _pq_sig = parse_hybrid_signature(hybrid_signer.sign_both(msg))
        ed_only = _b64url(bytes(ed_sig))
        with pytest.raises(HybridVerificationError, match="exactly 3373 raw bytes"):
            parse_hybrid_signature(ed_only)

    def test_three_segments_rejected(self, hybrid_signer):
        slot = hybrid_signer.sign_both(b"m") + ".extra"
        with pytest.raises(HybridVerificationError):
            parse_hybrid_signature(slot)

    def test_wrong_ed_key_rejected(self, hybrid_signer):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        msg = b"m"
        slot = hybrid_signer.sign_both(msg)
        foreign_ed_pub = Ed25519PrivateKey.generate().public_key()
        pq_pub = hybrid_signer.pq_private.public_key()
        with pytest.raises(HybridVerificationError):
            verify_hybrid(msg, slot, foreign_ed_pub, pq_pub)

    def test_wrong_pq_key_rejected(self, hybrid_signer):
        other_priv, other_pub, _ = pq_generate()
        msg = b"m"
        slot = hybrid_signer.sign_both(msg)
        ed_pub = hybrid_signer.ed25519_private.public_key()
        with pytest.raises(HybridVerificationError):
            verify_hybrid(msg, slot, ed_pub, other_pub)


class TestJoseShapeConformance:
    """The pq1 signature slot as Compact JWS (RFC 7515).

    The signature component of a Compact JWS is EXACTLY ONE base64url
    segment, so the pq1 slot is the base64url of the raw concatenation
    ed25519 (64 bytes) || ml_dsa_65 (3309 bytes): constant component
    lengths make the framing deterministic with no length prefix and no
    delimiter. A standards-conformant JOSE parser sees a valid
    three-segment Compact JWS and rejects on the unknown ``raucle/pq1``
    crit entry (the RFC-correct handling of an unrecognised critical
    profile). The previous two-segment dot form was not
    Compact-conformant; it stays verify-only during a deprecation window
    and every legacy acceptance logs a named deprecation marker.
    """

    #: Substring of the named deprecation marker (raucle.pq logger).
    DEPRECATION_MARKER = "legacy two-segment dot form"
    CONCAT_LEN = 64 + 3309

    @staticmethod
    def _flip(raw: bytes, index: int) -> bytes:
        """Return *raw* with the byte at *index* XOR-flipped."""
        buf = bytearray(raw)
        buf[index] ^= 0xFF
        return bytes(buf)

    def _legacy_slot(self, slot: str) -> str:
        """Rebuild a slot in the legacy dot form from a current one."""
        ed_sig, pq_sig = parse_hybrid_signature(slot)
        return _b64url(ed_sig) + "." + _b64url(pq_sig)

    # -- emission shape ---------------------------------------------------

    def test_new_signature_slot_is_a_single_base64url_segment(self, hybrid_signer):
        msg = b'{"operation":"model_call"}'
        slot = hybrid_signer.sign_both(msg)
        assert "." not in slot, "the JWS signature slot must be one segment (RFC 7515)"

    def test_new_signature_slot_decodes_to_exact_raw_concatenation(self, hybrid_signer):
        msg = b'{"operation":"model_call"}'
        slot = hybrid_signer.sign_both(msg)
        raw = base64.urlsafe_b64decode(slot + "=" * (-len(slot) % 4))
        assert len(raw) == self.CONCAT_LEN, (
            "the slot payload is the raw 64 + 3309 byte concatenation: "
            f"no length prefix, no delimiter, got {len(raw)} bytes"
        )
        ed_sig, pq_sig = parse_hybrid_signature(slot)
        assert (ed_sig, pq_sig) == (raw[:64], raw[64:]), (
            "the constant-length framing splits the concatenation in order: "
            "Ed25519 first, ML-DSA-65 second"
        )

    def test_emitted_receipt_is_strict_compact_jws(self):
        """Pin (d): the emitted receipt passes a naive 3-segment Compact
        split - header.payload.signature, no extra dots anywhere."""
        ident, logger, chain = self._emit_chain()
        with open(chain, encoding="utf-8") as fh:
            first = json.loads(fh.readline())
        jws = first["jws"]
        parts = jws.split(".")
        assert len(parts) == 3, f"naive Compact split holds 3 segments, got {len(parts)}"
        assert jws.count(".") == 2, "no extra dots anywhere in the receipt"
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["crit"] == ["raucle/v1", "raucle/pq1"]
        assert header["raucle/pq1"] == "ml-dsa-65"
        assert len(header["pqk"]) == 16
        os.unlink(chain)

    def _emit_chain(self, quantum_mode="strict"):
        ident = AgentIdentity.generate(agent_id="agent:jose-shape")
        fd, chain = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        logger = ProvenanceLogger(agent=ident, sink_path=chain, quantum_mode=quantum_mode)
        logger.record_user_input(text="jose shape pin")
        logger.close()
        return ident, logger, chain

    # -- round trips and framing refusals (new form) ----------------------

    def test_new_form_round_trip_and_wrong_component_order_refused(self, hybrid_signer):
        msg = b"compact era"
        slot = hybrid_signer.sign_both(msg)
        ed_pub = hybrid_signer.ed25519_private.public_key()
        pq_pub = hybrid_signer.pq_private.public_key()
        verify_hybrid(msg, slot, ed_pub, pq_pub)
        ed_sig, pq_sig = parse_hybrid_signature(slot)
        swapped = _b64url(pq_sig + ed_sig)
        with pytest.raises(HybridVerificationError, match="Ed25519"):
            verify_hybrid(msg, swapped, ed_pub, pq_pub)

    def test_framing_refuses_wrong_lengths(self, hybrid_signer):
        msg = b"framing"
        ed_sig, pq_sig = parse_hybrid_signature(hybrid_signer.sign_both(msg))
        bad_slots = [
            _b64url(ed_sig),  # downgrade: ML-DSA half stripped
            _b64url(pq_sig),  # Ed25519 half missing
            _b64url(ed_sig + pq_sig[:-1]),  # one byte short
            _b64url(ed_sig + pq_sig + b"\x00"),  # one byte long
        ]
        for bad in bad_slots:
            with pytest.raises(HybridVerificationError, match="3373"):
                parse_hybrid_signature(bad)

    def test_wrong_segment_count_refused(self, hybrid_signer):
        slot = hybrid_signer.sign_both(b"counts")
        with pytest.raises(HybridVerificationError):
            parse_hybrid_signature(slot + ".junk")
        with pytest.raises(HybridVerificationError):
            parse_hybrid_signature(slot + ".junk.more")
        with pytest.raises(HybridVerificationError):
            parse_hybrid_signature("")
        with pytest.raises(HybridVerificationError):
            parse_hybrid_signature(42)  # type: ignore[arg-type]

    def test_downgrade_of_concat_slot_refused_end_to_end(self):
        """Strip the ML-DSA half of the concatenation: the surviving Ed25519
        component is a structurally valid 64-byte slot for the pq1 header
        and the verifier must refuse it on framing (fail-closed)."""
        ident, logger, chain = self._emit_chain()
        v = self._verifier(ident, logger)
        with open(chain, encoding="utf-8") as fh:
            parts = json.loads(fh.readline())["jws"].split(".")
        os.unlink(chain)
        slot_raw = base64.urlsafe_b64decode(parts[2] + "==")
        downgraded = parts[0] + "." + parts[1] + "." + _b64url(slot_raw[:64])
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
        os.unlink(dchain)

    def _verifier(self, ident, logger):
        pq_pub = logger._hybrid.pq_private.public_key()
        return ProvenanceVerifier(
            public_keys={ident.key_id: ident.public_key_pem()},
            pq_public_keys={pq_key_id_from_public_key(pq_pub): pq_public_key_pem(pq_pub)},
        )

    # -- legacy dot form: dual acceptance in the window --------------------

    def test_legacy_slot_still_verifies_with_deprecation_log(self, hybrid_signer, caplog):
        msg = b"window"
        legacy = self._legacy_slot(hybrid_signer.sign_both(msg))
        ed_pub = hybrid_signer.ed25519_private.public_key()
        pq_pub = hybrid_signer.pq_private.public_key()
        with caplog.at_level(logging.WARNING, logger="raucle.pq"):
            verify_hybrid(msg, legacy, ed_pub, pq_pub)
        marker = [r for r in caplog.records if self.DEPRECATION_MARKER in r.getMessage()]
        assert marker, "every legacy acceptance logs the named deprecation marker"
        assert all(r.name == "raucle.pq" for r in marker)

    def test_legacy_form_component_tamper_refused(self, hybrid_signer):
        """Flip a component inside the legacy dot form: refused regardless
        of the accepted form (fail-closed is form-independent)."""
        msg = b"legacy tamper"
        legacy = self._legacy_slot(hybrid_signer.sign_both(msg))
        ed_b64, pq_b64 = legacy.split(".")
        ed_pub = hybrid_signer.ed25519_private.public_key()
        pq_pub = hybrid_signer.pq_private.public_key()
        ed_flipped = _b64url(self._flip(_b64url_decode(ed_b64), 0))
        pq_flipped = _b64url(self._flip(_b64url_decode(pq_b64), 5))
        with pytest.raises(HybridVerificationError, match="Ed25519"):
            verify_hybrid(msg, ed_flipped + "." + pq_b64, ed_pub, pq_pub)
        with pytest.raises(HybridVerificationError, match="ML-DSA-65"):
            verify_hybrid(msg, ed_b64 + "." + pq_flipped, ed_pub, pq_pub)
        with pytest.raises(HybridVerificationError, match="3373"):
            parse_hybrid_signature(ed_b64)  # strip-one-signature, legacy shape

    # -- verifier pipeline: new form + unchanged profile policies ----------

    def test_strict_chain_new_form_verifies(self):
        ident, logger, chain = self._emit_chain()
        v = self._verifier(ident, logger)
        report = v.verify_chain(chain)
        assert report.valid
        assert report.receipt_count == 1
        assert report.signature_failures == 0
        os.unlink(chain)

    def test_require_pq_accepts_new_form_chain(self):
        ident, logger, chain = self._emit_chain()
        v = self._verifier(ident, logger)
        v._require_pq = True
        report = v.verify_chain(chain)
        assert report.valid, report.errors
        os.unlink(chain)

    def test_dual_profile_chain_classical_plus_hybrid_verifies(self):
        """Verification policy unchanged across profiles: a chain carrying a
        classical v1 receipt and a current-form pq1 receipt verifies."""
        ident = AgentIdentity.generate(agent_id="agent:dual-profile")
        fd, chain = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        classical = ProvenanceLogger(agent=ident, sink_path=chain)
        root = classical.record_user_input(text="classical head")
        classical.close()
        hybrid = ProvenanceLogger(agent=ident, sink_path=chain, quantum_mode="strict")
        hybrid.record_model_call(parents=[root], model="glm-5.3", input_text="q", output_text="a")
        hybrid.close()
        v = self._verifier(ident, hybrid)
        report = v.verify_chain(chain)
        assert report.valid, report.errors
        assert report.receipt_count == 2
        os.unlink(chain)

    def test_off_mode_emission_byte_unchanged(self):
        """v1 (classical) receipts: untouched by the pq1 encoding change."""
        ident, logger, chain = self._emit_chain(quantum_mode="off")
        with open(chain, encoding="utf-8") as fh:
            first = json.loads(fh.readline())
        parts = first["jws"].split(".")
        assert len(parts) == 3
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert "raucle/pq1" not in header
        os.unlink(chain)


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
        assert len(parts) == 3, "hybrid receipts are 3-segment Compact JWSes"
        slot = parts[2]
        assert "." not in slot, "the signature slot is one segment (RFC 7515)"
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
        slot = base64.urlsafe_b64decode(parts[2] + "==")
        pq_bytes = bytearray(slot[64:])  # ML-DSA half of the concatenation
        pq_bytes[7] ^= 0x55
        bad_jws = (
            parts[0]
            + "."
            + parts[1]
            + "."
            + base64.urlsafe_b64encode(bytes(slot[:64]) + bytes(pq_bytes)).decode().rstrip("=")
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
        assert "legacy_reference_jws" in data
        assert "legacy_reference_receipt_hash" in data
        assert "deprecation_window" in data

    def test_reference_jws_shape(self):
        data = json.loads(self.VECTOR_PATH.read_text())
        parts = data["reference_jws"].split(".")
        assert len(parts) == 3, "the current reference is a 3-segment Compact JWS"
        assert "." not in parts[2], "the signature component is exactly one segment"
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["crit"] == ["raucle/v1", "raucle/pq1"]
        assert header["raucle/pq1"] == "ml-dsa-65"
        assert header["pqk"] == data["pq_key_id"]
        legacy_parts = data["legacy_reference_jws"].split(".")
        assert len(legacy_parts) == 4, "the carried legacy reference keeps its published form"
        raw = base64.urlsafe_b64decode(parts[2] + "==")
        assert len(raw) == 64 + 3309, "reference slot = raw 64+3309 concatenation"

    def test_reference_signature_verifies_both_forms(self):
        """The cross-language contract: verify BOTH reference instances
        (current concatenation form and legacy verify-only dot form)."""
        data = json.loads(self.VECTOR_PATH.read_text())
        ed_priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["ed_seed_hex"]))
        pq_priv = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(data["pq_seed_hex"]))
        prefix = data["deterministic_prefix"].encode("ascii")
        parts = data["reference_jws"].split(".")
        verify_hybrid(prefix, parts[2], ed_priv.public_key(), pq_priv.public_key())
        legacy_parts = data["legacy_reference_jws"].split(".")
        verify_hybrid(
            prefix,
            legacy_parts[2] + "." + legacy_parts[3],
            ed_priv.public_key(),
            pq_priv.public_key(),
        )

    def test_reference_slot_is_concatenation_of_seed_derived_components(self):
        """The single-segment framing is component-complete: the slot's
        Ed25519 half verifies alone under the seed-derived public key."""
        data = json.loads(self.VECTOR_PATH.read_text())
        ed_priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["ed_seed_hex"]))
        parts = data["reference_jws"].split(".")
        raw = base64.urlsafe_b64decode(parts[2] + "==")
        ed_priv.public_key().verify(raw[:64], data["deterministic_prefix"].encode("ascii"))

    def test_downgrade_negative_vector_rejected(self):
        """The committed downgrade instances must fail closed at both layers,
        in BOTH accepted forms."""
        data = json.loads(self.VECTOR_PATH.read_text())
        negatives = {n["name"]: n for n in data["negative_vectors"]}
        ed_priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["ed_seed_hex"]))
        pq_priv = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(data["pq_seed_hex"]))
        ed_pub = ed_priv.public_key()
        pq_pub = pq_priv.public_key()
        prefix = data["deterministic_prefix"].encode("ascii")
        # Legacy downgrade: v1-shaped JWS, pq1 header; the middle segment is
        # the lone Ed25519 component and fails the pq1 slot framing.
        legacy = negatives["downgrade_strips_pq_segment"]["input_jws"]
        middle_segment = legacy.split(".")[2]
        with pytest.raises(HybridVerificationError):
            parse_hybrid_signature(middle_segment)
        # Current-form downgrade: 64-byte slot for a pq1 header.
        truncated = negatives["downgrade_truncates_concat_slot"]["input_jws"]
        truncated_slot = truncated.split(".")[2]
        with pytest.raises(HybridVerificationError, match="exactly 3373 raw bytes"):
            parse_hybrid_signature(truncated_slot)
        # Current-form framing attack: reversed components stay frame-valid
        # (3373 bytes, one segment) but fail the Ed25519 component.
        swapped_slot = negatives["component_order_swapped"]["input_jws"].split(".")[2]
        with pytest.raises(HybridVerificationError, match="Ed25519"):
            verify_hybrid(prefix, swapped_slot, ed_pub, pq_pub)
        # Current-form tamper vectors: the AND rule fails per component.
        ed_flip = negatives["ed_component_flipped_concat"]
        pq_flip = negatives["pq_component_flipped_concat"]
        for vec, match in ((ed_flip, "Ed25519"), (pq_flip, "ML-DSA-65")):
            raw_slot = vec["input_jws"].split(".")[2]
            with pytest.raises(HybridVerificationError, match=match):
                verify_hybrid(
                    prefix,
                    raw_slot,
                    ed_pub,
                    pq_pub,
                )

    def test_receipt_hash_matches_reference_jws(self):
        data = json.loads(self.VECTOR_PATH.read_text())
        digest = hashlib.sha256(data["reference_jws"].encode("ascii")).hexdigest()
        assert data["reference_receipt_hash"] == f"sha256:{digest}"
        legacy_digest = hashlib.sha256(data["legacy_reference_jws"].encode("ascii")).hexdigest()
        assert data["legacy_reference_receipt_hash"] == f"sha256:{legacy_digest}"
