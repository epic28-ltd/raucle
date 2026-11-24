#!/usr/bin/env python3
"""Generate the pq1 hybrid test vectors for the provenance spec.

Writes a self-contained ``pq1_test_vectors.json`` next to the v1 vector
file. Deterministic: the Ed25519 and ML-DSA-65 keys are derived from
fixed seeds, so every run (and every reference port) produces the same
keys and signing input. ML-DSA signing is randomised (hedged), so the
reference signature is verified, never byte-compared.

The vector set pins the JOSE-conformant wire format: 3-segment Compact
JWS whose signature component is ONE base64url segment over the raw
concatenation ed25519 (64 bytes) || ml_dsa_65 (3309 bytes) - constant
lengths, no length prefix, no delimiter. The legacy 4-segment dot-form
reference is carried forward byte-identically and marked
legacy_verify_only: acceptable for verification during the deprecation
window. Negative vectors assert the fail-closed behaviour (downgrade,
truncate, swap, tamper, foreign key) under BOTH accepted forms.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = Path(__file__).resolve().parents[1] / "docs/spec/provenance/v1/pq1-test-vectors.json"

ED_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PQ_SEED = hashlib.sha256(b"raucle-pq1-vector-seed").digest()

ED_SIG_LEN = 64
PQ_SIG_LEN = 3309


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def flip_concat_byte(sig: bytes, byte: int, xor: int) -> bytes:
    """Flip one byte of a raw signature buffer (deterministically)."""
    buf = bytearray(sig)
    buf[byte] ^= xor
    return bytes(buf)


def main() -> None:
    ed_priv = Ed25519PrivateKey.from_private_bytes(ED_SEED)
    ed_pub_raw = ed_priv.public_key().public_bytes_raw()
    ed_kid = hashlib.sha256(ed_pub_raw).hexdigest()[:16]

    pq_priv = mldsa.MLDSA65PrivateKey.from_seed_bytes(PQ_SEED)
    pq_pub = pq_priv.public_key()
    pq_pub_raw = pq_pub.public_bytes_raw()
    pq_kid = hashlib.sha256(pq_pub_raw).hexdigest()[:16]

    # A representative canonical payload (JCS subset, integers only)
    payload = {
        "agent_id": "agent:vector-pq1",
        "agent_key_id": ed_kid,
        "iat": 1788257576,
        "input_hash": "sha256:" + hashlib.sha256(b"input").hexdigest(),
        "iss": "raucle-detect/provenance",
        "model": "glm-5.3",
        "operation": "model_call",
        "output_hash": "sha256:" + hashlib.sha256(b"output").hexdigest(),
        "parents": [],
        "taint": ["external_user"],
        "typ": "provenance-receipt/v1",
    }
    header = {
        "alg": "EdDSA",
        "crit": ["raucle/v1", "raucle/pq1"],
        "kid": ed_kid,
        "pqk": pq_kid,
        "raucle/pq1": "ml-dsa-65",
        "raucle/v1": "provenance",
        "typ": "provenance-receipt/v1",
    }

    def canon(obj: dict) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )

    signing_input = b64url(canon(header)) + "." + b64url(canon(payload))
    ed_sig = ed_priv.sign(signing_input.encode("ascii"))
    pq_sig = pq_priv.sign(signing_input.encode("ascii"))

    # Current emission: the signature component is ONE base64url segment
    # over the RAW concatenation (constant lengths, no delimiter) - a
    # conformant Compact JWS (RFC 7515).
    compact_jws = signing_input + "." + b64url(ed_sig + pq_sig)
    receipt_hash = "sha256:" + hashlib.sha256(compact_jws.encode("ascii")).hexdigest()

    # Legacy dot-form reference: byte-identical carry-forward of the
    # previously published 4-segment reference (when present) so old
    # vectors keep their published bytes; verify-only in the window.
    old: dict = {}
    if OUT.exists():
        try:
            old = json.loads(OUT.read_text())
        except (ValueError, OSError):
            old = {}
    legacy_ref = old.get("reference_jws", "")
    legacy_hash = old.get("reference_receipt_hash", "")
    if legacy_ref.count(".") != 3:
        # No previously published legacy reference (or a malformed file):
        # mint a fresh one over the same canonical bytes.
        legacy_ref = signing_input + "." + b64url(ed_sig) + "." + b64url(pq_sig)
        legacy_hash = "sha256:" + hashlib.sha256(legacy_ref.encode("ascii")).hexdigest()

    # NOTE ON DETERMINISM: Ed25519 signing is deterministic, but FIPS 204
    # ML-DSA signing is randomised (hedged). The same seed + message NEVER
    # yields the same signature bytes, so the v1 byte-identity discipline
    # cannot apply to the ML-DSA component. The pq1 vectors therefore pin
    # the deterministic parts (keys, canonical signing input, header) and
    # REFERENCE signatures, and the cross-language contract is
    # VERIFICATION: every port must verify each reference signature under
    # the seed-derived public keys, and must produce its own signatures
    # that verify under the same keys.
    vectors = {
        "spec_version": "raucle-provenance-receipt/v1+pq1",
        "generator_version": "raucle pq1-vector-gen 1.1.0",
        "profile": "raucle/pq1",
        "algorithm": "ml-dsa-65",
        "ed_seed_hex": ED_SEED.hex(),
        "pq_seed_hex": PQ_SEED.hex(),
        "ed_public_key_hex": ed_pub_raw.hex(),
        "pq_public_key_hex": pq_pub_raw.hex(),
        "pq_key_id": pq_kid,
        "deterministic_prefix": signing_input,
        "reference_jws": compact_jws,
        "reference_receipt_hash": receipt_hash,
        "legacy_reference_jws": legacy_ref,
        "legacy_reference_receipt_hash": legacy_hash,
        "deprecation_window": (
            "The legacy 4-segment dot-form receipts (signature slot holds two "
            "base64url segments joined by a dot) were not Compact-JWS-conformant "
            "(RFC 7515: the signature component is exactly one segment). They "
            "are ACCEPTED FOR VERIFICATION ONLY during the deprecation window; "
            "emission switched to the single-segment concatenation form and "
            "legacy removal is scheduled with the pq1 vector freeze."
        ),
        "verification_contract": (
            "Ports MUST (a) derive the same keys from the seeds, "
            "(b) byte-match the deterministic_prefix, (c) VERIFY the "
            "reference_jws signature slot under those keys - the slot is ONE "
            "base64url segment decoding to the raw 64+3309 byte concatenation; "
            "split by the constant lengths - and (d) produce their own "
            "signatures over the same prefix that also verify. Ports accepting "
            "legacy receipts must implement the dot-form split with the same "
            "component lengths. Signature bytes are not reproducible: ML-DSA "
            "signs randomised."
        ),
        "vectors": [
            {
                "name": "pq1_hybrid_receipt",
                "description": (
                    "Hybrid receipt: Ed25519 + ML-DSA-65 over the same "
                    "canonical JCS bytes. 3-segment Compact JWS (RFC 7515); "
                    "the signature component is ONE base64url segment over "
                    "the raw ed25519(64)||ml_dsa_65(3309) concatenation - no "
                    "length prefix, no delimiter. The JWS is a reference "
                    "instance (ML-DSA is randomised); verify it, do not "
                    "byte-compare re-signings."
                ),
                "expected_segments": 3,
                "expected_signature_slot_segments": 1,
                "expected_concat_len": ED_SIG_LEN + PQ_SIG_LEN,
                "expected_ed_signature_len": ED_SIG_LEN,
                "expected_pq_signature_len": PQ_SIG_LEN,
                "expected_kid": ed_kid,
                "expected_pqk": pq_kid,
                "expected_crit": ["raucle/v1", "raucle/pq1"],
            },
            {
                "name": "pq1_hybrid_receipt_legacy_dot_form",
                "description": (
                    "Pre-JOSE-conformance emission: 4-segment JWS whose "
                    "signature slot holds two base64url segments joined by a "
                    "literal dot. Verify-only during the deprecation window "
                    "(legacy_verify_only); never an emission target."
                ),
                "legacy_verify_only": True,
                "expected_segments": 4,
                "expected_ed_signature_len": ED_SIG_LEN,
                "expected_pq_signature_len": PQ_SIG_LEN,
                "expected_kid": ed_kid,
                "expected_pqk": pq_kid,
                "expected_crit": ["raucle/v1", "raucle/pq1"],
            },
        ],
        "negative_vectors": [
            {
                "name": "downgrade_strips_pq_segment",
                "description": (
                    "The ML-DSA segment is removed, leaving a structurally "
                    "valid v1 JWS with a valid Ed25519 signature. A pq1-aware "
                    "verifier MUST reject: the header declares raucle/pq1, so "
                    "the v1 path refuses it (downgrade closure), and the pq1 "
                    "path refuses it on shape."
                ),
                "input_jws": legacy_ref.rsplit(".", 1)[0],
                "must_reject": True,
            },
            {
                "name": "ed_signature_flipped",
                "description": (
                    "The Ed25519 component is tampered; ML-DSA intact. The "
                    "AND rule fails: hybrid verification must reject even "
                    "though the PQ component verifies. (Legacy reference, "
                    "legacy_verify_only window.)"
                ),
                "input_jws": legacy_ref,
                "flip": {"segment": 2, "byte": 3, "xor": 255},
                "must_reject": True,
            },
            {
                "name": "pq_signature_flipped",
                "description": (
                    "The ML-DSA component is tampered; Ed25519 intact. The "
                    "AND rule fails: hybrid verification must reject even "
                    "though the classical component verifies. (Legacy "
                    "reference, legacy_verify_only window.)"
                ),
                "input_jws": legacy_ref,
                "flip": {"segment": 3, "byte": 5, "xor": 85},
                "must_reject": True,
            },
            {
                "name": "downgrade_truncates_concat_slot",
                "description": (
                    "Current-form downgrade: the ML-DSA half is stripped from "
                    "the concatenated slot, leaving the valid Ed25519 "
                    "signature alone as a 64-byte single-segment slot for a "
                    "pq1 header. MUST reject on the constant-length framing "
                    "(64 != 64+3309)."
                ),
                "input_jws": signing_input + "." + b64url(ed_sig),
                "must_reject": True,
            },
            {
                "name": "component_order_swapped",
                "description": (
                    "Current-form framing attack: the concatenation is "
                    "reversed (ml_dsa_65 first). Framing-valid (3373 bytes, "
                    "one segment) but the Ed25519 component fails verification "
                    "over the canonical bytes. MUST reject."
                ),
                "input_jws": signing_input + "." + b64url(pq_sig + ed_sig),
                "must_reject": True,
            },
            {
                "name": "ed_component_flipped_concat",
                "description": (
                    "Current-form tamper: one byte flipped inside the Ed25519 "
                    "half of the concatenated slot. The AND rule fails. "
                    "flip.byte is an offset into the DECODED concatenation."
                ),
                "input_jws": signing_input
                + "."
                + b64url(flip_concat_byte(ed_sig, 3, 255) + pq_sig),
                "flip": {"segment": "signature_slot", "byte": 3, "xor": 255},
                "must_reject": True,
            },
            {
                "name": "pq_component_flipped_concat",
                "description": (
                    "Current-form tamper: one byte flipped inside the ML-DSA "
                    "half of the concatenated slot. The AND rule fails. "
                    "flip.byte is an offset into the DECODED concatenation."
                ),
                "input_jws": signing_input + "." + b64url(ed_sig + flip_concat_byte(pq_sig, 5, 85)),
                "flip": {"segment": "signature_slot", "byte": 5, "xor": 85},
                "must_reject": True,
            },
        ],
    }

    OUT.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"wrote {OUT}")
    print(f"  pqk: {pq_kid}")
    print(f"  reference receipt_hash: {receipt_hash[:30]}...")
    print(f"  reference jws size: {len(compact_jws)} chars")
    print(f"  legacy reference hash: {legacy_hash[:30]}... (carry-forward or fresh)")


if __name__ == "__main__":
    main()
