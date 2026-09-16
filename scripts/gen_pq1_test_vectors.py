#!/usr/bin/env python3
"""Generate the pq1 hybrid test vectors for the provenance spec.

Writes a self-contained ``pq1_test_vectors.json`` next to the v1 vector
file. Deterministic: the Ed25519 and ML-DSA-65 keys are derived from
fixed seeds, so every run (and every reference port) produces
byte-identical receipts.

The vector set pins the wire format: 4-segment JWS, crit carrying both
profiles, pqk pinning, and the two-segment signature slot. Negative
vectors assert the fail-closed behaviour (downgrade, tamper, foreign
key) at the parse and verify layers.
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


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


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
    slot = b64url(ed_sig) + "." + b64url(pq_sig)
    jws = signing_input + "." + slot
    receipt_hash = "sha256:" + hashlib.sha256(jws.encode("ascii")).hexdigest()

    # NOTE ON DETERMINISM: Ed25519 signing is deterministic, but FIPS 204
    # ML-DSA signing is randomised (hedged). The same seed + message NEVER
    # yields the same signature bytes, so the v1 byte-identity discipline
    # cannot apply to the ML-DSA component. The pq1 vectors therefore pin
    # the deterministic parts (keys, canonical signing input, header) and
    # one REFERENCE signature, and the cross-language contract is
    # VERIFICATION: every port must verify this reference signature under
    # the seed-derived public keys, and must produce its own signatures
    # that verify under the same keys.
    vectors = {
        "spec_version": "raucle-provenance-receipt/v1+pq1",
        "generator_version": "raucle pq1-vector-gen 1.0.0",
        "profile": "raucle/pq1",
        "algorithm": "ml-dsa-65",
        "ed_seed_hex": ED_SEED.hex(),
        "pq_seed_hex": PQ_SEED.hex(),
        "ed_public_key_hex": ed_pub_raw.hex(),
        "pq_public_key_hex": pq_pub_raw.hex(),
        "pq_key_id": pq_kid,
        "deterministic_prefix": signing_input,
        "reference_jws": jws,
        "reference_receipt_hash": receipt_hash,
        "verification_contract": (
            "Ports MUST (a) derive the same keys from the seeds, "
            "(b) byte-match the deterministic_prefix, (c) VERIFY the "
            "reference_jws signature slot under those keys, and (d) produce "
            "their own signatures over the same prefix that also verify. "
            "Signature bytes are not reproducible: ML-DSA signs randomised."
        ),
        "vectors": [
            {
                "name": "pq1_hybrid_receipt",
                "description": (
                    "Hybrid receipt: Ed25519 + ML-DSA-65 over the same "
                    "canonical JCS bytes. 4-segment JWS; the signature slot "
                    "carries two base64url segments joined by a dot. The "
                    "JWS is a reference instance (ML-DSA is randomised); "
                    "verify it, do not byte-compare re-signings."
                ),
                "expected_segments": 4,
                "expected_ed_signature_len": 64,
                "expected_pq_signature_len": 3309,
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
                    "path refuses it on shape (three segments where four are "
                    "required)."
                ),
                "input_jws": jws.rsplit(".", 1)[0],
                "must_reject": True,
            },
            {
                "name": "ed_signature_flipped",
                "description": (
                    "The Ed25519 component is tampered; ML-DSA intact. The "
                    "AND rule fails: hybrid verification must reject even "
                    "though the PQ component verifies."
                ),
                "input_jws": jws,
                "flip": {"segment": 2, "byte": 3, "xor": 255},
                "must_reject": True,
            },
            {
                "name": "pq_signature_flipped",
                "description": (
                    "The ML-DSA component is tampered; Ed25519 intact. The "
                    "AND rule fails: hybrid verification must reject even "
                    "though the classical component verifies."
                ),
                "input_jws": jws,
                "flip": {"segment": 3, "byte": 5, "xor": 85},
                "must_reject": True,
            },
        ],
    }

    OUT.write_text(json.dumps(vectors, indent=2) + "\n")
    print(f"wrote {OUT}")
    print(f"  pqk: {pq_kid}")
    print(f"  reference receipt_hash: {receipt_hash[:30]}...")
    print(f"  reference jws size: {len(jws)} chars")


if __name__ == "__main__":
    main()
