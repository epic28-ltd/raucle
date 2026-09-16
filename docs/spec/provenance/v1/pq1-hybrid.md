# Quantum-Readiness Design: Hybrid Post-Quantum Signatures (`raucle/pq1`)

Status: design document for raucle v0.23. Implements the migration path so
receipts minted today stay verifiable after a cryptographically relevant
quantum computer exists. "Harvest now, forge later" is an attack on an audit
system's core promise: a receipt must remain verifiable for decades.

## Why this matters for raucle specifically

A receipt's entire value is long-horizon verifiability. Regulators verify
three-month-old receipt chains; auditors verify years. The threat model has
always included "the operator's key is compromised". A CRQC is a global,
non-targeted version of that event: captured receipt archives become
forgeable retroactively. An evidence artefact must migrate to post-quantum
signatures before the capture happens, not after.

Standards context:

- **FIPS 204** (final, August 2024): ML-DSA. Parameter sets ML-DSA-44
  (category 2), ML-DSA-65 (category 3), ML-DSA-87 (category 5).
- **RFC 9964**: JOSE/COSE serialisations for ML-DSA; algorithm names
  `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`, registered in the JOSE registry.
- **NIST SP 1800-38 / IETF LAMPS**: hybrid/composite signatures (classical
  + PQ) as the migration pattern. A composite signature is valid only if
  BOTH component signatures verify. No final JOSE composite standard exists
  yet, so this profile specifies the hybrid envelope precisely and pins it
  with test vectors, the same discipline as the canonicalisation suite.

## Chosen parameters

- **ML-DSA-65** as the PQ primitive. Category 3 (AES-192 strength), the
  standard replacement tier for Ed25519-class signatures. Sizes: public key
  1952 bytes, signature 3309 bytes, private seed 32 bytes.
- **Ed25519 retained** in every quantum-safe receipt. Hybrid means both
  signatures must verify. Rationale: classical security does not depend on
  lattice assumptions; PQ security does not depend on any classical
  implementation defect; verifiers can check both during migration windows.
- **Hashing unchanged**: SHA-256 everywhere. Grover affects SHA-256
  preimages only to 2^128 and collisions to 2^128 under the relevant
  quantum collision bounds; both remain infeasible. No hash migration.

## Wire format: the `raucle/pq1` receipt profile

A quantum-safe receipt is a JWS whose header carries the hybrid markers and
whose signature slot holds both signatures.

### JOSE header (hybrid)

```json
{
  "typ": "provenance-receipt/v1",
  "raucle/v1": "provenance",
  "raucle/pq1": "ml-dsa-65",
  "crit": ["raucle/v1", "raucle/pq1"],
  "kid": "<ed25519 key id>",
  "pqk": "<ml-dsa-65 key id, first 16 hex chars of sha256(pubkey)>"
}
```

- `crit` includes both profile ids: a verifier that does not know
  `raucle/pq1` MUST reject rather than guess (the load-bearing profile pin,
  same principle as the canonicalisation profile versioning).
- `pqk` pins the ML-DSA key id so trust registries can carry both keys per
  issuer.

### Signature encoding

The JWS signature slot holds two base64url segments joined by a literal `.`:

```
<base64url(ed25519-signature, 64 bytes)>.<base64url(ml-dsa-65-signature, 3309 bytes)>
```

The JOSE `alg` remains `EdDSA` (the classical component) so legacy
verifiers reject gracefully on the unexpected length rather than
mis-parsing. `raucle/pq1` in `crit` is what tells a quantum-aware verifier
to expect and check the second segment.

### Verification algorithm (pq1)

1. Parse the JWS. Header must contain `raucle/v1: "provenance"` and
   `raucle/pq1: "ml-dsa-65"`, both listed in `crit`; otherwise reject as
   an unrecognised profile.
2. Split the signature slot on `.` into exactly two segments. Reject on any
   other shape.
3. Resolve the Ed25519 key by `kid` and the ML-DSA-65 key by `pqk` from the
   trust registry. Both must resolve; failure is fail-closed.
4. Recompute the canonical JCS bytes of header and payload (the existing
   `_canonical_json` pipeline, unchanged).
5. Verify the Ed25519 signature over the canonical bytes. Reject on fail.
6. Verify the ML-DSA-65 signature over the same canonical bytes. Reject on
   fail.
7. The receipt is quantum-valid only if BOTH verify. Either alone: reject.
   No downgrade path.

### Size and latency impact (honest numbers, measured)

| | v1 (Ed25519) | pq1 (hybrid) | factor |
|---|---|---|---|
| Public key | 32 B | 1984 B (both) | 62x |
| Signature | 64 B | 3373 B | 53x |
| Receipt JSONL row | ~1.2 KB | ~5.4 KB | 4.5x |
| Chain, 1000 receipts | ~1.2 MB | ~5.4 MB | 4.5x |
| Sign | ~0.05 ms | ~1.2 ms | 24x |
| Verify | ~0.10 ms | ~0.3 ms | 3x |
| Keygen | ~0.1 ms | ~7 ms | 70x |

Signing is asynchronous from the gate decision (receipt emission is off the
hot path), so the gate's sub-100µs decision budget is unaffected. Storage
growth is noted for SIEM forwarding budgets.

## Key and trust-registry model

- Each issuer holds an Ed25519 key (existing) and an ML-DSA-65 key (new).
  Key ids are independent: `kid` and `pqk`.
- A trust registry entry carries both public keys and both key ids.
  Registry checkpoints in pq1 mode are signed by both keys; a checkpoint
  verifier checks both.
- Rotation: either key rotates independently; the registry version
  increments and post-rotation receipts pin the new key ids.
- KMS/HSM: the signer abstraction gains an ML-DSA backend alongside
  local/aws/azure/vault as providers ship ML-DSA. v0.23 ships local keys
  and the backend interface.

## Modes and migration

1. **Emission (operator-side)**: `quantum_mode` config in the provenance
   logger and gateway. `off` (default, no wire change), `strict`
   (hybrid receipts only), `dual` (v1 receipt plus a hybrid receipt linked
   by parent hash for chain continuity during migration windows).
2. **Verification (consumer-side)**: the verifier accepts v1, pq1, and in
   dual chains validates that both representations agree on the event.
   A pq1 receipt with a missing or invalid ML-DSA segment is INVALID.
3. **Audit chains**: checkpoints sign the hash-chained envelope with both
   keys in pq1 mode.
4. **Test vectors**: `docs/spec/provenance/v1/pq1-test-vectors.json` -
   fixed seeds, the deterministic signing prefix, one reference hybrid
   JWS, and negative vectors (downgrade-stripped, Ed25519-flipped,
   ML-DSA-flipped). NOTE: FIPS 204 ML-DSA signing is randomised (hedged),
   so hybrid receipts are NOT byte-reproducible the way v1 receipts are.
   The cross-language contract is therefore verification-based: ports
   (a) derive the same keys from seeds, (b) byte-match the deterministic
   prefix, (c) verify the reference signature under those keys, and
   (d) produce their own signatures that also verify. The Python
   reference is authoritative; TS/Go/Rust/C# ports add ML-DSA via their
   PQ libraries.
5. **No v1 breakage**: everything deployed today keeps verifying forever.
   pq1 is additive. Old vectors stay published - the version-pinned
   recomputable-evidence property, applied to this profile.

## What is explicitly NOT claimed

- ML-DSA-65 is not "quantum-proof"; it is the NIST-standard signature with
  no known efficient quantum attack. The hybrid construction means receipt
  security reduces to the AND of Ed25519 and ML-DSA: an attacker must break
  both.
- SLH-DSA (FIPS 205) is the conservative backstop if lattices fall; out of
  scope here, noted for a future `raucle/pq2: slh-dsa-192s` profile.
- HSM ML-DSA signing depends on provider availability.

## Deliverables for v0.23

1. `raucle/pq.py`: `HybridSigner`, `verify_hybrid`, ML-DSA key generation,
   dual-key management, seed handling.
2. Provenance logger `quantum_mode` (off/strict/dual).
3. Trust registry: dual-key entries, dual-signature checkpoints.
4. Gateway/KMS signer backend interface extension.
5. CLI: verify `--require-pq`, registry publish `--with-pq-key`, key
   generation.
6. `pq1_test_vectors` plus conformance harness extension.
7. This document, spec changelog, README section.
8. Tests: unit (sign/verify/tamper, negative cases), integration (hybrid
   chain verifies end to end; dual-mode continuity), vectors
   (byte-identity across ports as they adopt ML-DSA).
9. Quantum-readiness statement mapped to NCSC PQC migration guidance and
   NIST SP 1800-38 phases (inventory, protect, migrate).