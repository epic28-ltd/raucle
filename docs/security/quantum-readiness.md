# Quantum Readiness Statement

Raucle's product is an evidence artefact: a receipt whose value is
long-horizon verifiability. This statement maps the product's
post-quantum position to the standard migration frameworks.

## Position

- **The threat**: "harvest now, forge later". Receipts captured today
  (or any time before migration) become forgeable once a
  cryptographically relevant quantum computer exists, because Ed25519
  falls to Shor's algorithm. For an audit system this is the whole
  game: a regulator verifying a three-year-old receipt chain in 2035
  needs those receipts to have been quantum-safe when minted.
- **The answer**: the [`raucle/pq1`](provenance/v1/pq1-hybrid.md)
  hybrid profile. Every hybrid receipt is signed by BOTH Ed25519 AND
  ML-DSA-65 (FIPS 204, NIST security category 3, the standard
  replacement tier for Ed25519-class signatures). Validity is the AND
  of both. An attacker must break both constructions.

## Standards alignment

| Framework | Where raucle stands |
|---|---|
| FIPS 204 (final, Aug 2024) | ML-DSA-65 implemented via the audited `cryptography` library (AWS-LC backend); exact FIPS parameter sizes enforced at parse (3309-byte signatures, 1952-byte keys) |
| RFC 9964 (JOSE/COSE ML-DSA) | Algorithm naming and JWS integration follow the RFC; the hybrid envelope is specified precisely because no final JOSE composite standard exists yet |
| NIST SP 1800-38 migration phases | Inventory: complete (every signature surface identified: receipts, chain checkpoints, registry checkpoints, capability tokens, A2A handoffs). Protect: hybrid emission shipped for receipts (`quantum_mode='strict'`). Migrate: registry/checkpoint/token surfaces next |
| NCSC PQC migration guidance | The hybrid-then-transition pattern matches NCSC's recommendation to adopt PQC alongside classical rather than waiting for a hard cutover |

## What is quantum-safe today (v0.23)

- **Receipts** under `raucle/pq1`: emission via
  `ProvenanceLogger(..., quantum_mode='strict')`, verification via
  `ProvenanceVerifier(pq_public_keys=...)`, CLI enforcement via
  `raucle provenance verify --require-pq`.
- **Hashes**: SHA-256 throughout. Quantum collision/preimage bounds
  (2^128) remain infeasible; no hash migration needed.
- **Downgrade resistance**: a hybrid receipt stripped of its ML-DSA
  component is rejected at three layers (parse shape, v1-path closure
  on the declared profile, registry resolution). No downgrade path
  exists by design.

## Migration roadmap

| Surface | Status | Target |
|---|---|---|
| Provenance receipts | **Hybrid shipped (pq1)** | Default-on in a future release as ML-DSA support matures |
| Trust registry entries | Dual-key support in the registry format | Next release |
| Registry/audit checkpoints | Single-key today | Hybrid checkpoint signatures |
| Capability tokens | Ed25519 today | Hybrid minting behind a flag |
| KMS/HSM signers | Local ML-DSA keys | AWS KMS/Azure Key Vault as providers ship ML-DSA |
| Cross-language ports | Python authoritative | TS/Go/Rust/C# via their PQ libraries against the published reference vectors |

## Honest limits

- ML-DSA-65 is not "quantum-proof"; it is the NIST-standard signature
  with no known efficient quantum attack. The hybrid construction
  means receipt security does not rest on lattice assumptions alone.
- SLH-DSA (FIPS 205, hash-based) is the conservative backstop if
  lattice cryptanalysis advances; it is noted as a future profile
  (`raucle/pq2`) and deliberately not shipped to avoid premature
  surface area.
- A runtime without ML-DSA support cannot verify pq1 receipts; the
  verifier raises `PQUnavailable` rather than silently downgrading.
- FIPS 204 ML-DSA signing is randomised (hedged), so hybrid receipts
  are not byte-reproducible the way v1 receipts are; the vector
  contract for cross-language ports is verification of the reference
  instance plus re-signing under the same seed-derived keys.