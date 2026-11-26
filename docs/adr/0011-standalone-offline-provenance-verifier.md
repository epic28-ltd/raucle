# ADR 0011: Standalone offline provenance verifier

- **Status:** Proposed
- **Date:** 2026-11-26
- **Owners:** Raucle engineering
- **Parent programme:** [Enterprise Readiness Programme #109](https://github.com/epic28-ltd/raucle-agent-assurance/issues/109)
- **Implementation tracking:** [Raucle issue #346](https://github.com/epic28-ltd/raucle/issues/346)

## Context

The enterprise proposal asks for a `raucle-verify` CLI that an external auditor can run
without access to Raucle servers. This is a strong product direction, but it is not a blank
feature.

Raucle already ships `raucle provenance verify`, which verifies provenance chains offline
against explicitly supplied public keys/capability statements. It supports optional
ML-DSA-65 hybrid verification requirements via `--pq-pubkeys` and `--require-pq`.
The repository also has cross-language reference implementations in Python, TypeScript,
Go and Rust.

The Rust implementation under `reference/provenance-rs` is currently a library, not a
standalone auditor CLI. It covers the classical v1 receipt profile and does not yet provide
the complete Python verifier surface for hybrid PQ receipts, trust-root lifecycle,
transparency proofs, signed segment seals and all attached proof artifacts.

## Decision

### 1. Build a separately distributable front end over the existing verification contract

The goal is a small auditor-facing executable, not a second, divergent verifier. First
inventory the complete Python verifier behaviour and the versioned test vectors. Reuse the
existing Rust reference implementation where it is complete; extend it only through
cross-language parity tests against the canonical Python implementation.

Do not copy cryptographic verification logic into a new CLI-specific module. A shared
verification library or generated conformance corpus is required so fixes and security
properties do not drift between implementations.

### 2. Define the trust model explicitly

- Trust roots are supplied out of band (for example, a pinned PEM/key-set file or a signed
  trust bundle whose own signer is pinned).
- A public key embedded in a receipt, proof or manifest is never trusted merely because it
  is present there.
- Key selection uses explicit key identifiers and event-time/rotation semantics.
- Retired keys remain available for historical verification; revoked/compromised key policy
  is explicit and must not erase history.
- Unknown receipt versions, algorithms, critical headers and proof formats fail closed.
- Hybrid verification reports classical and ML-DSA status separately. With
  `--require-pq`, a classical-only receipt is rejected; no silent downgrade is permitted.
- Verification must be possible with network access disabled. The CLI does not fetch
  trust roots, revocation state, policies or transparency checkpoints implicitly.

### 3. Define a stable command and output contract

Proposed command shape:

```text
raucle-verify receipt <chain.jsonl> --trust-roots <bundle>
  [--pq-keys <directory>] [--require-pq]
  [--transparency-proof <proof.json>] [--format json|text]
```

The exact grammar is to be settled during implementation. The CLI should support:
- deterministic JSON output for automation;
- a human-readable summary for auditors;
- stable exit codes for verified, invalid evidence, unsupported profile, missing trust
  material and operational/input errors;
- explicit verification coverage, including which checks were performed and which were
  unavailable/not requested;
- no "valid" overall result when a required check was skipped or could not be performed.

The output must distinguish signature validity from policy-proof validity, transparency
inclusion/consistency, seal metadata and archive/checkpoint checks. It must not collapse
partial verification into a generic success.

### 4. Static binary, not a misleading "zero-dependency" claim

A statically linked binary can bundle its runtime dependencies and run without Python or
network access. It still has build-time dependencies and cryptographic libraries. Describe
the target as a self-contained/static executable with no runtime installation requirement,
unless the implementation can substantiate a stronger claim.

### 5. Share the conformance corpus

The CLI must consume the existing versioned fixtures and add fixtures for:
- canonical and non-canonical JWS payloads;
- tampered receipt body, hash and signature;
- unknown `typ`, critical headers, versions and algorithms;
- missing, mismatched and untrusted key identifiers;
- retired and revoked key lifecycle cases;
- classical-only receipt when PQ is required;
- invalid ML-DSA signature and hybrid downgrade;
- missing/invalid Lean/SMT proof artifacts and policy-hash mismatch;
- malformed, truncated or wrong-key transparency inclusion/consistency proofs;
- unsigned, tampered and wrong-key segment seal metadata;
- incomplete chain/receipt collection and checkpoint rollback where an external checkpoint is
  supplied.

Each result must match the canonical Python verifier's status and reason classification for
the profiles both implementations claim to support.

## Consequences

- External auditors get an offline executable without requiring a Raucle service account.
- The current Python CLI remains supported and is the behavioural reference until parity is
  demonstrated.
- The first release may explicitly support a narrower subset, but it must list unsupported
  evidence classes and fail closed when a caller requests them.
- "Zero dependency" is replaced with the verifiable promise of a self-contained executable.
- The executable does not create trust; customers still need to provision/pin the correct
  trust roots and preserve prior checkpoints.

## Required validation

- Run the same conformance fixtures through Python and Rust and compare statuses/reasons.
- Run CLI integration tests in a network-disabled environment.
- Verify that embedded proof keys cannot become trust roots.
- Verify `--require-pq` rejects classical-only receipts and malformed hybrid signatures.
- Verify output/exit codes remain stable across supported platforms.
- Build reproducible release artifacts and bind them to checksums, SBOM and provenance.

## References

- `raucle/cli.py` (`raucle provenance verify`)
- `raucle/provenance.py`
- `reference/provenance-rs/`
- `reference/provenance-go/`
- `reference/provenance-ts/`
- [Raucle issue #346](https://github.com/epic28-ltd/raucle/issues/346)
