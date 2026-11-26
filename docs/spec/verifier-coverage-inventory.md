# Offline provenance verifier: coverage inventory, output contract and packaging

- **Status:** Implemented for issue \#346 slice 1 (CLI surface, output contract, packaging, fail-closed regressions)
- **Date:** 2026-11-26
- **Authority:** ADR 0011 (standalone offline provenance verifier), issue \#346
- **Canonical implementation:** `raucle/provenance.py` (`ProvenanceVerifier`). This document inventories what the canonical verifier already covers, marks what is not covered, and defines the new auditor-facing CLI surface, its versioned machine output and its stable exit codes. No invented coverage: every implemented row cites the module that enforces it.

## 1. Scope of this slice

This slice delivers only the CLI surface, the output contract and packaging. Items deliberately NOT changed in this slice (sibling-lane boundary, reported not edited): receipt store, chain and transparency verification internals, fixtures and the canonical verifier's reason strings. Where a lower-layer change would improve the output contract, it is recorded in §9 instead of being implemented past the boundary.

## 2. Coverage inventory

### 2.1 Receipt versions and envelope

- implemented: v1 classical profile, three-segment compact JWS (`alg: EdDSA`, Ed25519), payload and header `typ` pinned to `provenance-receipt/v1` (`raucle/provenance.py`: `_EXPECTED_TYP`, `from_jws(strict=True)`).
- implemented: `raucle/pq1` hybrid profile (`raucle/pq.py`: `header_is_pq1`, three-segment slot over the raw Ed25519 + ML-DSA-65 concatenation; header pins `raucle/pq1: ml-dsa-65` and a 16-hex `pqk`).
- implemented: legacy four-segment dot-form acceptance during the verify-only deprecation window, with the named `LEGACY_DOT_FORM_DEPRECATION` marker (`raucle/pq.py`).
- implemented: minimal `{receipt_hash, jws}` chain envelope with unknown-envelope-field refusal and registered `x-raucle-` envelope extensions (`raucle/provenance.py`: `_registry.unknown_envelope_fields`); legacy rich envelopes migrate via `raucle provenance migrate-envelope`.
- gap: removal of the legacy dot-form acceptance window is scheduled with the pq1 vector freeze; the acceptance still exists today (named follow-up, `raucle/pq.py` deprecation marker).

### 2.2 JWS critical headers and structural failure closure

- implemented: unknown `alg` refused (only `EdDSA`); unknown header `typ` and unknown payload `typ` refused; header `typ` and payload `typ` must agree.
- implemented: `kid` bound to the payload `agent_key_id` (spec v1 section 3; cross-implementation divergence closure from round-3).
- implemented: `crit` understood-set enforcement (RFC 7515 section 4.1.11): unknown entries refused, named parameters must be present, `crit` must include `raucle/v1` (`_enforce_crit`).
- implemented: header key allowlist; unknown header keys refused; a vendor extension is only possible if it is also listed in `crit`.
- implemented: duplicate JSON object keys refused in the header, the payload and the outer envelope (`_reject_duplicate_keys`).
- implemented: JCS-canonical header and payload bytes enforced at strict parse (`_canonical_json(header) == header_bytes`, same for payload).
- implemented: JWS and payload byte caps (`MAX_JWS_BYTES`, `MAX_PAYLOAD_BYTES`) and per-line malformed-record classification; a hostile line never aborts the whole bundle.

### 2.3 Canonicalisation rule

- implemented: the shared canonical JSON profile (RFC 8785-equivalent UTF-16 code-unit key ordering) centralised in `raucle/_canon.py` and enforced at sign and verify; lone UTF-16 surrogates refused so all reference implementations byte-agree.

### 2.4 Trust-root selection

- implemented: trust roots are supplied out of band only, through `--pubkeys` / `--trust-roots`: capability-statement JSON files or raw PEM files keyed by the SHA-256 prefix of the key bytes (`raucle/cli.py`: `_load_provenance_pubkeys`).
- implemented: a public key embedded in the evidence is never a trust anchor: a supplied capability statement is re-verified under the out-of-band key, its `key_id` must equal the SHA-256 prefix of its own PEM, and a self-widened statement fails closed (`ProvenanceVerifier._verify_statement`, round-4 F2).
- implemented: transparency tooling holds the operator's epoch key as a pinned parameter and never verifies a proof against a key riding the proof (`raucle/transparency.py`: `verify_log_inclusion`).
- implemented (CLI layer, this slice): the versioned report names every `kid`/`pqk` the chain references that has no supplied trust root, classified `missing_trust_material`.
- gap: no signed trust-bundle format yet; trust roots are loose files. A pinned, itself-signed bundle format is a follow-up slice.
- gap: the canonical verifier's error stream reports a missing key exactly like a bad signature (one generic string). This slice resolves the distinction at the CLI layer (§5 scanner); a structured reason-code enum inside the canonical report is reported in §9, not implemented here.

### 2.5 Hybrid Ed25519 + ML-DSA-65 handling

- implemented: dual verification of both components over the same canonical signing input; either component alone is invalid; no downgrade path by design (`raucle/pq.py`: `verify_hybrid`).
- implemented: v1-path closure: a receipt whose header declares `raucle/pq1` never verifies through the classical path even with a valid Ed25519 component (`ProvenanceVerifier._verify_signature_v1`).
- implemented: missing or unknown `pqk` fails closed; a runtime without ML-DSA-65 support raises the distinct `PQUnavailable` (never a silent classical pass) (`_verify_signature_hybrid`, `raucle/pq.py`: `PQUnavailable`).
- implemented: `--require-pq` strict mode as a constructor requirement and as a CLI flag; a classical-only chain fails with a named reason and never verifies as PQ-clean (`_jws_declares_pq1`, `_enforce_require_pq`).
- implemented (regressions, this slice): require-pq cannot silently downgrade, verified in `tests/test_verifier_cli.py` (classical-only refused; stripped hybrid slot refused; hybrid without supplied PQ keys refused).
- gap: legacy two-segment dot-form signatures remain verifiable during the deprecation window (removal tracked with the pq1 vector freeze).

### 2.6 Policy and proof artifacts

- implemented (out of band, not part of chain verification): Lean/SMT policy proofs via `raucle prove` with `PolicyUnproven` fail-closed; operator policy seal sidecars with the honest `verified` / `unsealed` / `refused` triad (`raucle/prove.py`, `raucle/policy_seal.py`).
- implemented (chain evidence, honest classification): counterfactual blocks are re-checked structurally and reported with honest `re-run`/`not re-run` rows; the verifier holds neither the alternative ruleset nor the stored input (`VerificationReport.counterfactual_evidence`).
- implemented (verification-side capability conformance): model/tool allowlists are re-checked when capability statements are supplied; without them the check is named as skipped, never silently assumed.
- gap: chain receipts carry `ruleset_hash` digests only; the verify command does not consume or check any policy or proof artifact attached to a receipt. Wiring attached artifacts into the versioned contract is a named follow-up.
- gap: the tool-definition pin pass needs deployment registry state; without it the checks stay structural (documented off-deployment residual).

### 2.7 Transparency proofs

- implemented (in-repo, separate tooling, offline): chain head computation and digest match against a supplied signed statement `verify_transparency_anchor`; honesty when no statement exists (`SELF-SIGNED-ONLY`); inclusion proofs recomputed entry-by-entry with the operator key as pinned parameter; consistency proofs and segment/org binding (`raucle/transparency.py`).
- implemented (in-chain): `x_timestamp` time anchors with head-digest re-derivation against the exact ledger line; unsupported anchor modes refused; a tsa-mode chain requirement is enforced (`_verify_time_anchor`).
- gap: the verify command does not consume transparency artifacts; the versioned report names them as skipped (§4 `coverage.skipped`). Full COSE statement verification against a transparency root is named in-module as follow-up wiring.
- boundary note: a sibling lane is editing receipt store, chain and transparency verification internals in this merge window; wiring transparency and seal checks into this CLI is therefore deliberately deferred and reported, not edited, in this slice.

### 2.8 Segment seals

- implemented (in-repo, separate tooling): size-based segments with `.meta` seal sidecars; `verify_seal_meta` returns the honest `verified` / `unsealed` / `unsigned` / `refused` triad; anonymous sealing is recorded as unsigned, never presented as signed; sealing and resume fail closed on unparsable lines (`raucle/receipt_store.py`).
- implemented (seal trust state): a configured seal identity signs the canonical meta bytes offline; the seal key is pinned out of band.
- gap: chain verification does not consume segment seal metas; wiring them into the versioned contract is a named follow-up (also affected by the sibling-lane boundary in §1).

### 2.9 Revocation and key lifecycle

- implemented: in-chain cascade revocation with reason rules and intent-constraint quoting refusals; lease revocation (`_verify_cascade_revocation`, `_verify_lease_extension`).
- implemented: `TrustRegistry` revoke with replayed last-entry-wins state, including PQ keys under their own `pq_key_id`; integrity failures refuse (`raucle/trust_registry.py`).
- implemented: retirement as the rotation transition state: a retired key still resolves and verifies history; the old key file is archived as retired-but-verifiable (never deleted); rotation refuses on revoked or mismatched registry state (`raucle/key_rotation.py`).
- implemented: `agents revoke-key` and operator rotation surfaces refuse to erase trust history.
- gap: the offline verifier CLI does not consume a `TrustRegistry` file yet; revocation and retirement reach chain verification only through in-chain receipts. A `--trust-registry` input feeding status checks into the versioned report is a named follow-up.

## 3. Auditor CLI surface

```text
raucle-verify CHAIN --trust-roots FILES [--pq-keys PEMS] [--require-pq] [--json]
```

- `CHAIN` is the provenance chain JSONL. `--trust-roots` (alias `--pubkeys`) takes capability-statement JSON files and/or PEM files. `--pq-keys` (alias `--pq-pubkeys`) takes ML-DSA-65 public key PEM files, each keyed by its 16-hex `pqk`. `--require-pq` fails unless every receipt is a valid `raucle/pq1` hybrid. `--json` switches to the versioned machine report.
- The console entry point is `raucle-verify = "raucle.verifier_cli:main"` in `pyproject.toml`. The same output contract is available additively on the canonical command: `raucle provenance verify CHAIN ... --json`.
- There is no network code in `raucle/verifier_cli.py` and no implicit fetching of trust roots, revocation state, policies or transparency checkpoints. Proof: `tests/test_verifier_cli.py::TestAuditorCliOffline::test_verification_runs_with_sockets_unavailable` runs a full verify with `socket.socket`, `socket.create_connection` and `socket.socketpair` patched to raise.
- Trust roots are loaded by the canonical loader (`raucle/cli.py::\_load_provenance_pubkeys`); `--require-pq` enforcement reuses the canonical enforcer. No crypto logic is duplicated in the front end.

## 4. Versioned machine output (`--json`)

Schema version: `raucle.verify.report/v1`. Evolution is additive: keys may be added, existing keys never change meaning and are never removed. Output is deterministic (no timestamps, no wall clock, insertion-ordered) and byte-identical across repeated runs on the same inputs. Keys, in emission order:

| Key | Meaning |
| --- | --- |
| `schema_version` | Always `raucle.verify.report/v1`. |
| `verdict` | Classified verdict, vocabulary in §5. |
| `invalid` | Boolean mirror: true unless `verdict == "verified"`. |
| `exit_code` | The stable exit code (§5); identical to the process exit code. |
| `receipt_count` | Receipts the verifier graded. |
| `failure_reasons` | Array of `{line, class, message}`; `line` is the JSONL line number or null; `message` is the canonical verifier's error verbatim (the front end never rewrites a reason). |
| `profiles_observed` | `v1`, `pq1`, `other`, `unparseable` header counts from the read-only observation scan. |
| `require_pq` | Echo of the flag. |
| `pq` | `available` (runtime ML-DSA-65 support) and `keys_supplied`. |
| `trust_roots_supplied` | Number of trust roots resolved. |
| `checked_artifacts` | `kind` (`chain`, `trust_root`, `pq_key`), `path`, `sha256` (hex, `sha256:` prefixed), `bytes` for every named input. |
| `coverage` | `performed` and `skipped` check rows; skipped rows carry a named reason (transparency anchor, seal metas, policy proofs are separate tooling; capability conformance only with statements; hybrid verification needs an ML-DSA-capable runtime; resource bounds can be disabled by `RAUCLE_VERIFY_BOUNDS=off`). |
| `offline` | Constant true: the command performs no network operations. |
| `counts` | Signature, parent-link, taint-monotonicity, capability-violation and unauthorised-sanitisation failure counts from the canonical report. |
| `tampered_receipts` | Receipt hashes whose recomputed hash mismatched. |
| `counterfactual_evidence` | Present only when the chain carries counterfactual blocks (honest re-run rows). |
| `capability_trust_modes` | Present only when capability statements resolved (Q16, informational). |

Empty bundle: an empty chain is `invalid` (exit 2, `empty_chain` reason) under the versioned contract because nothing was verified. The legacy default mode keeps its pre-slice behaviour (exit 0 on an empty bundle); this divergence is deliberate and documented for the additive contract only.

Known limitation (honest): a missing trust root and a bad signature produce the same canonical error string; the front end's header scan adds the explicit `missing_trust_material` rows that make the distinction, so the report is actionable today. A structured reason-code enum inside the canonical report would make this structural (§9).

## 5. Verdicts and stable exit codes

Exit codes are fixed integers; the JSON body carries the same value in `exit_code`. Without `--json`, `raucle provenance verify` keeps its pre-existing behaviour: 0 for a valid chain, 2 for an invalid chain, 1 for input errors, unchanged human output.

| Exit code | Verdict | Meaning |
| --- | --- | --- |
| 0 | `verified` | The chain passed every performed check; no required check was skipped as part of the verdict. |
| 1 | `operational_error` | Missing or unreadable chain or artifact, malformed JSON input at the wrapper level, or an unsupported extra. Not a statement about the chain. |
| 2 | `invalid` | The chain failed verification: tampering, bad or missing-key signature, parent-link break, taint monotonicity, structural rules, capability violations, verifier bound refusals, extension re-checks, unclassified failure reasons, or an empty bundle. Fail-closed fallback for anything unrecognised. |
| 3 | `unsupported_profile` | A receipt the verifier cannot accept as an understood profile: unknown algorithm, unknown header or payload `typ` (unknown receipt version), unknown critical header parameter, unknown header key, unknown envelope field, non-canonical encoding, malformed hybrid profile pin. Fail closed. |
| 4 | `missing_trust_material` | The chain references a `kid` or `pqk` with no supplied trust root (including the retired-key provisioning case: a retired key removed from the bundle leaves its history unverifiable). |
| 5 | `policy_requirement_unmet` | `--require-pq` unmet: a classical-only receipt fails the quantum-safe requirement. |
| 6 | `pq_runtime_unavailable` | The runtime cannot verify ML-DSA-65 at all; pq1 receipts are undecidable and fail closed (`PQUnavailable`), never classically. |

Classification precedence (first present decides the verdict, then the exit code): `unsupported_profile` > `missing_trust_material` > `policy_requirement_unmet` > everything else invalid. `PQUnavailable` short-circuits to verdict 6; unreadable inputs short-circuit to 1. An unclassified reason never produces a verified verdict. Reason strings pass through verbatim so the canonical verifier remains the single source of truth for message text.

## 6. Human output

Both the auditor CLI's default mode and the canonical command's default mode remain human-readable, with no colours, no timestamps and no network dependency in `raucle-verify`'s summary. The default output is unchanged on the canonical command; only the additive `--json` switches the report (it takes precedence over `--format table|json` when both are passed).

## 7. Packaging notes (what is and is not shipped)

What IS shipped:

- An installed console script, `raucle-verify`, generated from `pyproject.toml` `[project.scripts]` when the `raucle` wheel is installed, running `raucle.verifier_cli:main`. It is a Python entry point over the canonical verification library, not a fork: any fix to crypto logic lands in `raucle/provenance.py` and `raucle/pq.py` and reaches auditors automatically.
- ML-DSA-65 (pq1) verification requires a `cryptography` build with an ML-DSA backend (wheels ship AWS-LC from 48.x); a runtime without it fails closed with exit 6 rather than downgrading.
- Deterministic, byte-stable JSON output for automation; honest human summary otherwise.

What is NOT shipped or claimed (anti-overclaim):

- No frozen or statically linked binary exists. Nothing in this slice has been built, checksummed, SBOM-bound or provenance-signed, so no static-binary claim is made. ADR 0011 section 4 keeps the target as a self-contained executable to be substantiated in a later slice; until then the shipped artefact is the console script only.
- No cross-language parity CLI: `reference/provenance-rs` remains a library covering the classical v1 profile; the Python verifier stays the canonical implementation.
- No "zero dependency" claim; the console script runs wherever a Python interpreter plus the wheel's dependencies are installed.

## 8. Tests added

`tests/test_verifier_cli.py` (23 tests): verified chains and contract shape/determinism (3); fail-closed regressions: missing trust root for a referenced key, tampered payload, unknown payload version, unknown JOSE `typ`, unknown algorithm, unknown critical header, incomplete chain, empty bundle (versioned contract and legacy divergence), require-pq vs classical-only chain, missing chain file, missing trust-root file (13); offline execution with sockets patched to raise (1); parent CLI additive-flag compatibility including legacy unversioned output and default table output (3); hybrid pq1 group (4): full hybrid chain verified offline, require-pq accepted on a hybrid chain, hybrid without supplied PQ keys refused with no silent downgrade, stripped hybrid signature slot refused.

## 9. Boundary report and follow-up slices (not implemented here)

- Reason-code enum: the canonical `VerificationReport` carries human strings; distinct exit codes for missing-key versus bad-signature rely on the front-end scan (§4). A structured, versioned reason field inside the report would improve every consumer, but it touches the shared report shape in the sibling lane's window, so it is reported here, not edited.
- Trust-bundle format: a pinned, itself-signed bundle (signer pinned out of band) instead of loose files.
- `--trust-registry` input: consume `TrustRegistry` state for revocation and retirement statuses in the versioned report.
- Wiring transparency anchors, log inclusion/consistency proofs, segment seal metas and proof artifacts into the versioned report (after the sibling lane's store/transparency merge lands).
- Static-binary evaluation with reproducible build, checksums, SBOM and provenance binding per ADR 0011 required-validation list.
- Legacy dot-form acceptance removal with the pq1 vector freeze.
