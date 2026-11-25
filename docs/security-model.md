# Raucle — security model & trust assumptions

This document states what raucle's guarantees depend on, so deployers can
reason about residual trust. It reflects the hardening from the 2026-06 security audit.

## Capability gate
- **Guarantee:** a tool call that is not covered by a valid, unexpired, correctly-signed
  capability whose constraints are satisfied **cannot execute** (`GateDecision.denied`).
- **Holds for:** `allowed_values` (whitelist), `starts_with`, `max_value`/`min_value`
  (finite numbers only — NaN/Inf are rejected), `forbidden_field_combinations`,
  `required_present`, tool match, dot-delimited `agent_id` scope, expiry, signature, issuer
  pinning, attenuation (children only narrow), and strict-mode proof binding (the cited proof
  must match the hash of the enforced constraints).
- **Schema binding (X1):** when a tool's schema is registered with the gate
  (`raucle/tool_schema.py`; primary source MCP `tools/list`, secondary OpenAPI
  fragment), rules referencing fields the schema does not declare fail at
  **config load** — never silently at call time — and type-confused argument
  values deny with a `schema_violation` reason before the name-based checks run.
  Undeclared arguments deny when the schema closes the object
  (`additionalProperties: false`), which closes the parameter-aliasing evasion
  above for schemas that declare closed objects.
- **Residual:** a tool **without** a registered schema keeps today's
  name-based, fail-closed behaviour, and aliasing closes only for
  closed-object schemas. **Prefer `allowed_values` whitelists** for
  security-critical fields either way. Spec:
  `docs/spec/x1-schema-enforcement.md`; conformance vectors:
  `standards/test-vectors/schema_enforcement_v1_*.json`.
- **Revocation:** per-token denylist; a revoked token (and, when a `parent_resolver` is
  configured, any revoked ancestor) is denied. Without a resolver, revoke each descendant or
  rely on short TTLs.
- **Runtime vs mechanised:** the guarantees above describe what the **runtime gate**
  enforces (and what the test suite covers). The Lean 4 mechanisation proves a **narrower
  model** — `allowed_values`, `forbidden_values`, `max_value`/`min_value`, `required_present`
  only. `starts_with`, `forbidden_field_combinations`, `agent_id` scope, revocation, expiry,
  signature, issuer pinning and strict-proof binding are runtime-and-test-enforced but not yet
  in the Lean model. See `paper/lean/README.md` for the exact proof boundary.

## Provenance verification
- **Capability conformance** is enforced **verifier-side only when you supply the
  `capabilities` map** to `ProvenanceVerifier`. With it: a receipt from an `agent_key_id` with
  no statement is a violation (fail-closed), and a model/tool the statement disallows is a
  violation. **Trust assumption:** `CapabilityStatement`s are self-attested by default
  (distributed alongside the agent key); the verify verdict now labels that trust mode
  explicitly (informational, see the trust-mode section below). A deployer who needs statements
  to be authoritative vouches them through the registry-anchored agent passport (an issuer
  countersigns the statement) or distributes them over a pinned trusted channel; issuer-binding
  beyond the passport is future work.
- **Taint laundering:** `SANITISATION` may only clear tags the issuing agent's
  `sanitisation_authority` permits (enforced verifier-side when `capabilities` is supplied;
  `["*"]` = allow-all, empty = deny-all). Without a `capabilities` map the removal is
  self-asserted — supply the map in any setting where producers are not fully trusted.
- **Parsing:** `from_jws` caps input/payload size, rejects duplicate keys, and (in strict mode,
  used by the verifier) enforces `alg=EdDSA` and the `crit` header. `alg:none` / alg-substitution
  is not accepted.
- **Resource bounds (Q19):** an untrusted bundle must not exhaust an auditor's verifier. A
  `ProvenanceVerifier.verify_chain` call runs under fixed resource bounds and refuses with a
  NAMED FAILURE, `ProvenanceVerifierBoundsExceeded`, naming the limit hit, the observed value
  and the cap. A refused bundle is invalid; where a bound caps the walk itself (bundle bytes,
  node budget, depth) the named refusal stops the verifier rather than grading further.

  | Bound | Default | Env override | Alignment with existing receipt-size patterns |
  |---|---|---|---|
  | bundle bytes (whole chain file) | 256 KiB | `RAUCLE_VERIFY_MAX_BUNDLE_BYTES` | byte-for-byte the simulate/manifest pasted-input cap family (`raucle.demo_scenarios._MAX_MANIFEST_BYTES` and the panel's client-side 256 KiB refusal): a chain file is the same class of untrusted pasted bundle |
  | parents per receipt | 256 | `RAUCLE_VERIFY_MAX_PARENTS` | the 256 family again; comfortably above any observed fan-out and below the ~420-parent ceiling the 32 KiB payload cap implies, so an oversize parent array refuses with this named bound rather than drifting into a payload parse cap |
  | ancestry graph depth | 256 | `RAUCLE_VERIFY_MAX_DEPTH` | an order of magnitude above the chain-graph composition query windows (`raucle.chain_graph._MAX_DEPTH = 20`, a query bound, not a verification bound) while still refusing deep-chain probes by name |
  | total receipts (node budget) | 1024 | `RAUCLE_VERIFY_MAX_NODES` | the same order as the demo chain-collection cap (`MAX_CHAIN_RECORDS = 1000`); with default bundle bytes the byte bound binds first, so this is the tail bound that bites when an operator raises the byte bound |

  Ancestry walking is memoised (visit-set keyed caching): shared ancestors resolve once per
  verify call, the work counters ride the report object as read-only diagnostics (never in the
  report body, so the v1.0 report shape stays byte-stable), and no verdict changes for honest
  chains. Cycles are refused by name by the traversal's defensive detector; receipt hashes are
  content-derived, so honest chains cannot present a cycle to the walk, and the detector exists
  so a forged or corrupted map terminates with a named refusal instead of spinning.

  The bounds are **default ON**. That is the deliberate choice under this document's fail-closed
  posture: a verifier that must be told before it protects itself is a verifier that is not
  protecting in the deployments that forget. For the migration window only, an operator can
  restore the legacy unbounded verifier with `RAUCLE_VERIFY_BOUNDS=off` (also `0`/`false`/`no`);
  bounds-disabled verification reproduces the pre-Q19 behaviour exactly. Operators with genuinely
  deep chains raise the per-bound env values instead (typically `RAUCLE_VERIFY_MAX_BUNDLE_BYTES`,
  with the depth bound then still binding at its own default). Values are non-negative integers; a
  malformed or ambiguous env value is refused loudly, never defaulted through.
- **Trust labelling (Q16):** the trust assumption above is now labelled explicitly in the verify
  output. When a statement is resolved through the verifier it is reported as `self-asserted`
  unless the caller marks it `authority-issued` (resolved through a separately vouched,
  registry-anchored passport); the label is informational and never changes a check outcome. See
  "Receipts, evidence levels and trust modes" below.

## Receipts, evidence levels and trust modes

raucle issues two different receipt families at a gated call, and they are
not the same kind of evidence. Reading one as the other is the audit
failure this section exists to prevent: an authorisation decision is not
execution proof, and an application's self-report is not an independent
witness.

| Guarantee | Where it lives today | What it binds | What it does NOT bind |
|---|---|---|---|
| Authorisation evidence | the `/gate` decision receipt (`x_gate`; `x_evidence: gate_observed`) | which authority allowed or denied a specific tool plus the canonical argument hash, for a named `agent_id`, under a policy and rule | it does NOT prove tool execution: the gate never sees the tool run |
| Application-attested execution evidence | the provenance `record_tool_call` receipt (`x_evidence: self_reported`) | tool, canonical input and output digests, as reported by the executing application | it is not independently witnessed: the executing application signs its own claim |
| Executor-attested (registered roadmap) | W1 state-verified write receipts (`docs/spec/provenance/v1.2/state-verification.md`) | read-back evidence of the write, bound at mint by the runtime that executed it | designed, not shipped as a verifier-checked level |
| Externally anchored (registered roadmap) | the hosted transparency log work | non-equivocation of the chain head, in front of an external service | designed, not shipped in the OSS verifier path |

The receipt schema evolution follows the AEC evidence-chain composition
work (`draft-schrock-ep-authorization-evidence-chain`) as its standards
direction.

### The verdict ladder an offline verifier can reach

| Level | What it says | Availability |
|---|---|---|
| PROVENANCE_SIGNATURE_VALID | the named key signed the receipt | issued today |
| CAPABILITY_OPERATION_PERMITTED | the resolved, trust-labelled capability statement permits the broad operation class | issued today |
| GATE_DECISION_VERIFIED | the specific tool and hashed arguments were gate-authorised | issued today: authorisation evidence only, it does NOT prove execution |
| EXECUTION_CONFIRMED | independent downstream evidence that the action ran | registered roadmap (W1 state verification, `docs/spec/provenance/v1.2/state-verification.md`, and the AEC composition draft `draft-schrock-ep-authorization-evidence-chain`): no receipt kind issues this level today |

### Trust modes are labelled, informationally

When verification resolves a capability statement, the verdict names HOW
the statement was vouched:

- `self-asserted`: the statement is self-signed in the OSS mode and moves
  with the agent key. A cryptographic self-signature never implies
  organisational authorisation: the verifier never upgrades a
  self-signature into authority.
- `authority-issued`: the statement is separately vouched, today through
  the registry-anchored agent passport (`raucle passport`,
  issuer-countersigned, fail-closed against the trust registry).

The trust mode is an informational field of the verify verdict: the
passport verdict carries `trust_mode`, and the chain verifier's report
carries `capability_trust_modes` per resolved statement (defaulting to
`self-asserted` when the caller marks nothing). The label never changes
any check outcome.

### The receipt's own evidence claim

New decision receipts carry `x_evidence`: `gate_observed` on `/gate`
decision receipts and `self_reported` on application-recorded
`record_tool_call` receipts. The field is the PRODUCER'S own claim about
its evidence, additive metadata in the `x_` extension namespace: the
receipt's `x_evidence` value is treated as informational by verifiers,
its absence on legacy receipts is tolerated, and no absent or unknown
value is ever upgraded; a receipt claiming a higher level
(`executor_attested`) verifies exactly like any other receipt, with no
extra trust granted.

The reviewer's trust-level vocabulary (SELF_REPORTED / GATE_OBSERVED /
EXECUTOR_ATTESTED / EXTERNALLY_CONFIRMED) is quoted here as the planned
schema evolution: the first two values ship today as the receipt's own
informational claim, while a typed, verifier-checked level schema
(including executor attestation and external confirmation) is designed,
not shipped.

## Tamper-evident audit chain
- **In-place tampering** (edit/reorder/splice within a signed, checkpointed prefix) is detected
  (hash chain + Merkle root + checkpoint signature).
- **Truncation of the tail** (dropping the most recent records) is only detectable with an
  **external high-water mark**: when a public key is supplied the chain must carry a signed
  checkpoint covering its final index, and `verify_chain(expected_head=...)` lets you assert the
  expected final index / hash / merkle-root from an out-of-band anchor. Publish your last
  checkpoint to an append-only external store to close the truncation gap; the durable closure
  for this residual is the externally anchored roadmap row in "Receipts, evidence levels and
  trust modes" above (the hosted transparency log work), not an evidence field.
- **Downgrade:** if a public key is supplied, an unsigned / unknown-mode chain is `invalid`
  (no silent acceptance of a signature-stripped chain).

## Untrusted-input surfaces
- **Scanner:** every pattern matches against at most the first 10,000 chars, wildcard spans in
  the bundled rules are bounded, and a per-scan wall-clock budget is the backstop against ReDoS.
- **Feed pull:** `https://` only; private/loopback/link-local hosts and the cloud-metadata IP are
  blocked; redirects are not followed; response size is capped. Feed signatures are verified
  before any content is merged.
- **Server:** ships **unauthenticated by default** — set `RAUCLE_DETECT_API_KEY` and bind to a
  trusted interface before exposing it.

## Deployment intake (external, portal-signed policies)
- `POST /api/deployments/accept` exists ONLY when a `deployment_trust`
  section is configured; the default posture has no intake endpoint
  (404) and nothing about the gate's other surfaces changes.
- The gate verifies the portal's Ed25519 JWS against its PINNED public
  key (issuer-pinned, EdDSA, digest-bound to the artefact in the request,
  nonce-replay-protected). Portal credentials never flow to the gate.
- On accept, the artefact is written atomically and the deployment is
  bound into the hash-chained audit chain + a gate-signed receipt under
  the gate's own identity. Every refusal is fail-closed and audited; the
  live policy is never touched on a verification refusal.
- Trust model and third-party offline verification: see
  `docs/deployment-intake.md`.

## Keys & supply chain
- Private keys are written `0600`. Do not commit key files (`*.pem`/`*.key` are git-ignored).
- Releases are published to PyPI via OIDC Trusted Publishing (no long-lived token); CI actions
  are pinned to commit SHAs.

Report vulnerabilities to **security@raucle.com** (see `.github/SECURITY.md`).

## Scope map: what is enforced where

Three scopes on one page, so no reader infers proof coverage from enforcement:

1. **Core policy gate.** Name-based constraint checks
   (`allowed_values`, `forbidden_values`, `max_value`/`min_value`,
   `starts_with`, `required_present`, `forbidden_field_combinations`) plus
   token checks: signature, issuer pinning, time bounds, identifier binding,
   revocation, expiry, delegation attenuation.
2. **X1 schema binding.** Applies per registered tool schema (MCP primary,
   OpenAPI fragment): load-time field binding and call-time type/undeclared
   checks. Tools without a registered schema are out of this scope and stay
   on the name-based path (`scope 1`).
3. **Lean 4 mechanisation.** Proves
   `allowed_values`, `forbidden_values`, `max_value`/`min_value`,
   `required_present`. X1 schema binding and every other runtime check on
   this page are tested in the suite but are not yet part of the Lean model.

