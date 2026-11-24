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
- **Documented limitation:** the gate enforces on the **argument names declared in the
  policy**; it does not know the tool's parameter schema. A `forbidden_values` *blacklist* can
  therefore be evaded if the tool reads the forbidden value under a different parameter name.
  **Prefer `allowed_values` whitelists** (which fail closed on an absent/aliased field) for
  security-critical fields. Binding the gate to a tool's declared schema is future work.
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
