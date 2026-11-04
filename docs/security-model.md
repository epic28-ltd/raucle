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
  violation. **Trust assumption:** `CapabilityStatement`s are currently self-attested
  (distributed alongside the agent key). A deployer who needs statements to be authoritative
  should distribute them over a trusted channel / pin them; cryptographic issuer-binding of
  statements is future work.
- **Taint laundering:** `SANITISATION` may only clear tags the issuing agent's
  `sanitisation_authority` permits (enforced verifier-side when `capabilities` is supplied;
  `["*"]` = allow-all, empty = deny-all). Without a `capabilities` map the removal is
  self-asserted — supply the map in any setting where producers are not fully trusted.
- **Parsing:** `from_jws` caps input/payload size, rejects duplicate keys, and (in strict mode,
  used by the verifier) enforces `alg=EdDSA` and the `crit` header. `alg:none` / alg-substitution
  is not accepted.

## Tamper-evident audit chain
- **In-place tampering** (edit/reorder/splice within a signed, checkpointed prefix) is detected
  (hash chain + Merkle root + checkpoint signature).
- **Truncation of the tail** (dropping the most recent records) is only detectable with an
  **external high-water mark**: when a public key is supplied the chain must carry a signed
  checkpoint covering its final index, and `verify_chain(expected_head=...)` lets you assert the
  expected final index / hash / merkle-root from an out-of-band anchor. Publish your last
  checkpoint to an append-only external store to close the truncation gap.
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
