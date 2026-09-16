# Changelog

## Unreleased

### Added — gateway identity and key persistence (PR-A, production readiness)
- Gate authentication modes (`RAUCLE_GATE_AUTH=off|apikey|token`): per-agent
  API keys (`X-Api-Key`, hashed at rest, constant-time verify, instant
  revocation) and capability-token authentication (`X-Capability-Token`,
  verified against the trust registry with per-call revocation propagation).
  `off` preserves the previous declared-identity behaviour (compat).
  Auth failures return a receipted DENY with the reason, not a bare 401.
- `raucle agents issue-key|revoke-key|list` CLI for credential management.
- Gateway signing key persistence: local signers persist the Ed25519 key
  (0600, default `<data-dir>/gateway-signing-key.pem`); tokens and receipts
  now verify across restarts; corrupt key material fails closed instead of
  silently regenerating.
- Admin user persistence (`RAUCLE_USERS_FILE`): users and MFA secrets
  survive restarts; demo-mode users remain in-memory by design.
- `docs/gateway-security.md`: auth-mode selection table, fail-closed
  semantics, in-process vs out-of-process trust boundary guidance.

### Added — conformance re-verification layer (`raucle.conformance`)

- Field-level Merkle commitments over call arguments (JCS-canonical leaves,
  UTF-16 code-unit ordering, domain-separated SHA-256 throughout; the scheme
  is deliberately zk-proof-system-portable).
- Selective disclosure: the operator opens only the fields a verifier
  requests, with Merkle paths; `verify_disclosure` fails closed on any
  tamper or root mismatch.
- Partial constraint re-check: per-constraint `SATISFIED` / `VIOLATED` /
  `UNKNOWN` verdicts re-derived independently of the operator's runtime.
  `UNKNOWN` is fail-closed and never counts as conformance.
- Design document: `docs/spec/provenance/v1/conformance-reverification.md`
  (Layer 1 of a three-layer roadmap; Layer 2 is a zkVM proof of the gate
  check with zero disclosure).

### Documentation

- NCSC Cyber Assessment Framework (CAF v3.2) and NCSC ML-security-principles
  control mapping: `docs/security/ncsc-caf-mapping.md`.
- Repository URLs updated across docs, package metadata, reference ports,
  and CI after the organisation move to `epic28-ltd/raucle`.
- Paper (§5, §8, author's note): conformance layer, remote-key signing, and
  policy-DSL gateway recorded as post-freeze engineering additions; the
  evaluation's pre-registration scope is unchanged.


## 0.22.0 (2026-06-11) — package renamed: raucle-detect is now raucle

The library outgrew "detect": receipts, provenance, the trust registry,
passports, and compliance evidence are the product; detection is one module.

### Changed

- **PyPI package**: `raucle-detect` -> `raucle` (`pip install raucle`).
  `raucle-detect` on PyPI receives one final transition release depending on
  `raucle` (so pinned installs surface the rename), then no further releases.
- **Import name**: `raucle_detect` -> `raucle`. A deprecation shim keeps
  `import raucle_detect` working (with a `DeprecationWarning`) for one
  transition cycle.
- **CLI**: `raucle` is the command; `raucle-detect` remains as a deprecated
  alias entry point.
- **GitHub repo**: renamed to `epic28-ltd/raucle` immediately after this
  release merged (old URLs redirect).
- **Env vars**: `RAUCLE_*` is the primary prefix; legacy `RAUCLE_DETECT_*`
  names remain supported.
- **Go reference port** (breaking): the module path is now
  `github.com/epic28-ltd/raucle/reference/provenance-go` — Go consumers must
  update import paths (Go modules cannot alias a renamed declared path).

### Unchanged — wire compatibility

- The provenance receipt `iss` identifier remains the frozen wire constant
  `"raucle-detect/provenance"` (spec v1, committed cross-language test
  vectors, and all five reference ports are byte-for-byte unaffected).
- Receipt/audit/registry formats, signatures, and canonical JSON are
  untouched: every existing receipt still verifies.


## 0.21.0 (2026-06-11) — platform trust layer (registry / handshake / passport / compliance)

Four new modules forming the cross-organisation trust layer, hardened through
**nine rounds of iterative adversarial security review** (independent codex
auditor; find → fix → re-verify until clean of HIGH and MEDIUM findings).
Every fix landed with a regression test.

### Added

- **Agent Trust Registry** (`raucle_detect.trust_registry`): append-only,
  hash-chained, operator-signed JSONL directory of issuer keys. Fail-closed
  revocation, canonical-issuer-name uniqueness (NFC + casefold), key_id↔PEM
  invariant enforced on load, and a signed freshness anchor (per-entry `ts`,
  `head()`, `min_index`/`expected_head_hash`/`max_age_seconds`) so a verifier
  can reject a rolled-back signed snapshot that omits a later revocation.
  CLI: `raucle-detect registry init|publish|list|resolve|revoke|verify`.
- **Cross-org handshake** (`raucle_detect.handshake`):
  `build_request`/`accept_call`/`verify_ack` — two organisations' agents
  authenticate via the shared registry with no prior key exchange. Signed ack
  receipts, responder-side replay rejection, and `verify_ack` requires a real
  anti-replay binding (`expected_request` or `expected_nonce`) by default.
- **Agent passport** (`raucle_detect.passport`): issuer-countersigned,
  registry-anchored identity document wrapping a `CapabilityStatement` —
  one portable artifact verifiable offline by any framework integration.
  Fail-closed on malformed input including hostile-but-signed bodies.
  CLI: `raucle-detect passport issue|verify`.
- **Compliance evidence packs** (`raucle_detect.compliance`): maps a signed
  receipt chain to EU AI Act / ISO/IEC 42001 / SOC 2 controls. Honest by
  design: an evidence map, not a conformance attestation — SATISFIED requires
  cryptographic chain verification; otherwise PARTIAL or OUT_OF_SCOPE.
  CLI: `raucle-detect compliance report --framework eu-ai-act|iso-42001|soc2`.
- All four modules exported from the top-level `raucle_detect` package.
- Runnable two-org demo under `examples/cross_org_demo/`.

## 0.20.0 (2026-06-10) — three fail-open fixes + MCP quickstart + LangChain demo

A security release. A post-relicense scan-and-build pass over the repository
surfaced **three fail-open/leak issues**, each found by actually exercising the
shipped integration paths and each now pinned by regression tests.

### Fixed — security

- **LangChain integration was fail-open on DENY.** langchain-core's callback
  manager swallows handler exceptions unless the handler sets ``raise_error``;
  ``RaucleCallbackHandler`` did not, so the ``CapabilityDenied`` raised by
  ``on_tool_start`` was logged as a warning and **the denied tool executed
  anyway** — the gate was advisory. The handler now sets ``raise_error=True``
  and ``run_inline=True`` (load-bearing, commented). End-to-end tests run the
  real ``tool.run(..., callbacks=[handler])`` dispatch path; the ``langchain``
  extra is now part of ``[dev]`` so CI exercises them.
- **MCP server: missing required arguments were a clean verdict.** A
  ``tools/call`` omitting a schema-required argument (e.g. ``detect_injection``
  called with the wrong key) silently scanned the empty string and returned
  CLEAN/ALLOW. The server now enforces each tool's declared
  ``inputSchema.required`` (derived from the published definitions, so
  enforcement cannot drift from ``tools/list``) and returns ``isError``.
- **Gate constraint-evaluation errors leaked internals.** The caller-visible
  DENY reason included the raw exception text; it is now generic, with the full
  traceback logged server-side only.

### Added

- **``Scanner(require_receipts=True)``** — fail-loud mode: failure to issue
  the verdict receipt, audit event, or provenance receipt raises
  ``ReceiptEmissionError`` instead of warn-and-continue (default unchanged).
- **Runnable LangChain demo** (``examples/langchain_demo/``) — no API key:
  legitimate payment ALLOWED, prompt-injected transfer DENIED before
  execution, signed receipt chain verified offline, tampering detected. Exit
  code doubles as a CI self-test.
- **MCP client quickstart** (``docs/getting-started/03-mcp-clients.md``) —
  2-minute setup for Claude Desktop, Claude Code, Cursor, Cline/Continue.
- **Registry publication pipeline** (``.github/workflows/publish-reference.yml``)
  — tag ``ref-v<version>`` publishes ``@raucle/provenance`` (npm, with
  provenance attestation), ``raucle-provenance`` (crates.io),
  ``Raucle.Provenance`` (nuget.org) and tags the Go nested module, gated on
  the 5-port cross-language conformance harness.
- Issuer ↔ standalone ``cap-verifier`` conformance round-trip tests; first
  test coverage for the REST server's auth fail-closed paths and the ML →
  heuristic classifier fallback.

### Fixed — other

- ``provenance-rs`` ``spec_vectors`` test could not load the v0.18.0 vectors
  file (the intentional lone-surrogate vector is unrepresentable in a Rust
  ``String``); the test now neutralises lone-surrogate escapes at load and
  skips ``must_reject`` vectors. This would have blocked ``cargo publish``.
- Rust crate metadata pointed at the wrong repository URL.
- CI language-setup actions pinned to commit SHAs (closing a documented
  policy deviation); duplicate-key JSON rejection consolidated into a shared
  ``_canon`` helper; proposal docs no longer reference phantom release
  versions; retired ``commercial@raucle.com`` contact replaced.

## 0.19.0 (2026-06-08) — relicensed to Apache-2.0

**The core package is now licensed under the Apache License, Version 2.0.**
This replaces the previous AGPL-3.0-or-later + commercial dual-licence model.

### Changed — licensing

- **Core (`raucle_detect/`) relicensed from AGPL-3.0-or-later to Apache-2.0.**
  Apache-2.0 is permissive and includes an explicit patent grant, making the
  engine trivial to embed in any agent runtime, gateway, SDK, or cloud —
  consistent with the goal of becoming the de-facto reference for verifiable
  agent authorization and provenance receipts.
- **Dual-licence apparatus retired.** Removed `COMMERCIAL.md`, `CLA.md`, and the
  `commercial@raucle.com` licensing lever. Contributions are now Apache-2.0
  (inbound = outbound) under the existing [DCO](DCO) sign-off; no separate
  copyright-assignment CLA is required.
- **Trademark posture unchanged.** Apache-2.0 §6 does not grant rights to the
  **"Raucle"** name; the trademark remains held separately
  (see [TRADEMARK.md](TRADEMARK.md)).
- **Unaffected:** the five reference implementations (`reference/`) remain MIT;
  the Provenance Receipt specification remains CC-BY-4.0.

> **Note on earlier releases.** This change is forward-looking. Releases
> **≤ v0.18.0** were published under AGPL-3.0-or-later and remain available under
> those terms; it does not retroactively alter copies already received.

## 0.18.0 (2026-06-02) — cross-language canonicalisation fix (B7) + interop vectors

A correctness release centred on a real **cross-language signing bug** found by
cross-model (Codex) review and hardened out across ~20 find→fix→verify rounds.

### Fixed — cross-language byte-identity (security/correctness)

- **Non-BMP object-key ordering diverged across the five reference encoders.**
  Python/Go/Rust sorted object keys (and `parents`/`taint`) by Unicode **code
  point**; TypeScript/C# by **UTF-16 code unit**. Identical for BMP/ASCII (so
  every shipped vector passed) but divergent for non-BMP (astral) keys — any
  signed object with an emoji/astral key would hash to different bytes across
  languages. All five are now unified on **UTF-16 code-unit ordering**
  (RFC 8785 / JCS §3.2.3), the spec's normative rule (§4.3.1). **Byte-neutral
  for all existing BMP material — no signature/ID churn.**
- All Python signed-material canonicalisers (`provenance`, `capability`,
  `prove`, `audit`, `feed`, `verdicts`) and the OWASP `cap-verifier` share one
  UTF-16 canonicaliser (`raucle_detect/_canon.py`).

### Added

- **New interop test vectors** — `canonicalization_vectors` and
  `invalid_canonicalization_vectors` in the published v1 set, including an
  A2A/APS `action_ref`-shaped vector. Each exposes the JCS preimage,
  `expected_canonical_hex`, and SHA-256; the invalid set covers floats and
  out-of-range integers that MUST be rejected.
- **`reference/canon_conformance.py`** — drives all five encoders and proves
  5-language byte-identity on the published vectors, non-BMP probes, and
  invalid-rejection.

### Hardened — capability gate / cap-verifier parity (fail-closed)

- Verifiers reject unsorted/duplicate `parents`/`taint`; `Capability.from_dict`
  validates all signed string fields, `parent_id` shape, and timestamps (no
  coercion) and rejects non-object input — every failure fails closed with
  `ValueError`.
- The OWASP `cap-verifier` reference brought to single-token parity with the
  gate (numeric/NaN/safe-int, unknown kinds, bool bounds, agent-id regex, NFC
  field names, constraint shapes, attenuation-chain deny, empty-field rejection).

### Docs

- Spec §13 now cites the authoritative GitHub vectors URL (always current;
  pin a tag for a stable snapshot).

## 0.17.0 (2026-06-01) — fail-closed redesign (stricter by default)

A structural pass that flips the prover/gate/verifier from "enumerate-bad" to
**fail-closed**: anything the system does not explicitly model now hits a
conservative verdict (gate → DENY, prover → UNDECIDED, mint/verify → reject)
**by construction**, driven by a single executable **Modelled Language Registry**
(`raucle_detect/registry.py`) with a CI drift guard. Designed across three
cross-model (Codex) design-review passes and hardened across three cross-model
code-review passes (6 fail-open blockers + 2 governance items closed) before
release.

### ⚠️ Breaking / stricter-by-default

- **Provenance chain envelope is now minimal `{receipt_hash, jws}`.** The
  previous format mirrored the whole payload into the envelope (unsigned,
  unvalidated). The verifier now rejects any other top-level field (no wildcard
  extension in v1). **Existing chain files with the old rich envelope will be
  rejected** — re-emit them (the authoritative payload is inside the signed JWS).
- **Canonical integers are bounded to the JS-safe range ±(2^53−1)** in all five
  reference encoders, so values round-trip byte-identically across
  Python/TS/Go/Rust/C#. Integers outside this range are rejected at
  sign/verify. (Real timestamps and bounds are far inside this range.)
- **Some inputs that previously returned `PROVEN` now return `UNDECIDED`:**
  policies carrying keys the prover does not model (`allowed_values`,
  `starts_with`), URL grammars/policies with unmodelled keys, and SQL templates
  using unmodelled constructs (quoted identifiers, `LATERAL`/`UNNEST`/`VALUES`,
  recursive CTEs, table functions). Narrow the grammar or accept UNDECIDED.
- **Some malformed constraint shapes now raise at mint** instead of being
  signed: non-list value sets (sets/tuples), non-JSON-scalar members, `bool`/
  float numeric bounds, non-string `starts_with` prefixes, and field names that
  collide under Unicode NFC.
- **`CapabilityGate.check` denies a token citing a `parent_id` when no
  `parent_resolver` is configured** (the chain cannot be verified → fail closed).
- **`from_jws(strict=True)` now also validates per-receipt structure** (root
  rule, required fields, sorted/unique parents+taint); pass
  `validate_structure=False` for the chain-verifier path that reports per-line.

### Security fixes (fail-open paths closed)

- **Decorative proof inputs (§8.2):** the JSON prover ignored
  `allowed_values`/`starts_with` while the gate enforced them, so a policy could
  be PROVEN with those keys silently dropped. Unmodelled policy keys now force
  UNDECIDED.
- **URL prover fail-open:** unknown URL grammar/policy keys returned PROVEN; now
  UNDECIDED.
- **SQL unmodelled-construct net was conditional** on `allowed_tables`; it now
  runs unconditionally, and unknown SQL grammar/policy keys force UNDECIDED.
- **Reference-verifier canonical parity (§8.10):** the TS/Go/Rust/C# verifiers
  now re-encode and byte-compare header+payload (JCS), matching Python — a
  non-canonical receipt no longer verifies in the ports.
- **JSONL envelope hardening:** duplicate-key rejection on the envelope wrapper
  (not just the inner JWS) and rejection of unknown envelope fields.
- **Unresolved attenuation chain DENY** (§8.7) and **mint value-domain
  rejection** (§8.5), as above.

### Scope & claims (read before citing)

- **SQL:** the SQL component is a **finite SQL-template checker over a modelled
  subset**, not a general "SQL prover". It proves properties over an enumerated
  set of statement templates; anything outside the modelled construct surface
  (quoted identifiers, `LATERAL`/`UNNEST`/`VALUES`, recursive CTEs, table
  functions, …) returns UNDECIDED.
- **`forbidden_values` is a best-effort denylist.** The gate enforces it on the
  argument *names* the policy declares; it cannot see a tool's full parameter
  schema, so a forbidden value supplied under a different parameter name is not
  caught. For security-critical fields prefer the fail-closed positive
  constraints — `allowed_values`, `required_present`, `max_value`/`min_value`.
- **Strict proof mode is opt-in.** `CapabilityGate(proof_enforcement_mode=...)`
  defaults to `"off"` for backward compatibility, so a token's
  `policy_proof_hash` is *informational* unless an operator enables
  `"lenient"`/`"strict"`. **Offline, proof-backed authorisation claims require
  strict proof mode** — without it the gate does not consult or enforce the
  cited proof.

### Internal

- **Modelled Language Registry** (`registry.py`): the executable source of truth
  for constraint kinds, JSON-schema keywords, URL/SQL grammar+policy keys, the
  SQL construct surface, and envelope fields. Runtime allowlists derive from it;
  `tests/test_registry_drift.py` fails CI if any consumer's modelled set diverges
  (exact `.get()`-literal extraction, not a heuristic scan).
- Consolidated strict receipt verification into a single documented
  `_validate_receipt_strict()` contract (§3.3).

## 0.16.4 (2026-06-01) — prover soundness + adapter scope (cross-model review)

Findings from an independent cross-model (Codex) review, on top of the round-3
adversarial audit and SonarQube static analysis. No wire-format change.

- **JSONSchemaProver soundness (was a false PROVEN):** a `forbidden_values`
  policy over a field that the schema permits via `additionalProperties` was
  silently discarded, returning PROVEN even though e.g. `{"x":"ok","role":"admin"}`
  is schema-valid and violates the policy. The prover now models an
  attacker-suppliable additional property as a free variable and REFUTES (with a
  counterexample); a closed schema (`additionalProperties: false`) keeps the
  blacklist correctly vacuous.
- **Agent Framework adapter:** the caller identity passed to the gate is now the
  framework context's caller (deployer-populated `metadata`/`session`), not the
  in-force token's own `agent_id` — so the token's agent scope is actually
  enforced against the caller rather than checked against itself. Falls back to
  the token's `agent_id` only when the framework surfaces no identity.
- **Receipt verifier:** strict verification additionally enforces the JOSE `typ`
  (`provenance-receipt/v1`) and the `raucle/v1: "provenance"` profile marker
  (spec v1 §4.1), after the existing alg/crit/kid/signature checks.

## 0.16.3 (2026-06-01) — static-analysis hardening (SonarQube Cloud)

Findings from a third, independent analysis method (SonarQube Cloud static
analysis), on top of the round-3 adversarial audit. No wire-format change;
five-language byte-identity preserved.

- **feed.py:** pin an explicit TLS 1.2 floor (`ctx.minimum_version`) rather than
  relying on the interpreter default — defence in depth for the (already
  SSRF-pinned) feed fetch. Adds a live DNS-rebind pin integration test.
- **TS reference impl:** strip base64url padding with `String#replaceAll` (no
  ReDoS-shaped regex); make the JCS canonical sort use an explicit UTF-16
  code-unit comparator (documented NOT to be `localeCompare`, which would break
  cross-language byte-identity). Behaviour byte-identical.
- **cli.py:** avoid a float-equality check in the fuzz coverage gate
  (`coverage <= 0.0`).
- Scoped SonarQube Cloud analysis to the shipped package via
  `.sonarcloud.properties`. Security and Reliability ratings: A (0 vulnerabilities,
  0 bugs).

## 0.16.2 (2026-06-01) — security hardening (round 3 + blind cross-check)

Two independent adversarial audits (a multi-agent finder/refutation workflow plus
a blind independent pass) and manual verification of every fix. No receipt wire-format
change; five-language byte-identity preserved. 20 new security regression tests.

- **Provers:** `SQLClauseProver` no longer returns PROVEN for a query reading a
  forbidden table via `EXCEPT`/`INTERSECT`/`MINUS`; default forbidden tokens add
  `INTO`/`MERGE`/`CREATE`; `URLPolicyProver` returns UNDECIDED for `forbid_query_keys`
  over an open query-key grammar (declare `query_keys_closed: true` to prove it).
- **Adapters:** the AutoGen adapter now enforces the token's `agent_id` scope (was
  recorded in the receipt but not checked); the LangChain adapter fails closed when a
  `forbidden_values` blacklist can't be enforced on an opaque string tool input.
- **Provenance verifier:** binds receipt `agent_id` to the capability statement,
  enforces statement `expires_at`, and requires the JOSE `kid` to equal `agent_key_id`
  (matching the TS/Go/Rust/C# verifiers).
- **Audit:** keyless verification of a chain declaring `signed=true` now fails closed
  (was reporting valid); `allow_nan=False` in canonical JSON; a non-hex (tampered) leaf
  hash yields `valid=False` instead of crashing.
- **Server:** request body / batch size caps, rate-bucket eviction (+ opt-in
  `RAUCLE_TRUST_PROXY`), and `/metrics` gated behind auth when an API key is set.
- **Other:** multimodal media/pixel/page caps; fixed a dead SSRF-pinning path in
  `fetch_feed`; CLI keygen writes private keys 0600 atomically; MCP no longer echoes
  raw exception text; conformance harness only claims five-language parity when all
  five run; formal-proof claims in README / Lean docs scoped to what is actually
  mechanised (the runtime gate enforces more than the Lean model proves).

## 0.16.1 (2026-06-01) — CLI developer-experience fix

No behaviour or wire-format changes. Polishes the command-line surface.

- **CLI:** expected user errors (missing file, invalid JSON, missing optional
  extra, malformed input) now print a one-line `error: ...` to stderr with a
  non-zero exit code instead of a raw Python traceback. Genuinely unexpected
  errors still raise a stack trace for debugging.
- **CLI:** `--help` description now reflects the product — verifiable
  authorization & audit (capability tokens, SMT/Lean-proven policies, signed
  provenance receipts), not just prompt-injection detection.

## 0.16.0 (2026-06-01) — security hardening (round 2 + re-audit)

A full security-focused audit + confirmation re-audit. All CRITICAL/HIGH/MEDIUM
findings closed with regression tests; receipt wire format unchanged (five-language
byte-identity preserved). New `docs/security-model.md` documents the trust model.

- **Gate:** reject non-finite numbers (NaN/Inf no longer satisfy numeric bounds);
  agent_id grammar forbids trailing/double dots; revocation denies descendants of a
  revoked ancestor when a resolver is configured.
- **Provenance:** SANITISATION may only clear taint tags the agent's
  `sanitisation_authority` permits (verifier-side); unknown `agent_key_id` is a
  violation when capabilities are supplied; `from_jws` hardened (size caps, duplicate
  keys rejected, strict `alg`/`crit`).
- **Audit chain:** signed chains require a head checkpoint covering the final index;
  `verify_chain(expected_head=...)` external anchor; unsigned/unknown chains are invalid
  when a key is supplied.
- **Provers:** `SQLClauseProver` no longer returns PROVEN for comma-join / subquery
  table references it can't soundly resolve (UNDECIDED instead); `URLPolicyProver`
  `max_path_depth` is UNDECIDED over prefix grammars.
- **Scanner:** ReDoS fixed — per-pattern length cap on ALL patterns, bounded wildcard
  spans, per-scan wall-clock budget (an 82s pathological scan is now ~0.01s).
- **Feed:** `fetch_feed` is https-only, blocks private/loopback/metadata IPs, pins the
  validated IP (no DNS-rebind), rejects redirects, caps body size.
- **Keys/supply chain:** private keys written `0600`; `*.pem`/`*.key` git-ignored; CI
  actions pinned to commit SHAs.

## 0.15.0 (2026-06-01) — security hardening

Pre-launch end-to-end audit. Closes gate-authorisation bypasses, hardens the
proof/verifier guarantees, and makes the reference implementations genuinely
interoperable.

### Security (gate)
- **Agent-id privilege escalation fixed.** Agent matching required a bare
  prefix, so a token for `agent:billing` authorised `agent:billing-evil`.
  Now requires exact match or a dot-delimited descendant (`agent:billing.x`);
  same fix in `attenuate()`.
- **Constraint bypass-by-omission fixed.** Value constraints were skipped when
  the named field was absent, so aliasing/omitting an argument bypassed them.
  Positive/bound constraints (`allowed_values`, `starts_with`, `max_value`,
  `min_value`) now **fail closed** on an absent field. (Documented limitation:
  `forbidden_values` blacklists can still be aliased without the tool schema —
  prefer `allowed_values`.)
- **Fail-open/DoS fixed.** Numeric bounds raised an unhandled `TypeError` on
  non-numeric args; non-numeric/bool now DENY, and the whole constraint check
  is wrapped so any error is a DENY, never a propagated exception.
- **Strict proof mode binds to enforced constraints.** A token can no longer
  cite a PROVEN proof over an unrelated policy; in strict mode `policy_hash`
  must equal the hash of the token's own constraints.

### Security (provenance)
- **Verifier-side capability enforcement.** `ProvenanceVerifier` accepts an
  optional `capabilities=` map and independently rejects receipts whose
  model/tool the issuing agent's `CapabilityStatement` does not permit (the
  cross-check the docstring already claimed). Adds `capability_violations`.

### Reference implementations
- **All five impls are now byte-identical.** The TS/Go/Rust/C# ports had each
  diverged from the Python reference and could not reproduce its receipt IDs.
  Reworked to match byte-for-byte; added `reference/conformance.py` proving
  identical `receipt_hash` across all five for every published test vector.

### Docs / claims
- Every quickstart snippet now runs verbatim (`[compliance]` install, real
  `HashChainSink`/`prove`/`audit verify` APIs, dead links removed).
- Eval claims scoped to the evidence (banking-suite '100%', restated latency,
  per-receipt vs one-time-Lean verification).
- Package metadata: author email + URLs corrected to live targets.

## 0.14.0 (2026-06-01)

### Capability constraints

- **`starts_with` prefix constraint** is now a first-class capability
  constraint, enforced at the gate (`{"starts_with": {"field": "prefix"}}`)
  and supported in attenuation (a child may extend a prefix, never broaden
  it). This was referenced in the docs/examples but previously unsupported;
  the headline quickstart now mints **and enforces** as written.
- **Unknown constraint keys now raise** instead of being silently dropped,
  so a mis-cased key (e.g. `allowedValues` vs `allowed_values`) can no
  longer produce a token that enforces less than intended.

### Capability gate — revocation

- `CapabilityGate` now accepts `revoked_token_ids` and exposes a
  `revoke(token_id)` method. A revoked token, or any child citing it as
  `parent_id`, is DENY'd before expiry — the early-revocation path that
  complements short TTLs.

### Fixes & docs

- `__version__` now tracks the package version (was stale at `0.7.0`).
- Spec: added non-normative appendices — related work (vs Biscuit /
  Macaroons / in-toto / SLSA / C2PA / VCs), canonical-form rationale, and
  the token lifetime/revocation model.
- Legal/governance docs name the registered entity, **Raucle
  as Raucle)**, so the dual-licence relicensing grant is unambiguous.
- CI: bumped `actions/checkout`→v5, `setup-python`→v6 (Node-20 retires
  2026-06-16).

## 0.13.0 (2026-05-28)

### Security — fail-loud cryptographic configuration (HOLD SCOPE FIX 1)

Six places in the codebase used `try / except: pass` patterns that silently
degraded cryptographic guarantees when configuration was wrong. Banking and
healthcare deployers explicitly do NOT want a silent fallback — they want a
loud failure they can act on. The behaviour is now:

- **Explicit config + broken = REFUSE.** Operator misconfigured the
  deployment; raise `ConfigurationError`, exit non-zero.
- **No config + safe default exists = WARN.** Log a prominent WARNING and
  continue in explicitly-marked unsigned mode.
- **Never silent.**

Specifics:

- `raucle_detect/errors.py` — new module exposing two named exception types:
  `ConfigurationError` (broken explicit config) and `PolicyUnproven` (strict
  mint mode refused).
- `raucle_detect.server._init_compliance()` — extracted from import-time
  init. When `RAUCLE_DETECT_VERDICT_KEY_PEM` or
  `RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM` is set but unparseable, raises
  `ConfigurationError` (module import fails; uvicorn refuses to start).
  When no key is configured at all, emits a `WARNING` and continues in
  unsigned mode.
- `VerdictSigner.__init__` and `Ed25519Signer.__init__` — replaced
  `except Exception: self._public_pem = b""` with a `logger.error(...)` +
  `raise ConfigurationError(...)`. A signer that cannot expose its public
  key cannot produce verifiable receipts; the swallowed-error path produced
  receipts that looked normal but were silently unverifiable.
- `audit.sink_from_env()` — when `RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM` is set
  but invalid, raises `ConfigurationError` instead of warning and returning
  an unsigned sink.
- `HashChainSink.__init__` — when no signer is supplied, emits a prominent
  `WARNING` at construction. **Every newly-created chain now writes a
  `chain_meta` header on line 1** carrying `{signed: bool, version, key_id?,
  signature?, created_at}`. The header is Ed25519-signed when a signer is
  present.
- `AuditVerifier` — reads the header and surfaces
  `report.signed_mode ∈ {"signed", "unsigned", "unknown"}` plus
  `report.chain_key_id`. Rejects signed checkpoints appearing in chains
  whose header declares `signed=false` (forgery indicator). Rejects
  checkpoints whose `key_id` does not match the header's `key_id`
  (cross-chain splice indicator). Legacy chains without a header remain
  verifiable but report `signed_mode == "unknown"`.

### Security — strict proof-enforced mint mode (HOLD SCOPE FIX 2)

Until now, `cap mint --policy-proof-hash` was advisory: a caller could pass
any string. Tokens cited proofs they had no structural relationship to. The
new strict mint mode makes the relationship enforceable:

- `Capability` gains two new optional fields, `grammar_hash` and
  `policy_hash`. Both nullable; backward-compatible default-absent. When
  set, they're covered by `token_id` and the signature.
- `CapabilityIssuer(..., require_proof=False)` is the new default; passing
  `require_proof=True` (or setting `RAUCLE_REQUIRE_PROOF=1`) enables strict
  mode. In strict mode, `mint()` requires a `ProofResult` whose `status` is
  `PROVEN` — anything else (absent, REFUTED, UNDECIDED) raises
  `PolicyUnproven`. The bound `policy_proof_hash`, `grammar_hash`, and
  `policy_hash` are taken from the supplied `ProofResult` so the linkage is
  structural, not advisory.
- Even outside strict mode, `mint(proof_result=...)` refuses to bind a
  non-PROVEN proof and refuses to bind contradictory hashes.
- `CapabilityGate` gains `proof_enforcement_mode ∈ {"off", "lenient",
  "strict"}` and `trusted_proofs: dict[str, ProofResult]`. Defence-in-depth
  at gate time: `"lenient"` warns on missing/invalid proof; `"strict"`
  denies. Default `"off"` preserves existing behaviour. (Registry-fetcher
  ships in a follow-up; current cache is in-memory + caller-supplied.)
- CLI: `raucle-detect cap mint --require-proof --proof-result PATH` for the
  strict path. `--policy-proof-hash` still works for the legacy advisory
  path.
- `raucle-detect prove json|url|sql` already returned exit-code 2 on REFUTED
  and 1 on UNDECIDED — both non-zero, both pipeline-fail by `set -e`. Now
  asserted by tests so CI never silently regresses.

15 new tests across `tests/test_audit.py`, `tests/test_verdicts.py`,
`tests/test_capability.py`, `tests/test_server_init.py`,
`tests/test_cli_exit_codes.py`.

## 0.12.0 (2026-05-27)

### Microsoft Agent Governance Toolkit integration — now first-class

raucle's contribution at [microsoft/agent-governance-toolkit#2610](https://github.com/microsoft/agent-governance-toolkit/pull/2610) — adding `proof_artefact` and `verification_pointers` carry-through on AGT's `BackendDecision` — **merged upstream on 2026-05-27** (commit `25abf72`, accepted by Microsoft maintainer Imran Siddique). raucle's reference integration ships in this release as a first-class module.

- **`raucle_detect.integrations.agt_backend.RauclePolicyBackend`** — implements AGT's `agent_os.policies.backends.ExternalPolicyBackend` Protocol. Plug raucle into any AGT-governed agent through the same seam OPA and Cedar already use. The backend reads the in-force capability token from the asyncio-ContextVar that the Agent Framework middleware also uses, so a single primed token covers both integration paths.
- Every `BackendDecision` raucle returns carries the cited `proof_artefact` (the policy proof hash from the capability token) and a `verification_pointers` dict (issuer pubkey URL, policy registry URL, optional Lean development URL). AGT's `PolicyEvaluator` propagates both into `PolicyDecision.audit_entry`, so any AGT audit-chain consumer immediately gets offline-verifiable evidence attached to every raucle-rendered decision.
- Graceful degradation — the backend detects whether the installed AGT carries the merged fields and silently drops them on older installs. raucle deployments survive pre-merge AGT.
- 7 tests in `tests/test_agt_backend.py`. Skipped automatically when `agent_os` is not installed; passing 7/7 against `microsoft/agent-governance-toolkit@main` post-merge.

This is the second of the three Microsoft-stack integrations. v0.11.0 shipped the Agent Framework `FunctionMiddleware`; v0.12.0 ships the AGT backend; the third (Azure AI Foundry MCP Gateway sidecar) ships when the recorded walkthrough lands.

### Stub-shape integration deprecated

The pre-merge `raucle_detect.integrations.agt` module — containing the `IPolicyProvider` stub we originally proposed (Microsoft instead chose to keep the existing `ExternalPolicyBackend` Protocol they already ship, which we then extended) — remains importable for one minor version and will be removed in v0.13.0. New consumers should use `raucle_detect.integrations.agt_backend.RauclePolicyBackend`.

## Unreleased

### Relicensed: MIT → AGPL-3.0-or-later + commercial

raucle-detect is now dual-licensed. The default open-source licence becomes the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later); a commercial licence is available from Raucle for organisations whose use is incompatible with AGPL terms.

The change protects the project from being absorbed into closed-source commercial forks while preserving full openness for self-hosting enterprises, academic research, security audits, and contributors. Self-hosting inside a single organisation for internal use — the dominant use case in our regulated-fintech ICP — is unaffected.

Versions tagged on or before commit `ac9aed0` remain available under the MIT licence under which they were released. See [LICENSING.md](LICENSING.md) for the rationale. (Note: the project was subsequently relicensed to Apache-2.0 in v0.19.0; the AGPL + commercial dual-licence described in this historical entry applied to releases v0.10.0–v0.18.0.)

## 0.10.0 (2026-05-14)

### Capability-based agent permissions — unforgeable tool handles

Every prompt-injection mitigation in 2026 still asks an LLM, in English, not to misuse its tools. v0.10.0 replaces that polite request with an OS-style capability discipline: a tool refuses to execute unless the caller presents an Ed25519-signed `Capability` token whose constraints are satisfied by the actual call arguments. Prompt injection becomes structurally irrelevant for tool calls — the malicious instruction has nothing to act with.

- **`Capability`** — the token. Binds `(agent_id, tool, constraints, nbf, exp, parent_id, policy_proof_hash, issuer, key_id)` under one Ed25519 signature. Constraint schema mirrors v0.9.0's `JSONSchemaProver` policy keys: `forbidden_values`, `allowed_values`, `max_value`/`min_value`, `required_present`, `forbidden_field_combinations`.
- **`CapabilityIssuer`** — mints fresh tokens; attenuates parents into more-restricted children.
- **`CapabilityIssuer.attenuate()`** — the killer property. A child cannot outlive its parent. A child's bounds can only narrow (min of two `max_value`s; intersection of two `allowed_values`; union of two `forbidden_values`). A child's `agent_id` must be a prefix-extension of the parent's. Broadening is structurally impossible.
- **`CapabilityGate`** — the choke point. `check(token, tool, args)` verifies issuer pinning, signature, `token_id` binding, time bounds, tool match, agent match, and every constraint against the supplied args. Optional `parent_resolver` walks the full attenuation chain. Fails closed by default.
- **`policy_proof_hash`** — a token can cite a v0.9.0 `ProofResult.hash`, claiming "these constraints are formally complete over this tool's schema". The proof, the receipt, the audit chain, and the capability all reference each other by hash. The trust graph closes.
- **CLI** — `raucle-detect cap keygen | mint | verify | check | attenuate`. Exit codes: 0 OK / ALLOW, 2 INVALID / DENY.
- 20 new tests covering signing, expiry, tampering, every attenuation invariant, full chain verification, and serialisation round-trip.

This is Move #2 of the revolutionary roadmap. With v0.9.0 (proofs over the tool grammar) and v0.10.0 (unforgeable handles to invoke that tool), the strongest agent-safety story on the market is now MIT-licensed open source.

## 0.9.0 (2026-05-14)

### Formal verification of bounded guardrails — proofs, not statistics

Every other AI security product on the market ships with the same line: *"tested against 10,000 attacks."* That is statistics over a sample. For bounded sub-languages — tool-call JSON and URL allowlists — we can do dramatically better: produce an actual **proof** that no string in the grammar bypasses a given policy. (SQL is narrower: a finite-template checker over a *modelled subset* that returns `UNDECIDED` for constructs it does not model — not a general SQL proof. See the v0.17.0 "Scope & claims" note for the precise framing.) v0.9.0 is the first release of that machinery.

- **`JSONSchemaProver`** — SMT-backed (Z3). Given a JSON Schema (type=object with primitive properties + enum + min/max) and a policy (`forbidden_values`, `max_value` / `min_value`, `required_present`, `forbidden_field_combinations`), returns `PROVEN` or a **concrete counterexample tool-call**. The right thing to point at every agent's tool-call interface.
- **`URLPolicyProver`** — enumerative. `require_https`, `forbid_query_keys`, `host_allowlist` (with `*.example.com` wildcards), `max_path_depth`. Counterexamples are concrete URLs.
- **`SQLClauseProver`** — bounded read-only-ish policy over a finite set of statement templates. `forbidden_tokens` (DROP, DELETE, TRUNCATE…), `allow_statement_chaining`, `allowed_tables`. Counterexamples include the offending template plus the rule that broke.
- **`ProofResult`** — canonical-JSON-hashed artifact carrying `(status, prover, prover_version, grammar_hash, policy_hash, counterexample, notes, timeout_ms)`. The hash drops straight into the v0.5.0 receipt and v0.4.0 audit chain — proof artifacts become first-class citizens of the trust graph.
- **`UnsupportedGrammar`** — explicit refusal. Recursive schemas, arbitrary string regex constraints, and full SQL grammars raise instead of pretending to prove something they can't. Honest scope beats lying coverage.
- **CLI** — `raucle-detect prove json --schema tool.json --policy policy.json`, `prove url --grammar grammar.json --policy policy.json`, `prove sql --grammar grammar.json --policy policy.json`. Exit codes: 0 PROVEN, 2 REFUTED, 1 UNDECIDED.
- **Optional `[proof]` extra** — `pip install 'raucle-detect[proof]'` pulls Z3. Core stays dependency-free.
- 19 new tests covering positive proofs, refutation paths with concrete counterexample inspection, hash determinism, and the rejection of unsupported grammars.

This is the depth play. The v0.8.0 feed is breadth — fast distribution of known badness. v0.9.0 is depth — cryptographic guarantees about declared interfaces. Together they bracket the field.

Move #3 of the revolutionary roadmap.

## 0.8.0 (2026-05-14)

### Federated signed-IOC feeds — Sigstore-shaped threat intel for AI

Every new deployment that subscribes makes every other deployment safer. Novel jailbreaks discovered by one team propagate to every gateway worldwide, cryptographically signed, no central authority, no API token.

- **`SignedIOC`** — content-addressed Indicator of Compromise. Fields: `kind` (`regex` | `substring` | `unicode_signature`), `pattern`, `severity`, `categories`, `issuer`, `key_id`, `issued_at`, optional `revokes` / `expires_at`. Body is canonical-JSON-hashed; `content_hash` is the identifier; Ed25519 `signature` is mandatory.
- **`Feed`** — a bundle of IOCs from one issuer, plus a Merkle root over sorted content hashes and one manifest signature. Every IOC is *also* individually signed, so partial copies remain verifiable offline.
- **`IOCSigner`** — publisher API. `generate(issuer=...)`, `sign_ioc(...)`, `build_feed(...)`, `save_private_key(...)`. Pure Ed25519 (`cryptography` extra).
- **`FeedStore`** — consumer API. Directory-backed, pinned-pubkey verification on every merge, honours intra-issuer `revokes`, drops expired IOCs. Renders the live set as pattern rules consumable by `Scanner(feed_store=...)`.
- **`Scanner(feed_store=...)`** — one new keyword. Feed-derived rules merge alongside built-ins and custom YAML, with `source: "feed:<issuer>"` carried through to `matched_rules` so downstream audit/receipt can attribute every hit.
- **Trust model** — no global root. Consumers pin one issuer pubkey per feed. Multiple feeds compose. Hostile cross-issuer revocations are silently ignored: an issuer can only revoke its own IOCs.
- **CLI** — `raucle-detect feed keygen`, `feed sign`, `feed verify`, `feed pull`, `feed list`.
- **Composition** — feed-derived rules participate in the ruleset hash bound into every v0.4.0 audit-chain entry and v0.5.0 signed receipt. Subscribing to a feed mutates the verdict surface in a way that is itself attestable.

This is the network-effect layer. Move #6 of the frontier roadmap.

## 0.7.0 (2026-05-14)

### Multimodal scanning — the 2026 attack surface

Attackers are no longer typing `ignore all previous instructions`. They hide it inside images (OCR + invisible-pixel encoding), audio (steganography), ASCII art (the ArtPrompt class), EXIF metadata, PDF streams, and zero-width Unicode wrapped around innocent-looking text. This release adds the detection layer text-only scanners miss.

- **`strip_invisible_unicode(text)`** — dep-free, always available. Strips zero-width spaces (U+200B/C/D), bidi overrides (U+202A–E, U+2066–9), variation selectors (U+FE00–F, U+E0100–1EF), word joiners (U+2060–4), the entire **tag-character block** (U+E0001–7F) used in 2024-era invisible-prompt attacks, the BOM, and the soft hyphen. Returns the cleaned string plus a list of every codepoint that was hidden, so the finding can be surfaced rather than silently sanitised away.
- **`detect_ascii_art(text)`** — dep-free heuristic for the **ArtPrompt** class. Identifies blocks of 5+ consecutive art-shaped rows (high fill-character density, low alphanumerics), then matches each 6-column slice against a library of 13 letter glyphs (A, B, E, G, I, N, O, P, R, S, T, U, V) at a 70% structural-similarity threshold. Catches the canonical "draw the word IGNORE in `#` characters and ask the model to read it" attack without needing OCR.
- **`MultimodalScanner`** — orchestrator that wraps a `Scanner` and pre-processes input through every detector. Returns a typed `MultimodalScanResult` with a `combined_verdict` that auto-escalates to MALICIOUS when any HIGH-severity finding is present — *seeing* invisible-Unicode in prose is itself evidence of bad intent, separate from what the scrubbed text scans as.
- **Image scanning** via Tesseract OCR + EXIF inspection. Extracts text from `.png`/`.jpg`/etc., inspects EXIF for prompt-bearing metadata, concatenates everything, and feeds it back through the standard text scanner. Requires the `[multimodal]` extra (Pillow + pytesseract + tesseract on PATH).
- **PDF scanning** via `pypdf` stream extraction. Same pattern: extract text, scrub, scan.

### New CLI

- **`raucle-detect scan-image <path>`** — full pipeline. `--mode`, `--rules-dir`, `--format table|json`. Exit code 0/1/2 by verdict.
- **`raucle-detect scan-pdf <path>`** — same options.
- **`raucle-detect scrub <text>`** — quick utility. Reports every invisible codepoint in the input and prints the scrubbed text.

### Deliberately not done yet

- Audio steganography — needs librosa/audio deps; deferred to a future release with its own `[audio]` extra.
- Image-pixel-encoded prompts (least-significant-bit steganography) — separate detector, separate PR.
- Multimodal LLM input correlation — Scanner currently treats text and image as separate scans.

### Stats

- 1 new module (`multimodal.py`)
- 3 new CLI commands (`scan-image`, `scan-pdf`, `scrub`)
- 22 new tests (20 dep-free + 2 that gracefully skip without Pillow/pypdf)
- 333 tests passing total
- New optional dependency group: `pip install 'raucle-detect[multimodal]'`

### Compatibility

All new functionality additive. `Scanner` unchanged. Existing chains, receipts, replay flows continue to work. Version 0.6.0 → 0.7.0.

## 0.6.0 (2026-05-14)

### Counterfactual replay — the SOC killer feature

Given any provenance chain produced by v0.5.0, you can now re-run every guardrail decision in it against a *different* policy and see exactly what would have changed. Answers the question every incident response actually needs: *"if we'd had stricter rules on last Tuesday, would we have caught this?"*

- **`InputStore`** — JSONL-backed, append-only, hash-verified mapping of `input_hash → original_text`. Lives alongside (not inside) the provenance chain so receipts stay privacy-by-default. Tampered entries are detected on lookup and reported as missing rather than silently returning the wrong prompt.
- **`Replayer`** — walks every `guardrail_scan` receipt in a chain, looks up the original input in the store, re-runs against a fresh `Scanner` configured with the counterfactual policy, and emits a typed diff.
- **`ReplayResult`** — separates **unchanged**, **newly blocked**, **newly allowed**, **newly alerted**, and **missing-input** receipts. Each `ReplayChange` carries the original receipt hash, the verdict transition, and a one-line explanation pulled from the new scan's matched rules.
- **Scanner integration** — pass `input_store=` to `Scanner()` and every `scan` / `scan_output` / `scan_tool_call` automatically persists the input text to the store. Opt-in, zero-cost when not configured.

### CLI

- **`raucle-detect provenance replay <chain> --input-store <store>`** — table or JSON output. Flags: `--mode` (strict/standard/permissive), `--rules-dir` for custom rule packs, `--show-unchanged` to include receipts whose verdict didn't change. Exit code 0 always (replay always succeeds at the analysis level; the diff is the output).

### How it works end-to-end

```python
from raucle_detect import AgentIdentity, ProvenanceLogger, Scanner
from raucle_detect.replay import InputStore

identity = AgentIdentity.generate(agent_id="agent:gateway")
with (
    ProvenanceLogger(agent=identity, sink_path="audit/chain.jsonl") as log,
    InputStore.open("audit/inputs.jsonl") as inputs,
):
    scanner = Scanner(mode="standard", provenance_logger=log, input_store=inputs)
    scanner.scan(user_prompt)   # writes signed receipt + persists prompt
```

Then, days later, after a near-miss:

```bash
raucle-detect provenance replay audit/chain.jsonl \
    --input-store audit/inputs.jsonl \
    --mode strict
```

→ table of every receipt whose verdict would have changed, with the rule that would have fired.

### What this is uniquely possible because of

Counterfactual replay is the first feature that *requires* the v0.5.0 provenance primitive. Every other guardrail vendor would have to log raw prompts in plaintext to do this; raucle does it from hash-keyed receipts plus a separately-managed input store, so the *signed* audit trail never has to carry the content. That separation is what makes the feature deployable in regulated environments.

### Stats

- 1 new module (`replay.py`)
- 1 new CLI subcommand (`provenance replay`)
- 13 new tests (input store round-trip, idempotency, tamper detection, malformed-line handling, Scanner auto-save, same-policy/strict-policy/missing-input replay, non-guardrail-receipt handling, result-view sanity)
- 311 tests passing total

### Compatibility

- All new parameters optional. Scanner gains an optional `input_store=` kwarg.
- No new mandatory dependencies; replay uses the existing crypto stack from v0.4.0/v0.5.0.
- Version 0.5.0 → 0.6.0.

## 0.5.0 (2026-05-14)

### AI Provenance Graph — cryptographic chain-of-custody for the agentic stack

The first open-source implementation of end-to-end signed provenance for multi-agent / multi-tool LLM workflows. Every step (user input, model call, tool call, retrieval, guardrail scan, agent handoff, sanitisation, merge) emits a signed receipt that composes into a Merkle DAG. Given any output you can reconstruct the entire causal chain back to the original input and prove nothing in the chain has been tampered with. The LLM-equivalent of certificate transparency + SBOM + DNSSEC.

- **`AgentIdentity`** — Ed25519 keypair plus a self-signed capability statement listing the agent's permitted models, tools, and data classifications. Acts as the agent's "TLS certificate".
- **`ProvenanceReceipt`** — compact JWS (EdDSA, `typ=provenance-receipt/v1`) binding `(agent_id, parent_receipts, operation, input_hash, output_hash, taint, timestamp)`. Hashes only — receipts never carry the raw prompt/output, privacy by default.
- **`ProvenanceLogger`** — high-level API: `record_user_input`, `record_model_call`, `record_tool_call`, `record_retrieval`, `record_guardrail_scan`, `record_agent_handoff`, `record_sanitisation`, `record_merge`. Auto-inherits taint from parents so callers can't accidentally drop it. Enforces capability allowlists at write time.
- **`ProvenanceVerifier`** — verifies (a) every signature, (b) every parent link exists, (c) taint monotonicity (descendants ⊇ parents, unless a `sanitisation` step explicitly removes specific tags). `trace()` walks the DAG backwards; `to_dot()` exports Graphviz for visualisation.
- **Auto-emit from `Scanner`** — pass `provenance_logger=` to `Scanner()` and every `scan` / `scan_output` / `scan_tool_call` automatically emits a `guardrail_scan` receipt with the verdict + ruleset hash. `ScanResult.provenance_hash` is the new receipt's hash. Downstream steps cite it as a parent, so the chain proves the guardrail actually ran before each model/tool call.

### CLI

- **`raucle-detect provenance keygen <agent_id>`** — generates Ed25519 keypair + capability statement. `--allowed-models` / `--allowed-tools` / `--ttl-days` shape the statement.
- **`raucle-detect provenance verify <chain> --pubkeys …`** — verifies signatures, DAG integrity, and taint monotonicity. Accepts capability statement JSON files or raw PEM keys.
- **`raucle-detect provenance trace <receipt> --chain …`** — walks the DAG backwards from a leaf to all roots; table or JSON output.
- **`raucle-detect provenance graph <receipt> --chain … --out g.dot`** — exports Graphviz DOT for visualisation.

### Receipt format (v1)

JWS header includes `typ=provenance-receipt/v1`, `crit=["raucle/v1"]`, `kid=<agent_key_id>`. Payload fields: `iss`, `iat`, `agent_id`, `agent_key_id`, `operation`, `parents` (list), `input_hash`, `output_hash`, `model`/`tool`/`corpus` (operation-specific), `ruleset_hash`, `guardrail_verdict`, `taint` (sorted list), optional `tenant`. Receipt's own hash = `sha256(compact_jws)` — content-addressed, deterministic.

### Stats

- 1 new module (`provenance.py` — ~600 lines)
- 1 new CLI subcommand with 4 actions (`keygen`, `verify`, `trace`, `graph`)
- 28 new tests (DAG composition, taint monotonicity, signature verification, tampering detection, capability enforcement, Scanner auto-emit)
- 293 tests passing total

### Compatibility

- All new parameters are optional. `ScanResult` gains an optional `provenance_hash` field.
- Requires `raucle-detect[compliance]` extra (already present in 0.4.0) for the `cryptography` dependency.
- Version 0.4.0 → 0.5.0.

## 0.4.0 (2026-05-13)

### Compliance & Audit (EU AI Act / SOC 2 ready)

- **Tamper-evident hash-chained audit log** (`HashChainSink`) — every detection event is hash-chained to its predecessor; Ed25519-signed Merkle-root checkpoints anchor the chain at configurable intervals. `AuditVerifier` detects any past-record tampering and pinpoints the first invalid index. Resumes existing chains seamlessly. CLI: `raucle-detect audit verify` and `audit keygen`.
- **Signed JWS verdict receipts** (`VerdictSigner` / `VerdictVerifier`) — every scan can emit a compact JWS receipt (Ed25519, `typ=raucle-receipt/v1`) containing input hash, ruleset hash, model version, and timestamp. Downstream SIEMs/gateways can verify decisions without trusting transport logs. The `crit=raucle/v1` header prevents generic JWT libraries from accidentally accepting these as auth tokens. CLI: `raucle-detect verify-receipt`.
- **`ScanResult.receipt`** field — present when a `VerdictSigner` is configured.
- REST endpoints: `POST /verdict/verify`, `GET /audit/status`.

### Outcome Verification

- **`OutcomeVerifier`** — classifies whether a malicious prompt actually *landed*: `LANDED`, `REFUSED`, or `UNCERTAIN`. Combines refusal-pattern detection, canary-leak checks, system-prompt-leak heuristics, secret-leak detection, and sensitive tool-call diffs. The single metric CISOs actually care about — cuts noise from prompts that *attempted* but were refused.
- REST endpoint: `POST /verify/outcome`.

### Model Context Protocol (MCP)

- **MCP server mode** (`raucle-detect mcp serve`) — speaks JSON-RPC 2.0 over stdio per the MCP 2024-11-05 spec. Exposes 8 tools to any MCP-compatible client (Claude Desktop, Cursor, Continue.dev, Cline): `detect_injection`, `scan_output`, `scan_tool_call`, `verify_outcome`, `scan_mcp_manifest`, `list_rules`, `embed_canary`, `check_canary_leak`. Zero external MCP SDK dependency.
- **MCP manifest static scanner** (`raucle-detect mcp scan`) — finds tool-poisoning attacks in other MCP servers: hidden instruction tags (`<IMPORTANT>`, `<SYSTEM>`, `[INST]`), invisible Unicode, direct injection phrases, rug-pull indicators, baked-in credentials, SSRF targets, dangerous tool names. Outputs JSON or **SARIF 2.1.0** for GitHub Advanced Security ingestion.

### Scanner integration

- `Scanner` now accepts optional `audit_sink`, `verdict_signer`, `model_version`, and `tenant` parameters. When wired, every `scan`, `scan_output`, and `scan_tool_call` automatically writes to the audit chain and attaches a signed receipt to the result.
- Server reads `RAUCLE_DETECT_AUDIT_PATH`, `RAUCLE_DETECT_AUDIT_PRIVATE_KEY_PEM`, `RAUCLE_DETECT_VERDICT_KEY_PEM`, `RAUCLE_DETECT_MODEL_VERSION`, `RAUCLE_DETECT_TENANT` from env.

### Dependencies

- New optional extra: `raucle-detect[compliance]` pulls `cryptography>=42.0` for Ed25519 signing/verification. Core install remains zero-dependency.

### Stats

- 5 new modules: `audit.py`, `verdicts.py`, `outcome.py`, `mcp_scanner.py`, `mcp_server.py`
- 5 new CLI commands: `audit verify`, `audit keygen`, `verify-receipt`, `mcp serve`, `mcp scan`
- 3 new REST endpoints: `/verdict/verify`, `/verify/outcome`, `/audit/status`
- SARIF output for GitHub code-scanning integration

## 0.3.0 (2026-05-13)

### New Features

- **Canary watermarking** (`CanaryManager`) — embed invisible tokens in system prompts to detect if the model is manipulated into leaking its instructions. Three concealment strategies: zero-width Unicode encoding, semantic sentence injection, and HTML comment. Supports HMAC-signed tokens for offline verification.
- **Attack export & replay** (`AttackLog`) — collect scan results and export to JSONL, Garak, PyRIT, or PromptBench format so production detections feed back into your test suite automatically.
- **Rule mutation fuzzer** (`raucle-detect rules fuzz`) — auto-generates leet-speak, homoglyph, zero-width, base64, ROT13, reversed, and case-flip variants of seed attack phrases, then measures what percentage each rule catches. Highlights low-coverage rules.
- **API authentication** — set `RAUCLE_DETECT_API_KEY` to require `Authorization: Bearer <key>` on all scan endpoints. Uses `secrets.compare_digest` to prevent timing attacks.
- **Rate limiting** — built-in token-bucket rate limiter per client IP. Configure via `RAUCLE_DETECT_RATE_LIMIT` (req/min) and `RAUCLE_DETECT_BURST_LIMIT`. Returns HTTP 429 with `Retry-After` header.
- **Prometheus metrics** (`GET /metrics`) — plain-text request counters, verdict histograms, per-endpoint latency (avg + p99), rate-limit and auth-failure counters. Scrape directly with Prometheus.
- **Docker Compose** (`docker-compose.yml`) — one-command deployment with all env vars documented.

### Bug Fixes

- **Negation window expanded** (`classifier.py`) — increased from 10 to 40 characters before a keyword, catching phrases like "I am NOT asking you to ignore".
- **Position bonus gameable bypass fixed** (`classifier.py`) — the 1.5× position multiplier no longer fires when benign preamble text appears in the first 100 characters, preventing "please help me: ignore all previous instructions" bypass.
- **Pattern compilation cached** (`patterns.py`) — `_compile_pattern()` is now module-level LRU-cached (2048 entries). `scan_with_rules()` no longer recompiles the same regex on every call; all `Scanner` instances share compiled patterns.
- **YAML rule schema validation** (`rules.py`) — rules are validated for required fields (`id`, `name`, `category`, `patterns`, `score`), score range (0–1), severity values, and valid regex patterns. Invalid rules are skipped with an error log instead of crashing at match time.
- **Session memory leak fixed** (`middleware.py`) — sessions idle longer than `session_ttl` seconds (default 1 hour) are automatically evicted. Added `active_session_count()` for monitoring.
- **Encoding error transparency** (`cli.py`) — file decoding with `errors='replace'` now counts and reports replacement characters to stderr instead of silently swallowing them.

### Stats

- 3 new modules: `canary.py`, `export.py`, `mutator.py`
- REST API: 7 endpoints (added `/metrics`; `/health` now reports `auth_enabled`)
- `HealthResponse` includes `auth_enabled` field

## 0.2.0 (2026-03-27)

### New Features

- **Output scanning** (`scan_output()`) — detect data leakage, system prompt exfiltration, and injection in LLM responses
- **Tool call validation** (`scan_tool_call()`) — block shell injection, path traversal, SQL injection, and SSRF in tool arguments
- **Session scanner** (`SessionScanner`) — multi-turn attack detection with escalation tracking, cumulative risk scoring, and trend analysis
- **Middleware interface** (`RaucleMiddleware`) — framework-agnostic `pre_process()`, `post_process()`, `pre_tool_call()` hooks with alert/block callbacks
- **OpenClaw plugin** (`plugins/openclaw/`) — real-time agent protection via `before_prompt_build` hook
- **RAG poisoning rules** (RAG-001 to RAG-004) — document injection, retrieval manipulation, invisible text, citation poisoning
- **Agent attack rules** (AGT-001 to AGT-005) — goal hijacking, tool abuse, memory manipulation, action coercion, privilege escalation
- **Output-specific rules** (OUT-001 to OUT-003) — system prompt leak, injection in output, exfiltration channels
- **Tool call rules** (TOOL-001 to TOOL-004) — dangerous shell commands, path traversal, SQL injection, SSRF

### Improvements

- **Weighted heuristic classifier** — position-aware scoring, negation detection, density bonuses (replaced flat keyword counting)
- **Broadened PI-004 patterns** — catches "print/show/display your system prompt" and variants
- **ReDoS protection** — risky regex patterns capped at 10K chars
- **Input size limits** — 1MB file cap in CLI, 100K char truncation in scanner
- **Worker count clamping** — batch scan workers clamped to CPU count
- **`ScanResult.notes` field** — reports truncation and other scan metadata

### Stats

- 55 rules, 250+ patterns (was 39 rules, 180+ patterns in 0.1.0)
- 208 tests passing (was 95 in 0.1.0)
- REST API: 5 endpoints (`/scan`, `/scan/batch`, `/scan/output`, `/scan/tool`, `/health`)

## 0.1.0 (2026-03-25)

- Initial release
- 39 detection rules across 6 categories
- Pattern matching + heuristic semantic classifier
- Python library, CLI tool, REST API
- Three sensitivity modes (strict/standard/permissive)
- YAML custom rule framework
- Zero mandatory dependencies
