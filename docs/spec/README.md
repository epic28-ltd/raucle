# Raucle specifications

This directory holds normative specification documents for the Raucle protocol family. Implementations claiming conformance MUST follow the version of the spec they target.

## Active specifications

| Spec | Version | Status | Document |
|---|---|---|---|
| Raucle Provenance Receipt | v1 | Draft 2 (first published 2026-05-14) | [provenance/v1.md](provenance/v1.md) |
| Raucle Time Source | v1 | Draft 1 (first published 2026-10-30) | [time-source-v1.md](time-source-v1.md) |
| Raucle Data-Flow Enforcement | v1 | Draft 1 | [dataflow/v1.md](dataflow/v1.md) |
| Advisory Middleware | v1 | Accepted 2026-11-17 | [advisory-middleware-v1.md](advisory-middleware-v1.md) |
| EE Proxy Runtime | v1 | Accepted 2026-11-17 | [ee-proxy-runtime-v1.md](ee-proxy-runtime-v1.md) |
| Advisor Classifier | v1 | Accepted 2026-11-18 | [advisor-classifier-v1.md](advisor-classifier-v1.md) |

## Receipts v1.2 additive extensions

Additive extensions to the Provenance Receipt v1
([provenance/v1.md](provenance/v1.md)): absent fields produce
byte-identical receipts, so a verifier that does not implement an
extension still verifies chains without it. Each document is normative
for the extension it defines.

| Extension | Status | Document |
|---|---|---|
| Task-intent binding (`x_gate.intent`) | Accepted 2026-10-29 | [provenance/v1.2/intent-binding.md](provenance/v1.2/intent-binding.md) |
| Credential-lease extension (`x_lease`) | Accepted 2026-10-30 | [provenance/v1.2/lease-extension.md](provenance/v1.2/lease-extension.md) |
| Harness findings (`x_finding`) | Shipped 2026-10-30 | [provenance/v1.2/harness-findings.md](provenance/v1.2/harness-findings.md) |
| Code authorship (`x_authorship`) | Shipped 2026-10-30 | [provenance/v1.2/code-authorship.md](provenance/v1.2/code-authorship.md) |
| Bilateral outcomes (`x_bilateral`) | Shipped 2026-11-06 | [provenance/v1.2/bilateral-outcomes.md](provenance/v1.2/bilateral-outcomes.md) |
| Content DLP (`x_dlp`) | Accepted 2026-11-17 | [provenance/v1.2/content-dlp.md](provenance/v1.2/content-dlp.md) |
| Counterfactual evidence (`x_gate.counterfactual`) | Shipped 2026-11-19 (spec #291, implementation #K3) | [provenance/v1.2/counterfactual-evidence.md](provenance/v1.2/counterfactual-evidence.md) |
| Revocation-event receipts (`x_revocation`, v1.2 kind) | Shipped 2026-11-19 (spec #291; v1.0 emitter shipped earlier) | [provenance/v1.2/revocation-receipts.md](provenance/v1.2/revocation-receipts.md) |
| Definition drift (`x_gate.tool_definition`) | Shipped 2026-11-20 (EPIC W lane W2) | [provenance/v1.2/definition-drift.md](provenance/v1.2/definition-drift.md) |

## Process

- Specs follow versioned URLs (`/spec/<name>/v<N>`). A spec at a given version is **immutable except for non-breaking clarifications**.
- Breaking changes are issued as the next major version (`v2`, `v3`, …) and SHOULD include a migration path from the previous version.
- The canonical published URL for each spec is `https://raucle.com/spec/<name>/v<N>` — that URL is the authoritative copy.
- Test vectors for each spec are published in this repository alongside the spec document (`docs/spec/<name>/v<N>/test-vectors.json`), which is the authoritative, always-current source; pin a release tag for a stable snapshot.

## Contributing

Spec changes follow the same pull-request flow as code. The label `spec` is applied to issues and PRs that touch a spec document. Substantive changes require a 14-day public comment period before merge.
