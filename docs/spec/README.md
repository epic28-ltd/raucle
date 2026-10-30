# Raucle specifications

This directory holds normative specification documents for the Raucle protocol family. Implementations claiming conformance MUST follow the version of the spec they target.

## Active specifications

| Spec | Version | Status | Document |
|---|---|---|---|
| Raucle Provenance Receipt | v1 | Draft 2 (first published 2026-05-14) | [provenance/v1.md](provenance/v1.md) |
| Raucle Time Source | v1 | Draft 1 (first published 2026-10-30) | [time-source-v1.md](time-source-v1.md) |

## Process

- Specs follow versioned URLs (`/spec/<name>/v<N>`). A spec at a given version is **immutable except for non-breaking clarifications**.
- Breaking changes are issued as the next major version (`v2`, `v3`, …) and SHOULD include a migration path from the previous version.
- The canonical published URL for each spec is `https://raucle.com/spec/<name>/v<N>` — that URL is the authoritative copy.
- Test vectors for each spec are published in this repository alongside the spec document (`docs/spec/<name>/v<N>/test-vectors.json`), which is the authoritative, always-current source; pin a release tag for a stable snapshot.

## Contributing

Spec changes follow the same pull-request flow as code. The label `spec` is applied to issues and PRs that touch a spec document. Substantive changes require a 14-day public comment period before merge.
