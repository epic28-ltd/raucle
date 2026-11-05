# Sonar acceptance decisions

Decision owner: Craig. Rule suppressions are recorded here with rationale.

## S6389 (bidirectional characters) - tests/test_multimodal.py, accepted 2026-11-05

The `test_bidi_override_detected` test must contain a real U+202E / U+202C
payload: it is detector bait that proves `strip_invisible_unicode` detects and
strips bidi attacks. The source uses `\u` escape literals so no raw bidi
characters appear in the file (clearing the rule without a suppress); the
runtime payload is byte-identical to the original raw-character version.
Accepted because a scrub would break the very guarantee the test exists to
verify.

## S8570 (missing Cargo.lock) - reference/provenance-rs, BLOCKED-CRAIG 2026-11-05

`cargo` is not installed on the hygiene host and toolchain installation was out
of scope for this wave. Needs `cargo generate-lockfile` run by someone with a
Rust toolchain, then the lock file committed.
