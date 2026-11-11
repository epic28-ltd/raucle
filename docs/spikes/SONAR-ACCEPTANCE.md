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

## S8570 (missing Cargo.lock) - reference/provenance-rs, RESOLVED 2026-11-05

Resolved by installing a user-local rustup toolchain (minimal profile) and
running `cargo generate-lockfile` in reference/provenance-rs; the generated
Cargo.lock is committed and `cargo check` passes against it.

## S8572 (logging.exception instead of error) - raucle/gateway.py, accepted 2026-11-05

The flagged `logger.error()` call inside `except` in the admission-control path
deliberately logs ONLY the exception type name sanitised through `repr()`:
the exception message can carry untrusted values arriving on the wire (agent
ids, registry contents) and the traceback's final line reproduces that message,
so `logging.exception()` would reintroduce the S5145 log-injection finding.
Full diagnostics stay in the admission receipt, not in the log file. Suppressed
with an inline `# NOSONAR` rationale and this entry. Decision owner: Craig.

## S5144 (server-side request forgery in UrlGate.forward) - raucle/urlgate.py, accepted 2026-11-06

O3 is a transparent URL-switch gate proxy: its purpose is to forward SDK
client traffic verbatim to the CONFIGURED upstream (`UrlGateConfig.upstream`,
bound to 127.0.0.1 by default). The client's method, origin-form request
target, headers and body are the proxied payload; altering or re-resolving
them would break the transparent-proxy contract. The destination host is
never client-controlled. Hardening applied with this acceptance: only
RFC 9112 origin-form request targets are proxied (`_is_origin_form`),
absolute/authority/asterisk-form targets (the only way a client could steer
the proxy at a different destination) are rejected with 400, and the taint
finding is suppressed with inline `# NOSONAR` markers on the forwarding
call. Accepted pattern: "a transparent proxy MUST forward client payload
to the configured upstream". Decision owner: Craig.

## pythonsecurity:S6549 (filesystem oracle via file content) - raucle/audit_pack.py, hardened and accepted 2026-11-11

The taint trace runs from the bytes of the attacker-controllable
`PACK.json` index into the read of every member in
`_resolve_member()`. Genuinely hardened, in order, before any member
read: non-string, empty and null-byte member names are refused
(`ValueError` on canonicalisation is caught, so a tampered index cannot
crash verification); absolute paths refused (`os.path.isabs`); `..`
traversal refused at any depth (`Path.parts`); backslash and
drive-colon member names refused (the assurance-pack verifier's
zip-slip shapes); symlinks cannot launder an escape (both sides
`resolve()`d, member must stay `is_relative_to` the pack root); and
every member's sha256 is bound into the Ed25519-signed index, so
forging the member set requires the audit private key. The taint
engine does not credit project-internal validators as sanitising, so
the residual resolve-line sink is suppressed with inline `# NOSONAR`
and this entry is the rationale. Regression tests pin every shape:
`tests/test_audit_pack.py::test_resolve_member_refuses_escape_shapes`
(payload table) and `...::test_pack_traversal_payloads_fail_integrity`
(integration through `verify_pack`, named per-shape reasons).
Decision owner: Craig.

## python:S1313 (hardcoded IP 169.254.169.254) - raucle/demo_scenarios.py, accepted 2026-11-11

The link-local instance-metadata address appears exactly once, in the
seeded *poisoned-helper* demo manifest (`fetch_internal`): the demo
exists to show the scanner catching an SSRF lure aimed at the cloud
metadata endpoint, and `169.254.169.254` is the canonical target for
that demonstration. Rewriting or indirection would weaken the demo's
fidelity to the attack it documents. The demo route is read-only,
static-analysis only, and gated behind the explicit demo-mode flag
plus admin authentication. Suppressed with inline `# NOSONAR` plus
this entry. Decision owner: Craig.
