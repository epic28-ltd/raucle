# Checker verdict - epic28-ltd/raucle PR #319 (Q11 enforcement modes)

- PR number: epic28-ltd/raucle #319
- Branch + head sha (gh pr view, 24 Nov): feat/q11-enforcement-modes @ 92aeb10bcb33838df6a10d5ecd4ba64c515a3d48
- Merge commit: 93380f5a2ec22799d5f227f55f726e5cca60d62c (merged 2026-11-24T10:07:03Z)
- Verdict: FAIL (one blocking defect) -> scope-matching fix-forward (b2762f5f) -> merged with NO PASS verdict file recorded (breach disclosed)
- Provenance: checker transcript deleg_bdd47a59/task-0.log (the FAIL audit, head a2fe895, completed 09:49:04Z; no fail file existed at the time), checker-fail-epic28-ltd-raucle-319.md (written 10:42Z by the wave-presence duty run after the fact), and the PR record with the merged tree.

## Key evidence
- A deep read-only checker (child bdd47a59, dispatched 09:38Z, completed 09:49:04Z) returned FAIL at reviewed head a2fe895c1d5311e3d49cac3470ffaf5ddd0613d4 (tree unchanged across the audit); the single blocking defect was the missing pinning test for the keyless verifier's unverifiable signed_mode; everything else verified green.
- No checker-fail file existed at the time; the verdict was recorded in-chat only, which the duty run's record flags as the procedurally broken part of this PR's trail.
- Fix commit b2762f5f "test(audit): pin the keyless verifier's unverifiable signed_mode (checker D1)" touched raucle/audit.py, raucle/compliance.py and tests/test_audit.py, followed by the align merge 92aeb10b.
- The PR merged at 10:07:03Z with no checker-verdict file on disk (flat or slashed) and no verdict-file-recorded re-check of the fix round; the duty run classed the change as a substantively scope-matching fix-forward with an absent verdict trail.
- Post-merge spot check at merged main (93380f5a): tests/test_audit.py carries test_verifier_surfaces_signed_mode_unverifiable_without_key at lines 167 to 171 with its regression-guard docstring "(Q11 checker D1, 24 Nov.)"; the pin exists where the checker demanded it.

## Fix round
- FAIL (missing D1 pin) -> b2762f5f -> merged without a recorded PASS re-check. This file stands as the persistent verdict record under the standing fail-file doctrine; a full re-audit of the fix round remains an owner option.

Recorded 2026-11-24.
