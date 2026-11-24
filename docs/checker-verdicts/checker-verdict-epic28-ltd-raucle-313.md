# Checker verdict - epic28-ltd/raucle PR #313 (X3 slice 3 receipted operator key rotation)

- PR number: epic28-ltd/raucle #313
- Branch + head sha (gh pr view, 24 Nov): feat/l14-x3-key-rotation @ 92d67a933d9cdd8af0d04a59734d9a51a5ad9642
- Merge commit: 92effdf0841ee0a7dd5fab6c76e6a9f001318aca (merged 2026-11-23T15:33:25Z by the merge rail)
- Verdict: FAIL (3 numbered claim-evidence defects) -> fix round -> scope-limited re-check PASS at 92d67a9 -> merged. Supersedes an earlier aligned-head verdict line (2e4a8e9) that lacked a full 40-character sha for rail binding.
- Provenance: checker transcripts deleg_e4d37add/task-0.log (deep checker FAIL at head 86f5d34, completed 23 Nov 14:24Z) and deleg_a1609aaa/task-0.log (re-check: the new pin falsification-proven, then ended early on a provider 429 while CI polls were still pending); the final PASS record is the checker verdict file pinned to the merged head (checker 2 of 2).

## Key evidence
- First audit: FAIL with 3 numbered defects, all small and precisely scoped (the claim-evidence kind); exemplar defect 1: the missing pinning test for the corrupted-registry boot refusal. The re-check proved the new pin genuine: it passes green on a pristine archive copy and fails when the corrupted-registry refusal is stripped to a bare load, while four of five artefacts were verified truthful and the PR body still carried pre-fix wording at that point.
- Diff scope: the merge-base delta against main lists exactly the 13 declared L14 files (6 docs, 5 raucle modules, 2 test files); the prior sync merge carried only sidecar files byte-identical to main, so no unexpected code change exists.
- Defences at head: tests/test_key_rotation.py (24 tests) plus tests/test_trust_registry.py (36) ran green from the worktree venv (60 passed, 0 skipped, 1.31s); the D1 close test_boot_refuses_corrupted_registry (KeyStoreRegistryMismatch on tampered registry bytes) and the D3 close (0o600 mode with O_CREAT|O_EXCL) passed by name.
- Honesty surfaces verified: the runbook env var names, the .retired date-stamped archive naming pinned at tests lines 434 and 629, the x_key_rotation receipt extension binding both key ids, and the receipted-path rewrite in docs/security/key-operations.md all match raucle/key_rotation.py and the CLI contract row.
- Wider gates: full suite 3203 passed / 35 skipped / 0 failed in 219.97s; ruff both channels green; CI 19/19 including Sonar Cloud with mergeStateStatus CLEAN at the pinned head.
- The rail merged the PR at 15:33:25Z with headRefOid unchanged, which is success proof of the verdict-file gate, not an anomaly.

Recorded 2026-11-23 (re-check), file written 2026-11-24.
