# Checker verdict - epic28-ltd/raucle PR #320 (Q17 gate hardening)

- PR number: epic28-ltd/raucle #320
- Branch + head sha (gh pr view, 24 Nov): feat/q17-gate-hardening @ 15b505d422dea3eb8723024895a9ec1d94114693
- Merge commit: 9b5222221c3be7200be4d22c66a1743d72153b62 (merged 2026-11-24T11:04:24Z)
- Verdict: PASS (deep checker) -> post-align re-pin PASS (orchestrator scope-limited, mechanical sha re-binding)
- Provenance: checker transcript deleg_19cfb7ca/task-1.log (deep PASS at audited head 8a5da37, merge-base 60e55da exactly as the PR body states) plus the checker verdict files (the post-align re-pin and the deeper record retained as bot-sessions checker-verdict-epic28-ltd/raucle-320.md).

## Key evidence
- Deep checker PASS at head 8a5da37 (short pin): RED-039 atomic approval consumption falsification-verified on both twins with 8 out of 8 deterministic 1-of-100 single-success runs; RED-040 quarantine identity binding and RED-041 mandatory session keys both red-falsified on the base tree.
- 18 new tests verified by collection including the 100-thread race; CI 19/19 on the audit head including Sonar at 100 percent new-code coverage; PR-scoped Sonar OPEN plus CONFIRMED issues total 0; ruff both channels clean; the changelog lane convention honoured; dependency-artefact junk scan clean.
- Re-pin basis: the 10:51Z rail align moved the head to 15b505d; the align delta is 14 commits, all main-side (merges of PRs #316, #317, #318 and #319) with zero new Q17 lane commits, so the PR content is identical and no fix scope was reopened.
- CI on the post-align head re-measured 24 Nov 11:09Z: 21 checks with zero non-success.
- Provenance wart recorded: the merge landed at 11:04:24Z, minutes before the re-pin file was written at 11:12Z; the re-pin is sha-bound to the merged head.

Recorded 2026-11-24.
