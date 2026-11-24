# Checker verdict - epic28-ltd/raucle-agent-red PR #45 (Q12 adversarial programme)

- PR number: epic28-ltd/raucle-agent-red #45
- Branch + head sha (gh pr view, 24 Nov): feat/adversarial-programme @ a832fc06abc72e23364cd09b422d691b924b5593
- Merge commit: 2d434b8a6becb9ae6ae992d362cdf8e545a209ed (merged 2026-11-24T09:46:33Z)
- Verdict: FAIL (D1 check-blocking, plus 5 minor notes D2 to D6) at audited head a0804628 -> workflow and content fixes 527fd60c and a832fc06 -> merged. No scope-limited re-check verdict was recorded for the fix round.
- Provenance: checker transcript deleg_877ae5b0/task-3.log (completed 09:17:26Z); that transcript's own capture truncates the D2 to D6 bodies, so their substance below is recovered from fix commit 527fd60c, which names each note; reconstructed from the PR record and labelled as such.

## Key evidence
- D1 (check-blocking): the 8 Q12 tests require ~/Projects/oaa-q12/raucle-main plus the .q12-pinned-sha marker, but build.yml materialises four other trees and never touches the oaa-q12 target; CI run 45361460428 ("Build and analyze" at head a0804628) is observed failing with six failures, each the q12 FileNotFoundError class, nothing else attributed.
- D2: the programme test's RED-056 label on trust_fold was wrong (it is RED-054; direct_exec is RED-056); rule equality pins were added for direct_exec (RED-056) and tail_recovery (RED-058).
- D3 and D4: the runner's marker-writer attribution now names operator or CI after git verification, and the tree-present, marker-absent path raises the accurate marker-missing error instead of the target-missing error.
- D5: the matrix doc's dangling docs/next-attacks.md reference is annotated as following this PR's base.
- D6: the PR body's "pins every outcome finding" claim is narrowed to what the tests actually pin, per the checker.
- Fixes: 527fd60c (09:29:23Z) "build(ci): materialise the Q12 pinned target and close the checker's six notes" makes build.yml clone raucle at a verified pinned sha and write the .q12-pinned-sha marker (the pinned target previously existed only on the operator machine) and closes D2 to D6; a832fc06 (09:33:29Z) untracks the coverage lock artefact.

## Fix round
- FAIL D1 to D6 at a0804628 -> 527fd60c and a832fc06 -> merged at 09:46:33Z. The checker's own bar was a code/workflow fix and a green CI re-run before merge; no recorded re-check verdict or green-run receipt was written for the fix head, so the fix round's provenance is the fix commit messages and the post-merge CI state, honestly labelled here.

Recorded 2026-11-24.
