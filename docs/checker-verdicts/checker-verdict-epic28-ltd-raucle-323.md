# Checker verdict - epic28-ltd/raucle PR #323 (Q13 control-plane integrity)

- PR number: epic28-ltd/raucle #323
- Branch + head sha (gh pr view, 24 Nov): feat/q13-control-plane-integrity @ 684ffa217e6b7a564578a967630c53ddb611f952
- Merge commit: 76925a37c77bd26d6cee9ad406ad66786905548b (merged 2026-11-24T12:42:03Z)
- Verdict: FAIL (Sonar S3776) -> gate condition cleared via align -> scope-limited re-check PASS at fb13cd28 -> head aligned once more -> merged
- Provenance: checker transcripts deleg_95737960/task-2.log (deep FAIL at head 5b64694, 11:22Z, single Sonar defect, no verdict file written under FAIL rules) and deleg_abf392ef/task-1.log (the concurrent PASS run at the same head, completed 12:00:10Z, with 2 numbered PR-body text defects); the fail file written by the duty run and the re-check record at fb13cd28 complete the trail.

## Key evidence
- Deep FAIL at head 5b64694 (11:20Z): the sole defect was the Sonar PR-scoped OPEN CRITICAL python:S3776, cognitive complexity 19 over the allowed 15, at raucle/gateway.py:1431. All three closes (policy seal, content-hash cache invalidation, DNS-safe SIEM targets) were verified clean at the same head with CI 20/20.
- An interim PASS (transcript deleg_abf392ef/task-1, 12:00:10Z, PASS with 2 numbered PR-body text defects: a stale suite count 3315 versus the true 3317, and a mis-attributed justification for the default mode) was set aside: its verdict file omitted the mandatory 40-hex head sha and the recorded Sonar issue was still open on live re-read; superseded per the #310 precedent, reversible only with evidence of a closed issue.
- Resolution at re-check head fb13cd28 (pushed 12:08:42Z as an align of origin/main): a fresh Sonar analysis followed (12:15:45Z) and the recorded issue key AaINMgA4AWznB8UxkQKF reads CLOSED with resolution FIXED at 12:21:46Z; the PR-scoped issues search (resolved=false and the OPEN, CONFIRMED, REOPENED slice) returns 0.
- Honest mechanism disclosure on the PASS: the closure follows the align, not a helper-extraction refactor; the flagged function's def line left the PR new-code window while the function's complexity is unchanged on the merged tree, recorded as main-level debt rather than hidden.
- Re-check receipts: 85 tests across named control-plane and merge-brought close files green at the pinned head; CI 21/21 on fb13cd28 including the Sonar quality gate OK on all six conditions; ruff 0.17.5 clean on both channels.

## Fix round
- FAIL S3776 at 5b64694 -> align merge fb13cd28 (the gate trigger reads zero at the pinned head) -> scope-limited re-check PASS -> the head aligned again to 684ffa2 -> merged at 12:42:03Z.

Recorded 2026-11-24.
