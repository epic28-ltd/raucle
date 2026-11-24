# Checker verdict - epic28-ltd/raucle PR #321 (Q15 deployment hardening)

- PR number: epic28-ltd/raucle #321
- Branch + head sha (gh pr view, 24 Nov): feat/q15-deployment-hardening @ 617968cf801e0b89d4365647f108eb6e24ed50ea
- Merge commit: 1c08f00165c57c473e36c0faf784404645bc213e (merged 2026-11-24T12:05:24Z, a manual merge under the craigamcw identity)
- Verdict: FAIL (4 numbered defects, re-confirmed at the merged head) -> merged WITHOUT any PASS verdict (breach record). No fix round landed on the branch.
- Provenance: checker transcript deleg_95737960/task-0.log (FAIL audit at head 25f235a, 11:22Z, 4 defects, no verdict file written under FAIL rules) and checker-fail-epic28-ltd-raucle-321.md (re-confirmed at 617968c ~12:07Z, breach record appended ~12:30Z), with the PR record and post-merge spot checks.

## Key evidence
- A deep-tier FAIL stood at the prior head 25f235a (11:20Z assessment); the pinned head 617968c then advanced by two align merges of origin/main (da4cc98, 617968c) that touched none of the four defect files, so a 12:07Z re-audit re-confirmed all four defects at the pinned head.
- Defect 1: Sonar S5778 MAJOR at tests/test_gate_rate_limit.py:247, where pytest.raises wraps two exception-capable invocations (the gateway construction and the helper that can raise independently).
- Defect 2: Sonar S9083 MINOR at tests/test_gateway_server.py:44 (@pytest.fixture() empty-parenthesis drift); verified live at the merge commit, still present.
- Defect 3: the receipted-DENY claim false against shipped code (raucle/gateway_app.py _gate_deny_response returns receipt_id None and the unauthenticated pre-gate deny fires before any receipt trail; scripts/demo_agents.py posts /gate with no credential headers) against docker-compose.gateway.yml:81 and docs/deployment-demonstrator.md:66; the demonstrator wording verified live at the merge commit, still present.
- Defect 4: uv.lock not regenerated for the lane's added extras (uv lock --check fails at the pinned head; the align brought main's lock, which predates the extras).
- Merge discipline breach: the 11:53Z rail cycle refused with "no checker verdict yet"; the 12:05:24Z merge was manual and no PASS verdict file ever existed on disk. CI was green at the pinned head (21 checks) and 43 targeted tests passed, so the defects are evidence, text and lock class, but the verdict trail is the recorded breach; defects 2 and 3 landed on main.

## Fix round
- None on the branch. Revert or fix-forward is the owner's decision per the breach record, never silent.

Recorded 2026-11-24.
