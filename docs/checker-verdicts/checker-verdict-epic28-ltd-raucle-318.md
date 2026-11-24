# Checker verdict - epic28-ltd/raucle PR #318 (Q10 trust-surface integrity)

- PR number: epic28-ltd/raucle #318
- Branch + head sha (gh pr view, 24 Nov): feat/q10-trust-surface-integrity @ c20c0b82699ef6ffa0bc504cd4c490facd11e2b7
- Merge commit: ef3e9f88c2bc6a70835b53f7910c0c482209dc7f (merged 2026-11-24T09:44:58Z)
- Verdict: FAIL (tracked .venv symlink, merge gate unmet, plus an open Sonar issue at the failed head) -> untrack fix -> PASS at the final head -> merged
- Provenance: FAIL transcript deleg_877ae5b0/task-2.log (audit completed 09:09:56Z) with the fail record preserved as checker-fail-epic28-ltd-raucle-318.md.stale-head-6b1afde6; final PASS transcript deleg_4710e4f4/task-0.log (09:47:13Z) at head c20c0b8 with CI terminal green 19/19 at 09:45Z, recorded in the checker verdict file.

## Key evidence
- Defect 1 at failed head 6b1afde6: the diff added a tracked file .venv (new blob mode 120000) whose target is the absolute host path /home/craigamcw/.cache/q10-venv, undeclared in the PR body; Build Package ("Build sdist and wheel") failed at tarfile.AbsoluteLinkError on run 45360112437 because .gitignore only lists directory patterns .venv/ and venv/, so a symlink blob was committable and hatchling packed it into the sdist.
- Defect 2 at the same head: Sonar python:S3776 CRITICAL (cognitive complexity) at raucle/passport.py:210 verify_passport.
- Fix: untrack commits 21ee3df and 3ba6d84 removed the blob with no code change; the lane then merged origin/main (the Q8 work) to reach c20c0b8. The recursive trees API at the final head has zero mode-120000 or 160000 entries and Build Package is green there.
- Final head PASS receipts: worktree tree hash equals the GitHub commits API tree (927 entries, byte-identical); 19/19 CI rows green; the S3776 issue closed on the new-code gate after the align with the honest disclosure that the passport blob is byte-identical and no refactor occurred (residual function complexity recorded as main-level debt).
- Q10 semantic claims re-verified at the final head: TrustRegistry keeps verify=True integrity on every load path with verify=False only as the named authoring hatch; accept_call takes the replay store as a mandatory keyword (explicit None refused by name, missing nonce refused, consume before any gate decision); passport ttl refuses 0, negatives, bools and non-integers while None keeps the documented no-expiry mode, all pinned by named tests.

## Fix round
- FAIL .venv -> untrack commits 21ee3df / 3ba6d84d -> PASS at c20c0b8 -> merged. The verdict file hit disk at 09:46Z, about one minute after the merge (provenance wart noted by the wave-presence duty run; same class as the #319 near-miss that morning).

Recorded 2026-11-24.
