# Checker verdict - epic28-ltd/raucle PR #327 (Q19 verifier resource bounds)

- PR number: epic28-ltd/raucle #327
- Branch + head sha (gh pr view, 24 Nov): feat/q19-verifier-bounds @ 8268d837ecd82e60c5ceb29f5541a9b308435781
- Merge commit: 0c5b246a548b16fce56ae675abf7107d1ffb91b7 (merged 2026-11-24T13:19:15Z; the supervisor re-pin file was written ~13:26Z, after the merge)
- Verdict: FAIL (2 evidence-class defects; the behaviour itself was verified sound live) -> fix commit 9256e7a7 -> scope-limited re-check PASS -> align re-pin -> merged
- Provenance: checker transcripts deleg_3087e434/task-0.log (FAIL completed 12:52:10Z at head 93db5566183002d4c4284a82aa0f0734b5bee244), deleg_a1774db1/task-0.log (scope-limited re-check: PASS pinned at fix commit 9256e7a7, re-pinned to the aligned head 8268d83, wrote the verdict file) and deleg_c70d0451/task-1.log (Q19 lane close-out, PR opened with 20 check runs started).

## Key evidence
- D1 at the FAIL head: the demo-bundle parity pin was vacuous, comparing bounds-ON against bounds-ON (tests/test_provenance_bounds.py:415 to 417), so it could not detect a bounds-regime-only divergence.
- D2: the red-first count was not reproducible as published (the body claimed "9 failed"; independent replay at the audited head returned 8 failed, 2 passed, the two parity cases green-by-construction at base).
- Behaviour was verified sound live before the verdict: memoisation counters break exactly when memoisation is scratch-dropped (15,176 edges and 15,179 expansions versus 35/19) and the depth override is live (RAUCLE_VERIFY_MAX_DEPTH=300 produces the observed=301, cap=300 refusal); scope was exactly the 5 declared files against merge-base 1c08f00.
- Fix commit 9256e7a7 (+8/-3, tests/test_provenance_bounds.py only, history append-only after green CI): the two legs now build from RAUCLE_VERIFY_BOUNDS=on and =off with sanity assertions before the field-for-field equality; falsification proved the fixed pin fails at the recorded mechanism (the line 424 parity assertion) under an injected bounds-only error while the pre-fix test stayed green, so the pin gained real detection power.
- Re-check receipts: the body publishes the erratum ("8 failed, 2 passed on clean replay") attributed to the checker in the fix commit message; the suite at the fix head is 3406 passed / 35 skipped, unchanged counts; all 21 CI checks green on the aligned head; the five audited lane files carry an empty diff across the align (targeted bounds suite 10/10).

## Fix round
- FAIL 2 evidence defects -> 9256e7a7 corrections -> PASS -> align 8268d83 -> merged at 13:19:15Z.
- The re-check PASS carries one MINOR advisory, non-gating: the test comment says the bounded leg runs "(env cleared)" while line 417 sets RAUCLE_VERIFY_BOUNDS=on explicitly (effect identical, prose-only remedy).
- Erratum for this wave's record: the brief referred to "fix commit f0fe396-era corrections". f0fe396 is the contemporaneous #328 extras-completeness fix commit, not a #327 fix; the actual #327 fix commit is 9256e7a7.

Recorded 2026-11-24.
