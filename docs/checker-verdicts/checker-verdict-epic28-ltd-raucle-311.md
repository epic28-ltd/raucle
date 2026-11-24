# Checker verdict - epic28-ltd/raucle PR #311 (X3 slice 4 single-writer receipt sidecar)

- PR number: epic28-ltd/raucle #311
- Branch + head sha (gh pr view, 24 Nov): feat/l15-x3-sidecar @ 37271b3395ccf3fbd32c1fe7f951901b4d49e852
- Merge commit: 3c1809899ce771d4d503e30106683277fd3e1a4a (merged 2026-11-23T14:46:16Z)
- Verdict: FAIL (PR-body-only defect, no code defect found) -> disclosed body edit -> PASS -> merged
- Provenance: checker transcript deleg_b133267f/task-0.log (23 Nov 14:24Z); the audited FAIL head was bfe801f0bc429961510b8a1c319c04429d83062e and the disclosed edit landed before the final head 37271b3.

## Key evidence
- Scope at the audited head was exactly the 19 declared files; the spec was committed in the first lane commit and never revised, and it matches the implementation line for line (env table, ordering, overflow, recovery, byte compat, residuals).
- The scale answer is honestly implemented: one sidecar owns the append path, gateways submit minted receipts over local HTTP with a shared-secret handshake, bounded-queue async submission carries a named overflow refusal, and single-writer, concurrency, overflow-never-blocks and authentication behaviour were all falsification-verified.
- Defect (body-only): the PR body claimed "11 passed" for test_receipt_sidecar.py while the file defines about 21 tests across 6 classes (later fix and coverage commits added them); stale counts, no semantics touched.
- Post-fix state recorded by the rail verdict file: 19/19 CI rows green including the Sonar Cloud gate, suite re-run 3148 passed / 35 skipped, and the three falsifications re-verified.
- Helm/chart honesty held: RWO node-sharing, /keys key volume and one-identity adoption notes; sidecar replicas 1 with Recreate and ClusterIP; STORE_DIR/INDEX_PATH rows gated in sidecar mode; signer_key_unwritable documented.

## Fix round
- The stale-count defect was corrected as a disclosed body edit per the checker prescription; the scope-limited re-check confirmed body-only change on PASS-grade evidence. Merge under standing approval on 23 Nov.

Recorded 2026-11-23 (audit), file written 2026-11-24.
