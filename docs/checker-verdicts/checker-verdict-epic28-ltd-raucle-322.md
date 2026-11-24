# Checker verdict - epic28-ltd/raucle PR #322 (Q14 OpenClaw plugin hardening)

- PR number: epic28-ltd/raucle #322
- Branch + head sha (gh pr view, 24 Nov): feat/q14-openclaw-hardening @ d3aa50f207a2b9f8d604b6c2e54a8a5ef4345507
- Merge commit: e5463d12cf14e7c4486d68859d15c91b5425a4a7 (merged 2026-11-24T12:50:08Z)
- Verdict: FAIL (6 numbered defects plus an open Sonar PR-scoped issue) -> no defect-fix commits on the branch -> merged WITHOUT any PASS verdict (breach record); the remedies remain owed on main
- Provenance: checker transcripts deleg_95737960/task-1.log (FAIL with 4 numbered defects at head 36c46d6, 11:17:29Z; a concurrent independent run on the same head, deleg_9972efcf/task-0.log, returned PASS with 2 numbered minors at 11:17:08Z) and the 12:11Z re-audit at 96d898f recorded in checker-fail-epic28-ltd-raucle-322.md with the breach record appended ~13:05Z; reconstructed with the PR record and the merged tree.

## Key evidence
- Defect 1: adoption accepts an unauthenticated scanner. plugins/openclaw/src/scanner-client.ts:153 type-checks scan_secret_required as a boolean only and accepts false, while a raucle server without RAUCLE_PLUGIN_SCAN_SECRET answers with scan_secret_required:false and server-manager.ts adopts on any probe.ok; the changelog and README claim adoption only on a secret-protected probe.
- Defect 2: on adoption refusal the manager respawns against the same occupied port and the exit-restart loop re-enters every 10 seconds forever (EADDRINUSE lockout), so the changelog claim of replacement by a freshly spawned scanner cannot hold.
- Defect 3: recordToolDecision hardcodes authority:true at every gated site while the real ack() return is discarded, so decision-log entries claim authorityAcknowledged:true even when no host receipt existed.
- Defects 4 to 6: "catalog" on added lines against standing "catalogue" usage; the new derivation pin re-declares the derivation inline and never exercises the shipped index.ts path (falsified: it stays green against the pre-fix shape); the malformed-response classification branch has no pin.
- Gate half: the Sonar PR-scoped issues search returns python:S9073 MAJOR at tests/test_scanner_server_auth.py:54, so the zero-open-issues precondition fails although all 21 CI checks were green.
- Merge discipline breach: the last commit before the merge was only the align d3aa50f2 (12:42:12Z); no PASS verdict file ever existed (checked 13:05Z) and the merge was manual after rail refusals (11:53Z and 12:24Z cycles). Post-merge spot check at the merge commit: scanner-client.ts:153 is still the boolean-only check, so defect 1 is live on main.

## Fix round
- None. The defect remedies remain owed on main; revert or fix-forward is the owner's decision per the breach record.

Recorded 2026-11-24.
