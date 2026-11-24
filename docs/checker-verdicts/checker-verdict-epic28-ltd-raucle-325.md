# Checker verdict - epic28-ltd/raucle PR #325 (Q18 adapter conformance)

- PR number: epic28-ltd/raucle #325
- Branch + head sha (gh pr view, 24 Nov): feat/q18-adapter-conformance @ 5026bd30c381f99f184560ff03084c1436eeb63f
- Merge commit: 72b4a4e9fd38679a818ea1740d784c849a9f6aa8 (merged 2026-11-24T12:24:10Z)
- Verdict: PASS. The audit started at 73536ae and the head moved mid-audit via a main-into-branch merge (5026bd3, 12:16:19Z); the verdict supersedes the earlier pin and was re-verified at the final pin.
- Provenance: checker transcript deleg_5e017eac/task-0.log (PASS with 1 numbered docs-only defect at the audit head 73536ae, 12:16Z) and the superseding checker verdict file re-verified at the final pin 5026bd3.

## Key evidence
- Scope at the final pin: exactly the 7 declared files (agent_framework, crewai and langgraph integrations plus their three test files and the Q18 changelog entry); all 7 PR-owned files byte-identical across the two pins and no junk files.
- Receipt semantics: mint-before-execute is pinned (test_receipt_emitted_before_call_next pins sink append before call_next); the durable mode (RAUCLE_MW_REQUIRE_DURABLE_RECEIPT=1) refuses a sink failure by name through MiddlewareTermination with the tool body never entered; every decision path mints and no path claims a receipt while skipping minting; receipt bodies carry argument digests only, never content.
- Determinism: schema_hash and call_args_hash are content-addressed and verified identical across two fresh processes; RAUCLE_TOOL_SCHEMA_MANIFEST is genuinely wired (the gateway reads it and the registry pins into the gate).
- Fail-visible falsification on a git-archive scratch, one probe per mechanism family, each failing at its own recorded mechanism: the pre-fix swallow revert, the gate view revert, and the identity-source removal.
- The first-audit PASS carried one numbered docs-only defect: the body's secondary skip-count sentence claimed an extras-venv pair that no extras combination reproduces (measured 3357 passed / 83 skipped under the dev-only venv) and mis-attributed the adapter-row skips; the primary count 3419/30 was verified exact. Docs-only rule applied; the superseding pin re-verified the seven files without carrying the defect.
- Red-first replay against a main tree reproduces exactly as published (integration 11 failed, argument normalisation 16 failed, conformance 1 failed); targeted suites at the final pin 76 passed, 0 failed, 0 skipped; ruff 0.17.5 clean on both channels over the owned files with no new repo debt.

Recorded 2026-11-24.
