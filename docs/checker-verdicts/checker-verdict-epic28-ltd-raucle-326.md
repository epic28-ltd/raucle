# Checker verdict - epic28-ltd/raucle PR #326 (Q20 pq1 JOSE-conformant encoding)

- PR number: epic28-ltd/raucle #326
- Branch + head sha (gh pr view, 24 Nov, latest read): feat/q20-pq1-jose-encoding @ d108f15a42fe747926d3a8c3c5b1c7598468a9bb. The branch head moves as main-aligns land (observed b98ee9cb then 6acbd005 then d108f15a within the same hour); the checker-audited head is b98ee9cb and the advisory-fix commit 4bcdcf99 is unchanged.
- Merge commit: none. State OPEN with mergedAt null when this file was written on 24 Nov; #326 is NOT merged in the 23-24 Nov wave despite the wave brief's "ultimately merged" premise. Recorded as found.
- Verdict: PASS (ready to merge on green CI) with 2 numbered advisory defects -> both advisory remedies shipped on the branch -> aligned, awaiting merge
- Provenance: checker transcript deleg_bb4ea500/task-0.log (completed 12:56:21Z) at audited head b98ee9cb031aad2fee8050fdb3964334ccacd148; the post-audit head movement is reconstructed from the PR record.

## Key evidence
- Emission proven at the audited head: sign_both returns ONE base64url segment over the raw 64 plus 3309 byte concatenation, no literal period, constant 3373-byte framing with no length prefix; the committed reference slot decodes to exactly 3373 bytes (4498 unpadded base64url characters, arithmetically exact).
- Dual acceptance: parse_hybrid_signature accepts the legacy dot-form with the LEGACY_DOT_FORM_DEPRECATION log; dispatch, require_pq, the gateway family and the chain_graph profile are header-based, not content-derived.
- Red-first replay: the 13 committed shape tests fail against the base implementation (the slot tests lead the failure list), so the pins have detection power.
- CI at the lane record: 21/21 checks including ruff 0.17.5, mypy, cross-language conformance over 5 ports and the Sonar Cloud row; the PR opened with mergeStateStatus BEHIND pending align.
- Advisory 1 (fixed by 4bcdcf99): mcp_server.py classified the receipt profile by dot counting with a stale 4-part comment, which the single-segment slot broke; the fix reads the parsed JOSE header with the crit pin authoritative. Advisory 2 (same fix): pq1-test-vectors.json mixed two flip regimes, so a port applying declared flips generically would double-flip the current-form negatives and face a valid receipt against must_reject=true; current-form negatives now declare bytes_state=pre_flipped with the flip removed, legacy negatives are marked unflipped_declared, and the contract string documents both regimes (tests/test_pq.py 46 passed against the edited file).

## Fix round
- Both advisory probes were closed by 4bcdcf99 "fix(pq1): the two checker advisories - header-based profile classification and the vector byte-flip convention" (13:02:26Z), followed by aligns 60a6b9d3 and 6acbd005. No further checker re-run was recorded after the advisory fix.

Recorded 2026-11-24.
