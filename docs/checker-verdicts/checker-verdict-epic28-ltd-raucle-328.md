# Checker verdict - epic28-ltd/raucle PR #328 (Q21 Foundry sidecar artefact honesty)

- PR number: epic28-ltd/raucle #328
- Branch + head sha (gh pr view, 24 Nov): feat/q21-sidecar-guard @ 1876d685d2051a68214b1ed64aa0ce8a4d5c8dfb
- Merge commit: 6537547b4d07bab740aab66fbb55f92f5d393ab6 (merged 2026-11-24T13:29:40Z)
- Verdict: FAIL (5 numbered defects at first-audit head e275f9d) -> fix round (f0fe396f) plus align (1876d685) -> merged. A concurrent independent checker run on the same head returned PASS with 3 prose-class minors; the FAIL governed and no post-fix PASS verdict file was recorded.
- Provenance: FAIL checker transcript deleg_a1774db1/task-1.log (first audit at head e275f9d, 13:22:18Z, wrote checker-fail-epic28-ltd-raucle-328.md); concurrent independent PASS-with-minors transcript deleg_1e7eba08/task-0.log (13:21:19Z); lane close-out transcript deleg_3e72fbef/task-0.log; the digest disposition verified against the PR body and the merged tree.

## Key evidence
- FAIL defect 1: the default container image reference in deploy/foundry-mcp-sidecar/bicep/main.bicep:50 was a mutable tag (v0.23.7 at the failed head) with no @sha256 digest, against the Q9 rail-convention MUST. The merged disposition is the recorded-deviation option: the PR body states plainly that no digest is recorded because no repo pipeline publishes a container image and ghcr does not resolve for anonymous pulls, and a fabricated digest would fail the honesty bar; the artefact records tag-to-commit provenance (v0.23.7 -> eafba15c, verified via the PEP 740 attestation) and the capture-then-pin instruction, verified present at the merged tree.
- FAIL defect 2: the PR body's close 0(iv) claimed the extras/dependency-completeness note was in the artefacts while it was absent from all of them; fixed on the branch by f0fe396f "fix(sidecar): the prerequisites table gains the extras-completeness line" (13:21:39Z).
- FAIL defects 3 to 5: the PR body misquoted the artefacts through a consistent "rauckle" misspelling at 15 sites; the e275f9d commit message carried 2 tokens misnaming the shipped surfaces; and two em dashes sat on added lines (the apim-policy.xml guard comment and main.bicep:187). The committed tree itself was spelled correctly everywhere.
- Advisory probes recorded for the wave board: the APIM on-error coverage wording, the routed-path seam (a routed MCP call 404s until the proposed forwarder, loudly labelled PROPOSED), and the composite denial-name token.
- Lane and pass-run verification: all four close-0 sub-fixes (M2-class PROPOSED relabelling with the shipped-components list and the unshipped forwarder marker; the Bicep startup command fixed to what ships; the image discipline comment; the compliance extras line, completed by f0fe396f), the implemented APIM direct-route fail-closed guard and the network-rule primacy close; config-pin tests were committed red (7 of 8 failing against the old artefacts) then green; suite 3426 passed / 83 skipped; CI 21/21.

## Fix round
- FAIL 5 numbered at e275f9d -> f0fe396f (extras-completeness) -> align 1876d685 -> merged at 13:29:40Z. The body and commit-message prose defects are docs-class under the standing rule; no further checker re-run was recorded before the merge.

Recorded 2026-11-24.
