# Security posture snapshot — raucle (epic28-ltd), NFR build P5.NFR v1

**Snapshot scope and honesty rules.** Everything below was measured live on
6 Nov 2026 against repo state `main` @ `7f4b3d3` via the GitHub REST API,
the SonarCloud API (authenticated with the project token) and the local
git clone. No figure is quoted from memory. This document is a point-in-time
snapshot: the standing rule is that it must be RE-MEASURED, not edited by
hand, before any release or demo cites it. It makes no compliance claims —
a receipt or a green gate does not establish compliance; see P5.N4 claims
discipline in `~/Projects/raucle-master-backlog.md`.

## Analysis pipeline

- Analysis method: CI-based only (`sonar.yml` workflow; GitHub-App automatic
  analysis is disabled for this project).
- Analysed scope: `sonar.sources=raucle,reference`, `sonar.tests=tests`;
  fixtures/docs/deploy excluded with documented rationale in
  `sonar-project.properties`.
- Latest `main` analysis: quality gate **OK**.
  - new_reliability_rating 1 (A), new_security_rating 1 (A),
    new_maintainability_rating 1 (A)
  - new_coverage 88.5 (gate threshold 80)
  - new_duplicated_lines_density 0.0 (threshold 3)
  - new_security_hotspots_reviewed 100.0

## Open findings (measured, project-level)

- 89 open Sonar issues on `main`, ALL `CODE_SMELL`: 82 MAJOR, 5 CRITICAL,
  2 MINOR. 0 VULNERABILITY, 0 BUG, 0 BLOCKER.
- These live entirely on pre-snapshot code (the gate measures only
  new-since-2026-09-01 code); PR #199 (`chore/sonar-sweep-r2`) is OPEN with
  the standing objective of clearing all 89. A reviewer should regard
  "89 open code smells" as the true current backlog count, not as a
  security rating.
- 2 open PRs (#201 containment v1, #199 Sonar sweep) — neither merged,
  both gated by the checks below.

## Branch protection (repo `epic28-ltd/raucle`, branch `main`)

Required status checks (strict, up-to-date required), measured via
`GET /branches/main/protection`:

- Lint, Test (Python 3.11 / 3.12 / 3.13), CLI Smoke Test,
  Policy static-verification (pre-registration invariant),
  SonarCloud Code Analysis, DCO Sign-off,
  plus Cross-language conformance (5 reference ports) and
  Build Package on the merge runs.

Also enforced: `enforce_admins` = true ("Do not allow bypassing the above
settings"); required PR reviews with required_approving_review_count = 0
(merge-by-checks, no human approval required); repo-level auto-merge
enabled (PRs use `gh pr merge --auto`); direct pushes to `main` fail
(GH006).

The per-PR merge gate additionally enforces (SONAR-ACCEPTANCE documented):
**a PR is unmergeable while ANY open Sonar issue remains on its new code** —
verified via the PR-scoped `qualitygates/project_status` and
`issues/search?pullRequest=<n>` before merge.

## DCO sign-off state

- Measured over the last 100 non-merge commits on `main`: **100/100 carry a
  `Signed-off-by:` trailer.** Merge commits created by the GitHub UI carry
  none (they are not code); every content commit is signed.
- Required check `DCO Sign-off` is green on the current branch runs.
- Identity note: trailers appear under both `craigamcw` and
  `Craig Allan-McWilliams` identities; both resolve to the same committer.

## Honest gaps (recorded, not spun)

- `secret_scanning`: **disabled**; `secret_scanning_push_protection`:
  **disabled**; `dependabot_security_updates`: **disabled**. These are
  repo settings on the free plan that were never opted in — they are NOT
  compensating controls and their absence is a gap this snapshot records.
- Sonar's taint engine finding count is engine-dependent; internal
  allowlists are not credited as sanitising (documented acceptances live in
  `docs/spikes/SONAR-ACCEPTANCE.md`, decision owner Craig).
- The pre-push local hook's sonar-scanner reports the working tree to the
  PROJECT default-branch identity — true project-level state converges only
  via the repo's own CI analysis on merged `main`. PR-scoped figures above
  are the verified state.
- Threat model coverage is documented separately in
  `docs/threat-model/v1.md` (P4.C); it is not restated here to avoid two
  sources of truth.

## Re-measure recipe (for the next snapshot)

```
curl -s https://sonarcloud.io/api/qualitygates/project_status?projectKey=epic28-ltd_raucle \
  -u "SONAR_PROJECT_TOKEN:"
curl -s "https://sonarcloud.io/api/issues/search?componentKeys=epic28-ltd_raucle\
&resolved=false&ps=1&facets=types,severities" -u "SONAR_PROJECT_TOKEN:"
gh api repos/epic28-ltd/raucle/branches/main/protection
git log origin/main -100 --no-merges --format='%(trailers:key=Signed-off-by,valueonly)' | grep -c .
```
