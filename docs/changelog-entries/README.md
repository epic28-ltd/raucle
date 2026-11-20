# Changelog entries (parallel-lane convention)

Builder lanes do NOT edit `CHANGELOG.md` directly. Concurrent lanes editing the
changelog collide on every merge; from this lane onward, each lane writes its
changelog bullets to a per-branch entry file instead, and the entries are
assembled into the changelog at merge time.

## The convention

- One entry file per lane branch: `docs/changelog-entries/<branch>.md`.
  The file name is the git branch name, with `/` replaced by `-`
  (for example `feat/w2-definition-drift` becomes
  `docs/changelog-entries/feat-w2-definition-drift.md`).
- The file contains ONLY the bullet lines that would have gone under
  `## Unreleased` in `CHANGELOG.md`. Plain `- ...` lines, no headings,
  no version banners. House style still applies (British English,
  no em dashes).
- Write it, commit it, and open the PR as usual. Do not touch
  `CHANGELOG.md` in the same lane.
- At merge time the merge orchestrator (or, once assembled into tooling,
  the `tools/assemble_changelog.py` script) inserts the entry bullets
  under `## Unreleased` in file order and deletes the entry files.
- The assembler refuses a bullet that duplicates an existing bullet line
  already in `CHANGELOG.md` (exit non-zero), so a re-run or a
  double-merged lane cannot seed duplicate lines.

## Why an entry file per branch

Two lanes appending to `CHANGELOG.md` at the root of the working tree are a
guaranteed rebase conflict; one small file per branch merges cleanly, and the
assembly step is mechanical and verifiable.
