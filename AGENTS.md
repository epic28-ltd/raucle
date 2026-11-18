# AGENTS.md — repo contract for every agent, bot, cron and delegate entering this repo

Owner: Craig (craigamcw), epic28-ltd. You were not briefed personally — this file is your brief.

## Non-negotiables
- NEVER push to any git remote. Commit locally with `-s craigamcw <craigamcw@users.noreply.github.com>`. Branch promotion (dev->main) is owner-only; the local pre-push hook is the hard gate.
- NEVER contact anyone or anything external: no emails, no GitHub comments/PRs on other repos, no EOI submissions, no blog posts, no partner approaches. No trademark or IP filings. External publishing is the owner's, in the moment.
- No compliance or legal claims in any produced text unless quoting an approved source verbatim.
- Secrets never go into git, code, or docs. If a task seems to need a secret, stop and note it as BLOCKED-OWNER.
- Do not touch ~/Projects/raucle-aws* (separate lane). The pinned historic worktree ~/Projects/oaa-spike-4nov/evd/raucle-63edacd is READ ONLY.
- Shared planning files (backlogs, strategy docs) are owner-lane: append status entries only where a documented convention says so; never rewrite.

## How to work
- Read before writing: README.md, docs/ structure, and the last few changelog entries. Match the existing style; the suite has a house format.
- Verify before declaring done: run the suite live yourself, `cd ~/Projects/raucle && .venv/bin/python -m pytest --tb=short -q` and `.venv/bin/ruff check .`. A bot summary is a self-report, not a fact; tests you ran are the only receipt.
- Security findings follow the RED-nnn convention: each fix merges with its own changelog entry; no separate advisories unless the owner asks.
- Worktree mode (`hermes -w`) when spawning concurrent agents on this repo.
- Timebox: if a wave exceeds its planned boundary, record state cleanly and stop; never fake progress.

## Style
- British English. No em dashes. User-facing copy is humanized (humanizer skill), concrete, no hype.

## Escalation
Anything irreversible, outward-facing, or needing credentials: record as BLOCKED-OWNER with the exact question, then stop.
