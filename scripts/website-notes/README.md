# Curated website release notes

One markdown file per release: `<version>.md` (for example `0.23.6.md`).

`scripts/sync_website.py` reads the file for the release being synced and
renders its two sections into raucle.com:

- `## Features` — one bullet per line. Rendered as the "Also in this release"
  list on the home page.
- `## What's new` — one plain paragraph, no trailing full stop. The script
  adds the "What's new in vX" lead-in and the changelog link.

If no file exists for the release, the sync falls back to extracting text
from `CHANGELOG.md` and prints a warning. Write the notes file before the
next release tag so the home page never shows engineering changelog prose.

Writing rules for this file: UK English, no em dashes, short sentences, name
the actor, keep every claim matched to the release's changelog section.
