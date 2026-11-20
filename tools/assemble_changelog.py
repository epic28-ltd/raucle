#!/usr/bin/env python3
"""Assemble docs/changelog-entries/*.md into CHANGELOG.md.

Reads the per-lane entry files (one file per branch, bullet lines only),
inserts their content under the `## Unreleased` heading in CHANGELOG.md in
file order, then deletes the entry files.

Exits non-zero if a bullet line would duplicate an existing bullet line in
CHANGELOG.md (a re-run or a double-merged lane must never seed duplicate
lines), or if the changelog has no `## Unreleased` heading to assemble into.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

DEFAULT_CHANGELOG = "CHANGELOG.md"
DEFAULT_ENTRIES_DIR = "docs/changelog-entries"
UNRELEASED_HEADING = "## Unreleased"


class AssembleError(Exception):
    """Raised when the changelog cannot be assembled safely."""


def bullet_lines(text: str) -> list[str]:
    """Return the bullet lines of a block of text."""
    return [line.strip() for line in text.splitlines() if line.strip().startswith("- ")]


def find_unreleased_index(lines: list[str]) -> int:
    """Return the index of the `## Unreleased` heading line."""
    for i, line in enumerate(lines):
        if line.strip() == UNRELEASED_HEADING:
            return i
    raise AssembleError(
        f"no '{UNRELEASED_HEADING}' heading found in CHANGELOG.md; "
        "the assembler needs it to insert entry bullets - recreate the "
        "heading and re-run"
    )


def load_entries(entries_dir: Path) -> dict[str, str]:
    """Load entry files keyed by filename, in sorted file order."""
    if not entries_dir.is_dir():
        return {}
    entries: dict[str, str] = {}
    for path in sorted(entries_dir.glob("*.md")):
        if path.name == "README.md":
            continue
        entries[path.name] = path.read_text(encoding="utf-8")
    return entries


def guard_duplicates(
    changelog_text: str,
    entries: dict[str, str],
) -> None:
    """Refuse any entry bullet that duplicates a changelog bullet line."""
    existing = set(bullet_lines(changelog_text))
    for name, text in entries.items():
        for bullet in bullet_lines(text):
            if bullet in existing:
                raise AssembleError(
                    f"duplicate bullet in entry file {name}: a line identical "
                    f"to '{bullet[:80]}...' already exists in CHANGELOG.md; "
                    "assembling would duplicate it - remove the duplicate "
                    "from the entry file and re-run"
                )


def build_insert_block(entries: dict[str, str]) -> str:
    """Build the block inserted under the Unreleased heading."""
    blocks: list[str] = []
    for name in sorted(entries):
        text = entries[name].rstrip("\n")
        blocks.append(text)
        blocks.append("")
    return "\n".join(blocks)


def assemble(changelog_path: Path, entries_dir: Path) -> int:
    """Assemble entries into the changelog; return the count of files merged."""
    changelog_text = changelog_path.read_text(encoding="utf-8")
    entries = load_entries(entries_dir)
    if not entries:
        print("no changelog entry files to assemble; nothing to do")
        return 0
    guard_duplicates(changelog_text, entries)
    lines = changelog_text.splitlines(keepends=True)
    heading_index = find_unreleased_index(lines)
    # Insert directly after the heading, then a blank line between the
    # assembled block and whatever section followed the heading.
    insert_block = build_insert_block(entries) + "\n"
    new_lines = (
        lines[: heading_index + 1]
        + [insert_block]
        + lines[heading_index + 1 :]
    )
    changelog_path.write_text("".join(new_lines), encoding="utf-8")
    for name in entries:
        (entries_dir / name).unlink()
    print(
        f"assembled {len(entries)} changelog entry file(s) under "
        f"{UNRELEASED_HEADING}: {', '.join(sorted(entries))}"
    )
    return len(entries)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root holding CHANGELOG.md and docs/changelog-entries/",
    )
    args = parser.parse_args(argv)
    changelog_path = args.repo_root / DEFAULT_CHANGELOG
    entries_dir = args.repo_root / DEFAULT_ENTRIES_DIR
    try:
        assemble(changelog_path, entries_dir)
    except AssembleError as exc:
        print(f"assemble_changelog: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"assemble_changelog: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
