#!/usr/bin/env python3
"""Sync raucle release content into the raucle.com website.

Parses ``CHANGELOG.md`` for a specific version's section, then injects three
pieces of HTML content into the target site between named comment markers:

- ``RAUCLE_DETECT:VERSION``   — release-badge with the current version
- ``RAUCLE_DETECT:FEATURES``  — bullet list of headline features
- ``RAUCLE_DETECT:WHATSNEW``  — "what's new in vN" callout

A curated per-release notes file (``scripts/website-notes/<version>.md``,
passed via ``--notes``) replaces the changelog extraction for FEATURES and
WHATSNEW.  Without it the script falls back to first-sentence extraction
from ``CHANGELOG.md`` and prints a warning — engineering changelog prose
should not reach the home page, so write the notes file before tagging.

Usage::

    python scripts/sync_website.py \\
        --changelog CHANGELOG.md \\
        --version 0.4.0 \\
        --website-html /tmp/raucle.com/index.html

The script is idempotent: running it twice with the same inputs produces
identical output.  It exits 0 on success, 1 if the version section is not
found, 2 if a required marker pair is missing in the website HTML.
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Marker helpers
# ---------------------------------------------------------------------------


def _marker_block(name: str) -> tuple[re.Pattern[str], str, str]:
    """Build the regex + literal markers for a named injection block."""
    start = f"<!-- RAUCLE_DETECT:{name}:START -->"
    end = f"<!-- RAUCLE_DETECT:{name}:END -->"
    pattern = re.compile(
        re.escape(start) + r".*?" + re.escape(end),
        flags=re.DOTALL,
    )
    return pattern, start, end


def _replace_block(html_doc: str, name: str, new_inner: str) -> str:
    """Replace the content between a marker pair with *new_inner*."""
    pattern, start, end = _marker_block(name)
    replacement = f"{start}\n{new_inner.rstrip()}\n            {end}"
    new_doc, count = pattern.subn(replacement, html_doc, count=1)
    if count == 0:
        raise SystemExit(f"error: markers RAUCLE_DETECT:{name}:* not found in website HTML")
    return new_doc


# ---------------------------------------------------------------------------
# CHANGELOG parsing
# ---------------------------------------------------------------------------


@dataclass
class ReleaseNotes:
    version: str
    headline_features: list[str] = field(default_factory=list)
    section_titles: list[str] = field(default_factory=list)
    raw_section: str = ""
    whatsnew_summary: str = ""


# Matches `## <version>`, optionally `(<date>)`, and optionally a trailing
# `— <title>` (em-dash / en-dash / hyphen) — the project's established changelog
# style, e.g. `## 0.17.0 (2026-06-01) — fail-closed redesign`.
_VERSION_HEADER_RE = re.compile(r"^##\s+([0-9][^\s(]*)\s*(?:\(([^)]*)\))?\s*(?:[—–-]\s.*)?$")
_BULLET_RE = re.compile(r"^\s*-\s+(.*)$")
_SUBSECTION_RE = re.compile(r"^###\s+(.*)$")
# Match Markdown emphasis like **foo** at the start of a bullet for the
# headline phrase.  Falls back to the first sentence fragment.
_BOLD_PHRASE_RE = re.compile(r"\*\*([^*]+)\*\*")


def parse_changelog(text: str, version: str) -> ReleaseNotes:
    """Extract the section for *version* and return parsed release notes."""
    lines = text.splitlines()
    notes = ReleaseNotes(version=version)
    collecting = False
    bullets: list[str] = []
    raw: list[str] = []
    current: str | None = None  # bullet being accumulated (may wrap lines)

    def _flush() -> None:
        nonlocal current
        if current is not None:
            bullets.append(current.strip())
            current = None

    for line in lines:
        header_match = _VERSION_HEADER_RE.match(line)
        if header_match:
            if collecting:
                # Hit the next release header — done
                break
            if header_match.group(1).lstrip("v") == version.lstrip("v"):
                collecting = True
                raw.append(line)
                continue
        if not collecting:
            continue

        raw.append(line)
        subsection = _SUBSECTION_RE.match(line)
        if subsection:
            _flush()
            notes.section_titles.append(subsection.group(1).strip())
            continue
        bullet = _BULLET_RE.match(line)
        if bullet:
            _flush()
            current = bullet.group(1).strip()
        elif current is not None and line.strip():
            # A wrapped continuation line of the current bullet (indented, no
            # marker). Join it so a multi-line bullet isn't truncated to its
            # first physical line in the website feature list.
            current += " " + line.strip()
        elif not line.strip():
            _flush()
    _flush()

    if not raw:
        raise SystemExit(f"error: version {version!r} not found in CHANGELOG")

    notes.raw_section = "\n".join(raw)
    notes.headline_features = _select_headline_features(bullets)
    return notes


def _select_headline_features(bullets: list[str], limit: int = 6) -> list[str]:
    """Pick the *limit* most marketing-friendly bullets.

    Heuristic: prefer bullets whose first **bold** phrase is short (a feature
    name) and whose remaining text reads as a benefit.  Strip nested markdown
    so the output is plain text suitable for HTML insertion.
    """
    headlines: list[str] = []
    for bullet in bullets:
        bold = _BOLD_PHRASE_RE.search(bullet)
        if bold and len(bold.group(1)) <= 60:
            # Use the bold phrase as the feature name, but condense
            # the post-em-dash explanation if present.
            # Strip markdown from the bold phrase too — bullets like
            # ``**`AgentIdentity`** — …`` carry literal backticks inside the
            # bold which otherwise render as visible punctuation on the page.
            name = _strip_markdown(bold.group(1).strip())
            rest = bullet[bold.end() :]
            rest = re.sub(r"^\s*\(`[^`]+`\)\s*", "", rest)  # drop (`code`) refs
            rest = re.sub(r"\s+", " ", rest).strip(" —–-")
            if rest:
                rest = _strip_markdown(rest)
                # Keep features concise — first sentence only
                rest = re.split(r"(?<=[.;])\s+", rest, maxsplit=1)[0]
                headlines.append(f"{name} — {rest}")
            else:
                headlines.append(name)
        else:
            cleaned = _strip_markdown(bullet)
            cleaned = re.split(r"(?<=[.;])\s+", cleaned, maxsplit=1)[0]
            headlines.append(cleaned)

        if len(headlines) >= limit:
            break

    return headlines


def _strip_markdown(text: str) -> str:
    """Remove `code`, **bold**, *italic*, and stray markdown punctuation."""
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]+)\*", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


_NOTES_SECTION_RE = re.compile(r"^##\s+(Features|What's new)\s*$", re.IGNORECASE)

# Curated site copy must not leak the changelog's category labels such as
# "Added - EPIC S2: ..." in the fallback WHATSNEW callout.
_FALLBACK_TITLE_PREFIX_RE = re.compile(r"^(Added|Changed|Fixed|Security|Deprecated)\s*-?\s*")


def parse_website_notes(text: str, version: str) -> ReleaseNotes:
    """Parse a curated website notes file (``website-notes/<version>.md``).

    ``## Features`` holds one bullet per line; ``## What's new`` holds a
    single plain paragraph rendered verbatim inside the callout.  A file
    missing either section is a hard error: curated copy that cannot be
    parsed must fail the sync rather than silently regressing to changelog
    prose on the home page.
    """
    notes = ReleaseNotes(version=version)
    bullets: list[str] = []
    summary_lines: list[str] = []
    section: str | None = None
    for line in text.splitlines():
        header = _NOTES_SECTION_RE.match(line.strip())
        if header:
            section = "features" if header.group(1).lower().startswith("feature") else "whatsnew"
            continue
        if section is None:
            continue  # skip the h1 and any preamble
        if section == "features":
            bullet = _BULLET_RE.match(line)
            if bullet:
                cleaned = _strip_markdown(bullet.group(1).strip())
                if cleaned:
                    bullets.append(cleaned)
        elif line.strip():
            summary_lines.append(_strip_markdown(line.strip()))
    if not bullets:
        raise SystemExit("error: curated website notes have no '## Features' bullet list")
    if not summary_lines:
        raise SystemExit("error: curated website notes have no '## What's new' paragraph")
    notes.headline_features = bullets
    notes.whatsnew_summary = " ".join(summary_lines).rstrip(".")
    return notes


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

_CHECK_SVG = (
    '<svg fill="none" stroke="currentColor" stroke-width="2" '
    'viewBox="0 0 24 24"><path d="M5 13l4 4L19 7"/></svg>'
)


def render_version_badge(version: str) -> str:
    return (
        '<p class="release-badge" '
        'style="display:inline-block;padding:4px 12px;background:#f1f2f4;'
        'border-radius:12px;font-size:0.75rem;color:#3a3f4b;margin-bottom:16px;">'
        f"Latest release: <strong>v{html.escape(version)}</strong>"
        "</p>"
    )


def render_features_list(features: list[str], heading: str | None = None) -> str:
    prefix = ""
    if heading:
        prefix = (
            '<h3 style="font-size:1.15rem;font-weight:600;margin:28px 0 8px;">'
            f"{html.escape(heading)}</h3>\n"
        )
    items = []
    for feat in features:
        items.append(
            f"                <li>\n"
            f"                    {_CHECK_SVG}\n"
            f"                    {html.escape(feat)}\n"
            f"                </li>"
        )
    body = (
        "\n".join(items)
        if items
        else (
            "                <li>\n"
            f"                    {_CHECK_SVG}\n"
            "                    Open-source detection engine\n"
            "                </li>"
        )
    )
    return prefix + '<ul class="oss-features">\n' + body + "\n            </ul>"


def render_whatsnew(
    version: str,
    section_titles: list[str],
    repo_url: str,
    summary: str | None = None,
) -> str:
    """Render a small 'what's new in vN' callout linking to the release notes.

    A curated *summary* replaces the section-title heuristic.  The fallback
    strips the changelog's leading "Added - " style prefixes so raw category
    labels never reach the page.
    """
    if summary:
        title_summary = html.escape(summary)
    elif not section_titles:
        title_summary = "release notes"
    else:
        # Take the most marketing-friendly section titles after stripping
        # changelog category prefixes.  If "New Features" is in the list,
        # lead with that.
        priority = ["New Features", "Compliance & Audit (EU AI Act / SOC 2 ready)"]
        cleaned = [_FALLBACK_TITLE_PREFIX_RE.sub("", t).strip() for t in section_titles]
        titles = sorted(
            cleaned,
            key=lambda t: (priority.index(t) if t in priority else 99, t),
        )
        title_summary = ", ".join(html.escape(t) for t in titles[:4])

    link = f"{repo_url}/blob/main/CHANGELOG.md"
    return (
        '<p class="release-whatsnew" '
        'style="margin-top:16px;font-size:0.85rem;color:var(--text-muted);">'
        f"<strong>What's new in v{html.escape(version)}:</strong> "
        f"{title_summary}. "
        f'<a href="{html.escape(link)}" '
        'style="color:var(--text-muted);text-decoration:underline;">Read the changelog →</a>'
        "</p>"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changelog", type=Path, required=True, help="Path to CHANGELOG.md")
    parser.add_argument("--version", required=True, help="Release version to sync, e.g. 0.4.0")
    parser.add_argument(
        "--website-html",
        type=Path,
        required=True,
        help="Path to the website index.html to update in-place",
    )
    parser.add_argument(
        "--notes",
        type=Path,
        default=None,
        help=(
            "Optional curated website notes file (website-notes/<version>.md) "
            "replacing changelog extraction for FEATURES/WHATSNEW"
        ),
    )
    parser.add_argument(
        "--repo-url",
        default="https://github.com/epic28-ltd/raucle",
        help="Base URL for the raucle GitHub repo",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print result, do not write")
    args = parser.parse_args(argv)

    changelog_text = args.changelog.read_text(encoding="utf-8")
    notes = parse_changelog(changelog_text, args.version)

    features_heading = None
    if args.notes is not None:
        if args.notes.exists():
            curated = parse_website_notes(args.notes.read_text(encoding="utf-8"), args.version)
            notes.headline_features = curated.headline_features
            notes.whatsnew_summary = curated.whatsnew_summary
            features_heading = "Also in this release"
            print(f"  Using curated website notes: {args.notes}", file=sys.stderr)
        else:
            print(
                f"::warning::No curated website notes at {args.notes}; "
                "falling back to changelog heuristics.",
                file=sys.stderr,
            )

    html_doc = args.website_html.read_text(encoding="utf-8")
    html_doc = _replace_block(html_doc, "VERSION", render_version_badge(notes.version))
    html_doc = _replace_block(
        html_doc, "FEATURES", render_features_list(notes.headline_features, features_heading)
    )
    html_doc = _replace_block(
        html_doc,
        "WHATSNEW",
        render_whatsnew(
            notes.version,
            notes.section_titles,
            args.repo_url,
            summary=notes.whatsnew_summary or None,
        ),
    )

    if args.dry_run:
        sys.stdout.write(html_doc)
        return 0

    args.website_html.write_text(html_doc, encoding="utf-8")
    print(f"Updated {args.website_html} for release v{notes.version}", file=sys.stderr)
    print(f"  Features injected: {len(notes.headline_features)}", file=sys.stderr)
    print(f"  Sections: {notes.section_titles}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
