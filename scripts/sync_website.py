#!/usr/bin/env python3
"""Sync raucle release content into the raucle.com website.

Parses the required curated notes file (``--notes``, the site checkout's
``notes/<version>.md``) and validates the version against ``CHANGELOG.md``
before injecting three pieces of HTML content into the target site.
Missing, incomplete or malformed notes fail closed; changelog prose is
never used as a fallback.

- ``RAUCLE_DETECT:VERSION``   — release-badge with the current version
- ``RAUCLE_DETECT:FEATURES``  — bullet list of headline features
- ``RAUCLE_DETECT:WHATSNEW``  — "what's new in vN" callout

Usage::

    python scripts/sync_website.py \\
        --changelog CHANGELOG.md \\
        --version 0.4.0 \\
        --website-html /tmp/raucle.com/trust-centre/release-evidence/index.html \\
        --notes /tmp/raucle.com/notes/0.4.0.md

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


# Matches `## <version>`, optionally `(<date>)`, and optionally a trailing
# `— <title>` (em-dash / en-dash / hyphen) — the project's established changelog
# style, e.g. `## 0.17.0 (2026-06-01) — fail-closed redesign`.
_VERSION_HEADER_RE = re.compile(r"^##\s+([0-9][^\s(]*)\s*(?:\(([^)]*)\))?\s*(?:[—–-]\s.*)?$")
_BULLET_RE = re.compile(r"^\s*-\s+(.*)$")
_SUBSECTION_RE = re.compile(r"^###\s+(.*)$")
# Match Markdown emphasis like **foo** at the start of a bullet for the
# headline phrase.  Falls back to the first sentence fragment.
_BOLD_PHRASE_RE = re.compile(r"\*\*([^*]+)\*\*")


def parse_notes(text: str) -> tuple[list[str], str]
    """Parse the curated notes markdown: '## Features' bullets and a
    '## What's new' summary paragraph. Returns (features, summary)."""
    features: list[str] | None = None
    summary_parts: list[str] = []
    section = None
    seen_summary = False
    for line in text.splitlines():
        stripped = line.strip()
        heading = re.match(r"^##\s+(.+?)\s*$", stripped)
        if heading:
            title = heading.group(1).replace("’", "'").casefold()
            if title == "features":
                if features is not None:
                    raise ValueError("duplicate '## Features' section")
                section = "features"
                features = []
            elif title == "what's new":
                if seen_summary:
                    raise ValueError("duplicate '## What's new' section")
                seen_summary = True
                section = "whatsnew"
            else:
                section = None
            continue
        if not stripped:
            continue
        if section == "features":
            bullet = re.match(r"^\s*[-*+]\s+(.+?)\s*$", line)
            if not bullet:
                raise ValueError("every non-empty line in '## Features' must be a Markdown bullet")
            feature = _strip_markdown(bullet.group(1)).strip()
            if not feature:
                raise ValueError("'## Features' contains an empty bullet")
            features.append(feature)
        elif section == "whatsnew":
            if stripped.startswith(("~~~", ">")) or stripped.startswith(chr(96) * 3) or re.match(r"^(?:[-*+]\s+|\d+[.)]\s+|#{1,6}\s+)", stripped):
                raise ValueError("'## What's new' must contain prose, not Markdown block syntax")
            prose = _strip_markdown(stripped).strip()
            if prose:
                summary_parts.append(prose)
    summary = " ".join(summary_parts).strip() or None
    if features is None:
        raise ValueError("notes file has no '## Features' section")
    if not features:
        raise ValueError("'## Features' section has no non-empty bullet entries")
    if not summary:
        raise ValueError("notes file has no non-empty '## What's new' summary paragraph")
    return features, summary


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
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]+)\*", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


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


def render_features_list(features: list[str]) -> str:
    if not features:
        raise ValueError("refusing to render an empty curated features list")
    items = []
    for feat in features:
        items.append(
            f"                <li>\n"
            f"                    {_CHECK_SVG}\n"
            f"                    {html.escape(feat)}\n"
            f"                </li>"
        )
    body = "\n".join(items)
    return '<ul class="oss-features">\n' + body + "\n            </ul>"


def render_whatsnew(version: str, section_titles: list[str], repo_url: str, summary: str | None = None) -> str:
    """Render a small 'what's new in vN' callout linking to the release notes."""
    if summary:
        title_summary = html.escape(summary)
    elif not section_titles:
        title_summary = "release notes"
    else:
        # Take the most marketing-friendly section titles.
        # If "New Features" is in the list, lead with that.
        priority = ["New Features", "Compliance & Audit (EU AI Act / SOC 2 ready)"]
        titles = sorted(
            section_titles,
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
        help="Path to the website HTML holding the release-evidence marker blocks",
    )
    parser.add_argument(
        "--notes",
        type=Path,
        required=True,
        help="Curated notes markdown (## Features bullets + ## What's new paragraph)",
    )
    parser.add_argument(
        "--repo-url",
        default="https://github.com/epic28-ltd/raucle",
        help="Base URL for the raucle GitHub repo",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print result, do not write")
    args = parser.parse_args(argv)

    if not args.notes.is_file():
        raise SystemExit(
            f"error: curated notes file not found: {args.notes} - refusing to "
            "render release copy from the raw changelog. Write notes/<version>.md"
            " in the site checkout (## Features + ## What's new) before syncing."
        )
    notes_text = args.notes.read_text(encoding="utf-8")
    try:
        features, summary = parse_notes(notes_text)
    except ValueError as exc:
        raise SystemExit(f"error: invalid curated notes: {exc}") from exc
    notes = parse_changelog(args.changelog.read_text(encoding="utf-8"), args.version)
    notes.headline_features = features

    html_doc = args.website_html.read_text(encoding="utf-8")
    html_doc = _replace_block(html_doc, "VERSION", render_version_badge(notes.version))
    html_doc = _replace_block(html_doc, "FEATURES", render_features_list(notes.headline_features))
    html_doc = _replace_block(
        html_doc,
        "WHATSNEW",
        render_whatsnew(notes.version, [], args.repo_url, summary=summary),
    )

    if args.dry_run:
        sys.stdout.write(html_doc)
        return 0

    args.website_html.write_text(html_doc, encoding="utf-8")
    print(f"Updated {args.website_html} for release v{notes.version}", file=sys.stderr)
    print(f"  Features injected (curated notes): {len(notes.headline_features)}", file=sys.stderr)
    print(f"  What's new summary: {summary}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
