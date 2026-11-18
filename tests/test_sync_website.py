"""Tests for the raucle.com release-sync script."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import sync_website  # noqa: E402

_CHANGELOG = textwrap.dedent("""\
    # Changelog

    ## 0.4.0 (2026-05-13)

    ### New Features

    - **Tamper-evident audit chain** (`HashChainSink`) — every event SHA-256
      linked to its predecessor; Ed25519 signed checkpoints.
    - **Signed JWS verdict receipts** (`VerdictSigner`) — downstream-verifiable.
    - **Outcome verification** — LANDED, REFUSED, or UNCERTAIN.

    ### Compliance

    - EU AI Act Article 12 ready.

    ## 0.3.0 (2026-05-12)

    ### New Features

    - **Old feature** — this should not appear in 0.4.0 output.
    """)


_HTML_TEMPLATE = textwrap.dedent("""\
    <html>
    <body>
        <section>
            <!-- RAUCLE_DETECT:VERSION:START -->
            <p>old version</p>
            <!-- RAUCLE_DETECT:VERSION:END -->
            <p>The detection engine.</p>
            <!-- RAUCLE_DETECT:FEATURES:START -->
            <ul><li>old feature</li></ul>
            <!-- RAUCLE_DETECT:FEATURES:END -->
            <!-- RAUCLE_DETECT:WHATSNEW:START -->
            <!-- RAUCLE_DETECT:WHATSNEW:END -->
        </section>
    </body>
    </html>
    """)


class TestParseChangelog:
    def test_extracts_target_version_only(self):
        notes = sync_website.parse_changelog(_CHANGELOG, "0.4.0")
        assert notes.version == "0.4.0"
        assert "Old feature" not in " ".join(notes.headline_features)

    def test_collects_section_titles(self):
        notes = sync_website.parse_changelog(_CHANGELOG, "0.4.0")
        assert "New Features" in notes.section_titles
        assert "Compliance" in notes.section_titles

    def test_headline_features_use_bold_phrase(self):
        notes = sync_website.parse_changelog(_CHANGELOG, "0.4.0")
        assert any("Tamper-evident audit chain" in f for f in notes.headline_features)
        assert any("Signed JWS verdict receipts" in f for f in notes.headline_features)

    def test_missing_version_raises(self):
        import pytest

        with pytest.raises(SystemExit, match="not found"):
            sync_website.parse_changelog(_CHANGELOG, "9.9.9")

    def test_header_with_em_dash_title_parses(self):
        """Regression: the project's changelog style puts a `— title` after the
        `(date)` (e.g. `## 0.17.0 (2026-06-01) — fail-closed redesign`). The
        parser must still locate the section (this broke the website sync on the
        v0.17.0 tag)."""
        changelog = (
            "## 0.17.0 (2026-06-01) — fail-closed redesign (stricter by default)\n\n"
            "### Security fixes\n\n"
            "- **Decorative proof inputs** — unmodelled keys force UNDECIDED.\n\n"
            "## 0.16.4 (2026-06-01) — prover soundness\n\n"
            "- **older** — prior release.\n"
        )
        notes = sync_website.parse_changelog(changelog, "0.17.0")
        assert notes.version == "0.17.0"
        assert "Security fixes" in notes.section_titles
        # Must stop at the next release header, not bleed into 0.16.4.
        assert "older" not in notes.raw_section
        assert all("older" not in f for f in notes.headline_features)

    def test_backticks_inside_bold_phrase_stripped(self):
        """Regression: ``**`AgentIdentity`** — …`` should produce a clean
        feature name ``AgentIdentity`` with no literal backticks rendered."""
        changelog_with_code_bold = (
            "## 0.5.0 (2026-05-14)\n\n"
            "### New Features\n\n"
            "- **`AgentIdentity`** — Ed25519 keypair plus a signed statement.\n"
        )
        notes = sync_website.parse_changelog(changelog_with_code_bold, "0.5.0")
        joined = " ".join(notes.headline_features)
        assert "AgentIdentity" in joined
        assert "`" not in joined

    def test_wrapped_bullet_is_joined_not_truncated(self):
        """Regression: a bullet that wraps across physical lines must be joined,
        not truncated to its first line (which produced mid-sentence fragments
        in the website feature list)."""
        changelog = (
            "## 0.6.0 (2026-05-20)\n\n"
            "### New Features\n\n"
            "- **Streaming verifier** — validates receipts incrementally as they\n"
            "  arrive, so a long chain never has to be buffered whole in memory.\n"
        )
        notes = sync_website.parse_changelog(changelog, "0.6.0")
        joined = " ".join(notes.headline_features)
        # The continuation line ("arrive, so a long chain…") must be present —
        # i.e. the bullet was joined, not cut at "as they".
        assert "buffered whole in memory" in joined
        assert not joined.rstrip().endswith("as they")


class TestRendering:
    def test_version_badge_html_escaped(self):
        out = sync_website.render_version_badge("0.4.0")
        assert "v0.4.0" in out
        assert 'class="release-badge"' in out

    def test_features_list_renders_items(self):
        out = sync_website.render_features_list(["Feature A", "Feature B & C"])
        assert "Feature A" in out
        assert "Feature B &amp; C" in out  # HTML-escaped
        assert out.count("<li>") == 2

    def test_features_list_empty_uses_placeholder(self):
        out = sync_website.render_features_list([])
        assert "<li>" in out  # still renders a fallback bullet

    def test_whatsnew_includes_link_and_titles(self):
        out = sync_website.render_whatsnew(
            "0.4.0",
            ["New Features", "Compliance"],
            "https://github.com/example/repo",
        )
        assert "v0.4.0" in out
        assert "New Features" in out
        assert "https://github.com/example/repo/blob/main/CHANGELOG.md" in out


class TestEndToEnd:
    def test_full_sync_replaces_all_three_blocks(self, tmp_path):
        changelog_path = tmp_path / "CHANGELOG.md"
        changelog_path.write_text(_CHANGELOG)
        website_path = tmp_path / "index.html"
        website_path.write_text(_HTML_TEMPLATE)

        rc = sync_website.main(
            [
                "--changelog",
                str(changelog_path),
                "--version",
                "0.4.0",
                "--website-html",
                str(website_path),
            ]
        )
        assert rc == 0

        result = website_path.read_text()
        assert "v0.4.0" in result
        assert "Tamper-evident audit chain" in result
        assert "old version" not in result
        assert "old feature" not in result
        assert "What's new in v0.4.0" in result

    def test_idempotent(self, tmp_path):
        changelog_path = tmp_path / "CHANGELOG.md"
        changelog_path.write_text(_CHANGELOG)
        website_path = tmp_path / "index.html"
        website_path.write_text(_HTML_TEMPLATE)

        args = [
            "--changelog",
            str(changelog_path),
            "--version",
            "0.4.0",
            "--website-html",
            str(website_path),
        ]
        sync_website.main(args)
        once = website_path.read_text()
        sync_website.main(args)
        twice = website_path.read_text()
        assert once == twice

    def test_missing_marker_raises(self, tmp_path):
        changelog_path = tmp_path / "CHANGELOG.md"
        changelog_path.write_text(_CHANGELOG)
        broken_html = "<html><body>no markers here</body></html>"
        website_path = tmp_path / "index.html"
        website_path.write_text(broken_html)

        import pytest

        with pytest.raises(SystemExit, match="markers RAUCLE_DETECT:VERSION"):
            sync_website.main(
                [
                    "--changelog",
                    str(changelog_path),
                    "--version",
                    "0.4.0",
                    "--website-html",
                    str(website_path),
                ]
            )


class TestCuratedNotes:
    _NOTES = textwrap.dedent("""\
        # Website release notes: 0.4.0

        Preamble that must be ignored.

        ## Features

        - **Curated feature** — from the curated file only.
        - Plain bullet two. See the changelog for the full list.

        ## What's new

        curated summary one, curated summary two
        """)

    def test_parse_website_notes_sections(self):
        notes = sync_website.parse_website_notes(self._NOTES, "0.4.0")
        assert len(notes.headline_features) == 2
        assert notes.headline_features[0].startswith("Curated feature")
        assert "**" not in notes.headline_features[0]
        assert "Preamble" not in " ".join(notes.headline_features)

    def test_parse_website_notes_summary_verbatim(self):
        notes = sync_website.parse_website_notes(self._NOTES, "0.4.0")
        assert notes.whatsnew_summary == "curated summary one, curated summary two"

    def test_malformed_notes_missing_summary_raises(self):
        import pytest

        truncated = self._NOTES.split("## What's new")[0]
        with pytest.raises(SystemExit, match="What's new"):
            sync_website.parse_website_notes(truncated, "0.4.0")

    def test_curated_sync_replaces_blocks_and_is_idempotent(self, tmp_path):
        notes_path = tmp_path / "0.4.0.md"
        notes_path.write_text(self._NOTES)
        changelog_path = tmp_path / "CHANGELOG.md"
        changelog_path.write_text(_CHANGELOG)
        website_path = tmp_path / "index.html"
        website_path.write_text(_HTML_TEMPLATE)
        args = [
            "--changelog",
            str(changelog_path),
            "--version",
            "0.4.0",
            "--notes",
            str(notes_path),
            "--website-html",
            str(website_path),
        ]
        sync_website.main(args)
        once = website_path.read_text()
        sync_website.main(args)
        assert once == website_path.read_text()
        assert "Also in this release" in once
        assert "curated summary one" in once
        # Changelog prose must not leak when curated notes are used.
        assert "Tamper-evident audit chain" not in once

    def test_missing_notes_file_falls_back_with_warning(self, tmp_path, capsys):
        changelog_path = tmp_path / "CHANGELOG.md"
        changelog_path.write_text(_CHANGELOG)
        website_path = tmp_path / "index.html"
        website_path.write_text(_HTML_TEMPLATE)
        rc = sync_website.main(
            [
                "--changelog",
                str(changelog_path),
                "--version",
                "0.4.0",
                "--notes",
                str(tmp_path / "nope.md"),
                "--website-html",
                str(website_path),
            ]
        )
        assert rc == 0
        assert "Tamper-evident audit chain" in website_path.read_text()
        assert "::warning::" in capsys.readouterr().err

    def test_curated_whatsnew_summary_reaches_page(self):
        out = sync_website.render_whatsnew("0.5.0", ["Added - something"], "url", summary="a, b")
        assert "a, b" in out
        assert "something" not in out

    def test_fallback_whatsnew_strips_category_prefix(self):
        out = sync_website.render_whatsnew(
            "0.5.0", ["Added - EPIC S2: thing", "New Features"], "url"
        )
        assert "Added - " not in out
        assert "EPIC S2: thing" in out
        assert "New Features" in out
