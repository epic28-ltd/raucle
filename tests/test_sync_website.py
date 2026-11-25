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

_NOTES = textwrap.dedent("""\
    ## Features

    - Tamper-evident audit chain: every event SHA-256 linked to its predecessor
    - Signed JWS verdict receipts: downstream-verifiable

    ## What's new

    The policy prover narrows capabilities before the gate runs.
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
    @staticmethod
    def _notes(tmp_path) -> Path:
        notes_path = tmp_path / "0.4.0.md"
        notes_path.write_text(_NOTES)
        return notes_path

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
                "--notes",
                str(self._notes(tmp_path)),
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
            "--notes",
            str(self._notes(tmp_path)),
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
                    "--notes",
                    str(self._notes(tmp_path)),
                ]
            )


class TestCuratedNotes:
    def test_parse_notes_extracts_features_and_summary(self):
        features, summary = sync_website.parse_notes(_NOTES)
        assert features == [
            "Tamper-evident audit chain: every event SHA-256 " "linked to its predecessor",
            "Signed JWS verdict receipts: downstream-verifiable",
        ]
        assert summary == "The policy prover narrows capabilities before the gate runs."

    def test_parse_notes_without_features_section_is_an_error(self, tmp_path):
        notes_path = tmp_path / "bad.md"
        notes_path.write_text("## What's new\n\nOnly a summary.\n")
        import pytest

        with pytest.raises(SystemExit, match="no '## Features' section"):
            sync_website.main(
                [
                    "--changelog",
                    str(_write_changelog(tmp_path)),
                    "--version",
                    "0.4.0",
                    "--website-html",
                    str(_write_website(tmp_path)),
                    "--notes",
                    str(notes_path),
                ]
            )

    def test_missing_notes_file_is_an_error(self, tmp_path):
        import pytest

        with pytest.raises(SystemExit, match="curated notes file not found"):
            sync_website.main(
                [
                    "--changelog",
                    str(_write_changelog(tmp_path)),
                    "--version",
                    "0.4.0",
                    "--website-html",
                    str(_write_website(tmp_path)),
                    "--notes",
                    str(tmp_path / "absent.md"),
                ]
            )


def _write_changelog(tmp_path) -> Path:
    p = tmp_path / "CHANGELOG.md"
    p.write_text(_CHANGELOG)
    return p


def _write_website(tmp_path) -> Path:
    p = tmp_path / "index.html"
    p.write_text(_HTML_TEMPLATE)
    return p
