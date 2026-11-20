"""Tests for the changelog entry assembler (tools/assemble_changelog.py).

Covers the parallel-lane convention: entry files insert under
`## Unreleased` in file order, entry files are deleted after assembly,
and a duplicate bullet is refused with a non-zero exit.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"
SCRIPT = TOOLS_DIR / "assemble_changelog.py"


def write_changelog(root: Path, body: str | None = None) -> Path:
    """Create a minimal changelog in a fake repo root."""
    if body is None:
        body = "# Changelog\n\n## Unreleased\n\n## 0.23.6 (2026-11-12)\n\n- existing\n"
    path = root / "CHANGELOG.md"
    path.write_text(body, encoding="utf-8")
    return path


def write_entry(root: Path, name: str, text: str) -> Path:
    entries = root / "docs" / "changelog-entries"
    entries.mkdir(parents=True, exist_ok=True)
    path = entries / name
    path.write_text(text, encoding="utf-8")
    return path


def run(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(root)],
        capture_output=True,
        text=True,
    )


def read_changelog(root: Path) -> str:
    return (root / "CHANGELOG.md").read_text(encoding="utf-8")


def test_bullets_insert_in_file_order_under_unreleased(tmp_path: Path) -> None:
    write_changelog(tmp_path)
    write_entry(tmp_path, "a-lane.md", "- Alpha bullet\n- Alpha second\n")
    write_entry(tmp_path, "b-lane.md", "- Beta bullet\n")
    result = run(tmp_path)
    assert result.returncode == 0
    text = read_changelog(tmp_path)
    unreleased_pos = text.index("## Unreleased")
    alpha_pos = text.index("- Alpha bullet")
    beta_pos = text.index("- Beta bullet")
    tail_pos = text.index("## 0.23.6")
    assert unreleased_pos < alpha_pos < beta_pos < tail_pos


def test_entry_files_are_deleted_after_assembly(tmp_path: Path) -> None:
    write_changelog(tmp_path)
    write_entry(tmp_path, "a-lane.md", "- Alpha bullet\n")
    run(tmp_path)
    assert not (tmp_path / "docs" / "changelog-entries" / "a-lane.md").exists()


def test_duplicate_bullet_skips_safely_without_duplicating(tmp_path: Path) -> None:
    """The checker's defect close (20 Nov): a populated Unreleased never
    loses content and a re-run never duplicates. The already-live bullet
    is skipped with a named notice; the entry file is consumed."""
    write_changelog(
        tmp_path,
        "# Changelog\n\n## Unreleased\n\n- Alpha bullet\n\n## 0.23.6\n\n- Beta\n",
    )
    write_entry(tmp_path, "a-lane.md", "- Alpha bullet\n")
    result = run(tmp_path)
    assert result.returncode == 0
    assert "skip a-lane.md" in result.stdout
    text = read_changelog(tmp_path)
    assert text.count("- Alpha bullet") == 1  # live, not duplicated
    assert not (tmp_path / "docs" / "changelog-entries" / "a-lane.md").exists()


def test_populated_unreleased_never_loses_content(tmp_path: Path) -> None:
    """The checker's content-loss scenario: assembling over a populated
    Unreleased keeps every pre-existing bullet and adds the new ones."""
    pre = "- Live bullet one\n- Live bullet two\n"
    write_changelog(
        tmp_path,
        f"# Changelog\n\n## Unreleased\n\n{pre}\n## 0.23.6\n",
    )
    write_entry(tmp_path, "a-lane.md", "- New bullet\n- Live bullet one\n")
    result = run(tmp_path)
    assert result.returncode == 0
    text = read_changelog(tmp_path)
    assert "- Live bullet one" in text and text.count("- Live bullet one") == 1
    assert "- Live bullet two" in text
    assert "- New bullet" in text


def test_missing_unreleased_heading_exits_non_zero(tmp_path: Path) -> None:
    write_changelog(tmp_path, "# Changelog\n\n## 0.23.6\n\n- existing\n")
    write_entry(tmp_path, "a-lane.md", "- Alpha bullet\n")
    result = run(tmp_path)
    assert result.returncode != 0


def test_no_entry_files_is_a_clean_noop(tmp_path: Path) -> None:
    write_changelog(tmp_path)
    result = run(tmp_path)
    assert result.returncode == 0
    assert "nothing to do" in result.stdout


def test_readme_is_never_assembled(tmp_path: Path) -> None:
    write_changelog(tmp_path)
    entries = tmp_path / "docs" / "changelog-entries"
    entries.mkdir(parents=True)
    (entries / "README.md").write_text(
        "# Convention\n\n- This is documentation, not an entry\n", encoding="utf-8"
    )
    result = run(tmp_path)
    assert result.returncode == 0
    assert "- This is documentation" not in read_changelog(tmp_path)


def test_empty_entry_file_tolerated(tmp_path: Path) -> None:
    write_changelog(tmp_path)
    write_entry(tmp_path, "empty-lane.md", "\n")
    write_entry(tmp_path, "a-lane.md", "- Alpha bullet\n")
    result = run(tmp_path)
    assert result.returncode == 0
    text = read_changelog(tmp_path)
    assert "- Alpha bullet" in text
    assert not (tmp_path / "docs" / "changelog-entries" / "a-lane.md").exists()


def test_multi_line_entry_content_is_preserved(tmp_path: Path) -> None:
    write_changelog(tmp_path)
    write_entry(
        tmp_path,
        "wrapped.md",
        "- A bullet that wraps\n  onto a following line\n",
    )
    result = run(tmp_path)
    assert result.returncode == 0
    text = read_changelog(tmp_path)
    assert "- A bullet that wraps\n  onto a following line\n" in text


def test_resulting_changelog_reassembles_without_duplicates(tmp_path: Path) -> None:
    # Second assembly round on the same changelog must also pass: the
    # previously assembled bullets become the existing content.
    write_changelog(tmp_path)
    write_entry(tmp_path, "a-lane.md", "- Alpha bullet\n")
    assert run(tmp_path).returncode == 0
    write_entry(tmp_path, "b-lane.md", "- Beta bullet\n")
    result = run(tmp_path)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "body",
    [
        "# Changelog\n\n## Unreleased\n",
        "# Changelog\n\n## Unreleased\n\n",
    ],
)
def test_heading_variants_insert_a_blank_line_after_the_block(tmp_path: Path, body: str) -> None:
    write_changelog(tmp_path, body)
    write_entry(tmp_path, "a-lane.md", "- Alpha bullet\n")
    result = run(tmp_path)
    assert result.returncode == 0
    text = read_changelog(tmp_path)
    assert text.startswith("# Changelog\n\n## Unreleased\n- Alpha bullet\n")
