"""Honesty guard for ``docs/integrations/matrix.md``.

The integration matrix must not drift from reality. Two rules, test-pinned
here:

1. Every module under ``raucle/integrations/`` appears in the matrix
   (no quietly dropped or forgotten adapters).
2. Every row marked WIRED names at least one test file that actually
   exists in ``tests/`` (a WIRED claim without running evidence is a
   false claim).
"""

from __future__ import annotations

import pathlib
import pkgutil

import raucle.integrations

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
MATRIX = REPO_ROOT / "docs" / "integrations" / "matrix.md"


def _matrix_text() -> str:
    assert MATRIX.exists(), "docs/integrations/matrix.md is missing"
    return MATRIX.read_text(encoding="utf-8")


def test_every_integration_module_is_in_the_matrix():
    text = _matrix_text()
    modules = {name for _, name, _ in pkgutil.iter_modules(raucle.integrations.__path__)}
    missing = sorted(m for m in modules if f"`{m}.py`" not in text)
    assert not missing, f"integration modules absent from matrix.md: {missing}"


def test_every_wired_row_names_a_real_test_file():
    text = _matrix_text()
    wired_rows = [line for line in text.splitlines() if "| WIRED |" in line]
    assert wired_rows, "matrix lost its WIRED rows — table format change?"
    for line in wired_rows:
        assert "tests/test_" in line, f"WIRED row without evidence: {line}"
        for token in line.split("`"):
            if token.startswith("tests/"):
                assert (REPO_ROOT / token).with_suffix(".py").exists(), (
                    f"matrix names a non-existent test file: {token}"
                )


def test_autogen_is_not_overstated():
    """AutoGen has no dedicated test file; it must stay DOC-ONLY until one
    lands. Guard against a well-meaning status upgrade."""
    text = _matrix_text()
    row = next(line for line in text.splitlines() if "`autogen.py`" in line)
    assert "DOC-ONLY" in row, "autogen.py upgraded without a test file"
