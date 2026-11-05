"""Regression tests for the raucle_detect -> raucle rename compatibility layer."""

from __future__ import annotations

import subprocess
import sys
import warnings


def test_old_import_warns_and_aliases():
    for mod in list(sys.modules):
        if mod == "raucle_detect" or mod.startswith("raucle_detect."):
            del sys.modules[mod]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        import raucle_detect  # noqa: F401
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)
    import raucle

    assert sys.modules["raucle_detect"] is raucle


def test_old_and_new_submodules_share_identity():
    """Mixed old/new imports must resolve to the SAME module objects, so class
    identity and monkeypatching behave (codex rename review)."""
    import raucle_detect.scanner

    import raucle.scanner

    assert raucle_detect.scanner is raucle.scanner
    from raucle_detect.scanner import Scanner as old_scanner

    from raucle.scanner import Scanner as new_scanner

    assert old_scanner is new_scanner


def test_legacy_env_var_fallback(monkeypatch):
    from raucle._env import env

    monkeypatch.delenv("RAUCLE_WIDGET", raising=False)
    monkeypatch.setenv("RAUCLE_DETECT_WIDGET", "legacy")
    assert env("WIDGET") == "legacy"
    monkeypatch.setenv("RAUCLE_WIDGET", "new")
    assert env("WIDGET") == "new"  # new name wins
    monkeypatch.delenv("RAUCLE_WIDGET")
    monkeypatch.delenv("RAUCLE_DETECT_WIDGET")
    assert env("WIDGET", "dflt") == "dflt"


def test_deprecated_cli_alias_warns_on_stderr(tmp_path):
    shim = tmp_path / "raucle-detect"
    shim.write_text("import sys\nfrom raucle.cli import main\nsys.exit(main(['rules', 'list']))\n")
    proc = subprocess.run(
        [sys.executable, str(shim)],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": ".", "PATH": "/usr/bin:/bin"},
        cwd=".",
    )
    assert proc.returncode == 0
    assert "deprecated" in proc.stderr


def test_stonechat_easter_egg():
    """The bird has a story; `raucle stonechat` (or `raucle bird`) tells it."""
    import contextlib
    import io

    from raucle.cli import main

    for alias in ("stonechat", "bird"):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            assert main([alias]) == 0
        out = buf.getvalue()
        assert "stonechat" in out
        assert "receipt" in out
