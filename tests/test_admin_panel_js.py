"""The admin panel HTML must ship JavaScript that actually parses.

Chromium discards an entire script block when any statement fails to parse,
which left every inline handler (enterDemo among them) undefined and the
"View Demo" button dead. Regression: the receipt-table builder emitted
showAncestry(\\'', an escaped quote followed by a stray closing quote, so the
outer JS string terminated mid-expression. v0.23.0 regression (ancestry link).

Guards:
- the builder carries the hash in a data attribute (no quote conflicts), and
- if node is available, the whole shipped script block must pass a V8 parse.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from raucle.gateway_app import ADMIN_PANEL_HTML


def test_receipt_rows_carry_hash_in_data_attribute() -> None:
    assert 'data-hash="' + "'+r.receipt_hash+'" in ADMIN_PANEL_HTML


def test_broken_showAncestry_onclick_escape_is_gone() -> None:
    # the faulty pattern: escaped quote followed by a stray terminator quote
    assert "showAncestry(\\''" not in ADMIN_PANEL_HTML
    # the onclick no longer embeds the hash through quote mazes
    assert "showAncestry('" not in ADMIN_PANEL_HTML


def test_row_click_delegation_is_registered_once() -> None:
    assert ADMIN_PANEL_HTML.count("rcptRowClick") == 2  # listener fn + attach


def test_login_field_canvas_present_and_reduced_motion_safe() -> None:
    assert 'id="field"' in ADMIN_PANEL_HTML
    assert "pointer-events: none" in ADMIN_PANEL_HTML
    assert "prefers-reduced-motion: reduce" in ADMIN_PANEL_HTML
    assert "document.hidden" in ADMIN_PANEL_HTML


def test_field_is_login_screen_only() -> None:
    assert "field.classList.toggle" in ADMIN_PANEL_HTML
    # the observer watches the login card visibility, with no legend/hud
    assert "getElem'+'entById" not in ADMIN_PANEL_HTML


def test_field_is_pure_greyscale() -> None:
    i = ADMIN_PANEL_HTML.find("/* --- ambient ledger field")
    j = ADMIN_PANEL_HTML.find("})();", i)
    field_js = ADMIN_PANEL_HTML[i:j]
    for tone in ("#16a34a", "#dd2f45", "#d97706", "22,163,74", "221,47,69", "217,119,6"):
        assert tone not in field_js


def _extract_script_blocks(html: str) -> list[str]:
    return [b for b in re.findall(r"<script[^>]*>(.*?)</script>", html, re.S) if b.strip()]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_shipped_script_parses_under_v8() -> None:
    blocks = _extract_script_blocks(ADMIN_PANEL_HTML)
    assert blocks, "panel must ship its script inline"
    with tempfile.TemporaryDirectory() as td:
        for i, block in enumerate(blocks):
            path = Path(td) / f"script{i:02}.js"
            path.write_text(block)
            proc = subprocess.run(
                ["node", "--check", str(path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert proc.returncode == 0, (
                f"script block {i} fails to parse: {(proc.stderr or proc.stdout).strip()[-300:]}"
            )
