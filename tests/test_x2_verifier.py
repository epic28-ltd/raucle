"""X2 slice 1: static offline verifier page.

Three gates:

1. **No-network** — the shipped page performs no network I/O: static analysis
   asserts the HTML contains no network-capable API literals and no absolute
   URLs, so nothing can dial out after load.
2. **Hash-pinned assets** — every file under assets/verifier/ must match
   assets/verifier/ASSET-HASHES.json (regenerate with scripts/x2_asset_hashes.py).
3. **Offline acceptance** — the node harness (tests/verifier_harness/x2_harness.mjs)
   runs the page's own verifier core against the committed fixture pack:
   named-clean must verify, and each doctored variant must deny with a named
   reason. Skips when node is unavailable (CI ships node).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets" / "verifier"
PAGE = ASSETS / "x2-verifier.html"
MANIFEST = ASSETS / "ASSET-HASHES.json"

# Network-capable surface: none of these tokens may appear anywhere in the
# shipped page (comments included — a future editor must not be able to
# mention dials without the test catching the dial itself).
FORBIDDEN_LITERALS = (
    "fetch",
    "XMLHttpRequest",
    "WebSocket",
    "EventSource",
    "sendBeacon",
    "navigator.",
    "importScripts",
    "http://",
    "https://",
    "<iframe",
    "<link",
    "@import",
)


def _script_blocks(html: str) -> list[str]:
    return re.findall(r"<script[^>]*>(.*?)</script>", html, flags=re.S)


def test_no_network_literals_in_shipped_page() -> None:
    html = PAGE.read_text(encoding="utf-8")
    low = html
    hits = [lit for lit in FORBIDDEN_LITERALS if lit in low]
    assert not hits, f"network-capable literal(s) in shipped verifier page: {hits}"
    # nothing is loaded from any origin: only the two inline scripts exist
    assert len(_script_blocks(html)) == 2
    assert 'src="' not in html and "href=" not in html.replace("</a>", "")


def _sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def test_vendored_assets_match_hash_manifest() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))["assets"]
    actual = {
        str(p.relative_to(ASSETS)): _sha256_hex(p.read_bytes())
        for p in ASSETS.rglob("*")
        if p.is_file() and p.name != "ASSET-HASHES.json"
    }
    assert actual == manifest, (
        "asset bytes drifted from ASSET-HASHES.json; regenerate with "
        "scripts/x2_asset_hashes.py after a deliberate change"
    )


def test_fixture_pack_verifies_in_python_fixtures_are_current() -> None:
    """The committed fixture must be named-clean under the real verifier —
    the node harness then proves the BROWSER implementation agrees."""
    from raucle.audit_pack import verify_pack

    v = verify_pack(ASSETS / "fixtures" / "fixture-pack")
    assert v.ok, v.reasons
    assert v.receipt_count == 2


def _node_available() -> bool:
    return shutil.which("node") is not None


@pytest.mark.skipif(not _node_available(), reason="node unavailable")
def test_node_harness_verifies_fixture_and_tamper_cases() -> None:
    html = PAGE.read_text(encoding="utf-8")
    # browser's own parse gate first: every shipped script block must parse
    for i, block in enumerate(_script_blocks(html)):
        script = ROOT / ".cache" / "scratch" / f"x2_block_{i}.js"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(block, encoding="utf-8")
        try:
            r = subprocess.run(
                ["node", "--check", str(script)], capture_output=True, text=True, check=False
            )
        finally:
            script.unlink(missing_ok=True)
        assert r.returncode == 0, f"script block {i} does not parse: {r.stderr}"

    r = subprocess.run(
        ["node", str(ROOT / "tests" / "verifier_harness" / "x2_harness.mjs"), str(ROOT)],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    out = r.stdout.strip()
    assert r.returncode == 0, f"harness failed:\n{r.stdout}\n{r.stderr}"
    verdict = json.loads(out.splitlines()[0] and out) if out else {}
    assert verdict.get("ok") is True, out
