#!/usr/bin/env python3
"""Regenerate assets/verifier/ASSET-HASHES.json over the X2 verifier assets.

Hash-pins every shipped verifier asset (the single-file page and the committed
fixture pack). tests/test_x2_verifier.py fails when a file drifts from this
manifest; run this script after deliberately updating an asset.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets" / "verifier"
MANIFEST = ASSETS / "ASSET-HASHES.json"


def digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    files = sorted(p for p in ASSETS.rglob("*") if p.is_file() and p.name != "ASSET-HASHES.json")
    manifest = {
        "_comment": (
            "sha256 pins for the X2 offline verifier page and its committed "
            "fixture pack; enforced by tests/test_x2_verifier.py. Regenerate "
            "with scripts/x2_asset_hashes.py after a deliberate asset change."
        ),
        "assets": {str(p.relative_to(ASSETS)): digest(p) for p in files},
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    for name in manifest["assets"]:
        print(f"{manifest['assets'][name]}  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
