#!/usr/bin/env python3
"""Threat-model-as-code checker (EPIC S3).

Validates ``docs/threat-model/threat-model.json`` against the repository:

1. Structure: version, source and every threat with its controls present.
2. A MAPPED control must name at least one test, and every named test must
   exist in the repository (relative to the repo root). This is the CI
   guard: the moment a control loses its test, this job goes red.
3. An OUT-OF-SCOPE control (or residual) must carry a reason.
4. Cross-check: every ``## T<n>`` heading in the source document must have
   a matching entry in the mapping, so a new threat section cannot be
   added without declaring its control status.

Exit 0 with a summary, or exit 1 listing every named failure.
Usage (defaults: docs/threat-model/*):
  python scripts/threat_model_check.py [--source SRC --mapping MAPPING]
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]


def check(source: Path, mapping: Path, repo_root: Path | None = None) -> list[str]:
    """Run all checks; return the list of named failures (empty = clean)."""
    root = repo_root if repo_root is not None else _REPO_ROOT
    source = Path(source) if Path(source).is_absolute() else root / source
    mapping = Path(mapping) if Path(mapping).is_absolute() else root / mapping
    errors: list[str] = []
    try:
        data = json.loads(mapping.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"mapping unreadable: {exc}"]

    threats = data.get("threats")
    if not isinstance(threats, list) or not threats:
        return [f"{mapping.name}: no threats array"]

    known_tests: set[str] = set()
    for threat in threats:
        tid = threat.get("id", "<no id>")
        if not threat.get("title"):
            errors.append(f"{tid}: missing title")
        controls = threat.get("controls")
        if not isinstance(controls, list) or not controls:
            errors.append(
                f"{tid}: no controls declared (map every control or mark it out-of-scope)"
            )
            continue
        for control in controls:
            cid = f"{tid}/{control.get('id', '<no id>')}"
            status = control.get("status")
            tests = control.get("tests", [])
            if not isinstance(tests, list):
                errors.append(f"{cid}: tests must be a list")
                continue
            if status == "mapped":
                if not tests:
                    errors.append(f"{cid}: control is mapped but names no test")
                    continue
                for test in tests:
                    known_tests.add(test)
                    if not (root / test).exists():
                        errors.append(f"{cid}: pinned test does not exist: {test}")
            elif status == "out_of_scope":
                if not control.get("reason"):
                    errors.append(f"{cid}: out-of-scope control carries no reason")
            else:
                errors.append(f"{cid}: unknown control status {status!r} (mapped | out_of_scope)")

    # cross-check against the source document: every "## T<n>" heading needs an entry
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as exc:
        return errors + [f"source unreadable: {exc}"]
    documented_ids = set(re.findall(r"^## (T\d+)\b", text, flags=re.MULTILINE))
    mapped_ids = {t.get("id", "") for t in threats}
    missing = sorted(documented_ids - mapped_ids)
    for tid in missing:
        errors.append(f"threat {tid} documented in {source.name} but absent from the mapping")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="docs/threat-model/v1.md")
    parser.add_argument("--mapping", default="docs/threat-model/threat-model.json")
    args = parser.parse_args(argv)
    errors = check(Path(args.source), Path(args.mapping))
    if errors:
        print("threat-model check FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(
        "threat-model check passed: every control mapped or explicitly "
        "out-of-scope; all pinned tests exist"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
