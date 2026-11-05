#!/usr/bin/env python3
"""Cross-language CANONICALISATION conformance for Raucle Provenance Receipt v1.

Complements reference/conformance.py (which proves receipt byte-identity). This
harness drives each implementation's *canonical-JSON encoder directly* and
asserts, for the published canonicalization_vectors, that all five produce the
exact same UTF-8 bytes AND that those bytes match the published
expected_canonical_hex; for the published invalid_canonicalization_vectors, that
every implementation REJECTS them.

Its reason to exist: the receipt vectors only use ASCII/BMP object keys, so they
cannot catch the non-BMP key-ordering trap (Unicode code point vs UTF-16 code
unit — §4.3.1). A naive code-point sort (Python sort_keys, Go sort.Strings, Rust
str Ord) diverges from JavaScript / .NET ordinal ordering for astral keys. This
harness exercises exactly that case and fails loudly if any port drifts.

Each port exposes a `--canon` stdin mode: read {"obj": <value>} lines, write
{"hex": "<utf8 hex of canonical bytes>"} lines (and reject invalid material with
a non-zero exit). Python is driven in-process.

Usage:  python reference/canon_conformance.py
Exit 0 on full agreement, non-zero otherwise.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REF = ROOT / "reference"
VECTORS = ROOT / "docs" / "spec" / "provenance" / "v1" / "test-vectors.json"

# Make the Python reference importable when run as `python reference/...`
# from a fresh checkout (no PYTHONPATH required).
sys.path.insert(0, str(ROOT))


def _run_lines(cmd: list[str], cwd: Path, reqs: list[dict]) -> list[dict]:
    stdin = "\n".join(json.dumps(r) for r in reqs) + "\n"
    proc = subprocess.run(cmd, cwd=cwd, input=stdin, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{cmd}: {proc.stderr.strip()}")
    return [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]


def _rejects(cmd: list[str], cwd: Path, obj) -> bool:
    """True ONLY if the canonical encoder genuinely REJECTS `obj` — i.e. exits
    non-zero. A clean (exit 0) run is treated as acceptance regardless of
    output: emitting a hex line clearly accepted invalid input, and a clean run
    with NO output is a silent/broken port that must NOT be scored as a reject
    (otherwise an encoder that does nothing would pass the invalid-vector
    check). Both cases therefore fail the contract. Used for the
    invalid_canonicalization_vectors (floats / out-of-range integers)."""
    stdin = json.dumps({"obj": obj}) + "\n"
    proc = subprocess.run(cmd, cwd=cwd, input=stdin, capture_output=True, text=True)
    return proc.returncode != 0


def _build(lang: str) -> None:
    """Compile the ports that need an explicit build step before --canon runs."""
    if lang == "rust":
        subprocess.run(
            ["cargo", "build", "--quiet", "--example", "emit"],
            cwd=REF / "provenance-rs",
            check=True,
            capture_output=True,
            text=True,
        )
    elif lang == "csharp":
        subprocess.run(
            ["dotnet", "build", "--nologo", "-v", "q", "interop/Interop.csproj"],
            cwd=REF / "provenance-cs",
            check=True,
            capture_output=True,
            text=True,
        )


# Per-language --canon invocation: (argv, cwd). Python is handled in-process.
CANON_CMD = {
    "go": (["go", "run", "./cmd/emit", "--canon"], REF / "provenance-go"),
    "rust": (
        ["cargo", "run", "--quiet", "--example", "emit", "--", "--canon"],
        REF / "provenance-rs",
    ),
    "typescript": (
        ["npx", "--no-install", "tsx", "src/emit-cli.ts", "--canon"],
        REF / "provenance-ts",
    ),
    "csharp": (
        ["dotnet", "run", "--no-build", "--project", "interop/Interop.csproj", "--", "--canon"],
        REF / "provenance-cs",
    ),
}

LANGS = [
    ("python", lambda: True),
    ("go", lambda: shutil.which("go")),
    ("rust", lambda: shutil.which("cargo")),
    ("typescript", lambda: shutil.which("npx")),
    ("csharp", lambda: shutil.which("dotnet")),
]


def _hexes(lang: str, reqs: list[dict]) -> list[str]:
    if lang == "python":
        from raucle.provenance import _canonical_json

        return [_canonical_json(r["obj"]).hex() for r in reqs]
    cmd, cwd = CANON_CMD[lang]
    return [row["hex"] for row in _run_lines(cmd, cwd, reqs)]


def _rejects_lang(lang: str, obj) -> bool:
    if lang == "python":
        from raucle.provenance import _canonical_json

        try:
            _canonical_json(obj)
            return False
        except Exception:
            return True
    cmd, cwd = CANON_CMD[lang]
    return _rejects(cmd, cwd, obj)


def main() -> int:
    vf = json.loads(VECTORS.read_text())
    published = vf.get("canonicalization_vectors", [])
    invalid = vf.get("invalid_canonicalization_vectors", [])

    # Extra string-valued probes for the key-ordering property (value-
    # independent), kept alongside the published vectors. The empty-looking
    # key in the first probe is U+E000 (BMP private-use): code point orders it
    # before the non-BMP key, UTF-16 orders the non-BMP key first.
    probes = [
        {"name": "probe_non_bmp_key_ordering", "obj": {"a": "x", "\U0001f511": "y", "": "z"}},
        {
            "name": "probe_non_bmp_keys_only",
            "obj": {"\U0001f600": "a", "￿": "b", "\U00010000": "c"},
        },
    ]
    # Valid-vector requests: every published canon vector (with its expected
    # hex) plus the probes (cross-lang agreement only, no published hex).
    valid = [
        {"name": v["name"], "obj": v["input_object"], "expected_hex": v["expected_canonical_hex"]}
        for v in published
    ] + probes

    all_langs = [l for l, _ in LANGS]
    ran, skipped = [], []
    for lang, avail in LANGS:
        if not avail():
            print(f"SKIP {lang} (toolchain not found)")
            skipped.append(lang)
            continue
        try:
            _build(lang)
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL {lang} build: {exc}")
            return 2
        ran.append(lang)

    ok = True
    hexes_by_lang: dict[str, list[str]] = {}
    for lang in ran:
        try:
            hexes_by_lang[lang] = _hexes(lang, valid)
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL {lang} canon: {exc}")
            return 2

    print("\n=== valid vectors: cross-language agreement + published-hex match ===")
    for i, req in enumerate(valid):
        hexes = {lang: hexes_by_lang[lang][i] for lang in ran}
        uniq = set(hexes.values())
        agree = len(uniq) == 1
        exp = req.get("expected_hex")
        hex_ok = (exp is None) or all(h == exp for h in hexes.values())
        status = "AGREE" if agree else "DIVERGE"
        if exp is not None:
            status += " + HEX-OK" if hex_ok else " + HEX-MISMATCH"
        ok = ok and agree and hex_ok
        print(f"  {req['name']}: {status}")
        if not agree:
            for lang, h in hexes.items():
                print(f"      {lang}: {h}")
        if exp is not None and not hex_ok:
            print(f"      expected: {exp}")

    print("\n=== invalid vectors: every language MUST reject ===")
    for v in invalid:
        verdicts = {lang: _rejects_lang(lang, v["input_object"]) for lang in ran}
        all_reject = all(verdicts.values())
        ok = ok and all_reject
        print(f"  {v['name']}: {'ALL-REJECT' if all_reject else 'NOT-REJECTED'}")
        if not all_reject:
            for lang, rej in verdicts.items():
                if not rej:
                    print(f"      {lang}: ACCEPTED (must reject)")

    n_ran, n_total = len(ran), len(all_langs)
    print()
    if not ok:
        print("RESULT: FAIL — canonicalisation drift / hex mismatch / invalid accepted")
        return 1
    if n_ran < n_total:
        print(
            f"RESULT: PASS ({n_ran}/{n_total}: {', '.join(ran)}) — agree for languages "
            f"that ran; SKIPPED: {', '.join(skipped)}. Full parity NOT proven."
        )
        return 3
    print(
        f"RESULT: PASS — {n_total}-language canonicalisation parity proven "
        f"(published vectors + non-BMP probes + invalid-rejection)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
