"""Generate the standards/ vector conformance data (S4).

Run from the repo root:
    PYTHONPATH=. python scripts/gen_conformance_data.py           # write
    PYTHONPATH=. python scripts/gen_conformance_data.py --check   # CI gate

Generates ``docs/spec/conformance/conformance.json`` — a machine-checkable
record of which published vector suites (standards/ and docs/spec/provenance/)
currently pass against this build. The committed file is BUILD-PINNED: CI
re-runs this generator and requires byte-equality with the committed file, so
any change to the vectors, the reference implementation, or the suite list must
update the file (and its digest) in a reviewable commit.

The gateway serves this file verbatim at ``/.well-known/raucle-conformance``;
the schema lives at ``docs/spec/conformance/raucle-conformance-v1.schema.json``.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = REPO_ROOT / "docs" / "spec" / "conformance" / "conformance.json"

SCHEMA_VERSION = "raucle-conformance/v1"

# (id, title, pytest target, vector count source)
SUITES = [
    (
        "provenance-receipt-v1",
        "Raucle Provenance Receipt v1 canonical vectors (docs/spec/provenance/v1)",
        "tests/test_spec_conformance.py",
        0,  # counted from the vectors file
    ),
    (
        "nelson14-delegation-gate",
        "Nelson14 delegation-gate escalation vectors",
        "tests/nelson14_vectors.py",
        0,  # counted from collected tests
    ),
    (
        "epaec-v1",
        "EPAEC v1 end-to-end conformance vectors (tests/vectors/epaec-v1.json)",
        "tests/test_epaec_vectors.py",
        0,
    ),
    (
        "eqr-v1",
        "Evidence-Quality Rank (eqr:v1) vectors (standards/test-vectors)",
        "tests/test_eqr_gate.py",
        0,
    ),
    (
        "dataflow-v1",
        "Data-flow taint deny vectors (standards/test-vectors)",
        "tests/test_dataflow_rules.py",
        0,
    ),
]


def _count_vectors(suite_id: str) -> int | None:
    """Best-effort published-vector count (None = count not file-derived)."""
    if suite_id == "provenance-receipt-v1":
        path = REPO_ROOT / "docs" / "spec" / "provenance" / "v1" / "test-vectors.json"
        if path.is_file():
            return len(json.loads(path.read_text()).get("vectors", []))
        return None
    return None


def _run_suite(target: str) -> bool:
    import pytest

    exit_code: int | object = pytest.main(
        ["-x", "-q", "--no-header", "-p", "no:cacheprovider", str(REPO_ROOT / target)]
    )
    return int(exit_code) == 0  # type: ignore[arg-type]


def generate() -> dict[str, object]:
    import raucle

    results: list[dict[str, object]] = []
    for suite_id, title, target, _ in SUITES:
        passed = _run_suite(target)
        results.append(
            {
                "id": suite_id,
                "title": title,
                "source": target,
                "vectors": _count_vectors(suite_id),
                "passed": passed,
            }
        )
    data: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": raucle.__version__,
        "all_passed": all(bool(r["passed"]) for r in results),
        "suites": results,
    }
    canonical = json.dumps(data, indent=2, sort_keys=True)
    data["data_digest"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return data


def render(data: dict[str, object]) -> str:
    body = {k: v for k, v in data.items() if k != "data_digest"}
    canonical = json.dumps(body, indent=2, sort_keys=True)
    digest = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    data["data_digest"] = digest
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def main() -> int:
    data = generate()
    text = render(data)
    if "--check" in sys.argv[1:]:
        committed = OUT_PATH.read_text()
        if committed != text:
            print(
                "conformance data drift: committed docs/spec/conformance/conformance.json "
                "differs from a fresh generation. If intentional, regenerate and commit:\n"
                "  PYTHONPATH=. python scripts/gen_conformance_data.py",
                file=sys.stderr,
            )
            return 1
        print(f"✓ conformance data matches (digest {data['data_digest']})")
        return 0
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(text)
    print(f"wrote {OUT_PATH.relative_to(REPO_ROOT)} (digest {data['data_digest']})")
    suites = data["suites"]  # type: ignore
    failed = [r["id"] for r in suites if not r["passed"]]
    if failed:
        print(f"warning: suites failing: {failed}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
