"""S1 acceptance: `raucle demo verify` on the shipped demo bundle.

- exits 0 on the shipped bundle, with the digest printed,
- tampered bundle exits non-zero,
- a wrong pinned digest exits non-zero even when the pack itself is intact.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from raucle.demo_bundle import bundle_digest, locate_demo_bundle

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_demo_verify(pack: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "raucle.cli", "demo", "verify", str(pack), *extra],
        capture_output=True,
        text=True,
    )


class TestDemoVerify:
    def test_shipped_bundle_verifies_with_exit_zero(self):
        result = _run_demo_verify(locate_demo_bundle())
        assert result.returncode == 0, result.stdout + result.stderr
        assert "RESULT: VERIFIED" in result.stderr

    def test_digest_is_printed_and_reproducible(self):
        result = _run_demo_verify(locate_demo_bundle())
        printed = [
            line.strip()
            for line in result.stderr.splitlines()
            if line.strip().startswith("sha256:")
        ]
        assert printed, f"no digest line printed:\n{result.stderr}"
        assert printed[-1] == bundle_digest(locate_demo_bundle())

    def test_tampered_bundle_exits_non_zero(self, tmp_path: Path):
        """Flip a byte in chain.jsonl of a COPY: integrity must catch it."""
        pack = locate_demo_bundle()
        copy = tmp_path / "demo-bundle"
        subprocess.run(["cp", "-r", str(pack), str(copy)], check=True)
        data = bytearray((copy / "chain.jsonl").read_bytes())
        data[len(data) // 2] ^= 0x01
        (copy / "chain.jsonl").write_bytes(bytes(data))

        result = _run_demo_verify(copy)
        assert result.returncode != 0
        assert "RESULT: REJECTED" in result.stderr
        assert "hash mismatch for chain.jsonl (tampered)" in result.stderr

    def test_wrong_pinned_digest_exits_non_zero(self):
        pack = locate_demo_bundle()
        result = _run_demo_verify(pack, "--pinned", "sha256:" + "0" * 64)
        assert result.returncode != 0
        assert "RESULT: REJECTED" in result.stderr

    def test_missing_bundle_errors_with_non_zero(self, tmp_path: Path):
        result = _run_demo_verify(tmp_path / "nope")
        assert result.returncode == 2

    def test_bundle_digest_stable_within_run(self):
        pack = locate_demo_bundle()
        assert bundle_digest(pack) == bundle_digest(pack)

    def test_pack_index_is_recognised_kind(self):
        from raucle.demo_bundle import pack_index_summary

        summary = pack_index_summary(locate_demo_bundle())
        assert summary["kind"] == "raucle-audit-pack/v1"
        assert int(summary["member_count"]) >= 3

    def test_ci_workflow_pins_the_published_digest(self):
        """The published value lives outside the bundle: CI pins it as a literal."""
        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
        assert "raucle demo verify" in workflow
        pinned_line = [ln for ln in workflow.splitlines() if "--pinned sha256:" in ln]
        assert len(pinned_line) == 1, pinned_line
        assert pinned_line[0].strip().split()[-1] == bundle_digest(locate_demo_bundle())
