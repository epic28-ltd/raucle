"""S1 acceptance: `raucle demo verify` on the shipped demo bundle.

- exits 0 on the shipped bundle, with the digest printed,
- tampered bundle exits non-zero,
- a wrong pinned digest exits non-zero even when the pack itself is intact.

In-process (no subprocess) so the CLI handler is credited in coverage runs;
the tamper case flips a byte in a COPY.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from raucle.cli import main
from raucle.demo_bundle import bundle_digest, locate_demo_bundle

REPO_ROOT = Path(__file__).resolve().parent.parent
PIN = "sha256:892587363d470b51d83a4cc7aca8c2155d3fe69b9fb2b95f9f839f6f935809d9"


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = main(["demo", "verify", *argv])
    out, err = capsys.readouterr()
    return code, err + out


def _independent_bundle_digest(pack_dir: Path) -> str:
    """Recompute the demo-bundle digest WITHOUT calling bundle_digest.

    Algorithm per ``raucle.demo_bundle`` docstring: sha256 over the sorted
    ``<digest>\\t<rel>`` lines of the members declared in PACK.json, plus
    PACK.json itself. Deliberately written from the spec so a tautological
    actual == actual comparison (Sonar S5863) is not needed.
    """
    index = json.loads((pack_dir / "PACK.json").read_text())
    digests = [
        (hashlib.sha256((pack_dir / m["path"]).read_bytes()).hexdigest(), m["path"])
        for m in index["members"]
    ]
    digests.append((hashlib.sha256((pack_dir / "PACK.json").read_bytes()).hexdigest(), "PACK.json"))
    payload = "\n".join(f"{d}\t{rel}" for d, rel in sorted(digests, key=lambda t: t[1])) + "\n"
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _tampered_copy(pack: Path, tmp_path: Path) -> Path:
    copy = tmp_path / "demo-bundle"
    shutil.copytree(pack, copy)
    data = bytearray((copy / "chain.jsonl").read_bytes())
    data[len(data) // 2] ^= 0x01
    (copy / "chain.jsonl").write_bytes(bytes(data))
    return copy


class TestDemoVerify:
    def test_shipped_bundle_verifies_with_exit_zero(self, capsys):
        assert locate_demo_bundle().is_dir()
        code, err = _run(capsys, str(locate_demo_bundle()))
        assert code == 0, err
        assert "RESULT: VERIFIED" in err

    def test_digest_is_printed_and_reproducible(self, capsys):
        code, err = _run(capsys, str(locate_demo_bundle()))
        assert code == 0, err
        printed = [line.strip() for line in err.splitlines() if line.strip().startswith("sha256:")]
        assert printed, f"no digest line printed:\n{err}"
        assert printed[-1] == bundle_digest(locate_demo_bundle())

    def test_tampered_bundle_exits_non_zero(self, capsys, tmp_path: Path):
        """Flip a byte in chain.jsonl of a COPY: integrity must catch it."""
        code, err = _run(capsys, str(_tampered_copy(locate_demo_bundle(), tmp_path)))
        assert code != 0
        assert "RESULT: REJECTED" in err
        assert "hash mismatch for chain.jsonl (tampered)" in err

    def test_wrong_pinned_digest_exits_non_zero(self, capsys):
        code, err = _run(capsys, str(locate_demo_bundle()), "--pinned", "sha256:" + "0" * 64)
        assert code != 0
        assert "RESULT: REJECTED" in err
        assert "published digest mismatch" in err

    def test_correct_pinned_digest_passes(self, capsys):
        code, err = _run(capsys, str(locate_demo_bundle()), "--pinned", PIN)
        assert code == 0, err
        assert "pinned published digest     PASS" in err

    def test_missing_bundle_errors_with_non_zero(self, capsys, tmp_path: Path):
        code, err = _run(capsys, str(tmp_path / "nope"))
        assert code == 2
        assert "demo verify failed" in err

    def test_directory_without_pack_json(self, capsys, tmp_path: Path):
        empty = tmp_path / "empty"
        empty.mkdir()
        code, err = _run(capsys, str(empty))
        assert code == 2

    def test_locate_falls_back_to_repo_when_cwd_has_none(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)  # tmp_path/docs/demo-bundle does not exist
        assert locate_demo_bundle().is_dir()

    def test_locate_raises_when_bundle_nowhere_to_be_found(self, tmp_path, monkeypatch):
        import raucle.demo_bundle as demo_mod

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            demo_mod, "DEMO_BUNDLE_DIRNAME", tmp_path / "nonexistent" / "bundle", raising=False
        )
        with pytest.raises(FileNotFoundError, match="demo bundle not found"):
            demo_mod.locate_demo_bundle()

    def test_bundle_digest_rejects_directory_without_pack_json(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="no PACK.json"):
            bundle_digest(tmp_path)

    def test_bundle_digest_rejects_member_without_path(self, tmp_path):
        (tmp_path / "PACK.json").write_text('{"members": [{"role": "x"}]}')
        with pytest.raises(ValueError, match="without a path"):
            bundle_digest(tmp_path)

    def test_bundle_digest_matches_independent_recomputation(self):
        pack = locate_demo_bundle()
        assert bundle_digest(pack) == _independent_bundle_digest(pack)

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
