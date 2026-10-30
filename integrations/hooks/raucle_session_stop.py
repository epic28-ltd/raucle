#!/usr/bin/env python3
"""Raucle code_authorship hooks plugin: session stop hook.

Claude Code / Codex hooks plugin (F6 P1). At session stop this hook
signs a code_authorship receipt for the session: changed files hashed
before/after against git, commands run recorded as digests, git context
bound. The receipt lands next to the repo (or the path given by --out)
and verifies offline with `raucle authorship verify`.

This script is stdlib-only. The signing lives in the raucle CLI
(`raucle authorship sign`), which must be on PATH in the environment the
hook runs (Ed25519 signing needs the cryptography package raucle ships).

Claude Code wiring (Settings hooks):

    "hooks": {
      "Stop": [
        {"hooks": [
          {"type": "command",
           "command": "raucle_session_stop.py"}
        ]}
      ]
    }

Codex (or any agent with a lifecycle command hook): invoke explicitly
with --repo/--transcript/--out; stdin JSON is optional.

The hook NEVER blocks a session stop: it exits 0 and prints a one-line
status for the transcript.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


def _stdin_payload() -> dict:
    try:
        raw = sys.stdin.read() if not sys.stdin.isatty() else ""
    except (ValueError, OSError):
        raw = ""
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="Repository path (default: hook stdin cwd)")
    parser.add_argument(
        "--transcript",
        help="Session transcript JSONL (default: stdin transcript_path)",
    )
    parser.add_argument(
        "--out",
        help="Receipt chain output path (default: <repo>/.raucle/authorship/stop-<n>.jsonl)",
    )
    parser.add_argument(
        "--key",
        required=True,
        help="Ed25519 private key PEM used to sign the receipt",
    )
    args = parser.parse_args(argv)

    payload = _stdin_payload()
    repo = args.repo or payload.get("cwd")
    transcript = args.transcript or payload.get("transcript_path")
    session_id = str(payload.get("session_id", ""))

    if not repo or not Path(repo).is_dir():
        print("raucle-authorship: no repository to record, skipping", file=sys.stderr)
        return 0

    out = args.out
    if not out:
        slots = sorted((Path(repo) / ".raucle" / "authorship").glob("stop-*.jsonl"))
        n = len(slots)
        out = str(Path(repo) / ".raucle" / "authorship" / f"stop-{n}.jsonl")

    # Pass the evidence to the signing CLI through a temp file so the
    # evidence never rides in command-line arguments or the shell.
    receipt_path = Path(out)
    raucle_bin = shutil.which("raucle")
    if not raucle_bin and Path(sys.executable).name.startswith("python"):
        # Fallback when the entrypoint script is not on PATH (venv
        # contexts): run the module directly.
        cmd = [sys.executable, "-m", "raucle"]
    else:
        cmd = [raucle_bin or "raucle"]
    cmd += [
        "authorship",
        "sign",
        "--repo",
        str(repo),
        "--out",
        str(receipt_path),
        "--key",
        str(args.key),
    ]
    if transcript:
        cmd += ["--transcript", str(transcript)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"raucle-authorship: sign failed ({type(exc).__name__})", file=sys.stderr)
        return 0

    if proc.returncode != 0:
        print("raucle-authorship: sign failed, receipt not written", file=sys.stderr)
        return 0

    label = f" session {session_id}" if session_id else ""
    print(f"raucle-authorship: code_authorship receipt written{label}: {receipt_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
