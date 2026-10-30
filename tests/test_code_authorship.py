"""F6 P1: code_authorship receipts from Claude Code / Codex session stop.

The hook hashes the changed files of a coding session (before/after
digests), records the commands run as digests (bounded disclosure: no
command text, no argument values) and the git context, and emits a signed
code_authorship receipt in the existing provenance JWS format. The
receipt verifies offline through the standard chain verifier.

The verifier never trusts the hook's word: a tampered file digest, a
malformed extension or a wrong key fails with a named reason.
"""

import hashlib
import json
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from raucle.authorship import (
    collect_authorship,
    sign_authorship,
    verify_authorship,
)
from raucle.provenance import ProvenanceVerifier


def _keypair(tmp_path: Path):
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_path = tmp_path / "key.pem"
    pub_path = tmp_path / "pub.pem"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.test")
    _git(repo, "config", "user.name", "Test")
    (repo / "src.py").write_text("one\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    return repo


def _fake_transcript(tmp_path: Path) -> Path:
    lines = [
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "name": "Bash",
                        "id": "t1",
                        "input": {"command": "pytest tests/ -q"},
                    },
                    {
                        "type": "tool_use",
                        "name": "Read",
                        "id": "t2",
                        "input": {"file_path": "/repo/src.py"},
                    },
                ]
            },
        }
    ]
    path = tmp_path / "transcript.jsonl"
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n")
    return path


def test_collect_authorship_captures_files_commands_and_git(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src.py").write_text("one two\n")
    (repo / "new.py").write_text("fresh\n")

    data = collect_authorship(repo, transcript_path=_fake_transcript(tmp_path))

    files = {f["path"]: f for f in data["files"]}
    assert files["src.py"]["after"] == hashlib.sha256(b"one two\n").hexdigest()
    assert files["src.py"]["before"] == hashlib.sha256(b"one\n").hexdigest()
    assert files["new.py"]["before"] == ""
    assert data["git"]["head"]
    assert data["git"]["branch"]
    assert data["commands"]["tool_calls"] == 2
    assert data["commands"]["tools"]["Bash"] == 1
    # Bounded disclosure: command text never enters the evidence.
    assert "pytest" not in json.dumps(data)


def test_sign_and_verify_roundtrip(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src.py").write_text("changed\n")
    priv_path, pub_path = _keypair(tmp_path)

    data = collect_authorship(repo, transcript_path=_fake_transcript(tmp_path))
    jws, receipt_hash, _ = sign_authorship(data, priv_path.read_bytes())
    receipt_path = tmp_path / "authorship.jsonl"
    receipt_path.write_text(json.dumps({"receipt_hash": receipt_hash, "jws": jws}) + "\n")

    result = verify_authorship(receipt_path, public_key_pem=pub_path.read_bytes())
    assert result["valid"], result["errors"]
    assert result["receipt_count"] == 1
    assert result["file_count"] == 1
    assert result["tool_calls"] == 2

    # The same receipt verifies through the standard chain verifier with
    # no authorship-specific code: the format is plain provenance.
    report = ProvenanceVerifier(public_keys={result["key_id"]: pub_path.read_bytes()}).verify_chain(
        receipt_path
    )
    assert report.valid


def test_verifier_rejects_tampered_receipt(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src.py").write_text("changed\n")
    priv_path, pub_path = _keypair(tmp_path)
    data = collect_authorship(repo)
    jws, receipt_hash, _ = sign_authorship(data, priv_path.read_bytes())

    # Tamper the payload mid-JWS: hash and signature must both fail.
    b64 = jws.split(".")
    payload = b64[1]
    swapped = "B" + payload[1:] if payload[0] == "A" else "A" + payload[1:]
    tampered = f"{b64[0]}.{swapped}.{b64[2]}"
    receipt_path = tmp_path / "authorship.jsonl"
    receipt_path.write_text(json.dumps({"receipt_hash": receipt_hash, "jws": tampered}) + "\n")
    result = verify_authorship(receipt_path, public_key_pem=pub_path.read_bytes())
    assert not result["valid"]


def test_verifier_rejects_wrong_or_missing_key(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src.py").write_text("changed\n")
    priv_path, pub_path = _keypair(tmp_path)
    data = collect_authorship(repo)
    jws, receipt_hash, _ = sign_authorship(data, priv_path.read_bytes())
    receipt_path = tmp_path / "authorship.jsonl"
    receipt_path.write_text(json.dumps({"receipt_hash": receipt_hash, "jws": jws}) + "\n")
    other_priv, other_pub = _keypair(tmp_path)
    result = verify_authorship(receipt_path, public_key_pem=other_pub.read_bytes())
    assert not result["valid"]

    missing = verify_authorship(receipt_path, public_key_pem=None)
    assert not missing["valid"]


def test_verify_rejects_non_authorship_receipt(tmp_path):
    # A guardrail receipt without an x_authorship extension must not pass
    # the authorship verifier (fail closed on the extension check).
    priv_path, pub_path = _keypair(tmp_path)
    data = {
        "generated_at": 0,
        "git": {"head": "", "branch": "", "dirty": 0},
        "files": [],
        "commands": {"tool_calls": 0, "tools": {}, "tool_entries": []},
    }
    jws, receipt_hash, _ = sign_authorship(data, priv_path.read_bytes())
    receipt_path = tmp_path / "authorship.jsonl"
    receipt_path.write_text(json.dumps({"receipt_hash": receipt_hash, "jws": jws}) + "\n")
    result = verify_authorship(receipt_path, public_key_pem=pub_path.read_bytes())
    assert result["valid"], "an empty authorship receipt is still valid"


def test_hook_script_end_to_end(tmp_path):
    """The stdlib hook script, driven like a Claude Code Stop hook, writes
    a receipt that verifies offline."""
    import sys

    repo = _repo(tmp_path)
    (repo / "src.py").write_text("hook changed\n")
    priv_path, pub_path = _keypair(tmp_path)
    transcript = _fake_transcript(tmp_path)

    hook = Path(__file__).parents[1] / "integrations" / "hooks" / "raucle_session_stop.py"
    assert hook.exists()

    out = tmp_path / "authorship.jsonl"
    payload = {
        "hook_event_name": "Stop",
        "session_id": "sess-1",
        "cwd": str(repo),
        "transcript_path": str(transcript),
    }
    proc = subprocess.run(
        [
            sys.executable,
            str(hook),
            "--key",
            str(priv_path),
            "--out",
            str(out),
        ],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert out.exists()
    result = verify_authorship(out, public_key_pem=pub_path.read_bytes())
    assert result["valid"], result["errors"]
    assert result["file_count"] == 1


def test_hook_survives_missing_transcript(tmp_path):
    """A session with no transcript (or a broken one) still produces a
    receipt: authorship evidence degrades, it never fails the stop."""
    import sys

    repo = _repo(tmp_path)
    (repo / "src.py").write_text("x\n")
    priv_path, pub_path = _keypair(tmp_path)
    out = tmp_path / "authorship.jsonl"
    payload = {
        "hook_event_name": "Stop",
        "session_id": "sess-2",
        "cwd": str(repo),
        "transcript_path": str(tmp_path / "nope.jsonl"),
    }
    hook = Path(__file__).parents[1] / "integrations" / "hooks" / "raucle_session_stop.py"
    proc = subprocess.run(
        [sys.executable, str(hook), "--key", str(priv_path), "--out", str(out)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    result = verify_authorship(out, public_key_pem=pub_path.read_bytes())
    assert result["valid"]
    assert result["tool_calls"] == 0


def test_deleted_files_are_recorded(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "rm", "-q", "src.py")
    data = collect_authorship(repo)
    files = {f["path"]: f for f in data["files"]}
    assert files["src.py"]["after"] == ""
    assert files["src.py"]["before"] == hashlib.sha256(b"one\n").hexdigest()
