"""F6 P1: code_authorship receipts from coding-agent session stop.

A Claude Code / Codex hooks plugin signs a code_authorship receipt at
session stop: the changed files of the session are hashed (before/after
digests against git), the commands run are recorded as digests only
(bounded disclosure: no command text, no argument values) and the git
context is bound. The receipt uses the existing provenance JWS format
(same shape as the x_compliance certificate, see raucle/compliance_pack)
so it verifies offline through the standard chain verifier.

Boundary: the format and the offline verifier are public OSS; the hook
runs entirely on the developer's machine and nothing is sent anywhere.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any

from raucle.provenance import ProvenanceVerifier

HASH_PREFIX = "sha256:"
RECEIPT_TYP = "provenance-receipt/v1"
RECEIPT_CRIT = "raucle/v1"

#: Evidence caps. A session that exceeds these still receipts, with the
#: surplus counted rather than stored (bounded disclosure, bounded size).
MAX_FILES = 500
MAX_TOOL_CALLS = 2000
_HEX = set("0123456789abcdef")


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_digest_hex(value: Any) -> bool:
    """sha256 (64-hex) or git object id (40-hex sha1), or empty string."""
    if not isinstance(value, str):
        return False
    return (
        value == ""
        or (len(value) == 64 and set(value) <= _HEX)
        or (len(value) == 40 and set(value) <= _HEX)
    )


def _git(repo: Path, *args: str) -> str:
    """Run git in the repo, returning stdout or '' on any failure.

    The hook must degrade, never fail the session stop.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout


def collect_authorship(
    repo: str | Path, *, transcript_path: str | Path | None = None
) -> dict[str, Any]:
    """Collect the authorship evidence for a coding session.

    Returns a plain dict (the x_authorship payload) with:
    - git context: head, branch, count of dirty/staged paths
    - files: changed paths with before/after sha256 digests ('' when the
      file is new, deleted, or unreadable; the status letter explains)
    - commands: tool call count, per-tool counts and per-call digests

    Paths and digests are recorded; command text and argument values are
    never recorded (bounded disclosure). Caps apply: more than
    MAX_FILES / MAX_TOOL_CALLS entries are counted, not stored.
    """
    repo = Path(repo).resolve()
    changed = _changed_files(repo)
    files: list[dict[str, Any]] = []
    for path, status in changed:
        if len(files) < MAX_FILES:
            entry = {
                "path": path,
                "status": status,
                "before": _head_blob_digest(repo, path),
                "after": _worktree_digest(repo / path),
            }
            files.append(entry)
    commands = _collect_commands(Path(transcript_path) if transcript_path else None)
    return {
        "git": {
            "head": _git(repo, "rev-parse", "HEAD").strip(),
            "branch": _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip(),
            "dirty": len(changed),
        },
        "files": files,
        "commands": commands,
    }


def _changed_files(repo: Path) -> list[tuple[str, str]]:
    out = _git(repo, "status", "--porcelain=v1", "-z")
    if not out:
        return []
    entries: list[tuple[str, str]] = []
    for token in out.split("\x00"):
        if len(token) < 4 or not token.strip():
            continue
        status_field = token[:2]
        path = token[3:]
        # Rename entries carry the original path after an embedded NUL,
        # which already split off into other tokens; the new path is
        # what HEAD/worktree hashing needs.
        entries.append((path.strip(), (status_field.strip() or "M")[:1]))
    return entries[: MAX_FILES + 1]


def _head_blob_digest(repo: Path, path: str) -> str:
    """sha256 of the file's blob at HEAD, or '' when absent at HEAD."""
    raw = _git_bytes(repo, ["show", f"HEAD:{path}"])
    if raw is None:
        return ""
    return _sha256_hex(raw)


def _git_bytes(repo: Path, args: list[str]) -> bytes | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout


def _worktree_digest(path: Path) -> str:
    try:
        return _sha256_hex(path.read_bytes())
    except OSError:
        return ""


def _collect_commands(transcript_path: Path | None) -> dict[str, Any]:
    """Extract tool-call evidence from a Claude Code transcript JSONL.

    Transcripts are agent-specific and freeform; anything unparseable is
    skipped, so evidence degrades instead of failing. Only the tool name
    and a digest of the arguments are kept.
    """
    tool_calls: list[dict[str, str]] = []
    tools: dict[str, int] = {}
    for line in _transcript_lines(transcript_path)[:8000]:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        for item in _tool_use_items(record):
            _record_tool_use(item, tool_calls, tools)
    return {"tool_calls": len(tool_calls), "tools": tools, "tool_entries": tool_calls}


def _transcript_lines(transcript_path: Path | None) -> list[str]:
    """Invariant: the transcript read never fails the session stop: a
    missing or unreadable transcript yields no lines instead of raising,
    so evidence degrades rather than blocking the receipt."""
    if transcript_path is None or not transcript_path.is_file():
        return []
    try:
        return transcript_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _tool_use_items(record: Any) -> list[dict[str, Any]]:
    """Invariant: only content items that are well-formed tool_use blocks
    with a string tool name become evidence; every other transcript shape
    yields nothing (freeform transcripts degrade, never fail)."""
    if not isinstance(record, dict):
        return []
    message = record.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, list):
        return []
    items: list[dict[str, Any]] = []
    for item in content:
        if _is_tool_use(item):
            items.append(item)
    return items


def _is_tool_use(item: Any) -> bool:
    """Invariant: a recorded tool call always names its tool (string); the
    input block may be anything, it is digested and never read."""
    return (
        isinstance(item, dict)
        and item.get("type") == "tool_use"
        and isinstance(item.get("name"), str)
    )


def _record_tool_use(
    item: dict[str, Any], tool_calls: list[dict[str, str]], tools: dict[str, int]
) -> None:
    """Invariant: bounded disclosure and bounded size: every use is
    counted per tool, stored entries stop at MAX_TOOL_CALLS, and only the
    tool name plus an argument digest is ever recorded."""
    digest = _sha256_hex(_canon(item.get("input", {})))
    if len(tool_calls) < MAX_TOOL_CALLS:
        tool_calls.append({"tool": item["name"], "args_digest": digest})
    tools[item["name"]] = tools.get(item["name"], 0) + 1


def sign_authorship(data: dict[str, Any], private_key_pem: bytes) -> tuple[str, str, bytes]:
    """Sign the authorship payload as a provenance receipt.

    Returns (jws, receipt_hash, public_key_pem). Guardrail_scan shape
    (rootable, ruleset hash bound to the extension), as the x_compliance
    and x_finding receipts use, so the standard ProvenanceVerifier and
    `raucle provenance verify` accept it with no special code.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("authorship key must be an Ed25519 private PEM")
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = _sha256_hex(pub_pem)[:16]
    ext = data.get("x_authorship", data) if isinstance(data, dict) else {}
    ext_digest = _sha256_hex(_canon(ext))

    payload: dict[str, Any] = {
        "iss": "raucle-authorship",
        "typ": RECEIPT_TYP,
        "iat": int(time.time()),
        "agent_id": "raucle:code-authorship",
        "agent_key_id": kid,
        "operation": "guardrail_scan",
        "parents": [],
        "taint": ["gate:observed"],
        "input_hash": ext_digest,
        "ruleset_hash": ext_digest,
        "guardrail_verdict": "authorship_recorded",
        "x_authorship": ext,
    }

    def _b64(blob: bytes) -> str:
        return base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")

    header = {
        "alg": "EdDSA",
        "typ": RECEIPT_TYP,
        "kid": kid,
        "crit": [RECEIPT_CRIT],
        RECEIPT_CRIT: "provenance",
    }
    signing_input = f"{_b64(_canon(header))}.{_b64(_canon(payload))}".encode("ascii")
    sig = priv.sign(signing_input)
    jws = signing_input.decode("ascii") + "." + _b64(sig)
    receipt_hash = HASH_PREFIX + _sha256_hex(jws.encode("ascii"))
    return jws, receipt_hash, pub_pem


def write_receipt(jws: str, receipt_hash: str, out_path: str | Path) -> Path:
    """Write the receipt as a one-line provenance chain (JSONL envelope)."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"receipt_hash": receipt_hash, "jws": jws})
    with open(out_path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return out_path


def verify_authorship(
    receipt_path: str | Path, *, public_key_pem: bytes | None = None
) -> dict[str, Any]:
    """Verify a code_authorship receipt offline.

    Runs the standard chain verifier over the receipt and adds the
    x_authorship semantics on top. Fails closed: a non-authorship
    receipt, a wrong key, a tampered hash or a malformed extension is
    invalid with a named reason. Reasons never quote field values.

    Returns a report dict with valid / receipt_count / errors and
    summary counts (file_count, tool_calls).
    """
    path = Path(receipt_path)
    errors: list[str] = []
    report: dict[str, Any] = {
        "valid": False,
        "receipt_count": 0,
        "file_count": 0,
        "tool_calls": 0,
        "key_id": "",
        "errors": errors,
    }
    if not path.is_file():
        errors.append("receipt file not found")
        return report

    envelope, payload = _check_envelope(path, report, errors)
    if report["receipt_count"] != 1 or envelope is None:
        if report["receipt_count"] != 1:
            errors.append("expected exactly one receipt per chain file")
        report["valid"] = False
        return report

    agent_key_id = payload.get("agent_key_id")
    if not isinstance(agent_key_id, str):
        errors.append("receipt missing key id")
    if payload.get("operation") != "guardrail_scan":
        errors.append("receipt is not an authorship-shaped operation")

    ext = payload.get("x_authorship")
    if not isinstance(ext, dict):
        errors.append("receipt carries no x_authorship extension")
    else:
        _check_authorship_extension(ext, report, errors)

    _check_key_binding(agent_key_id, public_key_pem, path, errors)

    if isinstance(agent_key_id, str):
        report["key_id"] = agent_key_id
    # Deduplicate while keeping order; bounded disclosure: named reasons.
    seen: list[str] = []
    for err in errors:
        if err not in seen:
            seen.append(err)
    report["errors"] = seen
    report["valid"] = not seen
    return report


def _check_envelope(
    path: Path, report: dict[str, Any], errors: list[str]
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Invariant: the receipt file is a JSON-lines ledger of
    {receipt_hash, jws} envelopes; every non-blank line is counted, its
    hash binding is re-derived from its own JWS, and the last parseable
    envelope plus its decoded payload are what the verifier reasons
    over."""
    envelope: dict[str, Any] | None = None
    payload: dict[str, Any] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            report["receipt_count"] += 1
            try:
                envelope = json.loads(line)
            except ValueError:
                errors.append("malformed receipt envelope")
                continue
            if not isinstance(envelope, dict):
                errors.append("malformed receipt envelope")
                envelope = None
                continue
            expected_hash = HASH_PREFIX + _sha256_hex(str(envelope.get("jws", "")).encode("ascii"))
            if envelope.get("receipt_hash") != expected_hash:
                errors.append("receipt hash mismatch")
            payload = _decode_jws_payload(envelope.get("jws"))
    return envelope, payload


def _decode_jws_payload(jws: Any) -> dict[str, Any]:
    """Invariant: the payload is read from the JWS middle segment only;
    anything unparseable yields an empty payload, so the semantics
    checks fail closed on missing fields instead of crashing."""
    if not (isinstance(jws, str) and jws.count(".") == 2):
        return {}
    try:
        chunk = jws.split(".")[1]
        chunk += "=" * (-len(chunk) % 4)
        payload = json.loads(base64.urlsafe_b64decode(chunk.encode("ascii")))
        return payload if isinstance(payload, dict) else {}
    except (ValueError, TypeError):
        return {}


def _check_authorship_extension(
    ext: dict[str, Any], report: dict[str, Any], errors: list[str]
) -> None:
    """Invariant: every extension block the summary reports is validated
    before it is trusted: files carry path, status and hex digests, the
    git context carries a hex-or-empty head, and the commands count is
    consistent with the recorded entries."""
    files = ext.get("files")
    if not isinstance(files, list):
        errors.append("extension files block missing or malformed")
    else:
        report["file_count"] = len(files)
        for entry in files:
            if not _is_valid_file_entry(entry):
                errors.append("file entry malformed or missing digest")
                break
    if isinstance(ext.get("git"), dict):
        head = ext["git"].get("head")
        if head is not None and not _is_digest_hex(head):
            errors.append("git head digest malformed")
    _check_commands_block(ext, report, errors)


def _is_valid_file_entry(entry: Any) -> bool:
    """Invariant: a file entry always carries a non-empty path, a status
    letter and hex-or-empty before/after digests ('' marks a new,
    deleted or unreadable file; the status letter explains)."""
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("path"), str)
        and entry["path"]
        and isinstance(entry.get("status"), str)
        and _is_digest_hex(entry.get("before"))
        and _is_digest_hex(entry.get("after"))
    )


def _check_commands_block(ext: dict[str, Any], report: dict[str, Any], errors: list[str]) -> None:
    """Invariant: the commands block is a dict whose tool_calls count is
    an integer (0 otherwise) and whose stored entries are individually
    valid; a malformed entries list fails without the count-consistency
    leg running."""
    commands = ext.get("commands")
    if not isinstance(commands, dict):
        errors.append("extension commands block missing or malformed")
        return
    report["tool_calls"] = (
        commands.get("tool_calls", 0) if isinstance(commands.get("tool_calls"), int) else 0
    )
    entries = commands.get("tool_entries", [])
    if not isinstance(entries, list):
        errors.append("tool entries malformed")
        return
    for entry in entries:
        if not _is_valid_tool_entry(entry):
            errors.append("tool entry malformed or missing digest")
            break
    _check_tool_count_consistency(report, entries, errors)


def _is_valid_tool_entry(entry: Any) -> bool:
    """Invariant: a tool entry always carries a tool name and a non-empty
    hex args digest: the digest is the only argument evidence kept
    (bounded disclosure: no command text, no argument values)."""
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("tool"), str)
        and entry["tool"]
        and _is_digest_hex(entry.get("args_digest"))
        and entry.get("args_digest") != ""
    )


def _check_tool_count_consistency(
    report: dict[str, Any], entries: list[Any], errors: list[str]
) -> None:
    """Invariant: a claimed tool-call count larger than the recorded
    entries, with the entries still below the storage cap, is an evidence
    lie and fails verification."""
    if report["tool_calls"] > len(entries) and len(entries) < MAX_TOOL_CALLS:
        errors.append("tool call count exceeds recorded evidence")


def _check_key_binding(
    agent_key_id: Any, public_key_pem: bytes | None, path: Path, errors: list[str]
) -> None:
    """Invariant: offline verification requires the issuer's public key,
    and only the key the receipt names may verify it; a missing or
    unloadable key fails closed with a named reason."""
    if not agent_key_id:
        return
    if public_key_pem is None:
        errors.append("verification requires the issuer public key (offline verify)")
        return
    _verify_receipt_signature(agent_key_id, public_key_pem, path, errors)


def _verify_receipt_signature(
    agent_key_id: Any, public_key_pem: bytes, path: Path, errors: list[str]
) -> None:
    """Invariant: the key id must re-derive from the supplied PEM (the
    verifier never trusts the receipt's own key claim) and the chain
    signature must verify; raw crypto errors are named by class only so
    no key material leaks."""
    from cryptography.hazmat.primitives import serialization

    try:
        pub = serialization.load_pem_public_key(public_key_pem)
        derived = _sha256_hex(
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )[:16]
        if derived != agent_key_id:
            errors.append("supplied key does not match the receipt key id")
    except (ValueError, TypeError):
        errors.append("supplied key not loadable")
    try:
        verifier = ProvenanceVerifier(public_keys={agent_key_id: public_key_pem})
        chain_report = verifier.verify_chain(path)
        for err in chain_report.errors:
            errors.append(f"chain verification: {err}")
        if not chain_report.valid:
            errors.append("chain verification failed")
    except (ValueError, TypeError, OSError) as exc:
        # A raw cryptography error must not leak key material; name
        # the failure class only.
        errors.append("chain verification error: " + type(exc).__name__)
