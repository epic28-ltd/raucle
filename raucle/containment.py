"""Operator-facing containment (emergency authority stop) — P4.A v0.

Design invariant (`~/Projects/p4a-killswitch-research.md` §3): **every halt
state transition is a signed, auditable, reversible receipt. A halt without
its receipt is a bug, not a feature.** The halt itself is a signed action in
the receipt chain, reversible by a paired resume that restores the exact
prior enforcement bytes, verified by SHA-256 on both sides.

v0 scopes (trace quarantine and lease suspension are v1 — named slots only):

- ``global``: swap the active policy file for a deny-all policy (zero
  rules) through the normal policy load path, so the gate's existing
  deny machinery ("no policy configured for tool") enforces the stop
  fail-closed.
- ``agent``: revoke every delegated capability chain of the named agent
  by appending revocation records to the configured revocations file —
  the same persistence leg the gateway's cascade revocation writes —
  so the gate refuses the agent's subtree on the next call.
- ``chain``: revoke one delegated token and its whole subtree, same
  persistence leg, rooted at the named token id.

Receipts are compact JWS (``raucle-receipt/v1``) signed by a dedicated
operator key generated once at first use and stored next to the
containment state; they verify offline with ``raucle verify-receipt``.

Fail-closed everywhere:

- if receipt emission fails, the transition is rolled back and the
  hold/resume does not take effect;
- hold and resume serialise on ``flock`` over the target file, so a
  hold races nothing (concurrent activation holding the lock fails the
  hold with a named error rather than interleaving);
- malformed scope, missing prerequisites and double-holds are named
  errors, never silent no-ops.
"""

from __future__ import annotations

import base64
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCOPE_GLOBAL = "global"
SCOPE_AGENT = "agent"
SCOPE_CHAIN = "chain"
SCOPES = (SCOPE_GLOBAL, SCOPE_AGENT, SCOPE_CHAIN)

VERDICT_HOLD = "containment_hold"
VERDICT_RESUME = "containment_resume"

_STATE_FILE = "containment-state.json"
_KEY_FILE = "containment-operator-key.pem"
_PUBKEY_FILE = "containment-operator-pubkey.pem"

_REVOCATION_PATH = "containment"  # named slot: trace quarantine / lease
#: v1 named slots kept in the CLI help; v0 only implements the policy


class ContainmentError(Exception):
    """A named containment failure (CLI maps these to exit code 1)."""


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


@dataclass
class ContainmentConfig:
    """Filesystem layout the containment CLI operates on."""

    #: active policy file (deny-allowlist -> deny-all swap target)
    policy_file: str = ""
    #: revocations JSONL the gate loads per call (agent/chain scope)
    revocations_file: str = ""
    #: delegation ledger the agent/chain scope resolves targets from
    delegations_file: str = ""
    #: receipt stream (append-only JSONL of {receipt_hash, jws})
    receipts_path: str = ""
    #: directory for the state file + operator keypair
    state_dir: str = ""
    actor: str = "operator"


class ContainmentManager:
    """Hold/resume/status over the gate's existing enforcement surfaces."""

    def __init__(self, config: ContainmentConfig) -> None:
        self.config = config
        self.state_dir = Path(config.state_dir or "~/.raucle/containment").expanduser()
        self.state_path = self.state_dir / _STATE_FILE

    # -- operator identity --------------------------------------------------

    def _operator_signer(self):
        """A VerdictSigner keyed by the persistent operator key.

        The keypair is generated once and reused so every containment
        receipt verifies against the same published public key.
        """
        from raucle.verdicts import VerdictSigner

        key_path = self.state_dir / _KEY_FILE
        pub_path = self.state_dir / _PUBKEY_FILE
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if key_path.exists():
            signer = VerdictSigner.from_pem(key_path.read_bytes())
        else:
            signer = VerdictSigner.generate()
            key_path.write_bytes(
                signer._private_key.private_bytes(
                    encoding=_serialization().Encoding.PEM,
                    format=_serialization().PrivateFormat.PKCS8,
                    encryption_algorithm=_serialization().NoEncryption(),
                )
            )
            os.chmod(key_path, 0o600)
        if not pub_path.exists():
            pub_path.write_bytes(signer._public_pem)
            os.chmod(pub_path, 0o644)
        return signer

    # -- receipt stream ------------------------------------------------------

    def _emit_receipt(self, *, verdict: str, description: str, extra: dict[str, Any]) -> str:
        """Sign + append a containment receipt. Returns the receipt id.

        Raises on any failure — the caller rolls the transition back:
        an unreceipted transition must never survive (design invariant).
        """
        signer = self._operator_signer()
        jws = signer.issue(
            input_text=description,
            verdict=verdict,
            confidence=1.0,
            ruleset_hash=_sha256_bytes(
                json.dumps(extra, sort_keys=True, separators=(",", ":")).encode()
            ),
            model_version="containment/v0",
            extra=extra,
        )
        receipt_hash = hashlib.sha256(jws.encode("ascii")).hexdigest()
        line = json.dumps({"receipt_hash": receipt_hash, "jws": jws}, ensure_ascii=False)
        path = Path(self.config.receipts_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return receipt_hash

    # -- state / locking -----------------------------------------------------

    def _read_state(self) -> dict[str, Any] | None:
        if not self.state_path.exists():
            return None
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise ContainmentError(f"containment state file is corrupt: {exc}") from exc
        return state if state else None

    def _locked_state(self):
        """Acquire the containment lock (flock) on the state file.

        Returns an open fd holding the exclusive lock. Non-blocking: a
        concurrent hold/activation wins the race; we fail named.
        """
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.state_path.with_suffix(".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise ContainmentError(
                "containment is locked by a concurrent operation (flock)"
            ) from exc
        return fd

    def _lock_target(self, target: Path):
        """flock the enforcement file itself: a hold never interleaves
        with a concurrent activation writing the same file."""
        fd = os.open(target, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise ContainmentError(
                f"'{target}' is locked by a concurrent activation (flock); hold not applied"
            ) from exc
        return fd

    @staticmethod
    def _write_atomic(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise

    # -- scope validation ----------------------------------------------------

    def _validate_agent_id(self, agent_id: str) -> None:
        from raucle.capability import _validate_agent_id

        try:
            _validate_agent_id(agent_id)
        except ValueError as exc:
            raise ContainmentError(f"malformed scope: {exc}") from exc

    def _ledger(self):
        if not self.config.delegations_file:
            raise ContainmentError(
                "delegations_file is not configured: agent/chain hold cannot "
                "resolve targets (set RAUCLE_DELEGATIONS_FILE or --delegations-file)"
            )
        ledger_path = Path(self.config.delegations_file)
        if not ledger_path.exists():
            raise ContainmentError(
                f"delegation ledger '{ledger_path}' does not exist; agent/chain "
                "hold refuses to guess at targets (fail-closed)"
            )
        from raucle.capability import DelegationLedger

        return DelegationLedger(ledger_path)

    def _target_for(self, scope: str) -> Path:
        if scope == SCOPE_GLOBAL:
            if not self.config.policy_file:
                raise ContainmentError(
                    "policy_file is not configured: global hold has no policy "
                    "surface to swap (set RAUCLE_POLICY_FILE or --policy-file)"
                )
            return Path(self.config.policy_file)
        if not self.config.revocations_file:
            raise ContainmentError(
                "revocations_file is not configured: cascade revocation cannot "
                "persist (set RAUCLE_REVOCATIONS_FILE or --revocations-file)"
            )
        return Path(self.config.revocations_file)

    def _resolve_ids(self, scope: str, scope_id: str) -> list[str]:
        ledger = self._ledger()
        if scope == SCOPE_AGENT:
            self._validate_agent_id(scope_id)
            roots = ledger.tokens_for_agent(scope_id)
            if not roots:
                raise ContainmentError(
                    f"no delegated tokens for agent '{scope_id}' in the ledger; "
                    "agent hold refuses a no-op (fail-closed)"
                )
            return roots
        if not scope_id:
            raise ContainmentError("malformed scope: chain hold requires a token id")
        records = getattr(ledger, "_records", {})
        if scope_id not in records:
            raise ContainmentError(
                f"malformed scope: token '{scope_id}' is not in the delegation ledger"
            )
        return ledger.descendants(scope_id)

    # -- transitions ---------------------------------------------------------

    def hold(self, *, scope: str, scope_id: str = "", reason: str = "") -> dict[str, Any]:
        """Apply the stop for *scope* and receipt it. Fail-closed."""
        if scope not in SCOPES:
            raise ContainmentError(
                f"malformed scope: '{scope}' (expected one of {', '.join(SCOPES)})"
            )
        if scope == SCOPE_AGENT:
            self._validate_agent_id(scope_id)  # malformed scope: named, before anything else
        state = self._read_state()
        if state:
            raise ContainmentError(
                f"already held since {state.get('held_at', '?')} "
                f"(scope {state.get('scope')}); resume first"
            )
        return self._hold_locked(scope, scope_id, reason)

    def _hold_locked(self, scope: str, scope_id: str, reason: str) -> dict[str, Any]:
        """Apply the hold under the state lock, receipt it, and release
        both locks in all paths."""
        actor = self.config.actor
        fd_target: int | None = None
        fd_lock: int | None = None
        ids: list[str] = []
        try:
            fd_lock = self._locked_state()
            state = self._read_state()  # re-read under the lock
            if state:
                raise ContainmentError(
                    f"already held since {state.get('held_at', '?')} "
                    f"(scope {state.get('scope')}); resume first"
                )

            target = self._target_for(scope)
            if scope == SCOPE_GLOBAL:
                if not target.exists():
                    raise ContainmentError(
                        f"policy file '{target}' does not exist; the gate is "
                        "already deny-all — nothing to hold (fail-closed)"
                    )
                fd_target = self._lock_target(target)
                original = target.read_bytes()
            else:
                ids = self._resolve_ids(scope, scope_id)
                rev_path = target
                rev_path.parent.mkdir(parents=True, exist_ok=True)
                fd_target = self._lock_target(rev_path) if rev_path.exists() else None
                if fd_target is None:
                    fd_target = os.open(rev_path, os.O_RDWR | os.O_CREAT, 0o600)
                    fcntl.flock(fd_target, fcntl.LOCK_EX | fcntl.LOCK_NB)
                revocations = rev_path.read_bytes()
                original = revocations

            original_sha = _sha256_bytes(original)
            if scope == SCOPE_GLOBAL:
                held_bytes = self._deny_all_policy_bytes(original)
                self._write_atomic(target, held_bytes)
            else:
                self._append_revocations(target, ids, reason=reason, actor=actor)

            try:
                receipt_id = self._emit_receipt(
                    verdict=VERDICT_HOLD,
                    description=f"containment:hold:{scope}:{scope_id}",
                    extra={
                        "scope": scope,
                        "scope_id": scope_id,
                        "actor": actor,
                        "reason": reason,
                        "target_file": str(target),
                        "sha256_before": original_sha,
                        "revoked_ids": ids if scope != SCOPE_GLOBAL else [],
                    },
                )
            except Exception as exc:
                # Receipt failed: roll the hold back — no unreceipted halt.
                self._write_atomic(target, original)
                raise ContainmentError(
                    f"hold receipt emission failed; hold rolled back: {exc}"
                ) from exc

            self._write_atomic(
                self.state_path,
                json.dumps(
                    {
                        "scope": scope,
                        "scope_id": scope_id,
                        "held_at": _now_iso(),
                        "actor": actor,
                        "reason": reason,
                        "target_file": str(target),
                        "target_existed": scope == SCOPE_GLOBAL or target.exists(),
                        "original_sha256": original_sha,
                        "held_sha256": _sha256_file(target),
                        "receipt_id": receipt_id,
                        "revoked_ids": ids if scope != SCOPE_GLOBAL else [],
                        "original_bytes_b64": base64.b64encode(original).decode("ascii"),
                    },
                    sort_keys=True,
                ).encode("utf-8"),
            )
            return {
                "status": "held",
                "scope": scope,
                "scope_id": scope_id,
                "target_file": str(target),
                "receipt_id": receipt_id,
                "revoked_ids": ids if scope != SCOPE_GLOBAL else [],
            }
        finally:
            if fd_target is not None:
                try:
                    fcntl.flock(fd_target, fcntl.LOCK_UN)
                finally:
                    os.close(fd_target)
            if fd_lock is not None:
                try:
                    fcntl.flock(fd_lock, fcntl.LOCK_UN)
                finally:
                    os.close(fd_lock)

    def resume(self, *, reason: str = "") -> dict[str, Any]:
        """Restore the pre-hold enforcement bytes exactly and receipt it."""
        actor = self.config.actor
        fd_target = None
        fd_lock = None
        try:
            fd_lock = self._locked_state()
            state = self._read_state()
            if not state:
                raise ContainmentError("not held; nothing to resume")
            target = Path(state["target_file"])
            original = base64.b64decode(state["original_bytes_b64"])
            expected = state["original_sha256"]
            if _sha256_bytes(original) != expected:
                raise ContainmentError(
                    "restore verification failed: snapshot digest mismatch; "
                    "resume refused (fail-closed)"
                )
            if target.exists():
                fd_target = self._lock_target(target)

            receipt_id = None
            try:
                # Receipt BEFORE the restore so a resume is never silent:
                # the receipt names the bytes about to come back online.
                receipt_id = self._emit_receipt(
                    verdict=VERDICT_RESUME,
                    description=f"containment:resume:{state['scope']}",
                    extra={
                        "scope": state["scope"],
                        "scope_id": state.get("scope_id", ""),
                        "actor": actor,
                        "reason": reason,
                        "target_file": str(target),
                        "sha256_restored": expected,
                        "sha256_before": state.get("held_sha256", ""),
                        "hold_receipt_id": state.get("receipt_id", ""),
                        "released_ids": state.get("revoked_ids", []),
                    },
                )
            except Exception as exc:
                raise ContainmentError(
                    f"resume receipt emission failed; resume refused: {exc}"
                ) from exc

            self._write_atomic(target, original)
            if not state.get("target_existed", True):
                with contextlib.suppress(FileNotFoundError):
                    target.unlink()
            actual = _sha256_file(target) if target.exists() else _sha256_bytes(original)
            if actual != expected:
                raise ContainmentError(
                    "resume verification failed: restored digest "
                    f"'{actual}' != snapshot '{expected}' (fail-closed)"
                )
            self._write_atomic(self.state_path, b"")
            with contextlib.suppress(FileNotFoundError):
                self.state_path.unlink()
            return {
                "status": "resumed",
                "scope": state["scope"],
                "scope_id": state.get("scope_id", ""),
                "target_file": str(target),
                "restored_sha256": actual,
                "receipt_id": receipt_id,
            }
        finally:
            if fd_target is not None:
                try:
                    fcntl.flock(fd_target, fcntl.LOCK_UN)
                finally:
                    os.close(fd_target)
            if fd_lock is not None:
                try:
                    fcntl.flock(fd_lock, fcntl.LOCK_UN)
                finally:
                    os.close(fd_lock)

    def status(self) -> dict[str, Any]:
        state = self._read_state()
        if not state:
            return {"held": False}
        return {
            "held": True,
            "scope": state.get("scope", ""),
            "scope_id": state.get("scope_id", ""),
            "held_at": state.get("held_at", ""),
            "actor": state.get("actor", ""),
            "reason": state.get("reason", ""),
            "target_file": state.get("target_file", ""),
            "original_sha256": state.get("original_sha256", ""),
            "receipt_id": state.get("receipt_id", ""),
            "revocation_path": (
                str(Path(self.config.revocations_file))
                if state.get("scope") != SCOPE_GLOBAL
                else ""
            ),
        }

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _deny_all_policy_bytes(original: bytes) -> bytes:
        """The deny-all policy: original issuer, zero rules.

        The gate loads it through the normal policy path and then denies
        every call with "no policy configured for tool" (fail-closed).
        """
        from raucle.policy import PolicyFile

        issuer = "raucle-containment"
        with contextlib.suppress(Exception):
            issuer = PolicyFile.from_dict(_yaml_safe_load(original)).issuer or issuer
        return PolicyFile(version=1, issuer=issuer, policies=[]).to_yaml().encode("utf-8")

    @staticmethod
    def _append_revocations(path: Path, ids: list[str], *, reason: str, actor: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        now = _now_iso()
        with open(path, "a", encoding="utf-8") as fh:
            for tid in ids:
                fh.write(
                    json.dumps(
                        {
                            "token_id": tid,
                            "reason": reason or "containment hold",
                            "actor": actor,
                            "timestamp": now,
                            "path": _REVOCATION_PATH,
                        }
                    )
                    + "\n"
                )


def _serialization():
    from cryptography.hazmat.primitives import serialization

    return serialization


def _yaml_safe_load(data: bytes) -> dict[str, Any]:
    import yaml

    loaded = yaml.safe_load(data.decode("utf-8"))
    return loaded if isinstance(loaded, dict) else {}


__all__ = [
    "ContainmentConfig",
    "ContainmentError",
    "ContainmentManager",
    "SCOPES",
    "SCOPE_AGENT",
    "SCOPE_CHAIN",
    "SCOPE_GLOBAL",
    "VERDICT_HOLD",
    "VERDICT_RESUME",
]
