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
import re
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
VERDICT_HOLD_PENDING = "containment_hold_pending"
VERDICT_HOLD_APPROVAL = "containment_hold_approval"
VERDICT_HOLD_ABORT = "containment_hold_abort"

_HOLD_PENDING_KIND = "hold_pending"

# v1: targeted containment (per-trace / per-lease, two-sided receipts).
VERDICT_TRACE_QUARANTINE = "containment_trace_quarantine"
VERDICT_TRACE_RELEASE = "containment_trace_release"
VERDICT_LEASE_SUSPEND = "containment_lease_suspend"
VERDICT_LEASE_REINSTATE = "containment_lease_reinstate"

STATE_QUARANTINED = "quarantined"
STATE_RELEASED = "released"
STATE_SUSPENDED = "suspended"
STATE_REINSTATED = "reinstated"

_QUARANTINE_PATH = "trace-quarantine"
_LEASE_PATH = "lease-suspension"
_ID_RE = re.compile(r"^[A-Za-z0-9._:/@-]{1,128}$")

_STATE_FILE = "containment-state.json"
_KEY_FILE = "containment-operator-key.pem"
_PUBKEY_FILE = "containment-operator-pubkey.pem"

_REVOCATION_PATH = "containment"  # named slot: trace quarantine / lease
# v1 named slots now implemented below: trace quarantine (quarantine/release)
# and lease suspension (suspend/reinstate) ride the same receipt machinery.


def _write_private(path: Path, data: bytes) -> None:
    """Create a key file owner-only, atomically: restrictive mode from the
    first byte, never a permissive window between create and tighten."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


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
    #: trace-quarantine registry JSONL the gate loads per call (v1)
    quarantines_file: str = ""
    #: lease-suspension registry JSONL the gate loads per call (v1)
    lease_suspensions_file: str = ""
    #: directory for the state file + operator keypair
    state_dir: str = ""
    actor: str = "operator"
    #: M-of-N containment authorisation (threat-model mitigation M3,
    #: OPT-IN): the number of DISTINCT sequential approver receipts a
    #: hold requires before the stop is applied. Default 1 keeps the v0
    #: single-approver path byte-identical; > 1 turns ``hold`` into a
    #: receipted pending state that each additional distinct approver
    #: (``approve_hold``) advances until the quorum is met.
    min_approvers: int = 1


class ContainmentManager:
    """Hold/resume/status over the gate's existing enforcement surfaces."""

    def __init__(self, config: ContainmentConfig) -> None:
        if config.min_approvers < 1:
            raise ContainmentError(
                f"minimal approver quorum must be >= 1, got {config.min_approvers}"
            )
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
            _write_private(
                key_path,
                signer._private_key.private_bytes(
                    encoding=_serialization().Encoding.PEM,
                    format=_serialization().PrivateFormat.PKCS8,
                    encryption_algorithm=_serialization().NoEncryption(),
                ),
            )
        if not pub_path.exists():
            _write_private(pub_path, signer._public_pem)
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
        """Apply the stop for *scope* and receipt it. Fail-closed.

        With the default quorum (``min_approvers == 1``) the stop is
        applied immediately. With an opt-in quorum above 1 the hold
        enters a receipted *pending* state instead and only applies
        once enough DISTINCT approvers have receipted it via
        :meth:`approve_hold` (M-of-N, mitigation M3).
        """
        if scope not in SCOPES:
            raise ContainmentError(
                f"malformed scope: '{scope}' (expected one of {', '.join(SCOPES)})"
            )
        if scope == SCOPE_AGENT:
            self._validate_agent_id(scope_id)  # malformed scope: named, before anything else
        state = self._read_state()
        if state:
            self._raise_state_busy(state)
        if self.config.min_approvers > 1:
            return self._open_pending_hold(scope, scope_id, reason)
        return self._hold_locked(scope, scope_id, reason)

    def _raise_state_busy(self, state: dict[str, Any]) -> None:
        """A named refusal for the two states that block a new hold."""
        if state.get("kind") == _HOLD_PENDING_KIND:
            received = len(state.get("approvers", []))
            required = int(state.get("min_approvers", self.config.min_approvers))
            raise ContainmentError(
                f"a hold is already pending approval ({received}/{required} "
                "approvers receipted): approve via approve_hold or abort "
                "the pending hold first"
            )
        raise ContainmentError(
            f"already held since {state.get('held_at', '?')} "
            f"(scope {state.get('scope')}); resume first"
        )

    # -- M-of-N pending hold (opt-in quorum, mitigation M3) -------------------

    def _open_pending_hold(self, scope: str, scope_id: str, reason: str) -> dict[str, Any]:
        """Open the receipted pending state without touching enforcement
        bytes: quorum not yet met, so nothing is stopped yet."""
        fd_lock = None
        try:
            fd_lock = self._locked_state()
            state = self._read_state()  # re-read under the lock
            if state:
                self._raise_state_busy(state)
            actor = self.config.actor
            required = self.config.min_approvers
            receipt_id = self._emit_receipt(
                verdict=VERDICT_HOLD_PENDING,
                description=f"containment:hold-pending:{scope}:{scope_id}",
                extra={
                    "scope": scope,
                    "scope_id": scope_id,
                    "actor": actor,
                    "reason": reason,
                    "min_approvers": required,
                    "approvers": [],
                },
            )
            self._write_atomic(
                self.state_path,
                json.dumps(
                    {
                        "kind": _HOLD_PENDING_KIND,
                        "scope": scope,
                        "scope_id": scope_id,
                        "reason": reason,
                        "actor": actor,
                        "min_approvers": required,
                        "approvers": [],
                        "approval_receipts": [],
                        "pending_receipt_id": receipt_id,
                        "requested_at": _now_iso(),
                    },
                    sort_keys=True,
                ).encode("utf-8"),
            )
            return {
                "status": "pending",
                "scope": scope,
                "scope_id": scope_id,
                "min_approvers": required,
                "approvers": [],
                "receipt_id": receipt_id,
            }
        finally:
            if fd_lock is not None:
                try:
                    fcntl.flock(fd_lock, fcntl.LOCK_UN)
                finally:
                    os.close(fd_lock)

    def approve_hold(self, *, approver: str) -> dict[str, Any]:
        """Receipt one distinct approver against the pending hold.

        Sequential by design: each call emits its own named approval
        receipt and advances the quorum. The approver identity must be
        fresh — repeat approvals by the same identity are refused
        (N-of-M quorums collude nothing). When the quorum is met the
        stop is applied and the hold receipt carries every approver.
        """
        if not isinstance(approver, str) or not approver.strip():
            raise ContainmentError("approver identity is required for an M-of-N approval receipt")
        approver = approver.strip()
        fd_lock = None
        try:
            fd_lock = self._locked_state()
            state = self._read_state()  # re-read under the lock
            if state is None:
                raise ContainmentError("no pending hold; nothing to approve")
            if state.get("kind") != _HOLD_PENDING_KIND:
                self._raise_state_busy(state)
            required = int(state.get("min_approvers", self.config.min_approvers))
            approvers = list(state.get("approvers", []))
            if approver in approvers:
                raise ContainmentError(
                    f"approver '{approver}' has already receipted this pending "
                    "hold (distinct approvers required)"
                )
            scope = str(state.get("scope", ""))
            scope_id = str(state.get("scope_id", ""))
            receipt_id = self._emit_receipt(
                verdict=VERDICT_HOLD_APPROVAL,
                description=f"containment:hold-approval:{scope}:{scope_id}:{approver}",
                extra={
                    "scope": scope,
                    "scope_id": scope_id,
                    "approver": approver,
                    "approvers_before": approvers,
                    "min_approvers": required,
                },
            )
            approvers.append(approver)
            state["approvers"] = approvers
            receipts = list(state.get("approval_receipts", []))
            receipts.append(receipt_id)
            state["approval_receipts"] = receipts
            if len(approvers) < required:
                self._write_atomic(
                    self.state_path,
                    json.dumps(state, sort_keys=True).encode("utf-8"),
                )
                return {
                    "status": "pending",
                    "scope": scope,
                    "scope_id": scope_id,
                    "approvers": approvers,
                    "min_approvers": required,
                    "outstanding": required - len(approvers),
                    "receipt_id": receipt_id,
                }
            # Quorum met: apply the stop, carrying the approver roll into
            # the hold receipt and the persisted held state.
            return self._apply_hold_locked(
                scope,
                scope_id,
                str(state.get("reason", "")),
                pending=state,
            )
        finally:
            if fd_lock is not None:
                try:
                    fcntl.flock(fd_lock, fcntl.LOCK_UN)
                finally:
                    os.close(fd_lock)

    def abort_hold(self, *, approver: str) -> dict[str, Any]:
        """Cancel a still-pending hold: receipted, never a silent clear."""
        if not isinstance(approver, str) or not approver.strip():
            raise ContainmentError("approver identity is required to abort a hold")
        approver = approver.strip()
        fd_lock = None
        try:
            fd_lock = self._locked_state()
            state = self._read_state()  # re-read under the lock
            if state is None:
                raise ContainmentError("no pending hold; nothing to abort")
            if state.get("kind") != _HOLD_PENDING_KIND:
                raise ContainmentError("hold already applied: abort refused (resume instead)")
            receipt_id = self._emit_receipt(
                verdict=VERDICT_HOLD_ABORT,
                description=(
                    f"containment:hold-abort:{state.get('scope')}:{state.get('scope_id', '')}"
                ),
                extra={
                    "scope": state.get("scope", ""),
                    "scope_id": state.get("scope_id", ""),
                    "actor": approver,
                    "pending_receipt_id": state.get("pending_receipt_id", ""),
                    "approvers_so_far": list(state.get("approvers", [])),
                },
            )
            self._write_atomic(self.state_path, b"")
            with contextlib.suppress(FileNotFoundError):
                self.state_path.unlink()
            return {
                "status": "aborted",
                "scope": state.get("scope", ""),
                "receipt_id": receipt_id,
            }
        finally:
            if fd_lock is not None:
                try:
                    fcntl.flock(fd_lock, fcntl.LOCK_UN)
                finally:
                    os.close(fd_lock)

    def _open_hold_target(
        self, scope: str, scope_id: str
    ) -> tuple[Any, int | None, bytes, list[str]]:
        """Acquire the target file lock for a hold and snapshot its
        current bytes (the rollback baseline)."""
        target = self._target_for(scope)
        if scope == SCOPE_GLOBAL:
            if not target.exists():
                raise ContainmentError(
                    f"policy file '{target}' does not exist; the gate is "
                    "already deny-all — nothing to hold (fail-closed)"
                )
            fd_target = self._lock_target(target)
            return target, fd_target, target.read_bytes(), []
        ids = self._resolve_ids(scope, scope_id)
        rev_path = target
        rev_path.parent.mkdir(parents=True, exist_ok=True)
        fd_target = self._lock_target(rev_path) if rev_path.exists() else None
        if fd_target is None:
            fd_target = os.open(rev_path, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(fd_target, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return target, fd_target, rev_path.read_bytes(), ids

    def _hold_locked(self, scope: str, scope_id: str, reason: str) -> dict[str, Any]:
        """Apply the hold under the state lock, receipt it, and release
        the state lock in all paths (the target lock is taken and
        released inside :meth:`_apply_hold_locked`)."""
        fd_lock = None
        try:
            fd_lock = self._locked_state()
            state = self._read_state()  # re-read under the lock
            if state:
                self._raise_state_busy(state)
            return self._apply_hold_locked(scope, scope_id, reason)
        finally:
            if fd_lock is not None:
                try:
                    fcntl.flock(fd_lock, fcntl.LOCK_UN)
                finally:
                    os.close(fd_lock)

    def _apply_hold_locked(
        self,
        scope: str,
        scope_id: str,
        reason: str,
        *,
        pending: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Mutate the enforcement bytes, receipt the hold, and persist the
        held state. The state lock must already be held by the caller.

        ``pending`` is the M-of-N pending record when the stop is being
        applied on quorum: the approver roll then rides the hold receipt
        and the held state (the default single-approver path — pending
        None — is byte-identical to v0: no extra keys anywhere).
        """
        actor = self.config.actor
        fd_target = None
        ids: list[str] = []
        try:
            target, fd_target, original, ids = self._open_hold_target(scope, scope_id)

            original_sha = _sha256_bytes(original)
            if scope == SCOPE_GLOBAL:
                held_bytes = self._deny_all_policy_bytes(original)
                self._write_atomic(target, held_bytes)
            else:
                self._append_revocations(target, ids, reason=reason, actor=actor)

            extra: dict[str, Any] = {
                "scope": scope,
                "scope_id": scope_id,
                "actor": actor,
                "reason": reason,
                "target_file": str(target),
                "sha256_before": original_sha,
                "revoked_ids": ids if scope != SCOPE_GLOBAL else [],
            }
            if pending is not None:
                # Quorum provenance rides the hold receipt: every approver
                # that receipted the pending hold, and the pending
                # receipt that opened it.
                extra["approvers"] = list(pending.get("approvers", []))
                extra["min_approvers"] = int(
                    pending.get("min_approvers", self.config.min_approvers)
                )
                extra["pending_receipt_id"] = pending.get("pending_receipt_id", "")
            try:
                receipt_id = self._emit_receipt(
                    verdict=VERDICT_HOLD,
                    description=f"containment:hold:{scope}:{scope_id}",
                    extra=extra,
                )
            except Exception as exc:
                # Receipt failed: roll the hold back — no unreceipted halt.
                self._write_atomic(target, original)
                raise ContainmentError(
                    f"hold receipt emission failed; hold rolled back: {exc}"
                ) from exc

            held_state: dict[str, Any] = {
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
            }
            if pending is not None:
                held_state["approvers"] = list(pending.get("approvers", []))
                held_state["min_approvers"] = int(
                    pending.get("min_approvers", self.config.min_approvers)
                )
            self._write_atomic(
                self.state_path,
                json.dumps(held_state, sort_keys=True).encode("utf-8"),
            )
            held_result: dict[str, Any] = {
                "status": "held",
                "scope": scope,
                "scope_id": scope_id,
                "target_file": str(target),
                "receipt_id": receipt_id,
                "revoked_ids": ids if scope != SCOPE_GLOBAL else [],
            }
            if pending is not None:
                held_result["approvers"] = list(pending.get("approvers", []))
                held_result["min_approvers"] = held_state["min_approvers"]
            return held_result
        finally:
            if fd_target is not None:
                try:
                    fcntl.flock(fd_target, fcntl.LOCK_UN)
                finally:
                    os.close(fd_target)

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
            if state.get("kind") == _HOLD_PENDING_KIND:
                received = len(state.get("approvers", []))
                required = int(state.get("min_approvers", self.config.min_approvers))
                raise ContainmentError(
                    f"the hold is still pending approval ({received}/{required} "
                    "approvers receipted); nothing is held yet - approve to "
                    "quorum or abort the pending hold"
                )
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

    def _validate_id(self, ident: str, label: str) -> None:
        """Hostile inputs are named errors, never silent acceptance."""
        if not ident:
            raise ContainmentError(f"malformed scope: {label} is required and cannot be empty")
        if ".." in ident:
            raise ContainmentError(
                f"malformed scope: {label} '{ident[:32]}' contains a path-traversal segment"
            )
        if not _ID_RE.fullmatch(ident):
            raise ContainmentError(
                f"malformed scope: {label} '{ident[:32]}' contains characters outside "
                "[A-Za-z0-9._:/@-] or exceeds 128 chars (fail-closed)"
            )

    # -- v1: registry transitions (trace quarantine / lease suspension) ------
    #
    # Each targeted lever is a state registry (append-only JSONL, last
    # record per id wins) the gateway loads per call, the same
    # propagate-immediately pattern as the revocations file. The registry
    # only ever DENIES new work: quarantined traces lose new gate
    # decisions, existing receipts stay independently verifiable — no
    # history is rewritten. Every transition (quarantine, release,
    # suspend, reinstate) mints a signed receipt appended to the same
    # operator receipt stream; if the receipt emission fails the registry
    # append is rolled back — an unreceipted transition never survives.

    def _registry_file(self, config_key: str, label: str, env: str) -> Path:
        path = getattr(self.config, config_key, "")
        if not path:
            raise ContainmentError(
                f"{config_key} is not configured: {label} cannot persist (set {env})"
            )
        return Path(path)

    @staticmethod
    def _registry_states(path: Path, id_field: str) -> dict[str, str]:
        """Last-record-wins state map for *id_field*; corrupt lines are
        skipped (the gate reads the same registries with the same
        tolerance — the receipt stream is the tamper evidence)."""
        if not path.exists():
            return {}
        states: dict[str, str] = {}
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict) and record.get(id_field):
                    states[str(record[id_field])] = str(record.get("state", ""))
        return states

    def _registry_transition(
        self,
        target: Path,
        record: dict[str, Any],
        *,
        verdict: str,
        description: str,
        extra: dict[str, Any],
        rollback_note: str,
    ) -> dict[str, Any]:
        """Append a registry record, then receipt it. Fail-closed: if the
        receipt cannot be minted the append is rolled back and the
        transition raises named — quarantine/suspension are never
        unreceipted (v0 invariant: halt without receipt = bug)."""
        fd_lock: int | None = None
        fd_target: int | None = None
        try:
            fd_lock = self._locked_state()
            target.parent.mkdir(parents=True, exist_ok=True)
            original = target.read_bytes() if target.exists() else b""
            if target.exists():
                fd_target = self._lock_target(target)
            else:
                fd_target = os.open(target, os.O_RDWR | os.O_CREAT, 0o600)
                fcntl.flock(fd_target, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with open(target, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            try:
                receipt_id = self._emit_receipt(
                    verdict=verdict, description=description, extra=extra
                )
            except Exception as exc:
                # Receipt failed: roll the append back — no silent halt state.
                if original:
                    self._write_atomic(target, original)
                else:
                    fcntl.flock(fd_target, fcntl.LOCK_UN)
                    os.close(fd_target)
                    fd_target = None
                    with contextlib.suppress(FileNotFoundError):
                        target.unlink()
                raise ContainmentError(
                    f"{rollback_note} receipt emission failed; transition rolled back: {exc}"
                ) from exc
            return {"state": record["state"], "receipt_id": receipt_id, "target_file": str(target)}
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

    def _trace_transition(
        self, trace_id: str, *, state: str, verdict: str, action: str, reason: str
    ) -> dict[str, Any]:
        self._validate_id(trace_id, "trace_id")
        target = self._registry_file(
            "quarantines_file", "trace quarantine", "RAUCLE_TRACE_QUARANTINE_FILE"
        )
        states = self._registry_states(target, "trace_id")
        current = states.get(trace_id, "")
        if action == "quarantine":
            if current == STATE_QUARANTINED:
                raise ContainmentError(
                    f"trace '{trace_id}' is already quarantined; release it first"
                )
            if current == STATE_RELEASED:
                pass  # re-quarantine after release is legitimate; appends again
        else:  # release
            if current != STATE_QUARANTINED:
                raise ContainmentError(
                    f"trace '{trace_id}' is not quarantined; nothing to release (fail-closed)"
                )
        record = {
            "trace_id": trace_id,
            "state": state,
            "reason": reason,
            "actor": self.config.actor,
            "timestamp": _now_iso(),
            "path": _QUARANTINE_PATH,
        }
        result = self._registry_transition(
            target,
            record,
            verdict=verdict,
            description=f"containment:{action}:trace:{trace_id}",
            extra={**record},
            rollback_note=f"trace {action}",
        )
        return {
            "status": state,
            "trace_id": trace_id,
            "receipt_id": result["receipt_id"],
            "target_file": result["target_file"],
            "reason": reason,
            "actor": record["actor"],
        }

    def quarantine_trace(self, trace_id: str, *, reason: str = "") -> dict[str, Any]:
        """Quarantine a trace: NEW gate work on this trace_id is denied
        before constraint evaluation; existing receipts remain
        independently verifiable (no history rewrite). Receipted."""
        return self._trace_transition(
            trace_id,
            state=STATE_QUARANTINED,
            verdict=VERDICT_TRACE_QUARANTINE,
            action="quarantine",
            reason=reason,
        )

    def release_trace(self, trace_id: str, *, reason: str = "") -> dict[str, Any]:
        """Release a quarantined trace: the gate resumes evaluating new
        work for this trace_id. Receipted, paired to the quarantine."""
        return self._trace_transition(
            trace_id,
            state=STATE_RELEASED,
            verdict=VERDICT_TRACE_RELEASE,
            action="release",
            reason=reason,
        )

    def _lease_transition(
        self,
        agent_id: str,
        lease_id: str,
        *,
        state: str,
        verdict: str,
        action: str,
        reason: str,
    ) -> dict[str, Any]:
        self._validate_agent_id(agent_id)
        if lease_id:
            self._validate_id(lease_id, "lease_id")
        target = self._registry_file(
            "lease_suspensions_file", "lease suspension", "RAUCLE_LEASE_SUSPENSIONS_FILE"
        )
        states = self._registry_states(target, "agent_id")
        current = states.get(agent_id, "")
        if action == "suspend" and current == STATE_SUSPENDED:
            raise ContainmentError(
                f"agent '{agent_id}' already has a suspended lease; reinstate it first"
            )
        if action == "reinstate" and current != STATE_SUSPENDED:
            raise ContainmentError(
                f"agent '{agent_id}' has no suspended lease; nothing to reinstate (fail-closed)"
            )
        record = {
            "agent_id": agent_id,
            "lease_id": lease_id,
            "state": state,
            "reason": reason,
            "actor": self.config.actor,
            "timestamp": _now_iso(),
            "path": _LEASE_PATH,
        }
        result = self._registry_transition(
            target,
            record,
            verdict=verdict,
            description=f"containment:{action}:lease:{agent_id}",
            extra={**record},
            rollback_note=f"lease {action}",
        )
        return {
            "status": state,
            "agent_id": agent_id,
            "lease_id": lease_id,
            "receipt_id": result["receipt_id"],
            "target_file": result["target_file"],
            "reason": reason,
            "actor": record["actor"],
        }

    def suspend_lease(
        self, agent_id: str, *, lease_id: str = "", reason: str = ""
    ) -> dict[str, Any]:
        """Suspend a credential lease via the gate's lease-suspension
        registry: the agent's credential is cut at the gate even with a
        valid token/key presented. Receipted, two-sided."""
        return self._lease_transition(
            agent_id,
            lease_id,
            state=STATE_SUSPENDED,
            verdict=VERDICT_LEASE_SUSPEND,
            action="suspend",
            reason=reason,
        )

    def reinstate_lease(
        self, agent_id: str, *, lease_id: str = "", reason: str = ""
    ) -> dict[str, Any]:
        """Reinstate a suspended credential lease. Receipted."""
        return self._lease_transition(
            agent_id,
            lease_id,
            state=STATE_REINSTATED,
            verdict=VERDICT_LEASE_REINSTATE,
            action="reinstate",
            reason=reason,
        )

    def _active_quarantines(self) -> list[str]:
        target = getattr(self.config, "quarantines_file", "")
        if not target:
            return []
        states = self._registry_states(Path(target), "trace_id")
        return sorted(t for t, s in states.items() if s == STATE_QUARANTINED)

    def _active_lease_suspensions(self) -> list[str]:
        target = getattr(self.config, "lease_suspensions_file", "")
        if not target:
            return []
        states = self._registry_states(Path(target), "agent_id")
        return sorted(a for a, s in states.items() if s == STATE_SUSPENDED)

    def status(self) -> dict[str, Any]:
        state = self._read_state()
        if not state:
            return {
                "held": False,
                "quarantined_traces": self._active_quarantines(),
                "suspended_leases": self._active_lease_suspensions(),
            }
        if state.get("kind") == _HOLD_PENDING_KIND:
            return {
                "held": False,
                "pending_hold": {
                    "scope": state.get("scope", ""),
                    "scope_id": state.get("scope_id", ""),
                    "min_approvers": int(state.get("min_approvers", self.config.min_approvers)),
                    "approvers": list(state.get("approvers", [])),
                    "receipt_id": state.get("pending_receipt_id", ""),
                    "requested_at": state.get("requested_at", ""),
                },
                "quarantined_traces": self._active_quarantines(),
                "suspended_leases": self._active_lease_suspensions(),
            }
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
            "quarantined_traces": self._active_quarantines(),
            "suspended_leases": self._active_lease_suspensions(),
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
    "STATE_QUARANTINED",
    "STATE_RELEASED",
    "STATE_REINSTATED",
    "STATE_SUSPENDED",
    "VERDICT_HOLD",
    "VERDICT_LEASE_REINSTATE",
    "VERDICT_LEASE_SUSPEND",
    "VERDICT_HOLD_ABORT",
    "VERDICT_HOLD_APPROVAL",
    "VERDICT_HOLD_PENDING",
    "VERDICT_RESUME",
    "VERDICT_TRACE_QUARANTINE",
    "VERDICT_TRACE_RELEASE",
]
