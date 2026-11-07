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
VERDICT_RESUME_REFUSED = "containment_resume_refused"
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

#: RED-028 honest mitigation (documented limit R3-L1): the operator keypair
#: fingerprint (sha256 over the public-key PEM) is PINNED into the hold
#: receipt and the held state at hold-request time; :meth:`resume` refuses
#: with ``operator_key_changed`` when the anchor moved out of band. This
#: converts the silent quarantiner re-anchor into a DETECTABLE attack for
#: the post-hold window; a swap completed BEFORE the hold still issues the
#: hold under the attacker key (the pin then matches) and remains a
#: documented limit — closing it needs an out-of-band anchor.
_ERR_OPERATOR_KEY_CHANGED = "operator_key_changed"
_ERR_OPERATOR_KEY_UNPINNED = "operator_key_unpinned"

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


# -- receipt-stream head anchor (SCITT-style, N2 pattern) --------------------
#
# The receipt stream is append-only *by convention*: an attacker with write
# access to it can erase receipt evidence without anything noticing (round-3
# RED-029 / AV-12). The N2 transparency machinery proves the head of an
# existing hash chain by anchoring its digest; the same construction anchors
# the containment receipt stream: every receipt emit updates a sidecar HEAD
# ANCHOR file binding (count, stream_head), where ``stream_head`` is a hash
# chain folded over the emitted receipt hashes. Deleting the stream — or any
# prefix/suffix/slice of it — no longer matches the anchored head, so the
# tamper is detectable under its own name, ``receipt_stream_gap``.
#
# Anchoring limit (honest, documented — not claimed away): detection runs at
# the next operator/containment action (receipt emit) or status read, so
# there is an inherent DETECTION LAG WINDOW — tampering after the last
# anchored emit stays invisible until that next action. The anchor also lives
# beside the receipt stream under the same operator-controlled storage, so a
# writer who rewrites BOTH resets anchoring; equivocation proof against a
# collusive writer needs an external Transparency Service
# (raucle/transparency.py), which is out of scope for this local anchor.
_RECEIPT_ANCHOR_SUFFIX = ".head"
_RECEIPT_ANCHOR_VERSION = 1
_GENESIS_HEAD = "0" * 64


def _receipt_anchor_path(receipts_path: str | Path) -> Path:
    return Path(str(receipts_path) + _RECEIPT_ANCHOR_SUFFIX)


def _fold_stream_head(prev_head: str, receipt_hash: str) -> str:
    return hashlib.sha256((prev_head + receipt_hash).encode("ascii")).hexdigest()


def _compute_stream_head(path: Path) -> tuple[str, int]:
    """Recompute the anchored head over a receipt stream's receipt_hash values."""
    head = _GENESIS_HEAD
    count = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                receipt_hash = str(json.loads(line).get("receipt_hash", ""))
            except json.JSONDecodeError:
                receipt_hash = ""  # malformed line: folds as its absence
            head = _fold_stream_head(head, receipt_hash)
            count += 1
    return head, count


def _read_stream_anchor(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        anchor = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return anchor if isinstance(anchor, dict) else None


def _write_stream_anchor(receipts_path: str | Path) -> dict[str, Any]:
    """Anchor the current receipt stream: (count, stream_head), atomically."""
    path = Path(receipts_path)
    head, count = _compute_stream_head(path)
    anchor = {
        "anchor": "receipt_stream_head",
        "version": _RECEIPT_ANCHOR_VERSION,
        "count": count,
        "stream_head": head,
        "updated_at": _now_iso(),
    }
    anchor_path = _receipt_anchor_path(receipts_path)
    anchor_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = anchor_path.with_suffix(anchor_path.suffix + ".tmp")
    tmp.write_text(json.dumps(anchor, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, anchor_path)
    return anchor


def verify_receipt_stream_anchor(receipts_path: str | Path) -> dict[str, Any]:
    """Compare the containment receipt stream against its head anchor.

    Tamper is named under ``receipt_stream_gap``: ``missing_stream`` (the
    stream file was deleted), ``truncated_or_rewritten`` (count or head
    mismatch), or ``none`` when intact. Unanchored legacy streams report
    ``anchored: False`` — absence of an anchor is never a silent pass.
    """
    path = Path(receipts_path)
    anchor = _read_stream_anchor(_receipt_anchor_path(receipts_path))
    if anchor is None:
        return {"anchored": False, "receipt_stream_gap": "none", "receipts_present": path.exists()}
    gap = "none"
    if not path.exists():
        gap = "missing_stream"
    else:
        head, count = _compute_stream_head(path)
        if int(anchor.get("count", 0)) != count or str(anchor.get("stream_head", "")) != head:
            gap = "truncated_or_rewritten"
    return {
        "anchored": True,
        "receipt_stream_gap": gap,
        "receipts_present": path.exists(),
        "count": int(anchor.get("count", 0)),
        "stream_head": str(anchor.get("stream_head", "")),
    }


def _key_fingerprint(pem: bytes) -> str:
    """Operator keypair fingerprint: sha256 over the public-key PEM (RED-028)."""
    return hashlib.sha256(pem).hexdigest()


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

    def _operator_key_fingerprint(self) -> str:
        """The persistent operator keypair's fingerprint (RED-028 pin).

        Refuses without generating when the key file is MISSING while the
        state directory already holds a pubkey: that path is exactly the
        RED-028 re-anchor shape and the check must stay read-only (a
        failed resume must not mint a fresh anchor).
        """
        key_path = self.state_dir / _KEY_FILE
        if not key_path.exists() and (self.state_dir / _PUBKEY_FILE).exists():
            raise ContainmentError(
                f"operator keypair file '{key_path.name}' is missing while the "
                f"published pubkey remains; the quarantiner anchor moved "
                f"({_ERR_OPERATOR_KEY_CHANGED}) - resume refused (fail-closed)"
            )
        signer = self._operator_signer()
        return _key_fingerprint(signer.public_key_pem())

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
        # Anchor check first: the receipt stream must match its head anchor
        # before the next receipt is appended onto it. A gap (deletion /
        # truncation / rewrite since the last anchored emit) is refused under
        # its own name — operator/containment actions never append receipt
        # evidence onto an unanchored, silently-rewritten stream.
        integrity = verify_receipt_stream_anchor(self.config.receipts_path)
        if integrity["anchored"] and integrity["receipt_stream_gap"] != "none":
            raise ContainmentError(
                "receipt_stream_gap: containment receipt stream no longer matches "
                f"its anchored head ({integrity['receipt_stream_gap']}); the receipt "
                "evidence was tampered with between the last anchored emit and this "
                "action — resolve the gap before issuing further containment receipts"
            )
        if not integrity["anchored"] and Path(self.config.receipts_path).exists():
            # Legacy (pre-anchor) stream: adopt it as anchored on first emit.
            _write_stream_anchor(self.config.receipts_path)
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
        # Re-anchor immediately after the append: the head anchor now covers
        # the new receipt too, shrinking the detection lag window to the gap
        # between this emit and the next operator/containment action.
        _write_stream_anchor(self.config.receipts_path)
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
            # RED-028: pin the operator keypair fingerprint at hold REQUEST
            # time so a later re-anchor is detectable at apply/resume time.
            operator_key_fingerprint = self._operator_key_fingerprint()
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
                    "operator_key_fingerprint": operator_key_fingerprint,
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
                        "operator_key_fingerprint": operator_key_fingerprint,
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
                "operator_key_fingerprint": operator_key_fingerprint,
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

    def _assert_pending_operator_fingerprint(self, pending: dict[str, Any]) -> None:
        """RED-028: a hold apply that rides a pending record re-checks the pin
        minted at request time; the anchor must not have moved in between
        (else the approvals were receipted under another key)."""
        pending_fp = str(pending.get("operator_key_fingerprint", ""))
        if pending_fp and pending_fp != self._operator_key_fingerprint():
            raise ContainmentError(
                f"operator keypair fingerprint changed since the hold "
                f"request ({_ERR_OPERATOR_KEY_CHANGED}): the pending "
                "approvals were receipted under a different anchor; "
                "apply refused (fail-closed)"
            )

    def _hold_apply_receipt_extra(
        self,
        scope: str,
        scope_id: str,
        actor: str,
        reason: str,
        target: Path,
        original_sha: str,
        ids: list[str],
        operator_key_fingerprint: str,
        pending: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Receipt payload for a hold: v0 core keys plus quorum provenance
        (approvers, M, and the pending receipt id) when riding a pending."""
        extra: dict[str, Any] = {
            "scope": scope,
            "scope_id": scope_id,
            "actor": actor,
            "reason": reason,
            "target_file": str(target),
            "sha256_before": original_sha,
            "revoked_ids": ids if scope != SCOPE_GLOBAL else [],
            "operator_key_fingerprint": operator_key_fingerprint,
        }
        if pending is not None:
            # Quorum provenance rides the hold receipt: every approver
            # that receipted the pending hold, and the pending
            # receipt that opened it.
            extra["approvers"] = list(pending.get("approvers", []))
            extra["min_approvers"] = int(pending.get("min_approvers", self.config.min_approvers))
            extra["pending_receipt_id"] = pending.get("pending_receipt_id", "")
        return extra

    def _hold_apply_held_state(
        self,
        scope: str,
        scope_id: str,
        actor: str,
        reason: str,
        target: Path,
        original_sha: str,
        original: bytes,
        ids: list[str],
        operator_key_fingerprint: str,
        receipt_id: str,
        pending: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Persisted held-state record for a hold (v0 core + quorum keys)."""
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
            "operator_key_fingerprint": operator_key_fingerprint,
        }
        if pending is not None:
            held_state["approvers"] = list(pending.get("approvers", []))
            held_state["min_approvers"] = int(
                pending.get("min_approvers", self.config.min_approvers)
            )
        return held_state

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

            # RED-028: a hold apply that rides a pending record re-checks
            # the pin minted at request time (fail-closed on drift).
            if pending is not None:
                self._assert_pending_operator_fingerprint(pending)
            operator_key_fingerprint = self._operator_key_fingerprint()

            original_sha = _sha256_bytes(original)
            if scope == SCOPE_GLOBAL:
                held_bytes = self._deny_all_policy_bytes(original)
                self._write_atomic(target, held_bytes)
            else:
                self._append_revocations(target, ids, reason=reason, actor=actor)

            extra = self._hold_apply_receipt_extra(
                scope,
                scope_id,
                actor,
                reason,
                target,
                original_sha,
                ids,
                operator_key_fingerprint,
                pending,
            )
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

            held_state = self._hold_apply_held_state(
                scope,
                scope_id,
                actor,
                reason,
                target,
                original_sha,
                original,
                ids,
                operator_key_fingerprint,
                receipt_id,
                pending,
            )
            self._write_atomic(
                self.state_path,
                json.dumps(held_state, sort_keys=True).encode("utf-8"),
            )
            if scope != SCOPE_GLOBAL and self.config.delegations_file:
                # M-026 (RED-026 / AV-02): publish the hold INTO the delegation
                # ledger so registrations made during the hold consult active
                # hold state at mint/registration time (fail-closed named
                # hold_active) instead of relying on the hold-time id snapshot.
                self._append_hold_marker(
                    {
                        "kind": "containment_hold_active",
                        "scope": scope,
                        "scope_id": scope_id,
                        "receipt_id": receipt_id,
                        "revocations_path": str(target),
                        "actor": actor,
                        "held_at": _now_iso(),
                    }
                )
            held_result: dict[str, Any] = {
                "status": "held",
                "scope": scope,
                "scope_id": scope_id,
                "target_file": str(target),
                "receipt_id": receipt_id,
                "revoked_ids": ids if scope != SCOPE_GLOBAL else [],
                "operator_key_fingerprint": operator_key_fingerprint,
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

    def _append_hold_marker(self, marker: dict[str, Any]) -> None:
        """Append a containment control row to the delegation ledger.

        Best-effort co-op with the ledger's own appender: a control row is
        never a capability, so no resolver misreads it. Marker failure is
        NOT swallowed (state already persisted - the marker must exist or
        the transition is incomplete), but a missing ledger surface just
        disables the registration-time consult for that hold.
        """
        if not self.config.delegations_file:
            return
        path = Path(self.config.delegations_file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(marker, ensure_ascii=False) + "\n")
        except OSError as exc:
            if marker.get("kind") == "containment_hold_active":
                raise ContainmentError(
                    f"containment hold marker append failed; hold incomplete: {exc}"
                ) from exc

    def _refuse_restamped_resume(self, state: dict[str, Any], target: Path) -> dict[str, Any]:
        """Named, RECEIPTED refusal of a re-stamped snapshot (M-027).

        The halt stays applied, the enforcement bytes are untouched
        (the held deny set stays live), and the refusal itself is a
        receipt so the attempted re-commit is never silent.
        """
        try:
            receipt_id = self._emit_receipt(
                verdict=VERDICT_RESUME_REFUSED,
                description=f"containment:resume_refused:{state['scope']}",
                extra={
                    "scope": state["scope"],
                    "scope_id": state.get("scope_id", ""),
                    "reason": "snapshot_restamped",
                    "target_file": str(target),
                    "state_snapshot_sha256": state.get("original_sha256", ""),
                    "hold_receipt_id": state.get("receipt_id", ""),
                },
            )
        # The receipt error must be named, never silent.
        except Exception as exc:  # noqa: BLE001
            raise ContainmentError(
                f"resume-refusal receipt emission failed; resume refused: {exc}"
            ) from exc
        return {
            "status": "resume_refused",
            "reason": "snapshot_restamped",
            "held": True,
            "scope": state["scope"],
            "scope_id": state.get("scope_id", ""),
            "target_file": str(target),
            "receipt_id": receipt_id,
        }

    def _hold_receipt_extra(self, state: dict[str, Any]) -> dict[str, Any]:
        """Return the claim-set ``extra`` of the RECEIPTED hold (M-027).

        The hold receipt binding is the authority for what the snapshot
        was: resume must refuse a state whose receipt cannot be found or
        decoded (fail-closed), never guess from state alone.
        """
        receipt_id = str(state.get("receipt_id", ""))
        if not receipt_id:
            raise ContainmentError(
                "resume refused: held state carries no hold receipt id; "
                "the snapshot cannot be bound to a receipt (fail-closed)"
            )
        receipts_path = Path(self.config.receipts_path or "")
        if not receipts_path.name or not receipts_path.is_file():
            raise ContainmentError(
                f"resume refused: hold receipt stream '{receipts_path}' "
                "unavailable; the snapshot cannot be bound to a receipt "
                "(fail-closed)"
            )
        try:
            rows = [
                json.loads(line)
                for line in receipts_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except (OSError, ValueError) as exc:
            raise ContainmentError(
                f"resume refused: hold receipt stream unreadable: {exc}"
            ) from exc
        row = next((r for r in rows if str(r.get("receipt_hash", "")) == receipt_id), None)
        if row is None:
            raise ContainmentError(
                f"resume refused: hold receipt '{receipt_id[:16]}...' is not in "
                "the receipt stream; the snapshot cannot be bound to a receipt "
                "(fail-closed)"
            )
        jws = str(row.get("jws", ""))
        parts = jws.split(".")
        if len(parts) != 3:
            raise ContainmentError("resume refused: hold receipt JWS is malformed (fail-closed)")
        try:
            payload = json.loads(
                base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)).decode("utf-8")
            )
        except ValueError as exc:  # UnicodeDecodeError is a ValueError subclass
            raise ContainmentError(
                f"resume refused: hold receipt payload undecodable: {exc}"
            ) from exc
        extra = payload.get("extra")
        if not isinstance(extra, dict):
            raise ContainmentError(
                "resume refused: hold receipt carries no claim set (fail-closed)"
            )
        return extra

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
            # RED-028: the quarantiner anchor is pinned at hold-request time;
            # a keypair swap after the hold must surface as a NAMED refusal
            # (operator_key_changed), never a silent re-anchor.
            pinned_fp = str(state.get("operator_key_fingerprint", ""))
            if not pinned_fp:
                raise ContainmentError(
                    f"held state predates operator keypair pinning "
                    f"({_ERR_OPERATOR_KEY_UNPINNED}): the anchor cannot be "
                    "verified out of band; resume refused (fail-closed) — "
                    "re-establish the pin with a fresh resumeable hold"
                )
            current_fp = self._operator_key_fingerprint()
            if current_fp != pinned_fp:
                raise ContainmentError(
                    f"operator keypair fingerprint changed since the hold "
                    f"request ({_ERR_OPERATOR_KEY_CHANGED}): the quarantiner "
                    "anchor moved out of band; resume refused (fail-closed)"
                )
            # M-027 (RED-027 / AV-10): the digest check above is
            # integrity-only - a state-file writer who re-stamps
            # ``original_bytes_b64`` together with ``original_sha256``
            # sails through it. So the SNAPSHOT is additionally bound to
            # the RECEIPTED hold: the hold receipt carries the snapshot
            # digest, and resume refuses any state whose snapshot does
            # not match the receipt (fail-closed, named
            # ``snapshot_restamped``). The refusal is receipted and the
            # halt stays applied: no attacker bytes are ever restored.
            receipt_extra = self._hold_receipt_extra(state)
            receipt_snapshot = str(receipt_extra.get("sha256_before", ""))
            scope_matches = str(receipt_extra.get("scope", "")) == str(state.get("scope", ""))
            if receipt_snapshot != expected or not scope_matches:
                return self._refuse_restamped_resume(state, target)
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
                        "operator_key_fingerprint": current_fp,
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
            if state.get("scope") != SCOPE_GLOBAL:
                # M-026 (RED-026 / AV-02): release the registration-time
                # hold consult, so authority minted AFTER the resume is
                # no longer snapped into the released hold's deny set.
                self._append_hold_marker(
                    {
                        "kind": "containment_resume",
                        "scope": state["scope"],
                        "scope_id": state.get("scope_id", ""),
                        "hold_receipt_id": state.get("receipt_id", ""),
                        "resume_receipt_id": receipt_id,
                        "actor": actor,
                        "released_at": _now_iso(),
                    }
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
            **self._receipt_integrity_fields(),
        }

    def _receipt_integrity_fields(self) -> dict[str, Any]:
        """Receipt-stream anchor status for ``status()`` report payloads.

        Unanchored legacy streams report ``receipt_integrity: null`` — no
        silent claim in either direction. When the anchored stream no longer
        matches (deleted / truncated / rewritten since the last anchored
        emit), the tamper is reported under its own name
        (``receipt_stream_gap``) with ``receipt_integrity: False``; this is
        the documented detection-lag window, evaluated as of this call.
        """
        integrity = verify_receipt_stream_anchor(self.config.receipts_path)
        if not integrity["anchored"]:
            return {"receipt_integrity": None, "receipt_stream_integrity": "unanchored"}
        gap = integrity["receipt_stream_gap"]
        return {
            "receipt_integrity": gap == "none",
            "receipt_stream_integrity": "receipt_stream_gap" if gap != "none" else "intact",
            "receipt_stream_erased": gap == "missing_stream" or None,
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
