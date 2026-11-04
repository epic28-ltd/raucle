"""One-time canary mint/verify service (P1.3a).

Each exfil-test run mints a canary that is issued as a real raucle
agent credential, so issuance and denial are receipted through the
same machinery the gateway already records.  The run's success is
claimed only when the canary value is later presented at an egress
point or surfaces in the receipt stream, where ``observe`` verifies
it against the outstanding mints.

Semantics:

- ``mint`` issues a fresh one-time ``rak_`` credential via the existing
  :class:`~raucle.agent_credentials.AgentCredentialStore` (stored
  hashed, shown once) and records the mint in a JSONL ledger plus an
  issuance receipt.
- ``observe`` verifies a presented value against the ledger.  Unknown,
  revoked and already-consumed values are denied and every denial is
  receipted.  A canary verifies exactly once: after a successful
  observation it is consumed and can never verify again.
- The verdict is deterministic and byte-comparable: the same inputs
  always produce identical verdict bytes (canonical JSON, sorted
  keys, no wall-clock stamps).  Mint-time and observed-at are
  recorded, but only in the richer verdict object and the receipt
  stream, never inside the comparable bytes.

No model is in the path: the whole service is hashing, JSON and file
IO.  The egress sink wiring itself is story P1.3b; this module
provides the observation API only.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from raucle.agent_credentials import AgentCredentialStore

_CANARY_ID_PREFIX = "canary:"
_KEY_FINGERPRINT_LEN = 16

# Stable reason codes: they appear inside the byte-comparable verdict,
# so they are free text never, codes always.
REASON_OBSERVED = "observed"
REASON_UNKNOWN = "denied:unknown-canary"
REASON_REVOKED = "denied:credential-revoked"
REASON_REPLAYED = "denied:already-consumed"

_STATUS_OBSERVED = "observed"
_STATUS_DENIED = "denied"


@dataclass
class CanaryMint:
    """A freshly minted one-time canary."""

    mint_id: str
    """Unique id for this mint (also the credential's agent id)."""

    value: str
    """The canary value. Shown exactly once, stored only as a hash."""

    run_id: str
    """Caller-supplied run identifier the canary is tied to."""

    minted_at: float
    """Unix timestamp (seconds) of the mint."""

    key_fingerprint: str
    """Short fingerprint of the credential, safe to log and compare."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "mint_id": self.mint_id,
            "run_id": self.run_id,
            "minted_at": self.minted_at,
            "key_fingerprint": self.key_fingerprint,
        }


@dataclass
class CanaryVerdict:
    """Result of presenting a canary value for observation."""

    status: str
    """``observed`` or ``denied``."""

    reason: str
    """Stable code, e.g. ``observed`` or ``denied:already-consumed``."""

    mint_id: str
    """Mint id when known, empty string otherwise."""

    run_id: str
    """Run id when known, empty string otherwise."""

    key_fingerprint: str
    """Credential fingerprint when known, empty string otherwise."""

    minted_at: float
    """Mint time when known, 0.0 otherwise. Excluded from the bytes."""

    observed_at: float
    """Time of this observation. Excluded from the bytes."""

    def observed(self) -> bool:
        return self.status == _STATUS_OBSERVED

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "mint_id": self.mint_id,
            "run_id": self.run_id,
            "key_fingerprint": self.key_fingerprint,
            "minted_at": self.minted_at,
            "observed_at": self.observed_at,
        }

    def verdict_bytes(self) -> bytes:
        """Deterministic, byte-comparable verdict bytes.

        Same inputs always produce identical bytes: canonical JSON,
        sorted keys, and only the deterministic fields.  Wall-clock
        stamps (``minted_at`` included here as a mint-fixed value, and
        ``observed_at`` never) are kept out of the comparison path.
        """
        payload = {
            "key_fingerprint": self.key_fingerprint,
            "mint_id": self.mint_id,
            "reason": self.reason,
            "run_id": self.run_id,
            "status": self.status,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class _LedgerEntry:
    key_hash: str
    minted_at: float
    run_id: str
    mint_id: str = ""
    consumed_at: float | None = field(default=None)


def _now() -> float:
    return time.time()


def _fingerprint(key_hash: str) -> str:
    return key_hash[:_KEY_FINGERPRINT_LEN]


def _append_receipt(path: Path, receipt: dict[str, Any]) -> None:
    """Append one receipt line. Receipts are append-only by design."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(receipt, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


class CanaryService:
    """Mint one-time canary credentials and observe their appearance."""

    def __init__(
        self,
        credential_store: AgentCredentialStore,
        *,
        ledger_path: str | Path,
        receipts_path: str | Path,
    ) -> None:
        self._creds = credential_store
        self._ledger_path = Path(ledger_path)
        self._receipts_path = Path(receipts_path)
        self._entries: dict[str, _LedgerEntry] = {}  # keyed by key_hash
        self._load()

    # ------------------------------------------------------------------
    # Mint
    # ------------------------------------------------------------------

    def mint(self, run_id: str) -> CanaryMint:
        """Issue a one-time canary credential tied to *run_id*.

        The canary value is a real ``rak_`` agent credential issued
        through the existing store, so denial of the credential later
        on is recorded exactly as for any other agent credential.  An
        issuance receipt is written regardless.
        """
        mint_id = f"{_CANARY_ID_PREFIX}{secrets.token_hex(8)}"
        value = self._creds.issue(agent_id=mint_id)
        key_hash = hashlib.sha256(value.encode("ascii")).hexdigest()
        minted_at = _now()
        self._entries[key_hash] = _LedgerEntry(
            key_hash=key_hash, minted_at=minted_at, run_id=run_id, mint_id=mint_id
        )
        self._persist()
        _append_receipt(
            self._receipts_path,
            {
                "event": "canary.mint",
                "ts": minted_at,
                "mint_id": mint_id,
                "run_id": run_id,
                "key_fingerprint": _fingerprint(key_hash),
            },
        )
        return CanaryMint(
            mint_id=mint_id,
            value=value,
            run_id=run_id,
            minted_at=minted_at,
            key_fingerprint=_fingerprint(key_hash),
        )

    # ------------------------------------------------------------------
    # Observe
    # ------------------------------------------------------------------

    def observe(self, value: str, *, at: float | None = None) -> CanaryVerdict:
        """Verify a presented canary value against outstanding mints.

        One-time semantics: the first observation that finds an active,
        unconsumed mint consumes it and returns ``observed``.  Every
        other presentation - unknown value, revoked credential, replay
        of a consumed canary - is denied and receipted.  ``at`` exists
        for deterministic tests; production callers omit it.
        """
        observed_at = _now() if at is None else at
        key_hash = self._hash_value(value)
        entry = self._entries.get(key_hash) if key_hash else None

        if entry is None or key_hash is None:
            return self._deny(
                value_presented=bool(value),
                reason=REASON_UNKNOWN,
                mint_id="",
                run_id="",
                key_fingerprint="",
                observed_at=observed_at,
            )

        mint_id = self._creds.verify(value) if value else None
        if mint_id is None:
            return self._deny(
                value_presented=True,
                reason=REASON_REVOKED,
                mint_id=entry.mint_id,
                run_id=entry.run_id,
                key_fingerprint=_fingerprint(key_hash),
                observed_at=observed_at,
            )

        if entry.consumed_at is not None:
            return self._deny(
                value_presented=True,
                reason=REASON_REPLAYED,
                mint_id=mint_id,
                run_id=entry.run_id,
                key_fingerprint=_fingerprint(key_hash),
                observed_at=observed_at,
            )

        entry.consumed_at = observed_at
        self._persist()
        _append_receipt(
            self._receipts_path,
            {
                "event": "canary.observe",
                "ts": observed_at,
                "mint_id": mint_id,
                "run_id": entry.run_id,
                "key_fingerprint": _fingerprint(key_hash),
                "status": _STATUS_OBSERVED,
            },
        )
        return CanaryVerdict(
            status=_STATUS_OBSERVED,
            reason=REASON_OBSERVED,
            mint_id=mint_id,
            run_id=entry.run_id,
            key_fingerprint=_fingerprint(key_hash),
            minted_at=entry.minted_at,
            observed_at=observed_at,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _hash_value(self, value: str) -> str | None:
        if not value or not isinstance(value, str):
            return None
        return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()

    def _deny(
        self,
        *,
        value_presented: bool,
        reason: str,
        mint_id: str,
        run_id: str,
        key_fingerprint: str,
        observed_at: float,
    ) -> CanaryVerdict:
        if value_presented:
            _append_receipt(
                self._receipts_path,
                {
                    "event": "canary.deny",
                    "ts": observed_at,
                    "mint_id": mint_id,
                    "run_id": run_id,
                    "key_fingerprint": key_fingerprint,
                    "reason": reason,
                    "status": _STATUS_DENIED,
                },
            )
        return CanaryVerdict(
            status=_STATUS_DENIED,
            reason=reason,
            mint_id=mint_id,
            run_id=run_id,
            key_fingerprint=key_fingerprint,
            minted_at=0.0,
            observed_at=observed_at,
        )

    def _load(self) -> None:
        if not self._ledger_path.exists():
            return
        text = self._ledger_path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"canary ledger {self._ledger_path} is corrupt (line {lineno}: "
                    f"{exc}); refusing to reset - restoring it would resurrect "
                    f"consumed canaries and break one-time semantics"
                ) from exc
            if not isinstance(rec, dict) or "key_hash" not in rec or "minted_at" not in rec:
                raise ValueError(
                    f"canary ledger {self._ledger_path} is corrupt (line {lineno}: "
                    f"not a mint record); refusing to reset"
                )
            self._entries[rec["key_hash"]] = _LedgerEntry(
                key_hash=rec["key_hash"],
                minted_at=float(rec["minted_at"]),
                run_id=str(rec.get("run_id", "")),
                mint_id=str(rec.get("mint_id", "")),
                consumed_at=(
                    float(rec["consumed_at"]) if rec.get("consumed_at") is not None else None
                ),
            )

    def _persist(self) -> None:
        """Write the ledger atomically (temp file + rename)."""
        self._ledger_path.parent.mkdir(parents=True, exist_ok=True)
        records = [
            {
                "key_hash": e.key_hash,
                "minted_at": e.minted_at,
                "run_id": e.run_id,
                "mint_id": e.mint_id,
                "consumed_at": e.consumed_at,
            }
            for e in sorted(self._entries.values(), key=lambda e: (e.minted_at, e.key_hash))
        ]
        payload = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)
        fd, tmp = tempfile.mkstemp(
            dir=str(self._ledger_path.parent), prefix=".canary-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._ledger_path)
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
