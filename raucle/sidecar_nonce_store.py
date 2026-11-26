"""Submit anti-replay for the X3 receipt sidecar (issue #340, ADR 0008 section 5).

The sidecar's ``POST /submit`` handshake previously authenticated each
request with an HMAC over a fresh nonce, but never persisted the nonce:
a captured valid submit could be replayed verbatim and append a second
envelope. This module closes that on the contract ADR 0008 section 5
drew: the HMAC request nonce is now a persisted, bounded-lifetime
request identifier with the exact request-body digest bound to it.

Why this builds on the existing replay store machinery instead of
forking a second mechanism: this store follows the
``raucle.replay_store.SqliteReplayStore`` idiom exactly (file-backed
SQLite on the receipt-index pattern, WAL, ``busy_timeout``, a primary
key as the uniqueness constraint, ``BEGIN IMMEDIATE`` serialisation,
retain-forever default, explicit operator purge, storage errors
propagate). The existing ``ReplayStore.consume(replay_key) -> bool``
interface alone cannot serve the sidecar because the duplicate decision
needs payload binding in the SAME atomic step:

* the same nonce over the same body is the named duplicate answer
  (``first_receipt_hash`` of the first acceptance), not a second
  acceptance and not another append;
* the same nonce over a different body must be refused as a mismatch,
  which a key-value ``consume`` cannot tell apart from any other
  already-consumed key.

Scope and honesty contract:

* SQLite-backed and single-host only. One file, one writer (the sidecar
  is deliberately the single writer per chain). It is a separate
  namespace from handshake replay keys: handshake nonces live in
  ``replay_nonces`` tables of ``SqliteReplayStore`` instances
  (``key_id:token_id:nonce``), never in this file, and submit nonces
  never enter a replay store.
* A multi-host shared replay backend (PostgreSQL unique-constraint
  transactions) is a named follow-up slice requiring a deployment
  decision (ADR 0008 section 3). No multi-host, multi-writer,
  multi-region or exactly-once claim is made by this module.
* Expiry is the clock-skew window: a request is acceptable only while
  its signed sent-at timestamp lies within ``skew_seconds`` of the
  sidecar clock. Retention is how long consumed nonce records (and
  therefore the named duplicate answer) are kept; the default keeps
  records forever. If a bounded retention is configured it must be at
  least twice the skew window: a replay of a captured request is then
  refused either as a duplicate (nonce still retained) or as stale
  (sent-at now outside the skew window, and the timestamp is under the
  HMAC so it cannot be refreshed by an attacker), never as a second
  first acceptance.
* Claim-before-enqueue is at-most-once ingest, honestly: a crash or a
  named enqueue/write failure after the nonce is consumed does not
  re-accept the same request identity on retry; it is recorded by name
  on the refusal path instead. This is at-most-once handling, never an
  exactly-once claim.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import logging
import re
import sqlite3
import threading
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger(__name__)

#: Nonces are lowercase hex, 16 to 128 characters (8 to 64 random bytes).
_NONCE_RE = re.compile(r"^[0-9a-f]{16,128}$")
#: sha256 body digests are exactly 64 lowercase hex characters.
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
#: The envelope receipt hash shape, shared with the sidecar's validation.
_RECEIPT_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _now() -> int:
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp())


class SubmitNonceDecision(NamedTuple):
    """The atomic outcome of one ``POST /submit`` nonce check.

    ``outcome`` is ``first`` (this request identity is newly recorded),
    ``duplicate`` (same nonce and same body already accepted; never a
    second acceptance) or ``mismatch`` (same nonce, different body).
    ``first_receipt_hash`` is the receipt hash of the first acceptance;
    for ``first`` it is this request's own receipt hash.
    """

    outcome: str
    first_receipt_hash: str


class SidecarSubmitNonceStore:
    """Persistent, atomic nonce store for sidecar submit anti-replay.

    One SQLite file per sidecar chain (default
    ``<store_dir>/submit_nonces.sqlite``), one row per consumed nonce.
    The primary key is the uniqueness constraint; ``consume`` decides
    inside one ``BEGIN IMMEDIATE`` transaction, so a concurrent
    duplicate (same thread, another thread of the
    ``ThreadingHTTPServer``, or another process through WAL) either sees
    the committed row or inserts the first one, never both.
    """

    _TABLE_SQL = """
        CREATE TABLE IF NOT EXISTS submit_nonces (
            nonce        TEXT PRIMARY KEY,
            body_digest  TEXT NOT NULL,
            receipt_hash TEXT NOT NULL,
            consumed_at  INTEGER NOT NULL
        )
    """

    def __init__(
        self,
        path: str | Path,
        *,
        skew_seconds: int = 300,
        retention_seconds: int | None = None,
    ) -> None:
        if skew_seconds < 1:
            raise ValueError("skew_seconds must be a positive number of seconds")
        if retention_seconds is not None and retention_seconds < 2 * skew_seconds:
            raise ValueError(
                "retention_seconds must be at least twice the clock-skew window "
                f"({2 * skew_seconds} s here): within retention a replay is refused "
                "as a duplicate, beyond it only the HMAC-bound sent-at window "
                "still refuses it, so a shorter retention forgets too early"
            )
        self._path = Path(path)
        parent = self._path.parent
        if str(parent):
            parent.mkdir(parents=True, exist_ok=True)
        self._skew_seconds = int(skew_seconds)
        self._retention_seconds = retention_seconds
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(self._TABLE_SQL)
        # Cross-thread serialisation on the single connection is the
        # connection lock, exactly as in SqliteReplayStore: transactions
        # are per-connection, so BEGIN..COMMIT serialises under the lock,
        # and cross-process ordering is the database write lock.
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def skew_seconds(self) -> int:
        return self._skew_seconds

    def consume(self, nonce: str, body_digest: str, receipt_hash: str) -> SubmitNonceDecision:
        """Atomically check-and-record one submit's request identity.

        ``first`` inserts the row; ``duplicate`` and ``mismatch`` leave
        the row untouched and report the first acceptance. Any SQLite
        failure rolls the transaction back and propagates: the caller
        must refuse the submit (fail closed), never enqueue without a
        decided nonce.
        """
        if not _NONCE_RE.fullmatch(nonce or ""):
            raise ValueError("nonce must be 16 to 128 lowercase hex characters")
        if not _DIGEST_RE.fullmatch(body_digest or ""):
            raise ValueError("body_digest must be a sha256 hex digest")
        if not _RECEIPT_HASH_RE.fullmatch(receipt_hash or ""):
            raise ValueError("receipt_hash must be sha256:<64 hex characters>")
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                row = self._conn.execute(
                    "SELECT body_digest, receipt_hash FROM submit_nonces WHERE nonce = ?",
                    (nonce,),
                ).fetchone()
                if row is not None:
                    self._conn.execute("COMMIT")
                    first_receipt_hash = str(row[1])
                    if str(row[0]) == body_digest:
                        return SubmitNonceDecision("duplicate", first_receipt_hash)
                    return SubmitNonceDecision("mismatch", first_receipt_hash)
                self._conn.execute(
                    "INSERT INTO submit_nonces (nonce, body_digest, receipt_hash, consumed_at)"
                    " VALUES (?, ?, ?, ?)",
                    (nonce, body_digest, receipt_hash, _now()),
                )
                self._conn.execute("COMMIT")
            except sqlite3.Error:
                with contextlib.suppress(sqlite3.Error):
                    self._conn.execute("ROLLBACK")
                raise
        self._sweep_expired()
        return SubmitNonceDecision("first", receipt_hash)

    def _sweep_expired(self) -> None:
        """Drop rows past the configured retention window (no-op when
        retention is not configured; the safe default forgets nothing)."""
        if self._retention_seconds is None:
            return
        try:
            with self._lock:
                self._conn.execute(
                    "DELETE FROM submit_nonces WHERE consumed_at <= ?",
                    (_now() - self._retention_seconds,),
                )
        except sqlite3.Error:
            logger.warning(
                "submit nonce store retention sweep failed at %s; consumed nonces are kept",
                self._path,
            )

    def purge_expired(self, *, older_than_seconds: int | None = None) -> int:
        """Operator-facing retention sweep. Returns the number of rows purged.

        Without an argument the configured retention window applies; a
        store built with neither a retention window nor an explicit
        ``older_than_seconds`` refuses: forgetting nonces is never
        silent.
        """
        cutoff = older_than_seconds if older_than_seconds is not None else self._retention_seconds
        if cutoff is None:
            raise ValueError(
                "purge_expired requires older_than_seconds when the store has no "
                "retention window; a consumed submit nonce must not be forgotten silently"
            )
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM submit_nonces WHERE consumed_at <= ?", (_now() - cutoff,)
            )
        return cursor.rowcount

    def count(self) -> int:
        """Rows currently retained (diagnostics and tests only)."""
        with self._lock:
            cursor = self._conn.execute("SELECT COUNT(*) FROM submit_nonces")
            row = cursor.fetchone()
        return int(row[0]) if row is not None else 0

    def close(self) -> None:
        self._conn.close()


__all__ = ["SidecarSubmitNonceStore", "SubmitNonceDecision"]
