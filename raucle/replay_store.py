"""The handshake replay store (Q10, a second external review of the main branch, P0).

Replay detection for ``raucle.handshake.accept_call`` used to be an OPTIONAL,
process-local ``seen`` set: it vanished on restart, was invisible to other
processes serving the same responder, and its check-then-insert was not atomic
under concurrency. The :class:`ReplayStore` interface replaces it: production
replay protection is a required, persistent, atomic check-and-insert.

The interface is deliberately tiny:

* ``consume(replay_key) -> bool`` is ATOMIC: exactly one caller wins the check
  and insert no matter how many threads or processes race; every other caller
  gets ``False`` and the request is refused as a replay.
* Implementations MUST persist across restarts: a nonce consumed for a request
  whose handling then crashed is refused after a restart too, so a crash can
  never turn into a second execution.
* Implementations MUST retain every consumed key at least as long as the
  longest capability token TTL the deployment mints, so a replay of an
  old-but-still-valid token is caught. Configure ``retention_seconds`` to at
  least that TTL, or keep the retain-forever default.

The default implementation (:class:`SqliteReplayStore`) follows the repo's
receipt-index sqlite idiom (WAL, autocommit) and enforces uniqueness with a
DATABASE constraint (the primary key), not application-level set membership.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)


def _now() -> int:
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp())


@runtime_checkable
class ReplayStore(Protocol):
    """The contract ``accept_call`` requires for replay protection.

    ``consume(replay_key)`` returns True when THIS call is the first handler
    of the key (the key is recorded atomically as a side effect) and False
    when the key was already consumed. The consume happens BEFORE any gate
    decision is recorded, and the signed ack receipt is the proof of the
    unique handling.
    """

    def consume(self, replay_key: str) -> bool: ...


class SqliteReplayStore:
    """File-backed :class:`ReplayStore` on the receipt-index sqlite idiom.

    One row per consumed replay key; the primary key IS the uniqueness
    constraint. A second consumer of the same key (same thread, another
    thread, or another process through WAL) hits the constraint and gets
    ``False``. Rows persist across restarts; retention is an explicit
    operator opt-in (``retention_seconds``, in practice the max token TTL)
    and nothing is forgotten without it.
    """

    _TABLE_SQL = """
        CREATE TABLE IF NOT EXISTS replay_nonces (
            replay_key  TEXT PRIMARY KEY,
            consumed_at INTEGER NOT NULL
        )
    """

    def __init__(self, path: str | Path, *, retention_seconds: int | None = None) -> None:
        self._path = Path(path)
        parent = self._path.parent
        if str(parent):
            parent.mkdir(parents=True, exist_ok=True)
        self._retention_seconds = retention_seconds
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(self._TABLE_SQL)
        # Transactions are per-CONNECTION in sqlite, so the shared
        # connection serialises its own BEGIN..COMMIT with a lock (the
        # sqlite3 docs hand cross-thread serialisation to the caller when
        # check_same_thread=False). Cross-process serialisation is the
        # database's write lock (WAL + busy_timeout).
        self._lock = threading.Lock()

    def consume(self, replay_key: str) -> bool:
        """Atomic check-and-insert: True for the first consumer, False for
        every replay, decided by the database's uniqueness constraint.

        The insert runs inside BEGIN IMMEDIATE: writers serialise on the
        write lock, so a concurrent consumer of the same key reads the first
        consumer's committed row and hits the primary key (never a lock
        race that could double-accept)."""
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._conn.execute(
                    "INSERT INTO replay_nonces (replay_key, consumed_at) VALUES (?, ?)",
                    (replay_key, _now()),
                )
            except sqlite3.IntegrityError as exc:
                with contextlib.suppress(sqlite3.Error):
                    self._conn.execute("ROLLBACK")
                if getattr(exc, "sqlite_errorname", "") in {
                    "SQLITE_CONSTRAINT_PRIMARYKEY",
                    "SQLITE_CONSTRAINT_UNIQUE",
                }:
                    return False
                raise
            except sqlite3.Error:
                with contextlib.suppress(sqlite3.Error):
                    self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")
        self._sweep_expired()
        return True

    def _sweep_expired(self) -> None:
        """Drop rows past the configured retention window (no-op when
        retention is not configured; the safe default forgets nothing)."""
        if self._retention_seconds is None:
            return
        try:
            with self._lock:
                self._conn.execute(
                    "DELETE FROM replay_nonces WHERE consumed_at <= ?",
                    (_now() - self._retention_seconds,),
                )
        except sqlite3.Error:
            logger.warning(
                "replay store retention sweep failed at %s; consumed keys are kept",
                self._path,
            )

    def purge_expired(self, *, older_than_seconds: int | None = None) -> int:
        """Operator-facing retention sweep. Returns the number of rows purged.

        Without an argument the configured retention window applies; a store
        built with neither a retention window nor an explicit
        ``older_than_seconds`` refuses: forgetting nonces is never silent.
        """
        cutoff = older_than_seconds if older_than_seconds is not None else self._retention_seconds
        if cutoff is None:
            raise ValueError(
                "purge_expired requires older_than_seconds when the store has no "
                "retention window; a replay key must not be forgotten silently"
            )
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM replay_nonces WHERE consumed_at <= ?", (_now() - cutoff,)
            )
        return cursor.rowcount

    def close(self) -> None:
        self._conn.close()


__all__ = ["ReplayStore", "SqliteReplayStore"]
