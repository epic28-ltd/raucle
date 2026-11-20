"""Receipt index: a SQLite projection over the receipt chain.

PR-C Task C1. The chain of record (segmented JSONL) stays the tamper-evident
truth. The index exists only to answer queries fast: by agent, tool,
decision, time range, trace id, with cursor pagination, and to walk receipt
ancestry (``parents``) without scanning files.

Design contract, enforced by tests:

- The index is a QUERY CACHE. It can be dropped and rebuilt from the
  segments at any time (``rebuild_from_store``); tampering with it changes
  query answers but never the chain, and a rebuild repairs it.
- Verification NEVER consults the index; it reads the chain.
- WAL mode with one writer thread and concurrent readers (matching the
  gateway's single-writer design); ``busy_timeout`` smooths lock races.
- Crash-resilience (J2): schema migration runs as ONE transaction, and
  open first inspects for - and deterministically repairs - the
  half-migrated state an interrupted migration leaves behind. A
  rebuildable projection must never crash-loop a boot.
"""

from __future__ import annotations

import base64
import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


# The live projection table (schema v3). One column list and one CREATE
# literal shared by the fresh path, the v1/v2 -> v3 migration and the
# mid-migration crash recovery, so the three can never drift apart.
_RECEIPTS_COLUMNS = (
    "receipt_hash",
    "iat",
    "agent_id",
    "tool",
    "decision",
    "reason",
    "policy",
    "latency_us",
    "trace_id",
    "session_id",
    "acting_for",
    "source",
    "destination",
    "parents_json",
    "segment",
    "line_no",
)

_RECEIPTS_TABLE_SQL = """
    CREATE TABLE receipts (
        receipt_hash TEXT NOT NULL,
        iat          INTEGER NOT NULL,
        agent_id     TEXT NOT NULL,
        tool         TEXT NOT NULL,
        decision     TEXT NOT NULL,
        reason       TEXT NOT NULL DEFAULT '',
        policy       TEXT,
        latency_us   INTEGER NOT NULL DEFAULT 0,
        trace_id     TEXT,
        session_id   TEXT,
        acting_for   TEXT NOT NULL DEFAULT '',
        source       TEXT NOT NULL DEFAULT '',
        destination  TEXT NOT NULL DEFAULT '',
        parents_json TEXT NOT NULL DEFAULT '[]',
        segment      TEXT,
        line_no      INTEGER
    )
"""

_RECEIPTS_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_receipts_iat ON receipts (iat)",
    "CREATE INDEX IF NOT EXISTS idx_receipts_agent ON receipts (agent_id, iat)",
    "CREATE INDEX IF NOT EXISTS idx_receipts_tool ON receipts (tool, iat)",
    "CREATE INDEX IF NOT EXISTS idx_receipts_trace ON receipts (trace_id)",
    # EPIC Q lane Q-1: behavioural sessions query receipts by
    # (session_id, iat); only DECLARED session keys are ever indexed.
    "CREATE INDEX IF NOT EXISTS idx_receipts_session ON receipts (session_id, iat)",
    # L1 boot-streaming: the compactor's batches are idempotent over
    # their line range. A unique index over (receipt_hash, segment,
    # line_no) lets a resumed or re-run sweep insert nothing twice while
    # the keyless doctrine survives: rows the live append path projects
    # carry NULL segment/line_no, and SQLite treats NULLs as distinct in
    # unique indexes, so byte-identical same-second attempts (the v2
    # fix) are never collapsed. The chain of record keeps every attempt.
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_projection_dedupe "
    "ON receipts (receipt_hash, segment, line_no)",
)

#: Sidecar state the boot compactor persists inside the index (L1):
#: cursor and done keys, disposable with the projection itself.
_COMPACTOR_STATE_SQL = """
    CREATE TABLE IF NOT EXISTS compactor_state (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
"""


class ReceiptIndex:
    """SQLite-backed query projection over gate receipts.

    One connection per instance, guarded by a lock for the write path
    (SQLite WAL allows one writer; the gateway is single-process so a
    single connection is the simplest correct shape).
    """

    def __init__(
        self,
        sqlite_path: str | Path,
        *,
        defer_migration: bool = False,
        cache_mb: int = 0,
    ) -> None:
        self._path = Path(sqlite_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # Autocommit (isolation_level=None) makes transaction boundaries
        # explicit and deterministic: schema work runs inside the BEGIN
        # IMMEDIATE blocks of _init_schema and of crash recovery (J2).
        # Every write call site already committed per statement, so the
        # durability semantics of the write path are unchanged.
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        # L1: the index page cache is a configured budget term
        # (RAUCLE_INDEX_CACHE_MB), not an accident of SQLite defaults;
        # mmap stays off so resident size never tracks the file.
        if cache_mb > 0:
            self._conn.execute(f"PRAGMA cache_size = {-int(cache_mb) * 1024}")
        # L1 boot-streaming: the boot opens the index WITHOUT the
        # migration's table copy (it is O(table) and belongs to the
        # background compactor, spec 3.5 phase 1). The J2 recovery
        # inspection still runs here: it is cheap and it is the
        # boot-safety contract.
        self._pending_migration = False
        if defer_migration:
            self._recover_interrupted_migration()
            version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            has_table = self._table_exists("receipts")
            self._pending_migration = bool(has_table and version < self.SCHEMA_VERSION)
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if not self._pending_migration:
                    # Only the O(table) migration copy defers (spec 3.5
                    # phase 1); a fresh or current-shape index still
                    # gets its cheap DDL at open, so a cold boot can
                    # project into it while the compactor runs.
                    self._create_receipts_table(if_not_exists=True)
                    for stmt in _RECEIPTS_INDEXES:
                        self._conn.execute(stmt)
                    self._conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
                self._conn.execute(_COMPACTOR_STATE_SQL)
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise
        else:
            self._init_schema()

    @property
    def pending_migration(self) -> bool:
        """Whether a schema migration is deferred to the compactor."""
        return self._pending_migration

    def run_pending_migration(self) -> None:
        """Run the deferred migration inside the J2 invariants: schema
        inspection already happened at open; the copy, the indexes and
        the version stamp are ONE transaction, so a crash at any step
        rolls the file back to the pristine pre-migration state."""
        if not self._pending_migration:
            return
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._migrate_dedupe_schema()
            for stmt in _RECEIPTS_INDEXES:
                self._conn.execute(stmt)
            self._conn.execute(_COMPACTOR_STATE_SQL)
            self._conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise
        self._pending_migration = False
        logger.warning(
            "receipt_index: compactor completed the deferred schema migration at %s",
            self._path,
        )

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    SCHEMA_VERSION = 3

    # Version history:
    # - v1 (pre-versioned): receipt_hash PRIMARY KEY + INSERT OR REPLACE.
    #   Two byte-identical same-second attempts (identical payload, hence
    #   identical hash) collapsed to one projection row, so trace/attempts
    #   queries undercounted. The chain of record keeps every attempt.
    # - v2: keyless inserts project all attempts; rowid tiebreak in cursors.
    # - v3 (EPIC Q lane Q-1): adds session_id (optional, Q1 behavioural
    #   sessions; composite (session_id, iat) index) and acting_for
    #   (present in x_gate since v1 but unindexed) as queryable columns.
    #   Both are nullable/''-empty by design: a receipt carries NO
    #   session_id unless the caller declared one - continuity is never
    #   fabricated. The index remains a QUERY CACHE (rebuild on open); a
    #   v2 file is copied across in place, a stale file also rebuilds
    #   from the store. Verification NEVER consults the index.
    # - J2 (crash-resilience, no schema change): the migration and the
    #   version stamp became one transaction, and open first repairs the
    #   half-migrated artifact the previous autocommitting implementation
    #   could leave behind (the 18 Nov demo incident: an OOM kill
    #   mid-migration, then a permanent boot crash-loop).
    def _init_schema(self) -> None:
        # Crash-resilience (J2): BEFORE any ALTER, inspect the schema for
        # an interrupted migration and repair it deterministically. The
        # migrate-on-open of v3 ran as separate autocommitted statements,
        # so a process killed between the rename and the copy (the 18 Nov
        # demo incident: an OOM kill at 23.4 GB RSS, three kills) left
        # receipts_prev_backup beside a half-built live table, and every
        # later boot re-entered the migration and died on the rename - a
        # permanent crash-loop under restart:always.
        self._recover_interrupted_migration()
        version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        has_table = self._table_exists("receipts")
        # The schema version rows are the migration journal. One explicit
        # transaction carries the schema change AND the version stamp
        # (probe-verified on SQLite 3.53.1: DDL and PRAGMA user_version
        # are transactional), so user_version only ever claims a shape a
        # committed transaction actually produced, and a crash at any
        # step rolls the file back to the pristine pre-migration state,
        # where the next open simply re-runs the migration.
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if has_table and version < self.SCHEMA_VERSION:
                self._migrate_dedupe_schema()
            else:
                self._create_receipts_table(if_not_exists=True)
            for stmt in _RECEIPTS_INDEXES:
                self._conn.execute(stmt)
            self._conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise

    def _create_receipts_table(self, *, if_not_exists: bool = False) -> None:
        """Create the live projection table. The caller owns the transaction."""
        prefix = "CREATE TABLE IF NOT EXISTS receipts" if if_not_exists else "CREATE TABLE receipts"
        self._conn.execute(_RECEIPTS_TABLE_SQL.replace("CREATE TABLE receipts", prefix, 1))

    def _table_exists(self, name: str) -> bool:
        return (
            self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (name,),
            ).fetchone()
            is not None
        )

    def _shared_columns(self, table: str) -> list[str]:
        """The projection columns *table* also carries, in table order."""
        old_cols = [row[1] for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()]
        return [c for c in _RECEIPTS_COLUMNS if c in old_cols]

    def _recreate_receipts_from(self, source: str) -> None:
        """Create the current-shape receipts table and copy the shared
        columns of *source* into it. The caller owns the transaction.

        Defaults cover the newer columns (no-continuity: session_id NULL,
        acting_for ''); a v2->v3 upgrade copies v2 columns whole, and a
        v1->v3 upgrade also keeps the session columns empty. A row never
        GAINS a session key it did not carry.
        """
        self._create_receipts_table(if_not_exists=False)
        shared = self._shared_columns(source)
        if not shared:
            return  # nothing projectable to copy
        cols_csv = ", ".join(shared)
        self._conn.execute(f"INSERT INTO receipts ({cols_csv}) SELECT {cols_csv} FROM {source}")

    def _recover_interrupted_migration(self) -> None:
        """Repair a migration interrupted by a crash, BEFORE any ALTER runs.

        Detection is by schema inspection - a receipts_prev_backup table
        is the artifact an interrupted rename leaves - never by catching
        the rename error after the fact. Three states, each recovered in
        the ordering that cannot lose projected data:

        - backup WITHOUT a live table: the crash landed between the rename
          and the re-create. Undo the rename - the backup is all the
          projection there is - and stamp user_version 0, because the
          restored table's true version is unknown and the version row
          must not claim a migration the schema did not get. The normal
          migration in _init_schema then re-runs from a known state.
        - backup WITH a live table at the current version: a completed
          migration commits the drop of the backup and the version stamp
          together, so this is a stale leftover this code cannot produce;
          the current live table is authoritative and the backup is
          dropped.
        - backup WITH a half-built live table at an older version: the
          observed OOM signature. The half-built table only ever received
          rows INSERT ... SELECTed from the backup (the store never
          finished booting, so no other writer touched it): its rows are a
          subset of the backup's. Drop the half-built table, complete the
          interrupted migration by re-copying from the backup, drop the
          backup only after its rows are re-copied, and stamp the version
          - all in one committed transaction.

        The chain of record is the truth and verification never consults
        the index, so recovery cannot affect any trust decision; it
        preserves the projected rows to avoid an avoidable cold rebuild at
        boot (the gateway rebuilds from the store only when the opened
        index is empty). Recovery is idempotent: a crash during it rolls
        back to the same detected state and the same branch re-runs.
        Every branch logs one named line an operator can grep:
        "receipt_index: recovered interrupted schema migration".
        """
        if not self._table_exists("receipts_prev_backup"):
            return
        live = self._table_exists("receipts")
        version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if not live:
                self._conn.execute("ALTER TABLE receipts_prev_backup RENAME TO receipts")
                self._conn.execute("PRAGMA user_version = 0")
                action = "renamed the backup back; migration re-runs"
            elif version >= self.SCHEMA_VERSION:
                self._conn.execute("DROP TABLE receipts_prev_backup")
                action = "dropped a stale backup beside a current index"
            else:
                self._conn.execute("DROP TABLE receipts")
                self._recreate_receipts_from("receipts_prev_backup")
                self._conn.execute("DROP TABLE receipts_prev_backup")
                self._conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
                action = "completed the interrupted copy from the backup"
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise
        logger.warning(
            "receipt_index: recovered interrupted schema migration (%s): "
            "%d projected rows preserved at %s",
            action,
            self.count(),
            self._path,
        )

    def _migrate_dedupe_schema(self) -> None:
        """Copy a PRIOR-version table across in place, without losing rows.

        v1 (pre-versioned) held at most one row per (identical) receipt id,
        so SELECT * preserves every row it has; v2 rows project whole. Both
        upgrade to the current shape with the newer columns left at their
        no-continuity defaults (session_id NULL, acting_for ''). The index
        is a disposable projection: any operator preferring a hard-rebuild
        path has ``rebuild_from_store``.

        Crash-resilience (J2): the caller runs this inside ONE explicit
        transaction with the version stamp, so a crash at any step rolls
        back to the pre-migration file and the next open re-runs it. This
        code can no longer produce a half-migrated file; the ones the
        previous autocommitting implementation left behind are repaired
        before any ALTER by ``_recover_interrupted_migration``.
        """
        self._conn.execute("ALTER TABLE receipts RENAME TO receipts_prev_backup")
        self._recreate_receipts_from("receipts_prev_backup")
        self._conn.execute("DROP TABLE receipts_prev_backup")

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    def index_receipt(
        self, record: dict[str, Any], segment: str | None = None, line_no: int | None = None
    ) -> bool:
        """Decode a receipt envelope and project it into the index.

        Unknown/malformed receipts are skipped by design: the index never
        rejects chain content, it only fails to accelerate it. Returns whether
        the record was indexed, so a rebuild count states what actually
        happened rather than how many lines were attempted.
        """
        try:
            params = self._project_row(record, segment=segment, line_no=line_no)
        except Exception:
            return False
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO receipts
                    (receipt_hash, iat, agent_id, tool, decision, reason,
                     policy, latency_us, trace_id, session_id, acting_for,
                     source, destination, parents_json, segment, line_no)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                params,
            )
            self._conn.commit()
        return True

    @staticmethod
    def _project_row(
        record: dict[str, Any], *, segment: str | None, line_no: int | None
    ) -> tuple[Any, ...]:
        """Decode a receipt envelope into one projection row. Shared by
        the live append path (plain INSERT, every attempt kept) and the
        compactor's batches (INSERT OR IGNORE over the line range)."""
        payload = ReceiptIndex._decode_payload(record)
        x_gate = payload.get("x_gate") or {}
        parents = json.dumps(payload.get("parents") or [])
        return (
            record.get("receipt_hash", ""),
            int(payload.get("iat", 0)),
            str(x_gate.get("agent_id", payload.get("agent_id", ""))),
            str(x_gate.get("tool", "")),
            str(x_gate.get("decision", payload.get("guardrail_verdict", ""))),
            str(x_gate.get("reason", "")),
            x_gate.get("policy"),
            int(x_gate.get("latency_us", 0)),
            x_gate.get("trace_id"),
            # EPIC Q lane Q-1: optional session continuity. Absent
            # session keys stay NULL - continuity is never
            # fabricated from trace_id or anywhere else.
            x_gate.get("session_id") or None,
            str(x_gate.get("acting_for", "")),
            str(x_gate.get("source", "")),
            str(x_gate.get("destination", "")),
            parents,
            segment,
            line_no,
        )

    def index_batch(
        self,
        items: Any,
        segment: str | None = None,
        *,
        state_updates: dict[str, str] | None = None,
    ) -> int:
        """Project a batch of ``(line_no, record)`` envelopes in ONE
        transaction (L1). Idempotent over its line range: the unique
        projection index ignores a row whose (receipt_hash, segment,
        line_no) is already projected, so a resumed or re-run sweep
        inserts nothing twice. ``state_updates`` persist compactor
        cursor and done keys inside the SAME transaction, so an
        interrupted run resumes at a committed cursor. Returns the
        number of items in the batch (what was attempted, matching the
        rebuild counters' honesty), not the number of new rows.
        """
        items = list(items)
        if not items and not state_updates:
            return 0
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for line_no, record in items:
                    try:
                        params = self._project_row(record, segment=segment, line_no=line_no)
                    except Exception:
                        continue  # shape-filtering a disposable projection
                    self._conn.execute(
                        """
                        INSERT OR IGNORE INTO receipts
                            (receipt_hash, iat, agent_id, tool, decision, reason,
                             policy, latency_us, trace_id, session_id, acting_for,
                             source, destination, parents_json, segment, line_no)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        params,
                    )
                for key, value in (state_updates or {}).items():
                    self._conn.execute(
                        "INSERT OR REPLACE INTO compactor_state (key, value) VALUES (?, ?)",
                        (key, str(value)),
                    )
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise
        return len(items)

    def rebuild_from_store(self, store: Any) -> int:
        """Drop and rebuild the projection from a SegmentedReceiptStore.

        The repair path: the chain is the truth; the index is disposable.
        Returns the number of receipts indexed.
        """
        self._clear()
        count = 0
        for seg in store.segments():
            with open(seg, encoding="utf-8") as fh:
                count += self._index_lines(fh, segment=seg.name)
        return count

    def rebuild_from_flat_file(self, path: str | Path) -> int:
        """Drop and rebuild the projection from a flat JSONL receipt chain.

        The legacy sink: ``receipt_store`` as a single file with no
        ``receipt_store_dir``. Before RED-034 a configured index was fed only
        on the segmented path, so the admin panel reported an empty chain
        while the store held every receipt.
        """
        self._clear()
        with open(path, encoding="utf-8") as fh:
            return self._index_lines(fh)

    def _clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM receipts")
            self._conn.commit()

    def _index_lines(self, lines: Any, segment: str | None = None) -> int:
        """Index every receipt envelope in an iterable of JSONL lines."""
        count = 0
        for line_no, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "receipt_hash" not in record or "jws" not in record:
                continue  # not a receipt envelope
            if self.index_receipt(record, segment=segment, line_no=line_no):
                count += 1
        return count

    # ------------------------------------------------------------------
    # Query path
    # ------------------------------------------------------------------

    def query(
        self,
        *,
        agent_id: str | None = None,
        tool: str | None = None,
        decision: str | None = None,
        trace_id: str | None = None,
        session_id: str | None = None,
        acting_for: str | None = None,
        since: int | None = None,
        until: int | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query receipts newest-first.

        ``cursor`` is the composite ``"<iat>:<receipt_hash>"`` of the last
        row seen (keyset pagination): records strictly after that sort
        position are returned. Handles ties on identical ``iat`` (burst
        traffic) that naive offset/iat cursors would drop.
        """
        sql = "SELECT rowid AS rowid, receipts.* FROM receipts WHERE 1=1"
        params: list[Any] = []
        if agent_id is not None:
            sql += " AND agent_id = ?"
            params.append(agent_id)
        if tool is not None:
            sql += " AND tool = ?"
            params.append(tool)
        if decision is not None:
            sql += " AND decision = ?"
            params.append(decision)
        if trace_id is not None:
            sql += " AND trace_id = ?"
            params.append(trace_id)
        if session_id is not None:
            sql += " AND session_id = ?"
            params.append(session_id)
        if acting_for is not None:
            # acting_for is an indexed v3 column: receipts without a
            # delegated principal are stored as '' and only match an
            # explicit acting_for='' filter, never an unset one.
            sql += " AND acting_for = ?"
            params.append(acting_for)
        if since is not None:
            sql += " AND iat >= ?"
            params.append(since)
        if until is not None:
            sql += " AND iat <= ?"
            params.append(until)
        if cursor is not None:
            # The receipt_hash field itself contains a colon ("sha256:..."),
            # so positional splits are forbidden: the rowid, when present,
            # is the LAST part (it is the only numeric one), and everything
            # between iat and rowid is the hash, colons included.
            parts = cursor.split(":")
            try:
                cur_iat_int = int(parts[0])
            except (ValueError, IndexError):
                cur_iat_int = 0
            tail = parts[1:]
            if tail and tail[-1].lstrip("-").isdigit():
                cur_rid = int(tail[-1])
                cur_hash = ":".join(tail[:-1])
            else:
                # schema v1 cursor: no rowid. It only advances on different
                # hash/iat, so identical-hash rows after it are skipped;
                # a v1 index holds at most one row per hash anyway.
                cur_rid = -1
                cur_hash = ":".join(tail)
            # DESC sort: "after the cursor" means older iat, or equal iat
            # with a smaller receipt_hash, or the same hash earlier in
            # insert order (rowid tiebreak, the DESC tiebreak of last resort).
            sql += (
                " AND (iat < ? OR (iat = ? AND (receipt_hash < ?"
                " OR (receipt_hash = ? AND rowid < ?))))"
            )
            params.extend([cur_iat_int, cur_iat_int, cur_hash, cur_hash, cur_rid])
        sql += " ORDER BY iat DESC, receipt_hash DESC, rowid DESC LIMIT ?"
        params.append(max(1, min(int(limit), 1000)))
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def session_receipts(
        self,
        session_id: str,
        *,
        since: int | None = None,
        until: int | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """All receipts of one declared behavioural session, oldest first.

        The (session_id, iat) retrieval path the later session-window
        lanes build on: every receipted decision (denies included) that
        carried the session key, in call order. Only keys the callers
        themselves declared are retrievable - receipts without a
        session_id are never part of any session.
        """
        rows = self.query(
            session_id=session_id, since=since, until=until, limit=min(int(limit), 1000)
        )
        rows.reverse()
        return rows

    def active_session_ids(self, since: int, *, limit: int = 1000) -> list[str]:
        """Distinct declared session keys with receipts at/after *since*,
        most recently active first (EPIC Q lane Q-2 boot replay).

        Only keys the callers themselves declared are ever indexed, so
        only declared sessions are replayable: receipts without a
        session_id are never part of any session. Ordered by latest
        activity so a bounded replay keeps the sessions that were live
        at the restart.
        """
        rows = self._conn.execute(
            "SELECT session_id, MAX(iat) AS latest FROM receipts "
            "WHERE session_id IS NOT NULL AND session_id != '' AND iat >= ? "
            "GROUP BY session_id ORDER BY latest DESC LIMIT ?",
            (int(since), max(1, min(int(limit), 10000))),
        ).fetchall()
        return [row[0] for row in rows]

    def cursor_for(self, row: dict[str, Any]) -> str:
        """The next-page cursor for the last row of a query result.

        v2 format is ``<iat>:<receipt_hash>:<rowid>``; the rowid is the
        final tiebreak that lets identical-hash duplicates (two same-second
        attempts of the same call) survive pagination.
        """
        return f"{row.get('iat', 0)}:{row.get('receipt_hash', '')}:{row.get('rowid', -1)}"

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])

    # ------------------------------------------------------------------
    # Compactor state (L1): disposable keys riding the projection
    # ------------------------------------------------------------------

    def get_state(self, key: str) -> str | None:
        """Read one compactor state key, or None when unset."""
        row = self._conn.execute(
            "SELECT value FROM compactor_state WHERE key = ?", (key,)
        ).fetchone()
        return None if row is None else str(row[0])

    def set_state(self, key: str, value: str) -> None:
        """Persist one compactor state key in its own transaction."""
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO compactor_state (key, value) VALUES (?, ?)",
                (key, str(value)),
            )
            self._conn.commit()

    def drop_live_twins(self) -> None:
        """Live-tail handover (L1): rows the live append path projected
        during a build are twins of swept rows. The store copy is the
        projection truth, so a twin is dropped once; a live row with no
        swept twin is the tail the sweep never reached and stays."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM receipts WHERE segment IS NULL AND receipt_hash IN "
                "(SELECT receipt_hash FROM receipts WHERE segment IS NOT NULL)"
            )
            self._conn.commit()

    def clear(self) -> None:
        """Public clear for the compactor's flat-store rebuild path."""
        self._clear()

    # ------------------------------------------------------------------
    # Ancestry (C3)
    # ------------------------------------------------------------------

    def ancestry(self, receipt_hash: str, max_depth: int = 50) -> dict[str, Any]:
        """Walk the ``parents`` DAG backwards from *receipt_hash*.

        Returns ``{"nodes": [...], "edges": [{"from", "to"}, ...]}`` with a
        visited-set (cycle safe) and a depth cap. Missing receipts are
        tolerated: the walk simply cannot continue past them.
        """
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, str]] = []
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(receipt_hash, 0)]
        while queue:
            current, depth = queue.pop(0)
            if current in visited or depth > max_depth:
                continue
            visited.add(current)
            row = self._conn.execute(
                "SELECT * FROM receipts WHERE receipt_hash = ?", (current,)
            ).fetchone()
            if row is None:
                continue  # tolerate missing (pruned/absent) receipts
            rec = dict(row)
            nodes[current] = rec
            parents = json.loads(rec.get("parents_json") or "[]")
            for parent in parents:
                edges.append({"from": parent, "to": current})
                if parent not in visited:
                    queue.append((parent, depth + 1))
        return {"nodes": list(nodes.values()), "edges": edges}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_payload(record: dict[str, Any]) -> dict[str, Any]:
        jws = record.get("jws", "")
        parts = jws.split(".")
        if len(parts) < 2:
            raise ValueError("not a JWS")
        return json.loads(_b64url_decode(parts[1]))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
