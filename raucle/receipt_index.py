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
"""

from __future__ import annotations

import base64
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


class ReceiptIndex:
    """SQLite-backed query projection over gate receipts.

    One connection per instance, guarded by a lock for the write path
    (SQLite WAL allows one writer; the gateway is single-process so a
    single connection is the simplest correct shape).
    """

    def __init__(self, sqlite_path: str | Path) -> None:
        self._path = Path(sqlite_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

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
    def _init_schema(self) -> None:
        version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        has_table = (
            self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'receipts'"
            ).fetchone()
            is not None
        )
        if has_table and version < self.SCHEMA_VERSION:
            self._migrate_dedupe_schema()
        else:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS receipts (
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
            )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_receipts_iat ON receipts (iat)")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_receipts_agent ON receipts (agent_id, iat)"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_receipts_tool ON receipts (tool, iat)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_receipts_trace ON receipts (trace_id)")
        # EPIC Q lane Q-1: behavioural sessions query receipts by
        # (session_id, iat); only DECLARED session keys are ever indexed.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_receipts_session ON receipts (session_id, iat)"
        )
        self._conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
        self._conn.commit()

    def _migrate_dedupe_schema(self) -> None:
        """Copy a PRIOR-version table across in place, without losing rows.

        v1 (pre-versioned) held at most one row per (identical) receipt id,
        so SELECT * preserves every row it has; v2 rows project whole. Both
        upgrade to the current shape with the newer columns left at their
        no-continuity defaults (session_id NULL, acting_for '') - a row
        never GAINS a session key it did not carry. The index is a
        disposable projection: any operator preferring a hard-rebuild path
        has ``rebuild_from_store``.
        """
        self._conn.execute("ALTER TABLE receipts RENAME TO receipts_prev_backup")
        self._conn.execute(
            """
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
        )
        old_cols = [
            row[1]
            for row in self._conn.execute("PRAGMA table_info(receipts_prev_backup)").fetchall()
        ]
        shared = [
            c
            for c in (
                "receipt_hash",
                "iat",
                "agent_id",
                "tool",
                "decision",
                "reason",
                "policy",
                "latency_us",
                "trace_id",
                "source",
                "destination",
                "parents_json",
                "segment",
                "line_no",
            )
            if c in old_cols
        ]
        cols_csv = ", ".join(shared)
        # defaults cover the newer columns (no-continuity: session_id NULL,
        # acting_for ''); a v2->v3 upgrade copies v2 columns whole, and a
        # v1->v3 upgrade also keeps the session columns empty.
        self._conn.execute(
            f"INSERT INTO receipts ({cols_csv}) SELECT {cols_csv} FROM receipts_prev_backup"
        )
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
            payload = self._decode_payload(record)
        except Exception:
            return False
        x_gate = payload.get("x_gate") or {}
        parents = json.dumps(payload.get("parents") or [])
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO receipts
                    (receipt_hash, iat, agent_id, tool, decision, reason,
                     policy, latency_us, trace_id, session_id, acting_for,
                     source, destination, parents_json, segment, line_no)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
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
                ),
            )
            self._conn.commit()
        return True

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
