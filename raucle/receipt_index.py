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

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_hash TEXT PRIMARY KEY,
                iat          INTEGER NOT NULL,
                agent_id     TEXT NOT NULL,
                tool         TEXT NOT NULL,
                decision     TEXT NOT NULL,
                reason       TEXT NOT NULL DEFAULT '',
                policy       TEXT,
                latency_us   INTEGER NOT NULL DEFAULT 0,
                trace_id     TEXT,
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
        self._conn.commit()

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    def index_receipt(
        self, record: dict[str, Any], segment: str | None = None, line_no: int | None = None
    ) -> None:
        """Decode a receipt envelope and project it into the index.

        Unknown/malformed receipts are skipped silently by design: the
        index never rejects chain content, it only fails to accelerate it.
        """
        try:
            payload = self._decode_payload(record)
        except Exception:
            return
        x_gate = payload.get("x_gate") or {}
        parents = json.dumps(payload.get("parents") or [])
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO receipts
                    (receipt_hash, iat, agent_id, tool, decision, reason,
                     policy, latency_us, trace_id, source, destination,
                     parents_json, segment, line_no)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    str(x_gate.get("source", "")),
                    str(x_gate.get("destination", "")),
                    parents,
                    segment,
                    line_no,
                ),
            )
            self._conn.commit()

    def rebuild_from_store(self, store: Any) -> int:
        """Drop and rebuild the projection from a SegmentedReceiptStore.

        The repair path: the chain is the truth; the index is disposable.
        Returns the number of receipts indexed.
        """
        with self._lock:
            self._conn.execute("DELETE FROM receipts")
            self._conn.commit()
        count = 0
        for seg in store.segments():
            seg_name = seg.name
            with open(seg, encoding="utf-8") as fh:
                for line_no, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if "receipt_hash" not in record or "jws" not in record:
                        continue  # not a receipt envelope
                    self.index_receipt(record, segment=seg_name, line_no=line_no)
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
        sql = "SELECT * FROM receipts WHERE 1=1"
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
        if since is not None:
            sql += " AND iat >= ?"
            params.append(since)
        if until is not None:
            sql += " AND iat <= ?"
            params.append(until)
        if cursor is not None:
            cur_iat, _, cur_hash = cursor.partition(":")
            try:
                cur_iat_int = int(cur_iat)
            except ValueError:
                cur_iat_int = 0
            # DESC sort: "after the cursor" means older iat, or equal iat
            # with a smaller receipt_hash (the DESC tiebreak).
            sql += " AND (iat < ? OR (iat = ? AND receipt_hash < ?))"
            params.extend([cur_iat_int, cur_iat_int, cur_hash])
        sql += " ORDER BY iat DESC, receipt_hash DESC LIMIT ?"
        params.append(max(1, min(int(limit), 1000)))
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def cursor_for(self, row: dict[str, Any]) -> str:
        """The next-page cursor for the last row of a query result."""
        return f"{row.get('iat', 0)}:{row.get('receipt_hash', '')}"

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
