"""Lane L1: the boot streams its stores in bounded windows (spec v0.1).

The invariants this suite pins, one class per acceptance criterion:

- AC1 bounded boot: the boot path's peak allocations stay under the
  configured budget and are flat in store size (a 2x store boots within
  noise of a 1x store).
- AC2 bind first: /health answers and the decision path serves while the
  compactor is mid-build.
- AC3 readiness honesty: mid-build, receipt query surfaces return a named
  refusal with progress, never an empty 200; after the build, query
  answers are identical to a full rebuild_from_store.
- AC4 fail-closed tail: a torn tail line is the named refusal
  chain_tail_malformed (file, line number, offset, the rotate command),
  never a silent skip; the file is never modified.
- AC5 session continuity: the TTL tail window restores session windows
  identical to a full-index replay, and session-rule calls before
  continuity lands refuse with session_continuity_pending, never a
  silent cold start.
- AC6 preflight integration: the J1 projection is re-derived from the
  window budget, so the effective ceiling lowers as the windows shrink
  while the knob and refusal contracts stay.
- AC8 recovery preserved: an interrupted compactor run resumes itself
  with no duplicates and no crash-loop.
- Watchdog: a sampled resident size over the J1 ceiling during the scan
  or compactor is the named BootMemoryCeilingExceeded refusal, never an
  OOM kill.
"""

from __future__ import annotations

import base64
import json
import threading
import time
import tracemalloc
from pathlib import Path

import pytest

from raucle.errors import BootMemoryCeilingExceeded, ChainTailMalformed

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MB = 1024 * 1024


def _b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _envelope(iat: int, *, receipt_no: int, session_id: str | None = None) -> str:
    """A minimal receipt envelope the index can project (payload-only JWS).

    The index decodes the payload and never verifies signatures: a
    disposable projection never judges chain content.
    """
    x_gate: dict[str, object] = {
        "agent_id": "agent:t",
        "tool": "web.fetch",
        "decision": "allow",
        "reason": "",
    }
    if session_id is not None:
        x_gate["session_id"] = session_id
    payload = {"iat": int(iat), "agent_id": "agent:t", "x_gate": x_gate}
    jws = f"{_b64url({'alg': 'none'})}.{_b64url(payload)}.AA"
    return json.dumps({"receipt_hash": f"sha256:{receipt_no:064x}", "jws": jws})


def _seed_segmented_store(
    store_dir: Path, envelopes: list[str], *, max_segment_bytes: int = 256 * 1024
) -> None:
    from raucle.receipt_store import SegmentedReceiptStore

    store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=max_segment_bytes)
    for env in envelopes:
        store.append_line(env)


def _open_index(path: Path, **kwargs):
    from raucle.receipt_index import ReceiptIndex

    return ReceiptIndex(sqlite_path=path, **kwargs)


def _default_compactor(
    index,
    *,
    store=None,
    flat_path=None,
    readiness,
    watchdog,
    ttl_seconds: int = 900,
    batch_rows: int = 256,
    scan_window_bytes: int = 8 * _MB,
    session_replay=None,
    audit_chain=None,
):
    from raucle.boot_stream import BootCompactor

    return BootCompactor(
        index,
        store=store,
        flat_path=flat_path,
        readiness=readiness,
        watchdog=watchdog,
        ttl_seconds=ttl_seconds,
        batch_rows=batch_rows,
        scan_window_bytes=scan_window_bytes,
        session_replay=session_replay,
        audit_chain=audit_chain,
    )


def _readiness():
    from raucle.boot_stream import BootReadiness

    return BootReadiness()


def _watchdog(ceiling_mb: int = 0, sampler=None):
    from raucle.boot_stream import BootWatchdog

    return BootWatchdog(ceiling_mb=ceiling_mb, sampler=sampler)


def _seed_audit_chain(path: Path, events: int, signer=None) -> None:
    from raucle.audit import HashChainSink

    sink = HashChainSink(path, signer=signer, checkpoint_every=100)
    for i in range(events):
        sink.append({"event": "gate_decision", "seq": i})
    sink.close()


# ---------------------------------------------------------------------------
# The bounded reverse tail read and the Merkle frontier
# ---------------------------------------------------------------------------


class TestMerkleFrontier:
    def test_frontier_roots_match_the_full_leaf_list(self):
        import hashlib

        from raucle.audit import MerkleFrontier, _merkle_root

        for n in (0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 63, 64, 100, 257):
            leaves = [hashlib.sha256(f"leaf{i}".encode()).hexdigest() for i in range(n)]
            frontier = MerkleFrontier()
            for leaf in leaves:
                frontier.add(leaf)
            assert frontier.leaf_count == n
            assert frontier.root() == _merkle_root(leaves), f"n={n}"

    def test_roundtrips_through_its_serialised_form(self):
        import hashlib

        from raucle.audit import MerkleFrontier

        frontier = MerkleFrontier()
        for i in range(9):
            frontier.add(hashlib.sha256(str(i).encode()).hexdigest())
        restored = MerkleFrontier.from_dict(frontier.to_dict())
        assert restored.leaf_count == frontier.leaf_count
        assert restored.root() == frontier.root()


class TestBoundedTailResume:
    def _build_chain(self, path: Path, events: int) -> None:
        from raucle.audit import Ed25519Signer, HashChainSink

        signer = Ed25519Signer.generate()
        sink = HashChainSink(path, signer=signer, checkpoint_every=50)
        for i in range(events):
            sink.append({"event": "gate_decision", "seq": i})
        sink.close()
        return signer

    def test_resume_reads_only_the_tail_window(self, tmp_path):
        from raucle.audit import HashChainSink, read_last_lines

        path = tmp_path / "audit.jsonl"
        self._build_chain(path, 400)

        # A window far smaller than the file recovers the same tail state
        # the whole-scan resume used to produce.
        start_offset, entries = read_last_lines(path, window_bytes=4096)
        assert start_offset > 0  # genuinely a partial window, not the file
        sink = HashChainSink(path, signer=None, checkpoint_every=50, scan_window_bytes=4096)
        assert sink.event_count == 400
        # The resumed sink appends seamlessly: the chain stays whole.
        sink.append({"event": "gate_decision", "seq": 400})
        assert sink.event_count == 401
        sink.close()
        # The file was only appended to, never rewritten.
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) >= 401

    def test_resumed_chain_verifies_whole_offline(self, tmp_path):
        from raucle.audit import AuditVerifier, Ed25519Signer, HashChainSink

        path = tmp_path / "audit.jsonl"
        signer = Ed25519Signer.generate()
        sink = HashChainSink(path, signer=signer, checkpoint_every=25)
        for i in range(60):
            sink.append({"event": "gate_decision", "seq": i})
        sink.close()

        # A second sink resumes over the same chain through the bounded
        # window and must produce checkpoints an offline verifier accepts.
        sink2 = HashChainSink(path, signer=signer, checkpoint_every=25, scan_window_bytes=8192)
        assert sink2.frontier_ready, "frontier sidecar must survive the resume"
        for i in range(60, 80):
            sink2.append({"event": "gate_decision", "seq": i})
        sink2.close()

        report = AuditVerifier(public_key_pem=signer.public_key_pem()).verify_chain(path)
        assert report.valid, report.errors
        assert report.event_count == 80

    def test_torn_tail_is_a_named_refusal_naming_coordinates(self, tmp_path):
        from raucle.audit import HashChainSink

        path = tmp_path / "audit.jsonl"
        self._build_chain(path, 30)
        before = path.read_bytes()

        # Tear the final write: truncate the last line mid-record.
        lines = before.splitlines(keepends=True)
        torn = lines[-1][: len(lines[-1]) // 2]
        path.write_bytes(b"".join(lines[:-1]) + torn)

        with pytest.raises(ChainTailMalformed) as excinfo:
            HashChainSink(path, scan_window_bytes=64 * _MB)
        msg = str(excinfo.value)
        assert "chain_tail_malformed" in msg
        assert str(path) in msg
        assert "raucle rotate-chain" in msg
        # The refusal names the line number and the byte offset.
        assert "line 32" in msg  # header + 30 events + the close-time checkpoint
        assert "offset" in msg
        # The file is never modified by a refusal.
        assert path.read_bytes() != before
        assert path.read_bytes() == (b"".join(lines[:-1]) + torn)

    def test_unparsable_line_inside_the_window_refuses_by_name(self, tmp_path):
        from raucle.audit import HashChainSink

        path = tmp_path / "audit.jsonl"
        self._build_chain(path, 30)
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        lines[20] = "this is not json\n"
        path.write_text("".join(lines), encoding="utf-8")

        with pytest.raises(ChainTailMalformed) as excinfo:
            HashChainSink(path, scan_window_bytes=64 * _MB)
        assert "chain_tail_malformed" in str(excinfo.value)
        assert "line 21" in str(excinfo.value)

    def test_broken_link_inside_the_window_refuses_by_name(self, tmp_path):
        from raucle.audit import HashChainSink

        path = tmp_path / "audit.jsonl"
        self._build_chain(path, 30)
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        rec = json.loads(lines[15])
        rec["prev_hash"] = "f" * 64
        lines[15] = json.dumps(rec) + "\n"
        path.write_text("".join(lines), encoding="utf-8")

        with pytest.raises(ChainTailMalformed) as excinfo:
            HashChainSink(path, scan_window_bytes=64 * _MB)
        assert "chain_link_broken" in str(excinfo.value)
        assert "raucle rotate-chain" in str(excinfo.value)

    def test_window_grows_until_the_tail_state_is_recoverable(self, tmp_path):
        from raucle.audit import Ed25519Signer, HashChainSink

        path = tmp_path / "audit.jsonl"
        signer = Ed25519Signer.generate()
        sink = HashChainSink(path, signer=signer, checkpoint_every=1)
        sink.append({"event": "boom", "pad": "x" * 4096})
        sink.append({"event": "boom", "pad": "x" * 4096})
        sink.close()

        # An absurdly small first window sees no event record; the resume
        # must grow the window rather than guess the tail state.
        sink2 = HashChainSink(path, signer=signer, checkpoint_every=1, scan_window_bytes=16)
        assert sink2.event_count == 2
        sink2.close()

    def test_missing_frontier_sidecar_degrades_checkpointing_by_name(self, tmp_path, caplog):
        from raucle.audit import Ed25519Signer, HashChainSink, MerkleFrontier

        path = tmp_path / "audit.jsonl"
        signer = Ed25519Signer.generate()
        sink = HashChainSink(path, signer=signer, checkpoint_every=10)
        for i in range(12):
            sink.append({"event": "gate_decision", "seq": i})
        sink.close()
        sidecar = Path(str(path) + ".frontier.json")
        assert sidecar.exists()
        sidecar.unlink()

        sink2 = HashChainSink(path, signer=signer, checkpoint_every=10)
        assert not sink2.frontier_ready
        # Degraded anchoring is named, never silent: no checkpoint is
        # emitted on a missing frontier.
        assert sink2.emit_checkpoint() is None
        # The background scan rebuilds the frontier and the sink can
        # anchor checkpoints again, producing the same roots a full leaf
        # list produces.
        frontier = MerkleFrontier()
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("checkpoint") or rec.get("chain_meta"):
                    continue
                frontier.add(rec["hash"])
        sink2.attach_frontier(frontier)
        assert sink2.frontier_ready
        sink2.append({"event": "gate_decision", "seq": 12})
        checkpoint = sink2.emit_checkpoint()
        assert checkpoint is not None
        sink2.close()

    def test_stale_frontier_sidecar_degrades_rather_than_lies(self, tmp_path):
        from raucle.audit import Ed25519Signer, HashChainSink

        path = tmp_path / "audit.jsonl"
        signer = Ed25519Signer.generate()
        sink = HashChainSink(path, signer=signer, checkpoint_every=1000)
        for i in range(5):
            sink.append({"event": "gate_decision", "seq": i})
        sink.close()

        sidecar = Path(str(path) + ".frontier.json")
        state = json.loads(sidecar.read_text(encoding="utf-8"))
        state["leaf_count"] = 99  # a stale sidecar from a lost write
        sidecar.write_text(json.dumps(state), encoding="utf-8")

        sink2 = HashChainSink(path, signer=signer, checkpoint_every=1000)
        assert sink2.event_count == 5
        assert not sink2.frontier_ready  # degraded by name, never trusted


# ---------------------------------------------------------------------------
# The index: deferred migration and batched, idempotent sweeps
# ---------------------------------------------------------------------------


class TestReceiptIndexDeferral:
    def _legacy_v2_index(self, path: Path, rows: int) -> None:
        import sqlite3

        conn = sqlite3.connect(str(path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE receipts (
                receipt_hash TEXT NOT NULL,
                iat INTEGER NOT NULL,
                agent_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                policy TEXT,
                latency_us INTEGER NOT NULL DEFAULT 0,
                trace_id TEXT,
                parents_json TEXT NOT NULL DEFAULT '[]',
                segment TEXT,
                line_no INTEGER
            )
            """
        )
        for i in range(rows):
            conn.execute(
                "INSERT INTO receipts (receipt_hash, iat, agent_id, tool, decision,"
                " reason, parents_json) VALUES (?, ?, ?, ?, ?, ?, '[]')",
                (f"sha256:{i:064x}", 1700000000 + i, "agent:t", "web.fetch", "allow", ""),
            )
        conn.execute("PRAGMA user_version = 2")
        conn.commit()
        conn.close()

    def test_deferred_open_leaves_the_migration_to_the_compactor(self, tmp_path):
        path = tmp_path / "index.sqlite"
        self._legacy_v2_index(path, rows=5)

        index = _open_index(path, defer_migration=True)
        assert index.pending_migration
        # No copy ran at open: the version row still tells the truth.
        import sqlite3

        assert sqlite3.connect(str(path)).execute("PRAGMA user_version").fetchone()[0] == 2
        assert index.count() == 5

        index.run_pending_migration()
        assert not index.pending_migration
        assert sqlite3.connect(str(path)).execute("PRAGMA user_version").fetchone()[0] == 3
        assert index.count() == 5  # every projected row survived
        index.close()

    def test_plain_open_still_migrates_as_before(self, tmp_path):
        path = tmp_path / "index.sqlite"
        self._legacy_v2_index(path, rows=3)
        index = _open_index(path)
        assert not index.pending_migration
        assert index.count() == 3
        index.close()

    def test_cache_mb_binds_the_sqlite_page_cache(self, tmp_path):
        path = tmp_path / "index.sqlite"
        index = _open_index(path, cache_mb=32)
        cache = index._conn.execute("PRAGMA cache_size").fetchone()[0]
        assert cache == -(32 * 1024)  # negative = KiB cap
        index.close()

    def test_index_batch_is_idempotent_over_its_line_range(self, tmp_path):
        path = tmp_path / "index.sqlite"
        index = _open_index(path)
        items = [(1, json.loads(_envelope(1700000000, receipt_no=1)))]
        assert index.index_batch(items, segment="seg-000000.jsonl") == 1
        # Re-running the same batch (a resumed sweep) must not duplicate.
        assert index.index_batch(items, segment="seg-000000.jsonl") == 1
        assert index.count() == 1
        index.close()


# ---------------------------------------------------------------------------
# The background compactor: phases, readiness, resume, watchdog
# ---------------------------------------------------------------------------


class TestBootCompactorPhases:
    def _seeded_store(self, tmp_path, count: int, *, ttl_span: int = 300):
        """A store whose receipts straddle the TTL boundary."""
        now = int(time.time())
        envelopes = [
            _envelope(now - ttl_span - 600 + i, receipt_no=i) for i in range(count // 2)
        ] + [_envelope(now - 60 + i, receipt_no=count // 2 + i) for i in range(count - count // 2)]
        store_dir = tmp_path / "receipts"
        _seed_segmented_store(store_dir, envelopes, max_segment_bytes=16 * 1024)
        return store_dir, envelopes

    def test_build_is_equivalent_to_a_full_rebuild(self, tmp_path):
        from raucle.receipt_store import SegmentedReceiptStore

        store_dir, envelopes = self._seeded_store(tmp_path, count=120)
        index = _open_index(tmp_path / "index.sqlite", defer_migration=True)
        readiness, watchdog = _readiness(), _watchdog()
        compactor = _default_compactor(
            index,
            store=SegmentedReceiptStore(base_dir=store_dir),
            readiness=readiness,
            watchdog=watchdog,
        )
        compactor.run_phases()

        snap = readiness.snapshot()
        assert snap["receipt_index"]["state"] == "ready"
        assert snap["session_continuity"] == "ready"
        assert snap["receipt_index"]["indexed_rows"] == len(envelopes)
        assert index.count() == len(envelopes)

        # AC3: the compacted projection is identical to a full rebuild.
        fresh = _open_index(tmp_path / "fresh.sqlite")
        fresh.rebuild_from_store(SegmentedReceiptStore(base_dir=store_dir))

        def rows(idx):
            return [{k: v for k, v in row.items() if k != "rowid"} for row in idx.query(limit=1000)]

        assert rows(index) == rows(fresh)
        index.close()
        fresh.close()

    def test_warm_index_ready_without_a_rebuild(self, tmp_path):
        from raucle.receipt_store import SegmentedReceiptStore

        store_dir, envelopes = self._seeded_store(tmp_path, count=40)
        index = _open_index(tmp_path / "index.sqlite", defer_migration=True)
        readiness, watchdog = _readiness(), _watchdog()
        compactor = _default_compactor(
            index,
            store=SegmentedReceiptStore(base_dir=store_dir),
            readiness=readiness,
            watchdog=watchdog,
        )
        compactor.run_phases()
        index.close()

        # A warm restart: the compactor recognises the done state and does
        # not clear or rebuild anything.
        index2 = _open_index(tmp_path / "index.sqlite", defer_migration=True)
        readiness2, watchdog2 = _readiness(), _watchdog()
        replayed = []
        compactor2 = _default_compactor(
            index2,
            store=SegmentedReceiptStore(base_dir=store_dir),
            readiness=readiness2,
            watchdog=watchdog2,
            session_replay=lambda: replayed.append(1),
        )
        before = index2.count()
        compactor2.run_phases()
        assert readiness2.snapshot()["receipt_index"]["state"] == "ready"
        assert index2.count() == before  # no duplicate sweep
        assert replayed == []  # a done build does not re-run continuity
        index2.close()

    def test_live_rows_during_a_build_are_never_duplicated(self, tmp_path):
        from raucle.receipt_store import SegmentedReceiptStore

        store_dir, envelopes = self._seeded_store(tmp_path, count=60)
        index = _open_index(tmp_path / "index.sqlite", defer_migration=True)
        readiness, watchdog = _readiness(), _watchdog()
        compactor = _default_compactor(
            index,
            store=SegmentedReceiptStore(base_dir=store_dir),
            readiness=readiness,
            watchdog=watchdog,
            batch_rows=8,
        )

        # A slow batch imitates a mid-build window; the live path (the
        # gateway's index_receipt on every sink) appends meanwhile.
        original = type(index).index_batch
        state = {"calls": 0}

        def slow_batch(self, items, segment=None, *, state_updates=None):
            state["calls"] += 1
            if state["calls"] == 2:
                # A live receipt lands mid-build, exactly as in production.
                live = json.loads(_envelope(int(time.time()), receipt_no=9_999))
                self.index_receipt(live)
            return original(self, items, segment=segment, state_updates=state_updates)

        import raucle.receipt_index as ri

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(ri.ReceiptIndex, "index_batch", slow_batch)
            compactor.run_phases()

        rows = index.query(limit=1000)
        hashes = [r["receipt_hash"] for r in rows]
        assert len(hashes) == len(set(hashes)), "no row may be projected twice"
        assert len(rows) == len(envelopes) + 1
        index.close()

    def test_interrupted_run_resumes_without_duplicates_or_crash(self, tmp_path):
        from raucle.receipt_store import SegmentedReceiptStore

        store_dir, envelopes = self._seeded_store(tmp_path, count=90)
        index = _open_index(tmp_path / "index.sqlite", defer_migration=True)
        readiness, watchdog = _readiness(), _watchdog()
        compactor = _default_compactor(
            index,
            store=SegmentedReceiptStore(base_dir=store_dir),
            readiness=readiness,
            watchdog=watchdog,
            batch_rows=8,
        )

        import raucle.receipt_index as ri

        original = ri.ReceiptIndex.index_batch
        state = {"calls": 0}

        def dying_batch(self, items, segment=None, *, state_updates=None):
            state["calls"] += 1
            if state["calls"] == 2:
                raise RuntimeError("simulated compactor death mid-sweep")
            return original(self, items, segment=segment, state_updates=state_updates)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(ri.ReceiptIndex, "index_batch", dying_batch)
            compactor.run_phases()  # the fault is recorded, never a crash-loop
        assert readiness.snapshot()["receipt_index"]["state"] != "ready"

        # A restart resumes the same run: no clearing, no duplicates.
        readiness2 = _readiness()
        compactor2 = _default_compactor(
            index,
            store=SegmentedReceiptStore(base_dir=store_dir),
            readiness=readiness2,
            watchdog=_watchdog(),
            batch_rows=8,
        )
        compactor2.run_phases()
        snap = readiness2.snapshot()
        assert snap["receipt_index"]["state"] == "ready"
        assert index.count() == len(envelopes)
        hashes = [r["receipt_hash"] for r in index.query(limit=1000)]
        assert len(hashes) == len(set(hashes))
        index.close()

    def test_watchdog_breach_is_the_named_ceiling_refusal(self, tmp_path):
        from raucle.receipt_store import SegmentedReceiptStore

        store_dir, envelopes = self._seeded_store(tmp_path, count=40)
        index = _open_index(tmp_path / "index.sqlite", defer_migration=True)
        readiness = _readiness()
        watchdog = _watchdog(ceiling_mb=64, sampler=lambda: 65)
        compactor = _default_compactor(
            index,
            store=SegmentedReceiptStore(base_dir=store_dir),
            readiness=readiness,
            watchdog=watchdog,
        )
        with pytest.raises(BootMemoryCeilingExceeded) as excinfo:
            watchdog.check()
        assert "boot_memory_ceiling_exceeded" in str(excinfo.value)

        compactor.run_phases()
        snap = readiness.snapshot()
        assert snap["receipt_index"]["state"] == "refused"
        assert "boot_memory_ceiling_exceeded" in snap["receipt_index"]["error"]
        index.close()

    def test_chain_scan_reports_progress_and_a_break_by_name(self, tmp_path):
        from raucle.receipt_store import SegmentedReceiptStore

        store_dir, _ = self._seeded_store(tmp_path, count=10)
        audit_path = tmp_path / "audit.jsonl"
        _seed_audit_chain(audit_path, events=50)
        index = _open_index(tmp_path / "index.sqlite", defer_migration=True)
        readiness, watchdog = _readiness(), _watchdog()
        compactor = _default_compactor(
            index,
            store=SegmentedReceiptStore(base_dir=store_dir),
            readiness=readiness,
            watchdog=watchdog,
            audit_chain=audit_path,
        )
        compactor.run_phases()
        snap = readiness.snapshot()
        assert snap["chain_scan"]["state"] == "done"
        assert snap["chain_scan"]["verified_through"] == audit_path.stat().st_size
        index.close()

        # A broken link stops the scan at the break with its coordinates.
        readiness2 = _readiness()
        lines = audit_path.read_text(encoding="utf-8").splitlines(keepends=True)
        rec = json.loads(lines[10])
        rec["prev_hash"] = "e" * 64
        lines[10] = json.dumps(rec) + "\n"
        audit_path.write_text("".join(lines), encoding="utf-8")
        index2 = _open_index(tmp_path / "index2.sqlite", defer_migration=True)
        compactor2 = _default_compactor(
            index2,
            store=SegmentedReceiptStore(base_dir=store_dir),
            readiness=readiness2,
            watchdog=_watchdog(),
            audit_chain=audit_path,
        )
        compactor2.run_phases()
        scan = readiness2.snapshot()["chain_scan"]
        assert scan["state"] == "refused"
        assert "chain_refused" in scan["error"]
        assert "line 11" in scan["error"]
        index2.close()

    def test_background_start_reports_while_building(self, tmp_path):
        from raucle.receipt_store import SegmentedReceiptStore

        store_dir, envelopes = self._seeded_store(tmp_path, count=200)
        index = _open_index(tmp_path / "index.sqlite", defer_migration=True)
        readiness, watchdog = _readiness(), _watchdog()

        import raucle.receipt_index as ri

        original = ri.ReceiptIndex.index_batch
        gate = threading.Event()
        sweep_started = threading.Event()

        def slow_batch(self, items, segment=None, *, state_updates=None):
            if state_updates is not None and "cursor" in state_updates:
                # The sweep's first cursor batch is the observation
                # point: by the phase ordering contract the tail window
                # (session continuity) has already landed by now.
                sweep_started.set()
                gate.wait(timeout=10)  # hold the sweep open for observation
            return original(self, items, segment=segment, state_updates=state_updates)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(ri.ReceiptIndex, "index_batch", slow_batch)
            compactor = _default_compactor(
                index,
                store=SegmentedReceiptStore(base_dir=store_dir),
                readiness=readiness,
                watchdog=watchdog,
                batch_rows=4,
            )
            compactor.start_background()
            try:
                # Mid-build the snapshot reports building with progress,
                # never a ready lie. The observation waits for the
                # sweep's first cursor batch (the gate above), so the
                # assertion below is deterministic, not a race against
                # the tail window landing.
                assert sweep_started.wait(timeout=10), "compactor never reached the sweep"
                snap = readiness.snapshot()
                assert snap["receipt_index"]["state"] == "building"
                assert 0.0 <= snap["receipt_index"]["progress"] <= 1.0
                assert snap["session_continuity"] == "ready"  # tail window landed first
            finally:
                gate.set()
                compactor.join(timeout=30)
        assert readiness.snapshot()["receipt_index"]["state"] == "ready"
        assert index.count() == len(envelopes)
        index.close()


# ---------------------------------------------------------------------------
# AC1: the boot path's peak allocations are flat in store size
# ---------------------------------------------------------------------------


class TestBootMemoryFlatness:
    def _boot_peak_bytes(self, tmp_path, *, receipts: int, audit_events: int) -> int:
        """Peak traced allocations across the bounded boot path: index
        open (deferred), the compactor's phases and the sink resume."""
        from raucle.audit import HashChainSink
        from raucle.receipt_store import SegmentedReceiptStore

        store_dir = tmp_path / "receipts"
        now = int(time.time())
        envelopes = [_envelope(now - i, receipt_no=i) for i in range(receipts)]
        _seed_segmented_store(store_dir, envelopes, max_segment_bytes=32 * 1024)
        audit_path = tmp_path / "audit.jsonl"
        _seed_audit_chain(audit_path, events=audit_events)

        tracemalloc.start()
        try:
            index = _open_index(tmp_path / "index.sqlite", defer_migration=True)
            readiness, watchdog = _readiness(), _watchdog()
            compactor = _default_compactor(
                index,
                store=SegmentedReceiptStore(base_dir=store_dir),
                readiness=readiness,
                watchdog=watchdog,
                batch_rows=128,
                scan_window_bytes=256 * 1024,
                audit_chain=audit_path,
            )
            compactor.run_phases()
            sink = HashChainSink(audit_path, scan_window_bytes=256 * 1024)
            sink.close()
            index.close()
        finally:
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        return peak

    def test_peak_allocations_are_flat_in_store_size(self, tmp_path):
        small = self._boot_peak_bytes(tmp_path / "s", receipts=800, audit_events=2_000)
        big = self._boot_peak_bytes(tmp_path / "b", receipts=1_600, audit_events=4_000)
        # Flatness: doubling the store must not double the boot's peak.
        # The absolute ceiling is one bounded window plus one bounded
        # batch plus working slack (a whole-store boot at this fixture's
        # size maps several times the ceiling, so it cannot slip through);
        # the flatness delta is the property AC1 pins.
        ceiling = 4 * _MB
        assert small < ceiling, f"1x boot peak {small} exceeds the bounded ceiling"
        assert big < ceiling, f"2x boot peak {big} exceeds the bounded ceiling"
        # Within noise of each other, expressed as a bounded absolute delta.
        assert abs(big - small) < 192 * 1024, (small, big)


# ---------------------------------------------------------------------------
# The SSE replay tail: bounded memory per dashboard hit
# ---------------------------------------------------------------------------


class TestSseTailBounded:
    def test_replay_tail_reads_a_window_not_the_file(self, tmp_path):
        from raucle.server import _iter_audit_events

        path = tmp_path / "gateway-audit.jsonl"
        with open(path, "w", encoding="utf-8") as fh:
            for i in range(20_000):
                fh.write(json.dumps({"index": i, "event": {"seq": i}}) + "\n")

        tracemalloc.start()
        try:
            frames = list(_iter_audit_events(str(path), replay=50, follow=False))
        finally:
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

        assert len(frames) == 50
        assert peak < 2 * _MB, f"replay tail peaked at {peak} bytes for 50 frames"
        # The frames are the true last 50 events, not a window artefact.
        last = json.dumps({"seq": 19_999}, ensure_ascii=False)
        assert frames[-1] == "data: " + last + "\n\n"
        assert json.loads(frames[0][len("data: ") :].strip())["seq"] == 19_950

    def test_replay_tail_skips_meta_lines(self, tmp_path):
        from raucle.server import _iter_audit_events

        path = tmp_path / "gateway-audit.jsonl"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"chain_meta": True, "signed": False}) + "\n")
            fh.write(json.dumps({"index": 0, "event": {"seq": 0}}) + "\n")
            fh.write(json.dumps({"checkpoint": True, "index": 1, "merkle_root": "x"}) + "\n")
            fh.write(json.dumps({"index": 1, "event": {"seq": 1}}) + "\n")

        frames = list(_iter_audit_events(str(path), replay=50, follow=False))
        assert len(frames) == 2
        assert json.loads(frames[0][len("data: ") :].strip())["seq"] == 0


# ---------------------------------------------------------------------------
# AC6: the preflight projection re-derived from the window budget
# ---------------------------------------------------------------------------


class TestPreflightBudget:
    def _config(self, tmp_path, **overrides):
        from raucle.gateway import GatewayConfig

        return GatewayConfig(
            host="127.0.0.1",
            signer_backend="local",
            policy_file="",
            receipt_store=str(tmp_path / "receipts.jsonl"),
            receipt_store_dir=str(tmp_path / "receipts"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            audit_persist=True,
            audit_log_file=str(tmp_path / "gateway-audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            **overrides,
        )

    def test_projection_is_the_budget_not_the_store_size(self, tmp_path):
        from raucle.chain_rotation import boot_memory_preflight

        config = self._config(tmp_path)
        report = boot_memory_preflight(config)
        budget = report["budget"]
        assert budget["scan_window_mb"] == config.boot_scan_window_mb
        assert budget["index_cache_mb"] == config.index_cache_mb
        assert report["projected_mb"] == sum(
            budget[k] for k in ("baseline_gateway_mb", "scan_window_mb", "index_cache_mb")
        )

        # A huge store no longer moves the projection: the invariant.
        big = tmp_path / "big.pad"
        big.write_bytes(b"x" * (24 * _MB))
        config.audit_chain = str(big)
        report2 = boot_memory_preflight(config)
        assert report2["projected_mb"] == report["projected_mb"]

    def test_shrinking_windows_lower_the_projection(self, tmp_path):
        from raucle.chain_rotation import boot_memory_preflight

        wide = self._config(tmp_path, boot_scan_window_mb=256, index_cache_mb=128)
        narrow = self._config(tmp_path, boot_scan_window_mb=16, index_cache_mb=16)
        assert (
            boot_memory_preflight(narrow)["projected_mb"]
            < boot_memory_preflight(wide)["projected_mb"]
        )

    def test_budget_over_ceiling_refuses_before_binding(self, tmp_path):
        from raucle.chain_rotation import boot_memory_preflight

        # The default budget (baseline 256 + 64 + 64) cannot fit under a
        # 128 MB ceiling, so the boot refuses before binding: the exact
        # AC6 contract. Shrinking the windows is the honest remedy.
        config = self._config(tmp_path, boot_scan_window_mb=64, boot_mem_ceiling_mb=128)
        with pytest.raises(BootMemoryCeilingExceeded) as excinfo:
            boot_memory_preflight(config)
        assert "RAUCLE_BOOT_MEM_CEILING_MB" in str(excinfo.value)

        small = self._config(
            tmp_path, boot_scan_window_mb=16, index_cache_mb=16, boot_mem_ceiling_mb=512
        )
        assert boot_memory_preflight(small)["projected_mb"] <= 512

        config2 = self._config(tmp_path, boot_scan_window_mb=4096, boot_mem_ceiling_mb=512)
        with pytest.raises(BootMemoryCeilingExceeded) as excinfo:
            boot_memory_preflight(config2)
        msg = str(excinfo.value)
        assert "raucle rotate-chain" in msg
        assert "512" in msg
        assert "RAUCLE_BOOT_SCAN_WINDOW_MB" in msg


# ---------------------------------------------------------------------------
# AC2 + AC3: the real app factory serves while the compactor is mid-build
# ---------------------------------------------------------------------------


class TestBindFirstAgainstRealApp:
    """AC2: the server binds and /health answers while the compactor is
    mid-build (a controlled-slow compactor against the real app
    factories). AC3: the receipt query surfaces refuse by name with
    progress, never an empty 200 that looks complete, then serve real
    answers once the build lands."""

    def _config(self, tmp_path, store_dir):
        from raucle.gateway import GatewayConfig

        policy = tmp_path / "policies.yaml"
        policy.write_text(
            "version: 1\n"
            "issuer: test.bank\n"
            "policies:\n"
            "  - tool: web.fetch\n"
            "    agent_id: agent:svc\n"
            "    ttl_seconds: 60\n"
            "    constraints: {}\n"
        )
        return GatewayConfig(
            host="127.0.0.1",
            admin_api_key="test-admin-key",
            signer_backend="local",
            policy_file=str(policy),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            receipt_store_dir=str(store_dir),
            receipt_index_path=str(tmp_path / "index.sqlite"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            emit_receipts=True,
        )

    def test_health_answers_and_receipts_refuse_while_building(self, tmp_path):
        from fastapi.testclient import TestClient

        import raucle.receipt_index as ri
        from raucle.gateway import RaucleGateway, UserManager
        from raucle.gateway_app import create_admin_app

        store_dir, _envelopes = TestBootCompactorPhases()._seeded_store(tmp_path, count=200)
        config = self._config(tmp_path, store_dir)

        gate = threading.Event()
        original = ri.ReceiptIndex.index_batch

        def slow_batch(self, items, segment=None, *, state_updates=None):
            gate.wait(timeout=15)  # hold every phase open for observation
            return original(self, items, segment=segment, state_updates=state_updates)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(ri.ReceiptIndex, "index_batch", slow_batch)
            # Bind-first: the constructor returns instantly with the
            # compactor mid-build, so the factories serve immediately.
            gateway = RaucleGateway(config)
            users = UserManager()
            users.add_user("admin-key", "admin", "Admin")
            client = TestClient(create_admin_app(gateway, users))
            headers = {"Authorization": "Bearer admin-key"}
            try:
                health = client.get("/health").json()
                assert health["status"] == "ok"
                snap = health["readiness"]
                assert snap["receipt_index"]["state"] in ("building", "pending")
                assert snap["session_continuity"] == "pending"
                # AC3: the named refusal, never an empty 200.
                resp = client.get("/api/receipts", headers=headers)
                assert resp.status_code == 503
                detail = resp.json()["detail"]
                assert detail["error"] == "receipt_index_building"
                assert 0.0 <= detail["progress"] <= 1.0
            finally:
                gate.set()
                gateway._boot_compactor.join(timeout=30)
        snap = gateway.boot_readiness.snapshot()
        assert snap["receipt_index"]["state"] == "ready"
        assert snap["session_continuity"] == "ready"
        # After completion the surface serves the real projection.
        resp = client.get("/api/receipts?limit=1000", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 200
        assert len(body["receipts"]) == 200


class TestSessionContinuityPendingRefusal:
    """AC5: a session-rule call before continuity lands receives the
    named session_continuity_pending refusal (a receipted deny), never
    a silently cold window; once continuity lands, the same call serves
    on the rule's own terms."""

    def test_session_rule_call_refuses_by_name_while_pending(self, tmp_path):
        from fastapi.testclient import TestClient

        import raucle.receipt_index as ri
        from raucle.gateway import GatewayConfig, RaucleGateway
        from raucle.gateway_app import create_gateway_app

        policy = tmp_path / "policies.yaml"
        policy.write_text(
            "version: 1\n"
            "issuer: test.bank\n"
            "session_rules:\n"
            "  - id: sr-storm\n"
            "    kind: repeated_deny_storm\n"
            "    threshold: 3\n"
            "    window_seconds: 600\n"
            "policies:\n"
            "  - tool: web.fetch\n"
            "    agent_id: agent:svc\n"
            "    ttl_seconds: 60\n"
            "    constraints: {}\n"
        )
        # A seeded store: the compactor's tail-window phase has real
        # work to hold open, so continuity is genuinely pending while
        # the build runs (an empty store lands it instantly, correctly).
        store_dir, _seeded = TestBootCompactorPhases()._seeded_store(tmp_path, count=60)
        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="test-admin-key",
            signer_backend="local",
            policy_file=str(policy),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            receipt_store_dir=str(store_dir),
            receipt_index_path=str(tmp_path / "index.sqlite"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "registry.jsonl"),
            emit_receipts=True,
        )

        gate = threading.Event()
        original = ri.ReceiptIndex.index_batch

        def stuck_batch(self, items, segment=None, *, state_updates=None):
            gate.wait(timeout=15)
            return original(self, items, segment=segment, state_updates=state_updates)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(ri.ReceiptIndex, "index_batch", stuck_batch)
            gateway = RaucleGateway(config)
            client = TestClient(create_gateway_app(gateway))
            body = {
                "tool": "web.fetch",
                "args": {},
                "agent_id": "agent:svc",
                "session_id": "boot-1",
            }
            try:
                resp = client.post("/gate", json=body).json()
                assert resp["decision"] == "deny"
                assert "session_continuity_pending" in resp["reason"]
            finally:
                gate.set()
                gateway._boot_compactor.join(timeout=30)
        assert gateway.boot_readiness.session_continuity_ready()
        # Continuity landed: the same call serves on the rule's own
        # terms (one deny so far, under the storm threshold).
        resp = client.post("/gate", json=body).json()
        assert resp["decision"] == "allow"


class TestEmptyAuditChainConfig:
    """An empty RAUCLE_AUDIT_CHAIN must not resolve to the process CWD.

    Path("") is "." and "." exists, so a bare exists() check would hand
    the compactor a directory as the audit chain: the scan would fault
    and refuse the whole index build. No chain configured, no scan.
    """

    def test_an_empty_audit_chain_config_scans_nothing_and_builds(self, tmp_path):
        from fastapi.testclient import TestClient

        from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
        from raucle.gateway_app import create_admin_app

        policy = tmp_path / "policies.yaml"
        policy.write_text(
            "version: 1\n"
            "issuer: test.bank\n"
            "policies:\n"
            "  - tool: web.fetch\n"
            "    agent_id: agent:svc\n"
            "    ttl_seconds: 60\n"
            "    constraints: {}\n"
        )
        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="test-admin-key",
            signer_backend="local",
            policy_file=str(policy),
            receipt_store=str(tmp_path / "receipts.jsonl"),
            receipt_store_dir=str(tmp_path / "receipts"),
            receipt_index_path=str(tmp_path / "index.sqlite"),
            audit_chain="",
            registry_path=str(tmp_path / "registry.jsonl"),
            emit_receipts=True,
        )
        gateway = RaucleGateway(config)
        users = UserManager()
        users.add_user("admin-key", "admin", "Admin")
        client = TestClient(create_admin_app(gateway, users))
        gateway._boot_compactor.join(timeout=15)
        snap = gateway.boot_readiness.snapshot()
        # No chain configured: the scan surface never starts, and the
        # empty store's build completes instead of refusing.
        assert snap["chain_scan"]["state"] == "idle"
        assert snap["receipt_index"]["state"] == "ready"
        assert client.get("/health").json()["status"] == "ok"
