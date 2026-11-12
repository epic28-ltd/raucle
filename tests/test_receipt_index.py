"""Receipt index tests (PR-C Task C1): SQLite projection over the chain.

The index is a QUERY CACHE, never a trust decision: it can be dropped and
rebuilt from the segments at any time, and verification always reads the
chain. These tests pin that contract.
"""

import asyncio
import contextlib
import gc
import json
import logging
import re

import pytest

from raucle.receipt_index import ReceiptIndex
from raucle.receipt_store import SegmentedReceiptStore


def _b64url_pad(s: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


def _make_receipt(
    i: int,
    tool: str = "lookup_balance",
    agent: str = "agent:svc",
    decision: str = "allow",
    trace: str = "",
) -> dict:
    """A decoded gate-receipt envelope (as recent()/find_by_hash returns)."""
    payload = {
        "iss": "raucle-gateway",
        "typ": "provenance-receipt/v1",
        "iat": 1758000000 + i,
        "agent_id": "agent:gate",
        "agent_key_id": "gatekey",
        "operation": "guardrail_scan",
        "parents": [],
        "taint": ["gate:observed"],
        "input_hash": f"ih{i}",
        "ruleset_hash": f"rh{tool}",
        "guardrail_verdict": decision,
        "x_gate": {
            "decision": decision,
            "reason": f"r{i}",
            "tool": tool,
            "agent_id": agent,
            "source": agent,
            "destination": tool,
            "policy": f"{tool}.yaml",
            "latency_us": 100 + i,
            "trace_id": trace,
        },
    }
    # fake jws: base64 header.payload.sig (index decodes payload)
    import base64

    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    jws = f"{b64({'alg': 'EdDSA'})}.{b64(payload)}.sig"
    return {"receipt_hash": f"sha256:{i:064x}", "jws": jws}


@pytest.fixture
def index(tmp_path):
    return ReceiptIndex(sqlite_path=tmp_path / "index.sqlite")


class TestReceiptIndex:
    def test_insert_and_query_by_agent(self, index):
        index.index_receipt(_make_receipt(1, agent="agent:pay"))
        index.index_receipt(_make_receipt(2, agent="agent:hr"))
        rows = index.query(agent_id="agent:pay")
        assert len(rows) == 1
        assert rows[0]["agent_id"] == "agent:pay"

    def test_query_by_tool_decision_time(self, index):
        index.index_receipt(_make_receipt(1, tool="t1", decision="allow"))
        index.index_receipt(_make_receipt(2, tool="t2", decision="deny"))
        index.index_receipt(_make_receipt(3, tool="t1", decision="allow"))
        assert len(index.query(tool="t1")) == 2
        assert len(index.query(decision="deny")) == 1
        assert len(index.query(tool="t1", decision="deny")) == 0
        # since/until are inclusive time bounds
        since = 1758000002
        until = 1758000002
        rows = index.query(since=since, until=until)
        assert {r["receipt_hash"] for r in rows} == {f"sha256:{2:064x}"}

    def test_query_by_trace(self, index):
        index.index_receipt(_make_receipt(1, trace="t-abc"))
        index.index_receipt(_make_receipt(2, trace="t-xyz"))
        index.index_receipt(_make_receipt(3, trace="t-abc"))
        assert len(index.query(trace_id="t-abc")) == 2

    def test_cursor_pagination(self, index):
        for i in range(25):
            index.index_receipt(_make_receipt(i))
        page1 = index.query(limit=10)
        assert len(page1) == 10
        # newest first
        assert page1[0]["receipt_hash"] == f"sha256:{24:064x}"
        page2 = index.query(limit=10, cursor=index.cursor_for(page1[-1]))
        assert len(page2) == 10
        hashes = {r["receipt_hash"] for r in page1} | {r["receipt_hash"] for r in page2}
        assert len(hashes) == 20  # no overlap

    def test_cursor_handles_iat_ties(self, index):
        """Burst traffic: identical iat values must not drop records."""
        for i in range(20):
            rec = _make_receipt(i)
            index.index_receipt(rec)
        # force all rows to the same iat via direct SQL (burst simulation)
        index._conn.execute("UPDATE receipts SET iat = 1000")
        index._conn.commit()
        page1 = index.query(limit=10)
        assert len(page1) == 10
        page2 = index.query(limit=10, cursor=index.cursor_for(page1[-1]))
        assert len(page2) == 10
        hashes = {r["receipt_hash"] for r in page1} | {r["receipt_hash"] for r in page2}
        assert len(hashes) == 20  # ties survive pagination

    def test_identical_attempts_projected_twice(self, index):
        """Two byte-identical same-second attempts are distinct events.

        The signed payload of two identical gate calls can be fully
        identical (second-granularity iat and equal measured latency), but
        each attempt is a separate event in the chain of record; the
        disposable index must project both, not collapse them.
        Regression: INSERT OR REPLACE keyed on receipt_hash silently
        dropped the second attempt and degraded trace queries to 1.
        """
        rec = _make_receipt(1, trace="t-dup")
        index.index_receipt(rec)
        index.index_receipt(rec)
        assert index.count() == 2
        rows = index.query(trace_id="t-dup")
        assert len(rows) == 2

    def test_cursor_survives_identical_hash_page_boundary(self, index):
        """Duplicate hashes across a page boundary survive keyset pagination."""
        rec = _make_receipt(7, trace="t-page")
        index.index_receipt(rec)
        index.index_receipt(rec)  # same iat, same hash, two rows
        page1 = index.query(limit=1)
        assert len(page1) == 1
        page2 = index.query(limit=1, cursor=index.cursor_for(page1[-1]))
        assert len(page2) == 1
        assert page2[0]["rowid"] != page1[0]["rowid"]
        page3 = index.query(limit=1, cursor=index.cursor_for(page2[-1]))
        assert page3 == []

    def test_schema_migration_preserves_rows(self, tmp_path):
        """An index built by the old (PK-dedup) schema survives the upgrade."""
        import sqlite3 as _s

        db = tmp_path / "old.sqlite"
        conn = _s.connect(str(db))
        conn.execute(
            "CREATE TABLE receipts (receipt_hash TEXT PRIMARY KEY, iat INTEGER NOT NULL,"
            " agent_id TEXT NOT NULL, tool TEXT NOT NULL, decision TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO receipts VALUES ('sha256:abc', 1758000001, 'agent:svc', 't', 'allow')"
        )
        conn.commit()
        conn.close()
        index = ReceiptIndex(sqlite_path=db)
        assert index.count() == 1  # copied across, not dropped
        assert index._conn.execute("PRAGMA user_version").fetchone()[0] == 2

    def test_rebuild_from_store(self, tmp_path):
        """The projection contract: drop the index, rebuild from segments."""
        store = SegmentedReceiptStore(base_dir=tmp_path / "segs", max_segment_bytes=2048)
        for i in range(30):
            store.append_line(json.dumps(_make_receipt(i, trace=f"tr{i % 5}")))
        idx = ReceiptIndex(sqlite_path=tmp_path / "i.sqlite")
        idx.rebuild_from_store(store)
        assert idx.count() == 30
        assert len(idx.query(trace_id="tr0")) == 6

    def test_rebuild_idempotent_no_duplicates(self, tmp_path):
        store = SegmentedReceiptStore(base_dir=tmp_path / "segs")
        for i in range(5):
            store.append_line(json.dumps(_make_receipt(i)))
        idx = ReceiptIndex(sqlite_path=tmp_path / "i.sqlite")
        idx.rebuild_from_store(store)
        idx.rebuild_from_store(store)  # second rebuild
        assert idx.count() == 5

    def test_concurrent_reader_during_writer(self, tmp_path):
        """WAL: a reader connection queries while the writer connection inserts."""
        import threading

        idx = ReceiptIndex(sqlite_path=tmp_path / "i.sqlite")
        stop = threading.Event()
        errors: list[Exception] = []

        def reader():
            while not stop.is_set():
                try:
                    idx.query(limit=5)
                except Exception as exc:
                    errors.append(exc)

        t = threading.Thread(target=reader)
        t.start()
        for i in range(50):
            idx.index_receipt(_make_receipt(i))
        stop.set()
        t.join(timeout=5)
        assert not errors

    def test_index_never_trusted_verification_reads_chain(self, tmp_path):
        """Tamper with the index; query answers change but the chain is
        untouched - documented separation of concerns."""
        store = SegmentedReceiptStore(base_dir=tmp_path / "segs")
        store.append_line(json.dumps(_make_receipt(1)))
        idx = ReceiptIndex(sqlite_path=tmp_path / "i.sqlite")
        idx.rebuild_from_store(store)
        # direct tamper
        import sqlite3

        conn = sqlite3.connect(tmp_path / "i.sqlite")
        conn.execute("UPDATE receipts SET agent_id = 'agent:tampered'")
        conn.commit()
        conn.close()
        rows = idx.query()
        assert rows[0]["agent_id"] == "agent:tampered"  # index reflects the tamper
        # but the chain file is pristine
        chain_rec = json.loads(
            store.recent(limit=1)[0]["jws"].split(".")[1]
            and _b64url_pad(store.recent(limit=1)[0]["jws"].split(".")[1])
        )
        assert chain_rec["x_gate"]["agent_id"] == "agent:svc"
        # and a rebuild repairs the index from the chain
        idx.rebuild_from_store(store)
        assert idx.query()[0]["agent_id"] == "agent:svc"

    def test_ancestry_walk(self, index):
        """C3 preview: parents-based ancestry traversal with cycle guard."""
        r0 = _make_receipt(0)
        r1 = _make_receipt(1)
        # parents live in the payload; index must store them
        index.index_receipt(r0)
        index.index_receipt(r1)
        # synthesize a linked receipt: child cites r0's hash as parent
        child = _make_receipt(2)
        import base64

        payload = json.loads(_b64url_pad(child["jws"].split(".")[1]))
        payload["parents"] = [r0["receipt_hash"]]
        b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        parts = child["jws"].split(".")
        child["jws"] = f"{parts[0]}.{b64}.{parts[2]}"
        index.index_receipt(child)
        ancestors = index.ancestry(child["receipt_hash"])
        hashes = {r["receipt_hash"] for r in ancestors["nodes"]}
        assert r0["receipt_hash"] in hashes
        assert child["receipt_hash"] in hashes

    def test_ancestry_depth_cap(self, index):
        nodes = [_make_receipt(i) for i in range(60)]
        # linear chain: each cites the previous
        import base64

        for i, node in enumerate(nodes):
            payload = json.loads(_b64url_pad(node["jws"].split(".")[1]))
            if i > 0:
                payload["parents"] = [nodes[i - 1]["receipt_hash"]]
            b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
            parts = node["jws"].split(".")
            node["jws"] = f"{parts[0]}.{b64}.{parts[2]}"
            index.index_receipt(node)
        result = index.ancestry(nodes[-1]["receipt_hash"], max_depth=50)
        # the chain has 60 nodes; the cap must bite (<= 51: depths 0..50)
        assert len(result["nodes"]) <= 51
        assert len(result["nodes"]) < 60

    def test_ancestry_cycle_safe(self, index):
        """A corrupted cycle in parents cannot hang the walk."""
        import base64

        a = _make_receipt(1)
        payload = json.loads(_b64url_pad(a["jws"].split(".")[1]))
        payload["parents"] = [a["receipt_hash"]]  # self-cycle (corrupt data)
        b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        parts = a["jws"].split(".")
        a["jws"] = f"{parts[0]}.{b64}.{parts[2]}"
        index.index_receipt(a)
        result = index.ancestry(a["receipt_hash"])
        assert len(result["nodes"]) == 1  # visited-set prevents the loop

    def test_ancestry_missing_receipt(self, index):
        result = index.ancestry("sha256:nonexistent")
        assert result["nodes"] == []
        assert result["edges"] == []


# ---------------------------------------------------------------------------
# T-B3: streamed export disconnect — sink write count matches, or fault recorded
# ---------------------------------------------------------------------------


class TestStreamedExportSinkUnit:
    """The sink itself: write counting + disconnect fault recording."""

    def _sink(self):
        from raucle.export import StreamedExportSink

        return StreamedExportSink(source="unit")

    def test_full_iteration_write_count_matches_source(self):
        lines = [f"line{i}" for i in range(7)]
        sink = self._sink()
        out = list(sink.stream(iter(lines)))
        assert out == lines
        assert sink.written == 7
        assert sink.fault is None

    def test_early_close_records_fault_and_count(self):
        lines = [f"line{i}" for i in range(7)]
        sink = self._sink()
        gen = sink.stream(iter(lines))
        got = [next(gen) for _ in range(3)]
        assert got == ["line0", "line1", "line2"]
        gen.close()  # the consumer went away mid-stream
        assert sink.fault is not None
        assert sink.fault.records_written == 3
        assert sink.written == 3
        assert sink.fault.to_dict()["type"] == "stream_disconnect"

    def test_close_after_completion_records_nothing(self):
        sink = self._sink()
        gen = sink.stream(f"x{i}" for i in range(2))
        assert len(list(gen)) == 2
        gen.close()
        assert sink.fault is None
        assert sink.written == 2


class TestStreamedExportOverHTTP:
    """Gateway /api/receipts/export: full stream counts match the index;
    an early client close is recorded as a fault."""

    POLICY = """
version: 1
issuer: test.bank
policies:
  - tool: lookup_balance
    agent_id: agent:svc
    ttl_seconds: 60
    constraints:
      allow:
        account: ["ACC-001", "ACC-002"]
"""

    @pytest.fixture
    def indexed_gateway(self, tmp_path):
        from fastapi.testclient import TestClient

        from raucle.gateway import GatewayConfig, RaucleGateway, UserManager
        from raucle.gateway_app import create_admin_app, create_gateway_app

        policy = tmp_path / "policies.yaml"
        policy.write_text(self.POLICY)
        config = GatewayConfig(
            host="127.0.0.1",
            admin_api_key="admin-key",
            signer_backend="local",
            policy_file=str(policy),
            receipt_store=str(tmp_path / "flat.jsonl"),
            audit_chain=str(tmp_path / "audit.jsonl"),
            registry_path=str(tmp_path / "reg.jsonl"),
            emit_receipts=True,
            receipt_store_dir=str(tmp_path / "segs"),
            receipt_segment_max_bytes=1_000_000,
            receipt_index_path=str(tmp_path / "idx.sqlite"),
        )
        gw = RaucleGateway(config)
        users = UserManager()
        users.add_user("admin-key", "admin", "Admin")
        gate = TestClient(create_gateway_app(gw))
        for i in range(5):
            resp = gate.post(
                "/gate",
                json={
                    "tool": "lookup_balance",
                    "args": {"account": "ACC-001"},
                    "agent_id": "agent:svc",
                },
                headers={"X-Trace-Id": f"trace-{i}"},
            )
            assert resp.status_code == 200, resp.text
        return gw, TestClient(create_admin_app(gw, users))

    AUTH = {"Authorization": "admin-key"}

    def test_full_stream_write_count_matches_index(self, indexed_gateway, caplog):
        gw, admin = indexed_gateway
        expected = gw._receipt_index.count()
        assert expected > 0
        with caplog.at_level(logging.INFO, logger="raucle.export"):
            resp = admin.get("/api/receipts/export", headers=self.AUTH)
        lines = [line for line in resp.text.splitlines() if line.strip()]
        assert len(lines) == expected
        indexed = {n["receipt_hash"] for n in gw._receipt_index.query(limit=expected)}
        assert len(indexed) == expected
        assert any(f"completed: {expected} records" in r.message for r in caplog.records)

    def test_early_client_close_is_recorded(self, indexed_gateway, caplog):
        """A client that hangs up mid-stream is a recorded fault, end to end.

        Hermetic driver: the recording happens when the export generator
        is CLOSED, and under starlette's TestClient a client hang-up
        cancels the response task, leaving that sync generator to be
        closed by the GC at an arbitrary later time — a race that reads
        as a missing record exactly under load (reproduced 2/18 under
        six-way suite load). This test drives the REAL admin ASGI app
        directly (no server, no threads, no sockets) and ends the stream
        the way a transport reports a client hang-up: the send raises
        OSError after the first record, starlette converts it, and the
        app call unwinds to completion on the test thread before any
        assertion runs. The disconnect record is then already in the log.
        """
        gw, admin = indexed_gateway
        app = admin.app
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.4"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/api/receipts/export",
            "raw_path": b"/api/receipts/export",
            "query_string": b"",
            "root_path": "",
            "headers": [(b"authorization", b"admin-key")],
            "client": ("127.0.0.1", 111),
            "server": ("127.0.0.1", 80),
        }
        seen = []
        gone = {"client": False}

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            if message["type"] == "http.response.body" and message.get("body"):
                if gone["client"]:
                    raise OSError("client hung up")  # the socket is gone
                seen.append(message["body"])
                gone["client"] = True  # the client read one record, then left

        async def consume():
            # the hang-up ends in ClientDisconnect (or a middleware-collapsed
            # group around it); the stream body below is what the test reads
            with contextlib.suppress(Exception):
                await app(scope, receive, send)

        with caplog.at_level(logging.WARNING, logger="raucle.export"):
            asyncio.run(consume())
            gc.collect()  # finalize any generator the unwind left behind
        assert len(seen) == 1
        disconnects = [r for r in caplog.records if "disconnected" in r.getMessage()]
        assert disconnects, "disconnect was not recorded"
        m = re.fullmatch(
            r"streamed export receipts disconnected by client after (\d+) records",
            disconnects[0].getMessage(),
        )
        assert m is not None, disconnects[0].getMessage()
        # the sink wrote a bounded amount then stopped; the disconnect
        # is recorded with the actual write count (the yield that raised
        # had already been counted when the send refused it)
        assert int(m.group(1)) >= len(seen)
        assert int(m.group(1)) < gw._receipt_index.count()
