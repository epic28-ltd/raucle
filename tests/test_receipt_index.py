"""Receipt index tests (PR-C Task C1): SQLite projection over the chain.

The index is a QUERY CACHE, never a trust decision: it can be dropped and
rebuilt from the segments at any time, and verification always reads the
chain. These tests pin that contract.
"""

import json

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


@pytest.fixture()
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
