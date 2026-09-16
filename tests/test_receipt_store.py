"""Tests for the segmented receipt store (PR-B Task B2)."""

import json

import pytest

from raucle.receipt_store import SegmentedReceiptStore


@pytest.fixture()
def store_dir(tmp_path):
    return tmp_path / "receipts"


def _line(i: int) -> str:
    receipt_hash = f"sha256:{i:064x}"
    return json.dumps({"receipt_hash": receipt_hash, "jws": f"h{i}.p{i}.s{i}"})


class TestSegmentedReceiptStore:
    def test_first_write_creates_current_segment(self, store_dir):
        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=1024)
        store.append_line(_line(1))
        assert (store_dir / "seg-000000.jsonl").exists()
        assert store.active_segment == "seg-000000.jsonl"

    def test_rollover_at_threshold(self, store_dir):
        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=300)
        # each line ~100 bytes; 3 lines exceed 300
        for i in range(5):
            store.append_line(_line(i))
        segments = sorted(p.name for p in store_dir.glob("seg-*.jsonl"))
        assert len(segments) >= 2, segments
        # earlier segments sealed, only the last is active
        assert store.active_segment == segments[-1]

    def test_sealed_segments_immutable(self, store_dir):
        """The store never writes to a sealed segment again (the contract
        that matters); the file is also chmod'd read-only as defence in
        depth."""
        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=300)
        for i in range(5):
            store.append_line(_line(i))
        sealed = sorted(store_dir.glob("seg-*.jsonl"))[0]
        content = sealed.read_text()
        import stat as _stat

        assert not (sealed.stat().st_mode & (_stat.S_IWUSR | _stat.S_IWGRP | _stat.S_IWOTH))
        # appending more never touches the sealed segment
        for i in range(5, 10):
            store.append_line(_line(i))
        assert sealed.read_text() == content

    def test_rollover_writes_checkpoint_record(self, store_dir):
        """A sealed segment gets a sidecar .meta with the seal metadata; the
        segment file itself stays a pure receipt chain."""
        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=300)
        for i in range(5):
            store.append_line(_line(i))
        sealed = sorted(store_dir.glob("seg-*.jsonl"))[0]
        meta_path = sealed.with_suffix(".jsonl.meta") if sealed.suffix == ".jsonl" else None
        meta_path = store_dir / (sealed.name + ".meta")
        assert meta_path.exists(), "sealed segment lacks its .meta sidecar"
        meta = json.loads(meta_path.read_text())
        assert meta["segment"] == sealed.name
        assert meta["receipt_count"] > 0
        assert meta["last_receipt_hash"]
        # and the segment contains ONLY receipt envelopes
        for line in sealed.read_text().splitlines():
            if line.strip():
                rec = json.loads(line)
                assert "receipt_hash" in rec and "jws" in rec

    def test_flush_durability(self, store_dir):
        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=1024)
        store.append_line(_line(1))
        # a new instance sees the line (append flushed per write)
        SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=1024)
        assert (store_dir / "seg-000000.jsonl").read_text().strip() != ""

    def test_total_count_across_segments(self, store_dir):
        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=300)
        n = 20
        for i in range(n):
            store.append_line(_line(i))
        assert store.total_receipt_count() == n

    def test_recent_across_segments(self, store_dir):
        """The query view reads newest-first across all segments without
        loading everything into memory."""
        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=300)
        for i in range(20):
            store.append_line(_line(i))
        recent = store.recent(limit=5)
        assert len(recent) == 5
        # newest first: hashes 19..15
        hashes = [r["receipt_hash"] for r in recent]
        assert hashes[0].endswith(f"{19:064x}")
        assert hashes[-1].endswith(f"{15:064x}")

    def test_segment_exportable_as_chain(self, store_dir):
        """A sealed segment IS a valid chain file: audit-pack build accepts it
        as the --chain argument (it is a plain JSONL receipt file)."""
        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=300)
        for i in range(10):
            store.append_line(_line(i))
        sealed = sorted(store_dir.glob("seg-*.jsonl"))[0]
        records = [json.loads(line) for line in sealed.read_text().splitlines() if line.strip()]
        # every record is a minimal envelope; no checkpoint lines inside
        assert all({"receipt_hash", "jws"} <= set(r.keys()) for r in records)
        assert all(not r.get("checkpoint") for r in records)
        # the sidecar carries the seal
        meta = json.loads((store_dir / (sealed.name + ".meta")).read_text())
        assert meta["receipt_count"] == len(records)

    def test_empty_store_reports_zero(self, store_dir):
        store = SegmentedReceiptStore(base_dir=store_dir)
        assert store.total_receipt_count() == 0
        assert store.recent(limit=10) == []
        assert store.active_segment is None

    def test_by_hash_lookup(self, store_dir):
        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=300)
        for i in range(10):
            store.append_line(_line(i))
        target = f"sha256:{7:064x}"
        rec = store.find_by_hash(target)
        assert rec is not None
        assert rec["receipt_hash"] == target

    def test_seal_now_manually(self, store_dir):
        """Operator action: seal the active segment early (e.g. retention
        policy boundary)."""
        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=1_000_000)
        store.append_line(_line(1))
        store.append_line(_line(2))
        sealed = store.seal_now()
        assert sealed is not None
        assert store.active_segment != sealed
