"""Tests for the segmented receipt store (PR-B Task B2)."""

import json

import pytest

from raucle.receipt_store import SegmentedReceiptStore


@pytest.fixture
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
                assert "receipt_hash" in rec
                assert "jws" in rec

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


class TestRestartResumesWritableTail:
    """Q8: a restart must resume the existing writable tail segment.

    Before the fix the constructor recorded the writable last segment but
    never opened it, so the first append started a NEW numbered segment and
    the old one was orphaned: writable, unsealed, never reopened.
    """

    def test_restart_resumes_existing_writable_segment(self, store_dir):
        import os

        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=1 << 20)
        store.append_line(_line(1))
        del store
        # "restart": a fresh store instance over the same directory
        restart = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=1 << 20)
        restart.append_line(_line(2))
        # the appended line lands IN the existing segment, not a new one
        assert sorted(p.name for p in store_dir.glob("seg-*.jsonl")) == ["seg-000000.jsonl"]
        contents = (store_dir / "seg-000000.jsonl").read_text()
        assert _line(1) in contents
        assert _line(2) in contents
        assert restart.active_segment == "seg-000000.jsonl"
        # the resumed segment size is tracked on disk, not assumed zero
        assert os.path.getsize(store_dir / "seg-000000.jsonl") == len(
            (_line(1) + "\n" + _line(2) + "\n").encode("utf-8")
        )

    def test_resumed_segment_seals_through_the_same_segment(self, store_dir):
        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=300)
        store.append_line(_line(1))
        store.append_line(_line(2))
        del store
        restart = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=300)
        for i in range(3, 7):
            restart.append_line(_line(i))
        # the grown past-threshold segment sealed THROUGH seg-000000
        meta = json.loads((store_dir / "seg-000000.jsonl.meta").read_text())
        assert meta["segment"] == "seg-000000.jsonl"
        assert meta["receipt_count"] == len(
            [
                line
                for line in (store_dir / "seg-000000.jsonl").read_text().splitlines()
                if line.strip()
            ]
        )
        # the seal still starts the next numbered segment at len(segments()):
        # contiguous numbering from zero, whatever the crossing count
        segments = sorted(p.name for p in store_dir.glob("seg-*.jsonl"))
        assert segments == [f"seg-{k:06d}.jsonl" for k in range(len(segments))]
        assert restart.active_segment == segments[-1]
        # the last appended receipt lives past the resumed segment (in the
        # chain the rollover produced), and the first receipt stayed in the
        # resumed, now-sealed one
        assert _line(1) in (store_dir / "seg-000000.jsonl").read_text()
        assert restart.total_receipt_count() == 6
        assert restart.find_by_hash(f"sha256:{6:064x}") is not None
        # the sealed segment is read-only again
        import stat as _stat

        mode = (store_dir / "seg-000000.jsonl").stat().st_mode
        assert not (mode & (_stat.S_IWUSR | _stat.S_IWGRP | _stat.S_IWOTH))

    def test_no_orphan_writable_segment_after_restart_append(self, store_dir):
        import os

        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=1 << 20)
        store.append_line(_line(1))
        del store
        restart = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=1 << 20)
        restart.append_line(_line(2))
        writable = [p.name for p in store_dir.glob("seg-*.jsonl") if os.access(p, os.W_OK)]
        # exactly one writable segment remains: the active one
        assert writable == [restart.active_segment]


class TestSealRefusesCorruptLines:
    """Q8: a seal of a segment with an unparsable line must fail closed by
    name, never silently seal the torn record read-only."""

    def test_seal_now_refuses_unparseable_line(self, store_dir):
        from raucle.errors import ReceiptStoreSealRefused

        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=1 << 20)
        store.append_line(_line(1))
        seg = store_dir / "seg-000000.jsonl"
        # a torn/corrupt line lands in the segment outside the store API
        with open(seg, "a", encoding="utf-8") as fh:
            fh.write("{not json\n")
        # the store appends a further valid line past the corrupt one
        store.append_line(_line(2))
        with pytest.raises(ReceiptStoreSealRefused) as excinfo:
            store.seal_now()
        message = str(excinfo.value)
        assert "seg-000000.jsonl" in message
        assert "line 2" in message
        # no meta is written for a refused seal
        assert not (store_dir / "seg-000000.jsonl.meta").exists()
        # the active file is still open and writable: the operator gets the
        # refusal, then appends successfully and decides about the seal
        store.append_line(_line(3))
        assert _line(3) in seg.read_text()
        assert store.active_segment == "seg-000000.jsonl"

    def test_restart_with_torn_tail_refuses_at_open(self, store_dir):
        from raucle.errors import ReceiptStoreSealRefused

        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=1 << 20)
        store.append_line(_line(1))
        store.append_line(_line(2))
        seg = store_dir / "seg-000000.jsonl"
        with open(seg, "a", encoding="utf-8") as fh:
            fh.write("{not json")  # torn write: partial record, no newline
        restart = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=1 << 20)
        # the named refusal fires at OPEN (the lazy resume on first append),
        # never silently past a torn tail
        with pytest.raises(ReceiptStoreSealRefused) as excinfo:
            restart.append_line(_line(3))
        assert "seg-000000.jsonl" in str(excinfo.value)
        assert "line 3" in str(excinfo.value)
        # fail closed: no segment was started, no orphan exists
        assert sorted(p.name for p in store_dir.glob("seg-*.jsonl")) == ["seg-000000.jsonl"]
        assert not (store_dir / "seg-000000.jsonl.meta").exists()
        # the refusal is re-raised on the next append (state un-poisoned)
        with pytest.raises(ReceiptStoreSealRefused):
            restart.append_line(_line(4))

    def test_clean_seal_keeps_the_meta_contract(self, store_dir):
        """The all-clean path seals with the same meta content as before:
        downstream consumers stay unaffected by the fail-closed change."""
        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=1 << 20)
        for i in range(5):
            store.append_line(_line(i))
        assert store.seal_now() == "seg-000000.jsonl"
        meta = json.loads((store_dir / "seg-000000.jsonl.meta").read_text())
        assert meta["segment"] == "seg-000000.jsonl"
        assert meta["receipt_count"] == 5
        assert meta["last_receipt_hash"] == f"sha256:{4:064x}"
        assert isinstance(meta["sealed_at"], float)

    def test_empty_segment_still_seals(self, store_dir):
        """A zero-receipt seal keeps working (empty existing segment picked
        up on restart, then sealed by name)."""
        store_dir.mkdir(parents=True, exist_ok=True)
        (store_dir / "seg-000000.jsonl").touch()
        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=1 << 20)
        assert store.active_segment == "seg-000000.jsonl"
        assert store.seal_now() == "seg-000000.jsonl"
        meta = json.loads((store_dir / "seg-000000.jsonl.meta").read_text())
        assert meta["receipt_count"] == 0
        assert meta["last_receipt_hash"] == ""


class TestSealMetaSignature:
    """Q8: sealed metas carry a verifiable house signature, or record their
    unsigned state honestly."""

    def _seal_signed(self, store_dir):
        from raucle.audit import Ed25519Signer

        signer = Ed25519Signer.generate()
        store = SegmentedReceiptStore(
            base_dir=store_dir, max_segment_bytes=1 << 20, seal_signer=signer
        )
        store.append_line(_line(1))
        store.append_line(_line(2))
        store.seal_now()
        meta = json.loads((store_dir / "seg-000000.jsonl.meta").read_text())
        return meta, signer

    def test_verify_seal_meta_accepts_store_sealed_meta(self, store_dir):
        from raucle.receipt_store import verify_seal_meta

        meta, signer = self._seal_signed(store_dir)
        verdict = verify_seal_meta(meta, signer.public_key_pem())
        assert verdict.verified is True
        assert verdict.unsigned is False
        assert not meta.get("unsigned")

    def test_verify_seal_meta_rejects_tampered_meta(self, store_dir):
        from raucle.receipt_store import verify_seal_meta

        meta, signer = self._seal_signed(store_dir)
        for field in ("receipt_count", "last_receipt_hash"):
            tampered = dict(meta)
            tampered[field] = 99 if field == "receipt_count" else "sha256:bad"
            verdict = verify_seal_meta(tampered, signer.public_key_pem())
            assert verdict.verified is False
            assert verdict.unsigned is False
            assert verdict.reason

    def test_unsigned_seal_records_its_state_honestly(self, store_dir):
        from raucle.receipt_store import verify_seal_meta

        store = SegmentedReceiptStore(base_dir=store_dir, max_segment_bytes=1 << 20)
        store.append_line(_line(1))
        store.seal_now()
        meta = json.loads((store_dir / "seg-000000.jsonl.meta").read_text())
        assert meta.get("unsigned") is True
        assert "signature" not in meta
        assert "key_id" not in meta
        verdict = verify_seal_meta(meta)
        assert verdict.unsigned is True
        assert verdict.verified is False
        assert verdict.reason
