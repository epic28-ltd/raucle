"""D (Q11): the audit chain survives concurrent writers across processes.

The pre-Q11 HashChainSink held its head (_next_index/_prev_hash) in memory
behind a threading.Lock alone, so two processes (or two sink instances in
one process pointed at the same file) each forked the chain at the same
index: same index, different prev hashes. These tests pin the close:

- an inter-process flock around the append critical section, plus
- a head refresh under that lock that recomputes _next_index/_prev_hash
  from DISK state, so a writer that slept while another wrote resumes the
  true chain instead of forking it,
- RAUCLE_AUDIT_SINGLE_WRITER=1 gates a boot-time exclusive lock and
  refuses a second writer by name when the promised property is missing,
- a REAL multiprocessing stress test (a threading test is not sufficient
  for a cross-process write race), N=4 processes, M records each,
- the crash-mid-append case: a torn tail is named on the sink's status
  channel and the chain continues from the last COMPLETE record; the torn
  line is never silently skipped and surfaces on the next verify.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import signal
import time

import pytest

from raucle.audit import AuditVerifier, HashChainSink
from raucle.errors import ConfigurationError


def _count_events(path) -> list[dict]:
    """Every complete event record in the file, in file order."""
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict) and "event" in rec:
                events.append(rec)
    return events


def _append_worker(path_text: str, m: int, result_queue) -> None:
    """One stress worker: a fresh sink, M records, jittered cadence."""
    import random

    sink = HashChainSink(path_text)
    for i in range(m):
        time.sleep(random.random() * 0.002)
        sink.append({"worker": os.getpid(), "seq": i})
    sink.close()
    result_queue.put((os.getpid(), sink.event_count))


def _torn_writer_worker(path_text: str, go_flag: str, result_queue) -> None:
    """The crashed appender: writes a partial record, then dies mid-write.

    This is exactly the on-disk state a SIGKILL mid-append leaves: a
    torn last line (no newline terminator), flushed to the page cache of
    a still-alive machine.
    """
    while not os.path.exists(go_flag):
        time.sleep(0.01)
    sink = HashChainSink(path_text)
    torn = '{"index": 99, "timestamp": "crashed", "prev_hash": "ab'
    sink._file.write(torn)  # noqa: SLF001 - the test drives the real append handle
    sink._file.flush()  # noqa: SLF001
    os.kill(os.getpid(), signal.SIGKILL)


def _survivor_worker(
    path_text: str,
    phase1: int,
    phase2: int,
    marker_flag: str,
    go_flag: str,
    resume_flag: str,
    result_queue,
) -> None:
    """A writer that appends phase 1, then pauses while the appender
    dies, then resumes phase 2 (the head refresh path under contention)."""
    sink = HashChainSink(path_text)
    open(marker_flag, "w").close()  # noqa: SIM115 - constructed before the crash
    while not os.path.exists(go_flag):
        time.sleep(0.01)
    seen_torn = False
    for i in range(phase1):
        sink.append({"worker": os.getpid(), "seq": f"p1-{i}"})
    while not os.path.exists(resume_flag):
        time.sleep(0.02)
    for i in range(phase2):
        rec = sink.append({"worker": os.getpid(), "seq": f"p2-{i}"})
        status = sink.status()
        if status.get("torn_tail") is not None:
            seen_torn = True
            result_queue.put(("torn_tail", dict(status["torn_tail"]), rec["index"]))
    sink.close()
    result_queue.put(("done", os.getpid(), sink.event_count, seen_torn))


class TestMultiProcessAppendSafety:
    def test_two_processes_interleave_into_one_chain(self, tmp_path):
        """Small smoke: two processes of fresh sinks must not fork the chain."""
        path = str(tmp_path / "audit.jsonl")
        ctx = multiprocessing.get_context("fork")
        queue = ctx.Queue()
        procs = [ctx.Process(target=_append_worker, args=(path, 10, queue)) for _ in range(2)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(30)
        assert all(p.exitcode == 0 for p in procs)

        report = AuditVerifier().verify_chain(path)
        assert report.valid, report.errors
        assert report.event_count == 20
        events = _count_events(path)
        indices = [rec["index"] for rec in events]
        assert indices == list(range(20))

    def test_stress_four_processes_exactly_n_times_m_one_chain(self, tmp_path):
        """The MANDATORY stress test: N=4 processes, M=40 records each,
        fresh sink per process, one file.

        After the run: exactly N*M records, one chain, every index unique
        and strictly increasing, the sink's own verifier passes on the
        merged chain.
        """
        path = str(tmp_path / "audit.jsonl")
        n, m = 4, 40
        ctx = multiprocessing.get_context("fork")
        queue = ctx.Queue()
        procs = [ctx.Process(target=_append_worker, args=(path, m, queue)) for _ in range(n)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(120)
        assert all(p.exitcode == 0 for p in procs)

        per_worker = {}
        while not queue.empty():
            pid, count = queue.get()
            per_worker[pid] = count
        assert len(per_worker) == n
        assert all(count == m for count in per_worker.values())

        events = _count_events(path)
        assert len(events) == n * m
        indices = [rec["index"] for rec in events]
        # One chain: unique, strictly increasing, no gaps, no forks.
        assert indices == list(range(n * m))
        report = AuditVerifier().verify_chain(path)
        assert report.valid, report.errors
        assert report.event_count == n * m
        assert report.first_invalid_index is None

    def test_two_instances_in_one_process_share_one_chain(self, tmp_path):
        """Two sink instances on the same file interleave without forking."""
        path = str(tmp_path / "audit.jsonl")
        a = HashChainSink(path)
        a.append({"which": "a", "seq": 0})
        b = HashChainSink(path)
        b.append({"which": "b", "seq": 0})
        a.append({"which": "a", "seq": 1})
        b.close()
        a.close()

        report = AuditVerifier().verify_chain(path)
        assert report.valid, report.errors
        assert report.event_count == 3
        events = _count_events(path)
        assert [rec["index"] for rec in events] == [0, 1, 2]
        assert [rec["event"]["which"] for rec in events] == ["a", "b", "a"]


class TestCrashMidAppend:
    def test_sigkilled_appender_torn_tail_named_and_chain_continues(self, tmp_path):
        """SIGKILL one appender mid-write: the torn tail is named on the
        surviving writers' status channel (file, line, offset), the chain
        continues from the last COMPLETE record, and the torn line is
        never silently skipped: the next verify surfaces it by name."""
        path = str(tmp_path / "audit.jsonl")
        go_flag = str(tmp_path / "go")
        resume_flag = str(tmp_path / "resume")
        # Seed one record so the torn write lands on a real chain tail.
        seed = HashChainSink(path)
        seed.append({"seed": True})
        seed.close()
        open(go_flag, "w").close()  # noqa: SIM115

        ctx = multiprocessing.get_context("fork")
        queue = ctx.Queue()
        survivors = []
        markers = []
        for idx in range(2):
            marker = str(tmp_path / f"alive-{idx}")
            markers.append(marker)
            survivors.append(
                ctx.Process(
                    target=_survivor_worker,
                    args=(path, 2, 8, marker, go_flag, resume_flag, queue),
                )
            )
        # Both survivors hold constructed sinks BEFORE the torn write can
        # land: the pinned boot-time refusal of a torn tail still stands,
        # and the refresh path is what keeps these writers going.
        for p in survivors:
            p.start()
        torn = ctx.Process(target=_torn_writer_worker, args=(path, go_flag, queue))
        deadline = time.monotonic() + 30
        for marker in markers:
            while not os.path.exists(marker):
                assert time.monotonic() < deadline, "survivor never constructed"
                time.sleep(0.02)
        torn.start()
        torn.join(30)
        assert torn.exitcode == -signal.SIGKILL
        open(resume_flag, "w").close()  # noqa: SIM115
        for p in survivors:
            p.join(120)
            assert p.exitcode == 0

        torn_named = []
        done = []
        while not queue.empty():
            item = queue.get()
            if item[0] == "torn_tail":
                torn_named.append(item)
            elif item[0] == "done":
                done.append(item)

        # The torn tail was named, not silently skipped: both survivors
        # adopted the head from the last complete record and named the
        # torn line with its coordinates (file, line, offset).
        assert len(done) == 2
        assert all(item[3] for item in done), "no survivor named the torn tail"
        assert torn_named
        detail = torn_named[0][1]
        assert str(path) in detail.get("detail", "") or str(path) in detail.get("file", "")
        assert "offset" in detail or isinstance(detail.get("offset"), int)

        # The chain continued: each survivor finished its phase 2 budget
        # (2 phase-1 + 8 phase-2 events each) on top of the seeded record.
        assert all(item[2] == 10 for item in done)

        # Exactly one line is torn (the crashed write concatenated with
        # the next record): the crash window is honest in the file.
        # Metadata records (the chain_meta genesis, checkpoints) parse
        # fine and are not torn lines; the house parsing rule for chain
        # files selects event records and skips the metadata.
        torn_lines = 0
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    rec = json.loads(stripped)
                    if isinstance(rec, dict) and (
                        "event" in rec or rec.get("chain_meta") or rec.get("checkpoint")
                    ):
                        continue
                except ValueError:
                    pass
                torn_lines += 1
        assert torn_lines == 1

        # The next verify surfaces the torn line by name; it is never a
        # silent skip. The chain itself continued under the surviving
        # writers: every parseable event record still links forward.
        report = AuditVerifier().verify_chain(path)
        assert not report.valid
        assert any("invalid JSON" in err for err in report.errors)
        events = _count_events(path)
        indices = [rec["index"] for rec in events]
        assert len(indices) == len(set(indices)), "forked chain: duplicate indices"
        # 1 seed + 2 survivors * (2 + 8) with the first post-crash record
        # riding the torn line (lost as a parseable record).
        assert len(events) == 20


class TestSingleWriterFlag:
    def test_boot_time_lock_refuses_a_second_writer_by_name(self, tmp_path):
        """RAUCLE_AUDIT_SINGLE_WRITER=1 promises one writer: a boot-time
        exclusive lock; a second writer refuses by name instead of
        running without the promised property."""
        path = str(tmp_path / "audit.jsonl")
        first = HashChainSink(path, single_writer=True)
        first.append({"only": "one"})

        with pytest.raises(ConfigurationError) as excinfo:
            HashChainSink(path, single_writer=True)
        msg = str(excinfo.value)
        assert "RAUCLE_AUDIT_SINGLE_WRITER" in msg
        assert "single writer" in msg or "single-writer" in msg

        first.close()
        second = HashChainSink(path, single_writer=True)
        second.append({"released": True})
        second.close()

    def test_env_flag_wires_single_writer_through_sink_from_env(self, tmp_path, monkeypatch):
        from raucle.audit import ENV_AUDIT_SINGLE_WRITER, sink_from_env

        path = str(tmp_path / "audit.jsonl")
        monkeypatch.setenv("RAUCLE_AUDIT_PATH", path)
        monkeypatch.setenv(ENV_AUDIT_SINGLE_WRITER, "1")
        sink = sink_from_env()
        assert sink is not None
        assert sink.status()["single_writer"] is True
        # A second writer refuses under the promised property.
        with pytest.raises(ConfigurationError):
            HashChainSink(path, single_writer=True)
        sink.close()
