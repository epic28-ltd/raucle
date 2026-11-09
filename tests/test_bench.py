"""X5: async receipt sink (bounded queue, NAMED overflow) + bench smoke.

The overflow contract is the load-bearing assertion: when the bounded
queue is full, the receipt is lost — and that loss must be a NAMED
failure event that is inspectable, countable and raised to the caller,
never a silent drop.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from raucle.async_receipt_sink import AsyncReceiptSink, ReceiptSinkOverflow

_REPO = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# AsyncReceiptSink — bounded queue + named overflow
# ---------------------------------------------------------------------------


def test_submit_drains_through_writer():
    written: list[dict] = []

    def writer(envelope: dict) -> None:
        written.append(envelope)

    sink = AsyncReceiptSink(writer, max_queue=32, name="t")
    for i in range(10):
        sink.submit({"receipt_hash": f"h{i}", "jws": f"j{i}"})
    stats = sink.close(drain_timeout=10.0)
    assert len(written) == 10
    assert stats["submitted"] == 10
    assert stats["written"] == 10
    assert stats["lost"] == 0
    assert sink.overflow_events == []


def test_queue_full_is_a_named_failure_event():
    """Overflow: ReceiptSinkOverflow raised AND a receipt_sink_overflow
    event recorded — the receipt loss is never silent."""
    resumed = threading.Event()
    consumed_first = threading.Event()
    lock = threading.Lock()
    state = {"first": True}

    def writer(envelope: dict) -> None:
        with lock:
            blocking = state["first"]
            state["first"] = False
        if blocking:
            consumed_first.set()
            resumed.wait(timeout=30.0)

    sink = AsyncReceiptSink(writer, max_queue=2, name="over")
    sink.submit({"receipt_hash": "h0"})  # consumed; writer blocks on it
    assert consumed_first.wait(timeout=10.0)
    sink.submit({"receipt_hash": "h1"})  # queue: 1
    sink.submit({"receipt_hash": "h2"})  # queue: 2 (full)
    with pytest.raises(ReceiptSinkOverflow):
        sink.submit({"receipt_hash": "h3"})
    events = sink.overflow_events
    assert len(events) == 1
    ev = events[0]
    assert ev["event"] == "receipt_sink_overflow"  # the NAMED failure event
    assert ev["sink"] == "over"
    assert ev["receipt_hash"] == "h3"
    resumed.set()
    stats = sink.close(drain_timeout=10.0)
    assert stats["written"] == 3
    assert stats["submitted"] == 3


def test_unbounded_queue_is_rejected():
    def writer(envelope: dict) -> None:  # pragma: no cover
        pass

    with pytest.raises(ValueError, match="bounded"):
        AsyncReceiptSink(writer, max_queue=0)


def test_writer_error_never_kills_the_sink():
    """A writer exception is counted and logged; the sink keeps working."""
    ok_written: list[dict] = []

    def writer(envelope: dict) -> None:
        if envelope["receipt_hash"] == "bad":
            raise OSError("disk full")
        ok_written.append(envelope)

    sink = AsyncReceiptSink(writer, max_queue=32, name="err")
    sink.submit({"receipt_hash": "bad"})
    sink.submit({"receipt_hash": "good"})
    stats = sink.close(drain_timeout=10.0)
    assert [e["receipt_hash"] for e in ok_written] == ["good"]
    assert stats["write_errors"] == 1
    assert stats["written"] == 2


# ---------------------------------------------------------------------------
# bench harness smoke: the script runs against a tiny count and reports
# every measured path
# ---------------------------------------------------------------------------

_EXPECTED_PATHS = {
    "gate_allow",
    "gate_deny",
    "receipt_emit",
    "receipt_append",
    "index_append",
    "siem_forward",
    "sink_submit",
}


def test_bench_harness_smoke(tmp_path: Path) -> None:
    out = tmp_path / "smoke.json"
    cmd = [
        sys.executable,
        str(_REPO / "bench" / "run_bench.py"),
        "--iter",
        "20",
        "--json",
        str(out),
    ]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_REPO)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)  # noqa: S603
    assert proc.returncode == 0, proc.stderr[-4000:]
    payload = json.loads(out.read_text())
    assert payload["bench"] == "x5-hot-path"
    assert set(payload["results"]) == _EXPECTED_PATHS
    for path, stats in payload["results"].items():
        for key in ("p50_us", "p99_us", "mean_us", "ceiling_ops_s"):
            assert key in stats, (path, key)
        assert stats["p99_us"] >= stats["p50_us"] >= 0
    # async sink ran clean in the smoke run
    assert payload["results"]["sink_submit"]["overflow_events"] == 0


def test_bench_results_recorded_from_this_machine():
    """The published NFR doc numbers must come from the recorded results
    file in-repo — a coherence check, not a perf assertion."""
    results = _REPO / "bench" / "results" / "x5-2026-11-09.json"
    assert results.exists(), "bench results file missing from the branch"
    payload = json.loads(results.read_text())
    assert set(payload["results"]) == _EXPECTED_PATHS
    for stats in payload["results"].values():
        assert 0 < stats["p50_us"] <= stats["p99_us"]
