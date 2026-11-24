#!/usr/bin/env python
"""X5 performance bench for the raucle hot path.

Measures five paths end-to-end against the real production modules —
no mocks on the measured leg:

* ``gate_allow``       — CapabilityGate.check on a schema-valid call
* ``gate_deny``        — CapabilityGate.check on the type-confused call
* ``receipt_emit``     — VerdictSigner.issue (Ed25519 JWS receipt)
* ``receipt_append``   — SegmentedReceiptStore.append_line (sync write)
* ``index_append``     — ReceiptIndex.index_receipt (SQLite projection)
* ``siem_forward``     — SIEMSink.append (ECS JSONL line, flushed)
* ``sink_submit``      — submit into AsyncReceiptSink (async receipt path)

Reports p50/p99 latency and ceiling throughput (1/mean) per path. Method
and recorded runs: docs/nfr/x5-performance-bench.md. All numbers come from
the machine actually running this script — never copied from another run.

Usage: python bench/run_bench.py [--iter N] [--json PATH]
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import sqlite3
import statistics
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from raucle.async_receipt_sink import AsyncReceiptSink
from raucle.capability import CapabilityGate, CapabilityIssuer
from raucle.receipt_index import ReceiptIndex
from raucle.receipt_store import SegmentedReceiptStore
from raucle.siem import SIEMSink
from raucle.tool_schema import ToolSchemaRegistry
from raucle.verdicts import VerdictSigner

REPO = Path(__file__).resolve().parent.parent
_TMP = Path(uuid.uuid4().hex[:8])


# ---------------------------------------------------------------------------
# k1-boot-streaming bench (docs/spec/boot-streaming-v0.1.md section 5)
# ---------------------------------------------------------------------------

#: Fixture scales. Every number this bench records is from the machine
#: that ran it (the X5 rule); the scale is recorded inside the result
#: so a recorded run can never be mistaken for another scale.
_K1_SCALES: dict[str, dict[str, int]] = {
    # The CI variant of AC1's flatness property: seconds-scale.
    "ci": {"audit_target_mb": 8, "receipts": 5_000},
    # The incident box's class at a runnable size: roughly 1/24th of
    # the 18 Nov audit log, enough to separate a bounded boot's peak
    # RSS from a whole-store boot's.
    "demo": {"audit_target_mb": 512, "receipts": 150_000},
    # The 18 Nov incident class itself (12.2 GB audit log, a 15 GB
    # index equivalent). A multi-hour run; the flag ships so the X5
    # session that can afford the wall-clock runs it on the target box.
    "incident": {"audit_target_mb": 12_288, "receipts": 40_000_000},
}

#: The W matrix (MiB) and the batch matrix (rows) the spec section 5 names.
_K1_WINDOW_MIB = (16, 64, 256)
_K1_BATCH_ROWS = (1_000, 10_000, 50_000)

#: Deterministic fixture constants: a fixed epoch and spread, so every
#: run at a scale sees byte-identical store content.
_K1_EPOCH = dt.datetime(2026, 11, 18, 12, 0, 0, tzinfo=dt.timezone.utc)
_K1_IAT_SPREAD_SECONDS = 4 * 3600


#: Sane fallback where os.sysconf cannot answer (platforms without the
#: syscall surface): the 4 KiB page size the x86/ARM default expects.
_FALLBACK_PAGE_SIZE = 4096


def _statm_rss_mb() -> float:
    """Resident size in MB from /proc (0.0 where unavailable).

    Page size comes from the syscall (os.sysconf), not a hard-coded 4096:
    /proc/self/statm reports resident pages, so the multiplier must be
    whatever SC_PAGESIZE the RUNNING kernel actually uses.
    """
    try:
        page_size = os.sysconf("SC_PAGESIZE")
    except (AttributeError, OSError, ValueError):
        page_size = _FALLBACK_PAGE_SIZE
    try:
        with open("/proc/self/statm", encoding="ascii") as fh:
            return int(fh.read().split()[1]) * page_size / (1024 * 1024)
    except (OSError, ValueError, IndexError):
        return 0.0


class _PeakRss:
    """Sample resident size on a daemon thread; hold peak while a leg runs.

    Sampling (not a high-water mark) so each leg reports its OWN peak:
    ru_maxrss is process-lifetime and cannot be reset between legs. The
    10 ms interval catches steady-state cost (scan buffers, SQLite page
    cache, sweep batches); sub-10 ms allocation spikes are invisible to
    it by construction, which the NFR note says out loud.
    """

    def __init__(self, interval_s: float = 0.01) -> None:
        self._interval = interval_s
        self._peak = 0.0
        self._stop = threading.Event()

    def __enter__(self) -> _PeakRss:
        self._peak = _statm_rss_mb()
        self._stop.clear()

        def _sample() -> None:
            while not self._stop.wait(self._interval):
                rss = _statm_rss_mb()
                if rss > self._peak:
                    self._peak = rss

        threading.Thread(target=_sample, daemon=True, name="k1-peak-rss").start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        rss = _statm_rss_mb()
        if rss > self._peak:
            self._peak = rss

    @property
    def peak_mb(self) -> float:
        return round(self._peak, 1)


def _k1_seed_audit_chain(path: Path, target_bytes: int) -> dict[str, int]:
    """Write a deterministic synthetic unsigned audit chain at target size.

    The record shape is the sink's own, produced with the sink's own
    canonicalisation primitives, so the chain scan recomputes each link
    exactly as it would over a production chain; timestamps run from a
    fixed epoch so the fixture is byte-stable across runs.
    """
    from raucle.audit import HashChainSink, _canonical_json, _sha256_hex

    header = {
        "chain_meta": True,
        "version": HashChainSink._CHAIN_META_VERSION,  # noqa: SLF001 - bench mirrors the sink's own header
        "signed": False,
        "created_at": _K1_EPOCH.isoformat(),
    }
    prev_hash = HashChainSink._GENESIS_HASH  # noqa: SLF001 - the fixture chains from genesis, as the sink does
    events = 0
    written = 0
    with open(path, "w", encoding="utf-8") as fh:
        line = json.dumps(header, ensure_ascii=False) + "\n"
        fh.write(line)
        written += len(line.encode("utf-8"))
        while written < target_bytes:
            record = {
                "index": events,
                "timestamp": (_K1_EPOCH + dt.timedelta(seconds=events)).isoformat(),
                "prev_hash": prev_hash,
                "event": {
                    "kind": "gate_decision",
                    "seq": events,
                    "tool": "web.fetch",
                    "agent_id": "agent:bench",
                    "decision": "allow",
                    "note": "k1 synthetic fixture record padded to incident-class line size",
                },
            }
            record_hash = _sha256_hex(_canonical_json(record))
            record["hash"] = record_hash
            line = json.dumps(record, ensure_ascii=False) + "\n"
            fh.write(line)
            written += len(line.encode("utf-8"))
            prev_hash = record_hash
            events += 1
    return {"events": events, "bytes": written}


def _k1_envelope(iat: int, receipt_no: int) -> str:
    """A minimal synthetic receipt envelope the index can project.

    Payload-only JWS, as the test fixtures use: the projection decodes
    and never verifies (a disposable projection never judges chain
    content). One in a hundred receipts carries a session id, so the
    tail window and the sweep project continuity-shaped rows.
    """
    x_gate: dict[str, object] = {
        "agent_id": "agent:bench",
        "tool": "web.fetch",
        "decision": "allow",
        "reason": "",
    }
    if receipt_no % 100 == 0:
        x_gate["session_id"] = f"k1-sess-{receipt_no % 32}"
    payload = {"iat": int(iat), "agent_id": "agent:bench", "x_gate": x_gate}

    def b64(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    jws = f"{b64({'alg': 'none'})}.{b64(payload)}.AA"
    return json.dumps({"receipt_hash": f"sha256:{receipt_no:064x}", "jws": jws})


def _k1_seed_receipt_store(store_dir: Path, receipts: int) -> dict[str, int]:
    """Write the synthetic receipt store as segment files, oldest first.

    Direct buffered writes (not the store's per-record append_line,
    which fsyncs per record): the fixture only needs the on-disk shape
    the real store reads back through segments(). Segments are ~4 MiB,
    the shipped order's class.
    """
    store_dir.mkdir(parents=True, exist_ok=True)
    seg_bytes = 4 * 1024 * 1024
    seg_index = 0
    current_size = 0
    count = 0
    fh = None
    try:
        for i in range(receipts):
            iat = int(_K1_EPOCH.timestamp()) + _K1_IAT_SPREAD_SECONDS - i % _K1_IAT_SPREAD_SECONDS
            line = _k1_envelope(iat, i) + "\n"
            if fh is None or current_size >= seg_bytes:
                if fh is not None:
                    fh.close()
                path = store_dir / f"seg-{seg_index:06d}.jsonl"
                fh = open(path, "w", encoding="utf-8")  # noqa: SIM115 - fixture writer, closed in the finally below
                seg_index += 1
                current_size = 0
            fh.write(line)
            current_size += len(line.encode("utf-8"))
            count += 1
    finally:
        if fh is not None:
            fh.close()
    total = sum(p.stat().st_size for p in sorted(store_dir.glob("seg-*.jsonl")))
    return {"receipts": count, "bytes": total, "segments": seg_index}


def _k1_legacy_index(path: Path, rows: int) -> None:
    """Build a schema-v2 index (pre-Q1 columns) for the migration leg.

    The v2 shape is v3 minus session_id and acting_for; the migration
    copies the shared columns whole (the J2 invariants), so this is the
    honest worst case the compactor's phase 1 takes over.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
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
                source       TEXT NOT NULL DEFAULT '',
                destination  TEXT NOT NULL DEFAULT '',
                parents_json TEXT NOT NULL DEFAULT '[]',
                segment      TEXT,
                line_no      INTEGER
            )
            """
        )
        conn.executemany(
            "INSERT INTO receipts (receipt_hash, iat, agent_id, tool, decision,"
            " reason, latency_us, source, destination) VALUES (?, ?, ?, ?, ?, '', 1000, 'a', 'b')",
            [
                (
                    f"sha256:{i:064x}",
                    int(_K1_EPOCH.timestamp()) + i,
                    "agent:bench",
                    "web.fetch",
                    "allow",
                )
                for i in range(rows)
            ],
        )
        conn.execute("PRAGMA user_version = 2")
        conn.commit()
    finally:
        conn.close()


def _k1_run_leg(fn, *args, **kwargs) -> dict[str, float]:
    """Run one bench leg under the peak-RSS sampler."""
    with _PeakRss() as peak:
        t0 = time.perf_counter()
        fn(*args, **kwargs)
        elapsed = time.perf_counter() - t0
    return {"elapsed_s": round(elapsed, 3), "peak_rss_mb": peak.peak_mb}


def k1_main(args: argparse.Namespace) -> None:
    """The k1-boot-streaming experiment: four legs, the W and batch
    matrices, and the three boot times, over a deterministic synthetic
    fixture at the chosen scale."""
    from raucle.audit import HashChainSink
    from raucle.boot_stream import BootCompactor, BootReadiness, BootWatchdog

    scale = _K1_SCALES[args.k1_scale]
    base = REPO / "bench" / ".tmp" / ("k1-" + uuid.uuid4().hex[:8])
    base.mkdir(parents=True, exist_ok=True)
    audit_path = base / "gateway-audit.jsonl"
    store_dir = base / "receipts"

    print(f"k1: generating fixture at scale {args.k1_scale} ...", flush=True)
    gen = _k1_seed_audit_chain(audit_path, scale["audit_target_mb"] * 1024 * 1024)
    store = _k1_seed_receipt_store(store_dir, scale["receipts"])
    print(
        f"k1: audit chain {gen['bytes'] / (1 << 20):.0f} MiB / {gen['events']} events; "
        f"store {store['bytes'] / (1 << 20):.1f} MiB / {store['receipts']} receipts",
        flush=True,
    )

    results: dict[str, Any] = {}

    # Boot time 1: the deferred index open is the pre-bind cost the
    # bind-first sequence pays before /health answers.
    def _open_deferred() -> ReceiptIndex:
        return ReceiptIndex(sqlite_path=base / "bind.sqlite", defer_migration=True, cache_mb=64)

    results["time_to_bind"] = _k1_run_leg(_open_deferred)
    index = _open_deferred()
    index.close()

    # Leg 1: bounded reverse tail resume across the W matrix.
    for w_mib in _K1_WINDOW_MIB:
        leg = _k1_run_leg(
            lambda w=w_mib: HashChainSink(audit_path, scan_window_bytes=w * 1024 * 1024).close()
        )
        results.setdefault("tail_resume", {})[f"w{w_mib}"] = leg

    # Leg 2: the background chain scan (verify-as-you-go) across W; the
    # scan is line-streamed, so W bounds nothing here and the matrix
    # records exactly that flatness.
    for w_mib in _K1_WINDOW_MIB:
        scan_index = ReceiptIndex(
            sqlite_path=base / f"scan-{w_mib}.sqlite", defer_migration=True, cache_mb=64
        )
        compactor = BootCompactor(
            scan_index,
            store=None,
            readiness=BootReadiness(),
            watchdog=BootWatchdog(),
            scan_window_bytes=w_mib * 1024 * 1024,
            audit_chain=audit_path,
        )
        # The leg measures the scan in isolation (the compactor's own
        # phase runner); the boot sequence measures it end-to-end below.
        results.setdefault("chain_scan", {})[f"w{w_mib}"] = _k1_run_leg(compactor._scan_chain)  # noqa: SLF001
        scan_index.close()

    # Leg 3: the deferred schema migration (compactor phase 1).
    legacy_path = base / "legacy-v2.sqlite"
    _k1_legacy_index(legacy_path, scale["receipts"])

    def _migrate() -> None:
        legacy = ReceiptIndex(sqlite_path=legacy_path, defer_migration=True, cache_mb=64)
        legacy.run_pending_migration()
        legacy.close()

    results["index_migration"] = _k1_run_leg(_migrate)

    # Boot times 2 and 3 plus leg 4: the tail window (session
    # continuity) then the batched sweep (index ready), across the
    # batch matrix on a cold index per size.
    for batch_rows in _K1_BATCH_ROWS:
        cold = ReceiptIndex(
            sqlite_path=base / f"sweep-{batch_rows}.sqlite", defer_migration=True, cache_mb=64
        )
        compactor = BootCompactor(
            cold,
            store=SegmentedReceiptStore(base_dir=store_dir),
            readiness=BootReadiness(),
            watchdog=BootWatchdog(),
            ttl_seconds=3600,
            batch_rows=batch_rows,
            scan_window_bytes=64 * 1024 * 1024,
        )
        results.setdefault("index_rebuild_batched", {})[f"b{batch_rows}"] = {
            "tail_window": _k1_run_leg(compactor._tail_window_phase),  # noqa: SLF001
            "sweep": _k1_run_leg(compactor._sweep_phase),  # noqa: SLF001
        }
        cold.close()

    # End-to-end boot: the same phases the gateway runs at boot, one
    # cold compactor over the whole fixture.
    boot_index = ReceiptIndex(sqlite_path=base / "boot.sqlite", defer_migration=True, cache_mb=64)
    boot_compactor = BootCompactor(
        boot_index,
        store=SegmentedReceiptStore(base_dir=store_dir),
        readiness=BootReadiness(),
        watchdog=BootWatchdog(),
        ttl_seconds=3600,
        batch_rows=10_000,
        scan_window_bytes=64 * 1024 * 1024,
        audit_chain=audit_path,
    )
    results["boot_end_to_end"] = _k1_run_leg(boot_compactor.run_phases)
    indexed = boot_index.count()
    boot_index.close()

    env = {
        "python_path": sys.executable,
        "scale": args.k1_scale,
        "fixture": {
            "audit_chain_bytes": gen["bytes"],
            "audit_events": gen["events"],
            "receipts": store["receipts"],
            "store_bytes": store["bytes"],
            "store_segments": store["segments"],
        },
        "indexed_rows_end_to_end": indexed,
        "rss_mb_at_start": round(_statm_rss_mb(), 1),
    }
    payload = {"bench": "k1-boot-streaming", "env": env, "results": results}
    print(json.dumps(payload, indent=2))
    out = REPO / args.json
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))
    print(f"saved: {out}")


def percentile(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    k = (len(s) - 1) * p
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def timed(call, *args, iters: int) -> dict[str, float]:
    """Run call(*args) iters times; return latency stats in microseconds."""
    xs: list[float] = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        call(*args)
        xs.append((time.perf_counter_ns() - t0) / 1000.0)
    mean = statistics.fmean(xs)
    return {
        "p50_us": round(percentile(xs, 0.50), 1),
        "p99_us": round(percentile(xs, 0.99), 1),
        "mean_us": round(mean, 1),
        "ceiling_ops_s": round(1e6 / mean, 0),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iter", type=int, default=2_000, help="iterations per path")
    ap.add_argument("--json", type=str, default="bench/results/latest.json")
    ap.add_argument(
        "--k1",
        action="store_true",
        help="run the k1 boot-streaming bench (spec boot-streaming-v0.1) instead of the hot path",
    )
    ap.add_argument(
        "--k1-scale",
        choices=sorted(_K1_SCALES),
        default="ci",
        help="fixture scale for the k1 bench (ci, demo or incident)",
    )
    args = ap.parse_args()
    if args.k1:
        k1_main(args)
        return
    n = args.iter

    base = REPO / "bench" / ".tmp" / _TMP
    base.mkdir(parents=True, exist_ok=True)

    # --- environment: real gate, schema registry, signer, sinks ----------
    iss = CapabilityIssuer.generate(issuer="bench.example")
    reg = ToolSchemaRegistry()
    schema = {
        "type": "object",
        "properties": {"amount": {"type": "number"}},
        "required": ["amount"],
    }
    reg.register("send_money", schema)
    reg.bind_policy("send_money", {"required_present": ["amount"]})
    gate = CapabilityGate(trusted_issuers={iss.key_id: iss.public_key_pem}, tool_schemas=reg)
    cap = iss.mint(
        agent_id="agent:bench", tool="send_money", constraints={"required_present": ["amount"]}
    )

    signer = VerdictSigner.generate()
    store = SegmentedReceiptStore(base / "store")

    def append_receipt(envelope: dict) -> None:
        record = {
            "receipt_hash": hashlib.sha256(envelope["jws"].encode()).hexdigest(),
            "jws": envelope["jws"],
        }
        store.append_line(json.dumps(record))

    index = ReceiptIndex(base / "index.sqlite")
    siem = SIEMSink(base / "siem.jsonl")
    sink = AsyncReceiptSink(append_receipt, max_queue=4096, name="bench-sink")

    def emit_and_record() -> str:
        jws = signer.issue(
            input_text=f"bench-call-{uuid.uuid4().hex}",
            verdict="allow",
            confidence=1.0,
            ruleset_hash="bench",
        )
        append_receipt({"jws": jws})
        return jws

    # one real receipt to seed the index bench with a valid envelope
    seed_jws = emit_and_record()

    def allow_call() -> None:
        gate.check(cap, tool="send_money", agent_id="agent:bench", args={"amount": 42})

    def deny_call() -> None:
        gate.check(cap, tool="send_money", agent_id="agent:bench", args={"amount": "99999"})

    def emit_receipt() -> None:
        signer.issue(
            input_text=f"bench-{uuid.uuid4().hex}",
            verdict="allow",
            confidence=1.0,
            ruleset_hash="bench",
        )

    def append_prebuilt(envelope: dict | None = None) -> None:
        append_receipt({"jws": seed_jws})

    def index_record(record: dict) -> None:
        index.index_receipt(record)

    def make_record() -> dict:
        jws = signer.issue(
            input_text=f"bench-{uuid.uuid4().hex}",
            verdict="allow",
            confidence=1.0,
            ruleset_hash="bench",
        )
        return {"receipt_hash": hashlib.sha256(jws.encode()).hexdigest(), "jws": jws}

    def siem_forward() -> None:
        siem.append({"event": "gate_decision", "decision": "allow", "tool": "send_money"})

    def sink_submit(record: dict) -> None:
        sink.submit(record)

    results: dict[str, dict] = {}
    results["gate_allow"] = timed(allow_call, iters=n)
    results["gate_deny"] = timed(deny_call, iters=n)
    results["receipt_emit"] = timed(emit_receipt, iters=n)
    results["receipt_append"] = timed(append_prebuilt, iters=n)
    results["index_append"] = timed(index_record, make_record(), iters=n)
    results["siem_forward"] = timed(siem_forward, iters=n)
    # async sink: submit-side latency is the caller-visible cost
    rec = make_record()
    results["sink_submit"] = timed(sink_submit, rec, iters=n)

    # async-sink ceiling: feed N records, drain, measure wall-clock rate
    t0 = time.perf_counter()
    for _ in range(n):
        sink.submit(make_record())
    submit_wall = time.perf_counter() - t0
    done = sink.close(drain_timeout=30.0)
    drain_wall = time.perf_counter() - t0 - submit_wall
    if done["written"] < n:
        print(f"WARNING: drain incomplete: {done}", flush=True)
    results["sink_submit"]["async_submit_rate_ops_s"] = round(n / submit_wall, 0)
    results["sink_submit"]["async_drain_write_rate_ops_s"] = round(n / max(drain_wall, 1e-9), 0)
    results["sink_submit"]["overflow_events"] = len(sink.overflow_events)

    siem.close()
    index.close()

    env = {
        "python_path": sys.executable,
        "iterations_per_path": n,
    }
    print(json.dumps({"bench": "x5-hot-path", "env": env, "results": results}, indent=2))

    out = REPO / args.json
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"bench": "x5-hot-path", "env": env, "results": results}, indent=2))
    print(f"saved: {out}")


if __name__ == "__main__":
    main()
