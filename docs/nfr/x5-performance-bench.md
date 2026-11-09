# NFR-S-M: X5 hot-path performance bench

**Status:** recorded 2026-11-09 on the development machine described below.
Numbers are from THIS machine and THIS run — never copied between runs or
machines. Re-run to reproduce; do not compare across hardware.

## What is measured

`bench/run_bench.py` exercises five production paths end-to-end against the
real modules (no mocks on the measured leg):

| Path | Module under measurement |
|---|---|
| `gate_allow` / `gate_deny` | `raucle.capability.CapabilityGate.check` — schema-bound gate, allow vs type-confused deny |
| `receipt_emit` | `raucle.verdicts.VerdictSigner.issue` — Ed25519 JWS receipt |
| `receipt_append` | `raucle.receipt_store.SegmentedReceiptStore.append_line` — chain-of-record JSONL write |
| `index_append` | `raucle.receipt_index.ReceiptIndex.index_receipt` — SQLite projection |
| `siem_forward` | `raucle.siem.SIEMSink.append` — ECS JSONL line, flushed per event |
| `sink_submit` | `raucle.async_receipt_sink.AsyncReceiptSink.submit` — bounded-queue async receipt path |

## Methodology (reproducible)

1. `PYTHONPATH=<repo>` `python bench/run_bench.py --iter N --json bench/results/<date>.json`
2. Per path: N single-shot calls timed with `time.perf_counter_ns` (wall
   clock, no warm-up loop beyond the framework's natural JIT-free state —
   CPython, so the first iterations are included in the distribution).
3. Reported stats: **p50**, **p99** (interpolated percentile over the sorted
   latency distribution), mean, ceiling throughput = 1/mean (an upper bound
   for a single-threaded loop; not a sustained-load figure).
4. The async sink is additionally measured as: submit-side wall-clock rate
   for N `submit` calls (`async_submit_rate_ops_s`) and the background
   writer's drain rate for the same N receipts (`async_drain_write_rate_ops_s`),
   with `overflow_events` asserted 0 (the run must NOT overflow — overflow is
   a named failure contract covered by tests, not a bench condition).
5. Environment is fresh temp dirs per run; the SIEM file handle, SQLite WAL
   connection and receipt store are real files on the OS page cache.

## Machine (the run that produced the recorded numbers)

- Intel Core i5-8250U (8 threads, 1.60 GHz base / 3.4 GHz max), 23 GiB RAM,
  Linux 7.2.8-9-omarchy, CPython 3.14.9 (repo venv), single-writer bench
  process, no load-shaping.

## Recorded results (2026-11-09, --iter 1500)

Source of record: `bench/results/x5-2026-11-09.json` (committed; re-check
against it rather than trusting this table).

| Path | p50 (µs) | p99 (µs) | ceiling ops/s |
|---|---|---|---|
| gate_allow | 237.7 | 472.8 | 3,792 |
| gate_deny | 233.1 | 521.6 | 3,836 |
| receipt_emit | 81.5 | 169.9 | 10,959 |
| receipt_append | 10.1 | 19.7 | 94,172 |
| index_append | 35.4 | 68.8 | 25,780 |
| siem_forward | 12.6 | 28.7 | 73,957 |
| sink_submit | 1.0 | 2.7 | 939,712 |

Async sink, same run: submit-side rate 8,065 ops/s for the submitting loop
(the loop also *signs* each receipt in-thread; the submit primitive itself
peaks at ~939k ops/s with pre-built envelopes), background drain/write rate
8,747,019 ops/s (write-ahead: the queue absorbs faster than the writer
consumes — exactly the situation the bounded queue and NAMED overflow exist
to govern), 0 overflow events.

## Reading the numbers honestly

- The gate ceiling (~3.8k ops/s) is dominated by per-call JWS verification —
  receipt emit (~11k ops/s) and chain append are individually much cheaper;
  the gate is the hot path's ceiling, not the sinks.
- Ceiling throughput is single-threaded best case. Sustained multi-client
  throughput, fsync behaviour on non-page-cached storage, and GC pauses are
  NOT measured here — do not quote `ceiling_ops_s` as a capacity number.
- The async sink's caller-visible cost (p50 1.0 µs, ~939k ops/s ceiling) is
  the whole point: decoupling moves the receipt-emit + append cost off the
  gate's thread at the price of a bounded queue whose overflow is a named
  `receipt_sink_overflow` failure event (see `tests/test_bench.py`).
