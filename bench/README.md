# bench/ — X5 hot-path performance harness

`run_bench.py` measures the raucle hot path against the real production
modules: capability-gate allow/deny, signed-receipt emit, receipt-store
append, SQLite index append, SIEM forward, and the bounded-queue
`AsyncReceiptSink` submit path (`raucle/async_receipt_sink.py`).

Run:

```
PYTHONPATH=. python bench/run_bench.py --iter 1500 --json bench/results/<date>.json
```

Methodology, machine description and the recorded p50/p99 + ceiling
throughput live in `docs/nfr/x5-performance-bench.md`. Results JSONs are
committed per run date — record your machine honestly, never transplant
numbers between machines.

The async receipt sink's overflow contract (queue full ⇒ `ReceiptSinkOverflow`
plus a Named `receipt_sink_overflow` event — never a silent drop) is tested
in `tests/test_bench.py`. `bench/.tmp/` is scratch (per-run), gitignored.
