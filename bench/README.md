# bench/ — X5 hot-path performance harness

`run_bench.py` measures the raucle hot path against the real production
modules: capability-gate allow/deny, signed-receipt emit, receipt-store
append, SQLite index append, SIEM forward, and the bounded-queue
`AsyncReceiptSink` submit path (`raucle/async_receipt_sink.py`).

Run:

```
PYTHONPATH=. python bench/run_bench.py --iter 1500 --json bench/results/<date>.json
```

## k1 boot-streaming bench

The boot-streaming experiment (spec section 5) runs the same script with
`--k1` and a fixture scale: `ci` (seconds-scale, the CI variant of the
flatness property), `demo` (a runnable incident-class slice) or `incident`
(the 18 Nov class itself, a multi-hour run on the target box):

```
python bench/run_bench.py --k1 --k1-scale demo --json bench/results/k1-<date>.json
```

Legs: `tail_resume` (the bounded reverse tail read) and `chain_scan` across
the W window matrix, `index_migration` (the deferred schema copy), and
`index_rebuild_batched` (tail window plus sweep) across the batch matrix,
plus `time_to_bind` and the end-to-end boot. Each leg reports elapsed time
and sampled peak RSS. Methodology, machine description and the recorded
numbers live in `docs/nfr/boot-streaming-v1.md`; the fixture is deterministic
and synthetic (no demo data), and the scale is recorded inside the result.

Methodology, machine description and the recorded p50/p99 + ceiling
throughput live in `docs/nfr/x5-performance-bench.md`. Results JSONs are
committed per run date — record your machine honestly, never transplant
numbers between machines.

The async receipt sink's overflow contract (queue full ⇒ `ReceiptSinkOverflow`
plus a Named `receipt_sink_overflow` event — never a silent drop) is tested
in `tests/test_bench.py`. `bench/.tmp/` is scratch (per-run), gitignored.
