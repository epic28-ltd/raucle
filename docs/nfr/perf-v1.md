# NFR performance snapshot — perf-v1

Measured by `tools/benchmarks/nfr.py` on the codebase it ships with.
Every figure below is a real measurement (N=1000 iterations per target,
100 warmup, wall-clock via `time.perf_counter`). Nothing here is
extrapolated, quoted from another machine, or hand-rounded beyond the
precision printed.

## Environment (the machine that produced these numbers)

Generated at: 2026-11-06T17:55:18+0000
- Host OS: Linux 7.2.8-9-omarchy (x86_64)
- CPU: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
- Python: 3.12.14
- Wall-clock timing only (time.perf_counter); no benchmark-specific tuning.
- Receipt store and registry live in a per-run temp directory (hot page
  cache): `/home/craigamcw/.hermes/profiles/z/cache/scratch/raucle-nfr-ttemy03f`. Sustained production throughput with cold storage
  will be materially slower — treat these as relative-ordering data,
  not an SLO.
- The receipt-write and gate targets are also exercised concurrently by
  `tests/test_nfr_chaos.py`; this snapshot reports the single-thread path.

## Results

| Target | N | mean (µs) | p50 (µs) | p95 (µs) | max (µs) |
| --- | --- | --- | --- | --- | --- |
| gate_decision (CapabilityGate.check) | 1000 | 591.9 | 545.8 | 685.2 | 5686.7 |
| receipt_write (SegmentedReceiptStore.append_line) | 1000 | 4120.3 | 3064.9 | 7798.5 | 141775.5 |
| verify_passport (registry-backed) | 1000 | 407.9 | 382.5 | 504.6 | 5908.7 |

## Honesty notes

- Same-process, same-event-loop-free measurement: each target is timed
  in isolation, so per-target numbers are not additive into an end-to-end
  request budget.
- p95 on a shared host can include scheduler noise spikes; the max column
  is the honest worst case seen in this run.
- No claimed latency figure elsewhere in the docs may cite this table
  unless it was produced by this harness version on the same commit.

Commit at time of measurement: `7f4b3d3a0ce2`.
