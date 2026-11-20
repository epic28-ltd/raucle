# Boot streaming NFR note - bounded boot memory and per-surface readiness (L1)

**Scope and honesty rules.** This note covers the gateway boot's memory
and readiness behaviour (docs/spec/boot-streaming-v0.1.md, ADR 0007,
raucle/boot_stream.py, the bounded resume in raucle/audit.py, the
deferred index open in raucle/receipt_index.py). The invariant claims
are pinned by tests the lane ran live (`tests/test_boot_stream.py`, 29
tests, plus the re-derived preflight suite in
`tests/test_chain_rotation.py`); the performance numbers are from THIS
machine only (the X5 rule: never transplant numbers between machines),
recorded in `bench/results/k1-2026-11-20.json` at the demo scale, with
the ci scale as the CI variant. The incident-scale leg (the 18 Nov
class itself) ships behind `--k1-scale incident` and had NOT been run
when this note was written; every incident-scale statement below is
labelled as extrapolation, not measurement.

## The invariant

INVARIANT (spec 3.1): the gateway boot's resident memory is bounded by
configuration and independent of store size. A store may grow without
bound; a boot may not grow with it.

Expressed as the budget the preflight projects before loading:

    projected_boot_rss = baseline_gateway (256 MB)
                      + W_replay          (RAUCLE_BOOT_SCAN_WINDOW_MB, 64)
                      + C_index           (RAUCLE_INDEX_CACHE_MB, 64)

The projection no longer contains the stores' bytes (the J1 2.0x
multiplier is retired to a historical constant). The knob
(`RAUCLE_BOOT_MEM_CEILING_MB`, 0 = detected memory minus a quarter,
never below 2 GB), the refusal (`BootMemoryCeilingExceeded`, naming
`raucle rotate-chain`) and the pre-binding refusal point are
unchanged J1 contracts. The defaults are the spec's starting points,
honestly pending the X5 re-derivation.

The runtime leg is the watchdog: it samples the process resident size
during the chain scan and the compactor phases, and a breach is the
same named refusal, never an OOM kill.

## What the boot does now (the sequence)

1. J1 preflight (budget projection; refusal before binding).
2. Policy, trust and identity load (bounded, unchanged).
3. Receipt store open (already bounded by design).
4. Index open WITHOUT the migration copy and WITHOUT the synchronous
   rebuild (both O(store) and moved behind the readiness gate); the J2
   recovery inspection stays at open.
5. Bind: the servers serve and `/health` answers. Gate traffic reads
   neither the index nor the audit chain.
6. The background compactor runs the four phases (migration, a
   TTL-bounded tail window that lands session continuity, a batched
   historical sweep, live-tail follow), and the readiness block on
   `/health` reports each surface.

Readiness is honest by contract: an index-backed query surface that is
not ready refuses with the named error `receipt_index_building` and
its progress (503, machine-readable), never an empty 200; a
session-rule call before continuity lands refuses with
`session_continuity_pending` (a receipted deny), never a silently cold
window. A torn or unparsable audit-chain tail raises
`chain_tail_malformed` naming the file, line and offset; a chain break
found by the scan stops it by name (`chain_refused`) and the sink does
not append past it. Both name `raucle rotate-chain` as the operator
path. No partial answers are served in v0.1.

## Machine and method (the recorded runs)

- Intel Core i5-8250U (8 threads, 1.60 GHz base), 23 GiB RAM, Linux
  7.2.15-1-omarchy, CPython 3.13.15 (the lane worktree venv),
  single-process bench, no load shaping.
- `python bench/run_bench.py --k1 --k1-scale demo --json
  bench/results/k1-2026-11-20.json`. Peak RSS is sampled every 10 ms
  from /proc/self/statm during each leg (so each leg's peak is the
  process's own, and sub-10 ms allocation spikes are invisible by
  construction); elapsed is wall-clock around the leg.
- Fixture (deterministic, synthetic, no demo data): a 512 MiB
  well-linked unsigned audit chain (1,305,311 events, ~410 bytes per
  line) plus 150,000 receipt envelopes over 11 segments (42.7 MiB),
  iats spread over four hours.

## Recorded results (demo scale, 2026-11-20)

Source of record: `bench/results/k1-2026-11-20.json`. The bench process
held ~109 MB baseline by the time legs started (post-generation); each
leg's peak is absolute process RSS, so a leg at ~109 MB is flat against
its baseline.

| Leg | Elapsed | Peak RSS |
|---|---|---|
| time_to_bind (deferred index open) | 0.016 s | 27.3 MB |
| tail_resume W=16 MiB | 0.56 s | 70.9 MB |
| tail_resume W=64 MiB | 2.1 s | 249.3 MB |
| tail_resume W=256 MiB | 8.9 s | 923.4 MB |
| chain_scan W=16 MiB | 71.6 s | 68.3 MB |
| chain_scan W=64 MiB | 71.4 s | 58.5 MB |
| chain_scan W=256 MiB | 79.3 s | 58.5 MB |
| index_migration (150k rows) | 1.1 s | 110.7 MB |
| tail window (TTL-bounded, per batch size) | 0.12-0.17 s | ~109-111 MB |
| sweep, batch 1k / 10k / 50k rows | 8.9 / 8.1 / 7.9 s | ~109-112 MB |
| boot end to end (scan + window + sweep) | 76.9 s | 108.7 MB |

Readings, honestly:

- **Bind-first is structural, not marginal**: the pre-bind cost
  (deferred index open) measured 16 ms against a 512 MiB chain and a
  150k-receipt store; the whole build ran after the bind, out of the
  request path.
- **The scan is W-independent and store-proportional in time only**:
  peak RSS is flat (58-68 MB) across the W matrix because the scan is
  line-streamed; W bounds the tail resume, not the scan. Throughput is
  ~5.5 us per event (18.3 MB/s), so at the incident's 12.2 GB the scan
  is an extrapolated ~30 minutes (NOT measured; the incident-scale leg
  exists for exactly this number).
- **W_replay is a real budget term with a measured multiplier**: the
  tail resume's peak grew 70.9 -> 249.3 -> 923.4 MB across W = 16 / 64
  / 256 MiB. The window's resident cost lands at roughly 3.5x W (the
  raw read plus the decoded line strings), so the honest projection
  correction for the X5 session is `W x ~3.5 + baseline + C_index`,
  not the spec's flat W. The default W=64 is conservative and correct
  today; the constant is what the bench replaces.
- **The sweep is batch-flat and time-proportional**: ~8 s for 150k
  receipts at every batch size (~19k rows/s), peak flat at ~109-112
  MB. Extrapolated (NOT measured) to the incident's 15 GB index
  class the sweep is hours, which is the spec's decision 3: if the
  incident-scale bench confirms hours, the v0.2 partial-serving
  extension (bounded-scope marker) moves into scope.
- **The end-to-end boot peaked at the process baseline** (108.7 MB)
  over a 512 MiB chain plus a 43 MiB store: the flatness property at
  demo scale. The whole-store boot this replaces would have mapped
  the chain's 1.3M records into the leaf list alone.

## The ci scale (the CI variant of AC1)

`--k1-scale ci` (8 MiB chain, 5k receipts) runs in ~6 s and is the
scale a CI job can afford. The suite's flatness test
(`tests/test_boot_stream.py::TestBootMemoryFlatness`) pins the same
property independently of the bench: peak traced allocations across
the bounded boot path at 2x store stay within a bounded absolute
delta of the 1x store and under a fixed ceiling.

## What the bench cannot settle (owner decisions, spec section 5)

- The incident-scale decomposition (the 23.4 GB) and the corrected
  projection constant: the incident leg must run on the target box
  (`--k1-scale incident`; a multi-hour run on this harness).
- The defaults in the spec's 3.8 table (W, C_index, batch rows) are
  starting points; no argument settles a window size, a distribution
  does.
- Whether restarts need a persisted verified-through checkpoint
  (spec decision 4): the measured ~18 MB/s scan throughput says a
  12.2 GB chain re-verifies in ~30 minutes on this class of box,
  which the owner may find acceptable without a cursor.
- `RAUCLE_INDEX_CACHE_MB`'s interaction with query latency on a 15 GB
  index after readiness is an operator preference the bench informs
  but cannot set (spec open question 3).
