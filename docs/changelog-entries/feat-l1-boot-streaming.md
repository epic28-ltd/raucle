- The 18 Nov incident's class defect closed at the structure (spec
  docs/spec/boot-streaming-v0.1.md, ADR 0007): the gateway binds first and
  streams its stores in bounded windows. The audit chain's resume is a
  bounded reverse tail read (W_replay, RAUCLE_BOOT_SCAN_WINDOW_MB, default
  64 MiB) with an incremental Merkle frontier sidecar replacing the
  whole-file leaf list (roots identical, O(log n) memory, disposable
  state per the strictest-verifier doctrine; the SSE replay tail reads a
  bounded window too, not the whole audit log per dashboard hit).
- Fail-closed where the old resume was silent: a torn or unparsable tail
  line raises the named refusal chain_tail_malformed (file, line number,
  byte offset, naming `raucle rotate-chain`), never the silent skip the
  whole-scan resume carried; the file is never modified. A chain break
  found by the background scan stops it by name (chain_refused with the
  break's coordinates) and the audit sink refuses to append past it.
- The receipt index builds in a background compactor after the bind, in
  the spec's four phases: migration inside the J2 one-transaction
  invariants (recovery inspection stays at open), a TTL-bounded tail
  window that lands session continuity (session-rule calls before it
  lands refuse by name, session_continuity_pending, never a silently
  cold window), a batched historical sweep with cursor-transactional
  resume (interrupted builds resume or restart, never crash-loop), then
  live-tail follow. Mid-build, index-backed query surfaces refuse by
  name with progress (receipt_index_building), never an empty 200 that
  looks complete; after the build, answers are byte-identical to a full
  rebuild_from_store.
- /health keeps its liveness contract and gains the machine-readable
  per-surface readiness block (gate, session continuity, chain scan
  with verified-through offset, receipt index with progress).
- Boot memory is bounded by configuration: the J1 preflight projects the
  window budget (baseline + scan window + index cache, spec 3.1) instead
  of the store's on-disk bytes, so the ceiling lowers as the windows
  shrink while the knob and refusal contracts stay; a runtime watchdog
  samples resident size during the scan and compactor and a breach is the
  shipped BootMemoryCeilingExceeded refusal, never an OOM kill.
- New knobs (honest defaults, pending the X5 bench re-derivation):
  RAUCLE_BOOT_SCAN_WINDOW_MB (64), RAUCLE_INDEX_CACHE_MB (64, SQLite
  page cache cap, mmap off), wired through the helm chart and
  deploy/prod.env.example with the J1 ceiling variable. The
  k1-boot-streaming bench (bench/run_bench.py --k1, scales ci, demo and
  incident) lands its legs in bench/results/k1-2026-11-20.json;
  docs/nfr/boot-streaming-v1.md records this machine's numbers and the
  incident-scale leg ships behind the flag for the X5 session that can
  afford it. The rotation runbook and the receipt-index ops note are
  extended, not contradicted.
- New tests pin the invariants (29 in tests/test_boot_stream.py, plus the
  re-derived preflight suite): bounded-boot flatness (peak allocations
  flat in store size, under the configured ceiling), bind-first against
  the real app factories, readiness honesty, the named torn-tail refusal,
  TTL session-continuity equivalence, the budget projection and the
  pre-binding refusal, the watchdog breach, resume-without-duplicates
  and the projection-equivalence guarantee.
