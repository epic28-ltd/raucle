# Boot streaming (v0.1): the gateway boot over bounded windows, never whole stores

Status: draft 19 November 2026. Lane K1, design slice. This document and
[ADR 0007](../adr/0007-boot-streaming.md) record the architecture for the
named bigger follow-up to the 18 November demo OOM incident: the boot must
stop mapping whole stores. It builds on the shipped interim primitives, the
boot memory preflight and `raucle rotate-chain` (J1, PR #297, in review) and
the receipt-index mid-migration recovery (J2, PR #296, merged). No code ships
in this lane; the implementing lane takes the acceptance criteria in
section 6. Line numbers are as of origin/main at this PR's head (includes #297's rotation command and boot preflight).

## 1. The problem, with the incident as evidence

The gateway's stores grow without bound and several boot-time paths cost
memory in proportion to them. A bounded box eventually meets an unbounded
store, and the meeting point is invisible until the next restart.

The incident record (docs/nfr/receipt-index-ops-v1.md, the J2 operational
note; docs/ops/chain-rotation.md, the J1 runbook, PR #297): during the 18
November demo, /data/gateway-audit.jsonl had grown to 12.2 GB and
/data/receipts-segments/index.sqlite to 15 GB. The boot ballooned to about
23.4 GB resident on a 24 GB box and the kernel killed it three times,
crash-looping under `restart:always`. Operator-reported details beyond the
records below (18 November deploy-session console and dmesg, not part of
this repository): kills visible from about 18:20, UID 999; the rolled-back
build (caf4a91) OOM'd identically. Two facts make this a class defect
rather than a bad day:

- The previous container had been up for six days, so the growth wall was
  crossed between restarts. The rebuilt code and the rollback OOM'd
  identically: the size, not that day's changes, was the cause.
- The second crash signature was independent of memory: the index's
  migrate-on-open failed closed on a half-migrated store an earlier OOM
  death had left behind. Fail-closed worked; recovery did not exist (J2
  shipped it).

The shipped interim answers the incident honestly but not structurally:

- J1's preflight states the projected boot memory before loading and
  refuses with a named error naming `raucle rotate-chain` when the
  projection exceeds `RAUCLE_BOOT_MEM_CEILING_MB` (default: detected
  memory minus a quarter, never less than 2 GB). The refusal is honest and
  it kills the crash-loop. It does not boot the box: a store past its
  ceiling keeps the gateway down until an operator acts.
- J2's recovery removes the migration crash-loop. Its own residual
  register says the rest plainly: the fix removes the crash-loop, not the
  memory pressure.

So the named follow-up this document designs: the boot itself must stream
its stores in bounded windows, so the projected memory stops scaling with
store size. The preflight and rotation stay; the condition that makes them
load-bearing shrinks.

## 2. Current behaviour (the sites that are size-proportional)

Verified against this PR's base main (includes #297):

| Site | What it does | Cost class |
|---|---|---|
| `raucle/receipt_index.py:115` open + `_init_schema` | Opens the index at boot and migrates schema v1/v2 to v3, copying the table. J2 made the migration one recoverable transaction (recovery inspection at :151); it is still a whole-table operation inside the boot path. | O(table) time and journal growth at boot |
| `raucle/gateway.py:1411-1418` count()==0 rebuild | A fresh or lost index triggers a full `rebuild_from_store` / `rebuild_from_flat_file` synchronously at gateway construction, one commit per record. | O(chain) boot latency; per-record commits |
| `raucle/audit.py:268` HashChainSink._resume | On construction the sink scans the entire chain file and retains every record's hash in `self._leaf_hashes` (audit.py:287), the list the periodic Merkle checkpoint roots (audit.py:361). Constructed per deployment-intake event over the gateway audit chain (raucle/deployment_intake.py:258) and long-lived on the scanner surface. | O(records) memory and O(file) scan per construction |
| `raucle/server.py:668` SSE replay tail | `fh.readlines()[-replay:]` loads the whole audit log to serve the last 50 frames. Request path, not boot, but the same class. | O(file) memory per dashboard hit |
| `raucle/audit.py:280-282` silent skip | `_resume` silently skips lines that fail to parse and takes the next parsable record as the tail. A torn write is absorbed, not named. | fail-closed gap |
| J1 preflight (PR #297) | Stats the boot stores (`resolve_boot_stores`) and projects resident cost at a documented 2.0x multiplier before loading. | the honest ceiling over an unbounded boot |

Two things at boot are already bounded and the design leaves them alone:
`SegmentedReceiptStore` (raucle/receipt_store.py) resolves its active segment
by glob and streams counts on demand, and the receipt chain appends per
record with a flush. The size-proportional costs are the index open path,
the synchronous rebuild, the audit sink resume and the replay tail.

One honesty note the bench must settle (section 5): the incident recorded
23.4 GB resident over 27.2 GB of stores. The shipped 2.0 multiplier
(raucle/chain_rotation.py, `BOOT_MEM_RSS_MULTIPLIER`) is a deliberately
conservative refusal threshold, not a measured decomposition of that
number. Nothing in the incident record attributes the 23.4 GB per
component. The bench fixture measures it and the preflight projection is
re-derived from the measurement.

## 3. The design

### 3.1 The invariant

INVARIANT (K1): the gateway boot's resident memory is bounded by
configuration and independent of store size. A store may grow without
bound; a boot may not grow with it.

Expressed as a budget the preflight can check before loading anything:

```text
projected_boot_rss = baseline_gateway
                   + W_replay          (chain scan window, default 64 MiB)
                   + C_index           (SQLite page cache cap, default 64 MiB)
                   + C_misc            (request buffers, bounded as today)
```

Every store-consuming boot path must fit one of the bounded terms or move
behind the readiness gate (3.6). A path that cannot is a defect against
this invariant, not a tuning problem.

### 3.2 Bind first (the boot sequence)

Today the gateway constructs fully, then serves. The design inverts the
two expensive halves: the server binds as soon as the decision path is
safe, and the store-derived state warms in the background.

```text
boot:
  0. J1 preflight (projection per 3.1; refusal names raucle rotate-chain)
  1. policy, trust and identity load (unchanged, bounded)
  2. boot selftest (unchanged, gateway_server.py:45)
  3. receipt store open (already bounded)
  4. index open: J2 recovery inspection only (schema artifact check);
     migration and rebuild are NOT run here
  5. bind the servers; /health answers (liveness contract unchanged)
  6. background compactor starts (3.4, 3.5) and readiness surfaces report
     progress (3.6) until they are ready
```

The gate decision path reads policy and tokens, never the index, and never
the audit chain; the J2 note states the general rule, verification always
reads the chain and never the index. One boot consumer does read the
index: the session-window replay (`_replay_session_windows`,
raucle/gateway.py:1380-1383) restores behavioural-rule counters so a
restart mid-session does not silently reset enforcement. That consumer
defines the compactor's first phase, not an excuse to block the bind.

### 3.3 Bounded tail resume (append readiness in seconds)

Appending to a hash chain needs exactly the tail state: the previous hash
and the next index. The design replaces whole-scan resume with a bounded
reverse read of the final window of the file (default W_replay), which
recovers the tail in seconds regardless of file size.

- `HashChainSink._resume` becomes a windowed scan: read the file in
  bounded windows, retain only the running tail state, and (for signed
  sinks) an incremental Merkle frontier instead of the full leaf list.
  The frontier is O(log n) memory and produces the same checkpoint roots
  a full leaf list produces; an offline verifier recomputing roots from
  the file detects a wrong frontier, so the frontier is a disposable
  cache in the same sense the index is (chain of record stays the truth).
- A missing or stale frontier degrades checkpoint anchoring only, and by
  name (a log line and a readiness surface), never silently: the
  background scan (3.4) rebuilds it.
- The same primitive serves the deployment-intake sink
  (raucle/deployment_intake.py:258), which today re-scans the whole audit
  chain per event, and the SSE replay tail (raucle/server.py:668), which
  today loads the whole file to keep 50 frames. Both are closed by the
  same bounded reverse read, not by two new mechanisms.

### 3.4 The background chain scan

After the bind, a single background scan walks the audit chain and the
receipt segments in bounded windows and produces the state the boot used
to retain up front: counters, the verified-through offset and the Merkle
frontier. The scan recomputes each record's chain link as it goes, so
readiness can report a real signal: chain verified through offset X, not
merely read through it. Nothing today at boot checks chain integrity;
this is an addition, and it must not be read as boot-time verification
of the chain of record, which stays an offline verifier's job
(docs/nfr/receipt-index-ops-v1.md).

### 3.5 The index compactor

The receipt index is a query cache over the chain; it can be dropped and
rebuilt at any time (`rebuild_from_store`, the repair contract). The
design moves its expensive phases off the boot path and behind the
readiness gate, in four ordered phases:

1. Migration. If the on-disk index needs a schema migration, the
   compactor runs it inside the J2 invariants: recovery by schema
   inspection before any ALTER, one transaction carrying the schema and
   the `user_version` stamp. J2's recovery inspection stays at open (it
   is cheap and it is the boot-safety contract); the copy itself becomes
   a readiness-gated phase.
2. Tail window. Index the recent segments covering the session-window TTL
   (`session_window_ttl_seconds`), newest first. This phase is bounded by
   the TTL, not the store, so it lands in seconds at any scale.
3. Session continuity. `_replay_session_windows` runs against the tail
   window and behavioural-rule counters go live. Until it does, calls whose
   policy depends on a session rule receive a named refusal
   (`session_continuity_pending`); the Q1 contract (restart must not
   silently reset enforcement) forbids serving them cold, and a bounded
   seconds-scale gate is the honest way to keep both.
4. Historical sweep. The compactor indexes the remaining prefix in
   batches (one transaction per batch, size a bench question), then
   switches to live-tail follow mode, which is the shipped append path
   (`index_receipt` on every sink, RED-034) and must not race the sweep:
   the sweep owns rows up to a cursor and the live path owns everything
   after it.

An interrupted compactor run must resume or restart itself, never
crash-loop: the same doctrine the J2 note pins for migrations extends to
builds, and `rebuild_from_store` stays the operator's repair path.

### 3.6 The readiness contract

Liveness and readiness separate. `/health` keeps its shipped liveness
contract (always open, gateway_app.py:648) and gains a machine-readable
readiness block; nothing about existing probes changes.

```text
GET /health
{
  "status": "ok",
  "readiness": {
    "gate":                "ready",
    "session_continuity":  "ready" | "pending",
    "chain_scan":          {"state": "scanning", "verified_through": "<offset>",
                            "progress": 0.0-1.0},
    "receipt_index":       {"state": "building" | "ready" | "refused",
                            "indexed_rows": n, "progress": 0.0-1.0}
  }
}
```

The contract the implementing lane must pin:

- A query surface that is not ready refuses with a named error and a
  machine-readable reason (`receipt_index_building`), never an empty
  200. An unbuilt index answering "no receipts" is indistinguishable
  from an empty chain, and that silence is the truncation this design
  refuses.
- Partial answers are not served in v0.1. Serving the indexed prefix with
  an explicit bounded-scope marker is a v0.2 extension, decided by the
  bench numbers (how long the sweep really takes at incident scale).
- Readiness states are monotonic per boot: a surface that reported ready
  does not regress without a named refusal at the cause (a chain break,
  a compactor fault).

### 3.7 Fail-closed discipline (the tail is named, never truncated)

- A torn or unparsable tail line found by the bounded tail resume or the
  scan is a named refusal: `chain_tail_malformed`, naming file, line
  number and offset. Today `_resume` silently skips unparsable lines
  (raucle/audit.py:280-282) and the boot proceeds on a chain whose tail is
  broken; that silence is the exact defect this closes. The refusal names
  the operator path (`raucle rotate-chain` archives the broken chain
  verifiably and starts a fresh one).
- A chain link that fails recomputation mid-scan stops the scan at the
  break: the chain surfaces report `chain_refused` with the break's
  coordinates. The audit sink must not append past a break (every later
  record would chain onto unverifiable links), so the sink seals and the
  operator decides. This is a deliberate availability trade: evidence
  integrity over uptime on a store already damaged. The gate's own
  receipts (the segmented receipt chain) are unaffected; the seal is the
  audit chain's alone.
- The index projection may still skip records that are not receipt
  envelopes (chain_meta and checkpoint records are expected
  non-receipts); shape-filtering a disposable projection is not
  truncation. The chain of record is never rewritten by any of this.

### 3.8 Hard memory bounds (the knobs)

| Knob | Default | Meaning |
|---|---|---|
| `RAUCLE_BOOT_SCAN_WINDOW_MB` | 64 | W_replay: the read window for tail resume, scan and rebuild feeding |
| `RAUCLE_INDEX_CACHE_MB` | 64 | SQLite page cache cap for the index connection (`PRAGMA cache_size`); mmap stays off |
| `RAUCLE_INDEX_BATCH_ROWS` | bench question | Rows per transaction in the sweep and migration feed |

Defaults are starting points for the bench, not decisions. The boot also
carries a watchdog: it samples its own resident size against the J1
ceiling during the scan and compactor, and a breach is a named refusal
(the shipped J1 exception `BootMemoryCeilingExceeded`; the deny-reason
  vocabulary renders it `boot_memory_ceiling_exceeded`), never an OOM kill.
The watchdog turns the preflight's projection from a claim into a checked
invariant.

## 4. Interaction with the shipped primitives

- J1's preflight stays and gets stronger. Its projection moves from
  "2.0x store bytes" to the budget in 3.1, so the ceiling a boot must
  meet no longer grows with the stores: as the windows shrink, the
  projection, and therefore the effective ceiling, lowers for the same
  refusal guarantee. The knob (`RAUCLE_BOOT_MEM_CEILING_MB`) and the
  refusal (`BootMemoryCeilingExceeded`, naming `raucle rotate-chain`)
  keep their contracts; existing J1 tests keep passing with the projection
  re-derived. The watchdog (3.8) is the preflight's runtime leg.
- J1's `rotate-chain` stays the operator action. Its role shifts from
  "the only way to boot a box that outgrew its memory" to disk hygiene,
  purposeful archiving and the recovery path for a chain the scan
  refused. The runbook (docs/ops/chain-rotation.md) keeps its incident
  worked example and gains the streaming-era "when to rotate" lines.
- J2's recovery stays the index's safety net. The compactor's phases run
  inside the one-transaction doctrine; the recovery inspection stays at
  open; `rebuild_from_store` stays the repair contract. The operational
  note (docs/nfr/receipt-index-ops-v1.md) must be updated, not
  contradicted, when the compactor lands, and the implementing lane
  extends it with the build-resume invariant.

## 5. Open questions and the bench (what cannot be decided without numbers)

The X5 harness (bench/run_bench.py, docs/nfr/x5-performance-bench.md)
measures seven hot paths today; the implementing lane extends it with a
boot leg and a fixture, both deterministic and synthetic (no demo data):

- Fixture: a seeded generator producing an audit chain and receipt store
  at incident scale (12.2 GB audit log class, index equivalent), plus a
  small-scale variant for CI.
- Experiment, named `k1-boot-streaming`: legs `tail_resume`,
  `chain_scan`, `index_migration`, `index_rebuild_batched`; measures peak
  RSS per leg, time-to-bind, time-to-session-continuity and
  time-to-index-ready across W in {16, 64, 256} MiB and batch in
  {1k, 10k, 50k} rows. Results land in bench/results/k1-<date>.json and
  the NFR note, never copied between machines (the X5 rule).
- Decisions gated on those numbers:
  1. The defaults in 3.8. No argument settles a window size; a
     distribution does.
  2. The real decomposition of the incident's 23.4 GB, and the corrected
     preflight projection. The 2.0 multiplier is a conservative refusal
     threshold; the bench replaces it with measured terms.
  3. Whether the historical sweep is minutes or hours at incident scale.
     Minutes: refuse-until-ready (3.6) is enough. Hours: the v0.2
     partial-serving extension moves into scope and the readiness
     payload needs the indexed-through marker.
  4. Whether restarts need a verified-through checkpoint (a resume
     cursor persisted beside the chain, disposable, fail-closed on
     mismatch) so a healthy restart skips the scan, or whether scan
     throughput makes the checkpoint unnecessary complexity.
  5. The rebuild floor implied by the shipped per-record commit
     (index_append p50 35.4 us on the recorded X5 run) once the fixture
     measures the real row count; batching is the lever, the bench sizes
     it.
- Open questions the bench cannot answer, for the owner:
  1. Is the seal-the-sink trade in 3.7 (evidence integrity over gate
     uptime when the audit chain is broken) the right default, or should
     the demo profile differ from production profiles?
  2. Should readiness live on `/health` as specified, or on a separate
     `/ready` surface, keeping `/health` byte-stable for existing
     probes? The contract is the machine-readable states either way.
  3. The `RAUCLE_INDEX_CACHE_MB` default interacts with query latency
     on a 15 GB index after readiness; the acceptable floor is an
     operator preference the bench informs but cannot set.

## 6. Acceptance criteria for the implementing lane

- AC1 Bounded boot. A synthetic incident-scale fixture boots with peak
  RSS within the configured budget, independent of store size. CI runs a
  scaled-down variant asserting the flatness property (RSS at 2x fixture
  within noise of RSS at 1x); the incident-scale number is the bench leg,
  recorded in bench/results/k1-<date>.json.
- AC2 Bind first. The server binds and /health answers while the
  compactor is mid-build, pinned by a test that drives a controlled-slow
  compactor against the real app factory.
- AC3 Readiness honesty. Mid-build, receipt query surfaces return a
  named refusal with progress, never an empty 200; after completion,
  query answers are byte-identical to a full `rebuild_from_store`
  (projection equivalence test).
- AC4 Fail-closed tail. A torn final line produces
  `chain_tail_malformed` naming file, line and offset, at tail resume and
  at scan; the file is never modified; the refusal names `raucle
  rotate-chain`.
- AC5 Session continuity. A boot with a TTL window of history restores
  session windows identical to a full-index replay (equivalence test),
  and session-rule calls before continuity lands receive the named
  `session_continuity_pending` refusal, never a silent cold start.
- AC6 Preflight integration. The J1 preflight keeps its knob and refusal
  contracts with the budget projection (3.1); the existing
  test_chain_rotation.py suite passes with the projection re-derived; a
  boot whose budget exceeds the ceiling refuses before binding.
- AC7 Rotation preserved. `raucle rotate-chain` round-trips unchanged on
  a stream-booted gateway: named refusals, archive, rotation receipt,
  fresh-boot verification.
- AC8 Recovery preserved. The J2 suite stays green; an interrupted
  compactor run resumes or rebuilds itself with no crash-loop (kill tests
  in the J2 style); the ops note gains the build-resume invariant.
- AC9 No verification weakening. The offline verifier and every chain
  integrity test are untouched and green; the index remains a disposable
  projection; no new in-band record kinds (frontiers and cursors are
  sidecar state, per the strictest-verifier doctrine).
- AC10 Numbers and docs. The k1-boot-streaming bench legs run and land
  in bench/results/; docs/nfr gains the boot NFR note; the runbook and
  the receipt-index ops note are updated, not contradicted; the changelog
  entry names the incident and the mechanism honestly.

## 7. Out of scope

Implementation code (this lane), the EE or cloud surfaces, the receipt or
verifier formats (no schema changes; frontiers and cursors are sidecar
files), prefix-serving queries (a named v0.2 extension, bench-gated), and
any change to what the offline verifier accepts.
