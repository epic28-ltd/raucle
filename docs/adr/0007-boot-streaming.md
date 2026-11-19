# ADR 0007: The gateway boot streams its stores in bounded windows and never maps a store whole

Status: Proposed (design slice K1, spec precedes implementation; ratify on
the implementing lane's bench evidence, acceptance criteria in
[docs/spec/boot-streaming-v0.1.md](../spec/boot-streaming-v0.1.md))
Date: 2026-11-19
Deciders: lane K1 design; owner ratification pending
Series: this is the first ADR filed in the raucle core repo. The suite
series it continues (0001-0006) lives in
raucle-agent-assurance/docs/adr/.

## Context

The 18 November demo outage OOM-killed the gateway three times at boot:
a 12.2 GB audit log plus a 15 GB receipt index ballooned to about
23.4 GB resident on a 24 GB box, crash-looping under `restart:always`
(docs/nfr/receipt-index-ops-v1.md). Two interim lanes shipped honest
answers: J1 added a boot memory preflight that refuses before loading and
an operator rotation command (PR #297), and J2 made the index's schema
migration crash-recoverable (PR #296). Neither changes the structural
fact: several boot paths cost memory in proportion to stores that grow
without bound, so the box that outgrows its ceiling cannot boot until an
operator rotates. The named follow-up was recorded in the incident
post-mortem: the boot must stop mapping whole stores.

## Decision

1. Boot memory is bounded by configuration, not by store size. Every
   boot-time store consumer reads through a bounded window (default 64
   MiB) or moves behind a readiness gate. The J1 preflight re-derives
   its projection from these window terms, so the effective ceiling
   lowers as windows shrink while the knob and refusal contracts stay.
2. The server binds first. Gate traffic does not read the index or the
   audit chain, so the decision path serves before the store-derived
   state is warm; only session-rule evaluation waits (bounded by the
   session TTL, a named refusal until it lands).
3. The receipt index builds in a background compactor after the bind:
   migration inside the J2 invariants, a TTL-bounded tail window for
   session continuity, then a batched historical sweep, then live-tail
   follow. An interrupted build resumes or rebuilds, never crash-loops.
4. Hash-chain resume becomes a bounded reverse tail read plus an
   incremental Merkle frontier (sidecar state, disposable, detectably
   wrong if tampered). The full in-memory leaf list goes away; the same
   primitive fixes the per-event whole-chain scans and the SSE replay
   tail.
5. Readiness is reported per surface (gate, session continuity, chain
   scan, receipt index) and is honest: an unbuilt surface refuses with a
   named error and progress, never an empty answer that looks complete.
   No partial answers in this version.
6. Fail-closed discipline is unchanged and tightened where it was
   silent: a torn tail is a named refusal (`chain_tail_malformed`),
   never a skipped line; a chain break mid-scan seals the audit sink
   rather than appending onto unverifiable links. The operator path for
   both stays `raucle rotate-chain`.
7. The shipped primitives keep their contracts: preflight (knob,
   refusal, headroom), rotation (receipted, never deletes), recovery
   (schema inspection before ALTER, one-transaction migration,
   `rebuild_from_store` as the repair contract).

## Consequences

- The unbootable-box class dies: a store of any size boots within its
  budget, and the growth wall stops existing at boot. The preflight and
  a runtime watchdog remain as the invariant's tripwires.
- Boot gains a warm-up window instead of a hard failure. Receipt search
  and chain-derived views are briefly unavailable by name, and
  session-rule calls refuse for a TTL-bounded interval. The demo and
  production profiles both pay this; the bench (k1-boot-streaming, on
  the X5 harness) measures how long it really is.
- Checkpoint anchoring can be briefly degraded by name (frontier
  rebuilding) where today it silently assumes the leaf list.
- Complexity moves from memory risk to sequencing: a compactor with
  phases, cursors and a live-tail handover replaces a single blocking
  construction. The acceptance criteria pin the races that handover can
  hide.
- The incident's 23.4 GB decomposition stays unattributed until the
  bench measures it; the shipped 2.0 multiplier remains a conservative
  refusal threshold until replaced by measured terms.

## Alternatives considered

- Map the files with mmap and let the kernel page them. RSS at access
  time still tracks store size, a scan still touches every page, and the
  OOM returns; the box's accounting just moves.
- Keep the current boot and require bigger boxes. Cost scales with
  store growth forever and the demo profile (24 GB) stays one growth
  spurt from a repeat.
- Refusal only (J1 as the final answer). Honest, but converts a growth
  wall into a hard outage until an operator acts, which is the exact
  availability gap this ADR closes.
- A separate index service. Defers the memory problem to another
  process boundary without bounding anything, and splits the
  single-process deployment story today. Revisit if the compactor's
  live-tail handover proves harder than the bench expects.
