# Drift analytics NFR note - the five signals and their honest limits (I2)

**Scope and honesty rules.** This note covers the drift and scope-drift
analytics surface (raucle/drift.py, the `raucle analytics drift` CLI,
tests/test_drift_analytics.py). The report is a deterministic read of
receipt fields only. The invariant claims are pinned by tests the lane
ran live (25 tests in tests/test_drift_analytics.py, plus the unchanged
suite); no number in this note is transplanted from another machine
because the surface makes no performance claims. The signals derive
from shipped receipt shapes only: the W2 `x_gate.tool_definition` block
(docs/spec/provenance/v1.2/definition-drift.md), the v1.1
`x_gate.authorization` block, gate decisions, and the `x_revocation`
block in both its v1.0 and v1.2 shapes
(docs/spec/provenance/v1.2/revocation-receipts.md). No new secret, no
vault access, no policy re-run, no input replay.

## What the surface is

`raucle analytics drift <source>` reads a receipt chain JSONL file or a
segmented store directory (`seg-*.jsonl` in name order, `.meta` sidecars
skipped) and returns the same report bytes for the same source every
run. It is an analytics read, not a trust decision: it reports what the
receipts claim. Signature verification, chain integrity and the
revocation cascade's validity remain the offline verifier's job
(`raucle provenance verify`). A store whose receipts fail verification
still produces a report; the report says nothing about verification and
must never be read as one.

## The five signals

Each row cites the receipt hashes it rests on. A signal that cannot cite
its receipts is not emitted.

1. **definition-drift** (per tool). Two consecutive gate receipts for a
   tool carry `tool_definition` blocks with different `definition_digest`
   values. The row cites the last receipt under the old digest and the
   first under the new one, both digests, both `iat`s, the tool, the
   manifest and the agents that minted the two receipts. A single digest
   occurrence is not drift; it is one observation.
2. **authority-widening** (per agent). The agent's cited authority
   (`x_gate.authorization`) moved from an attenuated capability
   (`attenuated` true: a delegated, narrowed child) to a
   non-attenuated one. That is who got widened. The row cites the last
   receipt under the old authority and the first under the new one.
3. **authority-narrowing** (per agent). The reverse transition: a root
   grant replaced by an attenuated child. Same citation shape.
4. **deny-rate-delta** (per agent). The agent's allow/deny sequence
   split into two windows by receipt order (first half, second half).
   Each window cites every receipt hash it counts, so the rate
   re-derives from the row alone. A signal fires when the absolute
   delta reaches the threshold (default 0.5) AND each window carries at
   least the floor count (default 4; `--min-window` and `--deny-delta`
   are operator-visible flags, never hidden constants). Escalations sit
   outside both windows: neither allowed nor denied.
5. **revocation-cascade** (per revocation event). A revocation of an
   authority the chain shows in real use: the row cites the revocation
   receipt, every earlier gate receipt exercising the revoked authority
   (presented as the capability or as its parent: a child of a revoked
   capability lost its chain too), and the deny receipts the prior
   agents minted after the revocation line. Optional versioned fields
   (root, reason_class, kind) ride only when the block carries them.

## Honest states

- A gate receipt whose envelope carries no receipt hash cannot be
  cited, so no signal derives from it. It still counts in
  `gate_receipts`: the scan is honest about what it saw.
- A capability switch between two equally attenuated children (or two
  root grants) is rotation, not drift: no signal.
- A revocation with no prior use in the scanned span is an ending, not
  a cascade: no signal. The revocation still counts in
  `revocation_receipts`.
- Unparsable lines count in `unparsable_lines` and never stop the scan.
- A deny-rate shift on windows thinner than the floor is not called,
  whatever the delta. Lowering the floor is the operator's explicit
  choice on the command line, and the report records what it was given,
  not what it wished for.
- The zero-signal report states its coverage explicitly (receipts,
  gate, revocation counts), so "no signals" reads as "nothing met a
  signal definition over N receipts", never as "no data".

## Bounded disclosure

The report is a bounded-disclosure surface: digests, identifiers, names
and counts only. Denial reasons can quote constraint values, so they
never enter any row; the receipts cited by a row are where the full
story lives. The test pins both halves: a seeded value string appears
nowhere in the serialized report, and no content-like field name (the
shared `provenance._FORBIDDEN_FIELD_NAMES` vocabulary) appears at any
depth in any row.

## What the report does NOT prove

- It does not verify signatures, chain integrity, or that any cited
  receipt is genuine. Run the verifier for that; the two tools answer
  different questions.
- definition-drift reports that a digest CHANGED. It does not say the
  new definition is wider, narrower, better or worse, and it cannot
  diff the two schemas: receipts carry digests, not definitions. What
  changed lives in the manifests the receipts name.
- authority-widening reports that the agent's cited authority changed
  width. It does not measure the authority's actual scope: receipts
  carry capability identifiers and the attenuation flag, never
  constraint sets. A "widened" row means the agent moved onto a root
  grant; whether that grant's scope is in any sense larger is a policy
  question the receipts do not answer.
- deny-rate-delta is a rate over two windows, not a cause. A delta can
  come from a policy change, a live attack, a tool outage or a fixture.
  The row cites the receipts; the explanation stays with the operator.
- revocation-cascade shows prior use and later denials in chain order.
  It does not claim the later denials were CAUSED by the revocation
  (a deny receipt may not cite the revoked capability at all), and it
  does not attempt post-revocation use: within a verified chain such
  receipts do not exist, and within an unverified one this tool makes
  no validity claim.
- The window split for deny-rate-delta is by receipt order, not
  calendar time. A store with a long quiet gap still splits at the
  median receipt. `iat` values ride the rows so the operator can see
  the actual spans.

## Byte-shape discipline

Optional row fields are omitted when absent, never nulled (a v1.0
revocation emits no `reason_class`/`kind` keys; a definition block
without a manifest emits no `manifest` key). The report is
deterministic: the same source produces the same bytes every run,
pinned by test. No existing report body was extended, so no existing
digest pin moves; the demo-bundle and fixture-pack currency tests ran
green in the same round as this lane's suite.

## Named follow-up

The operator panel integration (a drift row in the receipts view) is a
named follow-up, not shipped here: a panel surface is an endpoint plus
render contract plus disclosure sweep of its own (the X6 simulate tab's
scope), not a cheap add-on to a CLI lane. The CLI report is the
deliverable surface of I2.
