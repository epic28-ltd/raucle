# Lean 4 mechanisation — Verified Capability Discipline

Skeleton for the three soundness theorems referenced in `paper/DRAFT.md` §4,
plus Theorem 4 on multi-token chaining and Theorems 5-6 on cross-call
effect composition over provenance paths.

**Status:** all six theorems are proved. `lake build` completes with zero
errors, zero warnings, and zero `sorry`s (see `STATUS.md`). The proofs cover the
data model and algorithms within the modelled scope (below), not the full runtime
gate.

## Files

- `Basic.lean` — data model: `Constraint`, `Policy`, `Token`, `GateDecision`.
- `Attenuation.lean` — Theorem 1: attenuation cannot broaden permissions.
- `Gate.lean` — Theorem 2: gate soundness.
- `Composition.lean` — Theorem 3: policy-proof composition.
- `ConfusedDeputy.lean` — Theorem 4: two-token chaining yields AND-composition, never OR-composition.
- `CrossCall.lean` — Theorems 5-6: cross-call effect composition and provenance-path composition over receipts.

## Build

```
elan default leanprover/lean4:v4.10.0
lake update
lake build
```

## Proof boundary (what the Lean model covers — and does not)

The mechanisation is intentionally a model of the gate, narrower than the
runtime implementation. Stating this precisely so the claim is not overread:

**Gate soundness (`Gate.lean`) models these constraint kinds:** `allowed_values`,
`forbidden_values`, `max_value`/`min_value`, `required_present`. The theorem
`gate_soundness` shows that an ALLOW implies these are satisfied over the
caller-supplied relevant-field list.

**NOT in the Lean model (enforced by the Python runtime gate + tests, not yet
mechanised):** `starts_with`, `forbidden_field_combinations`, dot-delimited
`agent_id` scope, the revocation denylist, expiry/`not_before`, signature and
issuer verification, and strict-mode proof binding. Extending the Lean `Policy`
and `Gate.check` to cover these is tracked future work.

**Composition (`Composition.lean`)** assumes prover soundness as an explicit
`axiom prover_soundness` — the Z3 provers in `prove.py` are NOT themselves
verified in Lean. Theorem 3 concludes, for a call in a tool's modelled call
language under a PROVEN proof for that tool's `(schema, P)` and a gate that
accepts it: (1) the call satisfies the policy `P` — via `prover_soundness`
(load-bearing) — and (2) the call satisfies the token's runtime constraints —
via `gate_soundness`. The binding that the *cited* proof pertains to this
tool's `(schema, P)` is an operational strict-mode runtime check
(`capability.py::_check_proof_binding`), taken as a hypothesis here and not
mechanised; the prover itself is not proved correct (it is the axiom). See
`STATUS.md` for the exact claim.

**Confused-deputy chaining (`ConfusedDeputy.lean`) - what is mechanised:** an
agent holding TWO valid capability tokens for the same tool with different
constraint policies, chaining both against ONE call that passes the gate under
each token. Theorem 4 (`confused_deputy_conjunction`) shows that such a call
satisfies the lattice meet of the two policies (`P1 ⊓ P2`, `Basic.lean`):
every constraint of either token is enforced over the call. Chaining multiple
credentials therefore yields AND-composition of constraints, never
OR-composition: the deputy cannot reach an action outside the intersection
of the two scopes by splitting authority across tokens.

**NOT in the ConfusedDeputy model (honest gaps, all outside the Lean model):**
splitting one intended EFFECT across two DIFFERENT calls (call 1 under token
1, call 2 under token 2) is only bound per-call: each call satisfies its own
token's constraints via `gate_soundness`, and the claim that no cross-call
combination exceeds the union of individual scopes is enforced by the runtime
review and receipt layer, not mechanised in this file (a first mechanised
fragment of that layer now exists: `CrossCall.lean`, see below). Also out of scope:
`forbidden_combos` is not part of `satisfies_field` (see the gap noted
under gate soundness, inherited by this theorem), and both gate checks in the
theorem are taken at the same clock instant `now`, so a token expiring
between the deputy holding the two tokens is not modelled.

**Cross-call composition (`CrossCall.lean`) - what is newly mechanised:** the
split-effect gap above now has its first mechanised fragment, with no new
axioms and no proof gaps:

- `Receipt`/`receiptOf`: the receipt layer records one allowed call exactly
  when `Gate.check` allows it (fail-closed); `receiptOf_sound` re-derives the
  `gate_soundness` conclusion for the recorded call, so every receipt carries
  the gate-soundness invariant.
- `EffectPolicy`: a policy over a call CHAIN, adding a cumulative ceiling per
  numeric field (`max_total_value`) to the per-call `Policy` kinds.
- `chainCheck`: the explicit call/effect-composition relation. A new receipt
  composes onto the accumulated receipts through the running total and must
  stay under every cumulative ceiling. The separation result
  `per_call_satisfaction_insufficient` proves the relation is load-bearing:
  two calls, each within the same per-call cap, jointly exceed the cumulative
  cap, so per-call satisfaction (the usable content of `gate_soundness`)
  alone CANNOT give the cross-call bound.
- Theorem 5 (`split_effect_composition`): the PR 253 split-effect scenario,
  mechanised end to end: two gate-allowed calls, bounded per call, also
  compose to a composite effect that admits the chain policy, in receipt
  terms and in call-argument terms.
- Theorem 6 (`provenance_path_composition`) with `Path.admits`: the first
  provenance-graph composition lemma: a path of receipts, each issued for a
  gate-allowed call and each compositing onto its predecessors, preserves
  both the gate-soundness invariant (node by node) and the chain-wide
  cumulative bound.

**NOT in the CrossCall model (honest gaps):** paths are linear (the spine of
a provenance graph; branching DAGs, where one receipt composes onto two
parents, are future work); the cumulative ceiling is the only cross-call
constraint kind so far (`forbidden_combos`-style cross-call kinds are not
modelled); the layer's own record-keeping (that recorded receipts match real
calls and compose in causal order) is inherited trust; two hops may cite
different tokens and nothing binds them (that is Theorem 1's attenuation
story); and all gate checks remain at one clock instant, as in Theorems 2-4.

## Trust assumptions

The mechanisation establishes correctness of the **data model and algorithms**
within the scope above. It does not mechanise:

- Ed25519 bit-level correctness (trusted oracle; see [BHB22] for an independently verified specification).
- Z3 solver soundness for the supported fragment (trusted oracle / explicit axiom; cross-validation against CVC5 recommended for production).
- The receipt layer's own record-keeping (`CrossCall.lean`): that recorded receipts match real calls and compose in causal order is inherited runtime trust; the Lean model takes receipts as given once the gate allows.
- The bridge from the Python implementation to the Lean model (maintained by structural correspondence; a future paper could mechanise this via PyLean or equivalent).
