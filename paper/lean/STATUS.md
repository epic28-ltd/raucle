# Lean development — status

**Toolchain:** Lean 4.10.0 + Mathlib 4.10.0.
**Build status:** `lake build` completes with **zero errors, zero warnings, zero sorrys**.

## All six theorems are mechanised

| Definition / Theorem | File | Status |
|---|---|---|
| `Policy` (record + lattice meet) | `VCD/Basic.lean` | ✓ type-checks |
| `Tighter` relation | `VCD/Basic.lean` | ✓ type-checks |
| `Token` (record) | `VCD/Basic.lean` | ✓ type-checks |
| `AgentId.extendsB` (Bool) | `VCD/Basic.lean` | ✓ type-checks |
| `attenuate` (function) | `VCD/Attenuation.lean` | ✓ type-checks |
| `Tighter.refl` | `VCD/Attenuation.lean` | **✓ proved** |
| `meet_tighter` (all 6 cases) | `VCD/Attenuation.lean` | **✓ proved** |
| **`attenuation_soundness` (Theorem 1)** | `VCD/Attenuation.lean` | **✓ PROVED** |
| `Gate.check`, `satisfies_field`, `satisfiesArgs` | `VCD/Gate.lean` | ✓ type-checks |
| **`gate_soundness` (Theorem 2)** | `VCD/Gate.lean` | **✓ PROVED** |
| `tighter_implies_satisfies_field` | `VCD/Composition.lean` | **✓ proved** |
| `tighter_implies_satisfies` | `VCD/Composition.lean` | **✓ proved** |
| **`policy_proof_composition` (Theorem 3)** | `VCD/Composition.lean` | **✓ PROVED** |
| `satisfies_field_meet` | `VCD/ConfusedDeputy.lean` | **✓ proved** |
| `satisfiesArgs_meet` | `VCD/ConfusedDeputy.lean` | **✓ proved** |
| **`confused_deputy_conjunction` (Theorem 4)** | `VCD/ConfusedDeputy.lean` | **✓ PROVED** |
| `Receipt`, `receiptOf`, `callContrib`, `totalAcross` | `VCD/CrossCall.lean` | ✓ type-checks |
| `EffectPolicy` (chain policy), `WellFormed`, `admits` | `VCD/CrossCall.lean` | ✓ type-checks |
| `chainCheck` (explicit effect-composition relation) | `VCD/CrossCall.lean` | ✓ type-checks |
| `Path` (inductive provenance path), `Hop`, `hopReceipt` | `VCD/CrossCall.lean` | ✓ type-checks |
| `receiptOf_sound`, `contrib_eq_callArg`, `totalAcross_append`, `totalAcross_two_comm` | `VCD/CrossCall.lean` | **✓ proved** |
| `Path.admits` | `VCD/CrossCall.lean` | **✓ proved** |
| `per_call_satisfaction_insufficient` (separation) | `VCD/CrossCall.lean` | **✓ PROVED** |
| **`split_effect_composition` (Theorem 5)** | `VCD/CrossCall.lean` | **✓ PROVED** |
| **`provenance_path_composition` (Theorem 6)** | `VCD/CrossCall.lean` | **✓ PROVED** |

**Theorem 3 — exact claim.** Given (a) a proof PROVEN for a tool's
`(schema, P)`, (b) a call in that tool's modelled call language
`SchemaLang schema`, and (c) a gate that accepts the call under token `t`, the
theorem concludes both that the call satisfies `P` (via the `prover_soundness`
axiom — which is load-bearing) **and** that it satisfies `t.constraints` (via
`gate_soundness`). It does **not** mechanise the binding that the *cited* proof
pertains to this tool's `(schema, P)`: operationally the gate's strict proof
mode binds `policy_proof_hash` to the proof's grammar/policy hashes
(`capability.py::_check_proof_binding`); the Lean model takes "the proof is for
this `(schema, P)`" as a hypothesis rather than re-deriving it from hashes.

**Theorem 4 - exact claim.** Given two tokens `t1`, `t2` with constraint
policies `P1`, `P2` and ONE call that the gate ALLOWS under each token
(`gate_soundness` discharged twice), the call satisfies the meet
`P1 ⊓ P2` (`Policy.meet`, `Basic.lean`). Chaining two valid tokens against a
single call therefore enforces the AND of both constraint sets, never the OR:
the deputy cannot reach an action outside the intersection of the two scopes
by splitting authority across tokens. NOT covered (honest gaps): splitting one
intended effect across two different calls (the runtime review and receipt
layer is trusted for that); `forbidden_combos` (absent from
`satisfies_field`, inherited from the gate model); and both gate checks are
taken at one clock instant. Uses no new axioms or sorrys. A first mechanised
fragment of the split-effect gap now exists: Theorems 5 and 6, below.

**Theorem 5 - exact claim.** Given (a) two gate-allowed calls c1, c2 under
tokens t1, t2, recorded by the receipt layer (`receiptOf` issues a receipt
exactly when the gate allows, fail-closed), and (b) both chain checks
passing (each new receipt composes onto the receipts before it through
`chainCheck` and the composed effect stays under every cumulative ceiling of
the chain policy E), the theorem concludes: (a) per-call, each call satisfies
its own token's constraints over its own field list (discharged through
`receiptOf_sound`, i.e. through `gate_soundness`); (b) cross-call, in receipt
terms, the composite effect of the two calls (contributions composed by the
running total across the receipt chain) admits E; and (c) cross-call, in
call-argument terms, the same composite computed from the calls' own
arguments admits E. This is the split-effect scenario PR 253 named as
trusted-but-not-mechanised. NOT covered: cumulative ceilings are the only
cross-call constraint kind; nothing binds hop 2's token to hop 1's; two gate
checks remain at one clock instant. Uses no new axioms or sorrys.

**Theorem 6 - exact claim.** Given a path of hops h1..hn and a receipt
assignment R such that the layer issued every record (`hopReceipt K h =
some (R h)` for each hop), every node compositing onto its predecessors
(inductive `Path`, newest first), every chain check along the path passing
(inside `Path`), and E well-formed (ceilings nonnegative), the path preserves
BOTH invariants: (a) gate soundness, node by node, every recorded call
satisfies its cited token's constraints over its own field list; and (b)
chain-wide, the composite total of the ENTIRE path admits E. This is the
first provenance-graph composition lemma; the graph is so far a linear path
(a spine), not a branching DAG. Uses no new axioms or sorrys.

**Separation result - exact claim.** Per-call satisfaction (the usable
content of `gate_soundness`) does NOT entail the cross-call cumulative
bound: there exist a policy p and call arguments a1, a2 with
`satisfiesArgs p a1 [f] = true`, `satisfiesArgs p a2 [f] = true`,
`p.max_value f = some cap` and `E.max_total_value f = some cap`, yet
400 + 400 = 800 exceeds cap = 500, so the composite admits-claim fails
(`per_call_satisfaction_insufficient`). The chain-layer check `chainCheck`
is exactly the missing premise, which is what makes the composition relation
load-bearing rather than vacuous. Uses no new axioms or sorrys.

## Trust assumptions

The mechanisation establishes correctness of the **data model and algorithms**. It does not mechanise:

- **Ed25519 bit-level correctness** (treated as a trusted oracle via `opaque Ed25519Verify`; see [BHB22] for an independently verified specification).
- **SHA-256 bit-level correctness** (`opaque Sha256Hex`).
- **Canonical-JSON encoding correctness** (`opaque canonBody`).
- **Z3 solver soundness** for the supported fragment (treated as a trusted oracle via the `prover_soundness` axiom; cross-validation against CVC5 recommended for production).
- **The receipt layer's own record-keeping** (`CrossCall.lean`): that recorded receipts match real calls and compose in causal order is inherited runtime trust; the Lean model takes receipts as given once the gate allows.
- **The Python implementation's faithfulness to this Lean model** (we maintain structural correspondence; mechanising the bridge would be a separate paper using PyLean or equivalent).

## How to reproduce

```bash
curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none
source ~/.elan/env
cd paper/lean
elan toolchain install leanprover/lean4:v4.10.0
elan default leanprover/lean4:v4.10.0
lake update           # ~5 min, fetches Mathlib + transitive deps
lake exe cache get    # ~2 min, downloads precompiled Mathlib .olean files
lake build            # ~30 sec
```

Expected output: every file builds, no warnings, no errors.

First-time disk usage: ~4.5 GB (Mathlib is large).

## Line counts

```
$ wc -l VCD/*.lean
  100 VCD/Basic.lean
  105 VCD/Attenuation.lean
  131 VCD/Composition.lean
  143 VCD/ConfusedDeputy.lean
  349 VCD/CrossCall.lean
   95 VCD/Gate.lean
  923 total
```

923 lines of Lean for the data model plus six soundness theorems plus the
cross-call receipt layer. Compact because Mathlib's lattice and decidability infrastructure does the heavy lifting.




## Notes from the iteration

Three sessions of compiler iteration on a Linux VM, totalling perhaps an hour of wall-clock time. Key tactic insights:

1. **`meet_tighter`'s inner cases** (allowed_values, max_value, min_value): after `unfold`, use `dsimp only` to expose the match, then `rw [hq]` to substitute the *first* scrutinee (`Tighter (meet p q) p`'s hypothesis is about the outer `p`, not `q`), then `cases _hq2 : q.X` to split on the second scrutinee. Commit the witness via `⟨…, rfl, …⟩` before the case split.

2. **`attenuation_soundness`**: `split_ifs at h` targets `if` specifically (unlike `split at h` which picks the innermost `match`). The `else` branch (`none = some c`) auto-closes, leaving only the `then` branch.

3. **`gate_soundness`**: explicit nested `by_cases` on each of the six guards. Each "negative" branch (where the guard's condition is true and the gate denies) is closed by `simp [h_<name>] at h` which substitutes and reduces to a contradiction with `h : .deny _ = .allow`. The final positive branch packs the six conclusions into the conjunction. After `cases hk : K t.key_id` the goal's `K t.key_id` is substituted, so the existential uses `rfl` rather than the equation.

4. **`tighter_implies_satisfies_field`**: `simp only [satisfies_field, Bool.and_eq_true, decide_eq_true_eq]` decomposes both the hypothesis and the goal into a four-way conjunction, after which each subgoal applies one of the six conjuncts of the `Tighter` relation. Compiled on the first try.

The structural decision to use `Bool` (not `Prop`) for the executable parts of the system and to parameterise satisfaction over a finite `fields : List FieldName` (rather than `∀ f : String`) was load-bearing — without it, `Decidable` synthesis blocked the proofs entirely.
