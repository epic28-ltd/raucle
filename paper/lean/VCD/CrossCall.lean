/-
  Theorems 5 and 6: cross-call effect composition and provenance paths.

  Scope (read this before citing the theorems). Slice 1 (PR 253, Theorem 4)
  bound a two-token chain PER CALL and stated honestly that splitting one
  intended EFFECT across two DIFFERENT calls is enforced by the runtime
  review and receipt layer, not mechanised. This file mechanises the
  cumulative-bound fragment of exactly that layer:

  - `Receipt` and `receiptOf`: the provenance record of one allowed call.
    The layer issues a receipt exactly when the gate allows (fail-closed),
    and `receiptOf_sound` re-derives the `gate_soundness` conclusion for the
    recorded call, so each receipt carries the gate-soundness invariant.
  - `EffectPolicy`: a policy over a call CHAIN rather than a single call:
    a cumulative ceiling per numeric field across the whole chain.
  - `chainCheck`: the explicit call/effect-composition relation. A new
    receipt composes onto the accumulated older receipts through the
    running total, and the composed effect must stay under every
    cumulative ceiling. A call that passes its own gate can still fail
    this check (see `per_call_satisfaction_insufficient`), which is what
    makes the relation load-bearing rather than vacuous.
  - `Path`: an inductive provenance path: receipts composed one at a time,
    each passing `chainCheck` against all earlier receipts. Lists are
    NEWEST-FIRST (the head is the most recent call), because Lean lists
    grow at the head; totals are unaffected by the order (see
    `totalAcross_two_comm`).
  - Theorem 5 (`split_effect_composition`): the split-effect scenario from
    PR 253, mechanised end to end: two gated calls compose into a composite
    effect that admits the chain policy, in receipt terms AND in call
    argument terms.
  - Theorem 6 (`provenance_path_composition`): a path of receipts preserves
    BOTH the gate-soundness invariant (node by node) and the chain-wide
    cumulative bound (over the whole composed total).

  What remains out of scope (honest gaps, see README.md):
  - Paths are LINEAR (the spine of a provenance graph). Branching DAGs,
    where one receipt composes onto two parents, are future work.
  - `chainCheck` is checked against receipts the runtime layer itself
    recorded; that the layer records faithfully and in causal order is
    inherited trust, not proved here.
  - Two hops may cite different tokens; nothing binds the second hop's
    token to the first's (that is the attenuation story, Theorem 1).
  - `forbidden_combos` remains absent from `satisfies_field` (gate model
    gap, inherited from Theorem 2).
  - All gate checks remain at one clock instant, as in Theorems 2-4.
  - No new axioms are introduced; `prover_soundness` (Theorem 3's axiom)
    is not used, and no proof in this file is left open.
-/

import VCD.Basic
import VCD.Gate

namespace VCD

/-! ## Receipts: the provenance record of one allowed call -/

/-- The numeric part of a call's argument on a field: only a `.num` value
    contributes; a string, a bool, a missing field all contribute `0`. -/
def callContrib (a : CallArgs) (f : FieldName) : Int :=
  match a f with
  | some (Value.num n) => n
  | _ => 0

/-- Provenance receipt: the runtime layer's record of one allowed call.
    `args`/`fields` mirror the gated call; `ts` is the clock instant. -/
structure Receipt where
  token_id : String
  tool     : Tool
  args     : CallArgs
  fields   : List FieldName
  ts       : Int

/-- A receipt's numeric contribution on a field: exactly the numeric part
    of the recorded call's argument. -/
def Receipt.contrib (R : Receipt) (f : FieldName) : Int :=
  callContrib R.args f

/-- The running total a receipt list has contributed on a field. This is
    the effect composition of a chain; the empty chain contributes `0`. -/
def totalAcross (Rs : List Receipt) (f : FieldName) : Int :=
  Rs.foldr (fun R acc => R.contrib f + acc) 0

/-- Cumulative totals compose over list concatenation. -/
theorem totalAcross_append (Rs Ss : List Receipt) (f : FieldName) :
    totalAcross (Rs ++ Ss) f = totalAcross Rs f + totalAcross Ss f := by
  induction Rs with
  | nil => simp [totalAcross]
  | cons R Rs ih =>
      have ih' : totalAcross (Rs ++ Ss) f = totalAcross Rs f + totalAcross Ss f := ih
      show Receipt.contrib R f + totalAcross (Rs ++ Ss) f =
        (Receipt.contrib R f + totalAcross Rs f) + totalAcross Ss f
      rw [ih']
      omega

/-- Totals are insensitive to receipt order (a two-element special case,
    stated because the path notation is newest-first). -/
theorem totalAcross_two_comm (r1 r2 : Receipt) (f : FieldName) :
    totalAcross [r1, r2] f = totalAcross [r2, r1] f := by
  simp only [totalAcross, List.foldr_cons, List.foldr_nil]
  omega

/-! ## Effect policies over chains and the composition relation -/

/-- Policy over a call CHAIN, beyond the per-call `Policy` of `Basic.lean`:
    a cumulative ceiling per numeric field across the whole chain. -/
structure EffectPolicy where
  max_total_value : FieldName → Option Int

namespace EffectPolicy

/-- Well-formedness: ceilings are nonnegative, so the empty chain (total
    `0`) respects them trivially. -/
def WellFormed (E : EffectPolicy) : Prop :=
  ∀ f cap, E.max_total_value f = some cap → 0 ≤ cap

/-- A total (field → running total) admits `E` if it stays under every
    cumulative ceiling. -/
def admits (E : EffectPolicy) (tot : FieldName → Int) : Prop :=
  ∀ f cap, E.max_total_value f = some cap → tot f ≤ cap

end EffectPolicy

/-- **The call/effect-composition relation.** A new receipt `R` composes
    onto the accumulated receipts `Rs`: on every field the composed effect
    is the running total plus `R`'s own contribution, and that composed
    effect must stay under every cumulative ceiling in `E`. The layer runs
    this check in addition to the per-call gate: a call whose own gate
    check allows can still be refused by the chain layer. -/
def chainCheck (E : EffectPolicy) (Rs : List Receipt) (R : Receipt) : Prop :=
  ∀ f cap, E.max_total_value f = some cap →
    R.contrib f + totalAcross Rs f ≤ cap

/-! ## Receipt issuance re-ifies the gate-soundness invariant -/

/-- The runtime layer issues a receipt exactly when the gate allows the
    recorded call (fail-closed). -/
def receiptOf (K : TrustedIssuers) (t : Token) (c : Call)
    (now : Int) (fs : List FieldName) : Option Receipt :=
  if Gate.check K t c now fs = GateDecision.allow then
    some { token_id := t.token_id, tool := c.tool, args := c.args,
           fields := fs, ts := now }
  else none

/-- The gate-soundness invariant, reified as a property of a receipt: a
    receipt issued by the layer for a gated call satisfies the recorded
    token's constraints over the recorded field list, and the record
    faithfully mirrors the call. This is the per-call content of
    `gate_soundness`, transported to the layered record. -/
theorem receiptOf_sound
    (K : TrustedIssuers) (t : Token) (c : Call) (now : Int) (fs : List FieldName)
    (r : Receipt)
    (h : receiptOf K t c now fs = some r) :
    r.token_id = t.token_id ∧
    r.args = c.args ∧
    r.fields = fs ∧
    Policy.satisfiesArgs t.constraints c.args fs = true := by
  unfold receiptOf at h
  split_ifs at h with hallow
  · obtain rfl := Option.some.inj h
    refine ⟨rfl, rfl, rfl, ?_⟩
    exact (gate_soundness K t c now fs hallow).2.1

/-- A receipt's contribution equals the numeric part of the recorded CALL's
    argument: the bridge from receipt arithmetic to call arguments. -/
theorem contrib_eq_callArg
    (K : TrustedIssuers) (t : Token) (c : Call) (now : Int) (fs : List FieldName)
    (r : Receipt)
    (h : receiptOf K t c now fs = some r) (f : FieldName) :
    r.contrib f = callContrib c.args f := by
  have hs := receiptOf_sound K t c now fs r h
  obtain ⟨_, h_args, _, _⟩ := hs
  simp only [Receipt.contrib, callContrib, ← h_args]

/-! ## Provenance paths and Theorem 6 -/

/-- One hop of a provenance path: the gated call with its token and gate
    context. -/
structure Hop where
  token  : Token
  call   : Call
  fields : List FieldName
  now    : Int

/-- The layer records a hop's receipt exactly when the gate allows. -/
def hopReceipt (K : TrustedIssuers) (h : Hop) : Option Receipt :=
  receiptOf K h.token h.call h.now h.fields

/-- An inductive provenance path: a chain of receipts composed one at a
    time, NEWEST-FIRST (the head is the most recent call). Building the
    path by `cons` checks the newest receipt against the accumulated older
    receipts via `chainCheck`. -/
inductive Path (E : EffectPolicy) : List Receipt → Prop where
  | nil : Path E []
  | cons (R : Receipt) (Rs : List Receipt) :
      Path E Rs → chainCheck E Rs R → Path E (R :: Rs)

/-- **Theorem 6, part (b).** A well-formed provenance path admits its own
    composited total: the cumulative bound holds over the WHOLE chain,
    a property no single per-call check can establish. -/
theorem Path.admits {E : EffectPolicy} {Rs : List Receipt}
    (h : Path E Rs) (hWF : EffectPolicy.WellFormed E) :
    EffectPolicy.admits E (totalAcross Rs) := by
  induction h with
  | nil =>
      intro f cap hcap
      exact hWF f cap hcap
  | cons _R _Rs _path _chk _ih =>
      intro f cap hcap
      exact _chk f cap hcap

/-- **Theorem 6 - provenance-path composition.** A chain of receipts, each
    issued by the layer for a gate-allowed call (the gate-soundness
    invariant holds at every node, via `receiptOf_sound`), and each
    composing onto its predecessors through `chainCheck` (the explicit
    effect-composition relation), preserves BOTH invariants across the
    whole path:

    (a) gate soundness, node by node: every recorded call satisfies its
        cited token's constraints over its own field list; and
    (b) the cross-call, chain-wide cumulative bound:
        `EffectPolicy.admits` over the composed total of the ENTIRE path.

    (b) exists only because receipts compose: per-call soundness alone
    does not see it. -/
theorem provenance_path_composition
    (K : TrustedIssuers) (E : EffectPolicy)
    (hs : List Hop) (R : Hop → Receipt)
    (hIssued : ∀ h ∈ hs, hopReceipt K h = some (R h))
    (hPath : Path E (hs.map R))
    (hWF : EffectPolicy.WellFormed E) :
    EffectPolicy.admits E (totalAcross (hs.map R)) ∧
    ∀ h ∈ hs, Policy.satisfiesArgs h.token.constraints h.call.args h.fields = true := by
  refine ⟨Path.admits hPath hWF, ?_⟩
  intro h hh
  have hrec : receiptOf K h.token h.call h.now h.fields = some (R h) := hIssued h hh
  exact (receiptOf_sound K h.token h.call h.now h.fields (R h) hrec).2.2.2

/-! ## Theorem 5: the split-effect scenario from PR 253 -/

/-- **Theorem 5 - split-effect cross-call composition.** The scenario
    Theorem 4 deliberately left to the trusted runtime layer: the deputy
    splits ONE intended effect across TWO different calls, c1 gated under
    t1 and c2 gated under t2 (the per-call level, discharged here through
    `receiptOf_sound`, i.e. through `gate_soundness`). The layer records
    both allowed calls as receipts and runs the chain check against the
    receipts so far. If both chain checks pass, the theorem concludes:

    (a) per-call bounds: c1 satisfies t1.constraints and c2 satisfies
        t2.constraints over their own field lists;
    (b) cross-call bound (new), receipt terms: the composite effect, both
        calls' contributions composed by the running total across the
        receipt chain, admits the chain policy E; and
    (c) cross-call bound (new), call-argument terms: the same composite
        computed from the calls' own arguments admits E.

    (b)/(c) are properties NEITHER call can establish alone: they are
    exactly the cross-call bound PR 253 named as trusted-but-not-mechanised. -/
theorem split_effect_composition
    (K : TrustedIssuers) (t1 t2 : Token) (c1 c2 : Call) (now : Int)
    (fs1 fs2 : List FieldName) (E : EffectPolicy) (r1 r2 : Receipt)
    (h1 : receiptOf K t1 c1 now fs1 = some r1)
    (h2 : receiptOf K t2 c2 now fs2 = some r2)
    (hchk1 : chainCheck E [] r1)
    (hchk2 : chainCheck E [r1] r2)
    (hWF : EffectPolicy.WellFormed E) :
    Policy.satisfiesArgs t1.constraints c1.args fs1 = true ∧
    Policy.satisfiesArgs t2.constraints c2.args fs2 = true ∧
    EffectPolicy.admits E (totalAcross [r1, r2]) ∧
    EffectPolicy.admits E (fun f => callContrib c1.args f + callContrib c2.args f) := by
  have hsat1 := (receiptOf_sound K t1 c1 now fs1 r1 h1).2.2.2
  have hsat2 := (receiptOf_sound K t2 c2 now fs2 r2 h2).2.2.2
  -- The two-hop path (newest first: r2 on top of r1) is certified by the
  -- two chain checks; its composite total then admits E by Theorem 6's
  -- composition lemma.
  have hpath : Path E [r2, r1] :=
    Path.cons r2 [r1] (Path.cons r1 [] Path.nil hchk1) hchk2
  have hb : EffectPolicy.admits E (totalAcross [r2, r1]) := Path.admits hpath hWF
  refine ⟨hsat1, hsat2, ?_, ?_⟩
  · -- (b): same total, list written oldest-first
    intro f cap hcap
    have hbb := hb f cap hcap
    rw [totalAcross_two_comm] at hbb
    exact hbb
  · -- (c): the bridge from receipt arithmetic to call arguments
    intro f cap hcap
    have hbb := hb f cap hcap
    rw [totalAcross_two_comm] at hbb
    have e1 : r1.contrib f = callContrib c1.args f :=
      contrib_eq_callArg K t1 c1 now fs1 r1 h1 f
    have e2 : r2.contrib f = callContrib c2.args f :=
      contrib_eq_callArg K t2 c2 now fs2 r2 h2 f
    simp only [totalAcross, List.foldr_cons, List.foldr_nil] at hbb
    rw [e1, e2] at hbb
    show callContrib c1.args f + callContrib c2.args f ≤ cap
    omega

/-! ## Separation: per-call soundness does NOT see the cumulative bound -/

/-- A single-argument record used by the separation result: `amount` is 400. -/
private def sepArgs : CallArgs :=
  fun g => if g = "amount" then some (Value.num 400) else none

/-- The per-call policy for the separation result: a 500 cap on `amount`. -/
private def sepPol : Policy :=
  { max_value := fun g => if g = "amount" then some 500 else none }

/-- The chain policy for the separation result: a 500 cumulative ceiling
    on `amount`. -/
private def sepEff : EffectPolicy :=
  { max_total_value := fun g => if g = "amount" then some 500 else none }

private theorem sepArgs_amount : sepArgs "amount" = some (Value.num 400) := rfl

private theorem sepPol_amount : sepPol.max_value "amount" = some 500 := rfl

private theorem sepEff_amount : sepEff.max_total_value "amount" = some 500 := rfl

/-- One call within the per-call cap satisfies the per-call policy. -/
private theorem sepSat : Policy.satisfiesArgs sepPol sepArgs ["amount"] = true := by
  simp [Policy.satisfiesArgs, satisfies_field, sepArgs, sepPol]

/-- The receipt recorded for the separation result's first call. -/
private def sepRec : Receipt :=
  { token_id := "", tool := "", args := sepArgs, fields := ["amount"], ts := 0 }

/-- **Separation result.** Per-call satisfaction, the usable content of
    `gate_soundness`, does NOT entail the cross-call cumulative bound: two
    calls, EACH within the same per-call cap, jointly exceed it (400 + 400
    against a 500 ceiling). The refused operation is the chain-layer check
    `chainCheck`, which is precisely the extra premise Theorem 5 adds. This
    is why the composition relation is load-bearing and why PR 253 could
    not have stated a cross-call bound from per-call soundness alone. -/
theorem per_call_satisfaction_insufficient :
    ∃ (p : Policy) (a1 a2 : CallArgs) (E : EffectPolicy) (f : FieldName)
        (cap : Int) (r1 r2 : Receipt),
      Policy.satisfiesArgs p a1 [f] = true ∧
      Policy.satisfiesArgs p a2 [f] = true ∧
      p.max_value f = some cap ∧
      E.max_total_value f = some cap ∧
      ¬ EffectPolicy.admits E (totalAcross [r1, r2]) := by
  refine ⟨sepPol, sepArgs, sepArgs, sepEff, "amount", 500,
          sepRec, sepRec, sepSat, sepSat, sepPol_amount, sepEff_amount, ?_⟩
  intro h
  have h' := h "amount" 500 sepEff_amount
  simp only [totalAcross, List.foldr_cons, List.foldr_nil, Receipt.contrib,
    callContrib, sepRec, sepArgs_amount] at h'
  omega

end VCD
