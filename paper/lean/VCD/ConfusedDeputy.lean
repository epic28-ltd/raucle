/-
  Theorem 4 — Confused-Deputy Conjunction (multi-token chaining bound).

  Scope (read this before citing the theorem): the confused-deputy scenario
  modelled here is an agent holding TWO valid capability tokens for the same
  tool with different constraint policies (t1.constraints = P1, t2.constraints
  = P2). If one and the same call passes the gate under BOTH tokens — the
  strongest chaining position the deputy can occupy for that call — the
  theorem shows the call satisfies the LATTICE MEET `P1 ⊓ P2` (see
  `Basic.lean`): every constraint of either token is enforced. Chaining
  therefore yields AND-composition of constraints, never OR-composition: the
  deputy cannot reach an action outside the intersection of the two scopes by
  splitting it across tokens.

  What this theorem does NOT cover (honest scope, see README.md):
  - Splitting one intended EFFECT across two DIFFERENT calls (call1 under t1,
    call2 under t2) is only bound per-call: each call satisfies its own
    token's constraints (via `gate_soundness`). That no cross-call
    combination exceeds the union of individual scopes is enforced by the
    runtime review/receipt layer, not mechanised here.
  - `forbidden_combos` is not part of `satisfies_field` (see `Gate.lean`) and
    so is out of scope for this theorem too.
  - Both gate checks are taken at the same clock instant `now`.
-/

import VCD.Basic
import VCD.Gate

namespace VCD

/-- Per-field: satisfying two policies individually implies satisfying their
    meet (the tightest policy enforcing both). -/
theorem satisfies_field_meet
    (p q : Policy) (f : FieldName) (v : Option Value)
    (hp : satisfies_field p f v = true)
    (hq : satisfies_field q f v = true) :
    satisfies_field (Policy.meet p q) f v = true := by
  cases v with
  | none =>
    simp only [satisfies_field, Policy.meet, decide_eq_true_eq] at hp hq ⊢
    intro hf
    rcases Finset.mem_union.1 hf with h | h
    · exact hp h
    · exact hq h
  | some w =>
    simp only [satisfies_field, Bool.and_eq_true, decide_eq_true_eq] at hp hq
    obtain ⟨⟨⟨hp_forb, hp_allow⟩, hp_max⟩, hp_min⟩ := hp
    obtain ⟨⟨⟨hq_forb, hq_allow⟩, hq_max⟩, hq_min⟩ := hq
    simp only [satisfies_field, Policy.meet, Bool.and_eq_true, decide_eq_true_eq]
    refine ⟨⟨⟨?_, ?_⟩, ?_⟩, ?_⟩
    · -- forbidden: w avoids the union of both forbidden sets
      intro hf
      rcases Finset.mem_union.1 hf with h | h
      · exact hp_forb h
      · exact hq_forb h
    · -- allowed_values: the meet's allowed set is the intersection;
      -- membership in it follows from membership in either factor.
      cases hpa : p.allowed_values f with
      | none =>
        cases hqa : q.allowed_values f with
        | none => rfl
        | some s =>
          simp only [hpa, hqa, decide_eq_true_eq] at hp_allow hq_allow ⊢
          exact hq_allow
      | some a =>
        cases hqa : q.allowed_values f with
        | none =>
          simp only [hpa, hqa, decide_eq_true_eq] at hp_allow hq_allow ⊢
          exact hp_allow
        | some b =>
          simp only [hpa, hqa, decide_eq_true_eq] at hp_allow hq_allow ⊢
          exact Finset.mem_inter.2 ⟨hp_allow, hq_allow⟩
    · -- max_value: n is below both bounds, hence below their min.
      cases hw : w with
      | num n =>
        cases hpm : p.max_value f with
        | none =>
          cases hqm : q.max_value f with
          | none => simp only [hw, hpm, hqm, decide_eq_true_eq] at hp_max hq_max ⊢
          | some b =>
            simp only [hw, hpm, hqm, decide_eq_true_eq] at hp_max hq_max ⊢
            exact hq_max
        | some a =>
          cases hqm : q.max_value f with
          | none =>
            simp only [hw, hpm, hqm, decide_eq_true_eq] at hp_max hq_max ⊢
            exact hp_max
          | some b =>
            simp only [hw, hpm, hqm, decide_eq_true_eq] at hp_max hq_max ⊢
            exact le_min_iff.2 ⟨hp_max, hq_max⟩
      | str _ =>
        simp only [hw] at hp_max hq_max ⊢
      | bool _ =>
        simp only [hw] at hp_max hq_max ⊢
    · -- min_value (symmetric): n is above both bounds, hence above their max.
      cases hw : w with
      | num n =>
        cases hpm : p.min_value f with
        | none =>
          cases hqm : q.min_value f with
          | none => simp only [hw, hpm, hqm, decide_eq_true_eq] at hp_min hq_min ⊢
          | some b =>
            simp only [hw, hpm, hqm, decide_eq_true_eq] at hp_min hq_min ⊢
            exact hq_min
        | some a =>
          cases hqm : q.min_value f with
          | none =>
            simp only [hw, hpm, hqm, decide_eq_true_eq] at hp_min hq_min ⊢
            exact hp_min
          | some b =>
            simp only [hw, hpm, hqm, decide_eq_true_eq] at hp_min hq_min ⊢
            exact max_le_iff.2 ⟨hp_min, hq_min⟩
      | str _ =>
        simp only [hw] at hp_min hq_min ⊢
      | bool _ =>
        simp only [hw] at hp_min hq_min ⊢
/-- Argument-list level: both satisfied implies the meet is satisfied. -/
theorem satisfiesArgs_meet
    (p q : Policy) (args : CallArgs) (fields : List FieldName)
    (hp : Policy.satisfiesArgs p args fields = true)
    (hq : Policy.satisfiesArgs q args fields = true) :
    Policy.satisfiesArgs (Policy.meet p q) args fields = true := by
  unfold Policy.satisfiesArgs at hp hq ⊢
  rw [List.all_eq_true] at hp hq ⊢
  intro f hf
  exact satisfies_field_meet p q f (args f) (hp f hf) (hq f hf)

/-- **Theorem 4 — confused-deputy conjunction.** If one call is allowed by the
    gate under two distinct tokens (the deputy chaining both credentials
    against the same call), the call satisfies the meet of the two constraint
    policies. Chaining grants the INTERSECTION of scopes, never a union. -/
theorem confused_deputy_conjunction
    (K : TrustedIssuers) (t1 t2 : Token) (call : Call) (now : Int)
    (fields : List FieldName)
    (h1 : Gate.check K t1 call now fields = .allow)
    (h2 : Gate.check K t2 call now fields = .allow) :
    Policy.satisfiesArgs (Policy.meet t1.constraints t2.constraints)
      call.args fields = true := by
  have h1' := gate_soundness K t1 call now fields h1
  have h2' := gate_soundness K t2 call now fields h2
  exact satisfiesArgs_meet _ _ _ _ h1'.2.1 h2'.2.1

end VCD
