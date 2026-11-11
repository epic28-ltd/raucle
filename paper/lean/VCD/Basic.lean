/-
  Verified Capability Discipline — data model.
  Mirrors the runtime types defined in `raucle/capability.py`.
-/

import Mathlib.Data.Finset.Basic
import Mathlib.Order.Lattice

namespace VCD

abbrev FieldName := String

inductive Value where
  | str  : String → Value
  | num  : Int → Value
  | bool : Bool → Value
deriving DecidableEq, Repr

structure Policy where
  forbidden_values  : FieldName → Finset Value := fun _ => ∅
  allowed_values    : FieldName → Option (Finset Value) := fun _ => none
  max_value         : FieldName → Option Int := fun _ => none
  min_value         : FieldName → Option Int := fun _ => none
  required_present  : Finset FieldName := ∅
  forbidden_combos  : Finset (Finset FieldName) := ∅

namespace Policy

/-- Pointwise lattice meet — "tightening" — used by `attenuate`. -/
def meet (p q : Policy) : Policy where
  forbidden_values := fun f => p.forbidden_values f ∪ q.forbidden_values f
  allowed_values   := fun f =>
    match p.allowed_values f, q.allowed_values f with
    | none, none => none
    | some a, none => some a
    | none, some b => some b
    | some a, some b => some (a ∩ b)
  max_value := fun f =>
    match p.max_value f, q.max_value f with
    | none, none => none
    | some a, none => some a
    | none, some b => some b
    | some a, some b => some (min a b)
  min_value := fun f =>
    match p.min_value f, q.min_value f with
    | none, none => none
    | some a, none => some a
    | none, some b => some b
    | some a, some b => some (max a b)
  required_present := p.required_present ∪ q.required_present
  forbidden_combos := p.forbidden_combos ∪ q.forbidden_combos

/-- p is tighter-or-equal to q iff p constrains at least as much as q. -/
def Tighter (p q : Policy) : Prop :=
  (∀ f, q.forbidden_values f ⊆ p.forbidden_values f) ∧
  (∀ f s, q.allowed_values f = some s →
      ∃ s', p.allowed_values f = some s' ∧ s' ⊆ s) ∧
  (∀ f a, q.max_value f = some a → ∃ a', p.max_value f = some a' ∧ a' ≤ a) ∧
  (∀ f a, q.min_value f = some a → ∃ a', p.min_value f = some a' ∧ a ≤ a') ∧
  (q.required_present ⊆ p.required_present) ∧
  (q.forbidden_combos ⊆ p.forbidden_combos)

infix:50 " ⊑ " => Tighter

end Policy

abbrev AgentId := String

/-- Executable: is `child` a sub-scope of `parent` (equal, or prefix-extension)? -/
def AgentId.extendsB (child parent : AgentId) : Bool :=
  child = parent ∨ (parent.length > 0 ∧ child.startsWith (parent ++ "."))

abbrev Tool := String

structure Token where
  token_id          : String
  agent_id          : AgentId
  tool              : Tool
  constraints       : Policy
  issued_at         : Int
  not_before        : Int
  expires_at        : Int
  parent_id         : Option String := none
  policy_proof_hash : Option String := none
  issuer            : String
  key_id            : String
  signature         : String

abbrev CallArgs := FieldName → Option Value

structure Call where
  tool : Tool
  args : CallArgs

inductive GateDecision where
  | allow
  | deny (reason : String)
deriving Repr, DecidableEq

end VCD
