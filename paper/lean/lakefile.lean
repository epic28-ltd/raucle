import Lake
open Lake DSL

package vcd

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.10.0"

@[default_target]
lean_lib VCD where
  roots := #[`VCD.Basic, `VCD.Attenuation, `VCD.Gate, `VCD.Composition, `VCD.ConfusedDeputy, `VCD.CrossCall]
