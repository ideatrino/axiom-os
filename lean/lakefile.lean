import Lake
open Lake DSL

package axiom where
  name := "axiom"

require mathlib from git
  "https://github.com/leanprover-community/mathlib4" @ "master"

lean_lib Axiom where
  roots := #[`Axiom]
