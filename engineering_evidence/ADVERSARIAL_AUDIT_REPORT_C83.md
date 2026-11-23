# Adversarial Audit Report - Alpha-C83

## Verified Countermeasures Against Silent Unsoundness
1. Wrapping `add` tightened to `add_nsw` is strictly refuted with signed-overflowing `(x, y)` witness.
2. Dropping `nsw` or proving `(x +_nsw 1) > x ==> 1` is proven sound under `verify_refinement`, whereas the wrapping counterpart is refuted at `x = INT64_MAX`.
3. Speculatively hoisting `sdiv` outside `y != 0` guard is refuted with `y = 0`; dropping `freeze` before returning potentially-poisoned result is refuted at `x = INT64_MAX`.
4. Memory load/store reordering across `p` and `q` is refuted by alias counterexample `p == q` when disjointness is off, and proven `unsat` when `enable_pointer_disjointness=True`.
5. Lag-register loop bisimulation where 1-induction fails is proven for all `N` via `PROVEN_K_INDUCTIVE_EQUIVALENT` (`k=2`), while a 1-step-delayed bug (`lag_add=8`) is still refuted with `n >= 2`.
