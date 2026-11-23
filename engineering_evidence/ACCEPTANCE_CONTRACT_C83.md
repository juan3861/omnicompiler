# Acceptance Contract - Alpha-C83: Alive2 UB/Poison, Pointer Disjointness & k-Induction

## Scope
Upgrade `validation/ssa_translation_validator.py` with:
1. Alive2-class UB/poison semantics (`add_nsw`, `add_nuw`, `sub_nsw`, `sub_nuw`, `mul_nsw`, `mul_nuw`, `sdiv_exact`, `udiv_exact`, `shl_nsw`, `shl_nuw`, `freeze`, division-by-zero / `INT64_MIN/-1` UB, branch-on-poison UB, out-of-bounds `alloca` UB) via `verify_refinement` and `enable_ub_poison=True`.
2. Explicit `QF_ABV` `noalias` pointer base disjointness (`enable_pointer_disjointness=True` / `fn.noalias_params`).
3. Unbounded *k*-induction (`_verify_k_inductive_loop_equivalence`, `max_k_induction >= 2`) solving loop bisimulation where 1-induction fails due to multi-step warmup/lag state synchronization.

## Empirical Gates
- `python -W error::ResourceWarning run_c83_tests.py` passes 100% with zero warnings.
- `python F:\AetherMind_Apotheosis_Final\aethermind_apotheosis\AetherMind_Strict_Auditor.py run_c83_tests.py` returns `APROVADO`.
- `python -W error::ResourceWarning test_empirical_audit.py` passes `14/14`.
- `python -W default -m unittest discover -s tests -p "test_*.py"` passes 100%.
