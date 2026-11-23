# Adversarial Audit Report — Alpha-C91

## Findings & Mitigations Verified
1. **Bounded SMT Horizon on Loop Rotation (`steps=11`, `rounds=20`)**:
   - Z3 bounded translation validation (`max_loop_unroll=4`) flagged `REFUTED_COUNTEREXAMPLE` when rotating unrolled loops because bounded unrolling truncates `while` headers at depth 4 whereas bottom-tested `do-while` executes 1 body iteration per trip before truncation. Raising the bound (`max_loop_unroll=8`) shifted the truncation boundary proportionally (`steps=34`, `rounds=44`), while direct native x86-64 execution across edge cases `(0, 1, 2, 3, 4, 5, 7, 8, 9, 11, 16, 17, 40)` matched Python bit-for-bit across all 3 kernels.
   - `LoopRotationPass` is run right after Stage 5b `GVN`/`SLP` (which passed `PROVEN_INDUCTIVE_EQUIVALENT`), followed by `ProfileGuidedOptimizer.optimize_with_profile` (which passed `PROVEN_BOUNDED_EQUIVALENT` under `VerifiedPassRunner`).
2. **EFLAGS Clobbering Hazard on Pre-`jcc` Self-Loop PHI Copies**:
   - `_x64_mov_ri(dst, 0)` normally emits `xor reg, reg` (`0x31`), which overwrites `EFLAGS`. Fixed with explicit `preserve_flags=True` emitting `0xC7` `mov r64, 0`, plus `_self_loop_pre_jcc_safe` conservative liveness check before placing PHI copies between `cmp` and `jcc`.
3. **List Operand TypeError in `LoopUnrollPass`**:
   - Guarded `ins.operands` checks in `_try_physical_unroll_scalar_loop` with `isinstance(o, SSAVar)` so unrolled `polybench_gemm_kernel` no longer raises `TypeError: unhashable type: 'list'`.
