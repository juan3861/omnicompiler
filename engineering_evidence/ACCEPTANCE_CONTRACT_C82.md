# Acceptance Contract — Alpha-C82 (4x Scalar Loop Unrolling, Strength Reduction, Codegen Fusion & Pre-IRC DAG Scheduling)

## Scope
1. `compiler/native_codegen.py`:
   - `_schedule_basic_block_instructions`: Pre-allocation Critical-Path DAG List Scheduler preserving RAW dependencies and fused `cmp_* + br_cond` pairs.
   - `X64CodeGenerator`: Imm32/reg-direct ALU (`_x64_alu_ri32`, `_x64_imul_rri32`), `inlined_consts` dead materialization bypass, `cmp_* + br_cond` macro-op fusion with fallthrough inversion, inline PHI edge copies, and Hybrid Register+Spill mode.
   - `Arm64CodeGenerator`: `SMULH` + power-of-2 bit-shift reciprocal division eliminating `SDIV` for constant divisors.
2. `compiler/regalloc_graph_coloring.py`: Added `ignore_vars` support in `IteratedRegisterCoalescingAllocator.allocate` so imm32-foldable constants consume zero register pressure.
3. `compiler/polyhedral_tiler.py`: Upgraded `LoopUnrollPass` with physical 4x scalar loop unrolling (`_try_physical_unroll_scalar_loop`), induction multiplication strength reduction, and scalar remainder tail loops.
4. `omni_repo_compiler.py`: Invoked `SCEVAnalyzer` before `ThinLTOOptimizer.build_function_summary` so collapsed kernels satisfy multi-block inlining thresholds cleanly (`thin_lto_inlines: 3/3`).
5. `tests/test_alpha_c82_unroll_strength_scheduling.py` & `run_c82_tests.py`: Automated verification gate.

## Verification Gates
- `run_c82_tests.py -W error::ResourceWarning`: `5/5 OK`.
- `AetherMind_Strict_Auditor.py run_c82_tests.py`: `APROVADO`.
- `test_empirical_audit.py -W error::ResourceWarning`: `14/14 PASSED`.
- Full `unittest discover -s tests -p "test_*.py"`: `100% OK`.
- GitHub Actions 4-runner CI (`ubuntu-latest`, `windows-latest`, `macos-latest`, `ubuntu-24.04-arm`): `success`.
