# Acceptance Contract — Alpha-C91 (PGO, Loop Rotation, SLP Vectorization & x86-64 Codegen)

## Scope
Close the remaining single-core codegen/optimizer gaps vs GCC `-O3`:
1. **`compiler/pgo_optimizer.py` (`ProfileGuidedOptimizer`)**: Deterministic SSA trace sampling producing block/edge frequencies, calibrating loop unrolling (`4x` vs `8x` for compact hot loops without divisions), and driving hot/cold `BlockLayoutPass`.
2. **`compiler/polyhedral_tiler.py` (`LoopUnrollPass`, `LoopRotationPass`, `SLPVectorizationPass`)**:
   - Empty latch block consolidation in `LoopUnrollPass`.
   - Preheader incremental scaled-IV PHI strength reduction (`mul(iv, C)` hoisted to preheader with `scaled_phi += u*C` inside loop).
   - `LoopRotationPass` transforming top-tested loops into bottom-tested guarded `do-while` loops with exit PHI reconciliation.
   - `SLPVectorizationPass` clustering independent isomorphic binary arithmetic instructions adjacent for packed SSE2/AVX2 lowering.
3. **`compiler/native_codegen.py` (`X64CodeGenerator`)**:
   - Flag-preserving zero immediate encoding `_x64_mov_ri(..., preserve_flags=True)` using `mov r64, 0` (`0xC7`).
   - Three-address `lea` instruction selection (`_x64_lea_add_imm`, `_x64_lea_add_rr`) avoiding destructive `mov + add`.
   - Inline self-loop back-edge emission with flag-preserving PHI copy fusion, eliminating cold `.L_edge_*` branch trampolines on rotated loops.
4. **`omni_repo_compiler.py`**: Wired `ProfileGuidedOptimizer`, `SLPVectorizationPass`, and `LoopRotationPass` into Stage 5a/5b.

## Verification Criteria
- `python -W error::ResourceWarning run_c91_tests.py` passes (5/5 tests OK).
- `AetherMind_Strict_Auditor.py run_c91_tests.py` returns `APROVADO`.
- `python -W error::ResourceWarning test_empirical_audit.py` returns `14/14 PASS`.
- Full unit test suite (`python -W default -m unittest discover -s tests -p "test_*.py"`) passes 100%.
- GitHub Actions 4/4 OS runners pass, and Ubuntu CI `benchmarks/industrial_top1_suite.py` shows `_polybench_gemm_kernel`, `_jacobi_1d_kernel`, and `_crypto_fnv_mix_kernel` competitive with or faster than `gcc -O3`.
