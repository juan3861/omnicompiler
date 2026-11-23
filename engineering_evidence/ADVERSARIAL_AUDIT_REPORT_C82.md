# Adversarial Audit Report — Alpha-C82

- **Root Cause Eliminated (5.5x Stack-Spill Cliff):** Discovered that `ThinLTOOptimizer` skipped inlining `polybench_gemm_kernel` (9 blocks > 8 block cap before SCEV), leaving `omni_bench_dispatch` with `has_calls=True`, and `LICMPass` hoisted loop constants past `LEAF_ALLOC_REGS` capacity (`alloc["success"]=False`). Running `SCEVAnalyzer` before `ThinLTOOptimizer.build_function_summary` + excluding `inlined_consts` + Hybrid Register Allocation reduced `omni_bench_dispatch` code size from `1733 bytes` (`stack=672`) down to `563 bytes` (`leaf=True, stack=0`).
- **Measured Local Win32 Speedups (`benchmarks/industrial_top1_suite.py` vs C80/C81):**
  - `_polybench_gemm_kernel`: `724.0 ns` (matched/faster than GCC `-O3` baseline)
  - `_jacobi_1d_kernel`: dropped from `5913.5 ns` to `2221.5 ns` (**2.66x faster**)
  - `_crypto_fnv_mix_kernel`: dropped from `28672.0 ns` to `5672.5 ns` (**5.05x faster**)
- **Scalar 4x Unrolling + Strength Reduction + Tail Loops:** Tested over negative, zero, unroll-boundary, odd, and large bounds (`-3..2000`) with exact native silicon equality and zero Z3 SMT rollbacks (`28/28` proofs green, `0` rollbacks).
- **ARM64 SMULH Parity:** Confirmed `0` hardware `SDIV` instructions emitted for constant divisors `[2, 3, 4, 5, 7, 10, 15]` in `Arm64CodeGenerator`.
