# Acceptance Contract — Alpha-C60: Native 8-Way 32-bit Loop Vectorization & Full-Stack 256-bit AVX2 Emission

## 1. Objective & Scope
Completes the end-to-end 32-bit vectorization pipeline in `OmniCompiler`:
1. **`LoopVectorizerPass._rewrite_struct_array_store_4x` ([`compiler/loop_vectorizer.py`](file:///F:/repository-compiler/compiler/loop_vectorizer.py)):**
   - Automatically strip-mines pure 32-bit (`i32`/`u32`/`f32`, stride 4) loops at width **8** (`eff_n >> 3` chunks + `eff_n % 8` scalar tail) with 8-lane alias disjointness guards.
   - Emits 8 contiguous 32-bit `store_off`s per vector chunk, unlocking native 256-bit AVX2 (`vpaddd`, `vmulps`, `vmovdqu ymm`) directly from high-level Python loops, alongside dual 128-bit NEON (`V0.4S`) and dual WebAssembly `v128` (`i32x4`/`f32x4`).

## 2. Acceptance Criteria
| ID | Requirement | Verification Method | Status |
|---|---|---|---|
| AC-C60-01 | Strip-mine 32-bit `i32`/`f32` loop 8-way, prove Z3 memory safe, emit AVX2 `vpaddd`/`vmulps` & verify parity | `test_01_native_8way_32bit_loop_emits_avx2_z3_safe_and_parity` | PASS |
| AC-C60-02 | Quad-ISA parity (x86-64 AVX2, ARM64 NEON Unicorn, Wasmtime `v128`, LLVM O3) on 8-way 32-bit loop | `test_02_quad_isa_parity_8way_32bit_loop` | PASS |
| AC-C60-03 | Full `OmniRepoCompiler` E2E PE64 Native, LLVM O3 PE64, and WSL2 Linux ELF64 executables | `test_03_omnirepo_e2e_8way_32bit_avx2_executable` | PASS |
