# ACCEPTANCE CONTRACT — Alpha-C55: Fused Single-Pass Store + Multi-Reduction Vectorization & WebAssembly 128-bit SIMD (`v128`)

## 1. Executive Summary
**Alpha-C55** advances `OmniCompiler` across loop fusion/vectorization (`compiler/loop_vectorizer.py`) and WebAssembly 128-bit SIMD code generation (`compiler/wasm_backend.py`):

1. **Single-Pass Fused Vectorized Store + Multi-Reduction Pipelines**:
   - Unifies `_match_struct_array_store` and `_rewrite_struct_array_store_4x` with `_extract_reduction_specs_from_phis` so a single loop containing `1..8` `store_off` destinations and `1..6` simultaneous independent reductions (`add`, `fadd`, `mul`, `fmul`, `and`, `or`, `xor`, `smin`, `smax`, `fmin`, `fmax`, unconditional or conditionally masked via if-conversion) is vectorized into a single 4-lane strip-mined loop pass.
   - Implements **Same-Iteration Store-to-Load Forwarding**: When a loop writes `dst[i] = expr` and subsequently reads `dst[i]` in the same iteration (`tot += dst[i]`), the redundant `load_off` is forwarded directly from the stored SSA value (`forwarded_map`), preventing memory reload hazards and false self-aliasing.
   - Preserves **Runtime Pointer-Alias Safe Scalar Fallback**: When runtime pointer intervals overlap (`chunks_v = 0`), the 4 lane accumulators collapse cleanly through `merge_bb` to `init_val` and the scalar tail loop executes all $N$ stores and reductions sequentially.

2. **WebAssembly 128-bit Hardware SIMD (`v128`) Generation (`WasmBackend`)**:
   - Enhances `WasmBackend._ssa_function_to_wat_func` (`emit_inst_sequence`) to fuse contiguous 8-byte `store_off` pairs (`i64`, `u64`, `f64`) and contiguous 4-byte `store_off` quads (`i32`, `u32`, `f32`) into WebAssembly 128-bit SIMD instructions (`0xFD` binary prefix):
     - **Full 128-bit Load + Packed ALU + Store**: Emits `v128.load`, `v128.load`, packed 128-bit SIMD ALU (`i64x2.add`, `i64x2.sub`, `i64x2.mul`, `f64x2.add`, `f64x2.sub`, `f64x2.mul`, `f64x2.div`, `i32x4.add`, `i32x4.sub`, `i32x4.mul`, `f32x4.add`, `f32x4.sub`, `f32x4.mul`, `f32x4.div`, `v128.and`, `v128.or`, `v128.xor`), and `v128.store`.
     - **Scalar-to-`v128` Lane Packing**: Packs arbitrary 64-bit pairs via `i64x2.splat` / `f64x2.splat` + `replace_lane 1` and 32-bit quads via `i32x4.splat` / `f32x4.splat` + `replace_lane 1..3` followed by `v128.store`.

---

## 2. Acceptance Criteria & Verification Matrix

| ID | Criterion | Component | Verification Method | Status |
| :--- | :--- | :--- | :--- | :--- |
| **AC-55.1** | Single-pass dual store + triple reduction (`sum + max + min`) with store-to-load forwarding proves Z3 safe and matches Native & LLVM O3 | `compiler/loop_vectorizer.py` | `test_01_fused_store_and_multireduction_single_pass_z3_and_parity` | **PROVADO** |
| **AC-55.2** | If-converted fused store + conditional reductions and runtime overlapping pointer alias scalar fallback | `compiler/loop_vectorizer.py` | `test_02_if_converted_fused_store_and_conditional_reductions_plus_alias_fallback` | **PROVADO** |
| **AC-55.3** | WebAssembly 128-bit SIMD (`v128.load`, `v128.store`, `i64x2.add`, `i64x2.splat`, `i64x2.replace_lane 1`, `0xFD` prefix) emitted and executed in Wasmtime | `compiler/wasm_backend.py` | `test_03_wasm_128bit_v128_simd_emission_and_live_wasmtime_execution` | **PROVADO** |
| **AC-55.4** | Strided (`i += 2`) and reverse countdown (`i -= 1`) fused store + reduction loops | `compiler/loop_vectorizer.py` | `test_04_strided_and_reverse_fused_store_reduction_parity` | **PROVADO** |
| **AC-55.5** | End-to-end `OmniRepoCompiler` executables across Native PE64, LLVM O3 PE64, and WSL2 Linux ELF64 | `compiler/repo_compiler.py` | `test_05_omnirepo_e2e_fused_store_reduction_executable` | **PROVADO** |
