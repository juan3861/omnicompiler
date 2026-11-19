# ACCEPTANCE CONTRACT — Alpha-C54: Strided Forward Loops, Reverse Countdown Loops & 4-Lane 32-bit Packed SSE/SSE2 Hardware SIMD

## 1. Executive Summary
**Alpha-C54** expands `OmniCompiler` across both affine loop auto-vectorization (`compiler/loop_vectorizer.py`) and 4-lane 32-bit x86-64 hardware SIMD emission (`compiler/native_codegen.py`):

1. **Strided Forward Loops (`i = start; while i < n: ... i += S`) & Non-Zero Start Vectorization**:
   - Generalizes `_match_zero_based_unit_loop` to canonicalize forward loops starting at arbitrary constant lower bounds `start_i >= 0` with constant steps `step_i >= 1` (power-of-2 steps $S \in \{1, 2, 4, 8\}$ for symbolic dynamic bounds, and arbitrary integer steps $S \ge 1$ for compile-time constant bounds).
   - Substitutes the affine index transformation $i(k) = \text{start\_i} + k \cdot \text{step\_i}$ directly into all `load_off` and `store_off` specifications ($\text{eff\_boff} = \text{boff} + \text{start\_i} \cdot \text{stride}$, $\text{eff\_stride} = \text{step\_i} \cdot \text{stride}$) as well as DAG references to `i_var`.
   - Emits an overflow-proof dynamic trip-count computation (`is_pos = cmp_gt(bound_op, start_i - bound_delta)`, `eff_n = select(is_pos, (bound_op + bound_delta - start_i + step_i - 1) >> p, 0)`) that is proven memory-safe by Z3 64-bit bit-vector bi-abduction (`BiAbductionVerifier`) without 64-bit signed wraparound counterexamples.

2. **Reverse Countdown Loops (`i = n - 1; while i >= L: ... i -= 1` and `i = C; while i >= L: ... i -= S`)**:
   - Canonicalizes both dynamic reverse countdown loops (`cmp_gt` / `cmp_ge` with `i -= 1` starting at `n - c` or `n`) and constant-start strided countdown loops (`i = C; while i >= L: ... i -= S`) into ascending canonical iteration spaces with positive memory strides, preserving runtime interval alias guards and enabling 128-bit SSE2 contiguous store fusion.

3. **4-Lane 32-bit Packed x86-64 SSE/SSE2 Hardware SIMD Emission (`X64CodeGenerator`)**:
   - Fuses 4 consecutive 4-byte (`i32`, `u32`, `f32`) `store_off` instructions at contiguous `+4, +8, +12` byte offsets (`_are_contiguous_4b_quad`):
     - **Full 4-Lane 128-bit SIMD Load + ALU + Store**: Emits `movdqu xmm0, [r11]` (`f3 41 0f 6f 03`), `movdqu xmm1, [r11]` (`f3 41 0f 6f 0b`), packed 4-lane 32-bit SSE/SSE2 ALU (`paddd` `66 0f fe c1`, `psubd` `66 0f fa c1`, `pand` `66 0f db c1`, `por` `66 0f eb c1`, `pxor` `66 0f ef c1`, `addps` `0f 58 c1`, `subps` `0f 5c c1`, `mulps` `0f 59 c1`), and `movdqu [r11], xmm0` (`f3 41 0f 7f 03`).
     - **General 4-Lane 32-bit Scalar-to-Vector Pack**: Packs 4 arbitrary 32-bit integer or `cvtsd2ss`-narrowed float values into `xmm0` via `punpckldq xmm0, xmm1` (`66 0f 62 c1`), `punpckldq xmm1, xmm2` (`66 0f 62 ca`), `punpcklqdq xmm0, xmm1` (`66 0f 6c c1`), and stores 16 bytes in one `movdqu [r11], xmm0` (`f3 41 0f 7f 03`).

---

## 2. Acceptance Criteria & Verification Matrix

| ID | Criterion | Component | Verification Method | Status |
| :--- | :--- | :--- | :--- | :--- |
| **AC-54.1** | Strided (`i += 2`, `i += 4`) and non-zero start (`i = 2`) loops for stores and multi-reductions pass Z3 bi-abduction and match Native PE64 & LLVM O3 | `compiler/loop_vectorizer.py` | `test_01_strided_and_nonzero_start_reductions_and_stores_z3_and_parity` | **PROVADO** |
| **AC-54.2** | Reverse countdown loops (`i = n - 1; while i >= 0: i -= 1` and `i = 30; while i >= 2: i -= 2`) pass Z3 bi-abduction and match Native PE64 & LLVM O3 | `compiler/loop_vectorizer.py` | `test_02_reverse_countdown_loops_dynamic_and_constant_unrolled_and_stripmined` | **PROVADO** |
| **AC-54.3** | Physical 4-lane 32-bit SSE/SSE2 opcodes (`paddd`, `addps`, `mulps`, `punpckldq`, `punpcklqdq`, `movdqu`) emitted and executed | `compiler/native_codegen.py` | `test_03_native_codegen_32bit_4lane_packed_sse_sse2_hardware_emission_and_execution` | **PROVADO** |
| **AC-54.4** | Live Wasmtime linear-memory roundtrip for strided store + reverse countdown reduction | `compiler/wasm_codegen.py`, `compiler/loop_vectorizer.py` | `test_04_live_wasmtime_strided_and_reverse_loops_roundtrip` | **PROVADO** |
| **AC-54.5** | End-to-end `OmniRepoCompiler` executables across Native PE64, LLVM O3 PE64, and WSL2 Linux ELF64 | `compiler/repo_compiler.py` | `test_05_omnirepo_e2e_strided_reverse_and_32bit_sse2_executable` | **PROVADO** |
| **AC-54.6** | Zero regressions across full test suite (`285` tests) and Strict Empirical Auditor approval | `tests/` | `AetherMind_Strict_Auditor.py run_c54_tests.py` & `unittest discover tests` | **PROVADO** |
