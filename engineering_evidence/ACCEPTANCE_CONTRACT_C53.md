# ACCEPTANCE CONTRACT — Alpha-C53: Vectorized Min/Max Reductions & Direct x86-64 SSE2 128-bit SIMD Codegen

## 1. Executive Summary
**Alpha-C53** elevates `OmniCompiler` across both high-level loop vectorization (`compiler/loop_vectorizer.py`) and bare-metal x86-64 hardware code generation (`compiler/native_codegen.py`):

1. **Vectorized `min` / `max` Reductions (`smin`, `smax`, `fmin`, `fmax`)**:
   - Recognizes built-in `min(acc, val)` / `max(acc, val)` (`select(cmp, acc, val)`) and branch-flattened `if val < acc: acc = val` / `if val > acc: acc = val` patterns for both signed integers (`smin`, `smax` via `lt`, `le`, `gt`, `ge`) and IEEE-754 floats (`fmin`, `fmax` via `flt`, `fle`, `fgt`, `fge`).
   - Supports conditional/filtered `min`/`max` reductions (`if v > 0: mn = min(mn, v); mx = max(mx, v)`) via nested `select` discovery (`_classify_minmax_select`).
   - Exploits idempotency (`min(x, x) == x`, `max(x, x) == x`) to initialize all 4 strip-mined vector accumulator lanes (`acc_0..acc_3`) with the loop's initial accumulator value (`init_val`), eliminating sentinel overflow risks and ensuring exact results for any $N \ge 0$ (including $N < 4$).
   - Composes seamlessly with Alpha-C52 multi-accumulator fusion (`1..6` simultaneous reductions in one pass, e.g., fused `min + max + sum`).

2. **Direct x86-64 Hardware SSE2 128-bit SIMD Emission (`X64CodeGenerator`)**:
   - Tracks SSA definitions, integer constants (`blk_const_int`), and constant-offset pointer expressions (`add base, off` / `add idx, off` via `_are_contiguous_8b_offsets`) per basic block in `compiler/native_codegen.py`.
   - Fuses consecutive 8-byte `store_off` pairs (`i64`, `u64`, `f64`) targeting contiguous `+8` byte memory offsets (`off_1 == off_0 + 8`) into genuine 128-bit hardware SSE2 instructions:
     - **Paired 128-bit Vector Load + Packed 128-bit ALU + 128-bit Store**: When both stored values come from matching elementwise binary operations (`add`, `sub`, `and`, `or`, `xor`, `fadd`, `fsub`, `fmul`) whose `lhs` and `rhs` are contiguous 8-byte `load_off` pairs, emits `movdqu xmm0, [r11]` (`f3 41 0f 6f 03`), `movdqu xmm1, [r11]` (`f3 41 0f 6f 0b`), packed 128-bit SSE2 ALU (`paddq` `66 0f d4 c1`, `psubq` `66 0f fb c1`, `pand` `66 0f db c1`, `por` `66 0f eb c1`, `pxor` `66 0f ef c1`, `addpd` `66 0f 58 c1`, `subpd` `66 0f 5c c1`, `mulpd` `66 0f 59 c1`), and `movdqu [r11], xmm0` (`f3 41 0f 7f 03`).
     - **General Scalar-to-Vector 128-bit Pack + Store**: For arbitrary 8-byte values stored at contiguous `+8` offsets (constants, expressions, strided loads), packs both 64-bit lanes into `xmm0` via `movq xmm0, rax` (`66 48 0f 6e c0`), `movq xmm1, rax` (`66 48 0f 6e c8`), `punpcklqdq xmm0, xmm1` (`66 0f 6c c1`), and emits a single 128-bit `movdqu [r11], xmm0` (`f3 41 0f 7f 03`).

---

## 2. Acceptance Criteria & Verification Matrix

| ID | Criterion | Component | Verification Method | Status |
| :--- | :--- | :--- | :--- | :--- |
| **AC-53.1** | Fused `min + max + sum` (`fmin`, `fmax`, `fadd` and `smin`, `smax`, `add`) via built-in `min`/`max` and branchless `if v < mn: mn = v` | `compiler/loop_vectorizer.py` | `test_01_minmax_sum_f32_builtin_and_if_branch_z3_and_parity` (Z3 + Native PE64 + LLVM O3 parity across $N \in \{1, 3, 4, 7, 16, 65\}$) | **PROVADO** |
| **AC-53.2** | Filtered conditional `if v > 0: mn = min(mn, v); mx = max(mx, v)` on dynamic $N$ and small constant $N=19$ unrolled tree | `compiler/loop_vectorizer.py` | `test_02_conditional_minmax_and_small_const_unrolled_tree` | **PROVADO** |
| **AC-53.3** | Physical 128-bit SSE2 opcodes (`movdqu`, `paddq`, `mulpd`, `punpcklqdq`) emitted in `X64CodeGenerator` machine code, passes `AssemblyInvariantAuditor` & `SiliconSafetySandbox` (Unicorn x86-64), and matches LLVM O3 | `compiler/native_codegen.py` | `test_03_native_codegen_sse2_128bit_hardware_simd_emission_and_execution` | **PROVADO** |
| **AC-53.4** | Live Wasmtime linear-memory roundtrip executing vectorized store + fused `min + max + sum` | `compiler/wasm_codegen.py`, `compiler/loop_vectorizer.py` | `test_04_live_wasmtime_minmax_and_store_roundtrip` | **PROVADO** |
| **AC-53.5** | End-to-end `OmniRepoCompiler` compilation and execution of SSE2 vector stores + fused `min/max/sum` across Native PE64, LLVM O3 PE64, and Linux ELF64 under WSL2 | `compiler/repo_compiler.py` | `test_05_omnirepo_e2e_minmax_and_sse2_executable` | **PROVADO** |
| **AC-53.6** | Zero regressions across complete test suite (`280` tests) and Strict Empirical Auditor approval | `tests/` | `AetherMind_Strict_Auditor.py run_c53_tests.py` & `unittest discover tests` | **PROVADO** |
