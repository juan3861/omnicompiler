# Acceptance Contract — Alpha-C61: Full 4-ISA 32-bit Vector Multiplication (`vpmulld`/`pmulld`) & 8-Lane 32-bit AVX2 Pack-and-Store

## 1. Objective & Scope
Closes the remaining SIMD symmetry gaps in [`compiler/native_codegen.py`](file:///F:/repository-compiler/compiler/native_codegen.py):
1. **32-bit Integer Vector Multiplication (`mul`/`imul`):** Adds `vpmulld ymm0, ymm0, ymm1` (`c4 e2 7d 40 c1`) to `_AVX2_PACKED_32B_ALU_OPS` and `pmulld xmm0, xmm1` (`66 0f 38 40 c1`) to `_SSE2_PACKED_32B_ALU_OPS`, achieving full 4-ISA parity with ARM64 NEON (`MUL V0.4S`), WebAssembly (`i32x4.mul`), and LLVM O3.
2. **256-bit AVX2 8-Lane 32-bit Pack-and-Store (`i32`/`u32`/`f32`):** Fuses non-binary-load 8-lane 32-bit stores (`out32[i] = a32[i] * 3 + 1`, `fout32[i] = fa32[i] * 2.5 + 0.5`) via `vmovd` + `vpinsrd` + `vinserti128` + `vmovdqu [r11], ymm0` + `vzeroupper`.

## 2. Acceptance Criteria
| ID | Requirement | Verification Method | Status |
|---|---|---|---|
| AC-C61-01 | Emit `vpmulld` (AVX2 8-lane) & `pmulld` (SSE4.1 4-lane) with Quad-ISA parity (x64 AVX2, ARM64 NEON, WASM `v128`, LLVM O3) | `test_01_x64_32bit_mul_vpmulld_avx2_and_pmulld_sse41` | PASS |
| AC-C61-02 | Emit 8-lane 32-bit AVX2 pack-and-store (`vpinsrd`, `vinserti128`, `vmovdqu ymm`, `vzeroupper`) for `i32` & `f32` | `test_02_avx2_8lane_32bit_general_pack_and_store_i32_and_f32` | PASS |
