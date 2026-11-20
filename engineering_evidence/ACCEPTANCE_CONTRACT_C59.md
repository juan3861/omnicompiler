# Acceptance Contract — Alpha-C59: 256-bit AVX2 Pack-and-Store & 8-Lane 32-bit Packed SIMD Fusion

## 1. Objective & Scope
Extends `X64CodeGenerator.compile_function` in [`compiler/native_codegen.py`](file:///F:/repository-compiler/compiler/native_codegen.py) with:
1. **256-bit AVX2 Pack-and-Store for 4 Contiguous 64-bit Stores:** Fuses non-binary-load 64-bit 4-lane stores (such as inclusive prefix scans and affine maps `v * 3 + 1`) into `vmovq` + `vpinsrq` + `vinserti128 ymm0, ymm0, xmm1, 1` + `vmovdqu [r11], ymm0` + `vzeroupper`.
2. **256-bit AVX2 8-Lane 32-bit Packed SIMD Fusion (`_AVX2_PACKED_32B_ALU_OPS`):** Fuses 8 contiguous `i32`/`u32`/`f32` `load_off` + ALU (`vpaddd`, `vpsubd`, `vpand`, `vpor`, `vpxor`, `vaddps`, `vsubps`, `vmulps`) + `store_off` into a single `vmovdqu ymm0` / `vmovdqu ymm1` / ALU / `vmovdqu [r11], ymm0` sequence.

## 2. Acceptance Criteria
| ID | Requirement | Verification Method | Status |
|---|---|---|---|
| AC-C59-01 | Emit 256-bit AVX2 pack-and-store (`vpinsrq`, `vinserti128`, `vmovdqu ymm`, `vzeroupper`) for prefix scan + affine map | `test_01_avx2_256bit_pack_and_store_prefix_scan_and_scale` | PASS |
| AC-C59-02 | Emit 256-bit AVX2 8-lane 32-bit `vpaddd` & `vmulps` and execute live | `test_02_avx2_256bit_8lane_32bit_packed_vpaddd_and_vmulps` | PASS |
| AC-C59-03 | Quad-ISA parity (x86-64 AVX2, ARM64 NEON Unicorn, Wasmtime `v128`, LLVM O3) on fused pack-scan + Tribonacci | `test_03_quad_isa_parity_fused_pack_scan_and_tribonacci` | PASS |
