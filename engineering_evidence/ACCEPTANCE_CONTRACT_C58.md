# Acceptance Contract — Alpha-C58: Order-$k$ ($k \in \{2, 3, 4\}$) Linear Recurrence Vectorization (`coupled_nxn`) & Direct 256-bit AVX2 VEX SIMD Fusion

## 1. Objective & Scope
1. **Generalized Order-$k$ Linear Recurrence Vectorization (`"coupled_nxn"`, $k \in \{2, 3, 4\}$) in [`compiler/loop_vectorizer.py`](file:///F:/repository-compiler/compiler/loop_vectorizer.py):**
   - Replaces the 2-state-only `"coupled_2x2"` special case with connected-component partitioning over linear state accumulators (`_mat_nxn_mul`, `_emit_coupled_nxn_1x_row`, `_emit_coupled_nxn_4x_row`).
   - Vectorizes 3rd-order Tribonacci (`nxt = a + b + c + v; a = b; b = c; c = nxt`), 4th-order Tetranacci / 4-tap linear state systems, and multi-group coupled systems across dynamic strip-mining, constant unrolling, and single-pass fused store pipelines.
2. **Direct 256-bit AVX2 VEX SIMD Fusion in `X64CodeGenerator.compile_function` ([`compiler/native_codegen.py`](file:///F:/repository-compiler/compiler/native_codegen.py)):**
   - Adds host CPUID AVX2 detection (`_host_supports_avx2()`) and `enable_avx2` configuration.
   - Fuses 4-lane contiguous 64-bit (`i64`/`u64`/`f64`) `load_off` + ALU (`vpaddq`, `vpsubq`, `vpand`, `vpor`, `vpxor`, `vaddpd`, `vsubpd`, `vmulpd`) + `vmovdqu [r11], ymm0` (`c4 c1 7e 7f 03`) and emits `vzeroupper` (`c5 f8 77`) in `.L_epilogue` when YMM registers are used.
3. **Anti-Misvectorization Negative-Start Coverage in [`tests/test_alpha_c49_dynamic_stripmining.py`](file:///F:/repository-compiler/tests/test_alpha_c49_dynamic_stripmining.py):**
   - Adds `"negative_init"` (`i = -2`) alongside `"non_pow2_step"` (`i += 3`) and `"loop_variant_bound"`.

## 2. Acceptance Criteria
| ID | Requirement | Verification Method | Status |
|---|---|---|---|
| AC-C58-01 | Vectorize $k=3$ Tribonacci & $k=4$ Tetranacci recurrences with Z3 memory safety and Native/LLVM O3 parity | `test_01_order3_tribonacci_and_order4_tetranacci_z3_and_parity` | PASS |
| AC-C58-02 | Emit 256-bit AVX2 VEX opcodes (`vmovdqu ymm`, `vpaddq`, `vmulpd`, `vzeroupper`), pass `AssemblyInvariantAuditor`, and execute live | `test_02_x64_avx2_256bit_vex_fusion_and_vzeroupper` | PASS |
| AC-C58-03 | Quad-ISA parity (x86-64 AVX2, ARM64 NEON Unicorn, Wasmtime `v128`, LLVM O3) for Order-3 Tribonacci + fused store | `test_03_quad_isa_parity_tribonacci_and_fused_store` | PASS |
| AC-C58-04 | Full `OmniRepoCompiler` E2E executable parity across Windows PE64 Native, LLVM O3 PE64, and WSL2 Linux ELF64 | `test_04_omnirepo_e2e_order3_tribonacci_executable` | PASS |
