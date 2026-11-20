# Acceptance Contract — Alpha-C57: Coupled 2-State & Second-Order Linear Recurrences (`2x2` Matrix Exponentiation) & Direct 128-bit ARM64 NEON / ASIMD Hardware Emission

## 1. Objective & Scope
Alpha-C57 advances `OmniCompiler` across two major vectorization and multi-architecture code generation dimensions:
1. **Coupled 2-State & Second-Order Linear Recurrence Vectorization (`"coupled_2x2"`) in [`compiler/loop_vectorizer.py`](file:///F:/repository-compiler/compiler/loop_vectorizer.py):**
   - Vectorizes coupled 2-variable linear systems and driven second-order recurrences (Fibonacci, Lucas, 2-tap IIR state filters):
     $$\begin{bmatrix} x_{k+1} \\ y_{k+1} \end{bmatrix} = \underbrace{\begin{bmatrix} c_{00} & c_{01} \\ c_{10} & c_{11} \end{bmatrix}}_{M} \begin{bmatrix} x_k \\ y_k \end{bmatrix} + \begin{bmatrix} \pm \Delta x_k \\ \pm \Delta y_k \end{bmatrix}$$
   - Precomputes $M^2, M^3, M^4 \in (\mathbb{Z}/2^{64}\mathbb{Z})^{2 \times 2}$ at compile time and folds 4 consecutive iterations into a single parallel step:
     $$\begin{bmatrix} x_{k+4} \\ y_{k+4} \end{bmatrix} = M^4 \begin{bmatrix} x_k \\ y_k \end{bmatrix} + M^3 \Delta_k + M^2 \Delta_{k+1} + M \Delta_{k+2} + \Delta_{k+3}$$
   - Composes seamlessly with single-pass fused vector stores, prefix scans, and scalar reductions.
2. **Direct 128-bit ARM64 NEON / ASIMD Hardware Emission in [`compiler/native_codegen.py`](file:///F:/repository-compiler/compiler/native_codegen.py) & Heap Memory Regions in [`validation/silicon_safety_sandbox.py`](file:///F:/repository-compiler/validation/silicon_safety_sandbox.py):**
   - Emits physical 128-bit ARM64 NEON instructions for 2-lane 64-bit (`V0.2D`) and 4-lane 32-bit (`V0.4S`) contiguous vector stores (`LDR Q0, [X9]` `0x3DC00120`, `LDR Q1, [X9]` `0x3DC00121`, `STR Q0, [X9]` `0x3D800120`, `ADD/SUB V0.2D`, `FADD/FSUB/FMUL V0.2D`, `AND/ORR/EOR V0.16B`, `ADD/SUB/MUL V0.4S`, `FADD/FSUB/FMUL V0.4S`, `INS V0.D[1], X11` `0x4E181D60`, `INS V0.S[k], W11`).
   - Collapses 4-way 64-bit accumulator trees in `Arm64CodeGenerator` using `ADD V0.2D` (`0x4EE18400`) + `ADDP D0, V0.2D` (`0x5EF1B800`) and `FADD V0.2D` (`0x4E61D400`) + `FADDP D0, V0.2D` (`0x7E70D400`).
   - Extends `SiliconSafetySandbox.emulate_arm64` with `memory_regions` and `memory_snapshots` for live Unicorn `UC_ARCH_ARM64` heap verification.

## 2. Acceptance Criteria
| ID | Requirement | Verification Method | Status |
|---|---|---|---|
| AC-C57-01 | Vectorize driven 2nd-order recurrences (`a, b = b, a + b + v`) & coupled 2D linear systems with Z3 safety proof | `test_01_coupled_2x2_second_order_fibonacci_and_state_space_z3_and_parity` | PASS |
| AC-C57-02 | Emit physical 128-bit ARM64 NEON opcodes (`LDR Q0`, `STR Q0`, `ADD V0.2D`, `FMUL V0.2D`, `ADD V0.4S`, `FMUL V0.4S`, `ADDP D0, V0.2D`) and verify live in Unicorn `UC_ARCH_ARM64` | `test_02_arm64_neon_128bit_simd_store_pair_quad_and_addp_unicorn_execution` | PASS |
| AC-C57-03 | Bit-exact quad-ISA parity across x86-64 SSE2, ARM64 NEON (Unicorn), WebAssembly `v128` (Wasmtime), and LLVM O3 JIT | `test_03_cross_arch_quad_isa_parity_x64_sse2_arm64_neon_wasm_v128_llvm` | PASS |
| AC-C57-04 | Single-pass fusion of vector store, inclusive prefix scan, coupled $2 \times 2$ recurrence, and `max` reduction | `test_04_fused_store_and_coupled_2x2_recurrence_pipeline` | PASS |
| AC-C57-05 | Full `OmniRepoCompiler` E2E executable parity across Windows PE64 Native, LLVM O3 PE64, and WSL2 Linux ELF64 | `test_05_omnirepo_e2e_coupled_2x2_executable` | PASS |
