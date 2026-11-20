# Acceptance Contract — Alpha-C63: Quad-Ecosystem Homeostasis & Active Build-Time Verification

## 1. Objective
Advance `HomeostasisRouter`, `WasmBackend`, and `OmniRepoCompiler` to full **Quad-Ecosystem Differential Consensus** (`Omni Native AVX2/NEON` == `LLVM 20.1.8 O3` == `GNU GCC O3` == `WebAssembly v128` via Wasmtime) with build-time differential probe verification (`homeostasis_probes`), cross-engine SIMD telemetry, and Z3 `TranslationValidation` across all active backends.

## 2. Hard Acceptance Gates
1. **WebAssembly `v128` Linear Memory & Stack `alloca` (`WasmBackend`):**
   - `WasmBackend.run_ssa_with_memory` executes vectorized `SSAFunction`s using `v128` SIMD instructions, honors virtual-to-linear memory mapping, restores `$__omni_sp` on `ret` when `alloca` is used, and reports `fuel_consumed` + `v128_instruction_count`.
2. **Quad-Ecosystem Bit-Exact Differential Consensus (`HomeostasisRouter`):**
   - `HomeostasisRouter.available_engines()` exposes all available engines among `native`, `llvm`, `gcc`, `wasm`.
   - `HomeostasisRouter.execute_differential` achieves bit-exact return-value and full memory-snapshot agreement across all 4 engines on Linux/WSL2 (`native`, `llvm`, `gcc`, `wasm`) and across `native`, `llvm`, `wasm` on headless Windows CI, isolating silent memory corruption even when return values match.
3. **Active Build-Time Homeostasis (`OmniRepoCompiler(..., backend="homeostasis")`):**
   - Collects cross-engine SIMD telemetry (`inspect_ecosystem_telemetry`), validates self-contained WASM functions with `BackendTranslationValidator.verify_ssa_to_wat` (`Z3`) and LLVM functions with `verify_ssa_to_llvm_ir` (`Z3`), runs live `homeostasis_probes` fail-closed, and produces valid native PE64/ELF64 standalone executables.
4. **Fail-Closed Quorum & Strict Auditor:**
   - Unresolvable consensus ties (`1` vs `1`) yield `consensus_reached=False` and `selected_engine=None`.
   - `AetherMind_Strict_Auditor.py` on `run_c63_tests.py` exits `0` (`APROVADO`) and full repository `unittest` regression passes 100%.
