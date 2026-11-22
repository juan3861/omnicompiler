# Acceptance Contract — Alpha-C71: Cross-Emitter `f64` Return ABI, Multi-Function Win64 `.pdata`/`.xdata` & DWARF v5 Subprograms

## 1. Objective
Execute **Fase 2 (Alpha-C71)** of the Top-1 Master Plan:
1. Propagate cross-repository `float`/`f64` return types (`global_return_types`) during AST-to-SSA lowering so `Native` callers invoke `LLVM`/`GCC` `f64`-returning callees via standard `XMM0`/`D0` ABI seamlessly.
2. Expose `cross_emitter_summaries` (purity, memory read/write, callees, return type, assigned emitter) in `Homeostasis` telemetry.
3. Emit sorted multi-function Win64 `.pdata`/`.xdata` unwind tables (`emit_win64_multi_pdata_xdata`) for all non-leaf functions and DWARF v5 `DW_TAG_subprogram` DIEs (`emit_debug_info_with_subprograms`).

## 2. Acceptance Criteria
- `test_01_cross_emitter_f64_return_abi_llvm_to_native_and_gcc_to_native`: Compiles `compute_f64_llvm` (`llvm`, returning `float`) called from `omni_main` (`native`), verifies `cross_emitter_summaries`, Unicorn preflight (`122`), and live `ctypes.CDLL` execution (`122`, `62`).
- `test_02_multi_function_win64_pdata_xdata_and_dwarf_v5_subprograms`: Verifies sorted multi-entry `.pdata` + `.xdata`, `DW_TAG_subprogram` DIEs, and PE32+ `.pdata` emission across multiple non-leaf functions in `OmniRepoCompiler`.
- `AetherMind_Strict_Auditor.py run_c71_tests.py`: `APROVADO`.
- `python -W error::ResourceWarning test_empirical_audit.py`: `14/14` gates PASSED.
- Full `unittest discover -s tests -p "test_*.py"` passes with 0 failures and 0 warnings.
