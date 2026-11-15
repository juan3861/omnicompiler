# Alpha-C26 Acceptance Contract — Unbounded Inductive Loop Proofs & Cross-Backend Translation Validation

**Date:** 2026-11-15  
**Target Repository:** `F:\repository-compiler`  
**Baseline Commit:** `649ba47` (Alpha-C25 green across Windows & Linux CI)

---

## Frozen Scope & Success Criteria

1. **Cross-IR Operator Semantic Unification (`shr` / `sar` / `neg` / `not`):**
   - `SSATranslationValidator` (`validation/ssa_translation_validator.py`) models `"shr"` as signed 64-bit arithmetic right shift (`v0 >> v1`), matching `ssa_ir.py`, x86-64 `sar`, ARM64 `ASRV`, LLVM `ashr`, and WASM `i64.shr_s` (`"lshr"` reserved for unsigned `z3.LShR`).
   - `_eval_const_binop` (`compiler/ssa_ir.py`) handles `("shr", "sar")` uniformly.
   - `NativeCodeGenerator` (`compiler/native_codegen.py`) implements `"sar"`, `"neg"`, and `"not"` on both **x86-64** and **ARM64** (executable and verified in `SiliconSafetySandbox`).

2. **Unbounded Inductive Loop Translation Validation (`validation/ssa_translation_validator.py`):**
   - `SSATranslationValidator(..., enable_inductive_loops: bool = False)` and `VerifiedPassRunner(..., enable_inductive_loops: bool = False)` preserve 100% C24/C25 backward compatibility when `enable_inductive_loops=False`.
   - When `enable_inductive_loops=True` and a cyclic CFG has no finite unroll termination (either `max_loop_unroll == 0` or `UNVERIFIED_LOOP_BOUND_EXCEEDED`), `_verify_inductive_loop_equivalence()` checks 1-inductive lockstep bisimulation over natural loops (Preheader Base $\implies$ Loop Guard Agreement + Inductive Body Preservation $\implies$ Post-Loop Exit Equivalence) via Z3 `QF_ABV`:
     - Proves valid loop optimizations (e.g., `LICMPass` hoisting invariants into preheader, loop constant folding, DSE inside loop) for **arbitrary symbolic loop bounds $N \ge 0$** (`status == "PROVEN_INDUCTIVE_EQUIVALENT"`, `bounded == False`, `proven == True`).
     - Refutes injected inductive loop bugs (step skew, guard mutation, unsound hoisting of loop-variant expressions) with `status == "REFUTED_COUNTEREXAMPLE"` (`proven == False`).
     - Fails closed (`UNVERIFIED_UNSUPPORTED_LOOP_SHAPE` or `UNVERIFIED_CYCLIC_CFG`) on irregular/unsupported loop shapes—never fail-open.

3. **Formal Backend Lowering Translation Validation (`validation/backend_translation_validator.py`):**
   - `verify_ssa_to_llvm_ir(ssa_fn, llvm_ir_str, timeout_ms=2000)` parses emitted LLVM IR text (`phi`, `alloca`/`inttoptr`/`getelementptr`/`load`/`store`, arithmetic/bitwise ops, `icmp`+`zext`, `select`, `br`, `ret`, plus bounded/inductive CFG support) into Z3 `QF_ABV` and proves equivalence against `SSATranslationValidator`. Catches lowering bugs (e.g., wrong predicate, `lshr` vs `ashr`, wrong operand).
   - `verify_ssa_to_wat(ssa_fn, wat_str, timeout_ms=2000)` parses emitted WebAssembly Text (`_ssa_function_to_wat_func` / `ssa_to_wat`) into Z3 `QF_ABV` and proves equivalence against `SSATranslationValidator`. Catches WAT lowering bugs (e.g., `i64.shr_u` vs `i64.shr_s`, swapped `select`, wrong `i64.rem_s`).
   - `verify_differential_execution(ssa_fn, inputs_list)` physically executes compiled machine/JIT/WASM code across Native x86-64 JIT, LLVM MCJIT O3, and Wasmtime and verifies bit-exact equality on all test vectors.

4. **OmniRepoCompiler E2E Wiring (`omni_repo_compiler.py`):**
   - `VerifiedPassRunner(..., enable_memory_theory=True, max_loop_unroll=4, enable_inductive_loops=True)` enabled for Passes 6–11.
   - `BiAbductionVerifier` wired into `compile_repositories()` to produce real `separation_proofs` across repository capsules and set `heap_biabduction` in the audit ledger from real proof results.
   - `BackendTranslationValidator` automatically verifies lowered LLVM IR (when `backend="llvm"`) and WAT (when `backend="wasm"`), surfacing metrics in `results["stages"]["backend_validation"]`.

5. **Verification & CI Gates:**
   - Dedicated C26 suite `tests/test_alpha_c26_inductive_and_backend_tv.py` + `run_c26_tests.py` + inclusion in `run_full_regression.py`.
   - Zero regressions in C13–C25 tests.
   - Strict Empirical Auditor + both `windows-latest` and `ubuntu-latest` GitHub Actions CI green.
