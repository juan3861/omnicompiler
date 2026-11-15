# ACCEPTANCE CONTRACT — Alpha-C28: Hierarchical Multi/Nested-Loop Inductive TV + Linear Memory (`load`/`store`) WASM/LLVM TV + Polyglot Subscript Writes & `switch`

**Status:** FROZEN BEFORE IMPLEMENTATION  
**Milestone:** Alpha-C28 (`F:\repository-compiler`)  
**Baseline:** Alpha-C27 (`9ad613a`, CI `43766985172`, 101/101 local / 187 discovery PASS)

## 1. Deliverables & Architecture Contracts

1. **Multi-Loop & 2-Level Nested Natural Loop Inductive Verification (`validation/ssa_translation_validator.py`):**
   - Extend `SSATranslationValidator(enable_inductive_loops=True)` to verify functions containing multiple natural loops (`>= 2` back-edge headers) without falling back to bounded unrolling:
     - **Sequential Disjoint Natural Loops:** Verify each loop's 1-inductive lockstep bisimulation in topological order, threading proven-equal converged loop exit states through intermediate DAG segments into the next loop and final return (`PROVEN_INDUCTIVE_EQUIVALENT`, `bounded=False`).
     - **2-Level Nested Natural Loops:** Decompose outer loop body (`outer_header` -> `inner_pre` -> `inner_loop` -> `outer_latch`), discharge the inner loop's Base, Lockstep Guard, and Step Preservation under arbitrary outer-loop state `(R_outer)`, substitute proven-equal Skolemized post-inner exit state summaries `(phi'_B == phi'_A, mem'_B == mem'_A)`, and prove the outer loop's Base, Lockstep Guard, Step Preservation, and Exit equivalence (`PROVEN_INDUCTIVE_EQUIVALENT`, `bounded=False`).
   - Fail closed & catch mutations: Any bug introduced in inner header, inner body, outer header, or outer body MUST return `REFUTED_COUNTEREXAMPLE` with concrete counterexample parameters.

2. **Linear Memory (`load`/`store`) Codegen & Formal Translation Validation (`compiler/wasm_backend.py`, `validation/backend_translation_validator.py`):**
   - Emit valid WASM 64-bit indexed linear-memory instructions (`i32.wrap_i64` byte-address `base + (idx << 3)`, `i64.load`, `i64.store`) and `(memory (export "memory") 1)` in `WasmBackend` when `load` or `store` instructions exist.
   - Lift WASM `i64.load` / `i64.store` sequences cleanly in `WATToSSALifter` back to SSA `"load"` and `"store"` instructions so `BackendTranslationValidator` formally proves both `SSAFunction <-> LLVM IR` (`enable_memory_theory=True`) and `SSAFunction <-> WAT` (`enable_memory_theory=True`), including counterexample detection on mutated offsets/values.

3. **Polyglot Subscript Mutation & `switch` Lowering (`frontends/polyglot_ssa_lowering.py`):**
   - Lower `arr[idx] = expr;` and `arr[idx] op= expr;` in JS, TS, Rust, and Go directly to `ast.Assign` / `ast.AugAssign` with `ast.Subscript(ctx=ast.Store())`.
   - Lower `switch (expr) { case C1: ... break; default: ... }` (JS/TS) and `switch expr { case C1: ... default: ... }` (Go) to structured `ast.If` chains.

## 2. Empirical Acceptance Gates

- `tests/test_alpha_c28_nested_loops_and_mem_tv.py` + `run_c28_tests.py`:
  1. Unbounded 2-level nested loop (`for i < n: for j < m:`) equivalent transform (`PROVEN_INDUCTIVE_EQUIVALENT`, `bounded=False`) + bug catch (`REFUTED_COUNTEREXAMPLE`) in both inner and outer loop bodies.
  2. Unbounded 2-sequential-loop (`loop1; loop2`) equivalent transform (`PROVEN_INDUCTIVE_EQUIVALENT`, `bounded=False`) + bug catch (`REFUTED_COUNTEREXAMPLE`).
  3. Formal `BackendTranslationValidator` proofs (`SSA <-> LLVM IR` and `SSA <-> WAT`) + physical linear-memory execution parity (`Native x86-64 JIT` == `LLVM O3 MCJIT` == `Wasmtime`) on buffer read/write (`arr[i] = val; ... return arr[k]`).
  4. Polyglot JS/TS/Rust/Go subscript mutation (`arr[i] = ...`, `arr[i] += ...`) and `switch/case` compiled to native machine code and `.wasm` via `OmniRepoCompiler` with exact execution results.
- Full regression `run_full_regression.py` + `unittest discover`, `AetherMind_Strict_Auditor.py` `APROVADO`, and GitHub Actions CI green on `ubuntu-latest` and `windows-latest`.
