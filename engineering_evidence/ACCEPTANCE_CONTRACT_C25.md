# ACCEPTANCE CONTRACT ALPHA-C25
## Complete SMT-Gated AOT Unification (`QF_ABV` Memory + Bounded Loop Unrolling + Unified `native`/`llvm`/`wasm` Backends)

- **Contract ID:** CONTRACT-ALPHA-C25-UNIFIED-SMT-AOT
- **Revision:** 1.0.0
- **Status:** FROZEN
- **Author:** AetherMind Apotheosis (Consenso AGI-Sys + AGI-Formal)
- **Target Repository:** `F:\repository-compiler` (remote `https://github.com/juan3861/omnicompiler.git`, branch `main`)

---

### 1. Requirements & Invariants

| ID | Category | Requirement Description | Gate Status |
|---|---|---|---|
| REQ-C25-01 | `QF_ABV` Memory & Bounded Loop Unrolling | Extend `SSATranslationValidator` with opt-in `enable_memory_theory: bool = False` (`alloca`, `load`, `store` over Z3 `Array(BitVecSort(64), BitVecSort(64))` distinguishing non-escaping `alloca` regions from visible external memory) and `max_loop_unroll: int = 0` (bounded CFG unrolling emitting `PROVEN_BOUNDED_EQUIVALENT`, `REFUTED_COUNTEREXAMPLE`, or fail-closed `UNVERIFIED_LOOP_BOUND_EXCEEDED`). Default parameters remain 100% C24-compatible (`UNVERIFIED_CYCLIC_CFG`). | REQUIRED |
| REQ-C25-02 | Expanded SMT Pass Coverage | Upgrade `VerifiedPassRunner` integration in `omni_repo_compiler.py` (`enable_memory_theory=True, max_loop_unroll=4`) to verify and guard `SCCPPass`, `GlobalValueNumberingPass`, `LICMPass`, `SROAPass`, `DSEPass`, `TailCallOptimizationPass`, and `BlockLayoutPass`. | REQUIRED |
| REQ-C25-03 | Inter-Procedural Specialization & Devirtualization Wiring | Wire `InterProceduralSCCPPass` (creating and compiling specialized `fn__spec_*` clones) and `DevirtualizationPass` (`speculative_targets` parameter) directly into `OmniRepoCompiler.compile_repositories()`, actively driving `specialized_functions` and `devirtualized_calls` in `stages["codegen"]`. | REQUIRED |
| REQ-C25-04 | Unified Multi-Backend Dispatch (`native` / `llvm` / `wasm`) | Wire `backend: str = "native"` (`"native"`, `"llvm"`, `"wasm"`) in `OmniRepoCompiler.compile_repositories()` and CLI `--backend`: `"llvm"` links `LLVMBackend.emit_object()` COFF/ELF objects through `NativeObjectLinker`; `"wasm"` lowers and compiles SSA into valid `.wasm` bytecode via `WasmBackend` + `wasmtime.wat2wasm`. | REQUIRED |
| REQ-C25-05 | Regression & CI | 100% pass rate on `run_c25_tests.py`, `run_full_regression.py` (C13–C25), `AetherMind_Strict_Auditor.py`, and GitHub Actions CI (`ubuntu-latest` & `windows-latest`). | REQUIRED |

---

### 2. Invariants & Guardrails
- **INV-01 (C24 Backward Compatibility):** Calling `SSATranslationValidator()` with default arguments MUST continue failing closed with `UNVERIFIED_CYCLIC_CFG` on loops and `UNVERIFIED_UNSUPPORTED_OPCODE_*` on memory/call opcodes.
- **INV-02 (Honest Bounded Status):** Bounded loop equivalence verification MUST report `"PROVEN_BOUNDED_EQUIVALENT"` (never `"PROVEN_EQUIVALENT"`) and MUST reject vacuous bounds where zero executions terminate (`UNVERIFIED_LOOP_BOUND_EXCEEDED`).
- **INV-03 (Sound Memory Equivalence):** Elimination of non-escaping `alloca` storage (e.g. via `SROAPass` / `DSEPass`) is accepted iff return values AND all external (non-`alloca`) memory writes match across all paths; escaping `alloca`s fail closed.
