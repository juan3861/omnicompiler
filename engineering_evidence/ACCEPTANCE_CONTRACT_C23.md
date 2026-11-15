# ACCEPTANCE CONTRACT ALPHA-C23
## Scalar Replacement of Aggregates (SROA) & Speculative Devirtualization with Guarded Fallback

- **Contract ID:** CONTRACT-ALPHA-C23-SROA-DEVIRT
- **Revision:** 1.0.0
- **Status:** FROZEN
- **Author:** AetherMind Apotheosis (Builder / Formal Verifier)
- **Target Repository:** `F:\repository-compiler` (remote `https://github.com/juan3861/omnicompiler.git`, branch `main`)

---

### 1. Requirements & Invariants

| ID | Category | Requirement Description | Gate Status |
|---|---|---|---|
| REQ-C23-01 | Scalar Replacement of Aggregates (SROA) | Provide `SROAPass` decomposing non-escaping `alloca` aggregates accessed at constant indices into pure SSA scalar variables, eliminating the `alloca`, `store`, and `load` instructions. | REQUIRED |
| REQ-C23-02 | SROA Soundness Guard | `SROAPass` must reject any `alloca` that escapes (`call`, `ret`, stored as a value) or is indexed dynamically (non-constant offset). | REQUIRED |
| REQ-C23-03 | Speculative Devirtualization | Provide `DevirtualizationPass` transforming polymorphic `call_indirect` / `vcall` instructions into guarded fast-path/fallback diamond CFGs (`cmp_eq` guard -> direct `call` fast path vs. indirect fallback + `phi` merge). | REQUIRED |
| REQ-C23-04 | Native Execution Correctness | SROA-promoted functions and guarded devirtualized CFGs must compile cleanly to x86-64 machine code and produce exact results in W^X `NativeJitCompiler`. | REQUIRED |
| REQ-C23-05 | Compiler Integration | Integrate `SROAPass` and `DevirtualizationPass` into `omni_repo_compiler.py`, reporting `sroa_replaced_allocas`, `sroa_eliminated_mem_ops`, and `devirtualized_calls` in `stages["codegen"]`. | REQUIRED |
| REQ-C23-06 | Regression & CI | 100% pass rate on `run_c23_tests.py`, `run_full_regression.py`, `AetherMind_Strict_Auditor.py`, and GitHub Actions CI (Ubuntu & Windows). | REQUIRED |

---

### 2. Invariants & Guardrails
- **INV-01 (No Escaped Alloca Promotion):** Any `alloca` passed to `call`, `ret`, or used as a stored value must not be decomposed by SROA.
- **INV-02 (Dominance & Initialization Safety):** Loads of an aggregate slot before any write in the same scope must either be initialized to `0` or conservatively skip SROA.
- **INV-03 (Guard Fallback Equivalence):** On guard failure (`tag != expected_tag`), `DevirtualizationPass` must execute the original indirect call semantics identically.
