# ACCEPTANCE CONTRACT ALPHA-C24
## Per-Pass SMT Translation Validation Gate (Alive2-Style Equivalence Verifier for SSA Passes)

- **Contract ID:** CONTRACT-ALPHA-C24-SMT-TRANSLATION-VALIDATION
- **Revision:** 1.0.0
- **Status:** FROZEN
- **Author:** AetherMind Apotheosis (Builder / Formal Verifier)
- **Target Repository:** `F:\repository-compiler` (remote `https://github.com/juan3861/omnicompiler.git`, branch `main`)

---

### 1. Requirements & Invariants

| ID | Category | Requirement Description | Gate Status |
|---|---|---|---|
| REQ-C24-01 | SSA-to-Z3 Symbolic Compiler | Provide `SSATranslationValidator` encoding acyclic multi-block `SSAFunction`s (including `phi` nodes, `br_cond`, `cmp_*`, bitwise, arithmetic, and `select`) into Z3 64-bit `QF_BV` formulas. | REQUIRED |
| REQ-C24-02 | Equivalence Proof & Counterexample Extraction | Prove $\forall \text{inputs}: \text{SSA}_{\text{before}}(\text{inputs}) \equiv \text{SSA}_{\text{after}}(\text{inputs})$ (`unsat` -> `PROVEN_EQUIVALENT`) or extract an exact Z3 counterexample (`sat` -> `REFUTED_COUNTEREXAMPLE`). | REQUIRED |
| REQ-C24-03 | Fail-Closed Pass Gate & Rollback | Provide `VerifiedPassRunner` that snapshots `SSAFunction` before an optimization pass, validates equivalence after the pass, and automatically rolls back to the original `SSAFunction` if `REFUTED_COUNTEREXAMPLE` occurs. | REQUIRED |
| REQ-C24-04 | Compiler Integration | Integrate `VerifiedPassRunner` / `SSATranslationValidator` into `omni_repo_compiler.py`, reporting `smt_pass_proofs` and `smt_pass_rollbacks` in `stages["codegen"]`. | REQUIRED |
| REQ-C24-05 | Regression & CI | 100% pass rate on `run_c24_tests.py`, `run_full_regression.py`, `AetherMind_Strict_Auditor.py`, and GitHub Actions CI (Ubuntu & Windows). | REQUIRED |

---

### 2. Invariants & Guardrails
- **INV-01 (Fail-Closed Soundness):** Unsupported opcodes (`call`, `alloca`, `load`, `store`), cyclic CFGs (loops), or Z3 `unknown` timeouts must never return `PROVEN_EQUIVALENT`.
- **INV-02 (Rollback Integrity):** When `VerifiedPassRunner` detects `REFUTED_COUNTEREXAMPLE`, the returned `SSAFunction` must be bit-identical to the pre-pass snapshot.
