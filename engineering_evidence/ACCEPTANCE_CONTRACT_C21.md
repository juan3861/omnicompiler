# ACCEPTANCE CONTRACT ALPHA-C21
## Loop-Invariant Code Motion (LICM), Alias Analysis & Dead Store Elimination (DSE)

- **Contract ID:** CONTRACT-ALPHA-C21-LICM-AA-DSE
- **Revision:** 1.0.0
- **Status:** FROZEN
- **Author:** AetherMind Apotheosis (Builder / Formal Verifier)
- **Target Repository:** `F:\repository-compiler` (remote `https://github.com/juan3861/omnicompiler.git`, branch `main`)

---

### 1. Requirements & Invariants

| ID | Category | Requirement Description | Gate Status |
|---|---|---|---|
| REQ-C21-01 | Alias Analysis | Provide `AliasAnalysis` classifying pointer pairs `(ptr_a, idx_a)` vs `(ptr_b, idx_b)` into `NO_ALIAS`, `MAY_ALIAS`, and `MUST_ALIAS`, distinguishing distinct `alloca` frames, `alloca` vs `param`, and distinct constant indices. | REQUIRED |
| REQ-C21-02 | Loop-Invariant Code Motion (LICM) | Provide `LICMPass` identifying pure loop-invariant instructions inside natural loops (whose operands are constants or defined outside the loop) and hoisting them safely into the loop pre-header. | REQUIRED |
| REQ-C21-03 | Dead Store Elimination (DSE) & Store-to-Load Forwarding | Provide `DSEPass` eliminating overwritten dead stores (`MUST_ALIAS` before intervening read/call) and forwarding stored values directly to subsequent loads (`load` -> `mov`) when no aliasing store/call intervenes. | REQUIRED |
| REQ-C21-04 | Compiler Integration | Integrate `LICMPass` and `DSEPass` into `omni_repo_compiler.py`, reporting `licm_hoisted_insts`, `dse_eliminated_stores`, and `forwarded_loads` in `stages["codegen"]`. | REQUIRED |
| REQ-C21-05 | Native Execution Correctness | LICM-hoisted loops must compile cleanly to x86-64 machine code and produce bit-identical execution results in W^X `NativeJitCompiler`. | REQUIRED |
| REQ-C21-06 | Regression & CI | 100% pass rate on `run_c21_tests.py`, `run_full_regression.py`, `AetherMind_Strict_Auditor.py`, and GitHub Actions CI (Ubuntu & Windows). | REQUIRED |

---

### 2. Invariants & Guardrails
- **INV-01 (Hoisting Safety):** `LICMPass` must never hoist instructions with side effects (`store`, `call`, `ret`, `br`, `br_cond`, `alloca`, `load`) or potentially trapping divisions (`sdiv`, `srem`) out of conditional loop bodies.
- **INV-02 (Alias Soundness):** `DSEPass` must conservatively invalidate tracked stores whenever an intervening `call` or `MAY_ALIAS` store occurs, preventing unsound load forwarding or dead-store removal.
- **INV-03 (Topological Order):** Hoisted instructions inserted into the pre-header must preserve their original data-dependency topological order before the pre-header terminator.
