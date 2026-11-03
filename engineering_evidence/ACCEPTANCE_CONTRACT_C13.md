# ACCEPTANCE CONTRACT — PROTOCOL ALPHA-C13 STATEFUL-SELECTION
**Protocol:** MASTER PROMPT ALPHA-C13 — STATEFUL-SELECTION (Repeated Rollouts · Cluster-Aware Evals · Scoped Approvals · Anti-Goodhart Promotion)  
**Contract Version:** 13.0.0 (FROZEN)  
**Mode of Execution:** `REAL_MULTI_AGENT` / `SEPARATE_CONTEXT_REVIEW`  
**Baseline Commit:** `2d4935a004eb7f5b33be1e3093246ebcfd3d0f04`  
**Timestamp:** `2026-11-02T18:30:00Z`  
**Audit Nonce:** `NONCE-ALPHA-C13-STATEFUL-20261102`  
**Target Repository:** `F:\repository-compiler` (`omnicompiler`)  
**Remote Origin:** `https://github.com/juan3861/omnicompiler.git` (`main`)  

---

### 1. Canonical Workspace & Baseline State
- **Root Directory:** `F:\repository-compiler`
- **Compiler Stack:** Python 3.11, Z3 SMT Solver (QF_BV / QF_ABV), LLVM 18 C-API / llvmlite, Wasmtime WASI Preview 2, Unicorn Engine (x86-64 / ARM64), Rust SIMD BLAKE3, SQLite 3 WAL.
- **Baseline Capabilities:** Multi-block SSA (Braun 2013), Cooper-Harvey-Kennedy dominators, Chaitin-Briggs + Poletto-Sarkar RegAlloc, x86-64 AVX2 + ARM64 codegen, W^X Native JIT, Native Heap Dynamic Collections (`OmniList`, `OmniDict`, `.append()`, `len()`, subscripts, in-place mutations), Multi-Repo linker with auto-thunk synthesis.
- **Baseline Test Suite:** 103 unit tests passing in 12.430s, 9 master ceiling benchmarks, zero regressions, 100% green remote GitHub Actions CI (`2d4935a`).

---

### 2. Functional & Non-Functional Gates Inventory

Under Alpha-C13, every gate is explicitly declared with strict status. No gate marked `REQUIRED` may become `NOT_APPLICABLE` without an authenticated contract version revision.

| Gate ID | Designation | Applicability | Threshold / Invariant | Verification Oracle |
| :--- | :--- | :---: | :--- | :--- |
| `GATE-C13-01` | License & Provenance | `REQUIRED` | Permissive open-source licenses (MIT/Apache-2.0/BSD/ISC). Zero AGPL/GPL contamination. | AST & SPDX manifest audit |
| `GATE-C13-02` | Memory Safety & W^X | `REQUIRED` | 100% of executable memory must enforce `PAGE_EXECUTE_READ` (0x20). Zero `PAGE_EXECUTE_READWRITE` pages. | Win32 `VirtualQuery` / POSIX `mprotect` probe |
| `GATE-C13-03` | Formal Refinement | `REQUIRED` | Fail-Closed Z3 SMT `QF_BV` proof: $\text{Pre}(S) \implies (S \equiv T)$. Divergences/UB must fail closed. | Z3 SmtRefinementVerifier |
| `GATE-C13-04` | Turing-Completeness | `REQUIRED` | Multi-block SSA CFG with minimal $\phi$-nodes, loops (`while`, `for`), branch conditions, and epilogue balance. | Braun et al. (2013) Invariant Checker |
| `GATE-C13-05` | Silicon Execution | `REQUIRED` | Real execution on physical silicon or Unicorn AArch64/AMD64 emulator without CPU exceptions. | SiliconSafetySandbox |
| `GATE-C13-06` | Zero-CPython Strings | `REQUIRED` | Small String Optimization (SSO $\le 15$ bytes), zero-copy slicing, native concatenation without CPython headers. | `test_alpha_c13_stateful_selection.py` |
| `GATE-C13-07` | ThinLTO Optimization | `REQUIRED` | Cross-repository whole-program constant propagation & dead symbol elimination before emission. | Inter-procedural call-graph slicer |
| `GATE-C13-08` | Stateful Selection | `REQUIRED` | Non-replayable single-use evaluation slots bound to `(baseline, candidate, eval_plan)` with Holm-Bonferroni control. | `validation/stateful_selection_ledger.py` |
| `GATE-C13-09` | Cluster Reliability | `REQUIRED` | Multi-rollout stability ($k \ge 5$) across independent seeds without pseudoreplication. | Rollout evaluator |
| `GATE-C13-10` | Zero Regression | `REQUIRED` | 100% pass on all 103 existing baseline tests + 8 composite tests. | Complete test runner |

---

### 3. Frozen Rubric, Weights & Thresholds

$$\text{Final Score} = \sum_{i=1}^{10} w_i \times g_i$$

- Weights:
  - $w_1$ (License & Safety): $10\%$
  - $w_2$ (W^X & Silicon): $10\%$
  - $w_3$ (Z3 SMT Fail-Closed): $10\%$
  - $w_4$ (SSA Turing-Completeness): $10\%$
  - $w_5$ (Native Strings & Heap): $15\%$
  - $w_6$ (ThinLTO Whole-Program): $15\%$
  - $w_7$ (Stateful-Selection Ledger): $10\%$
  - $w_8$ (Cluster Rollouts & Non-Pseudoreplication): $10\%$
  - $w_9$ (Anti-Goodhart Pareto Frontier): $5\%$
  - $w_{10}$ (Zero Regressions): $5\%$
- **Eliminatory Rule:** If any `REQUIRED` gate evaluates to `FAIL` or `UNKNOWN`, promotion is immediately rejected.
- **Approval Threshold:** Overall score $\ge 95.0\%$ with $0$ critical failures ($F=0$).

---

### 4. Cryptographic Proof Hashes (Frozen Contract State)
- `CONTRACT_SHA256`: `d47a98b2c6e310028e9f5bca94e50882fa4b1b39ce8a7f19cb54238e55e4e70a`
- `GATE_SPEC_SHA256`: `8192af83e74c82b0149c0d5718a2431cfb0965d1d642878bf8f47f6311654320`
- `RUBRIC_SHA256`: `fe77a63b019b84179374023758b97b1029c7b50931481e18b02ea878bf01bc99`

---

### 5. Anti-Gaming and Least-Privilege Policy
1. No mock bypasses, synthetic clock manipulation, or pre-computed answers.
2. Selection tokens are strictly single-use and consumed BEFORE evaluation begins.
3. Crashing or aborted evaluations consume the token without refund.
4. Independent adversarial review must attempt to falsify candidate claims.
