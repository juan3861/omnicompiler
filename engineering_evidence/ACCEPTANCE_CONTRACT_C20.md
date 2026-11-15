# ACCEPTANCE CONTRACT ALPHA-C20
## Inter-Procedural SCCP, Global Value Numbering (GVN) & Call-Site Function Specialization

- **Contract ID:** CONTRACT-ALPHA-C20-IPSCCP-GVN
- **Revision:** 1.0.0
- **Status:** FROZEN
- **Author:** AetherMind Apotheosis (Builder / Formal Verifier)
- **Target Repository:** `F:\repository-compiler` (remote `https://github.com/juan3861/omnicompiler.git`, branch `main`)

---

### 1. Requirements & Invariants

| ID | Category | Requirement Description | Gate Status |
|---|---|---|---|
| REQ-C20-01 | Global Value Numbering (GVN) | Provide `GlobalValueNumberingPass` using Dominator-Tree Scoped Hash Tables over SSA IR. Must canonicalize commutative operations (`add`, `mul`, `and`, `or`, `xor`, `cmp_eq`, `cmp_ne`) and eliminate redundant computations across the same block and dominated successor blocks. | REQUIRED |
| REQ-C20-02 | Sparse Conditional Constant Propagation (SCCP) | Provide `SCCPPass` implementing 3-level lattice (`TOP`, `CONSTANT(v)`, `BOTTOM`), folding constant `br_cond` terminators into unconditional `br`, pruning dead unreachable CFG blocks, and simplifying `phi` nodes whose incoming edges become unreachable. | REQUIRED |
| REQ-C20-03 | Inter-Procedural SCCP & Call-Site Specialization | Provide `InterProceduralSCCPPass` / `CallSiteSpecializer` that propagates constant arguments across call sites, clones target functions with constant parameters bound (`fn__spec_<args>`), optimizes the specialized clone (folding branches & strength reduction), and rewrites the call site. | REQUIRED |
| REQ-C20-04 | Compiler Integration | Integrate GVN, SCCP, and Call-Site Specialization into `omni_repo_compiler.py`, reporting `gvn_eliminated_exprs`, `sccp_folded_branches`, and `specialized_functions` in `stages["codegen"]`. | REQUIRED |
| REQ-C20-05 | Native Execution Correctness | Specialized and GVN-optimized functions must compile cleanly to x86-64/ARM64 machine code and produce bit-identical execution results in W^X JIT / AOT binaries. | REQUIRED |
| REQ-C20-06 | Regression & CI | 100% test pass rate across `run_full_regression.py`, `AetherMind_Strict_Auditor.py`, and GitHub Actions CI (Ubuntu & Windows). | REQUIRED |

---

### 2. Invariants & Guardrails
- **INV-01 (Dominance Soundness):** GVN must only reuse a value number if the defining instruction's block strictly dominates the target block (enforced via scoped symbol tables during dominator-tree DFS traversal).
- **INV-02 (Side-Effect Safety):** Instructions with side effects (`call`, `store`, `ret`, `br`, `br_cond`, `param`, `alloca`, `load`) must never be eliminated or merged by GVN.
- **INV-03 (CFG Integrity on Branch Pruning):** When SCCP folds a `br_cond` to `br`, predecessor/successor edges and `phi_incoming` lists in target blocks must be updated atomically so no dangling phi references remain.
- **INV-04 (Recursion & Clone Budget Guard):** Call-site specialization must enforce a deterministic clone budget and avoid infinite specialization on recursive constant-stepping calls.
