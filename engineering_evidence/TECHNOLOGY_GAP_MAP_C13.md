# TECHNOLOGY GAP MAP — PROTOCOL ALPHA-C13
**Protocol:** MASTER PROMPT ALPHA-C13 — STATEFUL-SELECTION  
**Baseline Commit:** `2d4935a`  
**Date:** 2026-11-02  

---

### 1. Architectural Technology Gaps Identified

| Gap ID | Technical Domain | Current State (Baseline `2d4935a`) | Target Ceiling (Alpha-C13) | Impact / Risk |
| :--- | :--- | :--- | :--- | :--- |
| `GAP-C13-01` | Native String Engine | Strings are AST literals or require CPython header references. No native SSO or zero-copy slicing. | C-ABI Native String (`OmniString`) with 24-byte SSO ($\le 15$ bytes inline), heap pointer for large strings, and $O(1)$ zero-copy slice descriptors `(ptr, offset, len)`. | **High**: Enables native compilation of real-world string processing, text parsing, and protocols without CPython. |
| `GAP-C13-02` | Whole-Program ThinLTO | Repositories compile independently into object modules; cross-repo constants and leaf functions require runtime call thunks. | Inter-procedural ThinLTO summary index (`thin_lto.py`), propagating constants across repo boundaries and inlining candidate leaf functions at SSA IR level. | **High**: Eliminates call trampolines and function prologue/epilogue overhead for cross-repo interfaces. |
| `GAP-C13-03` | Stateful Selection Ledger | Benchmark peeks and evaluations were recorded post-facto; no single-use slot allocation or family-wise alpha control. | Stateful Selection Ledger (`stateful_selection_ledger.py`) allocating non-replayable tickets consumed *before* eval runs, enforcing Holm-Bonferroni family-wise error bounds. | **Medium**: Eliminates Winner's Curse and over-fitting to known benchmark inputs (Anti-Goodhart). |
| `GAP-C13-04` | Cluster Reliability & Multi-Rollouts | Evaluations ran once per test case, vulnerable to stochastic timing jitter or pseudoreplication. | Cluster-aware multi-rollouts ($k \ge 5$) across independent seeds, aggregating reliability metrics at project cluster level. | **Medium**: Proves reproducibility and eliminates pseudoreplication in stochastic benchmarks. |

---

### 2. Upstream Lineages and Reference Architectures
1. **SSO String Optimization:** LLVM libc++ `std::basic_string` (24-byte layout: discriminator bit in length/capacity byte, 15 inline chars or heap pointer/capacity/length); Rust `compact_str` (24 bytes, 24 UTF-8 bytes max SSO inline).
2. **ThinLTO Inter-Procedural Optimization:** LLVM ThinLTO (`SummaryIndex`, call-graph edge weights, import/export lists for cross-module inlining); Rust compiler `rustc_codegen_ssa` cross-crate ThinLTO.
3. **Selection Error Control:** Holm-Bonferroni step-down procedure ($\alpha / (m - i + 1)$), Benjamini-Hochberg False Discovery Rate (FDR), Neyman-Pearson randomized rollouts.
