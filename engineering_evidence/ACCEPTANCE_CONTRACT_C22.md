# ACCEPTANCE CONTRACT ALPHA-C22
## Tail-Call Optimization (TCO), Hot/Cold Basic-Block Layout & Peephole Machine Optimizer

- **Contract ID:** CONTRACT-ALPHA-C22-TCO-LAYOUT-PEEPHOLE
- **Revision:** 1.0.0
- **Status:** FROZEN
- **Author:** AetherMind Apotheosis (Builder / Formal Verifier)
- **Target Repository:** `F:\repository-compiler` (remote `https://github.com/juan3861/omnicompiler.git`, branch `main`)

---

### 1. Requirements & Invariants

| ID | Category | Requirement Description | Gate Status |
|---|---|---|---|
| REQ-C22-01 | Tail-Call Optimization (TCO) | Provide `TailCallOptimizationPass` detecting self-tail-recursive `call <fn>(args); ret res` patterns in SSA IR and lowering them into $O(1)$ stack loops via `tco_header` with `phi` parameter updates and `br tco_header`. | REQUIRED |
| REQ-C22-02 | Deep Recursion Silicon Proof | TCO-transformed tail-recursive functions (e.g., `sum_tail(100000, 0)`) must execute in W^X x86-64 `NativeJitCompiler` without stack overflow and return exact results. | REQUIRED |
| REQ-C22-03 | Hot/Cold Basic-Block Layout | Provide `BlockLayoutPass` ordering CFG blocks by loop-depth/PGO hotness while keeping `entry` first and maximizing fallthrough adjacency. | REQUIRED |
| REQ-C22-04 | Peephole Machine Optimizer | Provide `PeepholeMachineOptimizer` eliminating zero-offset fallthrough `jmp rel32` (`E9 00 00 00 00`) and redundant self-moves (`mov reg, reg`) in emitted x86-64 machine code. | REQUIRED |
| REQ-C22-05 | Compiler Integration | Integrate TCO, BlockLayout, and Peephole into `omni_repo_compiler.py`, reporting `tco_converted_calls`, `reordered_blocks`, and `peephole_bytes_saved` in `stages["codegen"]`. | REQUIRED |
| REQ-C22-06 | Regression & CI | 100% pass rate on `run_c22_tests.py`, `run_full_regression.py`, `AetherMind_Strict_Auditor.py`, and GitHub Actions CI (Ubuntu & Windows). | REQUIRED |

---

### 2. Invariants & Guardrails
- **INV-01 (Tail Position Strictness):** Only transform `call` instructions immediately followed by `ret` (either returning the call's result directly or void) with matching parameter arity.
- **INV-02 (Entry Block Preservation):** `BlockLayoutPass` must always keep `fn.entry_block` at index 0 of `fn.blocks` and preserve all CFG edges.
- **INV-03 (Machine Code Relocation Safety):** `PeepholeMachineOptimizer` must only strip zero-offset `E9 00 00 00 00` or self-moves when no internal branch displacement is invalidated (or adjust/report safely on standalone sequences without internal relocations).
