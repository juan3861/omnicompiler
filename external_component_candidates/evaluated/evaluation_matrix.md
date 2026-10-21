# Multi-Criteria Evaluation Matrix (0 - 100)

Evaluation performed according to Phase 2.1 of the Master Protocol.

Weights:
- **W1: Architectural & Tech Compatibility (25%)**
- **W2: Functional Benefit & Performance Gain (25%)**
- **W3: Integration Friction & Adaptation Effort (20%)**
- **W4: Maturity, Testing & Maintenance (15%)**
- **W5: Security, Stability & Licensing (10%)**
- **W6: Modularity & Reversibility (5%)**

$$\text{Final Score} = 0.25 \cdot W_1 + 0.25 \cdot W_2 + 0.20 \cdot W_3 + 0.15 \cdot W_4 + 0.10 \cdot W_5 + 0.05 \cdot W_6$$

---

## Detailed Scores

| Candidate | W1 (25%) | W2 (25%) | W3 (20%) | W4 (15%) | W5 (10%) | W6 (5%) | Total Score | Status |
|---|---|---|---|---|---|---|---|---|
| **CAND-01: Tree-Sitter Polyglot Parser** | 95 | 95 | 92 | 98 | 98 | 95 | **95.25** | **APPROVED (Selected)** |
| **CAND-02: LLVM / llvmlite Native Backend** | 92 | 98 | 88 | 98 | 98 | 90 | **94.10** | **APPROVED (Selected)** |
| **CAND-03: Unicorn Virtual CPU Sandbox** | 90 | 92 | 90 | 95 | 92 | 95 | **91.80** | **APPROVED (Selected)** |
| **CAND-04: pefile & pyelftools Verifiers** | 96 | 88 | 95 | 98 | 98 | 98 | **94.60** | **APPROVED (Selected)** |
| **CAND-05: Wasmtime WebAssembly Target** | 88 | 90 | 85 | 96 | 98 | 90 | **89.90** | **APPROVED (Selected)** |
| **CAND-06: Cranelift JIT** | 80 | 85 | 70 | 82 | 90 | 85 | **81.15** | Rejected (High integration friction) |
| **CAND-07: Slither Static Analyzer** | 65 | 75 | 50 | 85 | 40 | 70 | **65.25** | Rejected (AGPL license conflict) |
| **CAND-08: Egg Rust E-Graph** | 82 | 90 | 65 | 88 | 95 | 80 | **82.40** | Deferred (Native Python egraph already present) |

---

## Approved Components for Integration

1. **CAND-01: Tree-Sitter Polyglot AST Engine** (`slicer/tree_sitter_polyglot.py` & `orchestrator/repo_manifest_ingestor.py`)
   - Replaces regex manifest/header matching with grammar-accurate AST parsing for C/C++, Rust, and Python.
2. **CAND-02: LLVM JIT & O3 Optimizing Backend** (`compiler/llvm_backend.py`)
   - Emits LLVM IR from OmniCompiler SSA, executes LLVM O3 optimization pipeline (inlining, DCE, vectorization), and outputs native machine code.
3. **CAND-03: Unicorn Engine Virtual CPU Pre-Flight Sandbox** (`validation/silicon_safety_sandbox.py`)
   - Emulates generated machine code in a sandboxed guest CPU (x86-64 / ARM) before physical `ctypes` silicon execution to guarantee zero crash risk.
4. **CAND-04: pefile & pyelftools Formal Binary Auditor** (`validation/binary_structure_auditor.py`)
   - Validates generated PE/COFF and ELF binaries for structural conformance, section headers, export tables, and relocation entries.
5. **CAND-05: Wasmtime Universal Portability Target** (`compiler/wasm_backend.py`)
   - Compiles cross-repo capsules to WebAssembly Component Model bytecode and runs them deterministically in a WASM sandbox.
