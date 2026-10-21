# SOTA Discovery Catalog — Compiler & Program Synthesis Subsystems

This catalog registers candidate open-source components discovered through multi-strategy retrieval (semantic search, dependency graph exploration, competitor feature benchmarking, and Pareto frontier analysis).

| Candidate ID | Name | Upstream Repository / Authors | Primary Focus | License | Status |
|---|---|---|---|---|---|
| CAND-01 | **Tree-Sitter Polyglot Parser** | tree-sitter / GitHub | Multi-language concrete syntax tree parsing (C, C++, Rust, Python) | MIT | Evaluated -> Selected |
| CAND-02 | **LLVM / llvmlite Backend** | numba/llvmlite & llvm-project | Industrial SSA optimization, O3 passes, and native machine code generation | BSD-2-Clause | Evaluated -> Selected |
| CAND-03 | **Unicorn CPU Sandbox** | unicorn-engine / Nguyen Anh Quynh | Isolated multi-architecture virtual CPU emulation for pre-flight machine code safety | GPL-2.0 w/ exception | Evaluated -> Selected |
| CAND-04 | **pefile & pyelftools Binary Verifiers** | erocarrera/pefile & eliben/pyelftools | Formal PE/COFF and ELF binary header, section, and relocation structure verification | MIT / Public Domain | Evaluated -> Selected |
| CAND-05 | **Wasmtime WebAssembly Engine** | bytecodealliance/wasmtime-py | Universal portable sandboxed compilation target with WASI isolation | Apache-2.0 | Evaluated -> Selected |
| CAND-06 | **Cranelift Code Generator** | bytecodealliance/wasmtime/cranelift | Low-latency JIT compiler backend | Apache-2.0 | Discovered (Research-grade) |
| CAND-07 | **Slither Static Analyzer** | crytic/slither | Static taint analysis & CFG | AGPL-3.0 | Discovered (License-restricted) |
| CAND-08 | **Egg (E-graphs Good)** | egraphs-good/egg | Fast equality saturation in Rust | MIT | Discovered (Pure Rust, wrapped via Python) |
