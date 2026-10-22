# ACCEPTANCE MANIFEST — ALPHA-C3 QUALITY GATES
**Protocol:** ALPHA-C3 Consensus & Independent Adversarial Audit  
**Version:** 3.0.0 (FROZEN)  
**Baseline Commit:** `700ecbae2c7e156cadf71d3def08076ea6574bde`  
**Minimum Score Threshold:** $\ge 95/100$ (with 0 eliminatory FAIL and 0 mandatory UNKNOWN)  

---

### Scoring Weights
- **Functional Correctness:** 30 pts
- **Reliability:** 25 pts
- **Security:** 15 pts
- **Integration & Architecture:** 15 pts
- **Measured Performance:** 10 pts
- **Reproducibility & Documentation:** 5 pts
- **Total:** 100 pts

---

### Inventory of Frozen Quality Gates
| Gate ID | Name | Category | Weight | Eliminatory? | Mandatory Invariant Oracle |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GATE-01-MANIFEST-TOPO` | Ingestion & Topological Resolution | Functional Correctness | 5 pts | YES | Deterministic DAG ordering with zero cycles. |
| `GATE-02-THINLTO-SLICING` | Dead-Code Slicing | Functional Correctness | 5 pts | YES | Symbol conservation: $S_{\text{before}} = S_{\text{after}} + S_{\text{pruned}}$. |
| `GATE-03-CPG-TAINT-ISOLATION` | Code Property Graph Taint Flow | Security | 7.5 pts | YES | Zero cross-tenant dataflow paths to public sinks. |
| `GATE-04-UNIVERSAL-ABI-CEGIS` | Universal ABI & CEGIS Synthesis | Integration / Arch | 7.5 pts | YES | Windows x64 $\leftrightarrow$ System V AMD64 calling convention with stack alignment. |
| `GATE-05-MACHINE-CODEGEN-LINKING` | Native Object Linking | Functional Correctness | 10 pts | YES | REL32 & ADDR64 relocations resolved with 0 unresolved symbols. |
| `GATE-06-CROSS-TARGET-EMISSION` | Cross-Target Binary Emission | Integration / Arch | 7.5 pts | YES | Freestanding PE32+ (x86-64/ARM64) and ELF64 (x86-64/ARM64) binaries without external tools. |
| `GATE-07-SILICON-SAFETY-SANDBOX` | Pre-Flight Silicon Sandbox | Security | 7.5 pts | YES | Unicorn CPU emulation catches crashes, infinite loops, and stack faults prior to host silicon. |
| `GATE-08-FORMAL-BINARY-AUDIT` | Formal PE/ELF Structure Audit | Reliability | 10 pts | YES | Validated by pefile and pyelftools for headers, sections, and export tables. |
| `GATE-09-ADVERSARIAL-MUTATION-FUZZ` | Adversarial Fuzzing & Mutations | Reliability | 15 pts | YES | 100% of injected mutants killed; Hypothesis fuzzing passes invariants. |
| `GATE-10-PERFORMANCE-RESOURCES` | Hardware Performance & Leaks | Measured Performance | 10 pts | YES | Native JIT speedup $> 100\times$; +0.00 MB memory delta across 100 DLL Load/Free cycles. |
