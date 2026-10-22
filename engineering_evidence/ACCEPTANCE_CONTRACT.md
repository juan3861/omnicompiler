# ACCEPTANCE CONTRACT — SCOPE FREEZE ALPHA-C3
**Protocol:** Dual-Agent Evidence-Driven Engineering (ALPHA-C3 Consensus & Independent Adversarial Audit)  
**Version:** 3.0.0 (FROZEN)  
**Contract Signature:** SHA-256 (Locked at initialization)  
**Date:** 2026-10-22  

---

### 1. Canonical Workspace & Baseline Commit
- **Repository:** `F:\repository-compiler` (`omnicompiler`)
- **Initial Baseline Commit:** `700ecbae2c7e156cadf71d3def08076ea6574bde`
- **Pre-existing Local State:** Clean working tree, fully synced with `origin/main`.
- **Target Remote:** `https://github.com/juan3861/omnicompiler.git`

---

### 2. Objective, Domain, Users & Explicit Scope Boundaries
- **Primary Objective:** Upgrade OmniCompiler under Protocol ALPHA-C3 into a universal, multi-target, polyglot compiler engine capable of cross-target compilation (Windows PE32+ x86-64/ARM64 and Linux ELF64 x86-64/ARM64) for standalone executables and shared libraries, with formal silicon safety emulation, ThinLTO dead-code slicing, persistent CPG taint tracking, e-graph equality saturation, and independent adversarial falsification.
- **Domain:** Compiler Engineering, Binary Linkers (PE/COFF & ELF), SMT Refinement, Microarchitectural Superoptimization, Sandboxing (Unicorn, Wasmtime).
- **Intended Users:** Systems programmers, compiler engineers, automated code-generation agents, formal verification researchers.
- **Mandatory Capabilities:**
  1. Universal CLI (`omnicompiler_cli.py`) supporting cross-target compilation (`--format {shared_lib,executable}`, `--target-os {windows,linux}`, `--arch {x86_64,arm64}`).
  2. Multi-repository manifest ingestion with topological dependency resolution.
  3. ThinLTO program dependence graph slicing (dead-code elimination).
  4. Persistent Code Property Graph (CPG) with cross-repo taint flow tracking and tenant isolation.
  5. Universal ABI Bridge (Windows x64 $\leftrightarrow$ System V AMD64) with struct alignment and CEGIS parameter synthesis.
  6. Direct machine-code native object linking (`REL32` and `ADDR64` relocations) without external toolchains.
  7. Dual-target binary emission: PE32+ (x86-64 & ARM64) and ELF64 (x86-64 & ARM64) for both shared libraries and standalone executables.
  8. Pre-flight silicon safety validation via Unicorn CPU emulation sandbox.
  9. Formal binary specification auditor (`pefile` & `pyelftools`).
  10. Independent adversarial audit with property fuzzing, mutation fault injection, and holdout testing.
- **Explicit Scope Boundaries:** Confined strictly to `F:\repository-compiler` and the designated evidence artifacts directory. No modification of external repositories or user workspace.

---

### 3. Environment, Architecture, Interfaces & Technical Constraints
- **Execution Platform:** Windows 10/11 x64 host with cross-compilation capability for System V AMD64, Linux ELF64, Windows ARM64, and Linux ARM64.
- **Python Version:** Python 3.11 (`C:\Users\juanp\AppData\Local\Programs\Python\Python311\python.exe`).
- **Core Technology Stack:**
  - Solvers: `z3-solver` (4.13.0.0), `clingo` (5.8.2).
  - Parsing: `tree-sitter` (0.25.2), `tree-sitter-language-pack` (0.13.0), `libcst` (1.9.0).
  - Compilation & Emulation: `llvmlite` (0.47.0), `wasmtime` (49.0.0), `unicorn` (2.1.4).
  - Binary Inspection: `pefile` (2024.8.26), `pyelftools` (0.33), `pypcode` (3.3.3).
  - Property & Fuzz Testing: `hypothesis` (6.170.2).
- **Constraints:** Freestanding binary generation with zero external compiler dependencies (no GCC, Clang, or MSVC required at runtime).

---

### 4. Threat Model, Licensing, Privacy & Security
- **Licenses:** All reused components MUST be permissive open-source (MIT, Apache-2.0, BSD-2-Clause, Public Domain). AGPL and restrictive proprietary licenses are strictly rejected.
- **Supply Chain Integrity:** All third-party imports must be validated for provenance and pinned versions.
- **Sandbox Security:** Emitted machine code must undergo pre-flight execution in the Unicorn virtual CPU sandbox before physical silicon execution.
- **Tenant Isolation:** Persistent CPG must enforce mathematical separation of multi-tenant data flows (zero cross-tenant taint leaks).

---

### 5. Functional, Performance, Integrity & Resource Baseline
- **Baseline Unit Tests:** 53 unit tests passing in $< 10.0$ seconds.
- **Baseline CI Pipeline:** 100% green on Windows and Ubuntu (`39686715181`).
- **Baseline Stress Protocol:** 3 consecutive clean rounds with 0 bottlenecks, 0 malfunctions, and +0.00 MB memory delta across 100 DLL LoadLibrary/FreeLibrary cycles.
- **Baseline Latency:**
  - Native x86-64 JIT: $0.60\text{ ms}$ for 1M iterations ($279.1\times$ faster than CPython).
  - AlphaDev MCTS: $6.0\times$ to $19.0\times$ speedup on arithmetic kernels.
  - Chaitin-Briggs Graph Coloring: 0 spills with 10 variables in SSA live range.
  - Unicorn Pre-flight: $< 2.0\text{ ms}$ per function.
  - Formal PE/ELF Audit: $< 1.0\text{ ms}$ per binary.

---

### 6. Success Metrics, Tolerances & Disqualifying Criteria
- **Eliminatory Criteria (Immediate REJECTED):**
  1. Any regression in the 53 existing test suites or the CI gates.
  2. Any access violation, segmentation fault, or unhandled exception during pre-flight or host execution.
  3. Any license violation (e.g. AGPL contamination).
  4. Any fabricated benchmark, mock bypass, or self-awarded score.
- **Success Threshold:**
  - $100\%$ PASS on all mandatory functional requirements.
  - Weighted evaluation score $\ge 95/100$ awarded by the Independent Adversarial Auditor.

---

### 7. Authorized Tools & Credentials
- **Tools:** Git, Python 3.11, Unittest/Pytest, Hypothesis, GitHub CLI (`gh`), PowerShell.
- **Permissions:** Full local read/write access to `F:\repository-compiler` and artifacts directory.
- **Prohibitions:** No access or modification to private credentials, user documents, or external workspaces.

---

### 8. Operational Budget & Bounds
- **Time/Execution Budget:** Maximum 5 iterative discovery and integration loops.
- **Storage Budget:** Artifacts and candidate files bounded to $< 50\text{ MB}$.
- **Process Concurrency:** Bounded subprocesses; clean handle release (`FreeLibrary` / `close()`).

---

### 9. Mandatory Evidence Receipt Structure & Audit Independence
- **Evidence Receipt Schema:**
  - `gate_id`: Specific requirement ID from ACCEPTANCE_MANIFEST.
  - `command`: Full CLI invocation string.
  - `working_dir`: Exact execution directory.
  - `exit_code`: Numeric return code ($0 = \text{success}$).
  - `stdout_hash` / `stderr`: Captured logs and output samples.
  - `timestamp`: UTC timestamp.
- **Independence:** Agent 2 (Adversarial Auditor) executes independent property tests, mutation analysis, and state invariant checks in a dedicated subagent context with clean session lineage.
