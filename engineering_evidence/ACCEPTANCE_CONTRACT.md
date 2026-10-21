# ACCEPTANCE CONTRACT — SCOPE FREEZE V2
**Protocol:** Dual-Agent Evidence-Driven Engineering  
**Version:** 2.0.0 (FROZEN)  
**Contract Signature:** SHA-256 (Locked at initialization)  
**Date:** 2026-10-21  

---

### 1. Canonical Workspace & Baseline Commit
- **Repository:** `F:\repository-compiler` (`omnicompiler`)
- **Initial Baseline Commit:** `b0e8d3299e0dddff994e9d6f443dd42348a05969`
- **Pre-existing Local State:** Working tree clean, synced with `origin/main`.
- **Target Remote:** `https://github.com/juan3861/omnicompiler.git`

---

### 2. Objective, Domain, Users & Explicit Scope Boundaries
- **Primary Objective:** Transform OmniCompiler into a provably robust, self-verifying, polyglot inter-repository compiler engine with automated dead-code program dependence slicing, property-based fuzzing verification, and high-performance cross-language binary linking.
- **Domain:** Compiler Engineering, Program Synthesis (CEGIS / SMT), Binary Linkers (COFF/ELF), Sandboxing (Unicorn, Wasmtime), Polyglot Parsing (Tree-Sitter).
- **Intended Users:** Systems engineers, compiler researchers, security auditors, automated synthesis frameworks.
- **Mandatory Capabilities:**
  1. Multi-repository manifest ingestion with dependency DAG resolution.
  2. Persistent Code Property Graph (CPG) with cross-repo call edges and taint flow tracking.
  3. Universal ABI Bridge (Windows x64 $\leftrightarrow$ System V AMD64) with struct alignment.
  4. Native object file linking with `REL32` and `ADDR64` relocations.
  5. SOTA compilation backends (LLVM O3 JIT, Wasmtime WASM).
  6. Pre-flight silicon safety validation via Unicorn CPU emulation sandbox.
  7. Formal binary structure auditor (`pefile` & `pyelftools`).
  8. Independent adversarial fuzzing and mutation audit suite.
- **Explicit Scope Boundaries:** Scope is strictly confined to `F:\repository-compiler`. No external workspaces or unauthorized system files may be modified.

---

### 3. Environment, Architecture, Interfaces & Technical Constraints
- **Execution Platform:** Windows 10/11 x64 host with cross-compilation capability for System V AMD64, Linux ELF64, and ARM64.
- **Python Version:** Python 3.11 (`C:\Users\juanp\AppData\Local\Programs\Python\Python311\python.exe`).
- **Core Technology Stack:**
  - Solvers: `z3-solver` (4.13.0.0), `clingo` (5.8.2).
  - Parsing: `tree-sitter` (0.25.2), `tree-sitter-language-pack` (0.13.0), `libcst` (1.9.0).
  - Compilation & Emulation: `llvmlite` (0.47.0), `wasmtime` (49.0.0), `unicorn` (2.1.4).
  - Binary Inspection: `pefile` (2024.8.26), `pyelftools` (0.33), `pypcode` (3.3.3).
  - Property & Fuzz Testing: `hypothesis` (6.170.2).
- **Constraints:** Zero reliance on external compilers (GCC, Clang, MSVC) at runtime; freestanding direct binary emission.

---

### 4. Threat Model, Licensing, Privacy & Security
- **Licenses:** All reused components MUST be permissive open-source (MIT, Apache-2.0, BSD-2-Clause, Public Domain). AGPL and proprietary restrictive licenses are strictly rejected.
- **Supply Chain Integrity:** All third-party imports must be validated for provenance and pinned versions.
- **Sandbox Security:** All emitted machine code must be tested in the Unicorn virtual CPU sandbox before physical host silicon execution to prevent `SIGSEGV` or arbitrary memory corruption.
- **Tenant Isolation:** Persistent CPG must enforce mathematical separation of multi-tenant data flows (zero cross-tenant taint leaks).

---

### 5. Functional, Performance, Integrity & Resource Baseline
- **Baseline Unit Tests:** 27 test suites passing in $< 1.0$ second.
- **Baseline CI Pipeline:** 9 quality gates passing 100% on Windows and Ubuntu.
- **Baseline Latency:**
  - LLVM O3 JIT: $0.0036\text{ ms}$ for 100k loop iterations.
  - Tree-Sitter AST: $19.77\text{ ms}$ for 400 prototypes.
  - Unicorn Pre-flight: $1.775\text{ ms}$ per function.
  - Formal PE Audit: $0.582\text{ ms}$ per binary.

---

### 6. Success Metrics, Tolerances & Disqualifying Criteria
- **Eliminatory Criteria (Immediate REJECTED):**
  1. Any regression in the 27 existing test suites or the 9 CI gates.
  2. Any access violation or host process crash during pre-flight emulation or execution.
  3. Any license violation (e.g. AGPL contamination).
  4. Any fabricated benchmark or fake test mock.
- **Success Threshold:**
  - $100\%$ PASS on all mandatory functional requirements.
  - Weighted evaluation score $\ge 95/100$ awarded by the Independent Adversarial Auditor.

---

### 7. Authorized Tools & Credentials
- **Tools:** Git, Python 3.11, Pytest/Unittest, GitHub CLI (`gh`), PowerShell.
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
  - `command`: Full CLI invocation string.
  - `working_dir`: Exact execution directory.
  - `exit_code`: Numeric return code ($0 = \text{success}$).
  - `stdout_hash` / `stderr`: Captured logs and output samples.
  - `timestamp`: UTC timestamp.
- **Independence:** Agent 2 (Adversarial Auditor) executes independent property tests, mutation analysis, and state invariant checks in a dedicated subagent context.

---

### 10. Convergence, Rollback & Escalation Conditions
- **Rollback Trigger:** If any new integration breaks existing CI gates or introduces irrecoverable regressions, git checkpoint rollback (`git restore` / `git reset`) is mandatory.
- **Convergence Criteria:** When all identified gaps are resolved, adversarial mutation score is $\ge 90\%$, and 3 consecutive discovery rounds yield zero unaddressed high-impact candidates.
