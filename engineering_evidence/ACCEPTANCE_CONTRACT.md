# ACCEPTANCE CONTRACT — SCOPE FREEZE ALPHA-C5
**Protocol:** Dual-Agent Evidence-Driven Engineering (ALPHA-C5 Epistemic Consensus, Bound Identity & Authenticated Evidence Ledger)  
**Version:** 5.0.0 (FROZEN)  
**Intensity Classification (C5.1):** `SUBSYSTEM` Tier (Compiler Subsystem Hardening: Cryptographic Audit Ledger, Section Relocation Boundary Verification, and Nonce-Gated Provenance)  
**Audit Nonce (C5.2):** `NONCE-C5-20261023-OMNI01`  
**Builder Session ID:** `SESSION-BUILDER-C5-c406d4a9`  
**Auditor Session ID:** `SESSION-AUDITOR-C5-46437d19`  
**Trusted Runner ID:** `RUNNER-TRUSTED-CPYTHON311-WIN64`  
**Baseline Commit:** `e171684e27f67adcf997bf9b794b6cefb548c8b6`  
**Date:** 2026-10-23  

---

### 1. Canonical Workspace & Baseline Commit
- **Repository:** `F:\repository-compiler` (`omnicompiler`)
- **Initial Baseline Commit:** `e171684e27f67adcf997bf9b794b6cefb548c8b6`
- **Pre-existing Local State:** Clean working tree, fully synced with `origin/main`.
- **Target Remote:** `https://github.com/juan3861/omnicompiler.git`

---

### 2. Adaptive Intensity Tier Classification (C5.1)
- **Assigned Tier:** `SUBSYSTEM`
- **Technical Justification:** OmniCompiler's core compiler pipeline (multi-repo ingestion, slicing, persistent CPG, ABI synthesis, native code generation, PE/ELF emission, Unicorn CPU emulation, and LLVM/Wasm backends) is established and verified. The current cycle hardens the compiler with an integrated cryptographic audit ledger (`compiler/audit_ledger.py`), enforces strict section boundary invariants during object relocation (`compiler/object_linker.py`), integrates CLI audit attestation, and validates all evidence receipts through nonce-bound identity attestation under Section 8B and C5.2–C5.7.

---

### 3. Objective, Domain, Users & Explicit Scope Boundaries
- **Primary Objective:** Upgrade OmniCompiler under Protocol ALPHA-C5 to embed authenticated cryptographic audit ledgers into compiled multi-repo artifacts, harden native object linking with strict section relocation bounds, enforce formal PE/ELF section alignment invariants, and execute dual-agent adversarial falsification with inventory closure.
- **Domain:** Compiler Engineering, Binary Linkers (PE/COFF & ELF), Cryptographic Provenance Ledgers, SMT Refinement, Sandboxing (Unicorn, Wasmtime).
- **Intended Users:** Systems programmers, compiler engineers, automated code-generation agents, formal verification researchers.
- **Mandatory Capabilities (11 Gates):**
  1. `GATE-01-MANIFEST-TOPO`: Multi-repo manifest ingestion with topological dependency resolution.
  2. `GATE-02-THINLTO-SLICING`: Inter-repository dead-code slicing with symbol conservation.
  3. `GATE-03-MACHINE-CODEGEN-LINKING`: Native object linking and relocation with strict boundary checks.
  4. `GATE-04-FORMAL-BINARY-AUDIT`: Formal PE/ELF structure and section alignment verification (`pefile`, `pyelftools`).
  5. `GATE-05-ADVERSARIAL-MUTATION-FUZZ`: Independent adversarial mutation testing (11/11 mutants killed) & Hypothesis fuzzing.
  6. `GATE-06-CPG-TAINT-ISOLATION`: Persistent Code Property Graph tenant isolation and taint tracking.
  7. `GATE-07-SILICON-SAFETY-SANDBOX`: Pre-flight silicon safety sandbox via Unicorn CPU emulation.
  8. `GATE-08-UNIVERSAL-ABI-CEGIS`: Universal ABI Bridge (Windows x64 $\leftrightarrow$ System V AMD64) with CEGIS parameter synthesis.
  9. `GATE-09-CROSS-TARGET-EMISSION`: Direct machine-code emission for PE32+ (x86-64/ARM64) and ELF64 (x86-64/ARM64) shared libraries and executables.
  10. `GATE-10-PERFORMANCE-RESOURCES`: Microarchitectural benchmark (>100x speedup vs CPython, 0 memory leaks across 100 cycles).
  11. `GATE-11-CRYPTO-AUDIT-LEDGER`: Embedded cryptographic audit ledger with HMAC/SHA-256 signatures, nonce verification, and CLI audit attestation.
- **Explicit Scope Boundaries:** Confined strictly to `F:\repository-compiler` and the engineering evidence artifacts.

---

### 4. Environment, Architecture, Interfaces & Technical Constraints
- **Execution Platform:** Windows 10/11 x64 host with cross-compilation capability for System V AMD64, Linux ELF64, Windows ARM64, and Linux ARM64.
- **Python Version:** Python 3.11 (`C:\Users\juanp\AppData\Local\Programs\Python\Python311\python.exe`).
- **Core Technology Stack:**
  - Solvers: `z3-solver` (4.13.0.0), `clingo` (5.8.2).
  - Emulators & Sandboxes: `unicorn` (2.1.4), `wasmtime` (49.0.0).
  - Code Generation: `llvmlite` (0.47.0), direct x86-64/AArch64 machine-code emitter.
  - Binary Parsers: `pefile` (2024.8.26), `pyelftools` (0.33).
  - Fuzzing & Property Testing: `hypothesis` (6.170.2).
  - Cryptography: `hashlib`, `hmac` (SHA-256).

---

### 5. Scoring Weights & Strict Precedence (ALPHA-C4 Section 8B & ALPHA-C5 C5.4)
- **Weight Distribution (Total 100 points):**
  - Functional Correctness: 30 pts (Gates 1, 2, 3)
  - Reliability: 25 pts (Gates 4, 5)
  - Security: 15 pts (Gates 6, 7)
  - Integration & Architecture: 15 pts (Gates 8, 9)
  - Measured Performance: 10 pts (Gate 10)
  - Reproducibility & Documentation: 5 pts (Gate 11)
- **Approval Threshold:** Total Score $\ge 95.0 / 100$.
- **Strict Precedence Rule:**
  1. Any authentic eliminatory `FAIL` $\implies$ **REJECTED** immediately.
  2. Any unverified or missing mandatory gate $\implies$ **BLOCKED**.
  3. Only with all 11 gates at verified `PASS` $\implies$ Calculate score via deterministic formula:
     $$\text{Final Score} = \sum_{i=1}^{11} (\text{Gate Pass}_i \times \text{Weight}_i)$$
  4. If $\text{Final Score} \ge 95.0 \implies$ **APPROVED**.

---

### 6. Inventory Closure (C5.3) & Authenticated Evidence Chain (C5.2)
- All evidence receipts must be generated with `audit_nonce = "NONCE-C5-20261023-OMNI01"`.
- Every gate must have a closed receipt in `EVIDENCE_LEDGER.md`.
- No cherry-picking PASS receipts. Any legitimate failure in an eliminatory gate forces REJECTED.
- Receipts must bind:
  - `gate_id`
  - `status` (`PASS`, `FAIL`, `UNKNOWN`)
  - `audit_nonce`
  - `session_id`
  - `runner_id`
  - `verified`: literal `True` (boolean)
  - `trusted_runner`: literal `True` (boolean)
  - `artifact_hash` (SHA-256)
  - `timestamp_iso`

---

### 7. Governance, Anti-Gaming & Budget
- **Dual-Agent Isolation:** Builder (Agent 1) implements features and local verification (`LOCAL_TEST_PASS`). Independent Adversarial Auditor (Agent 2 - Subagent) independently validates, runs adversarial mutations, and issues binding verdict (`APPROVED` / `REJECTED` / `BLOCKED`).
- **Anti-Gaming:** No mock bypasses, no hardcoded benchmark inputs, no altered timeouts, no self-attested score by Agent 1.
- **Budget Ceiling:** Max 15 minutes test execution, zero cost API tokens (local compute).
