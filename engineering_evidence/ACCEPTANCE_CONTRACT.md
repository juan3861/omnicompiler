# ACCEPTANCE CONTRACT — SCOPE FREEZE ALPHA-C7 DISCOVERY-100
**Protocol:** MASTER PROMPT ALPHA-C7 DISCOVERY-100 (Autonomous Engineering with Independent Evidence)  
**Version:** 7.0.0 (FROZEN)  
**Mode of Execution:** `DUAL_AGENT_VERIFIED`  
- **Agent 1 (Principal Builder):** `SESSION-BUILDER-C7-c406d4a9`  
- **Agent 2 (Independent Adversarial Auditor):** `SESSION-AUDITOR-C7-46437d19`  
- **Trusted Host Runner:** `RUNNER-TRUSTED-CPYTHON311-WIN64`  
**Baseline Commit:** `d743d404d49a37a7b8e1a7ba313faea4bc01c6e1`  
**Timestamp:** `2026-10-26T04:00:00Z`  
**Audit Nonce:** `NONCE-C7-20261026-DISCOVERY100`  

---

### 1. Canonical Workspace & Baseline
- **Repository:** `F:\repository-compiler` (`omnicompiler`)
- **Remote:** `https://github.com/juan3861/omnicompiler.git` (branch `main`)
- **Initial Baseline State:** Clean working tree, 80 tests passing in 7.98s, CI 100% green on commit `d743d40`.

---

### 2. Objective, Scope Boundaries & Exclusions
- **Primary Objective:** Advance OmniCompiler under Protocol ALPHA-C7 with a systematic **DISCOVERY-100** campaign (surveying up to 100 real, canonical open-source compiler, linker, SMT, and verification repositories). Identify verified technology gaps, select candidates meeting relevance $\ge 80/100$, stage in `external_component_candidates/`, integrate high-impact minimal adaptations, and subject the system to independent adversarial audit and trusted ledger verification.
- **Explicit Exclusions:** No modifications to external directories or user files outside `F:\repository-compiler` and the designated evidence artifacts. No fabricated repository URLs or synthetic maturity scores.

---

### 3. Functional and Non-Functional Requirements (Gate Inventory)

| Requirement ID | Specification / Domain Invariant | Category | Eliminatory |
| :--- | :--- | :--- | :---: |
| `REQ-C7-01-DISCOVERY100` | Research, verify and catalog up to 100 unique, real, traceable canonical repositories with deduplication and metrics. | Research & Discovery | Yes |
| `REQ-C7-02-GAP-MAP` | Define factual `EXISTING_CAPABILITY_MAP.md` and `TECHNOLOGY_GAP_MAP.md` without selecting redundant components. | Architecture | Yes |
| `REQ-C7-03-SCORECARD` | Two-axis scoring (Relevance 0–100, Readiness 0–100) per gear; threshold $\ge 80$ for candidate staging. | Methodology | Yes |
| `REQ-C7-04-STAGING-GATE` | Verify licenses, supply chain, compatibility, and isolation before staging in `external_component_candidates/selected/`. | Security & Governance | Yes |
| `REQ-C7-05-MINIMAL-INTEG` | Implement verified minimal component adaptation addressing a concrete technology gap without regression. | Functional Correctness | Yes |
| `REQ-C7-06-UNIT-INTEG-E2E` | Full suite pass rate (80+ tests) including E2E multi-repo compilation and new component tests. | Reliability | Yes |
| `REQ-C7-07-ADVERSARIAL-FUZZ` | 100% of mutation faults killed (11/11+) and adversarial boundary tests passing. | Reliability | Yes |
| `REQ-C7-08-LEDGER-CLOSURE` | Provenance audit ledger with nonce authentication and cryptographic hash closure. | Reproducibility & Provenance | Yes |
| `REQ-C7-09-PERFORMANCE-ZERO-LEAK` | JIT latency $>100\times$ vs CPython and zero memory leaks across 100 cycles (+0.00 MB delta). | Measured Performance | Yes |
| `REQ-C7-10-DUAL-AGENT-AUDIT` | Independent audit conducted by Agent 2 subagent issuing verifiable verdict (APPROVED/REJECTED/BLOCKED). | Governance | Yes |

---

### 4. Epistemic Decision Hierarchy & Precedence
1. Any authentic eliminatory `FAIL` $\implies$ **REJECTED** immediately.
2. Any missing mandatory evidence or unverified gate $\implies$ **BLOCKED**.
3. All mandatory gates `PASS` $\implies$ Calculate score via deterministic rubric. Threshold $\ge 95.0/100 \implies$ **APPROVED**.

---

### 5. Operational Budget & Anti-Gaming Rules
- **Budget:** Max 20 minutes execution; zero API token billing (local compute + open search); max disk delta $< 50\text{ MB}$.
- **Anti-Gaming:** No mock bypasses, no hardcoded inputs, no synthetic URLs in DISCOVERY-100 catalog, no self-attestation of approval by Agent 1.
