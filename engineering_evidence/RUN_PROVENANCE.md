# RUN PROVENANCE RECORD (ALPHA-C3)
**Protocol:** ALPHA-C3 Governance & Provenance Tracking  
**Version:** 3.0.0  
**Date:** 2026-10-22  

---

### Session & Execution Provenance

- **Orchestrator Session ID:** `c406d4a9-0136-4cdd-8cd9-db340e5067bb`
- **Builder Role:** Agent 1 (Principal Builder / Research Engineer)
- **Auditor Role:** Agent 2 (Independent Adversarial Auditor) — Isolated subagent
- **Auditor Subagent Conversation ID:** `cbee0e80-0049-4b1d-90ff-c8eb44bc83b0` (fresh subagent invocation)
- **Execution Host:** Windows 10/11 x64 (Build 26100), Intel Core i7-8700 CPU @ 3.20GHz
- **Host Python Executable:** `C:\Users\juanp\AppData\Local\Programs\Python\Python311\python.exe`
- **Git Commit Baseline:** `700ecbae2c7e156cadf71d3def08076ea6574bde`
- **Target Repository Path:** `F:\repository-compiler`
- **Target Remote:** `https://github.com/juan3861/omnicompiler.git`

---

### Tool & Dependency Verification Matrix

| Tool / Subsystem | Installed Version | License | Integrity Verification |
| :--- | :--- | :--- | :--- |
| `python` | 3.11.9 (64-bit) | PSF License | Verified via sys.version |
| `z3-solver` | 4.13.0.0 | MIT | Verified via `z3.get_version()` |
| `unicorn` | 2.1.4 | GPL-2.0 w/ Exception | Verified via `unicorn.Uc` |
| `llvmlite` | 0.47.0 | BSD-2-Clause | Verified via `llvmlite.binding` |
| `wasmtime` | 49.0.0 | Apache-2.0 | Verified via `wasmtime.Engine` |
| `pefile` | 2024.8.26 | MIT | Verified via `pefile.PE` |
| `pyelftools` | 0.33 | Public Domain | Verified via `elftools.elf.elffile` |
| `hypothesis` | 6.170.2 | MPL-2.0 | Verified via `hypothesis.given` |
| `git` | 2.45.2.windows.1 | GPL-2.0 | Verified via `git --version` |

---

### Audit Independence Guarantee
In accordance with ALPHA-C3 Section C1, C5, and 8A.4, Agent 2 has not co-authored the implementation, and independently executes its own adversarial falsification harness with strict separation of concerns.
