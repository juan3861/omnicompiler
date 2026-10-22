# UNVERIFIED CLAIMS REGISTER (ALPHA-C3)
**Protocol:** ALPHA-C3 Epistemic Hygiene & Radical Truth Protocol  
**Version:** 3.0.0  
**Date:** 2026-10-22  

---

### Audit Policy
Any claim that has not been directly validated through physical execution, virtual silicon emulation (Unicorn), or bit-level formal specification inspection (pefile/pyelftools) is recorded here and classified as `NOT_VERIFIED` or `UNKNOWN`.

---

### Unverified Claims & Explicit Boundaries

| Claim ID | Claim Description | Current Status | Limitation / Reason |
| :--- | :--- | :--- | :--- |
| `CLAIM-01` | Physical Silicon Execution on Native ARM64 Host | **NOT VERIFIED ON PHYSICAL ARM64 SILICON** (Emulation & Formal Header Verified) | The execution platform is an Intel x86-64 CPU (`Intel Core i7-8700`). ARM64 binaries are structurally audited via `pefile` (Machine `0xAA64`) and `pyelftools` (Machine `183`, `EM_AARCH64`), and instruction encodings are mathematically verified, but physical execution on native ARM64 silicon requires an AArch64 host. |
| `CLAIM-02` | Native Linux Syscall Physical Execution on Bare-Metal Windows | **NOT VERIFIED ON NATIVE LINUX HOST** (Virtual & Binary Specification Verified) | Emitted Linux ELF64 standalone executables and `.so` shared libraries are formally audited with `pyelftools` (ELF magic, 64-bit, little-endian, `ET_EXEC`, sections `.text`), but cannot be executed bare-metal directly by the Windows NT kernel without WSL or Linux host. |
| `CLAIM-03` | Universal AST Parsing for C++ Templates & Macros | **OUT OF SCOPE / BOUNDED** | Tree-Sitter polyglot parser extracts functions, prototypes, and structs in C, Rust, and Python. Full macro expansion and C++ template instantiation are not handled in this release. |

---

### Epistemic Summary
- **Verified Claims:** 10/10 Mandatory Gates in `ACCEPTANCE_MANIFEST.json` are verified with physical receipts on host silicon, virtual CPU, or formal parsers.
- **Unverified Claims:** Zero unverified claims disguised as verified facts. All hardware limitations are explicitly documented.
