# Acceptance Contract — Alpha-C70: Mach-O 64 Dynamic `dyld` Bindings & Inter-Procedural `f64` SCCP

## 1. Objective
1. Emit `__DATA,__got` pointer slots, `LC_DYLD_INFO_ONLY` (`0x80000022`) bind opcodes for `/usr/lib/libSystem.B.dylib`, and patched `FF 25` (x86-64) / `ADRP+LDR+BR` (ARM64) import stubs in Mach-O 64 executables (`macho64`, `arm64_macho`), audited by `BinaryStructureAuditor`.
2. Extend `SCCPPass` and `InterProceduralSCCPPass` to fold and specialize IEEE-754 `f64` constants (`fconst`, `fneg`, `fadd`, `fsub`, `fmul`, `fdiv`, `fcmp_*`, `sitofp`, `fptosi`) across repositories while preserving `SSAVar.var_type == "f64"` for Z3 translation validation.

## 2. Acceptance Criteria
- `test_01_macho64_x86_64_and_arm64_dyld_bind_opcodes_and_got_patching`: Verifies `__DATA.__got`, `LC_DYLD_INFO_ONLY` bind symbols `["malloc", "printf"]`, patched `FF 25` / `ADRP X16` stubs, and SHA-256 `LC_CODE_SIGNATURE` on ARM64.
- `test_02_f64_sccp_and_multi_hop_interprocedural_specialization`: Verifies multi-hop `f64` call-site specialization (`f_top -> f_mid -> f_leaf`), constant-return folding (`const 9.5`), dead clone pruning, and MCJIT execution (`f_top(10) == 19`).
- `test_03_omnirepo_e2e_f64_ipsccp_heterogeneous_homeostasis`: Verifies end-to-end `OmniRepoCompiler` cross-repo `f64` specialization under `backend="homeostasis"` (`llvm` + `native`), Unicorn preflight (`42`), and live `ctypes.CDLL` execution (`fn(10) == 42`, `fn(5) == 22`).
- `AetherMind_Strict_Auditor.py run_c70_tests.py`: `APROVADO`.
- `python -W error::ResourceWarning test_empirical_audit.py`: `14/14` gates PASSED.
- Full `unittest discover -s tests -p "test_*.py"` passes with 0 failures and 0 warnings.
