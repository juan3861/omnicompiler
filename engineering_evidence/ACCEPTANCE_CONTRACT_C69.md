# Acceptance Contract — Alpha-C69: ARM64 `.rodata` Relocations (`ADRP`/`LO12`), Dynamic Mach-O 64 Executables & Transitive Multi-Hop IP-SCCP

## 1. Objective
Close the remaining binary-linking and inter-procedural optimization gaps across all 6 target triples (`windows`/`linux`/`macos` x `x86_64`/`arm64`):
1. Support ARM64 `ADRP` (`ARM64_PAGE21`) and `ADD`/`LDR`/`STR` (`ARM64_LO12`) `.rodata` relocations across ELF64, Windows COFF, and macOS Mach-O 64 object ingestion, plus true target-triple assembly emission in `LLVMBackend.emit_assembly()`.
2. Support dynamic `Mach-O 64` executable (`MH_EXECUTE`) emission with `LC_LOAD_DYLINKER`, `LC_LOAD_DYLIB`, `LC_SYMTAB`, `LC_DYSYMTAB`, `LC_MAIN` entry offset, and Apple Silicon `LC_CODE_SIGNATURE` Ad-Hoc SHA-256 verification, alongside `arm64_pe` and `arm64_elf` `entry_offset` propagation.
3. Upgrade `InterProceduralSCCPPass` to multi-hop transitive fixpoint specialization + constant-return propagation + dead specialization pruning, and propagate `homeostasis_function_overrides` to `__spec_` clones while keeping them exported.

## 2. Acceptance Criteria
- `test_01_arm64_page21_lo12_rodata_relocations_across_elf_coff_and_macho`: Compiles an ARM64 kernel referencing `.rodata` LUT (`lut_load`) and C-string (`cstr_addr`) across `aarch64-unknown-linux-gnu`, `aarch64-pc-windows-msvc`, and `arm64-apple-macosx`, links behind an offset caller, and executes in Unicorn ARM64 returning exact `1107`, `1207`, `1307`, `1407`.
- `test_02_dynamic_macho_executable_and_arm64_entry_offset_audit`: Links a 2-module ARM64 macOS binary importing `printf` and `malloc` at a non-zero `entry_offset`, emits `arm64_macho`, `arm64_pe`, and `arm64_elf` executables, and passes `BinaryStructureAuditor` including `LC_DYSYMTAB`, `LC_MAIN`, `LC_CODE_SIGNATURE`, PE `AddressOfEntryPoint`, and ELF `BL` target verification.
- `test_03_multi_hop_transitive_ipsccp_and_heterogeneous_homeostasis_inheritance`: Verifies multi-hop specialization (`tier1 -> tier2`), constant-return folding (`tier2 -> 67`), dead clone pruning, override inheritance (`tier1 -> llvm`, `omni_main -> native`), Unicorn preflight, and live `ctypes.CDLL` execution returning `267`.
- `AetherMind_Strict_Auditor.py run_c69_tests.py`: `APROVADO`.
- `python -W error::ResourceWarning test_empirical_audit.py`: `14/14` gates PASSED.
- Full `unittest discover -s tests -p "test_*.py"` passes with 0 failures and 0 warnings.
