# Acceptance Contract - Alpha-C88: RISC-V 64 Backend, SPIR-V GPU Emitter & GDB DWARF v5

## Scope
1. Create `compiler/riscv64_codegen.py` (`Riscv64CodeGenerator` LP64 RV64IM) and wire `arch="riscv64"` in `NativeCodeGenerator`.
2. Add `build_riscv64_elf` (`e_machine = 0xF3`) and `riscv64_elf` / `spirv` targets to `StandaloneBinaryEmitter`, plus `EM_RISCV` in `BinaryStructureAuditor`.
3. Create `compiler/spirv_emitter.py` emitting Khronos SPIR-V 1.5 binary word streams (`0x07230203`) with embedded word-stream validator.
4. Bind `DW_AT_stmt_list` into `DwarfV5Emitter.emit_debug_info_with_subprograms` and verify real `gdb --batch` + `readelf` parsing on Ubuntu CI.

## Empirical Gates
- `python -W error::ResourceWarning run_c88_tests.py` executes RV64 code & ELF `ecall` in Unicorn RISC-V64 and passes 100%.
- `AetherMind_Strict_Auditor.py run_c88_tests.py` -> `APROVADO`.
- Full audit, full regression suite, and 4/4 GitHub Actions runners (including Ubuntu `gdb --batch` DWARF v5 check) green.
