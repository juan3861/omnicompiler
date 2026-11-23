# Acceptance Contract - Alpha-C84: x86-64 & ARM64 Machine-to-SSA Lifter

## Scope
Upgrade `validation/backend_translation_validator.py` with:
1. Pure-Python `X64MachineToSSALifter` supporting SysV/Win64 ABIs, stack frames, GPR register tracking, ALU/imm/imul/idiv/shifts/cmp/test/setcc/jcc/cmovcc, heap load/store, and Cytron-Braun CFG + PHI reconstruction.
2. Pure-Python `Arm64MachineToSSALifter` supporting AAPCS64 (`x0..x30`), `sp/x29` stack slots, `stp/ldp/ldr/str/ldur/stur`, `movz/movk/movn`, ALU/mul/msub/smulh/sdiv/shifts (`sbfm`/`ubfm`), `cset/csel`, `b/b.cond/cbz/cbnz`, and PHI reconstruction.
3. `BackendTranslationValidator.verify_ssa_to_machine_code` end-to-end verification against `SSATranslationValidator`.

## Empirical Gates
- `python -W error::ResourceWarning run_c84_tests.py` passes 100%.
- `python F:\AetherMind_Apotheosis_Final\aethermind_apotheosis\AetherMind_Strict_Auditor.py run_c84_tests.py` returns `APROVADO`.
- `python -W error::ResourceWarning test_empirical_audit.py` passes `14/14`.
- Full `unittest discover` passes 100%.
