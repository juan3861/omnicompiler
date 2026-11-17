# ACCEPTANCE CONTRACT — Alpha-C36

**Date:** 2026-11-17  
**Milestone:** Alpha-C36  
**Scope:** Multi-Way `match` / `switch` Pattern Lowering (`Python ast.Match`, `Rust match`, `Go/TS switch`) & Static `.rodata` Constant Lookup Tables (`LUT`s) Across All 4 Backends + Z3 `QF_ABVFP` Translation Validation

---

## Frozen Deliverables & Verification Criteria

1. **Multi-Way `match` / `switch` Pattern Lowering (`compiler/ssa_ir.py`, `frontends/polyglot_ssa_lowering.py`):**
   - Lower Python `ast.Match` (`MatchValue`, `MatchOr`, `MatchAs` wildcard/binding, optional `guard`) cleanly into SSA CFG blocks (`cmp_eq` / `fcmp_eq`, `br_cond`, `merge_bb`).
   - Parse Rust `match expr { pat1 | pat2 => ..., _ => ... }` (including `return match ...` and multi-stmt arms), Go `switch expr { case a, b: ... default: ... }`, and TypeScript `switch (expr) { case a: case b: ... break; default: ... }` into `ast.Match`.

2. **Static `.rodata` Constant Lookup Tables (`SSAFunction.luts` / `lut_load`):**
   - Extract top-level constant LUT definitions (`LUT = [v0, v1, ...]`, `pub const LUT: [T; N] = [...]`, Go `var`/`const LUT = [N]T{...}`, TS `const LUT = [...]`) in Python & Polyglot modules.
   - Emit real target `.rodata`:
     - `X64CodeGenerator`: trailing `.rodata` table after `ret`, accessed via `lea r11, [rip + .L_ro_<name>]` + indexed load (`code_end_offset` preserved on `CompiledFunctionArtifact` for `AssemblyInvariantAuditor`).
     - `Arm64CodeGenerator`: literal `.rodata` pool after `RET`, accessed via `ADR X9, #imm` + indexed load (`LDR X11`/`LDR D0`/`LDRSW`/`LDR S0`).
     - `LLVMBackend`: module-level `private unnamed_addr constant [N x <ty>]` + `getelementptr` + `load`.
     - `WasmBackend`: real `(data (i32.const 245760) ...)` linear memory segment + indexed loads.
     - `SSATranslationValidator` (`QF_ABVFP`) + `LLVMIRToSSALifter` + `WATToSSALifter`: symbolic `z3.If` chain equivalence across SSA <-> LLVM <-> WAT.

3. **Mandatory Verification Gates (Pass Criteria):**
   - `tests/test_alpha_c36_match_switch_and_rodata_luts.py` via `run_c36_tests.py`:
     1. Python `match` + `.rodata` `f64` LUT dispatch proven equivalent across `Z3 QF_ABVFP` (LLVM + WAT) and executed with bit-exact parity (`Native x86_64 == LLVM MCJIT == Wasmtime`).
     2. ARM64 Unicorn execution combining multi-way `match` dispatch + `.rodata` constant array indexing (`ADR` literal pool + `FADD`/`LDRSW`).
     3. Multi-repo Polyglot `Rust match` + `Go switch` + `TS switch` + `.rodata` LUT fusion via `OmniRepoCompiler` (`native`, `llvm`, `wasm`, `refuted == 0`, Wasmtime execution).
     4. W^X Native JIT dispatch computing dynamic scores from `.rodata` LUT + host C `libc` FFI integration.
   - `AetherMind_Strict_Auditor.py` returns `APROVADO` on `run_c36_tests.py` and `run_full_regression.py`.
   - `python -W default -m unittest discover -s tests -t F:\repository-compiler` passes 100% (226/226 tests, 0 warnings).
