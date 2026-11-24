# Acceptance Contract: Alpha-C95 (Dynamic Shared-Library OS Linking & Expanded Polyglot OSS Subset)

## Objective
1. Upgrade shared-library emission (`PE64 .dll`, `ELF64 x86_64/arm64 .so`, `Mach-O 64 arm64 .dylib`) to emit compliant OS dynamic import tables (`.idata` / `DT_NEEDED` + `.got.plt` + `.rela.plt` / `LC_LOAD_DYLIB` + `LC_DYLD_INFO_ONLY` + Ad-Hoc CodeSign) wired from `NativeObjectLinker.emit_linked_shared_library` and `OmniRepoCompiler`.
2. Expand the polyglot AOT frontend (`frontends/polyglot_ssa_lowering.py`), `AstToSsaLowering`, and `StackPromotionPass` for real OSS idioms across Rust, Go, TypeScript, and C:
   - Fixed local array literals (`[...]`, `[val; N]`, Go `[]int64{...}`, C `T arr[N] = {...}`) and `.len()`/`.length`.
   - Stack-promoted local structs & struct literals (`Point { x, y }`, `Box{...}`, `const p: Pair = {...}`, `struct Vec2 v = {...}`) with C-ABI field offsets.
   - Inline closures and lambdas (`|k| ...`, `(z) => ...`, `func(k int64) int64 { ... }`).
   - Cross-module `import` / `use` / `#include` tracking and module-qualified cross-repo calls.

## Non-Negotiable Acceptance Gates
1. `python -W error::ResourceWarning run_c95_tests.py` exits `0` with all tests passing (including live `ctypes.CDLL` host execution calling dynamically imported `malloc`/`free` and cross-platform binary format verification via `pefile`, `pyelftools`, and Mach-O auditor).
2. `python F:\AetherMind_Apotheosis_Final\aethermind_apotheosis\AetherMind_Strict_Auditor.py run_c95_tests.py` exits `0` (`APROVADO`).
3. `python -W error::ResourceWarning test_empirical_audit.py` exits `0` (`14/14 PASS`).
4. Full repository test suite `python -W default -m unittest discover -s tests -p "test_*.py"` passes with zero failures or unexpected errors.
