# Acceptance Contract - Alpha-C87: Apple Silicon Mach-O Dylib Native Execution

## Scope
Upgrade `compiler/binary_emitter.py`, `omni_repo_compiler.py`, `benchmarks/industrial_top1_suite.py`, and `.github/workflows/ci.yml`:
1. `StandaloneBinaryEmitter.build_macho64_dylib` emits `LC_DYLD_INFO_ONLY` ULEB128 export trie (`0x80000022`), `LC_DYSYMTAB` (`0x0B`), `LC_BUILD_VERSION` (`0x32`), and XNU ad-hoc `LC_CODE_SIGNATURE` (`0x1D`) compatible with macOS `dyld4` `dlopen()` / `ctypes.CDLL`.
2. `OmniRepoCompiler` and `industrial_top1_suite.py` detect `darwin/arm64` natively and emit/execute `arm64_macho_dylib`.
3. `verify-macos-arm64` CI job runs `run_c87_tests.py` executing `ctypes.CDLL` natively on Apple Silicon hardware.

## Empirical Gates
- `python -W error::ResourceWarning run_c87_tests.py` passes 100%.
- `python F:\AetherMind_Apotheosis_Final\aethermind_apotheosis\AetherMind_Strict_Auditor.py run_c87_tests.py` -> `APROVADO`.
- Full audit & regression suite pass, plus 4/4 CI runners green.
