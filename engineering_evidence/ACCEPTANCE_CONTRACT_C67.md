# Acceptance Contract — Alpha-C67: Cross-Target Multi-Arch LLVM + Native + GCC Tri-Ecosystem Homeostasis

## 1. Objective
Extend `OmniRepoCompiler(backend="llvm" | "homeostasis")` to full host-independent cross-target & cross-architecture heterogeneous compilation and linking across `(windows | linux) x (x86_64 | arm64)`:
1. Lazy cached cross-target `LLVMBackend` registry (`x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `aarch64-unknown-linux-gnu`, `aarch64-pc-windows-msvc`) decoupled from host execution triple while keeping PGO differential probing host-safe.
2. Stripping ARM/AArch64 ELF & COFF mapping symbols (`$x`, `$d`, `$a`, `$t`) inside `NativeObjectLinker` (`load_elf_object` & `load_coff_object`) for collision-free cross-module ARM64 linking.
3. CLI `--homeostasis-overrides` flag exposing per-function heterogeneous emitter control directly from `omni_repo_compiler.py`.
4. Live `benchmark_heterogeneous_hybrid()` stage in `comparative_benchmark.py`.

## 2. Hard Gates
1. `OmniRepoCompiler` builds and executes a true 3-way tri-ecosystem (`hybrid:gcc+llvm+native`) ELF64 binary (`Native` -> `GCC -O3` -> Cross-Target `LLVM x86_64-unknown-linux-gnu`) via both Python API and `--homeostasis-overrides` CLI.
2. `OmniRepoCompiler` cross-compiles and formally audits Windows PE32+ (`x86_64-pc-windows-msvc`) hybrid `llvm+native` DLLs on both Linux and Windows (executing live on Windows).
3. `OmniRepoCompiler` and `NativeObjectLinker` produce valid hybrid ARM64 (`aarch64-unknown-linux-gnu` ELF64 & `aarch64-pc-windows-msvc` PE32+) binaries (`hybrid:llvm+native`), strip `$x`/`$d` mapping symbols, patch `ARM64_CALL26` cross-module calls, and pass live Unicorn AArch64 execution.
4. `AetherMind_Strict_Auditor.py` (`APROVADO`), full `unittest discover -W default`, `test_empirical_audit.py -W error::ResourceWarning` (`14/14`), and GitHub Actions CI (`ubuntu-latest` & `windows-latest`) pass 100%.
