# Acceptance Contract — Alpha-C66: Heterogeneous Per-Function Linking, WASM Linear-Memory Libc & Zero-Warning Hygiene

## 1. Objective
Advance `OmniCompiler` (`F:/repository-compiler`) across three remaining engineering frontiers:
1. **True Heterogeneous Per-Function Hybrid Linking** inside `OmniRepoCompiler(backend="homeostasis")`, partitioning individual functions within/across repositories across GNU GCC `-O3`, LLVM 20.1.8 `-O3`, and Omni Native (`x86_64` AVX2/AVX-512 / `arm64`) and linking all relocatable objects together into a single verified native PE64 or ELF64 binary.
2. **Wasmtime Linear-Memory Libc/Heap & Host Stdio Bridge** inside `WasmBackend` + `HomeostasisRouter`, enabling full standalone programs calling `malloc`, `calloc`, `realloc`, `free`, `memcpy`, `memmove`, `memset`, `strlen`, `strcmp`, `abs`, `labs`, `puts`, `putchar`, and variadic `printf` to compile, run in Wasmtime with automatic `memory.grow`, and reach bit-exact 4-engine consensus alongside Native JIT, LLVM 20, and GCC.
3. **Host-Adaptive 8-Lane AVX-512 Vectorizer Wiring, GCC `-O3` Frame-Pointer Audit Precision & Zero-Warning Hygiene**, eliminating all `ResourceWarning`s in `test_empirical_audit.py` and ensuring accurate GCC `-O3` YMM-aligned epilogue validation without weakening adversarial mutation killing.

## 2. Hard Gates
1. `OmniRepoCompiler(backend="homeostasis")` produces true multi-emitter executables and shared libraries (`heterogeneous_link=True`, `binary_emitter_engine="hybrid:..."`), verified both with explicit `homeostasis_function_overrides` AND autonomously from `HomeostasisProfileStore` PGO signatures across cross-calling functions (`Native <-> LLVM <-> GCC`).
2. `WasmBackend.run_ssa_with_memory` and `HomeostasisRouter.execute_differential` compile and reach bit-exact multi-engine consensus (`native`, `llvm`, `gcc`, `wasm`, zero isolated engines) on functions invoking `malloc`, `calloc`, `realloc`, `free`, `memset`, `memcpy`, `memmove`, `abs`, `strlen`, `strcmp`, and variadic `printf` (with captured stdout).
3. `LoopVectorizerPass().vectorize_vla_function(..., target_isa="AVX512_512")` unrolls 8 contiguous `f64` FMA lanes triggering `X64CodeGenerator` 512-bit EVEX ZMM emission (`0x62` / `vfmadd213pd zmm*`) while preserving `CPUID` safety on AVX2-only hosts.
4. `AssemblyInvariantAuditor` accurately validates GCC `-O3` YMM-spilled frame teardowns (`and rsp, -32` + `lea -k(rbp), rsp` / interleaved epilogue `pop`s / `leave`) while still failing closed on all stack-imbalance mutants.
5. `python -W error::ResourceWarning test_empirical_audit.py` exits `0` (`14/14` gates PASSED), `AetherMind_Strict_Auditor.py` returns `APROVADO`, full `unittest discover -W default` passes 100%, and GitHub Actions CI passes on `ubuntu-latest` and `windows-latest`.
