# Acceptance Contract — Alpha-C62: Homeostase dos Três Ecossistemas (`OmniCompiler` + `LLVM 20.1.8` + `GCC O3`)

## 1. Objective & Scope
Executa integralmente as Fases 1 a 4 de [PLANO_HOMEOSTASE_TRES_ECOSSISTEMAS_A_Z.md](file:///C:/Users/juanp/.gemini/antigravity/brain/c406d4a9-0136-4cdd-8cd9-db340e5067bb/PLANO_HOMEOSTASE_TRES_ECOSSISTEMAS_A_Z.md):
1. **Fase 1 (`GCCBackend` em [`compiler/gcc_backend.py`](file:///F:/repository-compiler/compiler/gcc_backend.py)):** Lowering completo `Omni-SSA` -> C99 determinístico zero-UB (`uint64_t` modular arithmetic, `__builtin_memcpy` strict-aliasing safe, cópia paralela atômica de $\phi$-nodes), emitindo objetos ELF64 `.o`, assembly `-S` com telemetria SIMD e execução isolada com snapshots de memória via `/usr/bin/gcc -O3` (Linux nativo ou WSL2).
2. **Fase 2 (`LLVMBackend` Cross-Target & Telemetria em [`compiler/llvm_backend.py`](file:///F:/repository-compiler/compiler/llvm_backend.py)):** Suporte a `target_triple` explícito (incluindo `aarch64-unknown-linux-gnu`) e método `inspect_optimization_stats(mod)`.
3. **Fase 3 (`HomeostasisRouter` em [`compiler/homeostasis_router.py`](file:///F:/repository-compiler/compiler/homeostasis_router.py) + integração em [`omni_repo_compiler.py`](file:///F:/repository-compiler/omni_repo_compiler.py)):** Orquestrador adaptativo (`consensus`, `throughput`, `latency`) com oráculo diferencial bit-a-bit entre Native AVX2, LLVM 20 O3 e GCC O3, isolamento automático de motores divergentes e modos `backend="gcc"` / `backend="homeostasis"` no compilador multi-repositório.

## 2. Acceptance Criteria
| ID | Requirement | Verification Method | Status |
|---|---|---|---|
| AC-C62-01 | `GCCBackend` O3 compila `Omni-SSA` vetorizado para ELF64 `.o`, passa no `AssemblyInvariantAuditor`, gera instruções SIMD e executa com memória real | `test_01_gcc_backend_ssa_to_c99_o3_avx2_elf64_and_execution` | PASS |
| AC-C62-02 | `LLVMBackend` emite objeto ARM64 AArch64 (`EM_AARCH64`) e telemetria O3 | `test_02_llvm_backend_cross_target_triples_and_optimization_stats` | PASS |
| AC-C62-03 | `HomeostasisRouter` atinge consenso bit-a-bit entre Native AVX2, LLVM 20 O3 e GCC O3, e isola automaticamente um 4º motor divergente | `test_03_homeostasis_router_tri_ecosystem_consensus_and_outlier_isolation` | PASS |
| AC-C62-04 | `OmniRepoCompiler` compila e executa binários reais com `backend="homeostasis"` e `backend="gcc"`, com guarda fail-closed multi-SO | `test_04_omnirepo_compiler_gcc_and_homeostasis_e2e_executables` | PASS |
