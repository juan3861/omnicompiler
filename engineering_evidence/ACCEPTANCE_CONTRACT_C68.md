# Acceptance Contract — Alpha-C68: WASM Coalescing Heap, Mach-O Hybrid Linker & 4-Language Polyglot Homeostasis

## 1. Objective
Close three deep industrial gaps from the C67 roadmap:
1. Replace tail-only heap reclaim in `WasmBackend` with an **address-ordered explicit free-list allocator with block splitting, bidirectional physical coalescing, double-free immunity, and top-of-heap tail trim** inside WebAssembly linear memory.
2. Implement `load_macho_object` in `NativeObjectLinker` and wire `("macos", "x86_64")` + `("macos", "arm64")` into `OmniRepoCompiler`, enabling **full 6-target (`windows/linux/macos x x86_64/arm64`) heterogeneous linking** plus hybrid DWARF v5 `.debug_line` coverage for GCC/LLVM/Native symbols.
3. Prove end-to-end **4-language Polyglot Homeostasis (`C + Rust + TypeScript + Go`)** heterogeneously compiled across Native, LLVM 20 `-O3`, and GCC `-O3` inside single native shared libraries and ELF64 executables.

## 2. Hard Gates
1. `WasmBackend.run_ssa_with_memory` passes coalescing (`free(p1); free(p2) -> malloc(128) == p1`), splitting, `realloc`, NULL/double-free safety, and top-of-heap reclaim assertions.
2. `load_macho_object` + `OmniRepoCompiler` builds and validates `Mach-O 64` x86-64 and ARM64 binaries (`hybrid:llvm+native`) resolving live `REL32`/`ARM64_CALL26` relocations (`>= 1` patched call), passing `BinaryStructureAuditor`, DWARF v5 `.debug_line`, and Unicorn x86-64 + ARM64 execution.
3. 4-language polyglot topology (`C` + `Rust` + `TypeScript` + `Go`) compiles across Native, LLVM 20, and GCC `-O3` (`hybrid:gcc+llvm+native` / `hybrid:llvm+native`) and executes bit-exact (`377`).
4. `AetherMind_Strict_Auditor.py` (`APROVADO`), full `unittest discover -W default`, `test_empirical_audit.py -W error::ResourceWarning` (`14/14`), and CI (`ubuntu-latest` + `windows-latest`) pass 100%.
