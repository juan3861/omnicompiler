# Acceptance Contract — Alpha-C72: Real ELF64 DWARF v5 Sections & Ecosystem Manifest Auto-Discovery

## 1. Objective
1. Materialize DWARF v5 `.debug_info`, `.debug_abbrev`, and `.debug_line` as real `SHT_PROGBITS` ELF64 sections inside emitted `.so` shared libraries (`build_elf64_so` + `emit_shared_library` + `emit_linked_shared_library` + `OmniRepoCompiler`), readable by `pyelftools` and `DwarfV5Emitter.decode_debug_line`.
2. Extend `RepoManifestIngestor` to auto-detect `Cargo.toml`, `package.json`, `go.mod`, and `pyproject.toml` repo types and extract `package_dependencies` without requiring manual `omni.toml`.

## 2. Acceptance Criteria
- `test_01_elf64_so_embeds_real_dwarf_v5_sections_via_pyelftools`: Emits an ELF64 `.so`, verifies `.debug_info`, `.debug_abbrev`, and `.debug_line` in `BinaryStructureAuditor`, decodes `.debug_line` with `DwarfV5Emitter.decode_debug_line`, and verifies `omni_main\x00` inside `.debug_info`.
- `test_02_ecosystem_manifest_auto_discovery_without_omni_toml`: Ingests Rust (`Cargo.toml`), TypeScript (`package.json`), Go (`go.mod`), and Python (`pyproject.toml`) repos without `omni.toml`, verifies `package_dependencies`, and compiles Rust+TS+Go end-to-end returning `50`.
- `AetherMind_Strict_Auditor.py run_c72_tests.py`: `APROVADO`.
- `python -W error::ResourceWarning test_empirical_audit.py`: `14/14` gates PASSED.
- Full `unittest discover -s tests -p "test_*.py"` passes with 0 failures and 0 warnings.
