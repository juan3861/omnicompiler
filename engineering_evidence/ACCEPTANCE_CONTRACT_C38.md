# ACCEPTANCE CONTRACT: ALPHA-C38 (FINAL ENGINEERING CEILING & TOP-100 GITHUB AUDIT)

## Scope
1. **CLI Multi-Backend & Provenance Polish (`omnicompiler_cli.py`)**:
   - Expose `--backend {native, llvm, wasm}`, `--entry`, and `--export-all` on `compile`.
   - Report Stage 1 Salsa Red-Green cache hits/misses, Stage 3b/5c Z3 spatial bounds & pointer disjointness, and Stage 5 optimization/SMT proof telemetry cleanly.
   - Add `top100-audit` CLI subcommand invoking `benchmarks.top100_ceiling_audit.run_top100_ceiling_audit`.
2. **Live Top-100 GitHub Compiler Engineering Re-Scan & Empirical Ceiling Benchmark (`benchmarks/top100_ceiling_audit.py`)**:
   - Re-query GitHub API for the top 100 compiler/JIT/linker/WASM/formal-verification repositories (`GITHUB_TOP_100_FINAL_AUDIT_C38.json`).
   - Empirically benchmark Native x86_64 vs LLVM O3 vs WASM vs CPython execution speedups and Salsa Cold vs Warm multi-repo incremental rebuild speedup on real binaries.
   - Generate `TOP100_FINAL_CEILING_AUDIT_C38.md` comparing OmniCompiler's 16 integrated gears objectively against the Top-100 GitHub ecosystem (stating both unified capabilities and honest scope boundaries).
3. **Final End-to-End Certification Gate**:
   - `tests/test_alpha_c38_cli_and_top100_ceiling_audit.py` + `run_c38_tests.py` (`AetherMind_Strict_Auditor.py` -> **APROVADO**).
   - `run_full_regression.py` (`AetherMind_Strict_Auditor.py` -> **APROVADO**) + `python -W default -m unittest discover -s tests`.
   - Clean GitHub Actions CI run (`ubuntu-latest` + `windows-latest` both green).
