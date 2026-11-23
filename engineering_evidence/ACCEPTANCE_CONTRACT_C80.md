# Acceptance Contract — Alpha-C80 (Industrial Benchmarks & Top-1 Master Plan Completion)

## Scope
1. `benchmarks/industrial_top1_suite.py`: End-to-end PolyBench GEMM, Jacobi-1D, and FNV-1a Crypto Mix native execution, distributed RBE/CAS cold vs warm speedup, and zero-config polyglot multi-repository ingestion (`Cargo.toml`, `go.mod`, `package.json`, `pyproject.toml`).
2. `tests/test_alpha_c80_industrial_top1_suite.py` & `run_c80_tests.py`: Automated verification gate.
3. `.github/workflows/ci.yml`: Runs `benchmarks/industrial_top1_suite.py` on CI (including live `gcc -O3` comparison on Linux).

## Verification Gates
- `run_c80_tests.py -W error::ResourceWarning`: `1/1 OK`.
- `AetherMind_Strict_Auditor.py run_c80_tests.py`: `APROVADO`.
- `test_empirical_audit.py -W error::ResourceWarning`: `14/14 PASSED`.
- Full `unittest discover -s tests -p "test_*.py"`: `100% OK`.
- GitHub Actions 4-runner CI (`ubuntu-latest`, `windows-latest`, `macos-latest`, `ubuntu-24.04-arm`): `success`.
