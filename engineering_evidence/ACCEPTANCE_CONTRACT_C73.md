# Acceptance Contract — Alpha-C73: Static Closure Conversion, `match`/`case` & Workspace Dependency Expansion

## 1. Objective
1. Implement static closure conversion (`def` nested functions + `lambda` expressions with captured environment) and `match`/`case` CFG lowering in `AstToSsaLowering` (`compiler/ssa_ir.py`) and `OmniRepoCompiler` (`omni_repo_compiler.py`).
2. Implement transitive local workspace dependency expansion (`Cargo.toml` `path =`, `package.json` `file:`, `go.mod` `replace =>`) in `RepoManifestIngestor` and `OmniRepoCompiler`.

## 2. Acceptance Criteria
- `test_01_nested_def_lambda_closures_and_match_case_e2e`: Verifies lifted closure symbols (`omni_main__closure_affine`, `omni_main__closure_bump`), `match`/`case` dispatch, Unicorn preflight (`61`), and live `ctypes.CDLL` execution (`fn(1) == 47`, `fn(2) == 104`, `fn(10) == 61`).
- `test_02_transitive_local_workspace_expansion_from_root_repo`: Compiles a 3-repo polyglot DAG (`Go -> TypeScript -> Rust`) passing ONLY `[r_root]`, verifying Unicorn preflight (`107`) and live `ctypes.CDLL` execution (`fn(10) == 107`, `fn(4) == 47`).
- `AetherMind_Strict_Auditor.py run_c73_tests.py`: `APROVADO`.
- `python -W error::ResourceWarning test_empirical_audit.py`: `14/14` gates PASSED.
- Full `unittest discover -s tests -p "test_*.py"` passes with 0 failures and 0 warnings.
