# Acceptance Contract — Alpha-C74: Generic Monomorphization & Structured `try`/`except`/`raise`

## 1. Objective
1. Implement structured `try / except / raise / finally` lowering in `AstToSsaLowering` (`compiler/ssa_ir.py`) and enable `ast.Try` / `ast.Raise` in `omni_repo_compiler.py`.
2. Capture generic type parameters (`<T>`) in `frontends/polyglot_ssa_lowering.py` and implement call-site type-driven monomorphization (`fn__mono_int` / `fn__mono_float`) in `omni_repo_compiler.py`.

## 2. Acceptance Criteria
- `test_01_structured_try_except_raise_and_finally_e2e`: Verifies `try`/`except Exception as err`/`raise ValueError(42)`/`finally` in Unicorn (`106`) and live `ctypes.CDLL` (`fn(10) == 106`, `fn(-5) == 1043`).
- `test_02_polyglot_generic_monomorphization_rust_and_typescript`: Verifies Rust `scale_gen<T>` and TypeScript `bias_gen<T>` monomorphize into `scale_gen__mono_int` and `bias_gen__mono_float`, executing via Unicorn (`42`) and `ctypes.CDLL` (`42`, `30`).
- `AetherMind_Strict_Auditor.py run_c74_tests.py`: `APROVADO`.
- `python -W error::ResourceWarning test_empirical_audit.py`: `14/14` gates PASSED.
- Full `unittest discover -s tests -p "test_*.py"` passes with 0 failures and 0 warnings.
