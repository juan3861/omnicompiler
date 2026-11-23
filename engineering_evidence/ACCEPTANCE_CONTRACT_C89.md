# Acceptance Contract - Alpha-C89: Self-Hosted Hot-Path Native Core

## Scope
Create `compiler/self_hosted_core.py`:
1. `SelfHostedCoreEngine` compiles OmniCompiler hot-path kernels (`omni_core_fnv_step`, `omni_core_trip_work`, `omni_core_spill_cost`) via `AstToSsaLowering` -> `SCEVAnalyzer` -> `NativeCodeGenerator` -> `NativeObjectLinker` into a native shared library loaded with `ctypes.CDLL`.
2. Transparent Python fallback for cross-arch hosts + deterministic `FreeLibrary` unloading.
3. Empirical benchmark vs Python loop + Stage-1 -> Stage-2 SHA-256 bit-exact fixpoint check (`verify_stage1_stage2_bootstrap`).

## Empirical Gates
- `python -W error::ResourceWarning run_c89_tests.py` passes 100%.
- `AetherMind_Strict_Auditor.py run_c89_tests.py` -> `APROVADO`.
- Full audit, full regression suite, and 4/4 CI runners green.
