# Acceptance Contract — Alpha-C75: Freestanding Hardware Atomics, Multi-Thread Stress & Apple Silicon ARM64 CI

## 1. Objective
Execute **Fase 4 (Alpha-C75)** of the Top-1 Master Plan:
1. Implement freestanding hardware atomic and spinlock kernels (`omni_atomic_add_i64`, `omni_atomic_cas_i64`, `omni_spinlock_acquire`, `omni_spinlock_release`) in `runtime/native_atomics.py` for Win64, SysV x86-64, and ARM64 (`LDAXR`/`STLXR`), auto-linked by `NativeObjectLinker`.
2. Expand `.github/workflows/ci.yml` with `verify-macos-arm64` (`macos-latest`, Apple Silicon ARM64) running `run_c69_tests.py`, `run_c70_tests.py`, `run_c75_tests.py`, and native execution of an emitted `arm64_macho` binary (`exit_code == 42`).

## 2. Acceptance Criteria
- `test_01_freestanding_atomics_and_spinlock_multithread_stress`: 8 concurrent OS threads executing 2,500 iterations each (`20,000` total) produce exact `20,000` on both atomic and spinlock-guarded counters with zero lost updates, plus verified CAS transitions.
- `test_02_arm64_llsc_atomic_kernels_unicorn_execution`: All ARM64 `LDAXR`/`STLXR` atomic kernels pass Unicorn ARM64 execution.
- `AetherMind_Strict_Auditor.py run_c75_tests.py`: `APROVADO`.
- `python -W error::ResourceWarning test_empirical_audit.py`: `14/14` gates PASSED.
- Full `unittest discover -s tests -p "test_*.py"` passes with 0 failures and 0 warnings.
- GitHub Actions CI passes on `ubuntu-latest`, `windows-latest`, AND `macos-latest` (Apple Silicon ARM64).
