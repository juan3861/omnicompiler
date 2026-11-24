# Acceptance Contract — Alpha-C94 (Zero-Cost Native EH Unwinder & Work-Stealing Async)

## Scope
1. **`runtime/native_eh_runtime.py` (`LsdaTable`, `NativeEHRuntime`, `build_x64_unwind_throw_stub`)**:
   - Synthesizes position-independent native `__omni_eh_throw` performing physical RBP/RIP stack walking over registered `LsdaTable` entries paired with `.eh_frame` (DWARF CFI) and Win64 `.pdata`/`.xdata` metadata.
   - Zero overhead on normal non-throwing execution paths.
2. **`compiler/ssa_ir.py` & `compiler/native_codegen.py`**:
   - Lowers cross-frame `try/except` regions containing calls into zero-byte `eh_try_begin` / `eh_try_end` / `eh_catch_val` markers populating `CompiledFunctionArtifact.eh_lsda_entries` without disturbing intra-function C74 semantics.
3. **`compiler/async_coroutine_lowering.py` (`build_native_coro_driver_x64`, `NativeWorkStealingScheduler`)**:
   - Native x86-64 coroutine driver loop driving multi-await coroutines to completion in machine code without returning to Python per intermediate `await`, scheduled across worker threads using per-worker double-ended queues with work stealing.

## Verification Criteria
- `outer(5) == 18` (zero-cost non-throwing) and `outer(-4) == 111` (3-frame `inner -> middle -> outer` unwind into `except`) pass via physical native machine-code execution.
- 32 multi-await coroutines complete bit-exactly across 4 OS worker threads via `native_coro_drive`.
- `python -W error::ResourceWarning run_c94_tests.py`, `AetherMind_Strict_Auditor.py`, `test_empirical_audit.py`, and full unit tests pass with zero warnings.
