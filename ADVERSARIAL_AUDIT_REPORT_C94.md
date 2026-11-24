# Adversarial Audit Report — Alpha-C94

## Findings & Mitigations Verified
1. **Cross-Architecture EH Isolation**:
   - Guarded `Arm64CodeGenerator` instruction dispatch cleanly for `eh_try_begin`/`eh_try_end`/`eh_catch_val` (`store_res(inst.result, 0)`) so ARM64 never falls into x64 `buf`/`rax` references.
2. **Preserve Backward Compatibility on Single-Function `try/raise`**:
   - Cross-frame `ast.Raise` -> `__omni_eh_throw` call is gated on `AstToSsaLowering(enable_cross_frame_eh=True)` and `eh_try_begin`/`eh_try_end` triggers when `try` encloses external `ast.Call` nodes, keeping C74 intra-function `try/raise/finally` behavior identical.
3. **RWX Memory Leak Prevention**:
   - Both `NativeEHRuntime` and `NativeWorkStealingScheduler` implement deterministic `.close()` / context manager cleanup (`VirtualFree(MEM_RELEASE)` on Windows, `munmap` on POSIX), verified under `-W error::ResourceWarning`.
