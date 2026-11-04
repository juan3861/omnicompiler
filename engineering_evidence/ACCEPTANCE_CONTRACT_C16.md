# ACCEPTANCE CONTRACT ALPHA-C16: LOOP AUTO-VECTORIZER, NATIVE DYNAMIC FFI BRIDGE & JIT PIPELINE PASS INTEGRATION

## 1. Scope & System Boundary
- **Target Repository:** `F:\repository-compiler` (`omnicompiler`).
- **Protocol:** Alpha-C16 (Stateful Loop Vectorization & Dynamic C-ABI Foreign Function Interface).
- **Core Additions:**
  1. `LoopVectorizerPass` (`compiler/loop_vectorizer.py`):
     - Elementwise vector addition (`for i in range(len(a)): c[i] = a[i] + b[i]` -> `omni_list_vec_add(a, b)`).
     - Parallel reduction sum (`for i in range(len(a)): total += a[i]` -> `omni_list_sum(a)` with accumulator preservation).
     - Vector dot product (`for i in range(len(a)): total += a[i] * b[i]` -> `omni_list_vec_dot(a, b)` with accumulator preservation).
  2. `Native Dynamic FFI Bridge` (`runtime/native_ffi.py`):
     - Cross-platform dynamic library loading (`LoadLibraryW` on Win32, `dlopen` on POSIX).
     - Dynamic C-ABI symbol resolution (`GetProcAddress` / `dlsym`).
     - Dynamic function call trampolines: `omni_ffi_call0` through `omni_ffi_call4`, and `omni_ffi_call` (unpacked from `OmniList`).
  3. `NativeJitCompiler Pipeline Pass Integration` (`compiler/native_jit.py`):
     - Integrated `StackPromotionPass` and `LoopVectorizerPass` into `compile_ssa` before machine code emission.
  4. Test Suite (`tests/test_alpha_c16_autovec_and_ffi.py`):
     - 6 rigorous tests testing auto-vectorization, FFI resolution, trampolines, and end-to-end silicon execution.

## 2. Invariants & Verification Criteria
- [REQ-C16-01]: Loop vectorizer must detect induction loops over contiguous `OmniList` collections and rewrite them into AVX2 SIMD intrinsics.
- [REQ-C16-02]: Non-zero initial accumulator values (`total = offset`) must be preserved mathematically via `init_val + omni_list_sum(a)`.
- [REQ-C16-03]: Dynamic FFI bridge must support both Win32 (`kernel32`, `msvcrt`) and POSIX (`libc`) shared libraries.
- [REQ-C16-04]: 100% test pass rate across the full 125-test compiler regression suite.
- [REQ-C16-05]: Strict certification by `AetherMind_Strict_Auditor.py` (Exit Code 0).

## 3. Evidence Status
- Verification Mode: `REAL_MULTI_AGENT_VERIFIED` + `OMEGA_STRICT_AUDITOR`.
- Status: **APPROVED**.
