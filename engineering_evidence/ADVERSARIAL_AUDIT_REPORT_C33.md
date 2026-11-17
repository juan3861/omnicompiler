# ADVERSARIAL AUDIT REPORT — Alpha-C33: Typed C-ABI Struct Layouts, Narrow `i32`/`f32` Memory Widths (`load_off`/`store_off`), `f64` Dynamic FFI Trampolines & Parallel Test Isolation

**Date:** 2026-11-16  
**Milestone:** Alpha-C33  
**Repository:** `F:\repository-compiler`  
**Verdict:** **PASS (100% EMPIRICALLY VERIFIED)**

---

## 1. Scope Audited

1. **C-ABI Struct Layouts & Field Lowering (`compiler/ssa_ir.py`, `frontends/polyglot_ssa_lowering.py`, `omni_repo_compiler.py`):**
   - Lowered Python `ast.ClassDef` definitions and polyglot struct/interface declarations (Rust `struct`, Go `type ... struct`, TypeScript `interface`) via `UniversalAbiBridge.compute_c_struct_layout` into `StructLayout` descriptors.
   - Added typed field resolution for `ast.Attribute` reads, writes, and augmented assignments (`p.field`, `p.field = v`, `p.field += v`), plus explicit width intrinsics (`load_i32`, `load_f32`, `load_i64`, `load_f64`, `store_i32`, `store_f32`, `store_i64`, `store_f64`) lowering to `load_off` / `store_off` (`["store_off"]` included in `SIDE_EFFECT_OPCODES`).
   - Added `struct_layouts` extraction across repository AST modules in `OmniRepoCompiler` so structs defined in one repository/language remain addressable across cross-repo calls.

2. **Hardware Narrow `i32`/`f32` + Wide `i64`/`f64` Codegen Across Native, LLVM & WebAssembly (`compiler/native_codegen.py`, `compiler/llvm_backend.py`, `compiler/wasm_backend.py`):**
   - `X64CodeGenerator`: `load_off` / `store_off` using `movsxd`, `mov dword`, `cvtss2sd`, `cvtsd2ss`, and `movss`.
   - `Arm64CodeGenerator`: `load_off` / `store_off` using `LDRSW`, `STR W`, `LDR S0 + FCVT D0, S0`, and `FMOV D0 + FCVT S0, D0 + STR S0`.
   - `LLVMBackend`: byte-offset `getelementptr i8` with `load i32` + `sext`, `load float` + `fpext`, `trunc` + `store i32`, `fptrunc` + `store float`, `load`/`store i64`/`double`.
   - `WasmBackend`: byte-offset `i64.add` + `i32.wrap_i64` with `i64.load32_s`, `i64.store32`, `f32.load` + `f64.promote_f32`, `f32.demote_f64` + `f32.store`, `i64.load/store`, `f64.load/store`.

3. **Unbounded Z3 `QF_ABVFP` Translation Validation & Differential Memory Parity (`validation/ssa_translation_validator.py`, `validation/backend_translation_validator.py`):**
   - Extended `SUPPORTED_Z3_MEMORY_OPCODES` with `"load_off"` and `"store_off"` and modeled 32-bit sign-extension (`z3.SignExt(32, z3.Extract(31, 0, ...))`) and IEEE-754 single/double conversion (`z3.Float32()` <-> `z3.Float64()`) at exact byte-offset addresses in both DAG symbolic encoding and inductive loop verification.
   - Updated `LLVMIRToSSALifter`, `WATToSSALifter`, and `BackendTranslationValidator.verify_differential_execution` to lift narrow/byte-addressed struct accesses and verify in-place struct byte buffers (`bytes`/`bytearray`) across Native x86_64, LLVM MCJIT, and Wasmtime.

4. **`f64` Dynamic FFI Trampolines (`runtime/native_ffi.py`, `runtime/native_heap.py`):**
   - Added `omni_ffi_call0_f64`, `omni_ffi_call1_f64`, `omni_ffi_call2_f64`, and `OmniFFI.call_f64`, updated `omni_ffi_load_lib` to map `"libm"`/`"m"` to `msvcrt` on Win32 (or `libm.so.6` / `CDLL(None)` on POSIX), and exported them in `NATIVE_FFI_SYMBOLS`.

5. **Parallel-Safe Legacy Workspace Isolation (`tests/test_alpha_c19_vla_polyhedral.py`):**
   - Replaced hardcoded `F:\repository-compiler\test_repo_c19_workspace` in `test_06_omni_repo_compiler_vla_polyhedral_integration` with `tempfile.TemporaryDirectory()`.

---

## 2. Adversarial Bugs Found & Fixed During Audit

1. **Circular Import Hiding `NATIVE_FFI_SYMBOLS` from `NativeJitCompiler` (`runtime/native_ffi.py`):**
   - *Finding:* Importing `runtime.native_ffi` before `runtime.native_heap` triggered a top-level import `from runtime.native_heap import omni_list_len, omni_list_get` inside `runtime/native_ffi.py` before `NATIVE_FFI_SYMBOLS` was defined, causing `runtime/native_heap.py`'s guarded `from runtime.native_ffi import NATIVE_FFI_SYMBOLS` to hit `ImportError` silently. Consequently, `NativeJitCompiler.compile_ssa` failed with unresolved relocations for `omni_ffi_call1_f64` and `omni_ffi_call2_f64`.
   - *Fix:* Moved the `omni_list_len` / `omni_list_get` import inside `omni_ffi_call()`, eliminating the circular import regardless of caller import order.

2. **LLVM O3 Tail-Call `JMP rel32` (`E9`) & Inter-Function Multi-Byte Alignment NOPs (`validation/assembly_invariant_auditor.py`, `omni_repo_compiler.py`):**
   - *Finding:* LLVM O3 compiled `ts_step_telemetry` (`return go_accumulate(t, dt);`) into a sibling tail call ending with `E9 00 00 00 00` (5-byte near `JMP rel32` awaiting linker relocation) and emitted multi-byte alignment NOPs (`0f 1f 44 00 00`, etc.) between adjacent `.text` functions. `AssemblyInvariantAuditor.audit_function_code` previously checked `code_bytes[-2] in (0xEB, 0xE9)`, which only matched 2-byte `EB rel8` jumps and misclassified 5-byte `E9 rel32` jumps (and trailing `0x00` bytes inside multi-byte NOPs) as invalid function termination (`found 0x00`).
   - *Fix:* Updated `AssemblyInvariantAuditor.audit_function_code` to recognize `EB rel8` (`code_bytes[-2] == 0xEB`), `E9 rel32` (`code_bytes[-5] == 0xE9`), and indirect `FF /4` jumps, and updated `omni_repo_compiler.py` to strip trailing canonical x86 alignment NOP sequences before auditing LLVM `.text` slices.

---

## 3. Verification Evidence

- `python run_c33_tests.py`: **4/4 PASS** (`5.529s`)
- `AetherMind_Strict_Auditor.py run_c33_tests.py`: **APROVADO**
- `AetherMind_Strict_Auditor.py run_full_regression.py`: **APROVADO** (`C13`–`C33`)
- `python -W default -m unittest discover -s tests -t F:\repository-compiler`: **214/214 PASS**, 0 warnings (`55.996s`)
