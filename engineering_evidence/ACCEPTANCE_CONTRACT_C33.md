# ACCEPTANCE CONTRACT — Alpha-C33: C-ABI Struct Layouts (`ClassDef` / Rust `struct` / Go `type struct` / TS `interface`), Narrow `i32`/`f32` Typed Memory (`load_off`/`store_off`), `f64` FFI Trampolines & Parallel Test Isolation

**Status:** FROZEN BEFORE IMPLEMENTATION  
**Milestone:** Alpha-C33 (`F:\repository-compiler`)  
**Baseline:** Alpha-C32 (`38ee201`, CI `43989580987`, 210 discovery PASS, zero warnings)

## 1. Deliverables & Architecture Contracts

1. **Dynamic `f64` FFI Trampolines (`runtime/native_ffi.py`, `omni_repo_compiler.py`):**
   - Implement `omni_ffi_call0_f64`, `omni_ffi_call1_f64`, `omni_ffi_call2_f64`, and `OmniFFI.call_f64(fn_ptr, *args)` using `ctypes.c_double`, exported via `NATIVE_FFI_SYMBOLS` and allowed in `NATIVE_BUILTIN_CALLS`.
   - Enable native x86-64 JIT compiled functions to invoke host C math runtime symbols (e.g. `sqrt`, `pow`, `fabs` from `msvcrt`/`libm`).

2. **Typed Byte-Offset Memory Opcodes (`load_off` / `store_off` for `i32`, `f32`, `i64`, `f64`) Across All Tiers:**
   - **Omni-SSA (`compiler/ssa_ir.py`):** Support `load_off [base, byte_off, width]` and `store_off [base, byte_off, val, width]`, built-in intrinsics `load_{i32,f32,i64,f64}` / `store_{i32,f32,i64,f64}`, `AstToSsaLowering` `StructLayout` registration (auto-extracted from Python `class` annotations or passed explicitly), and `p.field` / `p.field = val` / `p.field += val` lowering to exact C-ABI byte offsets.
   - **Polyglot (`frontends/polyglot_ssa_lowering.py`):** Parse Rust `struct Name { ... }`, Go `type Name struct { ... }`, and TS `interface Name { ... }` into Python `ast.ClassDef` nodes inside `mod.body`, preserve struct parameter annotations, and lower `p.field = expr` / `p.field += expr` statements.
   - **Native x86-64 & ARM64 (`compiler/native_codegen.py`):** Emit `movsxd`/`mov dword`, `cvtss2sd`/`cvtsd2ss`, `LDRSW`/`STR W`, `LDR S0 + FCVT D0, S0` / `FCVT S0, D0 + STR S0`, plus 64-bit `i64`/`f64` byte-offset accesses.
   - **LLVM & WASM (`compiler/llvm_backend.py`, `compiler/wasm_backend.py`):** Emit `getelementptr i8` + `i32`/`float`/`i64`/`double` `sext`/`trunc`/`fpext`/`fptrunc` in LLVM IR, and `i64.load32_s`/`i64.store32`/`f32.load + f64.promote_f32`/`f32.demote_f64 + f32.store` in WAT.
   - **Z3 `QF_ABVFP` Translation Validation & Lifters (`validation/ssa_translation_validator.py`, `validation/backend_translation_validator.py`):** Add bit-precise `SignExt(32, ...)` and `Float32 <-> Float64` Z3 modeling for `load_off`/`store_off`, lift LLVM/WAT typed narrow loads & stores back to Omni-SSA, prove equivalence, and refute width/signedness mutations (e.g. `sext` -> `zext`).

3. **Parallel-Safe Workspace Isolation (`tests/test_alpha_c19_vla_polyhedral.py`):**
   - Replace hardcoded `r"F:\repository-compiler\test_repo_c19_workspace"` with `tempfile.TemporaryDirectory()` so concurrent test runners never collide.

## 2. Empirical Acceptance Gates

- `tests/test_alpha_c33_cabi_structs_narrow_widths_and_f64_ffi.py` + `run_c33_tests.py`:
  1. Python `class Packet:` C-ABI struct (`i32` + `f32` + `f64` with alignment padding) compiled across Native x86-64, LLVM O3 MCJIT, and Wasmtime linear memory with bit-exact return & mutated struct bytes verification, plus LLVM/WAT formal Z3 proofs and signedness (`sext -> zext`) refutation.
  2. Polyglot Rust `struct Metric`, Go `type Metric struct`, and TypeScript `interface Metric` mutating/reading `i32`, `f32`, and `f64` fields end-to-end and through `OmniRepoCompiler`.
  3. Physical ARM64 execution of C-ABI `i32`/`f32`/`f64` struct kernel on Unicorn ARMv8-A.
  4. Native x86-64 JIT execution calling C `sqrt`/`pow` via `omni_ffi_call1_f64` / `omni_ffi_call2_f64` + `OmniFFI.call_f64`.
- Full regression `run_full_regression.py` + `unittest discover`, `AetherMind_Strict_Auditor.py` `APROVADO`, and GitHub Actions CI green on `ubuntu-latest` and `windows-latest`.
