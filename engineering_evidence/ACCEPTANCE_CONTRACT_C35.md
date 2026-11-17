# ACCEPTANCE CONTRACT — Alpha-C35

**Date:** 2026-11-17  
**Milestone:** Alpha-C35  
**Scope:** Embedded Fixed-Size C-ABI Arrays in Structs (`[T; N]` / `[N]T` / `Array[T, N]`), Inline Array-of-Structs Addressing (`p.items[i].port`), C-ABI Alignment & Stride Semantics across SSA / Native x86_64 / ARM64 Unicorn / LLVM O3 / Wasmtime / Z3 `QF_ABVFP` TV / Multi-Repo `OmniRepoCompiler`

---

## Frozen Deliverables & Verification Criteria

1. **Canonical Fixed-Array Type Encoding & C-ABI Layout (`adapters/universal_abi_bridge.py`, `compiler/ssa_ir.py`):**
   - Represent embedded fixed arrays canonically as `arr:<elem_ft>:<count>`.
   - Support Python `Array[T, N]` / `FixedArray[T, N]`, Rust `[T; N]`, Go `[N]T`, and TypeScript `[T; N]` / `FixedArray<T, N>` in struct declarations (`ClassDef` / `_try_parse_top_level_struct`).
   - Exact C-ABI size (`sizeof(T) * N`) and natural alignment (`alignof(T)`), supporting both scalar elements (`u8`, `i16`, `u16`, `i32`, `f32`, `f64`, `i64`) and nested structs (`[Header; 2]`).

2. **Unified Multi-Level L-Value & Fixed-Array Element Lowering (`compiler/ssa_ir.py`, `frontends/polyglot_ssa_lowering.py`):**
   - Replace `_resolve_struct_field` with unified `_resolve_lvalue_address` + `_emit_lvalue_byte_offset` supporting arbitrary combinations of dotted attributes and inline array subscripts (`p.scores[i]`, `p.hdr.tags[i]`, `p.items[i].port`) across reads, `Assign`, and `AugAssign`.
   - Extend `PolyglotParser._parse_simple_stmt` to accept `(ast.Subscript, ast.Attribute)` L-values with `=` and compound operators (`+=`, `-=`, `*=`, etc.).

3. **Mandatory Verification Gates (Pass Criteria):**
   - `tests/test_alpha_c35_embedded_arrays_and_cabi_strides.py` via `run_c35_tests.py`:
     1. CPython `ctypes.Structure` exact `sizeof` / `offset` congruence for `TelemetryBatch` (`tag: i8`, `tags: [u8; 4]`, `headers: [Header; 2]`, `weights: [f32; 4]`, `total: f64`), dynamic loop sum + mutation across `Z3 QF_ABVFP` TV (LLVM + WAT `proven == True`) and `Native == LLVM == Wasmtime` byte parity.
     2. ARM64 Unicorn execution of inline array-of-structs mutation & accumulation (`p.headers[i].port += delta`, `p.tags[i]`).
     3. Cross-Repo Polyglot Fusion (`Header` + `RustPacket` `[f32; 4]` in Rust, `GoBatch` `[2]Header` + `[4]float32` in Go, `ts_process_batch` in TypeScript) compiled via `OmniRepoCompiler` (`native`, `llvm`, `wasm`) + Wasmtime execution + Z3 `refuted == 0`.
     4. W^X Native JIT `build_and_verify_batch` serializing inline array struct elements into `omni_alloc` RAM verified via host C `libc`/`msvcrt` `memcmp` against `ctypes.Structure`.
   - `AetherMind_Strict_Auditor.py` returns `APROVADO` on `run_c35_tests.py` and `run_full_regression.py`.
   - `python -W default -m unittest discover -s tests -t F:\repository-compiler` passes 100% (222/222 tests, 0 warnings).
