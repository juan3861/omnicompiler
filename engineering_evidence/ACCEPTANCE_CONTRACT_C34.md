# ACCEPTANCE CONTRACT — Alpha-C34

**Date:** 2026-11-16  
**Milestone:** Alpha-C34  
**Scope:** Sub-32-bit Signed/Unsigned Integer Widths (`i8`/`u8`/`i16`/`u16`/`u32`), Nested By-Value Struct Layouts (`Header` inside `PacketFrame`), Multi-Level Attribute Chains (`p.hdr.port`), Multi-Pass Cross-Repo Struct Layout Resolution, Native `ctypes.Structure` / Host C `memcmp` Verification

---

## Frozen Deliverables & Verification Criteria

1. **Full Width Spectrum (`i8`, `u8`, `i16`, `u16`, `i32`, `u32`, `f32`, `i64`, `u64`, `f64`) across `load_off` / `store_off`:**
   - **Frontend & SSA IR (`compiler/ssa_ir.py`, `omni_repo_compiler.py`):**
     - Support builtins `load_i8`, `load_u8`, `load_i16`, `load_u16`, `load_u32`, `load_u64` and `store_i8`, `store_u8`, `store_i16`, `store_u16`, `store_u32`, `store_u64`.
     - Map C/Rust/Go/TS type aliases (`i8`/`int8`, `u8`/`uint8`, `i16`/`int16`, `u16`/`uint16`, `i32`/`int32`, `u32`/`uint32`, `u64`/`uint64`) to canonical widths.
   - **Hardware & Bytecode Backends:**
     - `X64CodeGenerator` (`compiler/native_codegen.py`): `movsx rax, byte ptr [r11]`, `movzx eax, byte ptr [r11]`, `movsx rax, word ptr [r11]`, `movzx eax, word ptr [r11]`, `mov eax, dword ptr [r11]`, `mov byte ptr [r11], al`, `mov word ptr [r11], ax`.
     - `Arm64CodeGenerator` (`compiler/native_codegen.py`): `LDRSB X11, [X9]`, `LDRB W11, [X9]`, `LDRSH X11, [X9]`, `LDRH W11, [X9]`, `LDR W11, [X9]`, `STRB W11, [X9]`, `STRH W11, [X9]`.
     - `LLVMBackend` (`compiler/llvm_backend.py`): `load i8/i16/i32` + `sext`/`zext`, `trunc` + `store i8/i16/i32`.
     - `WasmBackend` (`compiler/wasm_backend.py`): `i64.load8_s`, `i64.load8_u`, `i64.load16_s`, `i64.load16_u`, `i64.load32_u`, `i64.store8`, `i64.store16`, `i64.store32`.

2. **Nested By-Value Struct Layouts & Chained Attributes (`p.hdr.port`):**
   - `adapters/universal_abi_bridge.py`: `StructField` / `StructLayout` accept `nested_layouts` so embedded by-value struct fields inherit exact `(total_size, struct_alignment)` and natural alignment padding.
   - `compiler/ssa_ir.py`: `AstToSsaLowering.register_struct_from_classdef` resolves nested struct fields using `self.struct_meta` / recursive size-alignment computation; `_resolve_struct_field` resolves arbitrary depth chains (`p.hdr.port`) into `(root_expr, cumulative_byte_offset, leaf_width)` for loads, stores, and `AugAssign`.
   - `frontends/polyglot_ssa_lowering.py` & `omni_repo_compiler.py`: Support `i8`/`u8`/`i16`/`u16`/`u32`/`u64` in Rust/Go/TS struct & function annotations, chained attribute assignments (`p.hdr.flags += 2;`, `p.hdr.port = 8080;`), and fixpoint cross-repo struct extraction so nested structs resolve regardless of file scan order.

3. **Unbounded Z3 `QF_ABVFP` Translation Validation & LLVM/WAT Lifters:**
   - `validation/ssa_translation_validator.py`: Extend `_load_off_z3` / `_store_off_z3` to handle `i8`, `u8`, `i16`, `u16`, `u32`, `u64` via exact `z3.SignExt`/`z3.ZeroExt`/`z3.Extract` bit-vector semantics; expand concrete witness byte probes for packed sub-32-bit offsets.
   - `validation/backend_translation_validator.py`: Update `LLVMIRToSSALifter` and `WATToSSALifter` for `i8`/`u8`/`i16`/`u16`/`u32` loads/stores and casts.

4. **Mandatory Verification Gates (Pass Criteria):**
   - `tests/test_alpha_c34_sub32_widths_and_nested_structs.py` via `run_c34_tests.py`:
     1. Sign-extension vs zero-extension parity (`i8` `-5` vs `u8` `251`, `i16` `-300` vs `u16` `65236`, `u32` `0xFFFFFFFF == 4294967295`) across Python C-ABI structs, Z3 TV, Native x86_64, LLVM MCJIT, and Wasmtime.
     2. ARM64 hardware sub-32-bit `LDRSB`/`LDRB`/`LDRSH`/`LDRH`/`LDR W`/`STRB`/`STRH` verification under real Unicorn ARM64 emulation on a nested `Header` + `Frame` C-ABI buffer.
     3. Multi-repo Polyglot Nested By-Value Struct Fusion (`Header` in Rust, `Frame` in Go, orchestration in TypeScript `ts_process_frame`) compiled via `OmniRepoCompiler` (`native`, `llvm`, `wasm`) + Wasmtime execution + Z3 proof (`refuted == 0`).
     4. Dynamic Heap C-ABI Serialization Proof: W^X Native JIT builds a `PacketFrame` in `omni_alloc` RAM using `store_u8`/`store_i8`/`store_u16`/`store_i16`/`store_u32`/`store_f32`/`store_f64` and invokes host C `libc`/`msvcrt` `memcmp` via `omni_ffi_call3` against a CPython `ctypes.Structure` (`memcmp == 0` when equal, `!= 0` after mutation).
   - `AetherMind_Strict_Auditor.py` returns `APROVADO` on `run_c34_tests.py` and `run_full_regression.py`.
   - `python -W default -m unittest discover -s tests -t F:\repository-compiler` passes 100% (218/218 tests, 0 warnings).
   - Commit & push to `origin/main` with green GitHub Actions CI (`ubuntu-latest` and `windows-latest`).
