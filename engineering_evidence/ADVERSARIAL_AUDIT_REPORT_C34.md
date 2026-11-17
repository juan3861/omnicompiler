# ADVERSARIAL AUDIT REPORT — Alpha-C34: Sub-32-Bit Signed/Unsigned Memory Widths (`i8`/`u8`/`i16`/`u16`/`u32`) & Nested By-Value C-ABI Struct Layouts

**Date:** 2026-11-16  
**Milestone:** Alpha-C34  
**Repository:** `F:\repository-compiler`  
**Verdict:** **PASS (100% EMPIRICALLY VERIFIED)**

---

## 1. Scope Audited

1. **Sub-32-Bit Signed/Unsigned Widths (`i8`/`u8`/`i16`/`u16`/`u32`) Across Frontend, Backends & SMT:**
   - `compiler/ssa_ir.py` & `omni_repo_compiler.py`: Registered `load_i8`, `load_u8`, `load_i16`, `load_u16`, `load_u32`, `load_u64`, `store_i8`, `store_u8`, `store_i16`, `store_u16`, `store_u32`, `store_u64` and C/Rust/Go/TS scalar width aliases (`int8`, `uint8`, `int16`, `uint16`, `uint32`, `uint64`).
   - `compiler/native_codegen.py`:
     - `X64CodeGenerator`: Added `movsx rax, byte/word ptr [r11]`, `movzx eax, byte/word ptr [r11]`, `mov eax, dword ptr [r11]`, `mov byte ptr [r11], al`, and `mov word ptr [r11], ax`.
     - `Arm64CodeGenerator`: Added `LDRSB X11, [X9]`, `LDRB W11, [X9]`, `LDRSH X11, [X9]`, `LDRH W11, [X9]`, `LDR W11, [X9]`, `STRB W11, [X9]`, and `STRH W11, [X9]`.
   - `compiler/llvm_backend.py`: Emits byte-GEP `load i8`/`i16`/`i32` + `sext`/`zext` to `i64` and `trunc` + `store i8`/`i16`/`i32` (`align 1`).
   - `compiler/wasm_backend.py`: Emits `i64.load8_s`, `i64.load8_u`, `i64.load16_s`, `i64.load16_u`, `i64.load32_u`, `i64.store8`, and `i64.store16`.

2. **Nested By-Value C-ABI Structs & Arbitrary Attribute Chains (`p.hdr.port`):**
   - `adapters/universal_abi_bridge.py`: Added `nested_layouts` support to `StructField` and `StructLayout` for exact embedded struct alignment/size propagation.
   - `compiler/ssa_ir.py`: Added `struct_meta`, `_get_type_size_align`, fixpoint `register_structs_from_statements`, and multi-level `_resolve_struct_field` chains (`p.hdr.port`) for `Attribute` loads, stores, and `AugAssign`.
   - `frontends/polyglot_ssa_lowering.py` & `omni_repo_compiler.py`: Preserved PascalCase cross-repo struct parameter annotations across files/languages, added chained dotted LHS assignments (`f.hdr.flags += delta_flags;`), and applied fixpoint cross-repo struct layout resolution before per-repo lowering.

3. **Z3 `QF_ABVFP` Semantics & LLVM/WAT Lifter Completeness (`validation/ssa_translation_validator.py`, `validation/backend_translation_validator.py`):**
   - Unified `_load_off_z3` and `_store_off_z3` via `_INT_WIDTH_SPEC` (`z3.SignExt`/`z3.ZeroExt`/`z3.Extract`), and expanded witness probe byte offsets across packed struct fields (`0, 1, 2, 4, 6, 8, 12, 16, 20, 24`).
   - Generalized `LLVMIRToSSALifter` and `WATToSSALifter` for `i8`/`u8`/`i16`/`u16`/`i32` signed/unsigned loads and stores.

---

## 2. Adversarial Bug Found & Fixed During Audit

1. **Cross-File / Cross-Repo Struct Parameter Annotation Drop in Polyglot Frontends (`frontends/polyglot_ssa_lowering.py`):**
   - *Finding:* When Rust `hdr.rs` defined `Header` while taking `(f: &mut Frame)` where `Frame` was declared in Go `frame.go` (a separate file/repository), `_skip_rust_or_ts_type` and `_skip_go_type` checked only `if tok in self.declared_structs`, discarding `"Frame"` to `None` before `OmniRepoCompiler` merged `global_struct_layouts`. Inside `rs_bump_hdr`, `f.hdr.flags += delta_flags;` failed `_resolve_struct_field` silently, leaving `pkt.hdr.flags == -10` instead of `-7`.
   - *Fix:* Updated `_skip_rust_or_ts_type`, `_skip_go_type`, and `_make_function_def` to preserve PascalCase custom struct type names across file boundaries so `AstToSsaLowering` binds them against `global_struct_layouts`.

---

## 3. Verification Evidence

- `python run_c34_tests.py`: **4/4 PASS** (`0.415s`), covering:
  - Exact offset & byte congruence against CPython `ctypes.Structure` (`CHeader`, `CPacketFrame`, `sizeof == 32`), Z3 `QF_ABVFP` LLVM+WAT proofs (`proven == True`), and `Native == LLVM == Wasmtime` parity.
  - Real Unicorn ARM64 execution of `LDRSB`/`LDRB`/`LDRSH`/`LDRH`/`LDR W`/`STRB`/`STRH` on `CPacketFrame`.
  - Cross-repo nested structs (`Header` in Rust, `Frame` in Go, `ts_step_frame` in TS) compiled via `OmniRepoCompiler` across `native`, `llvm` (`refuted == 0`), and `wasm` + Wasmtime execution.
  - W^X x86_64 JIT heap struct serialization via `omni_alloc` + `store_*` compared against `CPacketFrame` via real host C `libc`/`msvcrt` `memcmp` (`0` when identical, `!= 0` on 1-byte mutation).
- `AetherMind_Strict_Auditor.py run_c34_tests.py`: **APROVADO**
- `AetherMind_Strict_Auditor.py run_full_regression.py`: **APROVADO** (`C13`–`C34`)
- `python -W default -m unittest discover -s tests -t F:\repository-compiler`: **218/218 PASS**, 0 warnings (`31.025s`)
