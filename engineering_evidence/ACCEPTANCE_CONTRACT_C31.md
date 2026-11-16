# ACCEPTANCE CONTRACT — Alpha-C31: Typed IEEE-754 `f64` Linear Memory Arrays (`ptr_f64`), In-Place Mutation & Unbounded `QF_ABVFP` Inductive Loop Verification

**Status:** FROZEN BEFORE IMPLEMENTATION  
**Milestone:** Alpha-C31 (`F:\repository-compiler`)  
**Baseline:** Alpha-C30 (`98ac0d2`, CI `43973046939`, 202 discovery PASS, zero warnings)

## 1. Deliverables & Architecture Contracts

1. **Typed `f64` Linear Memory (`ptr_f64`) in Omni-SSA (`compiler/ssa_ir.py`):**
   - Recognize float pointer/slice parameter annotations (`ptr_f64`, `f64_ptr`, `float_ptr`, `Float64Array`, `list[float]`, `ptr[float]`) and set `param_types[p] = "ptr_f64"`.
   - Lower `a[i]` (`ast.Subscript` load) on `ptr_f64` (or `*_f64_ptr` / `*_f64_buf`) to `SSAInstruction(res, "load", [base_var, idx_var])` with `res.var_type = "f64"`.
   - Lower `a[i] = val` (`_assign_target`) on `ptr_f64` with automatic `sitofp` promotion when `val` is `i64`.
   - Lower `a[i] += val` / `-=` / `*=` / `/=` (`ast.AugAssign` on `ast.Subscript`) on raw pointers (`ptr` and `ptr_f64`) directly to `load` + arithmetic (`fadd`/`fsub`/`fmul`/`fdiv` or integer binop) + `store`.

2. **Polyglot Float Slice/Array Lowering (`frontends/polyglot_ssa_lowering.py`):**
   - Recognize Rust `&[f64]`, `&mut [f64]`, `*const f64`, `*mut f64`; Go `[]float64`, `[]f64`; and TypeScript/JS `Float64Array`, `f64[]`, `double[]`, `Array<f64>`, `Array<double>` as `ptr_f64` parameter annotations and auto-enable float literal tokenization when present.

3. **LLVM `double` & WASM `f64` Memory Codegen + Lifters + Differential Array Execution (`compiler/llvm_backend.py`, `compiler/wasm_backend.py`, `validation/backend_translation_validator.py`):**
   - `LLVMBackend` & `LLVMIRToSSALifter`: Emit and lift `getelementptr double, ptr %ptr, i64 %idx`, `load double, ptr %gep, align 8`, and `store double %val, ptr %gep, align 8`.
   - `WasmBackend` & `WATToSSALifter`: Emit and lift `f64.load` and `f64.store`.
   - `BackendTranslationValidator.verify_differential_execution`: Support `list` array arguments for `ptr` and `ptr_f64` parameters across Native x86-64 JIT, LLVM O3 MCJIT, and Wasmtime linear memory (`memory.write` / `memory.read`), verifying bit-exact parity of both return values and post-call mutated memory buffers (`memory_by_backend`).

4. **Native x86-64 AVX2 `vaddpd` & ARM64 NEON `FADD Vd.2D` + VFP `f64` Array Execution (`compiler/native_codegen.py`):**
   - Add `emit_avx2_vector_add_f64` (256-bit `vmovupd` / `vaddpd` 4x `f64` per cycle + scalar `addsd` tail) in `X64CodeGenerator` and `emit_neon_vector_add_f64` (`LDR Q0`/`LDR Q1`, `FADD V0.2D, V0.2D, V1.2D`, `STR Q0` + scalar `FADD D0` tail) in `ARM64CodeGenerator`, verified physically on x86-64 silicon and Unicorn ARMv8-A.

5. **Unbounded Inductive `QF_ABVFP` Loop Translation Validation (`validation/ssa_translation_validator.py`):**
   - Support float constants in `eval_pre_val`, `eval_loop_val`, and `_eval_var_in_seg`.
   - Apply sound Leibniz-equality invariant substitution (`sym_a := sym_b`, `sym_ext_a := sym_ext_b`, `sym_loc_a := sym_loc_b`) + `z3.simplify` in `_verify_inductive_loop_equivalence` and `_verify_loop_sequence_in_region` so unbounded `f64` and `f64`-array loops prove `PROVEN_INDUCTIVE_EQUIVALENT` (`bounded=False`).
   - Extend concrete witness substitution with `z3.K(bv64, ...)` initial memory and `z3.Select(mem_b, addr) != z3.Select(mem_a, addr)` congruence checks to refute mutated `f64` array loads/stores (`REFUTED_COUNTEREXAMPLE`).

## 2. Empirical Acceptance Gates

- `tests/test_alpha_c31_f64_memory_and_inductive_qfabvfp.py` + `run_c31_tests.py`:
  1. Python & Polyglot (Rust `&mut [f64]`, Go `[]float64`, TS `Float64Array`) `f64` array reductions and in-place mutations (`a[i] = ...`, `a[i] += ...`), bit-exact return + post-call buffer parity across Native x86-64, LLVM O3, and Wasmtime.
  2. Unbounded inductive `QF_ABVFP` loop equivalence (`PROVEN_INDUCTIVE_EQUIVALENT`, `bounded=False`) across LICM-optimized `f64` array loops, nested 2D `f64` array loops, `SSA <-> LLVM IR`, and `SSA <-> WAT`, plus mutation refutation (`REFUTED_COUNTEREXAMPLE`).
  3. Physical execution of x86-64 AVX2 `emit_avx2_vector_add_f64` and ARM64 NEON `emit_neon_vector_add_f64` + ARM64 scalar `f64` array loops on Unicorn ARMv8-A.
- Full regression `run_full_regression.py` + `unittest discover`, `AetherMind_Strict_Auditor.py` `APROVADO`, and GitHub Actions CI green on `ubuntu-latest` and `windows-latest`.
