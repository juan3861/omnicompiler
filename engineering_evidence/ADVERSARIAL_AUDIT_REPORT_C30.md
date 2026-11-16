# ADVERSARIAL AUDIT REPORT — Alpha-C30: Full IEEE-754 Floating-Point (`f64`) Stack Across Polyglot AST, Omni-SSA, Native SSE2/ARM64, LLVM, WASM & Z3 QF_FP

**Date:** 2026-11-16  
**Milestone:** Alpha-C30  
**Repository:** `F:\repository-compiler`  
**Verdict:** **PASS (100% EMPIRICALLY VERIFIED)**

---

## 1. Scope Audited

1. **Omni-SSA Typed Floating-Point IR (`compiler/ssa_ir.py`):**
   - `SSAFunction.return_type` (`"i64"` | `"f64"`) and `SSAVar.var_type` (`"f64"`) propagation across `param`, `ret`, `phi`, and multi-block CFGs (`if/else`, `while`, `for`).
   - Full IEEE-754 scalar double instruction set: `fconst`, `fneg`, `fadd`, `fsub`, `fmul`, `fdiv`, `fcmp_{eq,ne,lt,le,gt,ge}`, `select`, `sitofp` (`float(x)` and implicit mixed `i64`/`f64` promotion), and `fptosi` (`int(x)`).
   - Post-seal `_finalize_ssa_types` pass eliminating redundant `sitofp` casts whose source operand was resolved to `f64` via unsealed loop-header `phi` nodes or parameter annotations.

2. **Native x86-64 SSE2 & ARM64 VFPv8 Code Generators (`compiler/native_codegen.py`):**
   - **x86-64 SSE2 (`X64CodeGenerator`):** Win64 (`xmm0..xmm3`) & System V AMD64 (`xmm0..xmm7`) parameter/call ABIs, `xmm0` return ABI, IEEE-754 bit-exact `fconst` loading (`movabs r64, imm64` + `movq xmm, r64`), scalar double `addsd`/`subsd`/`mulsd`/`divsd`, sign-bit `fneg` (`1 << 63` XOR), `cvtsi2sd`, `cvttsd2si`, and ordered/unordered-safe `ucomisd` comparisons (`fcmp_eq` checking `ZF=1 && PF=0`, `fcmp_ne` checking `ZF=0 || PF=1`, `fcmp_lt/le/gt/ge` via swapped/direct `seta`/`setae`).
   - **ARM64 VFPv8 (`ARM64CodeGenerator`):** AAPCS64 `d0..d7` incoming/call/return registers, `FMOV Dd, Xn` / `FMOV Xd, Dn`, scalar double `FADD`, `FSUB`, `FMUL`, `FDIV`, `FNEG`, `SCVTF`, `FCVTZS`, and `FCMP` + `CSET`, physically verified on Unicorn ARMv8-A (`CPACR_EL1.FPEN = 0b11`).

3. **LLVM `double` & WebAssembly `f64` Backends (`compiler/llvm_backend.py`, `compiler/wasm_backend.py`):**
   - `LLVMBackend`: Exact 16-hex-digit IEEE-754 constant encoding (`0x<16-hex>`), `double` parameter/return/phi types, `fadd`/`fsub`/`fmul`/`fdiv`/`fneg`/`fcmp`/`sitofp`/`fptosi`, verified via `llvmlite` O3 MCJIT execution.
   - `WasmBackend`: Typed `(param $... f64)`, `(result f64)`, `(local $... f64)` (including `$ptmp_*` phi temporaries), `f64.const`, `f64.add/sub/mul/div/neg`, `f64.eq/ne/lt/le/gt/ge`, `f64.convert_i64_s`, `i64.trunc_f64_s`, verified via `wasmtime` execution.

4. **Z3 `QF_FP` (`Float64`) Translation Validation & Lifters (`validation/ssa_translation_validator.py`, `validation/backend_translation_validator.py`):**
   - `SSATranslationValidator(enable_float_theory=True)` models IEEE-754 double precision via `z3.Float64()` (`FPSort(11, 53)`, `z3.RNE()`, `z3.RTZ()` for `fptosi`), bit-exact `z3.fpToIEEEBV` storage, algebraic `z3.simplify` equivalence fast-path, and sound `z3.substitute` witness refutation.
   - `LLVMIRToSSALifter` and `WATToSSALifter` lift single-block and multi-block `$cfg_dispatch` `double`/`f64` functions back to typed `SSAFunction`s.
   - `BackendTranslationValidator.verify_differential_execution` executes `ctypes.c_double` signatures across Native x86-64 JIT, LLVM O3 MCJIT, and Wasmtime with bit-exact (`struct.pack("<d", ...)`) comparison.

5. **Polyglot `f64` Lowering (`frontends/polyglot_ssa_lowering.py`):**
   - Supports `allow_floats: bool = False` plus automatic enablement when explicit `f64` / `float64` / `double` type annotations are present in Rust, Go, TypeScript, or JavaScript, while keeping C27 unannotated strict-mode float rejection (`PolyglotLoweringError`) 100% intact.

---

## 2. Adversarial Bugs Found & Fixed During Audit

1. **Redundant `sitofp` on Unsealed Loop-Header Phis (`compiler/ssa_ir.py`):**
   - *Finding:* During loop body lowering (`for i in range(1, n + 1): acc = acc + (scale / float(i))`), `for_cond` was not yet sealed when `acc` and `scale` were read, causing temporary `i64`-typed Phi placeholders to trigger `_promote_to_f64` (`sitofp`) before `_seal_block` / `_finalize_ssa_types` resolved them to `f64`. `llvmlite` rejected `sitofp i64 %arg_scale to double` because `%arg_scale` had type `double`.
   - *Fix:* Added redundant `sitofp` elimination in `_finalize_ssa_types` whenever `inst.opcode == "sitofp"` has an operand whose resolved `var_type == "f64"`, rewriting all downstream uses to the `f64` source variable.

2. **WAT Multi-Block Lifter `const [0.0]` in `SSATranslationValidator` (`validation/ssa_translation_validator.py`):**
   - *Finding:* `WATToSSALifter` initialized `f64` locals with `SSAInstruction(..., "const", [0.0])`, which triggered `NON_INT_CONST` in `SSATranslationValidator`.
   - *Fix:* Enabled `isinstance(val, float) and self.enable_float_theory` in both DAG and unrolled `op == "const"` handlers in `SSATranslationValidator`.

3. **Z3 `QF_FP` 53-Bit Adder Bit-Blasting Timeout on Non-Associativity Refutation (`validation/ssa_translation_validator.py`):**
   - *Finding:* Full SAT bit-blasting of `(a + b) + c != a + (b + c)` over unconstrained 64-bit `Float64` timed out under heavy test load.
   - *Fix:* Added sound `z3.is_true(z3.simplify(z3.substitute(mismatch_cond, *subst_pairs)))` witness probing over canonical IEEE-754 vectors (`(0.1, 0.2, 0.3)`, `(1e16, -1e16, 1.0)`, etc.) and `z3.simplify` AST equality before full `solver.check()`, reducing `test_alpha_c30_ieee754_float_stack.py` runtime to `1.714s`.

---

## 3. Verification Evidence

- `python run_c30_tests.py`: **5/5 PASS** (`1.714s`)
- `AetherMind_Strict_Auditor.py run_c30_tests.py`: **APROVADO**
- `AetherMind_Strict_Auditor.py run_full_regression.py`: **APROVADO**
- `python -m unittest discover -s tests -t F:\repository-compiler`: **202/202 PASS**, 0 warnings
