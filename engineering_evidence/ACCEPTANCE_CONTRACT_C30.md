# ACCEPTANCE CONTRACT — Alpha-C30: Full IEEE-754 Floating-Point (`f64`) Stack Across Polyglot AST, Omni-SSA, Native SSE2/ARM64, LLVM, WASM & Z3 QF_FP

**Status:** FROZEN BEFORE IMPLEMENTATION  
**Milestone:** Alpha-C30 (`F:\repository-compiler`)  
**Baseline:** Alpha-C29 (`4499d2f`, CI `43793051145`, 197 discovery PASS, zero ResourceWarnings)

## 1. Deliverables & Architecture Contracts

1. **Typed IEEE-754 `f64` Omni-SSA IR (`compiler/ssa_ir.py`):**
   - Add `return_type: str = "i64"` on `SSAFunction` and propagate `"f64"` across `SSAVar`, `param`, `ret`, `phi`, and control flow (`if/else`, `while`, `for`).
   - Support float annotations (`float`, `f64`, `float64`, `double`), float constants (`fconst`), `fneg`, `fadd`, `fsub`, `fmul`, `fdiv`, `fcmp_{eq,ne,lt,le,gt,ge}`, `select` over `f64`, `sitofp` (`float(x)` / implicit mixed int->float promotion), and `fptosi` (`int(x)`).
   - Preserve 100% backward compatibility with integer (`i64`) single-expression fast path and integer `Div` semantics when no float operands/annotations are present.

2. **Native x86-64 SSE2 & ARM64 VFP Codegen (`compiler/native_codegen.py`):**
   - x86-64: Emit IEEE-754 SSE2 scalar double instructions (`addsd`, `subsd`, `mulsd`, `divsd`, `ucomisd`, `cvtsi2sd`, `cvttsd2si`, `movq`, bit-63 `fneg`), ABI parameter loading (`xmm0..xmm3` Win64, `xmm0..xmm7` SysV) and `xmm0` return.
   - ARM64: Emit scalar VFPv8 instructions (`fadd`, `fsub`, `fmul`, `fdiv`, `fcmp`+`cset`, `scvtf`, `fcvtzs`, `fmov`), incoming `d0..d7` params, and `d0` return, verified physically on Unicorn ARM64.

3. **LLVM & WebAssembly Typed `f64` Codegen (`compiler/llvm_backend.py`, `compiler/wasm_backend.py`):**
   - `LLVMBackend`: Emit LLVM `double` signatures, constants, `fadd`/`fsub`/`fmul`/`fdiv`/`fneg`, `fcmp`, `sitofp`, `fptosi`, and typed `phi` nodes.
   - `WasmBackend`: Emit WAT `f64` params/locals/results/phi-temps (`f64.const`, `f64.add`, `f64.sub`, `f64.mul`, `f64.div`, `f64.neg`, `f64.eq/ne/lt/le/gt/ge`, `f64.convert_i64_s`, `i64.trunc_f64_s`).

4. **Z3 `QF_FP` (`Float64`) Translation Validation & Backend Lifters (`validation/ssa_translation_validator.py`, `validation/backend_translation_validator.py`):**
   - Add `enable_float_theory: bool = False` in `SSATranslationValidator` modeling `"f64"` via `z3.Float64()` (`z3.FPSort(11, 53)`, `z3.RNE()`) and IEEE-754 bit-exact checks (`z3.fpToIEEEBV`).
   - Lift `double` (LLVM IR) and `f64` (WAT) in `LLVMIRToSSALifter` and `WATToSSALifter`, and support `ctypes.c_double` + `float` vectors in `BackendTranslationValidator.verify_differential_execution`.

5. **Polyglot `f64` Lowering (`frontends/polyglot_ssa_lowering.py`):**
   - Support `allow_floats: bool = False` (plus automatic enablement when explicit `f64`/`float64`/`double` type annotations are present), emitting typed Python `ast.FunctionDef` (`float` parameter & return annotations) across Rust, Go, TypeScript, and JavaScript while keeping C27 unannotated strict-mode rejection intact.

## 2. Empirical Acceptance Gates

- `tests/test_alpha_c30_ieee754_float_stack.py` + `run_c30_tests.py`:
  1. Python & Polyglot (Rust `f64`, Go `float64`, TS `allow_floats=True`) `f64` arithmetic, `if/else`, counted/while loops, mixed `sitofp`/`fptosi`, and bit-exact physical execution parity (`Native x86-64 SSE2` == `LLVM O3 MCJIT` == `Wasmtime`).
  2. ARM64 VFP scalar `f64` physical execution on Unicorn ARM64 simulator.
  3. Formal Z3 `QF_FP` Equivalence (`PROVEN_EQUIVALENT`) across `SSATranslationValidator`, `SSA <-> LLVM IR`, and `SSA <-> WAT`, plus IEEE-754 non-associativity / constant bug detection (`REFUTED_COUNTEREXAMPLE`).
  4. C27 backward-compatibility check (`allow_floats=False` still fails closed on unannotated JS floats).
- Full regression `run_full_regression.py` + `unittest discover`, `AetherMind_Strict_Auditor.py` `APROVADO`, and GitHub Actions CI green on `ubuntu-latest` and `windows-latest`.
