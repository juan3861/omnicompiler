# ACCEPTANCE CONTRACT — Alpha-C32: `f64` SIMD Auto-Vectorization (`omni_list_vec_*_f64`), Cross-Repo `f64`/`ptr_f64` ThinLTO & GVN/LICM/DSE Optimization Pipeline (`OmniRepoCompiler`)

**Status:** FROZEN BEFORE IMPLEMENTATION  
**Milestone:** Alpha-C32 (`F:\repository-compiler`)  
**Baseline:** Alpha-C31 (`e3ad8ca`, CI `43978710863`, 206 discovery PASS, zero warnings)

## 1. Deliverables & Architecture Contracts

1. **`f64` Collection SIMD Runtime & Loop Auto-Vectorizer (`runtime/native_collections_simd.py`, `compiler/loop_vectorizer.py`, `compiler/native_jit.py`):**
   - Add `compile_avx2_vector_add_f64` on `NativeJitCompiler` and wire `NativeJitCompiler.compile_ssa` to use `ctypes.c_double` for `"f64"` parameters and return types.
   - Add `omni_list_vec_add_f64`, `omni_list_vec_dot_f64`, and `omni_list_sum_f64` in `runtime/native_collections_simd.py` (backed by hardware 256-bit AVX2 `vaddpd` and 4-way ILP `ctypes.c_double` IEEE-754 accumulators) and register them in `NATIVE_SIMD_SYMBOLS`.
   - Extend `LoopVectorizerPass` (`compiler/loop_vectorizer.py`) to detect `f64` (`fadd`/`fmul`) `OmniList` loops and rewrite them to `omni_list_vec_add_f64`, `omni_list_vec_dot_f64`, and `omni_list_sum_f64`, while guarding raw-pointer `(ptr, n)` / `(ptr_f64, n)` loops (without `OmniList` allocation/length calls) so raw-pointer loops remain pure LLVM/WASM/Native loops.

2. **`f64`-Aware ThinLTO Inlining, GVN, LICM, DSE & `VerifiedPassRunner` (`compiler/thin_lto.py`, `compiler/ip_sccp_gvn.py`, `compiler/licm_and_dse.py`, `compiler/ssa_ir.py`, `validation/ssa_translation_validator.py`):**
   - Preserve `return_type` in `clone_ssa_function` (`compiler/ip_sccp_gvn.py`) and add `enable_float_theory: bool = False` to `VerifiedPassRunner.__init__`.
   - Add pure `f64` opcodes (`fconst`, `fneg`, `fadd`, `fsub`, `fmul`, `fdiv`, `fcmp_*`, `sitofp`, `fptosi`) to `GVN_PURE_OPCODES` (`compiler/ip_sccp_gvn.py`) and `LICM_SAFE_PURE_OPCODES` (`compiler/licm_and_dse.py`), and fold `fconst` + `fadd`/`fsub`/`fmul`/`fdiv`/`fneg`/`fcmp_*` in `optimize_ssa` (`compiler/ssa_ir.py`).
   - Preserve `var_type="f64"` across single-block and multi-block inlining, constant-float return folding, and cross-module call return types in `ThinLtoOptimizer` (`compiler/thin_lto.py`).

3. **End-to-End Multi-Repo `f64` / `ptr_f64` Compilation in `OmniRepoCompiler` (`omni_repo_compiler.py`) & CI Anti-Jitter Hardening (`test_empirical_evolution_audit.py`):**
   - Add `"float"`, `"omni_list_vec_add_f64"`, `"omni_list_vec_dot_f64"`, and `"omni_list_sum_f64"` to `NATIVE_BUILTIN_CALLS`, enable `enable_float_theory=True` on `VerifiedPassRunner` in `OmniRepoCompiler`, and support `add_function` alias on `ThinLtoSummaryIndex`.
   - Harden `test_empirical_evolution_audit.py::test_speedup_benchmark` using best-of-5 timing rounds (`min` across 5 iterations after warmup) to eliminate OS scheduler preemption noise on shared CI VMs.

## 2. Empirical Acceptance Gates

- `tests/test_alpha_c32_f64_autovec_thinlto_and_omnirepo.py` + `run_c32_tests.py`:
  1. `LoopVectorizerPass` + `NativeJitCompiler` auto-vectorization and physical execution of `f64` `OmniList` vector addition (`omni_list_vec_add_f64`), dot product (`omni_list_vec_dot_f64`), and reduction sum (`omni_list_sum_f64`).
  2. `VerifiedPassRunner(enable_float_theory=True)` running `GVN`, `LICM`, and `DSE` (store-to-load forwarding) on `f64` & `ptr_f64` functions with formal Z3 `PROVEN_EQUIVALENT` / `PROVEN_INDUCTIVE_EQUIVALENT` proofs.
  3. Cross-repository `f64` + `ptr_f64` ThinLTO inlining and full multi-repo compilation (`Rust` + `Go` + `TypeScript`) through `OmniRepoCompiler` across `backend="native"`, `backend="llvm"`, and `backend="wasm"` with physical Wasmtime execution parity.
- Full regression `run_full_regression.py` + `unittest discover`, `AetherMind_Strict_Auditor.py` `APROVADO`, and GitHub Actions CI green on `ubuntu-latest` and `windows-latest`.
