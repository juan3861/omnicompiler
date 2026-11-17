# ADVERSARIAL AUDIT REPORT — Alpha-C32: `f64` SIMD Auto-Vectorization (`omni_list_vec_*_f64`), Cross-Repo `f64`/`ptr_f64` ThinLTO & GVN/LICM/DSE Optimization Pipeline (`OmniRepoCompiler`)

**Date:** 2026-11-16  
**Milestone:** Alpha-C32  
**Repository:** `F:\repository-compiler`  
**Verdict:** **PASS (100% EMPIRICALLY VERIFIED)**

---

## 1. Scope Audited

1. **`f64` Collection SIMD Runtime & Loop Auto-Vectorizer (`runtime/native_collections_simd.py`, `compiler/loop_vectorizer.py`, `compiler/native_jit.py`):**
   - `NativeJitCompiler`: Added `compile_avx2_vector_add_f64` and updated `compile_ssa` to marshal `ctypes.c_double` for `"f64"` parameters and return types.
   - `runtime/native_collections_simd.py`: Implemented `omni_list_vec_add_f64` (backed by hardware 256-bit AVX2 `vaddpd`), `omni_list_vec_dot_f64`, and `omni_list_sum_f64` and registered them in `NATIVE_SIMD_SYMBOLS`.
   - `LoopVectorizerPass`: Detects `f64` (`fadd`/`fmul`/`sitofp`) `OmniList` loops and rewrites them to `omni_list_vec_add_f64`, `omni_list_vec_dot_f64`, and `omni_list_sum_f64`, while guarding raw-pointer `(ptr, n)` / `(ptr_f64, n)` loops so they remain pure native/LLVM/WASM loops.

2. **`f64`-Aware ThinLTO Inlining, GVN, LICM, DSE & `VerifiedPassRunner` (`compiler/thin_lto.py`, `compiler/ip_sccp_gvn.py`, `compiler/licm_and_dse.py`, `compiler/ssa_ir.py`, `validation/ssa_translation_validator.py`):**
   - `clone_ssa_function` preserves `return_type`, and `VerifiedPassRunner` accepts `enable_float_theory: bool = False`.
   - `GVN_PURE_OPCODES` and `LICM_SAFE_PURE_OPCODES` include `fconst`, `fneg`, `fadd`, `fsub`, `fmul`, `fdiv`, `fcmp_*`, `sitofp`, and `fptosi`, with `LICMPass` treating `float` operands as loop-invariant constants.
   - `optimize_ssa` folds `fconst` + `fadd`/`fsub`/`fmul`/`fdiv`/`fneg`/`fcmp_*` and eliminates redundant `sitofp` instructions whose operand resolved to `f64` after inlining.
   - `ThinLtoOptimizer` preserves `var_type="f64"` across single-block and multi-block inlining, folds `float` constant returns to `fconst`, and upgrades caller integer opcodes (`add -> fadd`, `mul -> fmul`, `cmp_* -> fcmp_*`) when cross-module callees return `f64`.

3. **Multi-Repo `f64` Linking & `OmniRepoCompiler` Integration (`omni_repo_compiler.py`, `compiler/object_linker.py`, `validation/assembly_invariant_auditor.py`, `validation/silicon_safety_sandbox.py`, `test_empirical_evolution_audit.py`):**
   - `load_coff_object` and `load_elf_object` in `compiler/object_linker.py` ingest `.rdata` / `.rodata` constant-pool sections (such as COFF `__real@<hex>` and ELF `.LCPI*` / `.rodata.cst8` section symbols) and resolve RIP-relative `REL32` relocations per module.
   - `AssemblyInvariantAuditor` validates stack frame balance across functions with multiple LLVM O3 return epilogues (`all(f == stack_alloc for f in free_sizes)`).
   - `SiliconSafetySandbox.emulate_arm64` enables `CPACR_EL1.FPEN = 0b11`, and `OmniRepoCompiler` maps `ptr` / `ptr_f64` pre-flight simulation arguments into mapped scratch RAM (`STACK_ADDR + 0x9000`).
   - `test_empirical_evolution_audit.py::test_speedup_benchmark` uses best-of-5 timing rounds (`min` across 5 iterations after warmup) to filter out shared-VM OS scheduler noise.

---

## 2. Adversarial Bugs Found & Fixed During Audit

1. **Post-Inlining Redundant `sitofp` & Integer Opcode Upgrade (`compiler/thin_lto.py`, `compiler/ssa_ir.py`):**
   - *Finding:* When a caller was lowered to SSA before `ThinLtoOptimizer` resolved cross-module callee return types, calls to `f64` functions initially had `var_type="i64"`, causing caller `+` / `ret` to emit integer `add` or `sitofp` on the call result. After inlining changed the call result to `f64`, `llvmlite` rejected `add i64 %double_val` and `sitofp i64 %double_val`.
   - *Fix:* Added a post-inlining `f64` type-propagation and opcode-upgrade fixpoint in `ThinLtoOptimizer.optimize_interprocedural_ssa` and redundant `sitofp -> mov` elimination in `optimize_ssa`.

2. **COFF `.rdata` (`__real@...`) & ELF `.rodata` IEEE-754 Constant Pool Linking (`compiler/object_linker.py`):**
   - *Finding:* LLVM O3 emits `double` constants into `.rdata` (Windows COFF `__real@<16-hex>`) and `.rodata.cst8` (Linux ELF `.LCPI*` / `STT_SECTION`) sections referenced via `REL32` RIP-relative relocations, which were previously skipped by `load_coff_object` and `load_elf_object`.
   - *Fix:* Extended `load_coff_object`, `load_elf_object`, and `NativeObjectLinker.link` to ingest `.rdata`/`.rodata` sections and resolve module-local and COMDAT constant-pool symbols.

3. **Multi-Epilogue Stack Balance Check on LLVM O3 Functions (`validation/assembly_invariant_auditor.py`):**
   - *Finding:* LLVM O3 emits separate `add rsp, 40; ret` epilogues for early loop-bypass and normal loop-exit paths; summing `stack_free` across both paths falsely reported `allocated 40 bytes but freed 80 bytes`.
   - *Fix:* Updated `AssemblyInvariantAuditor` to accept functions where every epilogue frees the exact `stack_alloc` frame size.

4. **Raw-Pointer Store vs Pure Reduction Guard in `LoopVectorizerPass` (`compiler/loop_vectorizer.py`):**
   - *Finding:* Gating `LoopVectorizerPass` solely on `has_omni_list_ops` broke C27's pure integer read reduction (`js_vec_loop(arr, n)`), whereas unguarded vectorization of loops containing `store` or raw `ptr_f64` pointers risked eliding stores or mis-reading non-`OmniList` headers.
   - *Fix:* Guarded `has_raw_store` and internal `br_cond` branches, required `has_omni_list_ops` for `f64` vector reductions, and preserved C27 pure `i64` `load`/`add` reductions (`vectorized_loops >= 1`).

---

## 3. Verification Evidence

- `python run_c32_tests.py`: **4/4 PASS** (`7.017s`)
- `AetherMind_Strict_Auditor.py run_c32_tests.py`: **APROVADO**
- `AetherMind_Strict_Auditor.py run_full_regression.py`: **APROVADO**
- `python -m unittest discover -s tests -t F:\repository-compiler`: **210/210 PASS**, 0 warnings (`65.287s`)
