# Adversarial Audit Report — Alpha-C57: Coupled 2-State & Second-Order Linear Recurrences & Direct 128-bit ARM64 NEON / ASIMD Hardware Emission

## 1. Executive Summary
- **Milestone:** Alpha-C57
- **Targets Audited:**
  - [`compiler/loop_vectorizer.py`](file:///F:/repository-compiler/compiler/loop_vectorizer.py) (`"coupled_2x2"`, `_mat2x2_mul`, `_emit_weighted_linear_sum`, `_emit_coupled_2x2_1x_row`, `_emit_coupled_2x2_4x_row`, `_decompose_coupled_linear_expr`)
  - [`compiler/native_codegen.py`](file:///F:/repository-compiler/compiler/native_codegen.py) (`Arm64CodeGenerator.compile_function` 128-bit NEON / ASIMD `LDR Q0`, `STR Q0`, `V0.2D`, `V0.4S`, `V0.16B`, `ADDP D0, V0.2D`, `FADDP D0, V0.2D`, 24-bit stack frame size support)
  - [`validation/silicon_safety_sandbox.py`](file:///F:/repository-compiler/validation/silicon_safety_sandbox.py) (`SiliconSafetySandbox.emulate_arm64` `memory_regions` & `memory_snapshots`)
  - [`tests/test_alpha_c57_coupled_2x2_and_arm64_neon.py`](file:///F:/repository-compiler/tests/test_alpha_c57_coupled_2x2_and_arm64_neon.py)

## 2. Adversarial Findings Resolved During Implementation
1. **Cross-Accumulator SSA Substitution Collision (`a = b; b = a + b + v`):**
   - *Adversarial Vector:* In a second-order recurrence `nxt = a + b + v; a = b; b = nxt`, the back-edge value `r_a["acc_next"]` of state variable `a` is the previous-iteration SSA variable `b_1 == r_b["acc_prev"]`. Naively substituting `{r_a["acc_prev"], r_a["acc_next"]}` with `a`'s post-loop merged variable would overwrite post-loop uses of `b_1` before `r_b`'s substitution runs.
   - *Resolution:* All 4 `_substitute_loop_uses` call sites in [`compiler/loop_vectorizer.py`](file:///F:/repository-compiler/compiler/loop_vectorizer.py) now exclude `other_prevs = {o["acc_prev"] for o in red_specs if o is not r}` from `target_vars`.
2. **ARM64 Stack Frame Overflow for Vectorized Loops (`frame_size > 4095`):**
   - *Adversarial Vector:* Strip-mined 4-way vectorized kernels with multiple 128-bit store pairs and coupled $2 \times 2$ matrix temporaries allocate $> 512$ SSA virtual slots ($> 4096$ bytes), overflowing the 12-bit immediate field of a single ARM64 `SUB SP, SP, #imm12`.
   - *Resolution:* Added 24-bit stack frame allocation and deallocation in `Arm64CodeGenerator.compile_function` using `LSL #12` high-12-bit `SUB/ADD SP, SP, #hi12, LSL #12` (`0xD14003FF` / `0x914003FF`) paired with low-12-bit `SUB/ADD SP, SP, #lo12`.

3. **Multi-Pair Coupled 2x2 Partitioning:** `_extract_reduction_specs_from_phis` now pairs coupled accumulators by mutual dependence (several disjoint 2x2 systems per loop, e.g. `(a, b)` and `(x, y)`), and `_build_unrolled_tree_reduction` uses per-pair unique SSA temp names.
4. **Stale C49 Anti-Misvectorization Test:** `test_alpha_c49_dynamic_stripmining::test_04` asserted that non-zero start and stride-2 loops never vectorize; Alpha-C54 intentionally added that support. This made the ubuntu CI jobs of C54, C55 and C56 fail (windows passed). The test now keeps only genuinely unsupported cases (`non_pow2_step`, `loop_variant_bound`).

## 3. Empirical Verification Summary
- Full regression: 300 tests, all OK after the C49 test fix (see commit).
- **`run_c57_tests.py`:** 5/5 end-to-end tests passing (Z3 memory safety, coupled $2 \times 2$ recurrences, ARM64 NEON 128-bit Unicorn execution, Quad-ISA x86-64/ARM64/WASM/LLVM parity, and `OmniRepoCompiler` PE64/ELF64 executables).
- **Strict Auditor (`AetherMind_Strict_Auditor.py`):** `APROVADO`.
