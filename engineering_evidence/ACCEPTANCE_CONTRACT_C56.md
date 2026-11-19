# ACCEPTANCE CONTRACT — Alpha-C56: Prefix-Scan Vectorization, Estrin 4-Way Linear Recurrences & x86-64 SSE2 128-bit Horizontal Tree Reduction

## 1. Executive Summary
**Alpha-C56** expands `OmniCompiler` across loop recurrence/scan auto-vectorization (`compiler/loop_vectorizer.py`) and 128-bit SSE2 horizontal tree collapse (`compiler/native_codegen.py`):

1. **Inclusive & Exclusive Prefix-Scan Vectorization (`s += v; out[i] = s` & `out[i] = s; s += v`)**:
   - Recognizes when a reduction accumulator's `acc_next` (inclusive scan) or `acc_prev` (exclusive scan) is written to memory by a `store_off` (`r["is_scan"] = True`).
   - Evaluates the 4-element intra-chunk prefix chain $(S_0, S_1, S_2, S_3)$ in register before emitting the 4 contiguous `store_off`s (which `X64CodeGenerator` and `WasmBackend` fuse into 128-bit `movdqu` / `v128.store` vector stores), while simultaneously supporting parallel independent reductions (e.g., `mx = max(mx, v)`) in the same loop pass.

2. **First-Order Linear Recurrence Vectorization via Estrin's 4-Way Parallel Horner Tree (`acc = acc * c +/- v` & `acc = (acc << sh) +/- v`)**:
   - Classifies first-order linear recurrences (`_classify_linear_recurrence`) where the accumulator is scaled by a compile-time constant integer $c$ (via `mul` or `shl`) and combined with a loop-body delta via `add` or `sub`.
   - Applies Estrin's 4-way parallel recurrence unrolling in $\mathbb{Z} / 2^{64}\mathbb{Z}$:
     $$S_{\text{next}} = S \cdot c^4 \pm \left( ((d_0 \cdot c^2 + d_2) \cdot c) + (d_1 \cdot c^2 + d_3) \right)$$
     cutting the loop-carried dependency chain latency on $S$ by 4x (from 4 serial multiplications + 4 additions to 1 multiplication + 1 addition per 4 elements) while preserving 100% bit-exact modular integer equivalence.

3. **Direct x86-64 SSE2 128-bit Horizontal Tree Reduction (`X64CodeGenerator`)**:
   - Fuses 4-to-1 binary tree reduction triples (`r_0_0 = op(a0, a1); r_0_1 = op(a2, a3); r_1_0 = op(r_0_0, r_0_1)`) for `op in ("add", "and", "or", "xor", "fadd")` into 128-bit SSE2 packed execution (`punpcklqdq` `66 0f 6c c1/ca` + `paddq`/`addpd`/`pand`/`por`/`pxor` + `pshufd xmm1, xmm0, 0x4E` `66 0f 70 c8 4e` + horizontal collapse).

---

## 2. Acceptance Criteria & Verification Matrix

| ID | Criterion | Component | Verification Method | Status |
| :--- | :--- | :--- | :--- | :--- |
| **AC-56.1** | Inclusive (`s += v; inc[i] = s`) and exclusive (`exc[i] = se; se += v`) prefix scans fused with `max` pass Z3 bi-abduction and match Native & LLVM O3 | `compiler/loop_vectorizer.py` | `test_01_inclusive_and_exclusive_prefix_scan_z3_and_parity` | **PROVADO** |
| **AC-56.2** | First-order linear recurrences (`h = h * 13 + v`, `h2 = (h2 << 2) - v`) via Estrin's 4-way parallel Horner tree across dynamic and constant bounds | `compiler/loop_vectorizer.py` | `test_02_first_order_linear_recurrence_estrin_horner_and_rolling_hash` | **PROVADO** |
| **AC-56.3** | Physical 128-bit SSE2 horizontal tree collapse opcodes (`pshufd 0x4E` `66 0f 70 c8 4e`, `punpcklqdq`, `paddq`, `addpd`) emitted and verified | `compiler/native_codegen.py` | `test_03_native_codegen_sse2_128bit_horizontal_tree_collapse_opcodes_and_execution` | **PROVADO** |
| **AC-56.4** | Live Wasmtime linear-memory roundtrip for vectorized prefix scan (`v128.store`) + linear recurrence | `compiler/wasm_backend.py`, `compiler/loop_vectorizer.py` | `test_04_live_wasmtime_prefix_scan_and_linear_recurrence_roundtrip` | **PROVADO** |
| **AC-56.5** | End-to-end `OmniRepoCompiler` executables across Native PE64, LLVM O3 PE64, and WSL2 Linux ELF64 | `compiler/repo_compiler.py` | `test_05_omnirepo_e2e_prefix_scan_and_horner_hash_executable` | **PROVADO** |
