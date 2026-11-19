# ACCEPTANCE CONTRACT — Alpha-C51: Branchless If-Conversion (`select` Predication), Multi-Store AoS Interleaved Vectorization & Multi-Load Struct Dot Products

**Cycle:** Alpha-C51  
**Repository:** `F:\repository-compiler` (`OmniCompiler`)  
**Verdict:** **APPROVED & EMPIRICALLY VERIFIED**

---

## 1. Delivered Invariants
1. **Non-Speculative Branchless Loop If-Conversion (`compiler/loop_vectorizer.py`):**
   - Implemented `_try_plan_if_conversion` and `_commit_if_conversion` inside `LoopVectorizerPass`:
     - Flattens pure single-block `if-then` triangles and `if-else` diamonds inside loops (`M.phi_nodes` lowered to `select(cond, t_val, f_val)`) ONLY when the resulting single-block body matches vectorization (`superseded_blks=reachable_from_body` preventing false escape detection on the original arm blocks).
     - Coalesces matching `if-else` `store_off` assignments targeting identical `(base, linear_offset, width)` into a single `select`-predicated `store_off`.
     - Explicitly blocks speculative `load_off` hoisting from conditional arms (e.g. `if i > 0: load_i64(a, (i - 1) * 8)`).
2. **Conditional & Transformed Reductions + Multi-Load Struct Dot Products (`_match_struct_array_sum`, `_build_unrolled_tree_reduction`, `_emit_strip_mined_4x_core`, `_rewrite_struct_array_*`):**
   - Generalized reductions via `_extract_pure_dag_slice` + `_clone_dag_insts` to support arbitrary pure per-element expressions (`a[i] * b[i]`, index arithmetic) across `1..8` `load_off` slots and `select`-masked conditional accumulations (`if v > thresh: s += v`) across constant tree reductions (`N <= 64`), static strip-mining, dynamic strip-mining (`while i < n`), and scalar tails.
3. **Multi-Store Contiguous & AoS Interleaved Vectorization (`_match_struct_array_store`, `_rewrite_struct_array_store_4x`, `_is_statically_disjoint_same_base`):**
   - Generalized `store_off` vectorization to `1..8` stores per loop iteration, adding modular stride disjointness verification for interleaved AoS fields (`pts[i].x` vs `pts[i].y` at stride 16) and pairwise runtime alias guards across both store-load and store-store hazards (`sum_arr == diff_arr`).
   - Added `vec_ci_` / `vec_st_ci_` guard in `_match_zero_based_unit_loop` to prevent re-vectorizing already strip-mined 4-lane chunk loops.
