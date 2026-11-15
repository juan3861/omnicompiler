# ACCEPTANCE CONTRACT ALPHA-C19
## Dynamic Vector-Length Agnostic (VLA) SIMD Engine & Polyhedral Loop Tiling Pipeline

- **Contract ID:** CONTRACT-ALPHA-C19-VLA-POLYHEDRAL
- **Revision:** 1.0.0
- **Status:** FROZEN
- **Author:** AetherMind Apotheosis (Builder / Formal Verifier)
- **Target Repository:** `F:\repository-compiler` (remote `https://github.com/juan3861/omnicompiler.git`, branch `main`)

---

### 1. Requirements & Invariants

| ID | Category | Requirement Description | Gate Status |
|---|---|---|---|
| REQ-C19-01 | Polyhedral Tiling | Provide `PolyhedralLoopTilerPass` capable of detecting 1D/2D nested affine loops in SSA IR / AST and partitioning them into L1/L2 cache-conscious rectangular or cubic tiles ($T_M \times T_N$) with correct boundary handling. | REQUIRED |
| REQ-C19-02 | Loop Unrolling | Provide `LoopUnrollPass` with configurable unroll factors $U \in \{2, 4, 8\}$ that interleaves accumulator registers to maximize superscalar CPU pipeline throughput and emit clean remainder loops. | REQUIRED |
| REQ-C19-03 | VLA SIMD Abstraction | Provide `VLASimdEngine` abstracting vector widths dynamically across ARM NEON (128-bit), x86 AVX2 (256-bit), AVX-512 (512-bit), and Scalable Vector Extension (SVE). | REQUIRED |
| REQ-C19-04 | Predicated Operations | Implement vector predication / masking (`predicated_load`, `predicated_store`, `predicated_add`, `predicated_mul`, `predicated_reduce_sum`) to execute arbitrary-length vector operations without scalar tail loop overhead. | REQUIRED |
| REQ-C19-05 | Compiler Integration | Integrate polyhedral tiling and VLA SIMD into `omni_repo_compiler.py` and `loop_vectorizer.py`, recording metrics `polyhedral_tiled_loops`, `unrolled_loops`, and `vla_vectorized_ops`. | REQUIRED |
| REQ-C19-06 | Regression & CI | Ensure 100% test pass rate across the full compiler regression suite (`run_full_regression.py`), pass `AetherMind_Strict_Auditor.py`, and pass all GitHub Actions CI checks on both Ubuntu and Windows. | REQUIRED |

---

### 2. Invariants & Guardrails
- **INV-01 (Semantics Preservation):** Loop tiling and unrolling must strictly preserve loop iteration semantics, index boundaries, and data dependencies for non-multiple trip counts.
- **INV-02 (Masked Soundness):** Predicated vector operations must never load from or store to out-of-bounds memory beyond the requested length $N$, preventing segmentation faults.
- **INV-03 (Zero Regression):** Existing SSA passes (ThinLTO, AVX2 SIMD collections, StackPromotion, IRC regalloc) must continue to function with 100% backward compatibility.
- **INV-04 (Fail-Closed):** If a loop contains loop-carried memory dependencies or non-affine indices, polyhedral tiling must safely reject transformation without mutating the original CFG.

---

### 3. Verification Protocol
1. Unit tests in `tests/test_alpha_c19_vla_polyhedral.py` exercising 1D/2D loop tiling, unroll-and-jam, VLA predication masks, and end-to-end compilation.
2. `AetherMind_Strict_Auditor.py` logical proof of execution.
3. Global regression suite `run_full_regression.py` pass.
4. Remote GitHub Actions CI dual-runner validation.
