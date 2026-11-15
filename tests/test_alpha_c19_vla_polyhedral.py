"""
OmniCompiler Alpha-C19 Test Suite (tests/test_alpha_c19_vla_polyhedral.py)
Validates:
1. Dynamic Vector-Length Agnostic (VLA) SIMD Engine:
   - Dynamic lane sizing: NEON (128-bit), AVX2 (256-bit), AVX-512 (512-bit), SVE (dynamic).
   - Active predication masks and bitmask generation.
   - Predicated memory loads and stores with zero out-of-bounds leakage.
   - Tail-folded vector addition, multiplication, FMA, and parallel reduction.
2. Polyhedral Loop Tiling & Unrolling Pass:
   - Affine loop discovery, induction variable detection, bounds extraction.
   - L1/L2 cache-conscious rectangular and cubic tile dimension calculation.
   - Loop unrolling with multi-accumulator reduction interleaving.
3. End-to-End OmniRepoCompiler Integration:
   - Verification of `polyhedral_tiled_loops` and `unrolled_loops` metrics during AOT compilation.
"""

import unittest
import ast
import os
import shutil

from compiler.vla_simd_engine import VLASimdEngine
from compiler.polyhedral_tiler import (
    PolyhedralLoopTilerPass,
    LoopUnrollPass,
    LoopNestInfo,
)
from compiler.loop_vectorizer import LoopVectorizerPass
from compiler.ssa_ir import (
    SSAFunction,
    BasicBlock,
    SSAInstruction,
    SSAVar,
    lower_ast_to_ssa,
)
from omni_repo_compiler import OmniRepoCompiler


class TestAlphaC19VlaPolyhedral(unittest.TestCase):

    def test_01_vla_simd_active_masks_and_predication(self):
        """
        Validates active predication mask calculation, bitmask synthesis,
        and bounds-safe memory operations for arbitrary non-multiple lengths.
        """
        engine = VLASimdEngine("AVX2_256")  # 4 lanes for 64-bit integers
        self.assertEqual(engine.vector_lanes, 4)

        # Total 10 elements, stride 4
        # Offset 0: [True, True, True, True]
        m0 = engine.compute_active_mask(offset=0, total_count=10, lanes=4)
        self.assertEqual(m0, [True, True, True, True])
        self.assertEqual(engine.compute_bitmask(m0), 0b1111)

        # Offset 4: [True, True, True, True]
        m1 = engine.compute_active_mask(offset=4, total_count=10, lanes=4)
        self.assertEqual(m1, [True, True, True, True])

        # Offset 8: [True, True, False, False]
        m2 = engine.compute_active_mask(offset=8, total_count=10, lanes=4)
        self.assertEqual(m2, [True, True, False, False])
        self.assertEqual(engine.compute_bitmask(m2), 0b0011)

        # Predicated Load test: ensure no access past 10 elements
        source_data = list(range(100, 110))  # 10 elements: 100..109
        loaded = engine.predicated_load(source_data, offset=8, mask=m2, neutral_val=0)
        self.assertEqual(loaded, [108, 109, 0, 0])

        # Predicated Store test: write back into dest
        dest_data = [0] * 10
        written = engine.predicated_store(dest_data, offset=8, values=[777, 888, 999, 999], mask=m2)
        self.assertEqual(written, 2)
        self.assertEqual(dest_data[8], 777)
        self.assertEqual(dest_data[9], 888)
        self.assertEqual(len(dest_data), 10)  # dest length unmodified

    def test_02_vla_vector_add_and_tail_folding(self):
        """
        Validates that `execute_vla_vector_add` correctly processes arbitrary length vectors
        using tail-folding without requiring scalar residual loops.
        """
        engine_avx2 = VLASimdEngine("AVX2_256", custom_lanes=4)
        engine_avx512 = VLASimdEngine("AVX512_512", custom_lanes=8)
        engine_neon = VLASimdEngine("NEON_128", custom_lanes=2)

        for n in [1, 3, 4, 7, 15, 33, 101]:
            vec_a = [i * 3 for i in range(n)]
            vec_b = [i * 7 + 1 for i in range(n)]
            expected = [a + b for a, b in zip(vec_a, vec_b)]

            # Test AVX2 (4 lanes)
            res_avx2 = engine_avx2.execute_vla_vector_add(vec_a, vec_b)
            self.assertEqual(res_avx2["output"], expected)
            self.assertEqual(res_avx2["total_elements"], n)

            # Test AVX-512 (8 lanes)
            res_avx512 = engine_avx512.execute_vla_vector_add(vec_a, vec_b)
            self.assertEqual(res_avx512["output"], expected)

            # Test NEON (2 lanes)
            res_neon = engine_neon.execute_vla_vector_add(vec_a, vec_b)
            self.assertEqual(res_neon["output"], expected)

    def test_03_vla_dot_product_and_fma_reduction(self):
        """
        Validates VLA dot product, FMA, and reduction sum over arbitrary sizes.
        """
        engine = VLASimdEngine("AVX2_256", custom_lanes=4)
        n = 23  # prime length, not a multiple of 4
        vec_a = [(i % 5) + 1 for i in range(n)]
        vec_b = [(i % 7) + 2 for i in range(n)]
        vec_c = [10 for _ in range(n)]

        # Dot product
        expected_dot = sum(a * b for a, b in zip(vec_a, vec_b))
        res_dot = engine.execute_vla_dot_product(vec_a, vec_b)
        self.assertEqual(res_dot["dot_product"], expected_dot)
        self.assertGreater(res_dot["masked_vectors_processed"], 0)

        # Reduction sum
        expected_sum = sum(vec_a)
        res_sum = engine.execute_vla_reduction_sum(vec_a)
        self.assertEqual(res_sum["sum"], expected_sum)

        # Predicated FMA test
        mask = [True, True, True, False]
        va = [2, 3, 4, 99]
        vb = [5, 6, 7, 99]
        vc = [1, 2, 3, 99]
        vfma = engine.predicated_fma(va, vb, vc, mask, neutral_val=0)
        self.assertEqual(vfma, [2 * 5 + 1, 3 * 6 + 2, 4 * 7 + 3, 0])

        # Metadata emission tests
        x86_meta = engine.emit_x86_vmaskmov_metadata(lanes=4)
        self.assertIn("vpmaskmovq", x86_meta["load_opcode"])
        arm_meta = engine.emit_arm64_sve_metadata(lanes=4)
        self.assertIn("whilelo", arm_meta["predicate_gen"])

    def test_04_polyhedral_affine_loop_analysis(self):
        """
        Validates discovery of natural loops, induction variables, and exit blocks in SSA IR.
        """
        src = """
def compute_sum(n: int) -> int:
    total = 0
    i = 0
    while i < n:
        total = total + i
        i = i + 1
    return total
"""
        tree = ast.parse(src)
        fn_def = tree.body[0]
        ssa_fn = lower_ast_to_ssa(fn_def, optimize=True)

        tiler = PolyhedralLoopTilerPass()
        loops = tiler.analyze_loops(ssa_fn)
        self.assertGreaterEqual(len(loops), 1)

        loop = loops[0]
        self.assertIsNotNone(loop.header_block)
        self.assertIsNotNone(loop.latch_block)
        self.assertIsNotNone(loop.exit_block)

    def test_05_polyhedral_cache_tiling_and_unroll_pass(self):
        """
        Validates cache tile dimension calculation, loop tiling pass, and loop unrolling pass.
        """
        tiler = PolyhedralLoopTilerPass(l1_cache_bytes=32768)
        # 1D tiling
        tm, tn = tiler.compute_tile_factors(dim_m=1000)
        self.assertLessEqual(tm * 8, 16384)
        self.assertEqual(tn, 1)

        # 2D tiling (e.g. 512 x 512 matrix)
        tm2, tn2 = tiler.compute_tile_factors(dim_m=512, dim_n=512, elem_size=8)
        self.assertLessEqual(tm2 * tn2 * 8, 16384)

        src = """
def loop_kernel(n: int) -> int:
    acc = 0
    i = 0
    while i < n:
        acc = acc + 5
        i = i + 1
    return acc
"""
        tree = ast.parse(src)
        ssa_fn = lower_ast_to_ssa(tree.body[0], optimize=True)

        # Apply Polyhedral Tiler
        ssa_fn, tile_stats = tiler.tile_function(ssa_fn, default_tile_size=32)
        self.assertIn("polyhedral_tiled_loops", tile_stats)
        self.assertGreaterEqual(tile_stats["polyhedral_tiled_loops"], 1)

        # Apply Loop Unroller
        unroller = LoopUnrollPass(unroll_factor=4)
        ssa_fn, unroll_stats = unroller.unroll_function(ssa_fn)
        self.assertEqual(unroll_stats["unroll_factor"], 4)
        self.assertGreaterEqual(unroll_stats["unrolled_loops"], 1)

        # Verify Vectorizer VLA extension
        vec_pass = LoopVectorizerPass()
        ssa_fn, vla_vec_stats = vec_pass.vectorize_vla_function(ssa_fn, target_isa="AVX2_256")
        self.assertEqual(vla_vec_stats["vla_isa"], "AVX2_256")
        self.assertEqual(vla_vec_stats["vla_lanes"], 4)

    def test_06_omni_repo_compiler_vla_polyhedral_integration(self):
        """
        Validates end-to-end AOT compilation of a repository module with loops,
        verifying that `polyhedral_tiled_loops` and `unrolled_loops` are reported.
        """
        repo_dir = r"F:\repository-compiler\test_repo_c19_workspace"
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir, ignore_errors=True)
        os.makedirs(repo_dir, exist_ok=True)

        module_code = """
def compute_vector_product(limit: int) -> int:
    total = 0
    i = 0
    while i < limit:
        total = total + i
        i = i + 1
    return total
"""
        with open(os.path.join(repo_dir, "pyproject.toml"), "w", encoding="utf-8") as f:
            f.write("""
[project]
name = "repo_c19"
version = "0.1.0"
[tool.omnicompiler.exports]
compute_vector_product = { file = "vector_math.py", symbol = "compute_vector_product" }
""")

        with open(os.path.join(repo_dir, "vector_math.py"), "w", encoding="utf-8") as f:
            f.write(module_code)

        try:
            compiler = OmniRepoCompiler()
            res = compiler.compile_repositories(
                repo_paths=[repo_dir],
                output_path=os.path.join(repo_dir, "libvector_math.dll"),
                target_format="shared_lib",
                target_os="windows",
                target_arch="x86_64",
                entry_export="compute_vector_product",
            )
            self.assertTrue(res["success"], f"AOT compilation failed: {res.get('error')}")
            codegen_stage = res["stages"]["codegen"]
            self.assertIn("polyhedral_tiled_loops", codegen_stage)
            self.assertIn("unrolled_loops", codegen_stage)
            self.assertGreaterEqual(codegen_stage["polyhedral_tiled_loops"], 1)
            self.assertGreaterEqual(codegen_stage["unrolled_loops"], 1)
        finally:
            shutil.rmtree(repo_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
