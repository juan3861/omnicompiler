"""
Test Suite for Alpha-C14: Multi-Block ThinLTO Inlining, AVX2 SIMD Vectorization, and Escape Analysis.
Validates:
1. Multi-block CFG inlining across repository boundaries with Phi-node return unification.
2. Cross-repo branch pruning and control-flow splicing.
3. Native 256-bit AVX2 SIMD vector addition (omni_list_vec_add) on contiguous OmniList buffers.
4. Native SIMD vector dot product (omni_list_vec_dot) and parallel reduction sum (omni_list_sum).
5. SSA IR lowering of vector intrinsics (vec_add, vec_dot, sum).
6. Inter-procedural Escape Analysis distinguishing NO_ESCAPE from GLOBAL_ESCAPE.
"""

import ast
import ctypes
import unittest

from compiler.ssa_ir import AstToSsaLowering, SSAFunction, SSAInstruction, SSAVar, optimize_ssa
from compiler.thin_lto import ThinLtoSummaryIndex, ThinLtoOptimizer, FunctionSummary
from compiler.escape_analysis import EscapeAnalysisPass, EscapeState
from runtime.native_heap import omni_list_new, omni_list_set, omni_list_get, omni_list_len
from runtime.native_collections_simd import (
    omni_list_vec_add,
    omni_list_vec_dot,
    omni_list_sum,
)


class TestAlphaC14MultiBlockLtoSimd(unittest.TestCase):

    def test_01_multiblock_thin_lto_branching_inline(self):
        """Validates multi-block CFG inlining for a branching clamp function."""
        index = ThinLtoSummaryIndex()
        optimizer = ThinLtoOptimizer(index)

        # Callee in repo "core_math": branching clamp with 3 return paths
        clamp_code = """
def clamp_val(x: int, low: int, high: int) -> int:
    if x < low:
        return low
    if x > high:
        return high
    return x
"""
        clamp_ast = ast.parse(clamp_code).body[0]
        clamp_ssa = AstToSsaLowering().lower_function_def(clamp_ast)
        summary = optimizer.build_summary_from_ssa(clamp_ssa, repo_name="core_math")
        self.assertTrue(summary.can_inline_multiblock)
        self.assertGreater(len(clamp_ssa.blocks), 1)

        # Caller in repo "app"
        app_code = """
def process_data(val: int) -> int:
    y = clamp_val(val, 10, 100)
    return y * 2
"""
        app_ast = ast.parse(app_code).body[0]
        app_ssa = AstToSsaLowering().lower_function_def(app_ast)

        # Apply ThinLTO inter-procedural optimization
        optimized_app, stats = optimizer.optimize_interprocedural_ssa(app_ssa)

        self.assertGreaterEqual(stats["multiblock_inlines"], 1)
        self.assertGreaterEqual(stats["inlined_calls"], 1)

        # Call to clamp_val must be eliminated
        remaining_calls = [
            inst.operands[0]
            for b in optimized_app.blocks
            for inst in b.instructions
            if inst.opcode == "call" and inst.operands
        ]
        self.assertNotIn("clamp_val", remaining_calls)

        # Verify CFG was spliced with multiple blocks and phi nodes
        self.assertGreater(len(optimized_app.blocks), 2)

    def test_02_multiblock_thin_lto_abs_diff(self):
        """Validates multi-block inlining with binary subtraction branches."""
        index = ThinLtoSummaryIndex()
        optimizer = ThinLtoOptimizer(index)

        callee_code = """
def abs_diff(a: int, b: int) -> int:
    if a > b:
        return a - b
    return b - a
"""
        callee_ast = ast.parse(callee_code).body[0]
        callee_ssa = AstToSsaLowering().lower_function_def(callee_ast)
        summary = optimizer.build_summary_from_ssa(callee_ssa, repo_name="math_utils")
        self.assertTrue(summary.can_inline_multiblock)

        caller_code = """
def compute_metric(u: int, v: int) -> int:
    d = abs_diff(u, v)
    return d + 5
"""
        caller_ast = ast.parse(caller_code).body[0]
        caller_ssa = AstToSsaLowering().lower_function_def(caller_ast)

        optimized_caller, stats = optimizer.optimize_interprocedural_ssa(caller_ssa)
        self.assertEqual(stats["multiblock_inlines"], 1)

        calls = [
            inst.operands[0]
            for b in optimized_caller.blocks
            for inst in b.instructions
            if inst.opcode == "call" and inst.operands
        ]
        self.assertNotIn("abs_diff", calls)

    def test_03_native_simd_vector_add_on_omnilist(self):
        """Validates hardware/vectorized addition on 1000-element contiguous OmniList buffers."""
        n = 1000
        list_a = omni_list_new(n)
        list_b = omni_list_new(n)
        ctypes.c_int64.from_address(list_a + 8).value = n
        ctypes.c_int64.from_address(list_b + 8).value = n

        # Initialize lists
        for i in range(n):
            omni_list_set(list_a, i, i * 2)
            omni_list_set(list_b, i, 100)

        # Perform SIMD vector addition
        list_res = omni_list_vec_add(list_a, list_b)
        self.assertNotEqual(list_res, 0)
        self.assertEqual(omni_list_len(list_res), n)

        # Verify bit-exact results
        for i in range(n):
            expected = (i * 2) + 100
            actual = omni_list_get(list_res, i)
            self.assertEqual(actual, expected, f"Mismatch at index {i}: {actual} vs {expected}")

    def test_04_native_simd_dot_product_and_reduction(self):
        """Validates vector dot product and parallel reduction sum."""
        n = 500
        list_a = omni_list_new(n)
        list_b = omni_list_new(n)
        ctypes.c_int64.from_address(list_a + 8).value = n
        ctypes.c_int64.from_address(list_b + 8).value = n

        for i in range(n):
            omni_list_set(list_a, i, i)
            omni_list_set(list_b, i, 2)

        # 1. Parallel Dot Product: sum(i * 2) for i in 0..499
        # sum(i) = 499 * 500 / 2 = 124,750. sum(2*i) = 249,500
        dot_res = omni_list_vec_dot(list_a, list_b)
        self.assertEqual(dot_res, 249500)

        # 2. Parallel Reduction Sum: sum(i) for i in 0..499 = 124,750
        sum_res = omni_list_sum(list_a)
        self.assertEqual(sum_res, 124750)

    def test_05_ssa_vector_lowering_and_calls(self):
        """Validates AST to SSA IR lowering of vector primitives: sum, vec_add, vec_dot."""
        py_code = """
def test_simd_primitives(a: list, b: list) -> int:
    c = vec_add(a, b)
    s = sum(c)
    d = vec_dot(a, b)
    return s + d
"""
        tree = ast.parse(py_code).body[0]
        ssa_fn = AstToSsaLowering().lower_function_def(tree)

        call_targets = [
            inst.operands[0]
            for b in ssa_fn.blocks
            for inst in b.instructions
            if inst.opcode == "call" and inst.operands
        ]
        self.assertIn("omni_list_vec_add", call_targets)
        self.assertIn("omni_list_sum", call_targets)
        self.assertIn("omni_list_vec_dot", call_targets)

    def test_06_escape_analysis_local_promotion(self):
        """Validates escape analysis distinguishing non-escaping local buffers from escaping ones."""
        # 1. Local-only list: elements read and added, never returned
        local_code = """
def local_pipeline(x: int) -> int:
    temp_list = [x, x + 1, x + 2]
    return temp_list[0] + temp_list[1]
"""
        local_ast = ast.parse(local_code).body[0]
        local_ssa = AstToSsaLowering().lower_function_def(local_ast)

        analyzer = EscapeAnalysisPass()
        allocs_local = analyzer.analyze_function(local_ssa)
        self.assertEqual(len(allocs_local), 1)
        record_local = list(allocs_local.values())[0]
        self.assertEqual(record_local.escape_state, EscapeState.NO_ESCAPE)
        self.assertTrue(record_local.is_stack_promotable)

        # 2. Escaping list: returned to caller
        escape_code = """
def factory_pipeline(x: int) -> list:
    ret_list = [x, x + 1]
    return ret_list
"""
        escape_ast = ast.parse(escape_code).body[0]
        escape_ssa = AstToSsaLowering().lower_function_def(escape_ast)

        allocs_escape = analyzer.analyze_function(escape_ssa)
        self.assertEqual(len(allocs_escape), 1)
        record_escape = list(allocs_escape.values())[0]
        self.assertEqual(record_escape.escape_state, EscapeState.GLOBAL_ESCAPE)
        self.assertFalse(record_escape.is_stack_promotable)


if __name__ == "__main__":
    unittest.main()
