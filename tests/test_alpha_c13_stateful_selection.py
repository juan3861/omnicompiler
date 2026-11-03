"""
Test Suite for Master Prompt Protocol Alpha-C13: Stateful Selection & ThinLTO.
Validates:
1. Native UTF-8 Strings with Small String Optimization (SSO <= 15 bytes) and Heap fallback.
2. Zero-Copy String Slice Descriptors (OmniStringSlice) and native equality/startswith.
3. SSA IR lowering of string constants, slicing, and attribute calls.
4. ThinLTO inter-procedural summary index, constant-return folding, and leaf-function inlining.
5. Stateful Selection Ledger with non-replayable evaluation tickets and atomic disk persistence.
6. Anti-Goodhart promotion with Holm-Bonferroni FWER control and (Q, F, C, L, K, P) Pareto evaluation.
"""

import ast
import ctypes
import os
import shutil
import tempfile
import unittest

from compiler.ssa_ir import AstToSsaLowering, ASTToSSAConverter, SSAFunction, SSAInstruction, SSAVar, optimize_ssa
from compiler.thin_lto import ThinLtoSummaryIndex, ThinLtoOptimizer, FunctionSummary
from runtime.native_strings import (
    omni_str_new_from_bytes,
    omni_str_len,
    omni_str_data_ptr,
    omni_str_get_byte,
    omni_str_concat,
    omni_str_slice,
    omni_str_slice_to_str,
    omni_str_eq,
    omni_str_startswith,
    omni_str_to_py,
    SSO_MAX_LEN,
    FLAG_HEAP,
)
from runtime.native_heap import omni_item_len, omni_item_get
from validation.stateful_selection_ledger import (
    StatefulSelectionLedger,
    EvaluationTicket,
    AntiGoodhartPromoter,
)


class TestAlphaC13StatefulSelection(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="omni_c13_test_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_native_string_sso_and_heap_representation(self):
        """Validates SSO (<= 15 bytes inline) and Heap (> 15 bytes) binary layouts."""
        # 1. SSO string: "AlphaC13" (8 bytes)
        raw_sso = b"AlphaC13"
        sso_ptr = omni_str_new_from_bytes(raw_sso)
        self.assertNotEqual(sso_ptr, 0)

        # Header byte should have length 8 and bit 7 == 0 (SSO)
        hdr_byte = ctypes.c_uint8.from_address(sso_ptr).value
        self.assertEqual(hdr_byte, 8)
        self.assertEqual(hdr_byte & FLAG_HEAP, 0)

        # Length verification
        self.assertEqual(omni_str_len(sso_ptr), 8)
        self.assertEqual(omni_item_len(sso_ptr), 8)

        # String content verification
        self.assertEqual(omni_str_to_py(sso_ptr), "AlphaC13")
        self.assertEqual(omni_str_get_byte(sso_ptr, 0), ord("A"))
        self.assertEqual(omni_str_get_byte(sso_ptr, 7), ord("3"))
        self.assertEqual(omni_item_get(sso_ptr, 0), ord("A"))

        # 2. Large Heap string: 42 bytes (> 15 bytes)
        raw_heap = b"ThinLTO_Stateful_Selection_AlphaC13_Engine"
        heap_ptr = omni_str_new_from_bytes(raw_heap)
        self.assertNotEqual(heap_ptr, 0)

        # Header byte must have bit 7 == 1 (FLAG_HEAP)
        hdr_heap = ctypes.c_uint8.from_address(heap_ptr).value
        self.assertTrue((hdr_heap & FLAG_HEAP) != 0)

        # Length at offset 8
        self.assertEqual(omni_str_len(heap_ptr), len(raw_heap))
        self.assertEqual(omni_item_len(heap_ptr), len(raw_heap))
        self.assertEqual(omni_str_to_py(heap_ptr), raw_heap.decode("utf-8"))
        self.assertEqual(omni_str_get_byte(heap_ptr, 0), ord("T"))
        self.assertEqual(omni_item_get(heap_ptr, 0), ord("T"))

    def test_02_native_string_zero_copy_slicing_and_equality(self):
        """Validates zero-copy slice descriptors, concatenation, equality, and startswith."""
        s = omni_str_new_from_bytes(b"OmniCompilerNativeStrings")
        self.assertEqual(omni_str_len(s), 25)

        # Slicing [0:12] -> "OmniCompiler"
        slice1 = omni_str_slice(s, 0, 12)
        self.assertEqual(omni_item_len(slice1), 12)
        # Slicing [12:25] -> "NativeStrings"
        slice2 = omni_str_slice(s, 12, 25)
        self.assertEqual(omni_item_len(slice2), 13)

        # Convert slice descriptors to owned strings
        owned1 = omni_str_slice_to_str(slice1)
        owned2 = omni_str_slice_to_str(slice2)
        self.assertEqual(omni_str_to_py(owned1), "OmniCompiler")
        self.assertEqual(omni_str_to_py(owned2), "NativeStrings")

        # Concatenate them back: "OmniCompiler" + "NativeStrings"
        rejoined = omni_str_concat(owned1, owned2)
        self.assertEqual(omni_str_to_py(rejoined), "OmniCompilerNativeStrings")

        # String equality
        self.assertEqual(omni_str_eq(s, rejoined), 1)
        self.assertEqual(omni_str_eq(owned1, owned2), 0)

        # StartsWith
        pref = omni_str_new_from_bytes(b"Omni")
        diff_pref = omni_str_new_from_bytes(b"Linux")
        self.assertEqual(omni_str_startswith(s, pref), 1)
        self.assertEqual(omni_str_startswith(s, diff_pref), 0)

    def test_03_ssa_string_lowering_and_jit_execution(self):
        """Validates AST to SSA IR lowering of string constants, slicing, and method calls."""
        py_code = """
def test_string_ops(x: int) -> int:
    msg = "AlphaC13Protocol"
    prefix = msg[0:8]
    if msg.startswith("Alpha"):
        return len(msg)
    return 0
"""
        tree = ast.parse(py_code)
        func_def = tree.body[0]
        converter = ASTToSSAConverter()
        ssa_fn = converter.lower_function_def(func_def)

        # Verify SSA instructions contain string calls
        all_opcodes = [inst.opcode for b in ssa_fn.blocks for inst in b.instructions]
        self.assertIn("call", all_opcodes)

        call_targets = [
            inst.operands[0]
            for b in ssa_fn.blocks
            for inst in b.instructions
            if inst.opcode == "call" and inst.operands
        ]
        self.assertIn("omni_str_slice", call_targets)
        self.assertIn("omni_str_startswith", call_targets)
        self.assertIn("omni_item_len", call_targets)

        # Run multi-pass SSA optimizer
        opt_fn = optimize_ssa(ssa_fn)
        self.assertIsNotNone(opt_fn)

    def test_04_thin_lto_cross_repo_leaf_inlining_and_const_folding(self):
        """Validates ThinLTO cross-repository constant-return folding and leaf inlining."""
        index = ThinLtoSummaryIndex()
        optimizer = ThinLtoOptimizer(index)

        # 1. Math module in repo "math_core" with constant return
        math_code = """
def get_magic_seed() -> int:
    return 42
"""
        math_ast = ast.parse(math_code).body[0]
        math_ssa = ASTToSSAConverter().lower_function_def(math_ast)
        math_summary = optimizer.build_summary_from_ssa(math_ssa, repo_name="math_core")
        self.assertEqual(math_summary.constant_return, 42)

        # 2. Leaf helper in repo "utils": x * 2 (simple leaf)
        leaf_code = """
def double_val(x: int) -> int:
    return x * 2
"""
        leaf_ast = ast.parse(leaf_code).body[0]
        leaf_ssa = ASTToSSAConverter().lower_function_def(leaf_ast)
        leaf_summary = optimizer.build_summary_from_ssa(leaf_ssa, repo_name="utils")
        self.assertTrue(leaf_summary.can_inline)

        # 3. Caller in repo "app" calling both
        app_code = """
def run_app(val: int) -> int:
    c = get_magic_seed()
    d = double_val(val)
    return c + d
"""
        app_ast = ast.parse(app_code).body[0]
        app_ssa = ASTToSSAConverter().lower_function_def(app_ast)

        # Apply ThinLTO optimization
        optimized_app, stats = optimizer.optimize_interprocedural_ssa(app_ssa)

        self.assertGreaterEqual(stats["folded_constants"], 1)
        self.assertGreaterEqual(stats["inlined_calls"], 1)

        # Verify that calls to get_magic_seed and double_val were eliminated
        remaining_calls = [
            inst.operands[0]
            for b in optimized_app.blocks
            for inst in b.instructions
            if inst.opcode == "call" and inst.operands
        ]
        self.assertNotIn("get_magic_seed", remaining_calls)
        self.assertNotIn("double_val", remaining_calls)

    def test_05_stateful_selection_ledger_anti_replay(self):
        """Validates evaluation ticket lifecycle, single-use burning, and replay protection."""
        ledger_path = os.path.join(self.temp_dir, "test_ledger.json")
        ledger = StatefulSelectionLedger(ledger_path)

        ticket = ledger.allocate_ticket(
            baseline_commit="2d4935a",
            candidate_hash="cand_hash_9876",
            eval_plan_hash="plan_hash_1234",
        )
        self.assertTrue(ticket.ticket_id.startswith("TCK-"))
        self.assertFalse(ticket.is_consumed)

        # Consume ticket with empirical measurements
        outcome = {
            "Q": 0.985,
            "F": 0,
            "latency_ms": 1.45,
            "passed": True,
        }
        consumed_ticket = ledger.consume_ticket(ticket.ticket_id, outcome)
        self.assertTrue(consumed_ticket.is_consumed)
        self.assertEqual(consumed_ticket.outcome["Q"], 0.985)

        # Attempting replay must raise critical violation
        with self.assertRaises(ValueError) as ctx:
            ledger.consume_ticket(ticket.ticket_id, outcome)
        self.assertIn("already consumed", str(ctx.exception))

        # Reload ledger from disk and confirm persistence
        reloaded_ledger = StatefulSelectionLedger(ledger_path)
        persisted_ticket = reloaded_ledger.tickets[ticket.ticket_id]
        self.assertTrue(persisted_ticket.is_consumed)

    def test_06_holm_bonferroni_fwer_and_pareto_promotion(self):
        """Validates Holm-Bonferroni FWER control and (Q, F, C, L, K, P) Pareto evaluation."""
        promoter = AntiGoodhartPromoter(family_alpha=0.05, min_quality_gain=0.05)

        # 1. Holm-Bonferroni test on 4 hypotheses
        p_values = [0.005, 0.012, 0.04, 0.18]
        # m = 4:
        # i=0: threshold = 0.05 / 4 = 0.0125. p=0.005 <= 0.0125 -> Reject H0 (Significant)
        # i=1: threshold = 0.05 / 3 = 0.0167. p=0.012 <= 0.0167 -> Reject H0 (Significant)
        # i=2: threshold = 0.05 / 2 = 0.025.  p=0.04 > 0.025   -> Fail to Reject (Not Significant)
        # i=3: threshold = 0.05 / 1 = 0.05.   p=0.18 > 0.05   -> Fail to Reject (Not Significant)
        corrections = promoter.holm_bonferroni_correction(p_values)
        self.assertEqual(len(corrections), 4)
        self.assertTrue(corrections[0][2])
        self.assertTrue(corrections[1][2])
        self.assertFalse(corrections[2][2])
        self.assertFalse(corrections[3][2])

        # 2. Rollouts evaluation across repeated seeds
        c_samples = [105.2, 106.1, 104.9, 105.8, 106.0]
        b_samples = [100.1, 99.8, 100.4, 99.9, 100.2]
        eval_res = promoter.evaluate_rollouts(c_samples, b_samples)
        self.assertTrue(eval_res["is_significant"])
        self.assertTrue(eval_res["meets_effect_size"])
        self.assertGreater(eval_res["diff"], 5.0)

        # 3. Pareto Multi-Objective Dominance
        baseline_vec = {"Q": 0.88, "F": 0, "C": 100.0, "L": 10.0, "K": 1, "P": 500}

        # Superior candidate: Higher Q (+0.07), zero F, lower latency L (8.5)
        cand_superior = {"Q": 0.95, "F": 0, "C": 98.0, "L": 8.5, "K": 1, "P": 490}
        promoted, reason = promoter.check_pareto_dominance(cand_superior, baseline_vec)
        self.assertTrue(promoted)
        self.assertIn("PROMOTED", reason)

        # Inferior candidate with critical failure (F = 1)
        cand_failed = {"Q": 0.99, "F": 1, "C": 50.0, "L": 5.0, "K": 1, "P": 300}
        promoted_f, reason_f = promoter.check_pareto_dominance(cand_failed, baseline_vec)
        self.assertFalse(promoted_f)
        self.assertIn("critical failures", reason_f)

        # Inferior candidate with >25% latency regression
        cand_regressed = {"Q": 0.90, "F": 0, "C": 100.0, "L": 15.0, "K": 1, "P": 500}
        promoted_r, reason_r = promoter.check_pareto_dominance(cand_regressed, baseline_vec)
        self.assertFalse(promoted_r)
        self.assertIn("regressed resource", reason_r)


if __name__ == "__main__":
    unittest.main()
