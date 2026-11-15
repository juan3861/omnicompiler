"""
OmniCompiler Alpha-C24 Test Suite (tests/test_alpha_c24_smt_translation_validation.py)
Validates:
1. SSATranslationValidator (Alive2-style 64-bit QF_BV Z3 equivalence verifier):
   - Proves SCCPPass and GlobalValueNumberingPass preserve bit-exact 64-bit semantics on multi-block acyclic SSA functions.
   - Refutes buggy mutant passes and extracts concrete counterexamples.
   - Fails closed on cyclic CFGs (loops) and unsupported opcodes (call, alloca).
2. VerifiedPassRunner:
   - Automatically rolls back any pass that fails equivalence verification and preserves W^X JIT execution semantics.
3. End-to-End OmniRepoCompiler AOT Integration:
   - Reports `smt_pass_proofs >= 1` and `smt_pass_rollbacks == 0` in `stages["codegen"]`.
"""

import copy
import os
import sys
import tempfile
import unittest

from compiler.ssa_ir import (
    SSAFunction,
    BasicBlock,
    SSAInstruction,
    SSAVar,
)
from compiler.ip_sccp_gvn import SCCPPass, GlobalValueNumberingPass
from compiler.native_jit import NativeJitCompiler
from validation.ssa_translation_validator import (
    SSATranslationValidator,
    VerifiedPassRunner,
)
from omni_repo_compiler import OmniRepoCompiler


def _build_acyclic_diamond_ssa() -> SSAFunction:
    """Builds a multi-block acyclic SSA function with redundant expressions and a phi merge."""
    fn = SSAFunction("diamond_fn", ["x", "y"])
    entry = BasicBlock("entry")
    then_bb = BasicBlock("then_bb")
    else_bb = BasicBlock("else_bb")
    merge_bb = BasicBlock("merge_bb")

    entry.connect_to(then_bb)
    entry.connect_to(else_bb)
    then_bb.connect_to(merge_bb)
    else_bb.connect_to(merge_bb)

    x = SSAVar("x", 0)
    y = SSAVar("y", 0)
    c_zero = SSAVar("c_zero", 0)
    c_ten = SSAVar("c_ten", 0)
    sum1 = SSAVar("sum1", 0)
    sum2 = SSAVar("sum2", 0)
    cond = SSAVar("cond", 0)

    t_then = SSAVar("t_then", 0)
    t_else = SSAVar("t_else", 0)
    merged = SSAVar("merged", 0)
    res = SSAVar("res", 0)

    entry.add_instruction(SSAInstruction(x, "param", ["x"]))
    entry.add_instruction(SSAInstruction(y, "param", ["y"]))
    entry.add_instruction(SSAInstruction(c_zero, "const", [0]))
    entry.add_instruction(SSAInstruction(c_ten, "const", [10]))
    entry.add_instruction(SSAInstruction(sum1, "add", [x, y]))
    entry.add_instruction(SSAInstruction(sum2, "add", [x, y]))  # GVN redundant
    entry.add_instruction(SSAInstruction(cond, "cmp_gt", [sum1, c_zero]))
    entry.add_instruction(SSAInstruction(None, "br_cond", [cond, "then_bb", "else_bb"]))

    then_bb.add_instruction(SSAInstruction(t_then, "add", [sum1, c_ten]))
    then_bb.add_instruction(SSAInstruction(None, "br", ["merge_bb"]))

    else_bb.add_instruction(SSAInstruction(t_else, "sub", [sum2, c_ten]))
    else_bb.add_instruction(SSAInstruction(None, "br", ["merge_bb"]))

    merge_bb.phi_nodes.append(
        SSAInstruction(merged, "phi", [], phi_incoming=[("then_bb", t_then), ("else_bb", t_else)])
    )
    merge_bb.add_instruction(SSAInstruction(res, "mul", [merged, 2]))
    merge_bb.add_instruction(SSAInstruction(None, "ret", [res]))

    fn.add_block(entry)
    fn.add_block(then_bb)
    fn.add_block(else_bb)
    fn.add_block(merge_bb)
    return fn


class TestAlphaC24SmtTranslationValidation(unittest.TestCase):

    def test_01_prove_gvn_and_sccp_equivalence_via_z3(self):
        """Proves SCCPPass and GlobalValueNumberingPass preserve bit-exact 64-bit semantics."""
        validator = SSATranslationValidator()
        fn_orig = _build_acyclic_diamond_ssa()

        fn_sccp, _ = SCCPPass().run_on_function(copy.deepcopy(fn_orig))
        verdict_sccp = validator.verify_equivalence(fn_orig, fn_sccp)
        self.assertTrue(verdict_sccp["proven"], f"SCCP proof failed: {verdict_sccp}")
        self.assertEqual(verdict_sccp["status"], "PROVEN_EQUIVALENT")
        self.assertIsNone(verdict_sccp["counterexample"])

        fn_gvn, _ = GlobalValueNumberingPass().run_on_function(copy.deepcopy(fn_sccp))
        verdict_gvn = validator.verify_equivalence(fn_sccp, fn_gvn)
        self.assertTrue(verdict_gvn["proven"], f"GVN proof failed: {verdict_gvn}")
        self.assertEqual(verdict_gvn["status"], "PROVEN_EQUIVALENT")
        self.assertIsNone(verdict_gvn["counterexample"])

    def test_02_refute_buggy_mutant_pass_and_extract_counterexample(self):
        """Injects a buggy optimization pass and verifies Z3 refutes it with a counterexample."""
        validator = SSATranslationValidator()
        fn_orig = _build_acyclic_diamond_ssa()
        fn_mutant = copy.deepcopy(fn_orig)

        # Mutate `res = merged * 2` into `res = merged + 2`
        for inst in fn_mutant.blocks[-1].instructions:
            if inst.opcode == "mul":
                inst.opcode = "add"
                break

        verdict = validator.verify_equivalence(fn_orig, fn_mutant)
        self.assertFalse(verdict["proven"])
        self.assertEqual(verdict["status"], "REFUTED_COUNTEREXAMPLE")
        self.assertIsInstance(verdict["counterexample"], dict)
        self.assertIn("x", verdict["counterexample"])
        self.assertIn("y", verdict["counterexample"])

    def test_03_verified_pass_runner_auto_rollback(self):
        """Verifies VerifiedPassRunner rolls back a buggy pass and preserves W^X JIT semantics."""
        fn_orig = _build_acyclic_diamond_ssa()

        def buggy_mutant_pass(fn: SSAFunction):
            mutated = copy.deepcopy(fn)
            for blk in mutated.blocks:
                for inst in blk.instructions:
                    if inst.opcode == "mul":
                        inst.opcode = "sub"
            return mutated, {"mutated": 1}

        runner = VerifiedPassRunner()
        final_fn, _stats, report = runner.run_verified_pass(fn_orig, buggy_mutant_pass)

        self.assertFalse(report["verified"])
        self.assertTrue(report["rolled_back"])
        self.assertEqual(report["verdict"]["status"], "REFUTED_COUNTEREXAMPLE")

        # Verify the rolled-back SSAFunction still executes identically in W^X silicon
        jit = NativeJitCompiler()
        fn_ptr_orig, _m1, _ = jit.compile_ssa(fn_orig)
        fn_ptr_final, _m2, _ = jit.compile_ssa(final_fn)

        for x_val, y_val in [(5, 3), (-10, 2), (0, 0), (100, -50)]:
            self.assertEqual(fn_ptr_final(x_val, y_val), fn_ptr_orig(x_val, y_val))

    def test_04_fail_closed_on_loops_and_unsupported_opcodes(self):
        """Verifies cyclic CFGs (loops) and unsupported opcodes (call, alloca) fail closed."""
        validator = SSATranslationValidator()

        # Case A: Cyclic CFG (loop back-edge)
        fn_loop = SSAFunction("loop_fn", ["n"])
        entry = BasicBlock("entry")
        header = BasicBlock("header")
        exit_bb = BasicBlock("exit")
        entry.connect_to(header)
        header.connect_to(header)
        header.connect_to(exit_bb)
        n = SSAVar("n", 0)
        c0 = SSAVar("c0", 0)
        cond = SSAVar("cond", 0)
        entry.add_instruction(SSAInstruction(n, "param", ["n"]))
        entry.add_instruction(SSAInstruction(c0, "const", [0]))
        entry.add_instruction(SSAInstruction(None, "br", ["header"]))
        header.add_instruction(SSAInstruction(cond, "cmp_gt", [n, c0]))
        header.add_instruction(SSAInstruction(None, "br_cond", [cond, "header", "exit"]))
        exit_bb.add_instruction(SSAInstruction(None, "ret", [n]))
        fn_loop.add_block(entry)
        fn_loop.add_block(header)
        fn_loop.add_block(exit_bb)

        verdict_loop = validator.verify_equivalence(fn_loop, copy.deepcopy(fn_loop))
        self.assertFalse(verdict_loop["proven"])
        self.assertEqual(verdict_loop["status"], "UNVERIFIED_CYCLIC_CFG")

        # Case B: Unsupported opcode (alloca / call)
        fn_call = SSAFunction("call_fn", ["x"])
        bb = BasicBlock("entry")
        x_v = SSAVar("x", 0)
        r_v = SSAVar("r", 0)
        bb.add_instruction(SSAInstruction(x_v, "param", ["x"]))
        bb.add_instruction(SSAInstruction(r_v, "call", ["helper", x_v]))
        bb.add_instruction(SSAInstruction(None, "ret", [r_v]))
        fn_call.add_block(bb)

        verdict_call = validator.verify_equivalence(fn_call, copy.deepcopy(fn_call))
        self.assertFalse(verdict_call["proven"])
        self.assertTrue(verdict_call["status"].startswith("UNVERIFIED_"))

    def test_05_omni_repo_compiler_c24_integration(self):
        """Verifies end-to-end OmniRepoCompiler reports smt_pass_proofs >= 1 and smt_pass_rollbacks == 0."""
        with tempfile.TemporaryDirectory() as td:
            repo_dir = os.path.join(td, "repo_c24")
            os.makedirs(repo_dir, exist_ok=True)

            with open(os.path.join(repo_dir, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("""
[project]
name = "repo_c24"
version = "0.1.0"
[tool.omnicompiler.exports]
c24_fn = { file = "smt_mod.py", symbol = "c24_fn" }
""")
            with open(os.path.join(repo_dir, "smt_mod.py"), "w", encoding="utf-8") as f:
                f.write("""
def c24_fn(x: int, y: int) -> int:
    if x > y:
        return (x - y) * 3
    return (y - x) + 7
""")

            compiler = OmniRepoCompiler()
            res = compiler.compile_repositories(
                repo_paths=[repo_dir],
                output_path=os.path.join(td, "c24_out.dll"),
                target_format="shared_lib",
                target_os="windows" if sys.platform == "win32" else "linux",
                target_arch="x86_64",
                entry_export="c24_fn",
            )
            self.assertTrue(res["success"], f"AOT compilation failed: {res.get('error')}")
            codegen_stage = res["stages"]["codegen"]
            self.assertIn("smt_pass_proofs", codegen_stage)
            self.assertIn("smt_pass_rollbacks", codegen_stage)
            self.assertGreaterEqual(codegen_stage["smt_pass_proofs"], 1)
            self.assertEqual(codegen_stage["smt_pass_rollbacks"], 0)


if __name__ == "__main__":
    unittest.main()
