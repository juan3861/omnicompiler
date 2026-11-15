"""
OmniCompiler Alpha-C20 Test Suite (tests/test_alpha_c20_ipsccp_gvn.py)
Validates:
1. Global Value Numbering (GVN):
   - Dominator-tree scoped hash tables.
   - Commutative expression canonicalization (`a + b == b + a`, `a * b == b * a`).
   - Redundant expression elimination across dominated blocks.
2. Sparse Conditional Constant Propagation (SCCP):
   - 3-level lattice propagation (`TOP`, `CONSTANT`, `BOTTOM`).
   - Constant `br_cond` folding into unconditional `br` and dead block pruning.
   - Phi-node simplification over pruned edges.
3. Inter-Procedural SCCP & Call-Site Function Specialization:
   - Constant argument specialization (`fn__spec_a1_16`) with dead-branch folding.
   - Pure constant-return propagation across callers.
4. End-to-End Native JIT & OmniRepoCompiler AOT Integration.
"""

import os
import sys
import shutil
import tempfile
import unittest

from compiler.ssa_ir import lower_source_to_ssa, SSAFunction
from compiler.ip_sccp_gvn import (
    GlobalValueNumberingPass,
    SCCPPass,
    InterProceduralSCCPPass,
)
from compiler.native_jit import NativeJitCompiler
from omni_repo_compiler import OmniRepoCompiler


class TestAlphaC20IpSccpGvn(unittest.TestCase):

    def test_01_gvn_commutative_and_dominated_elimination(self):
        """
        Verifies GVN eliminates redundant commutative expressions (`a + b` and `b + a`)
        both within a block and across dominated successor blocks, and compiles to exact native code.
        """
        src = """
def gvn_kernel(a: int, b: int) -> int:
    t1 = a + b
    t2 = b + a
    if a > 0:
        t3 = a + b
        return t1 + t2 + t3
    return t1 + t2
"""
        ssa_fn = lower_source_to_ssa(src, "gvn_kernel", optimize=True)
        gvn = GlobalValueNumberingPass()
        opt_fn, stats = gvn.run_on_function(ssa_fn)

        # `t2 = b + a` and `t3 = a + b` (in dominated then-block) are redundant with `t1 = a + b`
        self.assertGreaterEqual(stats["gvn_eliminated_exprs"], 2)

        # Verify native JIT execution correctness
        jit = NativeJitCompiler()
        fn_ptr, _mem, _ = jit.compile_ssa(opt_fn)
        self.assertEqual(fn_ptr(5, 7), 36)   # (12 + 12 + 12) = 36
        self.assertEqual(fn_ptr(-2, 7), 10)  # (5 + 5) = 10

    def test_02_sccp_constant_branch_folding_and_dead_block_pruning(self):
        """
        Verifies SCCP folds constant conditional branches and prunes dead unreachable blocks,
        producing exact native machine code.
        """
        src = """
def sccp_branch(x: int) -> int:
    flag = 10
    if flag > 5:
        res = x + 100
    else:
        res = x - 9999
    return res
"""
        ssa_fn = lower_source_to_ssa(src, "sccp_branch", optimize=False)
        initial_blocks = len(ssa_fn.blocks)

        sccp = SCCPPass()
        opt_fn, stats = sccp.run_on_function(ssa_fn)

        self.assertGreaterEqual(stats["sccp_folded_branches"], 1)
        self.assertGreaterEqual(stats["sccp_pruned_blocks"], 1)
        self.assertLess(len(opt_fn.blocks), initial_blocks)

        # Native JIT execution check
        jit = NativeJitCompiler()
        fn_ptr, _mem, _ = jit.compile_ssa(opt_fn)
        self.assertEqual(fn_ptr(42), 142)

    def test_03_sccp_phi_constant_convergence_across_branches(self):
        """
        Verifies SCCP converges Phi nodes when all reachable incoming edges hold the same constant.
        """
        src = """
def sccp_phi_const(cond: int) -> int:
    if cond > 0:
        val = 42
    else:
        val = 42
    return val + 8
"""
        ssa_fn = lower_source_to_ssa(src, "sccp_phi_const", optimize=False)
        opt_fn, stats = SCCPPass().run_on_function(ssa_fn)

        self.assertGreaterEqual(stats["sccp_folded_constants"], 1)
        jit = NativeJitCompiler()
        fn_ptr, _mem, _ = jit.compile_ssa(opt_fn)
        self.assertEqual(fn_ptr(1), 50)
        self.assertEqual(fn_ptr(-5), 50)

    def test_04_interprocedural_call_site_specialization(self):
        """
        Verifies InterProceduralSCCPPass specializes a callee for constant arguments,
        folds internal branches in the specialized clone, and rewrites the caller's call site.
        """
        callee_src = """
def scaled_compute(x: int, mode: int) -> int:
    if mode == 1:
        return x * 16
    else:
        return x + 999
"""
        caller_src = """
def caller_entry(x: int) -> int:
    return scaled_compute(x, 1) + 5
"""
        program = {
            "scaled_compute": lower_source_to_ssa(callee_src, "scaled_compute", optimize=True),
            "caller_entry": lower_source_to_ssa(caller_src, "caller_entry", optimize=True),
        }

        ip_pass = InterProceduralSCCPPass()
        opt_prog, stats = ip_pass.optimize_program(program)

        self.assertGreaterEqual(stats["specialized_functions"], 1)
        self.assertGreaterEqual(stats["sccp_folded_branches"], 1)

        spec_names = [k for k in opt_prog.keys() if k.startswith("scaled_compute__spec_")]
        self.assertEqual(len(spec_names), 1)
        spec_fn = opt_prog[spec_names[0]]
        self.assertEqual(spec_fn.params, ["x"])  # `mode` specialized away!

        # Verify caller's call instruction now targets specialized clone with 1 arg
        caller_calls = [
            inst
            for b in opt_prog["caller_entry"].blocks
            for inst in b.instructions
            if inst.opcode == "call"
        ]
        self.assertEqual(len(caller_calls), 1)
        self.assertEqual(caller_calls[0].operands[0], spec_names[0])
        self.assertEqual(len(caller_calls[0].operands), 2)  # [spec_name, x]

    def test_05_interprocedural_pure_constant_return_propagation(self):
        """
        Verifies InterProceduralSCCPPass propagates pure constant-return functions into callers.
        """
        magic_src = """
def get_magic() -> int:
    return 1337
"""
        caller_src = """
def use_magic(x: int) -> int:
    m = get_magic()
    return x + m
"""
        program = {
            "get_magic": lower_source_to_ssa(magic_src, "get_magic", optimize=True),
            "use_magic": lower_source_to_ssa(caller_src, "use_magic", optimize=True),
        }

        opt_prog, stats = InterProceduralSCCPPass().optimize_program(program)
        self.assertGreaterEqual(stats["ip_constant_returns_propagated"], 1)

        # Call to get_magic should be eliminated in `use_magic`
        remaining_calls = [
            inst
            for b in opt_prog["use_magic"].blocks
            for inst in b.instructions
            if inst.opcode == "call"
        ]
        self.assertEqual(len(remaining_calls), 0)

        jit = NativeJitCompiler()
        fn_ptr, _mem, _ = jit.compile_ssa(opt_prog["use_magic"])
        self.assertEqual(fn_ptr(63), 1400)

    def test_06_omni_repo_compiler_c20_integration(self):
        """
        Verifies end-to-end OmniRepoCompiler AOT compilation runs SCCP and GVN passes
        and records `gvn_eliminated_exprs` and `sccp_folded_branches`.
        """
        with tempfile.TemporaryDirectory() as td:
            repo_dir = os.path.join(td, "repo_c20")
            os.makedirs(repo_dir, exist_ok=True)

            with open(os.path.join(repo_dir, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("""
[project]
name = "repo_c20"
version = "0.1.0"
[tool.omnicompiler.exports]
c20_opt_fn = { file = "opt_mod.py", symbol = "c20_opt_fn" }
""")
            with open(os.path.join(repo_dir, "opt_mod.py"), "w", encoding="utf-8") as f:
                f.write("""
def c20_opt_fn(a: int, b: int) -> int:
    k = 10
    t1 = a + b
    t2 = b + a
    if k > 3:
        return t1 + t2
    return a - 999
""")

            compiler = OmniRepoCompiler()
            res = compiler.compile_repositories(
                repo_paths=[repo_dir],
                output_path=os.path.join(td, "c20_out.dll"),
                target_format="shared_lib",
                target_os="windows" if sys.platform == "win32" else "linux",
                target_arch="x86_64",
                entry_export="c20_opt_fn",
            )
            self.assertTrue(res["success"], f"AOT compilation failed: {res.get('error')}")
            codegen_stage = res["stages"]["codegen"]
            self.assertIn("gvn_eliminated_exprs", codegen_stage)
            self.assertIn("sccp_folded_branches", codegen_stage)
            self.assertGreaterEqual(codegen_stage["gvn_eliminated_exprs"], 1)


if __name__ == "__main__":
    unittest.main()
