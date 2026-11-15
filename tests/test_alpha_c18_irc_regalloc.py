import ast
import os
import sys
import tempfile
import unittest

from compiler.ssa_ir import SSAFunction, BasicBlock, SSAInstruction, SSAVar, lower_ast_to_ssa
from compiler.regalloc_graph_coloring import (
    IteratedRegisterCoalescingAllocator,
    IRCAllocator,
    ChaitinBriggsAllocator,
    WIN64_CALLER_SAVED,
    WIN64_CALLEE_SAVED,
    SYSV64_CALLER_SAVED,
    SYSV64_CALLEE_SAVED,
    ARM64_CALLER_SAVED,
    ARM64_CALLEE_SAVED,
)
from compiler.native_codegen import NativeCodeGenerator
from compiler.native_jit import NativeJitCompiler
from omni_repo_compiler import OmniRepoCompiler


class TestAlphaC18IteratedRegisterCoalescing(unittest.TestCase):
    def test_01_briggs_and_george_conservative_coalescing(self):
        """
        Verify Briggs and George conservative coalescing criteria and full IRC move coalescing
        across `mov` and `phi` copy edges without introducing spills.
        """
        u = SSAVar("u", 0)
        v = SSAVar("v", 0)
        n1 = SSAVar("n1", 0)
        n2 = SSAVar("n2", 0)
        n3 = SSAVar("n3", 0)

        # Case A: K=2, n1 and n2 have degree 1 (< K). Merging u and v yields 0 neighbors of degree >= 2.
        adj_safe = {
            u: {n1},
            v: {n2},
            n1: {u},
            n2: {v},
        }
        self.assertTrue(IteratedRegisterCoalescingAllocator.briggs_criterion(u, v, adj_safe, k=2))
        self.assertTrue(IteratedRegisterCoalescingAllocator.george_criterion(u, v, adj_safe, k=2))

        # Case B: K=2, n1 and n2 both have degree 2 (>= K) and do NOT interfere with u.
        # Merging u and v would give uv two neighbors (n1, n2) of degree >= 2, violating Briggs & George for K=2!
        adj_unsafe = {
            u: set(),
            v: {n1, n2},
            n1: {v, n3},
            n2: {v, n3},
            n3: {n1, n2},
        }
        self.assertFalse(IteratedRegisterCoalescingAllocator.briggs_criterion(u, v, adj_unsafe, k=2))
        self.assertFalse(IteratedRegisterCoalescingAllocator.george_criterion(u, v, adj_unsafe, k=2))

        # Build an SSA function with chain of non-interfering `mov` copies and a `phi` merge
        fn = SSAFunction("irc_coalesce_demo", params=["a"])
        b_entry = BasicBlock("entry")
        b_left = BasicBlock("left")
        b_merge = BasicBlock("merge")
        b_entry.successors = [b_left]
        b_left.predecessors = [b_entry]
        b_left.successors = [b_merge]
        b_merge.predecessors = [b_left]

        v_a0 = SSAVar("a", 0)
        v_c1 = SSAVar("c", 1)
        v_c2 = SSAVar("c", 2)
        v_m1 = SSAVar("m", 1)
        v_out = SSAVar("out", 1)

        b_entry.instructions.append(SSAInstruction(v_c1, "mov", [v_a0]))
        b_entry.instructions.append(SSAInstruction(None, "br", ["left"]))

        b_left.instructions.append(SSAInstruction(v_c2, "mov", [v_c1]))
        b_left.instructions.append(SSAInstruction(None, "br", ["merge"]))

        phi = SSAInstruction(v_m1, "phi", [v_c2], phi_incoming=[("left", v_c2)])
        b_merge.phi_nodes.append(phi)
        b_merge.instructions.append(SSAInstruction(v_out, "add", [v_m1, 10]))
        b_merge.instructions.append(SSAInstruction(None, "ret", [v_out]))

        fn.blocks = [b_entry, b_left, b_merge]

        irc = IteratedRegisterCoalescingAllocator(abi="win64")
        res = irc.allocate(fn)

        self.assertTrue(res["success"])
        self.assertEqual(res["allocator"], "GeorgeAppelIRC")
        self.assertGreaterEqual(res["coalesced_moves"], 3)
        # Verify the entire non-interfering chain a_0 -> c_1 -> c_2 -> m_1 was coalesced into 1 register
        reg_a0 = res["color_map"][v_a0]
        self.assertEqual(res["color_map"][v_c1], reg_a0)
        self.assertEqual(res["color_map"][v_c2], reg_a0)
        self.assertEqual(res["color_map"][v_m1], reg_a0)

    def test_02_call_site_liveness_and_abi_callee_saved_partitioning(self):
        """
        Verify that variables live across a `call` instruction are identified in `live_across_call`
        and automatically assigned ABI `callee_saved` (non-volatile) registers, while short-lived
        variables that do not cross a call receive `caller_saved` (volatile) registers.
        """
        fn = SSAFunction("call_crossing_fn", params=["x"])
        blk = BasicBlock("entry")

        v_x = SSAVar("x", 0)
        v_short = SSAVar("short_tmp", 1)
        v_arg = SSAVar("call_arg", 1)
        v_ret = SSAVar("call_ret", 1)
        v_final = SSAVar("final_res", 1)

        # v_short is used BEFORE the call and never after -> NOT live across call
        blk.instructions.append(SSAInstruction(v_short, "add", [10, 20]))
        blk.instructions.append(SSAInstruction(v_arg, "mul", [v_short, 2]))
        # v_x is defined at entry and used AFTER the call -> LIVE ACROSS CALL!
        blk.instructions.append(SSAInstruction(v_ret, "call", ["helper_fn", v_arg]))
        blk.instructions.append(SSAInstruction(v_final, "add", [v_x, v_ret]))
        blk.instructions.append(SSAInstruction(None, "ret", [v_final]))
        fn.blocks = [blk]

        # Test Windows x64 ABI
        irc_win = IteratedRegisterCoalescingAllocator(abi="win64")
        res_win = irc_win.allocate(fn)
        self.assertTrue(res_win["success"])
        self.assertIn(str(v_x), res_win["live_across_call"])
        self.assertNotIn(str(v_short), res_win["live_across_call"])
        self.assertIn(res_win["color_map"][v_x], WIN64_CALLEE_SAVED)
        self.assertIn(res_win["color_map"][v_short], WIN64_CALLER_SAVED)

        # Test System V AMD64 ABI
        irc_sysv = IteratedRegisterCoalescingAllocator(abi="sysv64")
        res_sysv = irc_sysv.allocate(fn)
        self.assertTrue(res_sysv["success"])
        self.assertIn(str(v_x), res_sysv["live_across_call"])
        self.assertIn(res_sysv["color_map"][v_x], SYSV64_CALLEE_SAVED)
        self.assertIn(res_sysv["color_map"][v_short], SYSV64_CALLER_SAVED)

    def test_03_arm64_aapcs64_caller_callee_partitioning(self):
        """
        Verify ARM64 AAPCS64 register allocation partitions `x0..x14` (caller-saved)
        and `x19..x28` (callee-saved) across `BL` call boundaries.
        """
        fn = SSAFunction("arm64_call_fn", params=["p"])
        blk = BasicBlock("entry")

        v_p = SSAVar("p", 0)
        v_tmp = SSAVar("tmp", 1)
        v_call = SSAVar("call_out", 1)
        v_sum = SSAVar("sum_out", 1)

        blk.instructions.append(SSAInstruction(v_tmp, "add", [5, 7]))
        blk.instructions.append(SSAInstruction(v_call, "call", ["ext_arm_fn", v_tmp]))
        blk.instructions.append(SSAInstruction(v_sum, "add", [v_p, v_call]))
        blk.instructions.append(SSAInstruction(None, "ret", [v_sum]))
        fn.blocks = [blk]

        irc_arm = IteratedRegisterCoalescingAllocator(abi="arm64")
        res_arm = irc_arm.allocate(fn)
        self.assertTrue(res_arm["success"])
        self.assertEqual(res_arm["k_registers"], 25)
        self.assertIn(str(v_p), res_arm["live_across_call"])
        self.assertIn(res_arm["color_map"][v_p], ARM64_CALLEE_SAVED)
        self.assertIn(res_arm["color_map"][v_tmp], ARM64_CALLER_SAVED)

    def test_04_freeze_and_loop_weighted_spill_under_chromatic_pressure(self):
        """
        Verify that under high chromatic pressure (4 simultaneously live variables with K=3 registers):
        1. Constrained/blocked move edges trigger Freeze/Constrained handling without infinite loops.
        2. Loop-depth-weighted spill heuristics (10^loop_depth / degree) spill the outer variable
           (loop_depth=0) while keeping hot inner-loop variables (loop_depth=2) in physical registers.
        """
        fn = SSAFunction("high_pressure_loop", params=[])
        b_outer = BasicBlock("outer")
        b_outer.loop_depth = 0
        b_inner = BasicBlock("inner")
        b_inner.loop_depth = 2

        b_outer.successors = [b_inner]
        b_inner.predecessors = [b_outer]

        v_cold = SSAVar("cold_outer", 1)
        v_hot1 = SSAVar("hot_a", 1)
        v_hot2 = SSAVar("hot_b", 1)
        v_hot3 = SSAVar("hot_c", 1)
        v_hot_copy = SSAVar("hot_copy", 1)
        v_res = SSAVar("res", 1)

        # Define cold_outer once in outer block (loop_depth=0, weight=1)
        b_outer.instructions.append(SSAInstruction(v_cold, "mov", [42]))
        b_outer.instructions.append(SSAInstruction(None, "br", ["inner"]))

        # Define and repeatedly use hot_a, hot_b, hot_c inside inner loop (loop_depth=2, weight=100)
        b_inner.instructions.append(SSAInstruction(v_hot1, "mov", [1]))
        b_inner.instructions.append(SSAInstruction(v_hot2, "mov", [2]))
        b_inner.instructions.append(SSAInstruction(v_hot3, "mov", [3]))
        # Constrained move between interfering hot_a and hot_b
        b_inner.instructions.append(SSAInstruction(v_hot_copy, "mov", [v_hot1]))
        b_inner.instructions.append(SSAInstruction(v_hot1, "add", [v_hot1, v_hot2]))
        b_inner.instructions.append(SSAInstruction(v_hot2, "add", [v_hot2, v_hot3]))
        b_inner.instructions.append(SSAInstruction(v_hot3, "add", [v_hot3, v_hot_copy]))
        # Use cold_outer at the end so all 4 variables interfere simultaneously across the inner block
        b_inner.instructions.append(SSAInstruction(v_res, "add", [v_hot1, v_cold]))
        b_inner.instructions.append(SSAInstruction(None, "ret", [v_res]))

        fn.blocks = [b_outer, b_inner]

        irc = IteratedRegisterCoalescingAllocator(k_registers=["r8", "r9", "rbx"], abi="win64")
        res = irc.allocate(fn)

        self.assertFalse(res["success"])
        self.assertGreaterEqual(res["spills_count"], 1)
        # Verify the cold outer variable was chosen to spill, preserving registers for hot inner vars
        self.assertIn(str(v_cold), res["spill_slots"])
        self.assertIn(v_hot1, res["color_map"])
        self.assertIn(v_hot2, res["color_map"])
        self.assertIn(v_hot3, res["color_map"])

    def test_05_leaf_codegen_zero_callee_saved_prologue_overhead(self):
        """
        Verify that `NativeCodeGenerator` using `IteratedRegisterCoalescingAllocator` allocates
        short-lived leaf variables to volatile caller-saved registers (`r8`, `r9`, `r10`) first,
        resulting in zero callee-saved `push`/`pop` instructions in the function prologue/epilogue.
        """
        src = """
def fast_leaf_math(a: int, b: int) -> int:
    c = a + b
    d = c * 3
    return d - a
"""
        tree = ast.parse(src)
        fn_def = tree.body[0]
        ssa_fn = lower_ast_to_ssa(fn_def, optimize=True)

        codegen = NativeCodeGenerator(arch="x86_64", target_os="windows")
        artifact = codegen.compile_ssa(ssa_fn)

        self.assertTrue(artifact.leaf_register_mode)
        self.assertEqual(artifact.saved_nonvolatile_regs, [])
        self.assertEqual(artifact.prologue_size, 0)

        jit = NativeJitCompiler()
        callable_fn, mem, _ = jit.compile_ssa(ssa_fn)
        try:
            res = callable_fn(10, 5)
            # c = 15, d = 45, return 45 - 10 = 35
            self.assertEqual(res, 35)
        finally:
            mem.free()

    def test_06_aot_omni_repo_compiler_irc_integration(self):
        """
        Verify end-to-end `OmniRepoCompiler` AOT compilation records `irc_coalesced_moves`
        in `results["stages"]["codegen"]` and produces a valid executable binary.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = os.path.join(tmpdir, "irc_repo")
            os.makedirs(repo_dir)

            with open(os.path.join(repo_dir, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("""
[project]
name = "irc_repo"
version = "0.1.0"
[tool.omnicompiler.exports]
compute_series = { file = "irc_math.py", symbol = "compute_series" }
""")

            mod_path = os.path.join(repo_dir, "irc_math.py")
            with open(mod_path, "w", encoding="utf-8") as f:
                f.write(
                    "def compute_series(n: int) -> int:\n"
                    "    acc = 0\n"
                    "    i = 1\n"
                    "    while i <= n:\n"
                    "        step = i * 2\n"
                    "        acc = acc + step\n"
                    "        i = i + 1\n"
                    "    return acc\n"
                )

            out_exe = os.path.join(tmpdir, "irc_series.exe")
            compiler = OmniRepoCompiler()
            res = compiler.compile_repositories(
                repo_paths=[repo_dir],
                output_path=out_exe,
                target_format="executable",
                target_os="windows" if sys.platform == "win32" else "linux",
                target_arch="x86_64",
                entry_export="compute_series",
            )

            self.assertTrue(res["success"])
            self.assertTrue(os.path.exists(out_exe))
            self.assertIn("irc_coalesced_moves", res["stages"]["codegen"])
            self.assertGreaterEqual(res["stages"]["codegen"]["irc_coalesced_moves"], 1)
            self.assertTrue(res["stages"]["formal_audit"]["is_valid"])


if __name__ == "__main__":
    unittest.main()
