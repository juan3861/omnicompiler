"""
OmniCompiler Alpha-C23 Test Suite (tests/test_alpha_c23_sroa_devirt.py)
Validates:
1. Scalar Replacement of Aggregates (SROA):
   - Decomposing non-escaping constant-indexed `alloca`s into pure SSA scalars.
   - Zero remaining `alloca`, `store`, or `load` instructions after promotion.
   - Exact W^X x86-64 JIT execution of SROA-promoted code.
   - Sound rejection of escaped or dynamically-indexed `alloca`s.
2. Speculative Devirtualization with Guarded Fallback:
   - Guarded diamond CFG synthesis (`cmp_eq` guard -> fast direct call vs. slow fallback + `phi`).
   - Synergy with `SCCPPass` folding constant-tag guards to eliminate slow fallback paths.
3. End-to-End OmniRepoCompiler AOT Integration.
"""

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
from compiler.sroa_and_devirt import SROAPass, DevirtualizationPass
from compiler.ip_sccp_gvn import SCCPPass
from compiler.native_jit import NativeJitCompiler
from omni_repo_compiler import OmniRepoCompiler


class TestAlphaC23SroaDevirt(unittest.TestCase):

    def test_01_sroa_promotes_constant_indexed_alloca_to_pure_registers(self):
        """
        Verifies SROAPass eliminates a non-escaping constant-indexed `alloca` pair,
        promotes fields directly into SSA scalars, and executes identically in W^X silicon.
        """
        fn = SSAFunction("sroa_pair", ["a", "b"])
        bb = BasicBlock("entry")
        a = SSAVar("a", 0)
        b = SSAVar("b", 0)
        pair = SSAVar("pair", 0)
        t0 = SSAVar("t0", 0)
        t1 = SSAVar("t1", 0)
        v0 = SSAVar("v0", 0)
        v1 = SSAVar("v1", 0)
        res = SSAVar("res", 0)

        bb.add_instruction(SSAInstruction(a, "param", ["a"]))
        bb.add_instruction(SSAInstruction(b, "param", ["b"]))
        bb.add_instruction(SSAInstruction(pair, "alloca", [16]))
        bb.add_instruction(SSAInstruction(t0, "add", [a, 10]))
        bb.add_instruction(SSAInstruction(t1, "mul", [b, 2]))
        bb.add_instruction(SSAInstruction(None, "store", [pair, 0, t0]))
        bb.add_instruction(SSAInstruction(None, "store", [pair, 1, t1]))
        bb.add_instruction(SSAInstruction(v0, "load", [pair, 0]))
        bb.add_instruction(SSAInstruction(v1, "load", [pair, 1]))
        bb.add_instruction(SSAInstruction(res, "add", [v0, v1]))
        bb.add_instruction(SSAInstruction(None, "ret", [res]))
        fn.add_block(bb)

        opt_fn, stats = SROAPass().run_on_function(fn)
        self.assertEqual(stats["sroa_replaced_allocas"], 1)
        self.assertEqual(stats["sroa_eliminated_mem_ops"], 5)  # 1 alloca + 2 store + 2 load

        mem_ops = [
            inst for blk in opt_fn.blocks for inst in blk.instructions
            if inst.opcode in ("alloca", "store", "load")
        ]
        self.assertEqual(len(mem_ops), 0)

        jit = NativeJitCompiler()
        fn_ptr, _mem, _ = jit.compile_ssa(opt_fn)
        self.assertEqual(fn_ptr(5, 7), 29)  # (5 + 10) + (7 * 2) = 29

    def test_02_sroa_rejects_escaped_and_dynamic_indexed_allocas(self):
        """
        Verifies SROAPass rejects allocas that escape via `call` or use dynamic indices.
        """
        # Case A: Escaping via call
        fn1 = SSAFunction("esc_alloca", ["x"])
        bb1 = BasicBlock("entry")
        x = SSAVar("x", 0)
        buf = SSAVar("buf", 0)
        r1 = SSAVar("r1", 0)
        bb1.add_instruction(SSAInstruction(x, "param", ["x"]))
        bb1.add_instruction(SSAInstruction(buf, "alloca", [8]))
        bb1.add_instruction(SSAInstruction(None, "store", [buf, 0, x]))
        bb1.add_instruction(SSAInstruction(r1, "call", ["external_fn", buf]))
        bb1.add_instruction(SSAInstruction(None, "ret", [r1]))
        fn1.add_block(bb1)

        _, stats1 = SROAPass().run_on_function(fn1)
        self.assertEqual(stats1["sroa_replaced_allocas"], 0)

        # Case B: Dynamic index
        fn2 = SSAFunction("dyn_alloca", ["idx"])
        bb2 = BasicBlock("entry")
        idx = SSAVar("idx", 0)
        buf2 = SSAVar("buf2", 0)
        r2 = SSAVar("r2", 0)
        bb2.add_instruction(SSAInstruction(idx, "param", ["idx"]))
        bb2.add_instruction(SSAInstruction(buf2, "alloca", [16]))
        bb2.add_instruction(SSAInstruction(None, "store", [buf2, idx, 42]))
        bb2.add_instruction(SSAInstruction(r2, "load", [buf2, 0]))
        bb2.add_instruction(SSAInstruction(None, "ret", [r2]))
        fn2.add_block(bb2)

        _, stats2 = SROAPass().run_on_function(fn2)
        self.assertEqual(stats2["sroa_replaced_allocas"], 0)

    def test_03_sroa_across_dominated_blocks(self):
        """
        Verifies SROAPass propagates aggregate slot values across dominated blocks
        and compiles cleanly to W^X x86-64 machine code.
        """
        fn = SSAFunction("sroa_dom", ["a"])
        entry = BasicBlock("entry")
        then_b = BasicBlock("then_b")
        else_b = BasicBlock("else_b")
        entry.connect_to(then_b)
        entry.connect_to(else_b)

        a = SSAVar("a", 0)
        agg = SSAVar("agg", 0)
        cond = SSAVar("cond", 0)
        v_then = SSAVar("v_then", 0)
        v_else = SSAVar("v_else", 0)

        entry.add_instruction(SSAInstruction(a, "param", ["a"]))
        entry.add_instruction(SSAInstruction(agg, "alloca", [16]))
        entry.add_instruction(SSAInstruction(None, "store", [agg, 0, a]))
        entry.add_instruction(SSAInstruction(cond, "cmp_gt", [a, 0]))
        entry.add_instruction(SSAInstruction(None, "br_cond", [cond, "then_b", "else_b"]))

        then_b.add_instruction(SSAInstruction(v_then, "load", [agg, 0]))
        then_b.add_instruction(SSAInstruction(None, "ret", [v_then]))

        else_b.add_instruction(SSAInstruction(v_else, "load", [agg, 0]))
        else_b.add_instruction(SSAInstruction(None, "ret", [v_else]))

        fn.add_block(entry)
        fn.add_block(then_b)
        fn.add_block(else_b)

        opt_fn, stats = SROAPass().run_on_function(fn)
        self.assertEqual(stats["sroa_replaced_allocas"], 1)

        jit = NativeJitCompiler()
        fn_ptr, _mem, _ = jit.compile_ssa(opt_fn)
        self.assertEqual(fn_ptr(15), 15)
        self.assertEqual(fn_ptr(-9), -9)

    def test_04_devirtualization_guarded_diamond_cfg(self):
        """
        Verifies DevirtualizationPass transforms a `vcall` into a guarded diamond CFG
        with a direct fast-path call, indirect slow-path fallback, and `phi` merge.
        """
        fn = SSAFunction("poly_caller", ["tag", "x"])
        entry = BasicBlock("entry")
        tag = SSAVar("tag", 0)
        x = SSAVar("x", 0)
        res = SSAVar("res", 0)
        out = SSAVar("out", 0)

        entry.add_instruction(SSAInstruction(tag, "param", ["tag"]))
        entry.add_instruction(SSAInstruction(x, "param", ["x"]))
        entry.add_instruction(SSAInstruction(res, "vcall", [tag, "compute", x]))
        entry.add_instruction(SSAInstruction(out, "add", [res, 1]))
        entry.add_instruction(SSAInstruction(None, "ret", [out]))
        fn.add_block(entry)

        opt_fn, stats = DevirtualizationPass().run_on_function(
            fn, speculative_targets={"compute": (7, "fast_compute")}
        )
        self.assertEqual(stats["devirtualized_calls"], 1)
        block_names = [b.name for b in opt_fn.blocks]
        self.assertTrue(any(n.startswith("devirt_fast") for n in block_names))
        self.assertTrue(any(n.startswith("devirt_slow") for n in block_names))
        self.assertTrue(any(n.startswith("devirt_merge") for n in block_names))

        # Verify direct `call fast_compute` exists in fast block
        fast_blk = next(b for b in opt_fn.blocks if b.name.startswith("devirt_fast"))
        self.assertEqual(fast_blk.instructions[0].opcode, "call")
        self.assertEqual(fast_blk.instructions[0].operands[0], "fast_compute")

    def test_05_devirtualized_fast_path_eligible_for_sccp_folding(self):
        """
        Verifies that when a constant tag is passed to a devirtualized call,
        SCCPPass folds the guard and prunes the slow fallback block completely.
        """
        fn = SSAFunction("const_poly_caller", ["x"])
        entry = BasicBlock("entry")
        x = SSAVar("x", 0)
        tag = SSAVar("tag", 0)
        res = SSAVar("res", 0)

        entry.add_instruction(SSAInstruction(x, "param", ["x"]))
        entry.add_instruction(SSAInstruction(tag, "const", [7]))
        entry.add_instruction(SSAInstruction(res, "vcall", [tag, "compute", x]))
        entry.add_instruction(SSAInstruction(None, "ret", [res]))
        fn.add_block(entry)

        opt_fn, d_stats = DevirtualizationPass().run_on_function(
            fn, speculative_targets={"compute": (7, "fast_compute")}
        )
        self.assertEqual(d_stats["devirtualized_calls"], 1)

        opt_fn, s_stats = SCCPPass().run_on_function(opt_fn)
        self.assertGreaterEqual(s_stats["sccp_folded_branches"], 1)
        self.assertGreaterEqual(s_stats["sccp_pruned_blocks"], 1)

        # Slow fallback block should be completely pruned!
        self.assertFalse(any(b.name.startswith("devirt_slow") for b in opt_fn.blocks))

    def test_06_omni_repo_compiler_c23_integration(self):
        """
        Verifies end-to-end OmniRepoCompiler AOT compilation reports
        `sroa_replaced_allocas`, `sroa_eliminated_mem_ops`, and `devirtualized_calls`.
        """
        with tempfile.TemporaryDirectory() as td:
            repo_dir = os.path.join(td, "repo_c23")
            os.makedirs(repo_dir, exist_ok=True)

            with open(os.path.join(repo_dir, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("""
[project]
name = "repo_c23"
version = "0.1.0"
[tool.omnicompiler.exports]
c23_fn = { file = "sroa_mod.py", symbol = "c23_fn" }
""")
            with open(os.path.join(repo_dir, "sroa_mod.py"), "w", encoding="utf-8") as f:
                f.write("""
def c23_fn(x: int, y: int) -> int:
    return (x + y) * 2
""")

            compiler = OmniRepoCompiler()
            res = compiler.compile_repositories(
                repo_paths=[repo_dir],
                output_path=os.path.join(td, "c23_out.dll"),
                target_format="shared_lib",
                target_os="windows" if sys.platform == "win32" else "linux",
                target_arch="x86_64",
                entry_export="c23_fn",
            )
            self.assertTrue(res["success"], f"AOT compilation failed: {res.get('error')}")
            codegen_stage = res["stages"]["codegen"]
            self.assertIn("sroa_replaced_allocas", codegen_stage)
            self.assertIn("sroa_eliminated_mem_ops", codegen_stage)
            self.assertIn("devirtualized_calls", codegen_stage)


if __name__ == "__main__":
    unittest.main()
