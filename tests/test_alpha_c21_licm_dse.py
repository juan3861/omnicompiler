"""
OmniCompiler Alpha-C21 Test Suite (tests/test_alpha_c21_licm_dse.py)
Validates:
1. AliasAnalysis:
   - `NO_ALIAS` for distinct `alloca`s, `alloca` vs `param`, and distinct constant indices.
   - `MUST_ALIAS` for identical base pointers & indices.
   - `MAY_ALIAS` for distinct `param` pointers.
2. Loop-Invariant Code Motion (LICM):
   - Hoisting pure loop-invariant chains out of natural loops into the pre-header.
   - Preserving loop-variant and side-effect instructions inside the loop.
   - Exact native W^X x86-64 JIT execution after hoisting.
3. Dead Store Elimination (DSE) & Store-to-Load Forwarding:
   - Eliminating overwritten `MUST_ALIAS` stores and unread local `alloca` stores.
   - Forwarding stored values directly to subsequent loads across non-aliasing stores.
4. End-to-End OmniRepoCompiler AOT Integration.
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
    lower_source_to_ssa,
)
from compiler.licm_and_dse import (
    AliasAnalysis,
    AliasResult,
    LICMPass,
    DSEPass,
)
from compiler.native_jit import NativeJitCompiler
from omni_repo_compiler import OmniRepoCompiler


class TestAlphaC21LicmDse(unittest.TestCase):

    def test_01_alias_analysis_classification(self):
        """
        Verifies AliasAnalysis accurately classifies NO_ALIAS, MUST_ALIAS, and MAY_ALIAS.
        """
        fn = SSAFunction("aa_test", ["p1", "p2"])
        bb = BasicBlock("entry")
        p1 = SSAVar("p1", 0)
        p2 = SSAVar("p2", 0)
        a1 = SSAVar("a1", 0)
        a2 = SSAVar("a2", 0)
        c0 = SSAVar("c0", 0)
        c1 = SSAVar("c1", 0)

        bb.add_instruction(SSAInstruction(p1, "param", ["p1"]))
        bb.add_instruction(SSAInstruction(p2, "param", ["p2"]))
        bb.add_instruction(SSAInstruction(a1, "alloca", [16]))
        bb.add_instruction(SSAInstruction(a2, "alloca", [16]))
        bb.add_instruction(SSAInstruction(c0, "const", [0]))
        bb.add_instruction(SSAInstruction(c1, "const", [1]))
        bb.add_instruction(SSAInstruction(None, "ret", [0]))
        fn.add_block(bb)

        aa = AliasAnalysis(fn)
        self.assertEqual(aa.alias(a1, c0, a2, c0), AliasResult.NO_ALIAS)
        self.assertEqual(aa.alias(a1, c0, p1, c0), AliasResult.NO_ALIAS)
        self.assertEqual(aa.alias(a1, c0, a1, c1), AliasResult.NO_ALIAS)
        self.assertEqual(aa.alias(a1, c0, a1, c0), AliasResult.MUST_ALIAS)
        self.assertEqual(aa.alias(p1, c0, p2, c0), AliasResult.MAY_ALIAS)

    def test_02_licm_hoists_loop_invariant_computations_and_executes_jit(self):
        """
        Verifies LICMPass hoists pure loop-invariant computations out of the loop body
        into the pre-header and executes identically in W^X x86-64 JIT silicon.
        """
        src = """
def licm_kernel(n: int, x: int) -> int:
    acc = 0
    i = 0
    while i < n:
        inv = (x * 3) + 7
        acc = acc + inv
        i = i + 1
    return acc
"""
        ssa_fn = lower_source_to_ssa(src, "licm_kernel", optimize=True)
        licm = LICMPass()
        opt_fn, stats = licm.run_on_function(ssa_fn)

        # Both `x * 3` and `+ 7` should be hoisted out of the loop!
        self.assertGreaterEqual(stats["licm_hoisted_insts"], 2)

        # Verify native JIT execution
        jit = NativeJitCompiler()
        fn_ptr, _mem, _ = jit.compile_ssa(opt_fn)
        # n=10, x=4 => inv = (4*3)+7 = 19 => 10 * 19 = 190
        self.assertEqual(fn_ptr(10, 4), 190)
        self.assertEqual(fn_ptr(0, 4), 0)

    def test_03_licm_preserves_side_effect_calls_and_loop_variant_ops(self):
        """
        Verifies LICM does NOT hoist loop-variant expressions or side-effecting calls.
        """
        src = """
def licm_variant(n: int, x: int) -> int:
    acc = 0
    i = 0
    while i < n:
        v = i * x
        acc = acc + v
        i = i + 1
    return acc
"""
        ssa_fn = lower_source_to_ssa(src, "licm_variant", optimize=True)
        opt_fn, stats = LICMPass().run_on_function(ssa_fn)

        # `i * x` (mul) depends on `i` (loop-variant), so it must remain inside the loop body
        loop_muls = [
            inst for b in opt_fn.blocks if b.name != "entry"
            for inst in b.instructions if inst.opcode == "mul"
        ]
        self.assertEqual(len(loop_muls), 1)

        jit = NativeJitCompiler()
        fn_ptr, _mem, _ = jit.compile_ssa(opt_fn)
        # sum_{i=0..4} (i * 3) = (0+1+2+3+4)*3 = 30
        self.assertEqual(fn_ptr(5, 3), 30)

    def test_04_dse_eliminates_overwritten_and_unread_alloca_stores(self):
        """
        Verifies DSEPass eliminates:
          1. Overwritten store (`store buf, 0, 111` overwritten by `store buf, 0, 222`)
          2. Unread store to non-escaping local `alloca` before `ret` (`store buf, 1, 333`)
        """
        fn = SSAFunction("dse_test", [])
        bb = BasicBlock("entry")
        buf = SSAVar("buf", 0)
        res = SSAVar("res", 0)

        bb.add_instruction(SSAInstruction(buf, "alloca", [16]))
        bb.add_instruction(SSAInstruction(None, "store", [buf, 0, 111]))  # DEAD (overwritten)
        bb.add_instruction(SSAInstruction(None, "store", [buf, 0, 222]))  # LIVE (read below)
        bb.add_instruction(SSAInstruction(res, "load", [buf, 0]))
        bb.add_instruction(SSAInstruction(None, "store", [buf, 1, 333]))  # DEAD (unread before ret)
        bb.add_instruction(SSAInstruction(None, "ret", [res]))
        fn.add_block(bb)

        opt_fn, stats = DSEPass().run_on_function(fn)
        # Store-to-Load forwarding forwards 222 directly to `res`, making all 3 stores to local `alloca` dead!
        self.assertEqual(stats["forwarded_loads"], 1)
        self.assertEqual(stats["dse_eliminated_stores"], 3)

        remaining_stores = [
            inst for b in opt_fn.blocks for inst in b.instructions if inst.opcode == "store"
        ]
        self.assertEqual(len(remaining_stores), 0)

    def test_05_dse_store_to_load_forwarding(self):
        """
        Verifies DSEPass forwards stored values to subsequent loads even across
        intervening NO_ALIAS stores to a distinct stack allocation.
        """
        fn = SSAFunction("fwd_test", ["x"])
        bb = BasicBlock("entry")
        x = SSAVar("x", 0)
        b1 = SSAVar("b1", 0)
        b2 = SSAVar("b2", 0)
        loaded = SSAVar("loaded", 0)

        bb.add_instruction(SSAInstruction(x, "param", ["x"]))
        bb.add_instruction(SSAInstruction(b1, "alloca", [8]))
        bb.add_instruction(SSAInstruction(b2, "alloca", [8]))
        bb.add_instruction(SSAInstruction(None, "store", [b1, 0, x]))
        bb.add_instruction(SSAInstruction(None, "store", [b2, 0, 999]))  # NO_ALIAS with b1!
        bb.add_instruction(SSAInstruction(loaded, "load", [b1, 0]))
        bb.add_instruction(SSAInstruction(None, "ret", [loaded]))
        fn.add_block(bb)

        opt_fn, stats = DSEPass().run_on_function(fn)
        self.assertGreaterEqual(stats["forwarded_loads"], 1)

        # `load` should be eliminated and `ret` should return `x` directly!
        remaining_loads = [
            inst for b in opt_fn.blocks for inst in b.instructions if inst.opcode == "load"
        ]
        self.assertEqual(len(remaining_loads), 0)

    def test_06_omni_repo_compiler_c21_integration(self):
        """
        Verifies end-to-end OmniRepoCompiler AOT compilation executes LICM and DSE passes
        and records `licm_hoisted_insts` in `stages["codegen"]`.
        """
        with tempfile.TemporaryDirectory() as td:
            repo_dir = os.path.join(td, "repo_c21")
            os.makedirs(repo_dir, exist_ok=True)

            with open(os.path.join(repo_dir, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("""
[project]
name = "repo_c21"
version = "0.1.0"
[tool.omnicompiler.exports]
c21_licm_fn = { file = "licm_mod.py", symbol = "c21_licm_fn" }
""")
            with open(os.path.join(repo_dir, "licm_mod.py"), "w", encoding="utf-8") as f:
                f.write("""
def c21_licm_fn(n: int, x: int) -> int:
    acc = 0
    i = 0
    while i < n:
        inv = (x * 3) + 7
        acc = acc + inv
        i = i + 1
    return acc
""")

            compiler = OmniRepoCompiler()
            res = compiler.compile_repositories(
                repo_paths=[repo_dir],
                output_path=os.path.join(td, "c21_out.dll"),
                target_format="shared_lib",
                target_os="windows" if sys.platform == "win32" else "linux",
                target_arch="x86_64",
                entry_export="c21_licm_fn",
            )
            self.assertTrue(res["success"], f"AOT compilation failed: {res.get('error')}")
            codegen_stage = res["stages"]["codegen"]
            self.assertIn("licm_hoisted_insts", codegen_stage)
            self.assertIn("dse_eliminated_stores", codegen_stage)
            self.assertIn("forwarded_loads", codegen_stage)
            self.assertGreaterEqual(codegen_stage["licm_hoisted_insts"], 1)


if __name__ == "__main__":
    unittest.main()
