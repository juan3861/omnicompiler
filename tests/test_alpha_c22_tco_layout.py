"""
OmniCompiler Alpha-C22 Test Suite (tests/test_alpha_c22_tco_layout.py)
Validates:
1. Tail-Call Optimization (TCO):
   - Converting self-tail-recursive SSA calls into O(1) stack-frame loops.
   - Deep recursion execution (n=100,000) in W^X x86-64 JIT silicon without stack overflow.
   - Preserving non-tail recursion untouched.
2. Hot/Cold Basic-Block Layout Ordering:
   - Entry block preserved at index 0; hot loop blocks ordered before cold exits.
3. Peephole Machine Optimizer:
   - Eliminating zero-displacement `jmp rel32` and redundant self-moves safely.
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
from compiler.tco_and_layout import (
    TailCallOptimizationPass,
    BlockLayoutPass,
    PeepholeMachineOptimizer,
)
from compiler.native_jit import NativeJitCompiler
from omni_repo_compiler import OmniRepoCompiler


class TestAlphaC22TcoLayout(unittest.TestCase):

    def test_01_tco_converts_tail_recursion_to_loop_and_eliminates_calls(self):
        """
        Verifies TailCallOptimizationPass transforms self-tail-recursion into a loop
        with zero remaining `call` instructions.
        """
        src = """
def sum_tail(n: int, acc: int) -> int:
    if n <= 0:
        return acc
    return sum_tail(n - 1, acc + n)
"""
        ssa_fn = lower_source_to_ssa(src, "sum_tail", optimize=True)
        opt_fn, stats = TailCallOptimizationPass().run_on_function(ssa_fn)

        self.assertEqual(stats["tco_converted_calls"], 1)
        remaining_calls = [
            inst for b in opt_fn.blocks for inst in b.instructions if inst.opcode == "call"
        ]
        self.assertEqual(len(remaining_calls), 0)

    def test_02_tco_deep_recursion_100000_jit_silicon(self):
        """
        Compiles TCO-transformed `sum_tail(100000, 0)` to W^X x86-64 machine code
        and executes 100,000 iterations in O(1) stack space without stack overflow.
        """
        src = """
def sum_tail(n: int, acc: int) -> int:
    if n <= 0:
        return acc
    return sum_tail(n - 1, acc + n)
"""
        ssa_fn = lower_source_to_ssa(src, "sum_tail", optimize=True)
        opt_fn, stats = TailCallOptimizationPass().run_on_function(ssa_fn)
        self.assertEqual(stats["tco_converted_calls"], 1)

        jit = NativeJitCompiler()
        fn_ptr, _mem, _ = jit.compile_ssa(opt_fn)
        self.assertEqual(fn_ptr(10, 0), 55)
        self.assertEqual(fn_ptr(100000, 0), 5000050000)

    def test_03_tco_non_tail_recursion_preserved(self):
        """
        Verifies non-tail recursion (e.g. `n * fact(n - 1)`) is NOT rewritten by TCO.
        """
        src = """
def fact(n: int) -> int:
    if n <= 1:
        return 1
    return n * fact(n - 1)
"""
        ssa_fn = lower_source_to_ssa(src, "fact", optimize=True)
        opt_fn, stats = TailCallOptimizationPass().run_on_function(ssa_fn)

        self.assertEqual(stats["tco_converted_calls"], 0)
        remaining_calls = [
            inst for b in opt_fn.blocks for inst in b.instructions if inst.opcode == "call"
        ]
        self.assertEqual(len(remaining_calls), 1)

    def test_04_block_layout_hot_cold_ordering(self):
        """
        Verifies BlockLayoutPass keeps `entry` first and orders hot loop blocks
        ahead of cold exit blocks.
        """
        fn = SSAFunction("layout_test", [])
        entry = BasicBlock("entry")
        entry.add_instruction(SSAInstruction(None, "br", ["cold_exit"]))

        cold_exit = BasicBlock("cold_exit")
        cold_exit.loop_depth = 0
        cold_exit.add_instruction(SSAInstruction(None, "ret", [0]))

        hot_loop = BasicBlock("hot_loop")
        hot_loop.loop_depth = 2
        hot_loop.add_instruction(SSAInstruction(None, "br", ["cold_exit"]))

        fn.add_block(entry)
        fn.add_block(cold_exit)
        fn.add_block(hot_loop)

        opt_fn, stats = BlockLayoutPass().run_on_function(fn)
        self.assertEqual(opt_fn.blocks[0].name, "entry")
        self.assertEqual(opt_fn.blocks[1].name, "hot_loop")
        self.assertEqual(opt_fn.blocks[2].name, "cold_exit")
        self.assertGreaterEqual(stats["reordered_blocks"], 2)

    def test_05_peephole_machine_optimizer_strips_zero_jmp_and_self_mov(self):
        """
        Verifies PeepholeMachineOptimizer strips zero-offset jmp rel32 and redundant self-moves,
        while conservatively leaving code with relocations or internal branches untouched.
        """
        peep = PeepholeMachineOptimizer()
        raw = b"\x48\x89\xc0\xe9\x00\x00\x00\x00\xc3"  # mov rax, rax; jmp +0; ret
        opt, stats = peep.optimize_bytes(raw, has_relocations=False)
        self.assertEqual(opt, b"\xc3")
        self.assertEqual(stats["peephole_bytes_saved"], 8)
        self.assertEqual(stats["eliminated_fallthrough_jmps"], 1)

        # When has_relocations=True, must not shift bytes
        opt_rel, stats_rel = peep.optimize_bytes(raw, has_relocations=True)
        self.assertEqual(opt_rel, raw)
        self.assertEqual(stats_rel["peephole_bytes_saved"], 0)

    def test_06_omni_repo_compiler_c22_integration(self):
        """
        Verifies end-to-end OmniRepoCompiler AOT compilation runs TCO and BlockLayout
        and records `tco_converted_calls` in `stages["codegen"]`.
        """
        with tempfile.TemporaryDirectory() as td:
            repo_dir = os.path.join(td, "repo_c22")
            os.makedirs(repo_dir, exist_ok=True)

            with open(os.path.join(repo_dir, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("""
[project]
name = "repo_c22"
version = "0.1.0"
[tool.omnicompiler.exports]
sum_tail = { file = "tco_mod.py", symbol = "sum_tail" }
""")
            with open(os.path.join(repo_dir, "tco_mod.py"), "w", encoding="utf-8") as f:
                f.write("""
def sum_tail(n: int, acc: int) -> int:
    if n <= 0:
        return acc
    return sum_tail(n - 1, acc + n)
""")

            compiler = OmniRepoCompiler()
            res = compiler.compile_repositories(
                repo_paths=[repo_dir],
                output_path=os.path.join(td, "c22_out.dll"),
                target_format="shared_lib",
                target_os="windows" if sys.platform == "win32" else "linux",
                target_arch="x86_64",
                entry_export="sum_tail",
            )
            self.assertTrue(res["success"], f"AOT compilation failed: {res.get('error')}")
            codegen_stage = res["stages"]["codegen"]
            self.assertIn("tco_converted_calls", codegen_stage)
            self.assertIn("reordered_blocks", codegen_stage)
            self.assertIn("peephole_bytes_saved", codegen_stage)
            self.assertEqual(codegen_stage["tco_converted_calls"], 1)


if __name__ == "__main__":
    unittest.main()
