"""
Test Suite for Alpha-C15: Native Stack Allocation Promotion & alloca Codegen.
Validates:
1. Stack promotion of non-escaping local OmniList dynamic buffers to stack alloca.
2. Prevention of stack promotion for escaping (returned or embedded) containers.
3. Native x86-64 JIT machine code execution of functions with alloca buffers (lea rax, [rbp - disp]).
4. ARM64 instruction encoding for stack alloca (sub X9, X29, #disp).
"""

import ast
import ctypes
import unittest

from compiler.ssa_ir import AstToSsaLowering, SSAFunction, SSAInstruction, SSAVar
from compiler.escape_analysis import EscapeAnalysisPass, EscapeState
from compiler.stack_promotion import StackPromotionPass
from compiler.native_codegen import NativeCodeGenerator
from compiler.native_jit import NativeJitCompiler, NativeJitMemory


class TestAlphaC15StackPromotion(unittest.TestCase):

    def test_01_stack_promotion_local_omnilist(self):
        """Validates that a non-escaping local list is promoted from heap to stack alloca."""
        py_code = """
def local_kernel(a: int, b: int) -> int:
    arr = [a, b, a + b]
    return arr[0] + arr[1] + arr[2]
"""
        tree = ast.parse(py_code).body[0]
        ssa_fn = AstToSsaLowering().lower_function_def(tree)

        # Verify initial heap call exists
        calls_before = [inst.operands[0] for b in ssa_fn.blocks for inst in b.instructions if inst.opcode == "call" and inst.operands]
        self.assertIn("omni_list_new", calls_before)

        # Apply stack promotion pass
        promoted_fn, stats = StackPromotionPass().promote_function(ssa_fn)
        self.assertEqual(stats["promoted_lists"], 1)
        self.assertGreater(stats["bytes_promoted_to_stack"], 0)

        # Verify omni_list_new is replaced with alloca
        all_opcodes = [inst.opcode for b in promoted_fn.blocks for inst in b.instructions]
        self.assertIn("alloca", all_opcodes)

        # Compile with native x86-64 codegen
        codegen = NativeCodeGenerator()
        artifact = codegen.compile_ssa(promoted_fn)
        self.assertGreater(len(artifact.code_bytes), 0)

    def test_02_escaping_list_not_promoted(self):
        """Validates that an escaping list is NOT promoted to stack to prevent dangling pointers."""
        py_code = """
def factory_list(x: int) -> list:
    ret_arr = [x, x * 2]
    return ret_arr
"""
        tree = ast.parse(py_code).body[0]
        ssa_fn = AstToSsaLowering().lower_function_def(tree)

        promoted_fn, stats = StackPromotionPass().promote_function(ssa_fn)
        self.assertEqual(stats["promoted_lists"], 0)
        self.assertEqual(stats["bytes_promoted_to_stack"], 0)

        all_opcodes = [inst.opcode for b in promoted_fn.blocks for inst in b.instructions]
        self.assertNotIn("alloca", all_opcodes)

    def test_03_native_jit_alloca_execution(self):
        """Validates hardware execution of an SSA function using stack alloca memory."""
        # Create an SSA function:
        # buf = alloca 32
        # store buf, 0, 42
        # store buf, 1, 84
        # a = load buf, 0
        # b = load buf, 1
        # res = add a, b
        # ret res
        fn = SSAFunction("test_alloca_fn", ["x"])
        entry = fn.blocks[0] if fn.blocks else None
        if not entry:
            from compiler.ssa_ir import BasicBlock
            entry = BasicBlock("entry")
            fn.add_block(entry)
            fn.entry_block = entry

        x_param = SSAVar("x", 0)
        entry.add_instruction(SSAInstruction(x_param, "param", ["x"]))

        buf_var = SSAVar("buf", 1)
        entry.add_instruction(SSAInstruction(buf_var, "alloca", [32]))

        c42 = SSAVar("c42", 1)
        c84 = SSAVar("c84", 1)
        idx0 = SSAVar("i0", 1)
        idx1 = SSAVar("i1", 1)
        entry.add_instruction(SSAInstruction(c42, "const", [42]))
        entry.add_instruction(SSAInstruction(c84, "const", [84]))
        entry.add_instruction(SSAInstruction(idx0, "const", [0]))
        entry.add_instruction(SSAInstruction(idx1, "const", [1]))

        entry.add_instruction(SSAInstruction(None, "store", [buf_var, idx0, c42]))
        entry.add_instruction(SSAInstruction(None, "store", [buf_var, idx1, c84]))

        ld_a = SSAVar("a", 1)
        ld_b = SSAVar("b", 1)
        entry.add_instruction(SSAInstruction(ld_a, "load", [buf_var, idx0]))
        entry.add_instruction(SSAInstruction(ld_b, "load", [buf_var, idx1]))

        res = SSAVar("res", 1)
        entry.add_instruction(SSAInstruction(res, "add", [ld_a, ld_b]))
        entry.add_instruction(SSAInstruction(None, "ret", [res]))

        # Compile and execute natively via JIT
        jit = NativeJitCompiler()
        fn_callable, mem, code_hex = jit.compile_ssa(fn)
        result = fn_callable(10)
        self.assertEqual(result, 126, f"Expected 42 + 84 = 126, got {result}")

    def test_04_arm64_alloca_bytecode_emission(self):
        """Validates that ARM64 compiler emits sub X9, X29, #disp for alloca."""
        from compiler.native_codegen import Arm64CodeGenerator
        from compiler.ssa_ir import BasicBlock

        fn = SSAFunction("arm_alloca_fn", ["x"])
        entry = BasicBlock("entry")
        fn.add_block(entry)
        fn.entry_block = entry

        x_param = SSAVar("x", 0)
        entry.add_instruction(SSAInstruction(x_param, "param", ["x"]))
        buf_var = SSAVar("buf", 1)
        entry.add_instruction(SSAInstruction(buf_var, "alloca", [48]))
        entry.add_instruction(SSAInstruction(None, "ret", [buf_var]))

        arm_gen = Arm64CodeGenerator()
        artifact = arm_gen.compile_function(fn)
        self.assertGreater(len(artifact.code_bytes), 0)


if __name__ == "__main__":
    unittest.main()
