import unittest
import ctypes
from compiler.llvm_backend import LLVMBackend
from compiler.ssa_ir import SSAFunction, BasicBlock, SSAInstruction, SSAVar


class TestLLVMBackend(unittest.TestCase):
    def setUp(self):
        self.backend = LLVMBackend(opt_level=3)

    def test_llvm_ir_compilation_and_jit_execution(self):
        if not self.backend.is_available:
            self.skipTest("LLVM not available on this platform")

        ir = f"""
        target triple = "{self.backend.target_triple}"
        define i64 @compute_formula(i64 %x, i64 %y) {{
        entry:
            %sum = add i64 %x, %y
            %prod = mul i64 %sum, 3
            ret i64 %prod
        }}
        """
        mod = self.backend.compile_ir(ir, optimize=True)
        fn = self.backend.create_jit_callable(
            mod,
            "compute_formula",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_int64, ctypes.c_int64]
        )
        res = fn(10, 5)
        self.assertEqual(res, (10 + 5) * 3)

    def test_emit_native_object(self):
        if not self.backend.is_available:
            self.skipTest("LLVM not available")

        ir = f"""
        target triple = "{self.backend.target_triple}"
        define i64 @simple_ret(i64 %a) {{
            ret i64 %a
        }}
        """
        mod = self.backend.compile_ir(ir, optimize=False)
        obj_bytes = self.backend.emit_object(mod)
        self.assertIsInstance(obj_bytes, bytes)
        self.assertGreater(len(obj_bytes), 100)

    def test_ssa_lowering_to_llvm_and_execution(self):
        if not self.backend.is_available:
            self.skipTest("LLVM not available")

        # Build SSA Function: f(a, b) = (a + b) * 4
        func = SSAFunction(name="ssa_calc", params=["a", "b"])
        bb = BasicBlock("entry")
        func.add_block(bb)

        v_sum = SSAVar("sum", 0)
        v_res = SSAVar("res", 0)

        bb.add_instruction(SSAInstruction(result=v_sum, opcode="add", operands=["a", "b"]))
        bb.add_instruction(SSAInstruction(result=v_res, opcode="mul", operands=[v_sum, "4"]))
        bb.add_instruction(SSAInstruction(result=None, opcode="ret", operands=[v_res]))

        llvm_ir = self.backend.ssa_to_llvm_ir(func)
        self.assertIn("define i64 @ssa_calc", llvm_ir)

        mod = self.backend.compile_ir(llvm_ir, optimize=True)
        fn = self.backend.create_jit_callable(
            mod,
            "ssa_calc",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_int64, ctypes.c_int64]
        )
        res = fn(7, 3)
        self.assertEqual(res, (7 + 3) * 4)


if __name__ == "__main__":
    unittest.main()
