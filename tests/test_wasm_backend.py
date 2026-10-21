import unittest
from compiler.wasm_backend import WasmBackend
from compiler.ssa_ir import SSAFunction, BasicBlock, SSAInstruction, SSAVar


class TestWasmBackend(unittest.TestCase):
    def setUp(self):
        self.backend = WasmBackend()

    def test_wat_compilation_and_execution(self):
        if not self.backend.is_available:
            self.skipTest("Wasmtime is not available")

        wat = """
        (module
          (func (export "wasm_calc") (param $x i64) (param $y i64) (result i64)
            local.get $x
            local.get $y
            i64.add
            i64.const 10
            i64.mul
          )
        )
        """
        res = self.backend.execute_wasm(wat, "wasm_calc", args=[3, 4])
        self.assertEqual(res, (3 + 4) * 10)

    def test_wat_binary_serialization(self):
        if not self.backend.is_available:
            self.skipTest("Wasmtime is not available")

        wat = """
        (module
          (func (export "identity") (param i64) (result i64)
            local.get 0
          )
        )
        """
        wasm_bytes = self.backend.compile_wat(wat)
        self.assertIsInstance(wasm_bytes, bytes)
        self.assertGreater(len(wasm_bytes), 10)

        # Execute from deserialized binary bytes
        res = self.backend.execute_wasm(wasm_bytes, "identity", args=[999])
        self.assertEqual(res, 999)

    def test_ssa_lowering_to_wasm(self):
        if not self.backend.is_available:
            self.skipTest("Wasmtime is not available")

        # Build SSA: f(x, y) = (x + y) * 2
        func = SSAFunction(name="omni_wasm_func", params=["x", "y"])
        bb = BasicBlock("entry")
        func.add_block(bb)

        v_sum = SSAVar("sum", 0)
        v_res = SSAVar("res", 0)

        bb.add_instruction(SSAInstruction(result=v_sum, opcode="add", operands=["x", "y"]))
        bb.add_instruction(SSAInstruction(result=v_res, opcode="mul", operands=[v_sum, "2"]))
        bb.add_instruction(SSAInstruction(result=None, opcode="ret", operands=[v_res]))

        wat = self.backend.ssa_to_wat(func)
        self.assertIn("omni_wasm_func", wat)

        res = self.backend.execute_wasm(wat, "omni_wasm_func", args=[15, 25])
        self.assertEqual(res, (15 + 25) * 2)


if __name__ == "__main__":
    unittest.main()
