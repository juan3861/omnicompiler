import unittest
from validation.silicon_safety_sandbox import SiliconSafetySandbox


class TestSiliconSafetySandbox(unittest.TestCase):
    def setUp(self):
        self.sandbox = SiliconSafetySandbox()

    def test_windows_abi_execution(self):
        # Code: add rcx, rdx; mov rax, rcx; ret
        code = b"\x48\x01\xd1\x48\x89\xc8\xc3"
        res = self.sandbox.emulate_x86_64(code, args=[12, 30], abi="windows")
        self.assertTrue(res.success, f"Emulation failed: {res.error}")
        self.assertEqual(res.return_value, 42)
        self.assertTrue(res.is_safe_for_silicon)
        self.assertGreater(res.steps_executed, 0)

    def test_system_v_abi_execution(self):
        # Code: add rdi, rsi; mov rax, rdi; ret
        code = b"\x48\x01\xf7\x48\x89\xf8\xc3"
        res = self.sandbox.emulate_x86_64(code, args=[100, 250], abi="system_v")
        self.assertTrue(res.success, f"Emulation failed: {res.error}")
        self.assertEqual(res.return_value, 350)
        self.assertTrue(res.is_safe_for_silicon)

    def test_invalid_instruction_containment(self):
        # Code: UD2 (illegal instruction)
        code = b"\x0f\x0b"
        res = self.sandbox.emulate_x86_64(code)
        self.assertFalse(res.success)
        self.assertFalse(res.is_safe_for_silicon)
        self.assertIn("Invalid instruction", str(res.error))

    def test_unmapped_memory_write_containment(self):
        # Code: mov dword ptr [0xdead0000], 1 (Unmapped memory write)
        code = b"\xc7\x04\x25\x00\x00\xad\xde\x01\x00\x00\x00\xc3"
        res = self.sandbox.emulate_x86_64(code)
        self.assertFalse(res.success)
        self.assertFalse(res.is_safe_for_silicon)
        self.assertIn("Invalid memory write", str(res.error))

    def test_infinite_loop_timeout_containment(self):
        # Code: jmp $ (infinite loop: EB FE)
        code = b"\xeb\xfe"
        res = self.sandbox.emulate_x86_64(code, max_steps=50)
        # Should stop after 50 steps without hanging
        self.assertFalse(res.is_safe_for_silicon)


if __name__ == "__main__":
    unittest.main()
