import unittest
from validation.assembly_invariant_auditor import AssemblyInvariantAuditor


class TestAssemblyInvariantAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = AssemblyInvariantAuditor()

    def test_valid_function_with_stack_balance(self):
        # sub rsp, 40 (0x28); mov rax, 42; add rsp, 40 (0x28); ret
        code = b"\x48\x83\xec\x28\xb8\x2a\x00\x00\x00\x48\x83\xc4\x28\xc3"
        rep = self.auditor.audit_function_code(code, "test_func")
        self.assertTrue(rep.is_valid, f"Expected valid, got errors: {rep.errors}")
        self.assertTrue(rep.stack_balanced)
        self.assertTrue(rep.termination_valid)
        self.assertTrue(rep.branch_displacements_safe)

    def test_stack_imbalance_detection(self):
        # sub rsp, 40 (0x28); mov rax, 42; ret (Forgot add rsp, 40!)
        code = b"\x48\x83\xec\x28\xb8\x2a\x00\x00\x00\xc3"
        rep = self.auditor.audit_function_code(code, "buggy_stack_func")
        self.assertFalse(rep.is_valid)
        self.assertFalse(rep.stack_balanced)
        self.assertIn("Stack frame imbalance", rep.errors[0])

    def test_missing_ret_termination_detection(self):
        # mov rax, 42 (No RET opcode!)
        code = b"\xb8\x2a\x00\x00\x00"
        rep = self.auditor.audit_function_code(code, "no_ret_func")
        self.assertFalse(rep.is_valid)
        self.assertFalse(rep.termination_valid)
        self.assertIn("does not terminate with RET", rep.errors[0])


if __name__ == "__main__":
    unittest.main()
