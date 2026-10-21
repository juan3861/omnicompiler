import unittest

try:
    from hypothesis import given, strategies as st, settings
    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False

from adapters.universal_abi_bridge import UniversalAbiBridge
from validation.silicon_safety_sandbox import SiliconSafetySandbox, UNICORN_AVAILABLE
from validation.binary_structure_auditor import BinaryStructureAuditor, PEFILE_AVAILABLE
from compiler.binary_emitter import StandaloneBinaryEmitter


class TestAdversarialPropertyFuzz(unittest.TestCase):
    def setUp(self):
        if not HYPOTHESIS_AVAILABLE:
            self.skipTest("Hypothesis is not installed in the current environment")
        self.abi_bridge = UniversalAbiBridge()
        self.sandbox = SiliconSafetySandbox()
        self.auditor = BinaryStructureAuditor()
        self.emitter = StandaloneBinaryEmitter()

    def test_fuzz_parameter_permutation_conservation(self):
        if not HYPOTHESIS_AVAILABLE:
            self.skipTest("Hypothesis not available")

        @settings(max_examples=50, deadline=None)
        @given(st.lists(st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=8), min_size=1, max_size=6, unique=True))
        def _run(param_names):
            # Shuffled parameter ordering
            caller_params = param_names
            callee_params = list(reversed(param_names))

            res = self.abi_bridge.synthesize_cross_repo_wrapper(caller_params, callee_params)
            self.assertTrue(res["synthesized"])
            self.assertEqual(len(res["permutations"]), len(param_names))
            # Ensure all caller params are mapped
            mapped_keys = list(res["mapping"].keys())
            self.assertEqual(sorted(mapped_keys), sorted(param_names))

        _run()

    def test_fuzz_silicon_addition_arithmetic_equivalence(self):
        if not HYPOTHESIS_AVAILABLE:
            self.skipTest("Hypothesis not available")
        if not UNICORN_AVAILABLE:
            self.skipTest("Unicorn not available")

        @settings(max_examples=30, deadline=None)
        @given(
            st.integers(min_value=-2**31, max_value=2**31 - 1),
            st.integers(min_value=-2**31, max_value=2**31 - 1)
        )
        def _run(x, y):
            # add rcx, rdx; mov rax, rcx; ret (Windows ABI)
            code = b"\x48\x01\xd1\x48\x89\xc8\xc3"
            res = self.sandbox.emulate_x86_64(code, args=[x, y], abi="windows")
            self.assertTrue(res.success)
            self.assertTrue(res.is_safe_for_silicon)

            # Expected 64-bit signed addition wrap-around
            expected_raw = (x + y) & 0xFFFFFFFFFFFFFFFF
            expected_signed = expected_raw if expected_raw < (1 << 63) else expected_raw - (1 << 64)
            self.assertEqual(res.return_value, expected_signed)

        _run()

    def test_fuzz_binary_emitter_and_auditor_conformance(self):
        if not HYPOTHESIS_AVAILABLE:
            self.skipTest("Hypothesis not available")
        if not PEFILE_AVAILABLE:
            self.skipTest("pefile not available")

        @settings(max_examples=25, deadline=None)
        @given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=3, max_size=16))
        def _run(export_name):
            code = b"\xb8\x01\x00\x00\x00\xc3"  # mov eax, 1; ret
            dll_bytes = self.emitter.build_pe64_dll(func_code=code, export_name=export_name)
            report = self.auditor.audit_binary(dll_bytes)

            self.assertTrue(report.is_valid)
            self.assertEqual(report.format, "PE32+")
            self.assertIn(export_name, report.exported_symbols)

        _run()


if __name__ == "__main__":
    unittest.main()

