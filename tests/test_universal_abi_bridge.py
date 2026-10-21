"""
Unit Tests for Universal ABI Bridge & Cross-Language Marshalling Engine
"""

import unittest
from adapters.universal_abi_bridge import UniversalAbiBridge, StructLayout


class TestUniversalAbiBridge(unittest.TestCase):

    def setUp(self):
        self.bridge = UniversalAbiBridge()

    def test_c_struct_layout_and_alignment(self):
        # Struct:
        # i8  flags;   // size 1, align 1 (offset 0)
        # padding 3 bytes
        # i32 count;   // size 4, align 4 (offset 4)
        # i64 ptr;     // size 8, align 8 (offset 8)
        # Total size: 16, alignment 8
        layout = self.bridge.compute_struct_layout([
            ("flags", "i8"),
            ("count", "i32"),
            ("data_ptr", "ptr")
        ])

        self.assertEqual(layout.get_offset("flags"), 0)
        self.assertEqual(layout.get_offset("count"), 4)
        self.assertEqual(layout.get_offset("data_ptr"), 8)
        self.assertEqual(layout.total_size, 16)
        self.assertEqual(layout.struct_alignment, 8)

    def test_abi_trampoline_generation(self):
        # System V to Windows x64 conversion
        t_sysv_to_win = self.bridge.generate_abi_trampoline("system_v_x64", "windows_x64")
        self.assertTrue(len(t_sysv_to_win) > 0)
        self.assertEqual(t_sysv_to_win[-1], 0xC3) # Ends with ret

        # Windows x64 to System V conversion
        t_win_to_sysv = self.bridge.generate_abi_trampoline("windows_x64", "system_v_x64")
        self.assertTrue(len(t_win_to_sysv) > 0)
        self.assertEqual(t_win_to_sysv[-1], 0xC3)

    def test_cross_repo_parameter_synthesis_and_permutations(self):
        caller_params = ["tenant_id", "doc_payload", "query_text"]
        callee_params = ["account_id", "raw_data", "filter_q"]

        wrapper = self.bridge.synthesize_cross_repo_wrapper(
            caller_params=caller_params,
            callee_params=callee_params,
            caller_abi="windows_x64",
            callee_abi="system_v_x64"
        )

        self.assertTrue(wrapper["synthesized"])
        self.assertEqual(wrapper["mapping"]["account_id"], "tenant_id")
        self.assertEqual(wrapper["mapping"]["raw_data"], "doc_payload")
        self.assertEqual(wrapper["mapping"]["filter_q"], "query_text")
        self.assertEqual(len(wrapper["permutations"]), 3)


if __name__ == "__main__":
    unittest.main()
