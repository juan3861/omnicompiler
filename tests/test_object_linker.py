"""
Unit Tests for Native Object Linker & Symbol Relocation Engine
"""

import unittest
import ctypes
import os
import tempfile
from compiler.object_linker import NativeObjectLinker, ObjectModule, LinkerError
from compiler.native_jit import NativeJitMemory


class TestNativeObjectLinker(unittest.TestCase):

    def setUp(self):
        self.linker = NativeObjectLinker()

    def test_inter_module_relocation_and_linking(self):
        # 1. Module A (Core Math Repo):
        # fast_add(rcx, rdx) -> rax = rcx + rdx
        # 48 89 c8       mov rax, rcx
        # 48 01 d0       add rax, rdx
        # c3             ret
        mod_core = ObjectModule("repo_core")
        code_fast_add = b"\x48\x89\xc8\x48\x01\xd0\xc3"
        mod_core.add_symbol("fast_add", code_fast_add)

        # 2. Module B (Service Repo):
        # service_calc(rcx):
        # adds 15 to rcx by calling fast_add(rcx, 15)
        # 48 c7 c2 0f 00 00 00   mov rdx, 15 (7 bytes)
        # e8 00 00 00 00         call <fast_add> (5 bytes: opcode E8 at offset 7, disp32 at offset 8)
        # c3                     ret
        mod_service = ObjectModule("repo_service")
        call_code = bytearray()
        call_code.extend(b"\x48\xc7\xc2\x0f\x00\x00\x00")  # mov rdx, 15
        call_offset = len(call_code) + 1                   # offset of disp32
        call_code.extend(b"\xe8\x00\x00\x00\x00")          # call placeholder
        call_code.append(0xc3)                             # ret

        mod_service.add_symbol("service_calc", bytes(call_code))
        mod_service.add_call_relocation(call_offset, "fast_add")

        # 3. Link Modules Together
        self.linker.add_module(mod_service)
        self.linker.add_module(mod_core)
        link_res = self.linker.link()

        self.assertTrue(link_res["success"])
        self.assertEqual(link_res["relocations_applied"], 1)
        self.assertIn("fast_add", link_res["global_symbols"])
        self.assertIn("service_calc", link_res["global_symbols"])

        # 4. Physical Execution of the Linked Machine Code in Executable RAM
        mem = NativeJitMemory(size=4096)
        mem.write_code(link_res["combined_code"])

        fn_type = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
        service_fn = fn_type(mem.ptr)

        # Invoke service_calc(100) -> should call fast_add(100, 15) = 115!
        result = service_fn(100)
        mem.free()

        self.assertEqual(result, 115)

    def test_unresolved_symbol_failure(self):
        mod = ObjectModule("broken_repo")
        mod.add_symbol("caller_fn", b"\xe8\x00\x00\x00\x00\xc3")
        mod.add_call_relocation(1, "non_existent_function")

        self.linker.add_module(mod)
        with self.assertRaises(LinkerError):
            self.linker.link()


if __name__ == "__main__":
    unittest.main()
