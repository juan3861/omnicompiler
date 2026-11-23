import ast
import ctypes
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from compiler.binary_emitter import StandaloneBinaryEmitter
from compiler.native_codegen import Arm64CodeGenerator
from compiler.ssa_ir import AstToSsaLowering
from validation.binary_structure_auditor import BinaryStructureAuditor


class TestAlphaC87MacOSArm64Dylib(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="omni_c87_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _compile_arm64_fn(self):
        src = """
def omni_arm64_calc(a, b):
    return a * 3 + b * 2
"""
        fn_def = ast.parse(src).body[0]
        ssa_fn = AstToSsaLowering().lower_function_def(fn_def)
        return Arm64CodeGenerator().compile_function(ssa_fn)

    def test_01_arm64_macho_dylib_export_trie_dysymtab_and_codesign(self):
        art = self._compile_arm64_fn()
        emitter = StandaloneBinaryEmitter()
        dylib_bytes = emitter.build_macho64_dylib(
            func_code=art.code_bytes[:art.code_end_offset],
            export_name="omni_arm64_calc",
            arch="arm64",
            dylib_name="libomni_arm64_calc.dylib",
        )
        rep = BinaryStructureAuditor().audit_binary(dylib_bytes)
        self.assertTrue(rep.is_valid, msg=rep.errors)
        self.assertEqual(rep.format, "Mach-O 64")
        self.assertEqual(rep.machine_arch, "ARM64")
        self.assertEqual(rep.binary_type, "shared_library")
        self.assertTrue(rep.metrics.get("codesign_verified"))
        self.assertTrue(rep.metrics.get("dysymtab_present"))

        # Verify LC_DYLD_INFO_ONLY export trie contains _omni_arm64_calc
        ncmds = struct.unpack_from("<I", dylib_bytes, 16)[0]
        off = 32
        found_trie = False
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", dylib_bytes, off)
            if cmd == 0x80000022:
                exp_off, exp_sz = struct.unpack_from("<II", dylib_bytes, off + 40)
                self.assertGreater(exp_sz, 0)
                trie_slice = dylib_bytes[exp_off:exp_off + exp_sz]
                self.assertIn(b"_omni_arm64_calc\x00", trie_slice)
                found_trie = True
            off += cmdsize
        self.assertTrue(found_trie, "Missing LC_DYLD_INFO_ONLY export trie")

    def test_02_arm64_macho_dylib_native_cdll_or_unicorn_execution(self):
        art = self._compile_arm64_fn()
        code = art.code_bytes[:art.code_end_offset]
        dylib_path = os.path.join(self.tmpdir, "libomni_arm64_calc.dylib")
        StandaloneBinaryEmitter().emit_shared_library(
            output_path=dylib_path,
            func_code=code,
            export_name="omni_arm64_calc",
            target_format="arm64_macho_dylib",
        )
        with open(dylib_path, "rb") as f:
            dylib_bytes = f.read()

        if sys.platform == "darwin" and platform.machine().lower() in ("arm64", "aarch64"):
            lib = ctypes.CDLL(dylib_path)
            fn = getattr(lib, "omni_arm64_calc")
            fn.argtypes = [ctypes.c_int64, ctypes.c_int64]
            fn.restype = ctypes.c_int64
            self.assertEqual(fn(10, 6), 42)
            self.assertEqual(fn(-4, 11), 10)
        else:
            from validation.silicon_safety_sandbox import SiliconSafetySandbox

            # Slice __text bytes directly out of emitted Mach-O dylib image at 0x4000
            text_bytes = dylib_bytes[0x4000:0x4000 + len(code)]
            self.assertEqual(text_bytes, code)
            sim = SiliconSafetySandbox().emulate_arm64(text_bytes, args=[10, 6])
            self.assertTrue(sim.is_safe_for_silicon, msg=sim)
            self.assertEqual(sim.return_value, 42)


if __name__ == "__main__":
    unittest.main()
