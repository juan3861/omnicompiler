"""
Unit Tests for OmniCompiler Mach-O 64-bit Cross-Target Compiler & Structural Auditor (ALPHA-C7)
Validates GEAR-001/002: macOS x86-64 and Apple Silicon ARM64 direct binary emission.
"""

import os
import io
import shutil
import tempfile
import unittest

from compiler.binary_emitter import StandaloneBinaryEmitter
from validation.binary_structure_auditor import BinaryStructureAuditor
from compiler.object_linker import NativeObjectLinker, ObjectModule


class TestMachOCrossTargetCompiler(unittest.TestCase):
    def setUp(self):
        self.emitter = StandaloneBinaryEmitter()
        self.auditor = BinaryStructureAuditor()
        self.temp_dir = tempfile.mkdtemp(prefix="omni_macho_test_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_macho_x86_64_executable_emission(self):
        """Validates macOS x86-64 standalone executable emission and formal header invariants."""
        # mov edi, 42 ; mov eax, 0x2000001 ; syscall
        code = b"\xbf\x2a\x00\x00\x00\xb8\x01\x00\x00\x02\x0f\x05"
        bin_bytes = self.emitter.build_macho64(exit_code=42, custom_code=code, arch="x86_64")
        
        # Verify 32-byte mach_header_64
        self.assertTrue(len(bin_bytes) >= 32)
        self.assertEqual(bin_bytes[:4], b"\xcf\xfa\xed\xfe")  # MH_MAGIC_64 little-endian

        report = self.auditor.audit_binary(bin_bytes)
        self.assertTrue(report.is_valid, f"Mach-O audit failed: {report.errors}")
        self.assertEqual(report.format, "Mach-O 64")
        self.assertEqual(report.machine_arch, "x86-64")
        self.assertEqual(report.binary_type, "executable")
        self.assertTrue(any("__TEXT.__text" in s for s in report.sections))

    def test_02_macho_arm64_executable_emission(self):
        """Validates macOS Apple Silicon (AArch64) standalone executable emission."""
        # mov x0, 42 ; mov x16, 1 ; svc 0x80
        bin_bytes = self.emitter.build_macho64(exit_code=42, arch="arm64")
        
        self.assertEqual(bin_bytes[:4], b"\xcf\xfa\xed\xfe")
        report = self.auditor.audit_binary(bin_bytes)
        self.assertTrue(report.is_valid, f"ARM64 Mach-O audit failed: {report.errors}")
        self.assertEqual(report.format, "Mach-O 64")
        self.assertEqual(report.machine_arch, "ARM64")
        self.assertEqual(report.binary_type, "executable")
        self.assertTrue(any("__TEXT.__text" in s for s in report.sections))

    def test_03_macho_x86_64_dylib_emission(self):
        """Validates macOS x86-64 dynamic shared library (.dylib) emission."""
        # mov eax, 175 ; ret
        func_code = b"\xb8\xaf\x00\x00\x00\xc3"
        dylib_bytes = self.emitter.build_macho64_dylib(
            func_code=func_code,
            export_name="omni_calc",
            arch="x86_64",
            dylib_name="libomni_calc.dylib"
        )
        report = self.auditor.audit_binary(dylib_bytes)
        self.assertTrue(report.is_valid, f"Mach-O dylib audit failed: {report.errors}")
        self.assertEqual(report.format, "Mach-O 64")
        self.assertEqual(report.machine_arch, "x86-64")
        self.assertEqual(report.binary_type, "shared_library")
        self.assertIn("libomni_calc.dylib", report.exported_symbols)

    def test_04_macho_arm64_dylib_emission(self):
        """Validates macOS Apple Silicon ARM64 dynamic shared library (.dylib) emission."""
        # mov w0, 175 ; ret
        func_code = b"\xe0\x15\x80\x52\xc0\x03\x5f\xd6"
        dylib_bytes = self.emitter.build_macho64_dylib(
            func_code=func_code,
            export_name="omni_compute",
            arch="arm64",
            dylib_name="libomni_compute.dylib"
        )
        report = self.auditor.audit_binary(dylib_bytes)
        self.assertTrue(report.is_valid, f"ARM64 Mach-O dylib audit failed: {report.errors}")
        self.assertEqual(report.format, "Mach-O 64")
        self.assertEqual(report.machine_arch, "ARM64")
        self.assertEqual(report.binary_type, "shared_library")
        self.assertIn("libomni_compute.dylib", report.exported_symbols)

    def test_05_auditor_rejects_corrupted_macho_header(self):
        """Invariant: Corrupted Mach-O magic or truncated load commands must be rejected."""
        # Valid header but corrupted magic
        bad_magic_bytes = b"\x00\x00\x00\x00" + (b"\x00" * 40)
        report = self.auditor.audit_binary(bad_magic_bytes)
        self.assertFalse(report.is_valid)

        # Truncated Mach-O
        truncated = b"\xcf\xfa\xed\xfe" + b"\x00" * 10
        report2 = self.auditor.audit_binary(truncated)
        self.assertFalse(report2.is_valid)
        self.assertIn("header truncated", report2.errors[0].lower())

    def test_06_object_linker_emits_macho_executable(self):
        """Validates that NativeObjectLinker correctly emits Mach-O executables."""
        linker = NativeObjectLinker()
        mod = ObjectModule("test_repo")
        mod.add_symbol("entry_point", b"\xb8\x2a\x00\x00\x00\xc3")
        linker.add_module(mod)

        out_path = os.path.join(self.temp_dir, "macho_exec")
        res_path = linker.emit_linked_executable(
            output_path=out_path,
            entry_symbol="entry_point",
            target_format="macho64"
        )
        self.assertTrue(os.path.exists(res_path))
        with open(res_path, "rb") as f:
            data = f.read()
        report = self.auditor.audit_binary(data)
        self.assertTrue(report.is_valid)
        self.assertEqual(report.format, "Mach-O 64")


if __name__ == "__main__":
    unittest.main()
