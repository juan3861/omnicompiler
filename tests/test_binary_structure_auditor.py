import unittest
from compiler.binary_emitter import StandaloneBinaryEmitter
from validation.binary_structure_auditor import BinaryStructureAuditor


class TestBinaryStructureAuditor(unittest.TestCase):
    def setUp(self):
        from validation.binary_structure_auditor import PEFILE_AVAILABLE, PYELFTOOLS_AVAILABLE
        self.pefile_avail = PEFILE_AVAILABLE
        self.pyelftools_avail = PYELFTOOLS_AVAILABLE
        self.emitter = StandaloneBinaryEmitter()
        self.auditor = BinaryStructureAuditor()

    def test_audit_pe64_executable(self):
        if not self.pefile_avail:
            self.skipTest("pefile library not available")
        pe_bytes = self.emitter.build_pe64(exit_code=42)
        report = self.auditor.audit_binary(pe_bytes)
        self.assertTrue(report.is_valid, f"PE64 Exe validation failed: {report.errors}")
        self.assertEqual(report.format, "PE32+")
        self.assertEqual(report.machine_arch, "x86-64")
        self.assertEqual(report.binary_type, "executable")
        self.assertIn(".text", report.sections)
        self.assertIn(".idata", report.sections)

    def test_audit_pe64_dll(self):
        if not self.pefile_avail:
            self.skipTest("pefile library not available")
        # Emit a test DLL with an exported function
        code = b"\xb8\x2a\x00\x00\x00\xc3"  # mov eax, 42; ret
        dll_bytes = self.emitter.build_pe64_dll(func_code=code, export_name="omni_calc")
        report = self.auditor.audit_binary(dll_bytes)
        self.assertTrue(report.is_valid, f"PE64 DLL validation failed: {report.errors}")
        self.assertEqual(report.format, "PE32+")
        self.assertEqual(report.machine_arch, "x86-64")
        self.assertEqual(report.binary_type, "shared_library")
        self.assertIn(".text", report.sections)
        self.assertIn(".edata", report.sections)
        self.assertIn("omni_calc", report.exported_symbols)

    def test_audit_elf64_executable(self):
        if not self.pyelftools_avail:
            self.skipTest("pyelftools library not available")
        elf_bytes = self.emitter.build_elf64(exit_code=0)
        report = self.auditor.audit_binary(elf_bytes)
        self.assertTrue(report.is_valid, f"ELF64 Exe validation failed: {report.errors}")
        self.assertEqual(report.format, "ELF64")
        self.assertEqual(report.machine_arch, "x86-64")
        self.assertEqual(report.binary_type, "executable")

    def test_audit_elf64_shared_library(self):
        if not self.pyelftools_avail:
            self.skipTest("pyelftools library not available")
        code = b"\xb8\x7b\x00\x00\x00\xc3"  # mov eax, 123; ret
        so_bytes = self.emitter.build_elf64_so(func_code=code, export_name="omni_compute")
        report = self.auditor.audit_binary(so_bytes)
        self.assertTrue(report.is_valid, f"ELF64 SO validation failed: {report.errors}")
        self.assertEqual(report.format, "ELF64")
        self.assertEqual(report.machine_arch, "x86-64")
        self.assertEqual(report.binary_type, "shared_library")
        self.assertIn("omni_compute", report.exported_symbols)


if __name__ == "__main__":
    unittest.main()
