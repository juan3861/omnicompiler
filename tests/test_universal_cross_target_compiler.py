"""
Tests for Universal Cross-Target Multi-Repository Compilation in OmniCompiler.
Verifies cross-target binary and shared library emission across Windows and Linux,
for both x86-64 and ARM64 architectures.
"""

import sys
import os
import unittest
import tempfile
import subprocess
import ctypes
from omni_repo_compiler import OmniRepoCompiler
from validation.binary_structure_auditor import BinaryStructureAuditor


class TestUniversalCrossTargetCompiler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = OmniRepoCompiler()
        cls.auditor = BinaryStructureAuditor()
        cls.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.modules_dir = os.path.join(cls.base_dir, "compiler_modules")
        cls.repo_paths = [
            os.path.join(cls.modules_dir, d)
            for d in sorted(os.listdir(cls.modules_dir))
            if os.path.isdir(os.path.join(cls.modules_dir, d))
        ]

    def test_01_cross_target_windows_x86_64_shared_lib(self):
        """Cross-target build: Windows x86-64 PE32+ DLL."""
        with tempfile.TemporaryDirectory() as td:
            out_path = os.path.join(td, "test_engine.dll")
            res = self.compiler.compile_repositories(
                repo_paths=self.repo_paths,
                output_path=out_path,
                target_format="shared_lib",
                target_os="windows",
                target_arch="x86_64",
                entry_export="omnicompiler_entrypoint"
            )
            self.assertTrue(res["success"])
            self.assertTrue(os.path.exists(out_path))

            # Audit
            with open(out_path, "rb") as f:
                rep = self.auditor.audit_binary(f.read())
            self.assertTrue(rep.is_valid)
            self.assertEqual(rep.format, "PE32+")
            self.assertEqual(rep.machine_arch, "x86-64")
            self.assertEqual(rep.binary_type, "shared_library")

            # Host physical execution on Windows
            if sys.platform == "win32":
                lib = ctypes.WinDLL(out_path)
                fn = getattr(lib, "omnicompiler_entrypoint")
                fn.argtypes = [ctypes.c_int64]
                fn.restype = ctypes.c_int64
                self.assertEqual(fn(10), 175)
                h = lib._handle
                del fn
                del lib
                ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(h))

    def test_02_cross_target_windows_x86_64_executable(self):
        """Cross-target build: Windows x86-64 PE32+ Standalone Executable."""
        with tempfile.TemporaryDirectory() as td:
            out_path = os.path.join(td, "test_app.exe")
            res = self.compiler.compile_repositories(
                repo_paths=self.repo_paths,
                output_path=out_path,
                target_format="executable",
                target_os="windows",
                target_arch="x86_64",
                entry_export="omnicompiler_entrypoint"
            )
            self.assertTrue(res["success"])
            self.assertTrue(os.path.exists(out_path))

            with open(out_path, "rb") as f:
                rep = self.auditor.audit_binary(f.read())
            self.assertTrue(rep.is_valid)
            self.assertEqual(rep.format, "PE32+")
            self.assertEqual(rep.machine_arch, "x86-64")
            self.assertEqual(rep.binary_type, "executable")

            # Host bare-metal execution on Windows
            if sys.platform == "win32":
                cp = subprocess.run([out_path, "10"], capture_output=True, timeout=5)
                self.assertEqual(cp.returncode, 175)

    def test_03_cross_target_linux_x86_64_executable(self):
        """Cross-target build: Linux x86-64 ELF64 Standalone Executable."""
        with tempfile.TemporaryDirectory() as td:
            out_path = os.path.join(td, "test_app_elf")
            res = self.compiler.compile_repositories(
                repo_paths=self.repo_paths,
                output_path=out_path,
                target_format="executable",
                target_os="linux",
                target_arch="x86_64",
                entry_export="omnicompiler_entrypoint"
            )
            self.assertTrue(res["success"])
            self.assertTrue(os.path.exists(out_path))

            with open(out_path, "rb") as f:
                data = f.read()
                rep = self.auditor.audit_binary(data)
            self.assertTrue(rep.is_valid)
            self.assertEqual(rep.format, "ELF64")
            self.assertEqual(rep.machine_arch, "x86-64")
            self.assertEqual(rep.binary_type, "executable")
            self.assertTrue(data.startswith(b"\x7fELF\x02\x01\x01"))

    def test_04_cross_target_linux_x86_64_shared_library(self):
        """Cross-target build: Linux x86-64 ELF64 Shared Library (.so)."""
        with tempfile.TemporaryDirectory() as td:
            out_path = os.path.join(td, "test_lib.so")
            res = self.compiler.compile_repositories(
                repo_paths=self.repo_paths,
                output_path=out_path,
                target_format="shared_lib",
                target_os="linux",
                target_arch="x86_64",
                entry_export="omnicompiler_entrypoint"
            )
            self.assertTrue(res["success"])
            self.assertTrue(os.path.exists(out_path))

            with open(out_path, "rb") as f:
                rep = self.auditor.audit_binary(f.read())
            self.assertTrue(rep.is_valid)
            self.assertEqual(rep.format, "ELF64")
            self.assertEqual(rep.machine_arch, "x86-64")
            self.assertEqual(rep.binary_type, "shared_library")

    def test_05_cross_target_windows_arm64_executable(self):
        """Cross-target build: Windows ARM64 (AArch64) PE32+ Executable."""
        with tempfile.TemporaryDirectory() as td:
            out_path = os.path.join(td, "test_app_arm64.exe")
            res = self.compiler.compile_repositories(
                repo_paths=self.repo_paths,
                output_path=out_path,
                target_format="executable",
                target_os="windows",
                target_arch="arm64",
                entry_export="omnicompiler_entrypoint"
            )
            self.assertTrue(res["success"])
            self.assertTrue(os.path.exists(out_path))

            with open(out_path, "rb") as f:
                rep = self.auditor.audit_binary(f.read())
            self.assertTrue(rep.is_valid)
            self.assertEqual(rep.format, "PE32+")
            self.assertEqual(rep.machine_arch, "ARM64")
            self.assertEqual(rep.binary_type, "executable")

    def test_06_cross_target_linux_arm64_executable(self):
        """Cross-target build: Linux ARM64 (AArch64) ELF64 Executable."""
        with tempfile.TemporaryDirectory() as td:
            out_path = os.path.join(td, "test_app_arm64_elf")
            res = self.compiler.compile_repositories(
                repo_paths=self.repo_paths,
                output_path=out_path,
                target_format="executable",
                target_os="linux",
                target_arch="arm64",
                entry_export="omnicompiler_entrypoint"
            )
            self.assertTrue(res["success"])
            self.assertTrue(os.path.exists(out_path))

            with open(out_path, "rb") as f:
                rep = self.auditor.audit_binary(f.read())
            self.assertTrue(rep.is_valid)
            self.assertEqual(rep.format, "ELF64")
            self.assertEqual(rep.machine_arch, "ARM64")
            self.assertEqual(rep.binary_type, "executable")


if __name__ == "__main__":
    unittest.main()
