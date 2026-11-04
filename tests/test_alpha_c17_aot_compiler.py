"""
OmniCompiler Alpha-C17 Test Suite: Autonomous Ahead-of-Time (AOT) Standalone Binary Compiler
(tests/test_alpha_c17_aot_compiler.py).

Verifies:
1. End-to-end multi-repository AOT compilation with whole-program ThinLTO inter-procedural inlining.
2. AOT compilation pipeline with Loop Auto-Vectorizer (scalar induction loops -> SIMD intrinsics).
3. AOT compilation pipeline with Stack Allocation Promotion (heap lists -> stack alloca).
4. Freestanding native machine code kernels in NativeObjectLinker (omni_list_len, omni_list_get, omni_str_len).
5. Standalone Windows PE32+ executable (.exe) bare-metal subprocess execution.
6. Cross-target standalone Linux ELF64 binary emission and structural audit.
"""

import os
import sys
import tempfile
import subprocess
import unittest

from omni_repo_compiler import OmniRepoCompiler
from compiler.object_linker import NativeObjectLinker, ObjectModule, NATIVE_FREESTANDING_KERNELS_X64
from validation.binary_structure_auditor import BinaryStructureAuditor


class TestAlphaC17AotCompiler(unittest.TestCase):

    def setUp(self):
        self.compiler = OmniRepoCompiler()
        self.auditor = BinaryStructureAuditor()

    def test_01_aot_thin_lto_cross_repo_inlining(self):
        """Verifies multi-repository AOT compilation with whole-program ThinLTO inlining."""
        with tempfile.TemporaryDirectory() as td:
            repo_a = os.path.join(td, "repo_a")
            repo_b = os.path.join(td, "repo_b")
            os.makedirs(repo_a)
            os.makedirs(repo_b)

            with open(os.path.join(repo_a, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("""
[project]
name = "repo_a"
version = "0.1.0"
[tool.omnicompiler.exports]
callee_leaf = { file = "leaf.py", symbol = "callee_leaf" }
""")
            with open(os.path.join(repo_a, "leaf.py"), "w", encoding="utf-8") as f:
                f.write("""
def callee_leaf(x: int) -> int:
    return (x << 2) + 7
""")

            with open(os.path.join(repo_b, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("""
[project]
name = "repo_b"
version = "0.1.0"
[tool.omnicompiler.exports]
caller_main = { file = "main.py", symbol = "caller_main" }
""")
            with open(os.path.join(repo_b, "main.py"), "w", encoding="utf-8") as f:
                f.write("""
def caller_main(x: int) -> int:
    return callee_leaf(x) + 3
""")

            out_bin = os.path.join(td, "test_lto.dll")
            res = self.compiler.compile_repositories(
                repo_paths=[repo_a, repo_b],
                output_path=out_bin,
                target_format="shared_lib",
                target_os="windows" if sys.platform == "win32" else "linux",
                target_arch="x86_64",
                entry_export="caller_main"
            )

            self.assertTrue(res["success"])
            self.assertGreaterEqual(res["stages"]["codegen"]["thin_lto_inlines"], 1)

    def test_02_aot_loop_vectorizer_pipeline(self):
        """Verifies AOT pipeline loop auto-vectorization across repository functions."""
        with tempfile.TemporaryDirectory() as td:
            repo_v = os.path.join(td, "repo_vec")
            os.makedirs(repo_v)

            with open(os.path.join(repo_v, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("""
[project]
name = "repo_vec"
version = "0.1.0"
[tool.omnicompiler.exports]
vector_sum = { file = "vec.py", symbol = "vector_sum" }
""")
            with open(os.path.join(repo_v, "vec.py"), "w", encoding="utf-8") as f:
                f.write("""
def vector_sum(a: list) -> int:
    total = 0
    for i in range(len(a)):
        total += a[i]
    return total
""")

            out_bin = os.path.join(td, "test_vec.dll")
            res = self.compiler.compile_repositories(
                repo_paths=[repo_v],
                output_path=out_bin,
                target_format="shared_lib",
                target_os="windows" if sys.platform == "win32" else "linux",
                target_arch="x86_64",
                entry_export="vector_sum"
            )

            self.assertTrue(res["success"])
            self.assertGreaterEqual(res["stages"]["codegen"]["vectorized_loops"], 1)

    def test_03_aot_stack_promotion_pipeline(self):
        """Verifies AOT pipeline stack promotion of non-escaping lists to alloca frames."""
        with tempfile.TemporaryDirectory() as td:
            repo_s = os.path.join(td, "repo_stack")
            os.makedirs(repo_s)

            with open(os.path.join(repo_s, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("""
[project]
name = "repo_stack"
version = "0.1.0"
[tool.omnicompiler.exports]
local_work = { file = "local.py", symbol = "local_work" }
""")
            with open(os.path.join(repo_s, "local.py"), "w", encoding="utf-8") as f:
                f.write("""
def local_work(x: int) -> int:
    buf = omni_list_new(4)
    buf[0] = x
    buf[1] = x + 10
    return buf[0] + buf[1]
""")

            out_bin = os.path.join(td, "test_stack.dll")
            res = self.compiler.compile_repositories(
                repo_paths=[repo_s],
                output_path=out_bin,
                target_format="shared_lib",
                target_os="windows" if sys.platform == "win32" else "linux",
                target_arch="x86_64",
                entry_export="local_work"
            )

            self.assertTrue(res["success"])
            self.assertGreaterEqual(res["stages"]["codegen"]["promoted_stack_allocs"], 1)

    def test_04_freestanding_collection_kernels_in_linker(self):
        """Verifies NativeObjectLinker resolves collection symbols with freestanding machine code."""
        linker = NativeObjectLinker()
        mod = ObjectModule("test_mod")
        # Dummy code that calls omni_list_len
        # call reloc at offset 1
        dummy_code = bytearray(b"\x48\x8b\x4c\x24\x08\xe8\x00\x00\x00\x00\xc3")
        mod.add_symbol("my_caller", bytes(dummy_code), is_exported=True)
        mod.add_call_relocation(offset_in_text=6, target_symbol="omni_list_len")

        linker.add_module(mod)
        link_res = linker.link(entry_symbol="my_caller")

        self.assertTrue(link_res["success"])
        self.assertIn("omni_list_len", link_res["global_symbols"])

        # Check that omni_list_len code bytes match the freestanding kernel exactly
        kernel_bytes = NATIVE_FREESTANDING_KERNELS_X64["omni_list_len"]
        len_offset = link_res["global_symbols"]["omni_list_len"]
        emitted_slice = link_res["combined_code"][len_offset:len_offset + len(kernel_bytes)]
        self.assertEqual(emitted_slice, kernel_bytes)

    def test_05_bare_metal_pe64_standalone_execution(self):
        """Verifies freestanding Windows PE32+ executable compilation and bare-metal execution."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        modules_dir = os.path.join(base_dir, "compiler_modules")
        repo_paths = [
            os.path.join(modules_dir, d)
            for d in sorted(os.listdir(modules_dir))
            if os.path.isdir(os.path.join(modules_dir, d))
        ]

        with tempfile.TemporaryDirectory() as td:
            out_exe = os.path.join(td, "aot_app.exe")
            res = self.compiler.compile_repositories(
                repo_paths=repo_paths,
                output_path=out_exe,
                target_format="executable",
                target_os="windows",
                target_arch="x86_64",
                entry_export="omnicompiler_entrypoint"
            )
            self.assertTrue(res["success"])
            self.assertTrue(os.path.exists(out_exe))

            # Audit PE32+ executable structure
            with open(out_exe, "rb") as f:
                rep = self.auditor.audit_binary(f.read())
            self.assertTrue(rep.is_valid)
            self.assertEqual(rep.format, "PE32+")
            self.assertEqual(rep.machine_arch, "x86-64")
            self.assertEqual(rep.binary_type, "executable")

            # Bare-metal subprocess execution on Windows host
            if sys.platform == "win32":
                cp = subprocess.run([out_exe, "12"], capture_output=True, timeout=5)
                # omnicompiler_entrypoint(12) = (12 << 4) + 15 = 192 + 15 = 207
                self.assertEqual(cp.returncode, 207)

    def test_06_cross_target_elf64_aot_executable(self):
        """Verifies cross-target Linux ELF64 standalone executable emission and audit."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        modules_dir = os.path.join(base_dir, "compiler_modules")
        repo_paths = [
            os.path.join(modules_dir, d)
            for d in sorted(os.listdir(modules_dir))
            if os.path.isdir(os.path.join(modules_dir, d))
        ]

        with tempfile.TemporaryDirectory() as td:
            out_elf = os.path.join(td, "aot_app_elf")
            res = self.compiler.compile_repositories(
                repo_paths=repo_paths,
                output_path=out_elf,
                target_format="executable",
                target_os="linux",
                target_arch="x86_64",
                entry_export="omnicompiler_entrypoint"
            )
            self.assertTrue(res["success"])
            self.assertTrue(os.path.exists(out_elf))

            with open(out_elf, "rb") as f:
                data = f.read()
                rep = self.auditor.audit_binary(data)

            self.assertTrue(rep.is_valid)
            self.assertEqual(rep.format, "ELF64")
            self.assertEqual(rep.machine_arch, "x86-64")
            self.assertEqual(rep.binary_type, "executable")
            self.assertTrue(data.startswith(b"\x7fELF\x02\x01\x01"))


if __name__ == "__main__":
    unittest.main()
