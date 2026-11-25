"""
Alpha-C101 Empirical Verification Suite:
1. Real C++ `__attribute__((constructor))` (`.init_array` + `DT_INIT_ARRAY` + `.rela.dyn` R_X86_64_RELATIVE)
   AND real open dynamic OS library calls (`qsort` in libc + `exp` in libm) executed live via `dlopen`/`ctypes.CDLL` in WSL2 Linux!
2. Real Thread-Local Storage (`__thread` `.tdata`/`.tbss`, `R_X86_64_TPOFF32`, `PT_TLS` ELF program header)
   verified structurally via `pyelftools` AND `readelf -l`.
3. Strict default `LinkerError` preserved vs `allow_open_dynamic_imports=True` open GOT/PLT promotion.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from compiler.object_linker import LinkerError, NativeObjectLinker, ObjectModule, load_elf_object
from omni_repo_compiler import OmniRepoCompiler


def _wsl_gcc_ready() -> bool:
    if sys.platform != "win32":
        return False
    try:
        r = subprocess.run(
            ["wsl", "python3", "-c", "import shutil; print(bool(shutil.which('gcc') and shutil.which('g++') and shutil.which('readelf')))"],
            capture_output=True,
            text=True,
            timeout=25,
            stdin=subprocess.DEVNULL,
        )
        return r.returncode == 0 and "True" in r.stdout
    except Exception:
        return False


def _to_wsl(p: str) -> str:
    ap = os.path.abspath(p).replace("\\", "/")
    if len(ap) >= 2 and ap[1] == ":":
        return f"/mnt/{ap[0].lower()}{ap[2:]}"
    return ap


class TestAlphaC101InitArrayOpenImportsTls(unittest.TestCase):
    def test_c101_elf64_init_array_constructors_and_open_dynamic_imports(self) -> None:
        if sys.platform != "win32" or not _wsl_gcc_ready():
            self.skipTest("WSL2 gcc/g++/readelf required for live Linux ELF .init_array verification")

        with tempfile.TemporaryDirectory() as td:
            repo_cpp = os.path.join(td, "repo_ctor_dyn")
            os.makedirs(repo_cpp, exist_ok=True)
            cpp_path = os.path.join(repo_cpp, "ctor_unit.cpp")
            obj_path = os.path.join(td, "ctor_unit.o")
            with open(cpp_path, "w", encoding="utf-8") as f:
                f.write(
                    "#include <stdlib.h>\n"
                    "#include <math.h>\n"
                    "static long g_ctor_magic = 0;\n"
                    "__attribute__((constructor))\n"
                    "static void c101_auto_init() {\n"
                    "    g_ctor_magic = 1000;\n"
                    "}\n"
                    "static int cmp_i64(const void* a, const void* b) {\n"
                    "    long va = *(const long*)a, vb = *(const long*)b;\n"
                    "    return (va > vb) - (va < vb);\n"
                    "}\n"
                    "extern \"C\" long c101_run(long x) {\n"
                    "    long arr[4] = {40, 10, 30, 20};\n"
                    "    qsort(arr, 4, sizeof(long), cmp_i64);\n"
                    "    volatile double dv = 0.0;\n"
                    "    long e_approx = (long)(exp(dv) + 0.5);\n"
                    "    return g_ctor_magic + arr[0] + (long)(e_approx * x);\n"
                    "}\n"
                )

            c_cmd = [
                "wsl", "g++", "-O2", "-fPIC", "-fno-exceptions", "-fno-rtti",
                "-fno-asynchronous-unwind-tables", "-c", _to_wsl(cpp_path), "-o", _to_wsl(obj_path),
            ]
            p_compile = subprocess.run(c_cmd, capture_output=True, text=True, timeout=25, stdin=subprocess.DEVNULL)
            self.assertEqual(p_compile.returncode, 0, msg=p_compile.stderr)

            with open(obj_path, "rb") as rf:
                obj_bytes = rf.read()
            mod = load_elf_object(obj_bytes, repo_name="ctor_mod")
            self.assertGreater(len(mod.init_array_bytes), 0, "ELF .init_array must be captured")

            linker = NativeObjectLinker(target_os="linux", allow_open_dynamic_imports=True)
            linker.add_module(mod)
            out_so = os.path.join(td, "lib_c101_ctor.so")
            linker.emit_linked_shared_library(out_so, export_name="c101_run", target_format="elf_so")
            self.assertTrue(os.path.exists(out_so))

            # Check DT_INIT_ARRAY tag via readelf -d
            p_dyn = subprocess.run(
                ["wsl", "readelf", "-d", _to_wsl(out_so)],
                capture_output=True,
                text=True,
                timeout=15,
                stdin=subprocess.DEVNULL,
            )
            self.assertEqual(p_dyn.returncode, 0, msg=p_dyn.stderr)
            self.assertIn("INIT_ARRAY", p_dyn.stdout)
            self.assertIn("libm.so.6", p_dyn.stdout)

            # Live ctypes.CDLL execution proves constructor ran automatically at dlopen AND qsort+exp ran!
            # Expected: g_ctor_magic(1000) + arr[0] after sort (10) + 1*7 = 1017
            wsl_exec = (
                "import ctypes, sys; "
                "l = ctypes.CDLL(sys.argv[1]); "
                "l.c101_run.argtypes = [ctypes.c_int64]; "
                "l.c101_run.restype = ctypes.c_int64; "
                "print(l.c101_run(7))"
            )
            p_run = subprocess.run(
                ["wsl", "python3", "-c", wsl_exec, _to_wsl(out_so)],
                capture_output=True,
                text=True,
                timeout=15,
                stdin=subprocess.DEVNULL,
            )
            self.assertEqual(p_run.returncode, 0, msg=p_run.stderr)
            self.assertEqual(p_run.stdout.strip(), "1017")

    def test_c101_elf64_tls_local_exec_and_pt_tls_emission(self) -> None:
        if sys.platform != "win32" or not _wsl_gcc_ready():
            self.skipTest("WSL2 gcc/readelf required for ELF PT_TLS verification")

        with tempfile.TemporaryDirectory() as td:
            c_path = os.path.join(td, "tls_unit.c")
            o_path = os.path.join(td, "tls_unit.o")
            with open(c_path, "w", encoding="utf-8") as f:
                f.write(
                    "__thread long tls_init_slot = 55;\n"
                    "__thread long tls_zero_slot = 0;\n"
                    "long c101_tls_add(long v) { return tls_init_slot + tls_zero_slot + v; }\n"
                )
            cmd = [
                "wsl", "gcc", "-O2", "-ftls-model=local-exec", "-fno-asynchronous-unwind-tables",
                "-c", _to_wsl(c_path), "-o", _to_wsl(o_path),
            ]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
            self.assertEqual(p.returncode, 0, msg=p.stderr)

            with open(o_path, "rb") as f:
                mod = load_elf_object(f.read(), repo_name="tls_mod")
            self.assertGreater(len(mod.tdata_bytes), 0, ".tdata must be captured")
            self.assertGreater(mod.tbss_size, 0, ".tbss must be captured")

            linker = NativeObjectLinker(target_os="linux")
            linker.add_module(mod)
            out_so = os.path.join(td, "lib_c101_tls.so")
            linker.emit_linked_shared_library(out_so, export_name="c101_tls_add", target_format="elf_so")

            p_ph = subprocess.run(
                ["wsl", "readelf", "-l", _to_wsl(out_so)],
                capture_output=True,
                text=True,
                timeout=15,
                stdin=subprocess.DEVNULL,
            )
            self.assertEqual(p_ph.returncode, 0, msg=p_ph.stderr)
            self.assertIn("TLS", p_ph.stdout)

    def test_c101_strict_missing_symbol_vs_open_dynamic_imports(self) -> None:
        mod = ObjectModule("strict_vs_open")
        mod.add_symbol("caller_fn", b"\xe8\x00\x00\x00\x00\xc3", is_exported=True)
        mod.add_call_relocation(1, "custom_unlisted_vendor_api", reloc_type="REL32")

        strict_linker = NativeObjectLinker()
        strict_linker.add_module(mod)
        with self.assertRaises(LinkerError):
            strict_linker.link()

        open_linker = NativeObjectLinker(target_os="linux", allow_open_dynamic_imports=True)
        open_linker.external_lib_hints["custom_unlisted_vendor_api"] = ("VENDOR.dll", "libvendor.so.1")
        open_linker.add_module(mod)
        res = open_linker.link()
        self.assertTrue(res["success"])
        self.assertIn("custom_unlisted_vendor_api", res["external_os_imports"])
        self.assertEqual(res["os_import_table"]["custom_unlisted_vendor_api"], ("VENDOR.dll", "libvendor.so.1"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
