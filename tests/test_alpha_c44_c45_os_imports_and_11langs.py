import _ctypes
import ctypes
import io
import os
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.binary_emitter import StandaloneBinaryEmitter
from frontends.polyglot_ssa_lowering import SUPPORTED_POLYGLOT_EXTENSIONS, lower_polyglot_source_to_ast
from omni_repo_compiler import OmniRepoCompiler


def _unload_cdll(lib: ctypes.CDLL) -> None:
    handle = getattr(lib, "_handle", None)
    del lib
    if handle is not None and sys.platform == "win32":
        _ctypes.FreeLibrary(handle)


class TestAlphaC44C45OsImportsAnd11Langs(unittest.TestCase):
    def test_01_pe64_multi_dll_iat_live_os_execution(self):
        import pefile

        emitter = StandaloneBinaryEmitter()

        def _build_code(iat_map, text_rva):
            # Call MSVCRT.DLL!abs(-42) -> rax=42 -> ecx=42 -> KERNEL32.DLL!ExitProcess(42)
            buf = bytearray()
            buf.extend(b"\x48\x83\xec\x28")  # sub rsp, 40 (shadow space + align)
            buf.extend(b"\xb9" + struct.pack("<i", -42))  # mov ecx, -42
            rip1 = text_rva + len(buf) + 6
            buf.extend(b"\xff\x15" + struct.pack("<i", iat_map[("MSVCRT.DLL", "abs")] - rip1))
            buf.extend(b"\x89\xc1")  # mov ecx, eax
            rip2 = text_rva + len(buf) + 6
            buf.extend(b"\xff\x15" + struct.pack("<i", iat_map[("KERNEL32.DLL", "ExitProcess")] - rip2))
            buf.extend(b"\x48\x83\xc4\x28\xc3")
            return bytes(buf)

        pe_bytes, iat_map = emitter.build_pe64_multi_import_exe(
            {"KERNEL32.DLL": ["ExitProcess"], "MSVCRT.DLL": ["abs"]},
            _build_code,
        )
        pe = pefile.PE(data=pe_bytes)
        imported = {
            entry.dll.decode("ascii").upper(): [imp.name.decode("ascii") for imp in entry.imports if imp.name]
            for entry in pe.DIRECTORY_ENTRY_IMPORT
        }
        pe.close()
        self.assertIn("KERNEL32.DLL", imported)
        self.assertIn("MSVCRT.DLL", imported)
        self.assertIn("ExitProcess", imported["KERNEL32.DLL"])
        self.assertIn("abs", imported["MSVCRT.DLL"])

        if sys.platform == "win32":
            with tempfile.TemporaryDirectory() as tmpdir:
                exe_path = os.path.join(tmpdir, "multi_iat_test.exe")
                with open(exe_path, "wb") as f:
                    f.write(pe_bytes)
                cp = subprocess.run([exe_path], capture_output=True, timeout=10)
                self.assertEqual(cp.returncode, 42, f"Expected MSVCRT!abs(-42)=42 via IAT, got {cp.returncode}")

    def test_02_elf64_dynamic_plt_got_needed_audit(self):
        from elftools.elf.elffile import ELFFile
        from elftools.elf.dynamic import DynamicSegment
        from elftools.elf.relocation import RelocationSection

        emitter = StandaloneBinaryEmitter()
        elf_bytes, got_slots = emitter.build_elf64_dynamic_exe(
            needed_libs=["libc.so.6", "libm.so.6"],
            imported_funcs=["abs", "puts", "sqrt"],
            exit_code=7,
        )
        elf = ELFFile(io.BytesIO(elf_bytes))
        self.assertEqual(elf["e_type"], "ET_EXEC")

        interp_found = False
        needed_found = []
        jmprel_vaddr = None
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_INTERP":
                raw_interp = seg.data().rstrip(b"\x00").decode("ascii")
                self.assertEqual(raw_interp, "/lib64/ld-linux-x86-64.so.2")
                interp_found = True
            elif isinstance(seg, DynamicSegment):
                for tag in seg.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed_found.append(tag.needed)
                    elif tag.entry.d_tag == "DT_JMPREL":
                        jmprel_vaddr = tag.entry.d_val

        self.assertTrue(interp_found)
        self.assertEqual(needed_found, ["libc.so.6", "libm.so.6"])
        self.assertIsNotNone(jmprel_vaddr)
        self.assertEqual(set(got_slots.keys()), {"abs", "puts", "sqrt"})

    def test_03_polyglot_11_languages_fusion_native_and_llvm(self):
        # Verify JavaScript direct parser as 11th extension
        js_res = lower_polyglot_source_to_ast("function js_ping(x) { return x + 1; }", language="javascript", strict=True)
        self.assertEqual(len(js_res.functions), 1)
        self.assertGreaterEqual(len(set(SUPPORTED_POLYGLOT_EXTENSIONS.values())), 10)  # + Python = 11 languages

        files_by_repo = {
            "repo_zig": ("ops.zig", "pub fn zig_fn(x: i64) i64 { return x + 1; }\n"),
            "repo_java": ("Ops.java", "public class Ops {\n    public static long java_fn(long x) { return x * 2; }\n}\n"),
            "repo_cs": ("Ops.cs", "namespace Demo {\npublic class Calc {\n    public static long cs_fn(long x) { return x + 3; }\n}\n}\n"),
            "repo_kt": ("ops.kt", "object KtOps {\n    fun kt_fn(x: Long): Long { return x + 4 }\n}\n"),
            "repo_c": ("ops.c", "#include <stdint.h>\nint64_t c_fn(int64_t x) { return x + 5; }\n"),
            "repo_cpp": ("ops.cpp", "static inline int64_t cpp_fn(int64_t x) { return x + 6; }\n"),
            "repo_rs": ("ops.rs", "pub fn rs_fn(x: i64) -> i64 { return x + 7; }\n"),
            "repo_go": ("ops.go", "func go_fn(x int) int { return x + 8 }\n"),
            "repo_ts": ("ops.ts", "export function ts_fn(x: number): number { return x + 9; }\n"),
            "repo_py": (
                "main.py",
                "def omni10_entry(x: int) -> int:\n"
                "    return (\n"
                "        zig_fn(x) + java_fn(x) + cs_fn(x) + kt_fn(x) + c_fn(x)\n"
                "        + cpp_fn(x) + rs_fn(x) + go_fn(x) + ts_fn(x)\n"
                "    )\n",
            ),
        }

        def _expected(x: int) -> int:
            return (x + 1) + (x * 2) + (x + 3) + (x + 4) + (x + 5) + (x + 6) + (x + 7) + (x + 8) + (x + 9)

        with tempfile.TemporaryDirectory() as tmpdir:
            repos = []
            for rname, (fname, src) in files_by_repo.items():
                rp = os.path.join(tmpdir, rname)
                os.makedirs(rp)
                with open(os.path.join(rp, fname), "w", encoding="utf-8") as f:
                    f.write(src)
                repos.append(rp)

            ext = ".dll" if sys.platform == "win32" else ".so"
            for bk in ("native", "llvm"):
                out_lib = os.path.join(tmpdir, f"omni10_{bk}{ext}")
                comp = OmniRepoCompiler()
                res = comp.compile_repositories(
                    repos, out_lib, target_format="shared_lib",
                    entry_export="omni10_entry", export_all=True,
                    backend=bk, audit_nonce=f"c45-10lang-{bk}",
                )
                self.assertTrue(res["stages"]["formal_audit"]["is_valid"])
                lib = ctypes.CDLL(out_lib)
                try:
                    fn = lib.omni10_entry
                    fn.argtypes = [ctypes.c_int64]
                    fn.restype = ctypes.c_int64
                    for x in (0, 5, 12):
                        self.assertEqual(fn(x), _expected(x), f"Mismatch backend={bk} x={x}")
                finally:
                    _unload_cdll(lib)


if __name__ == "__main__":
    unittest.main()
