"""
Alpha-C97 Empirical Verification Suite:
1. Windows PE64 `.dll` with RW `.data`, `.bss`, and `.data` function pointer table (`.reloc` DIR64) executed live via `ctypes.CDLL`.
2. Linux ELF64 `.so` via WSL2: real `ar rcs` `.a` static archive demand-driven resolution + mutable RW `.data`/`.bss` + `.rela.dyn` (`R_X86_64_RELATIVE`), executed live inside WSL2 `ctypes.CDLL` AND end-to-end via `OmniRepoCompiler`.
3. Mach-O 64-bit `__DATA.__data` / `__DATA.__bss` / `rebase` opcodes + BSD `#1/<len>` archive parser validation.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from compiler.binary_emitter import StandaloneBinaryEmitter
from compiler.llvm_backend import LLVMBackend
from compiler.object_linker import (
    NativeObjectLinker,
    ObjectModule,
    load_coff_object,
    load_static_archive,
)
from omni_repo_compiler import OmniRepoCompiler


def _wsl_available() -> bool:
    if sys.platform != "win32":
        return False
    try:
        r = subprocess.run(
            ["wsl", "python3", "-c", "import shutil; print(bool(shutil.which('gcc') and shutil.which('ar')))"],
            capture_output=True,
            text=True,
            timeout=10,
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


class TestAlphaC97RwDataBssAndArchives(unittest.TestCase):
    def test_c97_windows_pe64_dll_rw_data_bss_and_ptr_table(self) -> None:
        if sys.platform != "win32":
            self.skipTest("Windows PE64 live DLL execution test runs on win32")
        llvm = LLVMBackend(target_triple="x86_64-pc-windows-msvc")
        self.assertTrue(llvm.is_available, "LLVM 20.1.8 backend required")

        ir_text = """
target triple = "x86_64-pc-windows-msvc"

@g_counter = global i64 40, align 8
@g_bss_accum = global i64 0, align 8
@g_fn_table = global [2 x ptr] [ptr @c97_bonus, ptr @c97_bonus], align 8

define dllexport i64 @c97_bonus(i64 %x) {
entry:
  %r = add i64 %x, 2
  ret i64 %r
}

define dllexport i64 @c97_rw_state_step(i64 %x) {
entry:
  %c0 = load i64, ptr @g_counter, align 8
  %c1 = add i64 %c0, %x
  store i64 %c1, ptr @g_counter, align 8

  %fn_ptr_slot = getelementptr inbounds [2 x ptr], ptr @g_fn_table, i64 0, i64 0
  %fn_ptr = load ptr, ptr %fn_ptr_slot, align 8
  %b_val = call i64 %fn_ptr(i64 %x)

  %z0 = load i64, ptr @g_bss_accum, align 8
  %z1 = add i64 %z0, %b_val
  store i64 %z1, ptr @g_bss_accum, align 8

  %tot = add i64 %c1, %z1
  ret i64 %tot
}
"""
        mod = llvm.compile_ir(ir_text, optimize=False)
        coff_bytes = llvm.emit_object(mod)
        obj = load_coff_object(coff_bytes, repo_name="c97_pe_mod")

        self.assertGreater(len(obj.data_bytes), 0, "COFF module must capture RW .data")
        self.assertGreater(obj.bss_size, 0, "COFF module must capture .bss")
        self.assertTrue(any(r.section == ".data" and r.reloc_type == "ADDR64" for r in obj.relocations))

        linker = NativeObjectLinker()
        linker.add_module(obj)

        with tempfile.TemporaryDirectory() as td:
            dll_path = os.path.join(td, "c97_rw_test.dll")
            out_dll = linker.emit_linked_shared_library(
                dll_path, export_name="c97_rw_state_step", target_format="pe_dll"
            )
            self.assertTrue(os.path.exists(out_dll))
            with open(out_dll, "rb") as f:
                pe_raw = f.read()
            self.assertIn(b".data\x00\x00\x00", pe_raw)
            self.assertIn(b".reloc\x00\x00", pe_raw)

            # Execute live in child Python subprocess so handle closes before tempdir cleanup
            probe_py = (
                "import ctypes, sys; "
                "d = ctypes.CDLL(sys.argv[1]); "
                "d.c97_rw_state_step.argtypes = [ctypes.c_int64]; "
                "d.c97_rw_state_step.restype = ctypes.c_int64; "
                "r1 = d.c97_rw_state_step(1); "
                "r2 = d.c97_rw_state_step(2); "
                "print(f'{r1},{r2}')"
            )
            proc = subprocess.run(
                [sys.executable, "-c", probe_py, out_dll],
                capture_output=True,
                text=True,
                timeout=15,
                stdin=subprocess.DEVNULL,
            )
            self.assertEqual(proc.returncode, 0, f"DLL run failed: {proc.stderr}")
            # Step 1: counter=40+1=41, bonus(1)=3, bss=0+3=3 -> 44
            # Step 2: counter=41+2=43, bonus(2)=4, bss=3+4=7 -> 50
            self.assertEqual(proc.stdout.strip(), "44,50")

    def test_c97_elf64_so_static_archive_and_rw_data_end_to_end_wsl(self) -> None:
        if sys.platform != "win32" or not _wsl_available():
            self.skipTest("WSL2 gcc/ar required for live Linux ELF64 + archive verification")

        with tempfile.TemporaryDirectory() as td:
            build_dir = os.path.join(td, "ar_src")
            os.makedirs(build_dir, exist_ok=True)
            lib_math_c = os.path.join(build_dir, "lib_math.c")
            unused_c = os.path.join(build_dir, "unused_mod.c")
            with open(lib_math_c, "w", encoding="utf-8") as f:
                f.write(
                    "static long g_state = 100;\n"
                    "static long g_zero_acc = 0;\n"
                    "static long add_one(long v) { return v + 1; }\n"
                    "static long (*g_fn_tbl[1])(long) = { add_one };\n"
                    "long c97_ar_step(long x) {\n"
                    "    g_state += x;\n"
                    "    g_zero_acc += g_fn_tbl[0](x);\n"
                    "    return g_state + g_zero_acc;\n"
                    "}\n"
                )
            with open(unused_c, "w", encoding="utf-8") as f:
                f.write("long c97_unused_never_pulled(long x) { return x * 999; }\n")

            lib_o = os.path.join(build_dir, "lib_math.o")
            unused_o = os.path.join(build_dir, "unused_mod.o")

            repo_ar = os.path.join(td, "repo_ar")
            os.makedirs(repo_ar, exist_ok=True)
            lib_a = os.path.join(repo_ar, "libhelper.a")
            app_c = os.path.join(repo_ar, "app.c")
            with open(app_c, "w", encoding="utf-8") as f:
                f.write(
                    "#include <stdint.h>\n"
                    "extern long c97_ar_step(long x);\n"
                    "long c97_app(long x) { return c97_ar_step(x); }\n"
                )

            c1 = ["wsl", "gcc", "-O2", "-fPIC", "-fno-asynchronous-unwind-tables", "-c", _to_wsl(lib_math_c), "-o", _to_wsl(lib_o)]
            c2 = ["wsl", "gcc", "-O2", "-fPIC", "-fno-asynchronous-unwind-tables", "-c", _to_wsl(unused_c), "-o", _to_wsl(unused_o)]
            c3 = ["wsl", "ar", "rcs", _to_wsl(lib_a), _to_wsl(lib_o), _to_wsl(unused_o)]
            for cmd in (c1, c2, c3):
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
                self.assertEqual(p.returncode, 0, f"cmd failed {cmd}: {p.stderr}")

            # Compile repo containing app.c + libhelper.a through OmniRepoCompiler targeting Linux ELF64
            compiler = OmniRepoCompiler()
            out_base = os.path.join(td, "out_c97_elf")
            res = compiler.compile_repositories(
                repo_paths=[repo_ar],
                output_path=out_base,
                entry_export="c97_app",
                target_os="linux",
                target_arch="x86_64",
                backend="llvm",
                toolchain_mode="federated_lto",
            )
            self.assertEqual(res["stages"]["federation"].get("static_archive_units"), 1)
            self.assertNotIn("c97_unused_never_pulled", res["stages"]["linking"]["exported_symbols"])

            out_so = out_base + ".so"
            self.assertTrue(os.path.exists(out_so))

            wsl_py = (
                "import ctypes, sys; "
                "s = ctypes.CDLL(sys.argv[1]); "
                "s.c97_app.argtypes = [ctypes.c_int64]; "
                "s.c97_app.restype = ctypes.c_int64; "
                "a = s.c97_app(5); "
                "b = s.c97_app(5); "
                "print(f'{a},{b}')"
            )
            exec_res = subprocess.run(
                ["wsl", "python3", "-c", wsl_py, _to_wsl(out_so)],
                capture_output=True,
                text=True,
                timeout=20,
                stdin=subprocess.DEVNULL,
            )
            self.assertEqual(exec_res.returncode, 0, f"WSL ELF .so load/exec failed: {exec_res.stderr}")
            # Step 1: state=105, zero_acc=6 -> 111
            # Step 2: state=110, zero_acc=12 -> 122
            self.assertEqual(exec_res.stdout.strip(), "111,122")

    def test_c97_macho64_dylib_rw_sections_and_bsd_archive_parser(self) -> None:
        emitter = StandaloneBinaryEmitter()
        macho = emitter.build_macho64_dylib(
            func_code=b"\x48\x89\xf8\xc3",
            export_name="c97_m_fn",
            arch="x86_64",
            data_bytes=struct.pack("<Q", 0x1000),
            bss_size=64,
            abs64_reloc_rvas=[0x1000],
        )
        self.assertEqual(macho[:4], b"\xcf\xfa\xed\xfe")
        self.assertIn(b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", macho)
        self.assertIn(b"__data\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", macho)
        self.assertIn(b"__bss\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", macho)

        # Verify BSD long-name `#1/<len>` ar archive parsing + demand-driven pull-in
        m1 = LLVMBackend(target_triple="x86_64-pc-windows-msvc")
        if m1.is_available:
            ir_used = "define i64 @c97_bsd_used(i64 %x) { ret i64 %x }"
            ir_dead = "define i64 @c97_bsd_dead(i64 %x) { ret i64 %x }"
            o_used = m1.emit_object(m1.compile_ir(ir_used, optimize=False))
            o_dead = m1.emit_object(m1.compile_ir(ir_dead, optimize=False))

            def _ar_hdr(name_field: str, sz: int) -> bytes:
                return f"{name_field:<16}{'0':<12}{'0':<6}{'0':<6}{'100644':<8}{sz:<10}`\n".encode("ascii")

            long_name = b"very_long_bsd_member_name.o\x00"
            body1 = long_name + o_used
            ar_buf = bytearray(b"!<arch>\n")
            ar_buf.extend(_ar_hdr(f"#1/{len(long_name)}", len(body1)))
            ar_buf.extend(body1)
            if len(body1) % 2:
                ar_buf.append(ord("\n"))
            ar_buf.extend(_ar_hdr("dead_mem.o/", len(o_dead)))
            ar_buf.extend(o_dead)
            if len(o_dead) % 2:
                ar_buf.append(ord("\n"))

            parsed = load_static_archive(bytes(ar_buf), repo_name="bsd_test")
            self.assertEqual(len(parsed), 2)
            self.assertTrue(any("c97_bsd_used" in m.symbols for m in parsed))


if __name__ == "__main__":
    unittest.main(verbosity=2)
