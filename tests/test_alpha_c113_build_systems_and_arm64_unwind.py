"""Alpha-C113 verification: Meson, Makefile, pkg-config, ARM64 ELF R_AARCH64_PREL32 & Mach-O __eh_frame."""

import ctypes
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

from elftools.elf.elffile import ELFFile

from compiler.binary_emitter import StandaloneBinaryEmitter
from compiler.llvm_backend import LLVMBackend
from compiler.object_linker import NativeObjectLinker, load_elf_object
from frontends.toolchain_federation import FederatedBuildAdapter
from omni_repo_compiler import OmniRepoCompiler


def _win_to_wsl(win_path: str) -> str:
    p = os.path.abspath(win_path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


class TestAlphaC113BuildSystemsAndArm64Unwind(unittest.TestCase):
    def test_01_meson_and_makefile_federation_and_live_execution(self):
        adapter = FederatedBuildAdapter(target_os="linux", target_arch="x86_64")
        has_linux_c = (
            (sys.platform == "linux" and platform.machine() in ("x86_64", "AMD64") and bool(adapter.native_tools.get("g++") or adapter.native_tools.get("clang++")))
            or (sys.platform == "win32" and bool(adapter.wsl_tools.get("g++") or adapter.wsl_tools.get("clang++")))
        )

        # 1. Meson project with subdir() and add_project_arguments
        with tempfile.TemporaryDirectory() as tmp_m:
            os.makedirs(os.path.join(tmp_m, "inc"), exist_ok=True)
            os.makedirs(os.path.join(tmp_m, "sub"), exist_ok=True)
            with open(os.path.join(tmp_m, "inc", "mhdr.hpp"), "w", encoding="utf-8") as f:
                f.write("#pragma once\nextern \"C\" int meson_sub_fn(int x);\n")
            with open(os.path.join(tmp_m, "root_api.cpp"), "w", encoding="utf-8") as f:
                f.write("#include \"mhdr.hpp\"\nextern \"C\" int c113_meson_entry(int x) { return meson_sub_fn(x) + MESON_VAL; }\n")
            with open(os.path.join(tmp_m, "sub", "sub_api.cpp"), "w", encoding="utf-8") as f:
                f.write("extern \"C\" int meson_sub_fn(int x) { return x * 4; }\n")
            with open(os.path.join(tmp_m, "sub", "meson.build"), "w", encoding="utf-8") as f:
                f.write("sub_src = files('sub_api.cpp')\n")
            with open(os.path.join(tmp_m, "meson.build"), "w", encoding="utf-8") as f:
                f.write(
                    "project('c113_meson', 'cpp', default_options : ['cpp_std=c++17'])\n"
                    "inc = include_directories('inc')\n"
                    "add_project_arguments('-DMESON_VAL=13', language : 'cpp')\n"
                    "subdir('sub')\n"
                    "shared_library('c113m', ['root_api.cpp', sub_src], include_directories : inc)\n"
                )
            ok_m, units_m = adapter._collect_meson_units(tmp_m)
            self.assertTrue(ok_m)
            self.assertEqual({os.path.basename(u[0]) for u in units_m}, {"root_api.cpp", "sub_api.cpp"})
            if has_linux_c:
                comp = OmniRepoCompiler()
                try:
                    res = comp.compile_repositories(
                        repo_paths=[tmp_m],
                        output_path=os.path.join(tmp_m, "libc113meson"),
                        target_format="shared_lib",
                        entry_export="c113_meson_entry",
                        target_os="linux",
                        target_arch="x86_64",
                        toolchain_mode="federated_lto",
                        export_all=True,
                        emit_provenance=False,
                    )
                finally:
                    comp.close()
                so_m = res["stages"]["emission"]["artifact_path"]
                if sys.platform == "linux":
                    lib = ctypes.CDLL(so_m)
                    lib.c113_meson_entry.argtypes = [ctypes.c_int]
                    lib.c113_meson_entry.restype = ctypes.c_int
                    self.assertEqual(lib.c113_meson_entry(5), 33)
                else:
                    proc = subprocess.run(
                        ["wsl", "-e", "python3", "-c", f"import ctypes; l=ctypes.CDLL('{_win_to_wsl(so_m)}'); l.c113_meson_entry.argtypes=[ctypes.c_int]; l.c113_meson_entry.restype=ctypes.c_int; v=l.c113_meson_entry(5); assert v==33, v"],
                        capture_output=True, text=True, check=True,
                    )
                    self.assertEqual(proc.returncode, 0)

        # 2. Makefile project with $(wildcard ...) and CFLAGS + LDLIBS
        with tempfile.TemporaryDirectory() as tmp_mk:
            os.makedirs(os.path.join(tmp_mk, "src"), exist_ok=True)
            with open(os.path.join(tmp_mk, "src", "mk_calc.c"), "w", encoding="utf-8") as f:
                f.write("int c113_mk_entry(int x) { return (x * MK_MUL) + 2; }\n")
            with open(os.path.join(tmp_mk, "Makefile"), "w", encoding="utf-8") as f:
                f.write("CFLAGS = -O2 -DMK_MUL=5\nLDLIBS = -lm -lz\nSRCS = $(wildcard src/*.c)\nall:\n\t$(CC) $(CFLAGS) -c $(SRCS)\n")
            ok_mk, units_mk = adapter._collect_makefile_units(tmp_mk)
            self.assertTrue(ok_mk)
            self.assertEqual([os.path.basename(u[0]) for u in units_mk], ["mk_calc.c"])
            self.assertIn("-DMK_MUL=5", units_mk[0][1])
            self.assertIn("m", adapter.discovered_external_libs)
            self.assertIn("z", adapter.discovered_external_libs)

    def test_02_arm64_elf_r_aarch64_prel32_eh_frame_and_pt_gnu_eh_frame(self):
        backend = LLVMBackend(target_triple="aarch64-unknown-linux-gnu")
        ir_text = (
            'target triple = "aarch64-unknown-linux-gnu"\n'
            'define dso_local i32 @a64_helper(i32 %k) #0 {\n'
            '  %r = add i32 %k, 9\n'
            '  ret i32 %r\n'
            '}\n'
            'define dso_local i32 @a64_unwind_entry(i32 %x) #0 {\n'
            '  %slot = alloca i32, align 4\n'
            '  store volatile i32 %x, ptr %slot, align 4\n'
            '  %v = load volatile i32, ptr %slot, align 4\n'
            '  %y = call i32 @a64_helper(i32 %v)\n'
            '  %z = mul i32 %y, 2\n'
            '  ret i32 %z\n'
            '}\n'
            'attributes #0 = { noinline uwtable }\n'
        )
        ll_mod = backend.parse_ir_or_bitcode(ir_text, optimize=True)
        a64_obj_bytes = backend.emit_object(ll_mod)
        mod = load_elf_object(a64_obj_bytes, repo_name="arm64_eh_obj")
        self.assertGreater(len(mod.eh_frame_bytes), 0)
        self.assertTrue(any(r.section == ".eh_frame" for r in mod.relocations))

        lnk = NativeObjectLinker()
        lnk.add_module(mod)
        with tempfile.TemporaryDirectory() as tmp:
            so_a64 = os.path.join(tmp, "libc113_a64.so")
            lnk.emit_linked_shared_library(so_a64, export_name="a64_unwind_entry", target_format="arm64_elf_so")
            with open(so_a64, "rb") as sf:
                elf = ELFFile(sf)
                self.assertEqual(elf["e_machine"], "EM_AARCH64")
                ph_types = [seg["p_type"] for seg in elf.iter_segments()]
                self.assertIn("PT_GNU_EH_FRAME", ph_types)

    def test_03_macho_arm64_dylib_eh_frame_section_emission(self):
        fake_cie = struct.pack("<II", 12, 0) + b"\x01zR\x00\x01\x78\x1e\x01\x1b\x0c\x1f\x00\x00"
        fake_fde = struct.pack("<IIii", 16, len(fake_cie) + 4, -(len(fake_cie) + 8), 16) + b"\x00\x00\x00\x00"
        eh_blob = fake_cie + fake_fde + b"\x00\x00\x00\x00"
        code_body = struct.pack("<II", 0x52800540, 0xD65F03C0) + (b"\x1f\x20\x03\xd5" * 2)  # mov w0, #42; ret (16B)
        emitter = StandaloneBinaryEmitter()
        dylib_bytes = emitter.build_macho64_dylib(
            func_code=code_body + eh_blob,
            export_name="macho_eh_fn",
            arch="arm64",
            eh_frame_offset_in_code=len(code_body),
            eh_frame_size=len(eh_blob),
        )
        # Validate Mach-O header and __TEXT sections (__text + __eh_frame)
        magic, cputype, _sub, ftype, ncmds, _szcmds, _flags, _res = struct.unpack_from("<IIIIIIII", dylib_bytes, 0)
        self.assertEqual(magic, 0xFEEDFACF)
        self.assertEqual(cputype, 0x0100000C)
        self.assertEqual(ftype, 0x6)
        self.assertGreaterEqual(ncmds, 7)
        # First load command at offset 32 is __TEXT LC_SEGMENT_64 (nsects should be 2)
        _cmd, _cmdsz, segname, _vm, _vmsz, _fo, _fs, _mp, _ip, nsects, _sflags = struct.unpack_from("<II16sQQQQIIII", dylib_bytes, 32)
        self.assertEqual(segname.rstrip(b"\x00"), b"__TEXT")
        self.assertEqual(nsects, 2)
        sec1_name = struct.unpack_from("<16s", dylib_bytes, 32 + 72)[0].rstrip(b"\x00")
        sec2_name = struct.unpack_from("<16s", dylib_bytes, 32 + 72 + 80)[0].rstrip(b"\x00")
        self.assertEqual(sec1_name, b"__text")
        self.assertEqual(sec2_name, b"__eh_frame")


if __name__ == "__main__":
    unittest.main()
