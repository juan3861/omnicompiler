"""Alpha-C117 verification: COFF Short-Import .lib (0xFFFF), COMDAT/Weak symbols & ELF DT_GNU_HASH."""

import ctypes
import os
import platform
import struct
import subprocess
import sys
import tempfile
import unittest

import pefile
from elftools.elf.elffile import ELFFile

from compiler.binary_emitter import StandaloneBinaryEmitter
from compiler.llvm_backend import LLVMBackend
from compiler.object_linker import NativeObjectLinker, ObjectModule, SymbolDef, load_coff_object, load_elf_object, load_static_archive
from frontends.toolchain_federation import ToolchainRegistry


def _to_wsl(win_path: str) -> str:
    p = os.path.abspath(win_path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


class TestAlphaC117CoffImplibComdatGnuHash(unittest.TestCase):
    def test_01_pe_coff_short_import_lib_inter_dll_execution(self) -> None:
        # Build provider DLL exporting c117_provider_mul(rcx) -> rcx * 7 + 3
        # imul eax, ecx, 7 (6b c1 07); add eax, 3 (83 c0 03); ret (c3)
        prov_code = b"\x6b\xc1\x07\x83\xc0\x03\xc3"
        prov_mod = ObjectModule("c117_provider")
        prov_mod.add_symbol("c117_provider_mul", prov_code, is_exported=True)

        prov_linker = NativeObjectLinker(target_os="windows")
        prov_linker.add_module(prov_mod)

        with tempfile.TemporaryDirectory() as tmp:
            prov_dll = os.path.join(tmp, "c117_prov.dll")
            prov_lib = os.path.join(tmp, "c117_prov.lib")
            prov_linker.emit_linked_shared_library(prov_dll, export_name="c117_provider_mul", target_format="pe_dll")
            self.assertTrue(os.path.isfile(prov_dll))
            self.assertTrue(os.path.isfile(prov_lib))

            with open(prov_lib, "rb") as lf:
                lib_bytes = lf.read()
            self.assertTrue(lib_bytes.startswith(b"!<arch>\n"))
            parsed_members = load_static_archive(lib_bytes, repo_name="c117_prov_lib")
            self.assertTrue(any(m.import_lib_hints.get("c117_provider_mul") == "c117_prov.dll" for m in parsed_members))

            # Build consumer DLL using strict NativeObjectLinker(allow_open_dynamic_imports=False)
            # + c117_prov.lib Short-Import archive
            # sub rsp, 0x28; call c117_provider_mul; add rsp, 0x28; ret
            cons_code = b"\x48\x83\xec\x28\xe8\x00\x00\x00\x00\x48\x83\xc4\x28\xc3"
            cons_mod = ObjectModule("c117_consumer")
            cons_mod.add_symbol("c117_call_prov", cons_code, is_exported=True)
            cons_mod.add_call_relocation(5, "c117_provider_mul", "REL32")

            cons_linker = NativeObjectLinker(target_os="windows", allow_open_dynamic_imports=False)
            cons_linker.add_module(cons_mod)
            cons_linker.add_static_archive(lib_bytes, repo_name="c117_prov_lib")
            cons_dll = os.path.join(tmp, "c117_cons.dll")
            cons_linker.emit_linked_shared_library(cons_dll, export_name="c117_call_prov", target_format="pe_dll")

            pe = pefile.PE(cons_dll)
            try:
                imp_dlls = {e.dll.decode("ascii").lower() for e in pe.DIRECTORY_ENTRY_IMPORT}
                self.assertIn("c117_prov.dll", imp_dlls)
                imp_syms = {s.name.decode("ascii") for e in pe.DIRECTORY_ENTRY_IMPORT for s in e.imports if s.name}
                self.assertIn("c117_provider_mul", imp_syms)
            finally:
                pe.close()

            if sys.platform == "win32":
                dll_dir_cookie = os.add_dll_directory(tmp)
                try:
                    lib = ctypes.CDLL(cons_dll)
                    try:
                        lib.c117_call_prov.argtypes = [ctypes.c_int32]
                        lib.c117_call_prov.restype = ctypes.c_int32
                        self.assertEqual(lib.c117_call_prov(6), 45)
                    finally:
                        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
                        k32.FreeLibrary.argtypes = [ctypes.c_void_p]
                        k32.FreeLibrary(ctypes.c_void_p(lib._handle))
                finally:
                    dll_dir_cookie.close()

    def test_02_comdat_and_weak_symbol_deduplication_coff_and_elf(self) -> None:
        # 1. LLVM ELF weak vs global override + caller redirection from weak module to strong symbol
        lb = LLVMBackend(target_triple="x86_64-unknown-linux-gnu")
        ir_weak = (
            'target triple = "x86_64-unknown-linux-gnu"\n'
            'define weak i32 @c117_shared_tmpl(i32 %x) {\n'
            '  %r = add i32 %x, 1\n'
            '  ret i32 %r\n'
            '}\n'
            'define dso_local i32 @c117_call_from_weak_owner(i32 %v) {\n'
            '  %y = call i32 @c117_shared_tmpl(i32 %v)\n'
            '  ret i32 %y\n'
            '}\n'
        )
        ir_strong = (
            'target triple = "x86_64-unknown-linux-gnu"\n'
            'define dso_local i32 @c117_shared_tmpl(i32 %x) {\n'
            '  %r = add i32 %x, 100\n'
            '  ret i32 %r\n'
            '}\n'
        )
        mod_w = load_elf_object(lb.emit_object(lb.parse_ir_or_bitcode(ir_weak, optimize=False)), repo_name="weak_tu")
        mod_s = load_elf_object(lb.emit_object(lb.parse_ir_or_bitcode(ir_strong, optimize=False)), repo_name="strong_tu")
        self.assertEqual(mod_w.symbols["c117_shared_tmpl"].binding, "weak")
        self.assertEqual(mod_s.symbols["c117_shared_tmpl"].binding, "global")

        # Note: strong comes FIRST; weak MUST NOT overwrite strong
        lnk = NativeObjectLinker(target_os="linux")
        lnk.add_module(mod_s)
        lnk.add_module(mod_w)
        link_res = lnk.link(entry_symbol="c117_call_from_weak_owner")
        self.assertIn("c117_shared_tmpl", link_res["weak_comdat_resolved"])

        # 2. COFF COMDAT SELECT_LARGEST selection (size 10 beats size 3 even when smaller comes later)
        m_small = ObjectModule("comdat_small")
        m_small.symbols["c117_comdat_fn"] = SymbolDef("c117_comdat_fn", ".text", 0, 3, True, "comdat_small", binding="comdat_largest")
        m_small.text_bytes.extend(b"\x89\xc8\xc3")  # mov eax, ecx; ret

        m_large = ObjectModule("comdat_large")
        # mov eax, ecx; add eax, 50; ret (6B)
        m_large.symbols["c117_comdat_fn"] = SymbolDef("c117_comdat_fn", ".text", 0, 6, True, "comdat_large", binding="comdat_largest")
        m_large.text_bytes.extend(b"\x89\xc8\x83\xc0\x32\xc3")

        c_lnk = NativeObjectLinker(target_os="windows")
        c_lnk.add_module(m_large)
        c_lnk.add_module(m_small)
        c_res = c_lnk.link(entry_symbol="c117_comdat_fn")
        self.assertIn("c117_comdat_fn", c_res["weak_comdat_resolved"])
        win_off = c_res["global_symbols"]["c117_comdat_fn"]
        self.assertEqual(c_res["combined_code"][win_off:win_off + 6], b"\x89\xc8\x83\xc0\x32\xc3")

    def test_03_elf64_gnu_hash_soname_runpath_and_dlopen(self) -> None:
        # Three tiny System V AMD64 functions: return x+1, x+2, x+3 (mov eax, edi; add eax, imm8; ret)
        fn_a = b"\x89\xf8\x83\xc0\x01\xc3"
        fn_b = b"\x89\xf8\x83\xc0\x02\xc3"
        fn_c = b"\x89\xf8\x83\xc0\x03\xc3"
        code = fn_a + fn_b + fn_c
        exports = {"c117_alpha": 0, "c117_beta": len(fn_a), "c117_gamma": len(fn_a) + len(fn_b)}

        emitter = StandaloneBinaryEmitter()
        so_bytes = emitter.build_elf64_so(
            func_code=code,
            export_name="c117_alpha",
            extra_exports=exports,
            arch="x86_64",
            soname="libomni_c117.so",
            runpath="$ORIGIN/lib",
        )
        with tempfile.TemporaryDirectory() as tmp:
            so_path = os.path.join(tmp, "libomni_c117.so")
            with open(so_path, "wb") as f:
                f.write(so_bytes)

            with open(so_path, "rb") as rf:
                elf = ELFFile(rf)
                tags = {}
                soname_s = None
                runpath_s = None
                for seg in elf.iter_segments():
                    if seg["p_type"] == "PT_DYNAMIC":
                        for tag in seg.iter_tags():
                            tags[tag.entry.d_tag] = tag.entry.d_val
                            if tag.entry.d_tag == "DT_SONAME":
                                soname_s = getattr(tag, "soname", None)
                            elif tag.entry.d_tag == "DT_RUNPATH":
                                runpath_s = getattr(tag, "runpath", None)
                self.assertIn("DT_GNU_HASH", tags)
                self.assertIn("DT_HASH", tags)
                self.assertEqual(soname_s, "libomni_c117.so")
                self.assertEqual(runpath_s, "$ORIGIN/lib")

            tools = ToolchainRegistry.discover()
            wsl_tools = ToolchainRegistry.discover_wsl() if sys.platform == "win32" else {}
            if sys.platform == "linux" and platform.machine() in ("x86_64", "AMD64"):
                lib = ctypes.CDLL(so_path)
                for fn_name, delta in (("c117_alpha", 1), ("c117_beta", 2), ("c117_gamma", 3)):
                    fn = getattr(lib, fn_name)
                    fn.argtypes = [ctypes.c_int32]
                    fn.restype = ctypes.c_int32
                    self.assertEqual(fn(40), 40 + delta)
            elif sys.platform == "win32" and wsl_tools.get("wsl"):
                py_cmd = (
                    f"import ctypes; l=ctypes.CDLL('{_to_wsl(so_path)}'); "
                    "res=[getattr(l, n)(40) for n in ('c117_alpha','c117_beta','c117_gamma')]; "
                    "assert res == [41, 42, 43], res"
                )
                subprocess.run(["wsl", "-e", "python3", "-c", py_cmd], check=True)


if __name__ == "__main__":
    unittest.main()
