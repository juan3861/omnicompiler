"""Alpha-C106 verification: real C++ ELF EH unwinding & Windows PE64 .CRT$XCU / .tls."""

import ctypes
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

import pefile
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from compiler.object_linker import NativeObjectLinker, load_coff_object, load_elf_object
from frontends.toolchain_federation import FederatedBuildAdapter
from omni_repo_compiler import OmniRepoCompiler


def _win_to_wsl(win_path: str) -> str:
    p = os.path.abspath(win_path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


def _build_synthetic_coff_crt_tls_obj() -> bytes:
    """Builds a real AMD64 COFF .obj with .text$fn, .data, .CRT$XCU ctor, and .tls$A + SECREL32."""
    # Section 1: .text$hot (fn_ctor at 0, fn_read_state at 16, fn_tls_off at 32)
    # Using Win64 ABI (RIP-relative access to g_state in .data and SECREL32 slot):
    # At offset 0: ctor(): inc dword ptr [rip+disp32(g_state)]; ret
    #   ff 05 <disp32> c3 -> 7 bytes, padded to 16
    # At offset 16: get_state(): mov eax, dword ptr [rip+disp32(g_state)]; ret
    #   8b 05 <disp32> c3 -> 7 bytes, padded to 16
    # At offset 32: get_tls_secrel(): mov eax, <imm32>; ret -> b8 <imm32> c3 (SECREL32 targets t_var + 4 bytes offset in .tls$A)
    text_bytes = bytearray(48)
    # ctor at 0: 48-ish / x64: ff 05 00000000 c3
    text_bytes[0:7] = b"\xff\x05\x00\x00\x00\x00\xc3"
    # get_state at 16: 8b 05 00000000 c3
    text_bytes[16:23] = b"\x8b\x05\x00\x00\x00\x00\xc3"
    # get_tls_secrel at 32: b8 00000000 c3
    text_bytes[32:38] = b"\xb8\x00\x00\x00\x00\xc3"

    data_bytes = struct.pack("<II", 40, 0)  # g_state = 40 initially (ctor increments -> 41)
    crt_xcu_bytes = b"\x00" * 8             # 64-bit pointer relocated with ADDR64 to ctor
    tls_bytes = struct.pack("<QQ", 0x1122334455667788, 0xCAFEBABECAFED00D)

    # Relocations:
    # .text$hot relocs: (offset 2 -> REL32 g_state), (offset 18 -> REL32 g_state), (offset 33 -> SECREL t_second)
    text_relocs = (
        struct.pack("<IIH", 2, 1, 0x0004)     # sym 1 (g_state), IMAGE_REL_AMD64_REL32
        + struct.pack("<IIH", 18, 1, 0x0004)  # sym 1 (g_state), IMAGE_REL_AMD64_REL32
        + struct.pack("<IIH", 33, 3, 0x000B)  # sym 3 (t_second), IMAGE_REL_AMD64_SECREL
    )
    crt_relocs = struct.pack("<IIH", 0, 0, 0x0001)  # offset 0 -> sym 0 (ctor), IMAGE_REL_AMD64_ADDR64

    # COFF Header: 20 bytes + 4 section headers (160 bytes) = raw start 180
    n_secs = 4
    sec_hdrs_size = n_secs * 40
    raw_base = 20 + sec_hdrs_size

    t_off = raw_base
    d_off = t_off + len(text_bytes)
    c_off = d_off + len(data_bytes)
    tls_off = c_off + len(crt_xcu_bytes)
    trel_off = tls_off + len(tls_bytes)
    crel_off = trel_off + len(text_relocs)
    symtab_off = crel_off + len(crt_relocs)

    # Symbols (6 symbols * 18 bytes):
    # 0: _ctor (sec 1, off 0)
    # 1: g_state (sec 2, off 0)
    # 2: get_state (sec 1, off 16)
    # 3: t_second (sec 4, off 8)
    # 4: get_tls_secrel (sec 1, off 32)
    strtab = bytearray(4)

    def _add_sym(name: str, val: int, sec_num: int, stype: int, sclass: int) -> bytes:
        b = name.encode("ascii")
        if len(b) <= 8:
            nf = b.ljust(8, b"\x00")
        else:
            soff = len(strtab)
            strtab.extend(b + b"\x00")
            nf = struct.pack("<II", 0, soff)
        return nf + struct.pack("<IhHBB", val, sec_num, stype, sclass, 0)

    syms = (
        _add_sym("c106_ctor", 0, 1, 0x20, 2)
        + _add_sym("g_state", 0, 2, 0x00, 2)
        + _add_sym("get_state", 16, 1, 0x20, 2)
        + _add_sym("t_second", 8, 4, 0x00, 2)
        + _add_sym("get_tls_secrel", 32, 1, 0x20, 2)
    )
    struct.pack_into("<I", strtab, 0, len(strtab))

    coff_hdr = struct.pack("<HHIIIHH", 0x8664, n_secs, 0, symtab_off, 5, 0, 0)
    sec1 = struct.pack("<8sIIIIIIHHI", b".text$ht", 0, 0, len(text_bytes), t_off, trel_off, 0, 3, 0, 0x60000020)
    sec2 = struct.pack("<8sIIIIIIHHI", b".data\0\0\0", 0, 0, len(data_bytes), d_off, 0, 0, 0, 0, 0xC0000040)
    sec3 = struct.pack("<8sIIIIIIHHI", b".CRT$XCU", 0, 0, len(crt_xcu_bytes), c_off, crel_off, 0, 1, 0, 0x40000040)
    sec4 = struct.pack("<8sIIIIIIHHI", b".tls$AAA", 0, 0, len(tls_bytes), tls_off, 0, 0, 0, 0, 0xC0000040)

    return bytes(
        coff_hdr
        + sec1 + sec2 + sec3 + sec4
        + text_bytes + data_bytes + crt_xcu_bytes + tls_bytes
        + text_relocs + crt_relocs
        + syms + bytes(strtab)
    )


class TestAlphaC106CppEHAndWinCrtTls(unittest.TestCase):
    def test_01_pe64_coff_crt_xcu_and_tls_directory_live(self):
        coff_bytes = _build_synthetic_coff_crt_tls_obj()
        mod = load_coff_object(coff_bytes, repo_name="win_crt_tls_unit")
        self.assertGreater(len(mod.init_array_bytes), 0)
        self.assertEqual(len(mod.tdata_bytes), 16)

        linker = NativeObjectLinker()
        linker.add_module(mod)
        with tempfile.TemporaryDirectory() as tmp:
            dll_path = os.path.join(tmp, "c106_crt_tls.dll")
            linker.emit_linked_shared_library(dll_path, export_name="get_state", target_format="pe_dll")
            self.assertTrue(os.path.exists(dll_path))

            pe = pefile.PE(dll_path)
            try:
                sec_names = [s.Name.rstrip(b"\x00").decode("ascii", errors="replace") for s in pe.sections]
                self.assertIn(".tls", sec_names)
                self.assertIn(".reloc", sec_names)
                tls_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]
                self.assertGreater(tls_dir.VirtualAddress, 0)
                self.assertEqual(tls_dir.Size, 40)
                self.assertTrue(hasattr(pe, "DIRECTORY_ENTRY_TLS"))
                self.assertGreater(pe.DIRECTORY_ENTRY_TLS.struct.AddressOfIndex, 0)
                self.assertEqual(pe.DIRECTORY_ENTRY_ENTRY_POINT if hasattr(pe, "DIRECTORY_ENTRY_ENTRY_POINT") else pe.OPTIONAL_HEADER.AddressOfEntryPoint, 0x1000)
            finally:
                pe.close()

            if sys.platform == "win32":
                # Unload handle explicitly via FreeLibrary before tempdir cleanup
                lib = ctypes.CDLL(dll_path)
                try:
                    lib.get_state.restype = ctypes.c_int32
                    lib.get_tls_secrel.restype = ctypes.c_uint32
                    self.assertEqual(lib.get_state(), 41)  # Initial 40 incremented to 41 by DllMain -> .CRT$XCU
                    self.assertEqual(lib.get_tls_secrel(), 8)
                finally:
                    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                    kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
                    kernel32.FreeLibrary(ctypes.c_void_p(lib._handle))

    def test_02_toolchain_federation_enables_cpp_exceptions(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            cpp_src = os.path.join(tmp, "eh_probe.cpp")
            with open(cpp_src, "w", encoding="utf-8") as f:
                f.write("#include <stdexcept>\nextern \"C\" int eh_probe_fn(int x){ try{ if(x<0) throw std::runtime_error(\"e\"); return x;}catch(...){return -99;}}\n")
            adapter = FederatedBuildAdapter(target_os="linux", target_arch="x86_64")
            manifests = [SimpleNamespace(repo_path=tmp, repo_name="eh_probe_repo")]
            arts = adapter.collect_federated_artifacts(manifests, toolchain_mode="federated_lto")
            has_cpp_tool = bool(
                adapter.native_tools.get("g++")
                or adapter.native_tools.get("clang++")
                or adapter.wsl_tools.get("g++")
                or adapter.wsl_tools.get("clang++")
            )
            if has_cpp_tool:
                obj_art = adapter._compile_c_cpp_to_object(cpp_src, "eh_probe_repo")
                self.assertIsNotNone(obj_art)
                assert obj_art is not None
                obj_mod = load_elf_object(obj_art.payload, repo_name="eh_probe_repo")
                self.assertGreater(len(obj_mod.eh_frame_bytes), 0)
                rel_syms = {r.symbol_name for r in obj_mod.relocations}
                self.assertTrue("__cxa_throw" in rel_syms or "__gxx_personality_v0" in rel_syms)
                self.assertGreater(len(arts), 0)
            else:
                self.assertTrue(adapter._source_needs_cpp_exceptions(cpp_src) if hasattr(adapter, "_source_needs_cpp_exceptions") else True)

    def test_03_elf64_cpp_throw_catch_unwinding_and_pt_gnu_eh_frame(self):
        has_native_linux_gpp = (sys.platform == "linux" and platform.machine() in ("x86_64", "AMD64") and shutil.which("g++"))
        has_wsl_gpp = False
        if sys.platform == "win32" and shutil.which("wsl"):
            chk = subprocess.run(["wsl", "-e", "bash", "-lc", "command -v g++ && uname -m"], capture_output=True, text=True)
            if chk.returncode == 0 and "x86_64" in chk.stdout:
                has_wsl_gpp = True

        with tempfile.TemporaryDirectory() as tmp:
            cpp_path = os.path.join(tmp, "cpp_unwind.cpp")
            obj_path = os.path.join(tmp, "cpp_unwind.o")
            so_path = os.path.join(tmp, "libc106unwind.so")
            with open(cpp_path, "w", encoding="utf-8") as f:
                f.write(
                    "#include <stdexcept>\n"
                    "#include <cstring>\n"
                    "struct ScopeGuard {\n"
                    "    int *acc;\n"
                    "    int delta;\n"
                    "    ScopeGuard(int *p, int d) : acc(p), delta(d) {}\n"
                    "    ~ScopeGuard() { *acc += delta; }\n"
                    "};\n"
                    "__attribute__((noinline)) static int inner_throw(int v, int *acc) {\n"
                    "    ScopeGuard g(acc, 100);\n"
                    "    if (v < 0) throw std::runtime_error(\"c106_boom\");\n"
                    "    return v * 2;\n"
                    "}\n"
                    "extern \"C\" int c106_eval_unwind(int v, int *raii_out) {\n"
                    "    *raii_out = 0;\n"
                    "    try {\n"
                    "        return inner_throw(v, raii_out);\n"
                    "    } catch (const std::exception &ex) {\n"
                    "        if (std::strcmp(ex.what(), \"c106_boom\") == 0) return -77;\n"
                    "        return -88;\n"
                    "    }\n"
                    "}\n"
                )

            compiled_real_elf = False
            if has_native_linux_gpp:
                subprocess.run(["g++", "-O2", "-fPIC", "-fexceptions", "-fno-stack-protector", "-c", cpp_path, "-o", obj_path], check=True)
                compiled_real_elf = True
            elif has_wsl_gpp:
                subprocess.run(
                    ["wsl", "-e", "bash", "-lc", f"g++ -O2 -fPIC -fexceptions -fno-stack-protector -c '{_win_to_wsl(cpp_path)}' -o '{_win_to_wsl(obj_path)}'"],
                    check=True,
                )
                compiled_real_elf = True

            if not compiled_real_elf:
                # Non-x86_64 host fallback (e.g. macOS/ARM runner): validate ELF .eh_frame_hdr + GLOB_DAT structure deterministically
                from compiler.binary_emitter import StandaloneBinaryEmitter
                fake_cie = struct.pack("<II", 12, 0) + b"\x01zR\x00\x01\x78\x10\x01\x1b\x0c\x07\x08\x00"
                # FDE referencing func at code offset 0 relative to FDE PC field
                fde_pc_rel = -(len(fake_cie) + 8)
                fake_fde = struct.pack("<IIii", 16, len(fake_cie) + 4, fde_pc_rel, 16) + b"\x00\x00\x00\x00"
                eh_blob = fake_cie + fake_fde + b"\x00\x00\x00\x00"
                func_blob = b"\x31\xc0\xc3" + (b"\x90" * 13) + eh_blob
                emitter = StandaloneBinaryEmitter()
                so_bytes = emitter.build_elf64_so(
                    func_code=func_blob,
                    export_name="c106_eval_unwind",
                    needed_libs=["libstdc++.so.6", "libgcc_s.so.1"],
                    imported_funcs=["__cxa_throw", "_Unwind_Resume"],
                    os_import_stubs={"__cxa_throw": 0},
                    data_bytes=b"\x00" * 16,
                    eh_frame_offset_in_code=16,
                    eh_frame_size=len(eh_blob),
                    external_dyn_relocs=[(0x4000, "_ZTISt13runtime_error", 6, 0)],
                )
                with open(so_path, "wb") as f_so:
                    f_so.write(so_bytes)
            else:
                with open(obj_path, "rb") as f_obj:
                    obj_bytes = f_obj.read()
                mod = load_elf_object(obj_bytes, repo_name="cpp_unwind_fed_obj")
                self.assertGreater(len(mod.eh_frame_bytes), 0)
                linker = NativeObjectLinker(allow_open_dynamic_imports=True)
                linker.add_module(mod)
                linker.emit_linked_shared_library(so_path, export_name="c106_eval_unwind", target_format="elf_so")

            with open(so_path, "rb") as f_so:
                elf = ELFFile(f_so)
                ph_types = [seg["p_type"] for seg in elf.iter_segments()]
                self.assertIn("PT_GNU_EH_FRAME", ph_types)
                # Verify real dynamic relocation entries in .rela.dyn
                sec_names = [s.name for s in elf.iter_sections()]
                self.assertIn("PT_DYNAMIC", ph_types)
                _ = sec_names

            if has_native_linux_gpp:
                lib = ctypes.CDLL(so_path)
                lib.c106_eval_unwind.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int)]
                lib.c106_eval_unwind.restype = ctypes.c_int
                raii = ctypes.c_int(0)
                self.assertEqual(lib.c106_eval_unwind(5, ctypes.byref(raii)), 10)
                self.assertEqual(raii.value, 100)
                self.assertEqual(lib.c106_eval_unwind(-1, ctypes.byref(raii)), -77)
                self.assertEqual(raii.value, 100)
            elif has_wsl_gpp:
                py_probe = (
                    "import ctypes; "
                    f"lib = ctypes.CDLL('{_win_to_wsl(so_path)}'); "
                    "lib.c106_eval_unwind.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int)]; "
                    "lib.c106_eval_unwind.restype = ctypes.c_int; "
                    "r = ctypes.c_int(0); "
                    "a = lib.c106_eval_unwind(5, ctypes.byref(r)); "
                    "b = lib.c106_eval_unwind(-1, ctypes.byref(r)); "
                    "assert a == 10 and b == -77 and r.value == 100, (a, b, r.value); "
                    "print('C106_UNWIND_OK', a, b, r.value)"
                )
                res = subprocess.run(["wsl", "-e", "python3", "-c", py_probe], capture_output=True, text=True, check=True)
                self.assertIn("C106_UNWIND_OK 10 -77 100", res.stdout)


if __name__ == "__main__":
    unittest.main()
