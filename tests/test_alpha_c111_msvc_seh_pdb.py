"""Alpha-C111 verification: Windows MSVC COFF .pdata/.xdata SEH (FH3), ADDR32NB & RSDS PDB."""

import ctypes
import os
import struct
import sys
import tempfile
import unittest

import pefile

from compiler.object_linker import NativeObjectLinker, load_coff_object


def _build_coff_msvc_seh_obj() -> bytes:
    """
    Builds a real AMD64 COFF `.obj` with `.text` (`seh_eval` + `__CxxFrameHandler3` call stub site),
    `.pdata` (`RUNTIME_FUNCTION` with `IMAGE_REL_AMD64_ADDR32NB` 0x0003 relocs),
    and `.xdata` (`UNWIND_INFO` with `UNW_FLAG_EHANDLER` + handler RVA relocated to `__CxxFrameHandler3`).
    """
    # sub rsp, 0x28; lea eax, [rcx + 11]; add rsp, 0x28; ret (12 bytes)
    # Followed by call rel32 __CxxFrameHandler3 unreachable tail (6 bytes, pulls external import)
    # Wait: keep seh_eval clean at 0..12, and unreachable guard thunk calling __CxxFrameHandler3 at 16..22
    text_bytes = bytearray(32)
    # seh_eval (0..12): sub rsp, 0x28; lea eax, [rcx+11]; add rsp, 0x28; ret
    text_bytes[0:12] = b"\x48\x83\xec\x28\x8d\x41\x0b\x48\x83\xc4\x28\xc3"
    # pad 12..16
    text_bytes[12:16] = b"\x90\x90\x90\x90"
    # helper calling __CxxFrameHandler3 (16..22): jmp rel32 __CxxFrameHandler3
    text_bytes[16:21] = b"\xe9\x00\x00\x00\x00"

    # .pdata: 12-byte RUNTIME_FUNCTION (BeginAddress, EndAddress=Begin+12, UnwindData)
    pdata_bytes = struct.pack("<III", 0, 12, 0)
    # .xdata: UNWIND_INFO v1 | UNW_FLAG_EHANDLER (0x09), prolog=4, count=1 (UWOP_ALLOC_SMALL 0x28 -> 1 code word),
    # 1 code word = (4 | 0x4200), + 2B align pad to 4B = total 8 bytes header, then Handler RVA (4B at off 8), LSDA (4B)
    xdata_bytes = struct.pack("<BBHHI", 0x09, 4, 0x01, 0x4204, 0)[:8] + struct.pack("<II", 0, 0xCAFE1111)

    # Relocations:
    # .text: offset 17 -> sym 1 (__CxxFrameHandler3) REL32
    text_relocs = struct.pack("<IIH", 17, 1, 0x0004)
    # .pdata:
    #   offset 0 -> sym 0 (seh_eval) ADDR32NB (0x0003)
    #   offset 4 -> sym 0 (seh_eval) ADDR32NB (0x0003, addend=12 already packed!)
    #   offset 8 -> sym 2 (.xdata) ADDR32NB (0x0003)
    pdata_relocs = (
        struct.pack("<IIH", 0, 0, 0x0003)
        + struct.pack("<IIH", 4, 0, 0x0003)
        + struct.pack("<IIH", 8, 2, 0x0003)
    )
    # .xdata: offset 8 -> sym 1 (__CxxFrameHandler3) ADDR32NB (0x0003)
    xdata_relocs = struct.pack("<IIH", 8, 1, 0x0003)

    n_secs = 3
    raw_base = 20 + n_secs * 40
    t_off = raw_base
    p_off = t_off + len(text_bytes)
    x_off = p_off + len(pdata_bytes)
    trel_off = x_off + len(xdata_bytes)
    prel_off = trel_off + len(text_relocs)
    xrel_off = prel_off + len(pdata_relocs)
    symtab_off = xrel_off + len(xdata_relocs)

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

    # 0: seh_eval (sec 1, val 0)
    # 1: __CxxFrameHandler3 (sec 0 external)
    # 2: unwind_seh_eval (sec 3 .xdata, val 0)
    syms = (
        _add_sym("seh_eval", 0, 1, 0x20, 2)
        + _add_sym("__CxxFrameHandler3", 0, 0, 0x20, 2)
        + _add_sym("unwind_seh_eval", 0, 3, 0x00, 3)
    )
    struct.pack_into("<I", strtab, 0, len(strtab))

    coff_hdr = struct.pack("<HHIIIHH", 0x8664, n_secs, 0, symtab_off, 3, 0, 0)
    sec1 = struct.pack("<8sIIIIIIHHI", b".text\0\0\0", 0, 0, len(text_bytes), t_off, trel_off, 0, 1, 0, 0x60000020)
    sec2 = struct.pack("<8sIIIIIIHHI", b".pdata\0\0", 0, 0, len(pdata_bytes), p_off, prel_off, 0, 3, 0, 0x40000040)
    sec3 = struct.pack("<8sIIIIIIHHI", b".xdata\0\0", 0, 0, len(xdata_bytes), x_off, xrel_off, 0, 1, 0, 0x40000040)

    return bytes(
        coff_hdr + sec1 + sec2 + sec3
        + text_bytes + pdata_bytes + xdata_bytes
        + text_relocs + pdata_relocs + xdata_relocs
        + syms + bytes(strtab)
    )


class TestAlphaC111MsvcSehAndPdb(unittest.TestCase):
    def test_01_coff_pdata_xdata_addr32nb_vcruntime_and_msf_pdb(self):
        coff = _build_coff_msvc_seh_obj()
        mod = load_coff_object(coff, repo_name="msvc_seh_obj")
        self.assertEqual(len(mod.coff_pdata_bytes), 12)
        self.assertEqual(len(mod.coff_xdata_bytes), 16)
        self.assertTrue(any(r.reloc_type == "COFF_ADDR32NB" for r in mod.relocations))

        linker = NativeObjectLinker()
        linker.add_module(mod)
        with tempfile.TemporaryDirectory() as tmp:
            dll_path = os.path.join(tmp, "c111_msvc_seh.dll")
            pdb_path = os.path.join(tmp, "c111_msvc_seh.pdb")
            linker.emit_linked_shared_library(dll_path, export_name="seh_eval", target_format="pe_dll")

            self.assertTrue(os.path.exists(dll_path))
            self.assertTrue(os.path.exists(pdb_path))

            pe = pefile.PE(dll_path)
            try:
                # Verify .pdata RUNTIME_FUNCTION & .xdata EHANDLER RVA resolution via ADDR32NB
                self.assertTrue(hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION"))
                rf_entry = pe.DIRECTORY_ENTRY_EXCEPTION[0].struct
                self.assertEqual(rf_entry.BeginAddress, 0x1010)
                self.assertEqual(rf_entry.EndAddress, 0x101C)
                u_rva = getattr(rf_entry, "UnwindData", getattr(rf_entry, "UnwindInfoAddressRVA", 0))
                self.assertGreater(u_rva, rf_entry.EndAddress)

                # Verify __CxxFrameHandler3 imported from VCRUNTIME140.dll
                imp_dlls = {e.dll.decode("ascii") for e in pe.DIRECTORY_ENTRY_IMPORT}
                self.assertIn("VCRUNTIME140.dll", imp_dlls)
                imp_syms = {s.name.decode("ascii") for e in pe.DIRECTORY_ENTRY_IMPORT for s in e.imports if s.name}
                self.assertIn("__CxxFrameHandler3", imp_syms)

                # Verify RSDS CodeView Debug Directory matches MSF 7.0 .pdb GUID
                self.assertTrue(hasattr(pe, "DIRECTORY_ENTRY_DEBUG"))
                dbg = pe.DIRECTORY_ENTRY_DEBUG[0]
                self.assertEqual(dbg.struct.Type, 2)  # IMAGE_DEBUG_TYPE_CODEVIEW
                rsds_off = dbg.struct.PointerToRawData
                raw_dll = pe.__data__
                self.assertEqual(raw_dll[rsds_off:rsds_off + 4], b"RSDS")
                pe_guid = raw_dll[rsds_off + 4:rsds_off + 20]
            finally:
                pe.close()

            with open(pdb_path, "rb") as pf:
                pdb_bytes = pf.read()
            self.assertTrue(pdb_bytes.startswith(b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"))
            self.assertEqual(len(pdb_bytes) % 4096, 0)
            self.assertIn(pe_guid, pdb_bytes)

            if sys.platform == "win32":
                lib = ctypes.CDLL(dll_path)
                try:
                    lib.seh_eval.argtypes = [ctypes.c_int32]
                    lib.seh_eval.restype = ctypes.c_int32
                    self.assertEqual(lib.seh_eval(31), 42)
                finally:
                    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                    kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
                    kernel32.FreeLibrary(ctypes.c_void_p(lib._handle))

    def test_02_llvmlite_msvc_coff_unwind_emission_and_linking(self):
        from compiler.llvm_backend import LLVMBackend
        try:
            backend = LLVMBackend(target_triple="x86_64-pc-windows-msvc")
        except Exception:
            self.fail("Expected LLVM backend for x86_64-pc-windows-msvc")

        if not backend.is_available:
            self.fail("LLVM backend must be available")

        ir_text = (
            'target triple = "x86_64-pc-windows-msvc"\n'
            'define dso_local i32 @msvc_leaf_step(i32 %a) #0 {\n'
            '  %r = mul i32 %a, 3\n'
            '  ret i32 %r\n'
            '}\n'
            'define dllexport i32 @msvc_frame_add(i32 %x) #0 {\n'
            'entry:\n'
            '  %buf = alloca i32, align 4\n'
            '  store volatile i32 %x, ptr %buf, align 4\n'
            '  %v = load volatile i32, ptr %buf, align 4\n'
            '  %y = call i32 @msvc_leaf_step(i32 %v)\n'
            '  %z = add i32 %y, 100\n'
            '  ret i32 %z\n'
            '}\n'
            'attributes #0 = { noinline uwtable }\n'
        )
        ll_mod = backend.parse_ir_or_bitcode(ir_text, optimize=True)
        coff_obj_bytes = backend.emit_object(ll_mod)
        mod = load_coff_object(coff_obj_bytes, repo_name="llvm_msvc_coff")
        self.assertIn("msvc_frame_add", mod.symbols)
        # Non-leaf Win64 frame produces .pdata + .xdata in COFF object
        self.assertGreater(len(mod.coff_pdata_bytes), 0)
        self.assertGreater(len(mod.coff_xdata_bytes), 0)

        lnk = NativeObjectLinker()
        lnk.add_module(mod)
        with tempfile.TemporaryDirectory() as tmp:
            dll_p = lnk.emit_linked_shared_library(
                os.path.join(tmp, "c111_llvm_msvc.dll"),
                export_name="msvc_frame_add",
                target_format="pe_dll",
            )
            pe = pefile.PE(dll_p)
            try:
                self.assertTrue(hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION"))
                self.assertTrue(hasattr(pe, "DIRECTORY_ENTRY_DEBUG"))
            finally:
                pe.close()
            if sys.platform == "win32":
                lib = ctypes.CDLL(dll_p)
                try:
                    lib.msvc_frame_add.argtypes = [ctypes.c_int32]
                    lib.msvc_frame_add.restype = ctypes.c_int32
                    self.assertEqual(lib.msvc_frame_add(7), 121)
                finally:
                    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                    kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
                    kernel32.FreeLibrary(ctypes.c_void_p(lib._handle))


if __name__ == "__main__":
    unittest.main()
