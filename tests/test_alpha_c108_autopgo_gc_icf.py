"""Alpha-C108 verification: Closed-loop Auto-PGO, --gc-sections BFS elimination, and Linker ICF."""

import ctypes
import json
import os
import platform
import struct
import sys
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

import omnicc_cli
from compiler.object_linker import NativeObjectLinker, ObjectModule, RelocationEntry
from omni_repo_compiler import OmniRepoCompiler


def _is_arm64() -> bool:
    return platform.machine().lower() in ("arm64", "aarch64")


def _unload_cdll(lib: ctypes.CDLL) -> None:
    if sys.platform == "win32":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
        kernel32.FreeLibrary(ctypes.c_void_p(lib._handle))


def _ret_add7_stub() -> bytes:
    if _is_arm64():
        # add w0, w0, #7; ret
        return struct.pack("<II", 0x11001C00, 0xD65F03C0)
    # x86-64 System V (edi) & Win64 (ecx): detect platform
    if sys.platform == "win32":
        # lea eax, [rcx+7]; ret -> 8d 41 07 c3
        return b"\x8d\x41\x07\xc3"
    # SysV: lea eax, [rdi+7]; ret -> 8d 47 07 c3
    return b"\x8d\x47\x07\xc3"


class TestAlphaC108AutoPgoGcIcf(unittest.TestCase):
    def test_01_gc_sections_eliminates_unreachable_modules_and_unused_imports(self):
        ret7 = _ret_add7_stub()
        if _is_arm64():
            # bl live_helper (4) + ret (4)
            entry_code = struct.pack("<II", 0x94000000, 0xD65F03C0)
            entry_rel = RelocationEntry(section=".text", offset=0, symbol_name="live_helper", reloc_type="ARM64_CALL26")
            dead_code = struct.pack("<II", 0x94000000, 0xD65F03C0) + (b"\x1f\x20\x03\xd5" * 1024)
            dead_rel = RelocationEntry(section=".text", offset=0, symbol_name="never_called_os_api", reloc_type="ARM64_CALL26")
        else:
            # jmp rel32 live_helper (tail call keeps single ret in helper)
            entry_code = b"\xe9\x00\x00\x00\x00\xc3"
            entry_rel = RelocationEntry(section=".text", offset=1, symbol_name="live_helper", reloc_type="REL32")
            dead_code = b"\xe8\x00\x00\x00\x00\xc3" + (b"\x90" * 4096)
            dead_rel = RelocationEntry(section=".text", offset=1, symbol_name="never_called_os_api", reloc_type="REL32")

        m_entry = ObjectModule("m_entry")
        m_entry.add_symbol("live_entry", entry_code, is_exported=True)
        m_entry.relocations.append(entry_rel)

        m_helper = ObjectModule("m_helper")
        m_helper.add_symbol("live_helper", ret7, is_exported=False)

        m_dead = ObjectModule("m_dead")
        m_dead.add_symbol("dead_orphan", dead_code, is_exported=False)
        m_dead.relocations.append(dead_rel)

        # Baseline without GC
        lnk_no_gc = NativeObjectLinker(allow_open_dynamic_imports=True, gc_sections=False)
        for m in (m_entry, m_helper, m_dead):
            lnk_no_gc.add_module(m)
        res_no_gc = lnk_no_gc.link(entry_symbol="live_entry")
        self.assertIn("dead_orphan", res_no_gc["global_symbols"])
        self.assertIn("never_called_os_api", res_no_gc["external_os_imports"])
        self.assertGreater(res_no_gc["total_text_size"], 4096)

        # With --gc-sections
        lnk_gc = NativeObjectLinker(allow_open_dynamic_imports=True, gc_sections=True)
        for m in (m_entry, m_helper, m_dead):
            lnk_gc.add_module(m)
        res_gc = lnk_gc.link(entry_symbol="live_entry")
        self.assertTrue(res_gc["gc_sections_applied"])
        self.assertEqual(res_gc["gc_eliminated_modules"], 1)
        self.assertGreaterEqual(res_gc["gc_bytes_reclaimed"], 4096)
        self.assertNotIn("dead_orphan", res_gc["global_symbols"])
        self.assertNotIn("never_called_os_api", res_gc["external_os_imports"])
        self.assertLess(res_gc["total_text_size"], 256)

        with tempfile.TemporaryDirectory() as tmp:
            lib_path = lnk_gc.emit_linked_shared_library(
                os.path.join(tmp, "c108_gc"),
                export_name="live_entry",
            )
            lib = ctypes.CDLL(lib_path)
            try:
                lib.live_entry.argtypes = [ctypes.c_int]
                lib.live_entry.restype = ctypes.c_int
                self.assertEqual(lib.live_entry(15), 22)
            finally:
                _unload_cdll(lib)

    def test_02_linker_icf_folds_identical_modules_and_preserves_exports(self):
        # Two separate identical compute_hash helpers (64+ bytes) with different exported names
        if _is_arm64():
            fn_bytes = struct.pack("<IIII", 0x11001C00, 0x11000800, 0x11000C00, 0xD65F03C0)  # x + 7 + 2 + 3 = x + 12
        else:
            # Windows (rcx) & Linux (rdi) neutral enough: mov eax, 100; add eax, 23; ret padded to 64B
            fn_bytes = b"\xb8\x64\x00\x00\x00\x83\xc0\x17\xc3" + (b"\x90" * 55)

        mod_a = ObjectModule("icf_a")
        mod_a.add_symbol("fn_alpha", fn_bytes, is_exported=True)

        mod_b = ObjectModule("icf_b")
        mod_b.add_symbol("fn_beta", fn_bytes, is_exported=True)

        lnk_no = NativeObjectLinker(icf_folding=False)
        lnk_no.add_module(mod_a)
        lnk_no.add_module(mod_b)
        res_no = lnk_no.link()

        lnk_icf = NativeObjectLinker(icf_folding=True)
        lnk_icf.add_module(mod_a)
        lnk_icf.add_module(mod_b)
        res_icf = lnk_icf.link()

        self.assertTrue(res_icf["icf_folding_applied"])
        self.assertEqual(res_icf["icf_folded_modules"], 1)
        self.assertEqual(res_icf["icf_bytes_saved"], len(fn_bytes))
        self.assertEqual(res_icf["global_symbols"]["fn_alpha"], res_icf["global_symbols"]["fn_beta"])
        self.assertLess(res_icf["total_text_size"], res_no["total_text_size"])

        with tempfile.TemporaryDirectory() as tmp:
            lib_path = lnk_icf.emit_linked_shared_library(
                os.path.join(tmp, "c108_icf"),
                export_name="fn_alpha",
            )
            lib = ctypes.CDLL(lib_path)
            try:
                lib.fn_alpha.restype = ctypes.c_int
                lib.fn_beta.restype = ctypes.c_int
                self.assertEqual(lib.fn_alpha(), 123 if not _is_arm64() else lib.fn_beta())
                self.assertEqual(lib.fn_beta(), lib.fn_alpha())
            finally:
                _unload_cdll(lib)

    def test_03_auto_pgo_closed_loop_and_cli_flags_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = os.path.join(tmp, "repo_pgo")
            os.makedirs(repo_dir, exist_ok=True)
            with open(os.path.join(repo_dir, "kernels.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def cold_add(a: int, b: int) -> int:\n"
                    "    return a + b + 1\n\n"
                    "def hot_loop_sum(n: int) -> int:\n"
                    "    acc: int = 0\n"
                    "    i: int = 0\n"
                    "    while i < n:\n"
                    "        acc = acc + i * 3 + 1\n"
                    "        i = i + 1\n"
                    "    return acc\n"
                )

            out_base = os.path.join(tmp, "c108_cli_out")
            stdout_cap = StringIO()
            argv = [
                "build",
                "--repos", repo_dir,
                "--output", out_base,
                "--entry", "hot_loop_sum",
                "--export-all",
                "--auto-pgo",
                "--gc-sections",
                "--icf",
                "--no-provenance",
                "--json",
            ]
            with patch("sys.stdout", stdout_cap):
                rc = omnicc_cli.main(argv)
            self.assertEqual(rc, 0)
            payload = json.loads(stdout_cap.getvalue())
            self.assertTrue(payload["success"])
            self.assertTrue(payload["auto_pgo"]["enabled"])
            weights = payload["auto_pgo"]["hot_weights"]
            self.assertGreater(weights["hot_loop_sum"], weights["cold_add"])
            self.assertTrue(payload["linking"]["hot_first_applied"])
            self.assertTrue(payload["linking"]["gc_sections_applied"])
            self.assertTrue(payload["linking"]["icf_folding_applied"])
            self.assertEqual(payload["linking"]["layout_order"][0], "hot_loop_sum")

            art_path = payload["artifact_path"]
            self.assertTrue(os.path.exists(art_path))
            lib = ctypes.CDLL(art_path)
            try:
                lib.hot_loop_sum.argtypes = [ctypes.c_int64]
                lib.hot_loop_sum.restype = ctypes.c_int64
                lib.cold_add.argtypes = [ctypes.c_int64, ctypes.c_int64]
                lib.cold_add.restype = ctypes.c_int64
                # sum_{i=0}^{9} (3i + 1) = 3*45 + 10 = 145
                self.assertEqual(lib.hot_loop_sum(10), 145)
                self.assertEqual(lib.cold_add(40, 2), 43)
            finally:
                _unload_cdll(lib)


if __name__ == "__main__":
    unittest.main()
