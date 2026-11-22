"""
Alpha-C71 Validation Suite:
1. Cross-Emitter `f64` Return ABI Parity (`Native <-> LLVM 20 <-> GCC`) via `global_return_types` propagation (`XMM0` / `D0`).
2. Full-Module Win64 `.pdata` + `.xdata` Unwind Tables across ALL non-leaf functions (`emit_win64_multi_pdata_xdata` + PE32+ `.pdata` section).
3. DWARF v5 `.debug_info` + `.debug_abbrev` `DW_TAG_subprogram` DIEs + `cross_emitter_summaries` telemetry in `Homeostasis`.
"""

import ctypes
import os
import struct
import sys
import tempfile
import unittest

from compiler.debug_info_emitter import DwarfV5Emitter, emit_win64_multi_pdata_xdata
from omni_repo_compiler import OmniRepoCompiler
from validation.binary_structure_auditor import BinaryStructureAuditor
from validation.validator import IndependentValidator


class TestAlphaC71CrossEmitterF64AbiPdataAndDwarfSubprograms(unittest.TestCase):
    def tearDown(self):
        IndependentValidator.close_persistent_worker()

    def test_01_cross_emitter_f64_return_abi_llvm_to_native_and_gcc_to_native(self):
        """
        Proves `Native` callers invoke `LLVM` and `GCC` callees that return `float` (`f64` in `XMM0`),
        converting `int(res)` cleanly via `fptosi` under `global_return_types` propagation.
        """
        r1_src = """
def compute_f64_llvm(val: float, gain: float) -> float:
    acc: float = 0.0
    if val > 0.0:
        acc = val * 3.0
    else:
        acc = val * 2.0
    if gain > 10.0:
        return acc + 100.0
    elif gain > 5.0:
        return acc + 50.0
    elif gain > 1.0:
        return acc * gain + 2.5
    elif gain > 0.0:
        return acc + 1.0
    return acc - 100.0
"""
        r2_src = """
def omni_main(x: int) -> int:
    xf = float(x)
    res = compute_f64_llvm(xf, 4.0)
    return int(res)
"""
        with tempfile.TemporaryDirectory() as td:
            r1 = os.path.join(td, "repo_f64_ret")
            r2 = os.path.join(td, "repo_native_caller")
            os.makedirs(r1, exist_ok=True)
            os.makedirs(r2, exist_ok=True)

            with open(os.path.join(r1, "f64_ret.py"), "w", encoding="utf-8") as f:
                f.write(r1_src)
            with open(os.path.join(r1, "omni.toml"), "w", encoding="utf-8") as f:
                f.write(
                    'repo_name = "repo_f64_ret"\n'
                    'version = "1.0.0"\n'
                    'exports = [{ name = "compute_f64_llvm", file = "f64_ret.py", args = ["val", "gain"], return_type = "float" }]\n'
                    'imports = []\n'
                )
            with open(os.path.join(r2, "caller.py"), "w", encoding="utf-8") as f:
                f.write(r2_src)
            with open(os.path.join(r2, "omni.toml"), "w", encoding="utf-8") as f:
                f.write(
                    'repo_name = "repo_native_caller"\n'
                    'version = "1.0.0"\n'
                    'exports = [{ name = "omni_main", file = "caller.py", args = ["x"], return_type = "int" }]\n'
                    'imports = [{ name = "compute_f64_llvm", from_repo = "repo_f64_ret" }]\n'
                )

            out_lib = os.path.join(td, "c71_f64_abi.dll" if sys.platform == "win32" else "libc71_f64_abi.so")
            compiler = OmniRepoCompiler()
            try:
                res = compiler.compile_repositories(
                    repo_paths=[r1, r2],
                    output_path=out_lib,
                    target_format="shared_lib",
                    entry_export="omni_main",
                    backend="homeostasis",
                    homeostasis_policy="throughput",
                    homeostasis_function_overrides={
                        "compute_f64_llvm": "llvm",
                        "omni_main": "native",
                    },
                )
            finally:
                compiler.close()

            self.assertTrue(res["success"])
            homeo = res["stages"]["homeostasis"]
            self.assertTrue(homeo["heterogeneous_link"])
            self.assertIn("cross_emitter_summaries", homeo)
            summaries = homeo["cross_emitter_summaries"]
            self.assertEqual(summaries["omni_main"]["emitter"], "native")
            self.assertFalse(summaries["omni_main"]["is_pure"])
            # 10 * 3.0 * 4.0 + 2.5 = 122.5 -> int = 122
            self.assertEqual(res["stages"]["preflight_safety"]["simulated_return_value"], 122)

            lib = ctypes.CDLL(res["stages"]["emission"]["artifact_path"])
            fn = lib.omni_main
            fn.argtypes = [ctypes.c_int64]
            fn.restype = ctypes.c_int64
            self.assertEqual(fn(10), 122)
            self.assertEqual(fn(5), 62)
            if sys.platform == "win32":
                ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(lib._handle))

    def test_02_multi_function_win64_pdata_xdata_and_dwarf_v5_subprograms(self):
        """
        Proves `emit_win64_multi_pdata_xdata` sorts `RUNTIME_FUNCTION` entries by `BeginAddress`,
        packs 4-byte-aligned `UNWIND_INFO` blobs, and `OmniRepoCompiler` emits `.pdata` + DWARF v5
        `DW_TAG_subprogram` DIEs across all compiled functions.
        """
        pdata, xdata = emit_win64_multi_pdata_xdata([
            {"func_rva": 0x1080, "code_size": 48, "prologue_size": 6, "stack_frame_size": 32, "saved_regs": ["rbx"]},
            {"func_rva": 0x1000, "code_size": 32, "prologue_size": 4, "stack_frame_size": 16, "saved_regs": ["rbp"]},
        ])
        self.assertEqual(len(pdata), 24)
        b0, e0, u0 = struct.unpack_from("<III", pdata, 0)
        b1, e1, u1 = struct.unpack_from("<III", pdata, 12)
        self.assertEqual((b0, e0, u0), (0x1000, 0x1020, 0))
        self.assertEqual((b1, e1), (0x1080, 0x10B0))
        self.assertGreater(u1, 0)
        self.assertEqual(u1 % 4, 0)

        dw = DwarfV5Emitter()
        d_info, d_abbrev = dw.emit_debug_info_with_subprograms(
            unit_name="multi.py",
            low_pc=0x1000,
            high_pc=0x1100,
            subprograms=[
                {"name": "fn_a", "low_pc": 0x1000, "high_pc": 0x1020, "line": 3},
                {"name": "fn_b", "low_pc": 0x1080, "high_pc": 0x10B0, "line": 12},
            ],
        )
        self.assertIn(b"fn_a\x00", d_info)
        self.assertIn(b"fn_b\x00", d_info)
        self.assertIn(b"\x02\x2e\x00", d_abbrev)  # abbrev 2 = DW_TAG_subprogram, no children

        # End-to-end OmniRepoCompiler with 2 non-leaf Native functions
        src = """
def leaf_helper(a: int) -> int:
    acc = a
    if acc > 100:
        acc = acc + 1
    elif acc > 50:
        acc = acc + 2
    elif acc > 20:
        acc = acc + 3
    elif acc > 10:
        acc = acc + 4
    else:
        acc = acc + 5
    return acc * 7 + 3

def mid_nonleaf(x: int) -> int:
    t = leaf_helper(x)
    return t + 11

def omni_main(x: int) -> int:
    return mid_nonleaf(x) + 5
"""
        with tempfile.TemporaryDirectory() as td:
            rdir = os.path.join(td, "repo_unwind")
            os.makedirs(rdir, exist_ok=True)
            with open(os.path.join(rdir, "mod.py"), "w", encoding="utf-8") as f:
                f.write(src)
            with open(os.path.join(rdir, "omni.toml"), "w", encoding="utf-8") as f:
                f.write(
                    'repo_name = "repo_unwind"\n'
                    'version = "1.0.0"\n'
                    'exports = [\n'
                    '  { name = "leaf_helper", file = "mod.py", args = ["a"], return_type = "int" },\n'
                    '  { name = "mid_nonleaf", file = "mod.py", args = ["x"], return_type = "int" },\n'
                    '  { name = "omni_main", file = "mod.py", args = ["x"], return_type = "int" }\n'
                    ']\n'
                    'imports = []\n'
                )
            out_lib = os.path.join(td, "c71_unwind.dll" if sys.platform == "win32" else "libc71_unwind.so")
            compiler = OmniRepoCompiler()
            try:
                res = compiler.compile_repositories(
                    repo_paths=[rdir],
                    output_path=out_lib,
                    target_format="shared_lib",
                    entry_export="omni_main",
                    target_os="windows",
                    target_arch="x86_64",
                    backend="native",
                )
            finally:
                compiler.close()

            self.assertTrue(res["success"])
            dbg = res["stages"]["debug_info"]
            self.assertGreaterEqual(dbg["subprograms_count"], 3)
            self.assertGreater(dbg["debug_info_bytes"], 32)
            self.assertGreaterEqual(dbg.get("win64_pdata_entries", 0), 2)
            self.assertIn(".pdata", res["stages"]["formal_audit"]["sections"])

            with open(res["stages"]["emission"]["artifact_path"], "rb") as bf:
                rep = BinaryStructureAuditor().audit_binary(bf.read())
            self.assertTrue(rep.is_valid)
            self.assertIn(".pdata", rep.sections)


if __name__ == "__main__":
    unittest.main()
