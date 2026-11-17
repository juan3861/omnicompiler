import ast
import _ctypes
import ctypes
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.ssa_ir import AstToSsaLowering, lower_ast_to_ssa
from omni_repo_compiler import OmniRepoCompiler
from validation.biabduction_verifier import BiAbductionVerifier


def _unload_cdll(lib: ctypes.CDLL) -> None:
    handle = getattr(lib, "_handle", None)
    del lib
    if handle is None:
        return
    if sys.platform == "win32":
        _ctypes.FreeLibrary(handle)
    elif hasattr(_ctypes, "dlclose"):
        _ctypes.dlclose(handle)


class TestAlphaC37Z3BoundsSalsaAndOsCdll(unittest.TestCase):
    def test_01_z3_ssa_spatial_bounds_proof_and_oob_refutation(self):
        verifier = BiAbductionVerifier()
        src = """
class SensorBox:
    flags: u32
    weights: Array[f32, 4]

def safe_sum_box(box: SensorBox) -> float:
    total = 0.0
    i = 0
    while i < 4:
        total += box.weights[i]
        i += 1
    return total

def oob_sum_box(box: SensorBox) -> float:
    total = 0.0
    i = 0
    while i < 5:
        total += box.weights[i]
        i += 1
    return total
"""
        mod = ast.parse(src)
        cls_node = mod.body[0]
        safe_fn_ast = mod.body[1]
        oob_fn_ast = mod.body[2]

        extractor = AstToSsaLowering()
        extractor.register_structs_from_statements([cls_node])
        safe_ssa = lower_ast_to_ssa(safe_fn_ast, optimize=True, struct_layouts=extractor.struct_layouts)
        oob_ssa = lower_ast_to_ssa(oob_fn_ast, optimize=True, struct_layouts=extractor.struct_layouts)
        struct_sizes = {k: sz for k, (sz, _al) in extractor.struct_meta.items()}
        pmap = {"box": "SensorBox"}

        safe_res = verifier.verify_ssa_memory_bounds(safe_ssa, struct_sizes=struct_sizes, param_struct_map=pmap)
        self.assertTrue(safe_res["proven"], f"Expected safe loop proven memory-safe, got: {safe_res}")
        self.assertGreaterEqual(safe_res["checks_passed"], 1)
        self.assertEqual(safe_res["violations"], [])

        oob_res = verifier.verify_ssa_memory_bounds(oob_ssa, struct_sizes=struct_sizes, param_struct_map=pmap)
        self.assertFalse(oob_res["proven"], f"Expected OOB loop (i < 5 on 4-elem array) to be refuted: {oob_res}")
        self.assertEqual(oob_res["status"], "BOUND_VIOLATION_REFUTED")
        self.assertGreaterEqual(len(oob_res["violations"]), 1)

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_safe = os.path.join(tmpdir, "repo_safe")
            repo_oob = os.path.join(tmpdir, "repo_oob")
            os.makedirs(repo_safe)
            os.makedirs(repo_oob)
            with open(os.path.join(repo_safe, "mod.py"), "w", encoding="utf-8") as f:
                f.write(
                    "class SensorBox:\n"
                    "    flags: u32\n"
                    "    weights: Array[f32, 4]\n\n"
                    "def safe_sum_box(box: SensorBox) -> float:\n"
                    "    total = 0.0\n"
                    "    i = 0\n"
                    "    while i < 4:\n"
                    "        total += box.weights[i]\n"
                    "        i += 1\n"
                    "    return total\n"
                )
            with open(os.path.join(repo_oob, "mod.py"), "w", encoding="utf-8") as f:
                f.write(
                    "class SensorBox:\n"
                    "    flags: u32\n"
                    "    weights: Array[f32, 4]\n\n"
                    "def oob_sum_box(box: SensorBox) -> float:\n"
                    "    total = 0.0\n"
                    "    i = 0\n"
                    "    while i < 5:\n"
                    "        total += box.weights[i]\n"
                    "        i += 1\n"
                    "    return total\n"
                )

            comp = OmniRepoCompiler()
            ext = ".dll" if sys.platform == "win32" else ".so"
            res_safe = comp.compile_repositories(
                [repo_safe],
                os.path.join(tmpdir, f"safe{ext}"),
                target_format="shared_lib",
                entry_export="safe_sum_box",
                export_all=True,
                audit_nonce="c37-safe-bounds",
            )
            sep_safe = res_safe["stages"]["separation_logic"]
            self.assertTrue(sep_safe["z3_bounds_verified"], sep_safe)
            self.assertGreaterEqual(sep_safe["z3_bounds_checks_passed"], 1)

            res_oob = comp.compile_repositories(
                [repo_oob],
                os.path.join(tmpdir, f"oob{ext}"),
                target_format="shared_lib",
                entry_export="oob_sum_box",
                export_all=True,
                audit_nonce="c37-oob-bounds",
            )
            sep_oob = res_oob["stages"]["separation_logic"]
            self.assertFalse(sep_oob["z3_bounds_verified"], sep_oob)
            self.assertGreaterEqual(len(sep_oob["z3_bounds_violations"]), 1)

    def test_02_z3_pointer_disjointness_analysis(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = os.path.join(tmpdir, "ptr_repo")
            os.makedirs(repo_dir)
            with open(os.path.join(repo_dir, "kernels.py"), "w", encoding="utf-8") as f:
                f.write(
                    "class SensorBox:\n"
                    "    flags: u32\n"
                    "    weights: Array[f32, 4]\n\n"
                    "def copy_box_flag(dst: SensorBox, src: SensorBox) -> int:\n"
                    "    val = src.flags\n"
                    "    dst.flags = val + 1\n"
                    "    return val + 1\n\n"
                    "def dual_mutate_box(a: SensorBox, b: SensorBox) -> int:\n"
                    "    a.flags = 10\n"
                    "    b.flags = 20\n"
                    "    return 30\n"
                )
            comp = OmniRepoCompiler()
            ext = ".dll" if sys.platform == "win32" else ".so"
            res = comp.compile_repositories(
                [repo_dir],
                os.path.join(tmpdir, f"ptrs{ext}"),
                target_format="shared_lib",
                entry_export="copy_box_flag",
                export_all=True,
                audit_nonce="c37-ptr-disjoint",
            )
            reports = {r["function"]: r for r in res["stages"]["separation_logic"]["pointer_disjointness"]}
            self.assertIn("copy_box_flag", reports)
            self.assertEqual(reports["copy_box_flag"]["written_pointers"], ["dst"])
            self.assertEqual(reports["copy_box_flag"]["read_only_pointers"], ["src"])
            self.assertTrue(reports["copy_box_flag"]["single_writer_disjoint"])

            self.assertIn("dual_mutate_box", reports)
            self.assertEqual(set(reports["dual_mutate_box"]["written_pointers"]), {"a", "b"})
            self.assertFalse(reports["dual_mutate_box"]["single_writer_disjoint"])

    def test_03_salsa_red_green_incremental_cache_hits_and_invalidation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repos = []
            for rname, body in [
                ("repo_a", "def alpha_fn(x: int) -> int:\n    return x * 3 + 1\n"),
                ("repo_b", "def beta_fn(x: int) -> int:\n    return x * 5 + 2\n"),
                ("repo_c", "def gamma_fn(x: int) -> int:\n    return alpha_fn(x) + beta_fn(x)\n"),
            ]:
                rp = os.path.join(tmpdir, rname)
                os.makedirs(rp)
                with open(os.path.join(rp, "lib.py"), "w", encoding="utf-8") as f:
                    f.write(body)
                with open(os.path.join(rp, "extra.py"), "w", encoding="utf-8") as f:
                    f.write(f"def {rname}_aux(v: int) -> int:\n    return v + 7\n")
                repos.append(rp)

            comp = OmniRepoCompiler()
            ext = ".dll" if sys.platform == "win32" else ".so"
            out1 = os.path.join(tmpdir, f"b1{ext}")
            res1 = comp.compile_repositories(
                repos, out1, target_format="shared_lib", entry_export="gamma_fn",
                export_all=True, audit_nonce="c37-salsa-1"
            )
            ing1 = res1["stages"]["ingestion"]
            self.assertGreaterEqual(ing1["salsa_ast_misses"], 6)
            self.assertEqual(ing1["salsa_ast_hits"], 0)

            out2 = os.path.join(tmpdir, f"b2{ext}")
            res2 = comp.compile_repositories(
                repos, out2, target_format="shared_lib", entry_export="gamma_fn",
                export_all=True, audit_nonce="c37-salsa-2"
            )
            ing2 = res2["stages"]["ingestion"]
            self.assertGreaterEqual(ing2["salsa_ast_hits"], 6)
            self.assertEqual(ing2["salsa_ast_misses"], 0)

            # Mutate ONLY ONE file in repo_c
            with open(os.path.join(repos[2], "lib.py"), "w", encoding="utf-8") as f:
                f.write("def gamma_fn(x: int) -> int:\n    return alpha_fn(x) + beta_fn(x) + 100\n")

            out3 = os.path.join(tmpdir, f"b3{ext}")
            res3 = comp.compile_repositories(
                repos, out3, target_format="shared_lib", entry_export="gamma_fn",
                export_all=True, audit_nonce="c37-salsa-3"
            )
            ing3 = res3["stages"]["ingestion"]
            self.assertEqual(ing3["salsa_ast_misses"], 1, f"Expected exactly 1 file re-parsed, got {ing3}")
            self.assertGreaterEqual(ing3["salsa_ast_hits"], 5)

            lib3 = ctypes.CDLL(out3)
            try:
                fn = lib3.gamma_fn
                fn.argtypes = [ctypes.c_int64]
                fn.restype = ctypes.c_int64
                # (10*3+1) + (10*5+2) + 100 = 31 + 52 + 100 = 183
                self.assertEqual(fn(10), 183)
            finally:
                _unload_cdll(lib3)

    def test_04_live_os_ctypes_cdll_multi_repo_native_and_llvm(self):
        rust_src = """
pub fn rust_lut_step(code: i64, x: i64) -> i64 {
    return match code {
        0 => x * 2 + 1,
        1 | 2 => x * 3 + 5,
        _ => x + 42,
    };
}
"""
        go_src = """
func go_switch_scale(mode int, x int) int {
    switch mode {
    case 1, 2:
        return x * 4 + 10
    case 3:
        return x * 6 + 20
    default:
        return x + 100
    }
}
"""
        py_src = """
LUT_OFFSETS = [10, 25, 50, 75]

def fused_os_entry(mode: int, x: int) -> int:
    r = rust_lut_step(mode, x)
    g = go_switch_scale(mode, x)
    if mode >= 0 and mode < 4:
        return r + g + LUT_OFFSETS[mode]
    return r + g
"""

        def _expected(mode: int, x: int) -> int:
            if mode == 0:
                r = x * 2 + 1
            elif mode in (1, 2):
                r = x * 3 + 5
            else:
                r = x + 42
            if mode in (1, 2):
                g = x * 4 + 10
            elif mode == 3:
                g = x * 6 + 20
            else:
                g = x + 100
            lut = [10, 25, 50, 75]
            return r + g + (lut[mode] if 0 <= mode < 4 else 0)

        with tempfile.TemporaryDirectory() as tmpdir:
            rp_rs = os.path.join(tmpdir, "rust_core")
            rp_go = os.path.join(tmpdir, "go_net")
            rp_py = os.path.join(tmpdir, "py_entry")
            for p in (rp_rs, rp_go, rp_py):
                os.makedirs(p)

            with open(os.path.join(rp_rs, "core.rs"), "w", encoding="utf-8") as f:
                f.write(rust_src)
            with open(os.path.join(rp_go, "net.go"), "w", encoding="utf-8") as f:
                f.write(go_src)
            with open(os.path.join(rp_py, "main.py"), "w", encoding="utf-8") as f:
                f.write(py_src)

            ext = ".dll" if sys.platform == "win32" else ".so"
            for bk in ("native", "llvm"):
                out_lib = os.path.join(tmpdir, f"fused_{bk}{ext}")
                comp = OmniRepoCompiler()
                res = comp.compile_repositories(
                    [rp_rs, rp_go, rp_py],
                    out_lib,
                    target_format="shared_lib",
                    entry_export="fused_os_entry",
                    export_all=True,
                    backend=bk,
                    audit_nonce=f"c37-os-cdll-{bk}",
                )
                self.assertTrue(os.path.exists(out_lib), f"Shared lib missing for backend={bk}")
                self.assertGreater(os.path.getsize(out_lib), 0)
                self.assertTrue(res["stages"]["formal_audit"]["is_valid"])

                lib = ctypes.CDLL(out_lib)
                try:
                    entry = lib.fused_os_entry
                    entry.argtypes = [ctypes.c_int64, ctypes.c_int64]
                    entry.restype = ctypes.c_int64
                    for mode in (-1, 0, 1, 2, 3, 7):
                        for x in (0, 5, 19):
                            got = entry(mode, x)
                            exp = _expected(mode, x)
                            self.assertEqual(
                                got, exp,
                                f"Live OS CDLL mismatch backend={bk} mode={mode} x={x}: got {got}, expected {exp}",
                            )
                finally:
                    _unload_cdll(lib)


if __name__ == "__main__":
    unittest.main()
