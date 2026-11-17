import _ctypes
import ctypes
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from omni_repo_compiler import OmniRepoCompiler


def _unload_cdll(lib: ctypes.CDLL) -> None:
    handle = getattr(lib, "_handle", None)
    del lib
    if handle is not None and sys.platform == "win32":
        _ctypes.FreeLibrary(handle)


class TestAlphaC42C43DiskSalsaAndCpp(unittest.TestCase):
    def test_01_persistent_disk_salsa_cache_across_separate_compiler_instances(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "omni_persist.db")
            repos = []
            for name, code in [
                ("repo_1", "def fn_one(x: int) -> int:\n    acc = 0\n    i = 0\n    while i < 4:\n        acc += x + i\n        i += 1\n    return acc\n"),
                ("repo_2", "def fn_two(x: int) -> int:\n    return x * 7 + 3\n"),
                ("repo_3", "def fn_top(x: int) -> int:\n    return fn_one(x) + fn_two(x)\n"),
            ]:
                rp = os.path.join(tmpdir, name)
                os.makedirs(rp)
                with open(os.path.join(rp, "mod.py"), "w", encoding="utf-8") as f:
                    f.write(code)
                repos.append(rp)

            ext = ".dll" if sys.platform == "win32" else ".so"
            out1 = os.path.join(tmpdir, f"b1{ext}")
            comp1 = OmniRepoCompiler(db_path=db_path)
            try:
                res1 = comp1.compile_repositories(
                    repos, out1, target_format="shared_lib",
                    entry_export="fn_top", export_all=True,
                    backend="native", audit_nonce="c42-disk-1",
                )
                self.assertEqual(res1["stages"]["ingestion"]["salsa_artifact_misses"], 3)
            finally:
                comp1.close()

            # Fresh compiler instance pointing to the same SQLite cache DB (simulates new CLI process)
            out2 = os.path.join(tmpdir, f"b2{ext}")
            comp2 = OmniRepoCompiler(db_path=db_path)
            try:
                res2 = comp2.compile_repositories(
                    repos, out2, target_format="shared_lib",
                    entry_export="fn_top", export_all=True,
                    backend="native", audit_nonce="c42-disk-2",
                )
                ing2 = res2["stages"]["ingestion"]
                self.assertEqual(ing2["salsa_artifact_hits"], 3, f"Expected 3 disk cache artifact hits, got {ing2}")
                self.assertEqual(ing2["salsa_artifact_misses"], 0)
            finally:
                comp2.close()

            lib2 = ctypes.CDLL(out2)
            try:
                fn = lib2.fn_top
                fn.argtypes = [ctypes.c_int64]
                fn.restype = ctypes.c_int64
                # fn_one(5) = (5+0)+(5+1)+(5+2)+(5+3) = 26; fn_two(5) = 38 => 64
                self.assertEqual(fn(5), 64)
            finally:
                _unload_cdll(lib2)

    def test_02_c_and_cpp_structs_switch_for_and_5lang_polyglot_fusion(self):
        c_src = """
#include <stdint.h>

typedef struct {
    uint32_t tag;
    float taps[4];
} CFrame;

int64_t c_switch_kernel(int64_t mode, int64_t x) {
    int64_t acc = 0;
    for (int i = 0; i < 4; i++) {
        acc += i;
    }
    switch (mode) {
    case 1:
    case 2:
        return acc + x * 3 + 10;
    default:
        return acc + x + 5;
    }
}
"""
        cpp_src = """
#include <cstdint>

static inline int64_t cpp_poly_accum(int64_t n) {
    int64_t s = 0;
    for (int64_t k = 0; k < n; k++) {
        s += k * 2 + 1;
    }
    return s;
}
"""
        rust_src = """
pub fn rs_bias(x: i64) -> i64 {
    return x + 11;
}
"""
        go_src = """
func go_scale(x int) int {
    return x * 2;
}
"""
        py_src = """
def poly5_entry(mode: int, x: int) -> int:
    return c_switch_kernel(mode, x) + cpp_poly_accum(4) + rs_bias(x) + go_scale(x)
"""

        def _expected(mode: int, x: int) -> int:
            c_v = 6 + (x * 3 + 10 if mode in (1, 2) else x + 5)
            cpp_v = sum(k * 2 + 1 for k in range(4))  # 1+3+5+7 = 16
            return c_v + cpp_v + (x + 11) + (x * 2)

        with tempfile.TemporaryDirectory() as tmpdir:
            specs = [
                ("c_repo", "dsp.c", c_src),
                ("cpp_repo", "ops.cpp", cpp_src),
                ("rs_repo", "step.rs", rust_src),
                ("go_repo", "route.go", go_src),
                ("py_repo", "entry.py", py_src),
            ]
            repos = []
            for dname, fname, content in specs:
                rp = os.path.join(tmpdir, dname)
                os.makedirs(rp)
                with open(os.path.join(rp, fname), "w", encoding="utf-8") as f:
                    f.write(content)
                repos.append(rp)

            ext = ".dll" if sys.platform == "win32" else ".so"
            for bk in ("native", "llvm"):
                out_lib = os.path.join(tmpdir, f"poly5_{bk}{ext}")
                comp = OmniRepoCompiler()
                res = comp.compile_repositories(
                    repos, out_lib, target_format="shared_lib",
                    entry_export="poly5_entry", export_all=True,
                    backend=bk, audit_nonce=f"c43-poly5-{bk}",
                )
                self.assertTrue(res["stages"]["formal_audit"]["is_valid"])
                lib = ctypes.CDLL(out_lib)
                try:
                    fn = lib.poly5_entry
                    fn.argtypes = [ctypes.c_int64, ctypes.c_int64]
                    fn.restype = ctypes.c_int64
                    for mode in (0, 1, 2, 9):
                        for x in (0, 7, 13):
                            self.assertEqual(fn(mode, x), _expected(mode, x))
                finally:
                    _unload_cdll(lib)


if __name__ == "__main__":
    unittest.main()
