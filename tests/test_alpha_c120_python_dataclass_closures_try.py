"""Alpha-C120 verification: Python AOT @dataclass zero-boxing, closures/lambdas & try/except."""

import ctypes
import os
import sys
import tempfile
import unittest

from omni_repo_compiler import OmniRepoCompiler


def _load_and_close(lib_path: str, fn_name: str, args_list):
    lib = ctypes.CDLL(lib_path)
    try:
        fn = getattr(lib, fn_name)
        fn.argtypes = [ctypes.c_int64] * len(args_list[0])
        fn.restype = ctypes.c_int64
        return [fn(*a) for a in args_list]
    finally:
        if sys.platform == "win32":
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.FreeLibrary.argtypes = [ctypes.c_void_p]
            k32.FreeLibrary(ctypes.c_void_p(lib._handle))


class TestAlphaC120PythonDataclassClosuresTry(unittest.TestCase):
    def test_01_python_dataclass_zero_boxing_methods_and_fields(self) -> None:
        src = (
            "from dataclasses import dataclass\n\n"
            "@dataclass\n"
            "class Vec2:\n"
            "    x: int\n"
            "    y: int\n\n"
            "    def mag2_plus(self, k: int) -> int:\n"
            "        return (self.x * self.x) + (self.y * self.y) + k\n\n"
            "def omni_main(a: int, b: int) -> int:\n"
            "    v = Vec2(a, b)\n"
            "    v2 = Vec2(y=b + 1, x=a + 2)\n"
            "    return v.mag2_plus(7) + v.x + v2.y\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "vec_app.py"), "w", encoding="utf-8") as f:
                f.write(src)
            comp = OmniRepoCompiler()
            try:
                res = comp.compile_repositories(
                    repo_paths=[tmp],
                    output_path=os.path.join(tmp, "c120_vec"),
                    target_format="shared_lib",
                    entry_export="omni_main",
                    toolchain_mode="aot_only",
                    export_all=False,
                    emit_provenance=False,
                )
            finally:
                comp.close()

            self.assertTrue(res["success"])
            art = res["stages"]["emission"]["artifact_path"]
            if sys.platform in ("win32", "linux"):
                vecs_01 = [(3, 4), (5, 12), (-2, 7)]
                got = _load_and_close(art, "omni_main", vecs_01)
                self.assertEqual(got, [(a * a + b * b + 7) + a + (b + 1) for a, b in vecs_01])

    def test_02_python_closures_inline_lambda_and_struct_capture(self) -> None:
        src = (
            "from dataclasses import dataclass\n\n"
            "@dataclass\n"
            "class Pair:\n"
            "    a: int\n"
            "    b: int\n\n"
            "def omni_main(x: int, factor: int) -> int:\n"
            "    p = Pair(x + 1, x + 2)\n"
            "    offset = 3\n"
            "    scale_fn = lambda v: v * factor + offset\n"
            "    def nested_sum(delta: int) -> int:\n"
            "        return p.a + p.b + delta\n"
            "    inline_v = (lambda z: z + factor)(10)\n"
            "    return scale_fn(x) + nested_sum(5) + inline_v\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "closure_app.py"), "w", encoding="utf-8") as f:
                f.write(src)
            comp = OmniRepoCompiler()
            try:
                res = comp.compile_repositories(
                    repo_paths=[tmp],
                    output_path=os.path.join(tmp, "c120_closures"),
                    target_format="shared_lib",
                    entry_export="omni_main",
                    toolchain_mode="aot_only",
                    export_all=True,
                    emit_provenance=False,
                )
            finally:
                comp.close()

            art = res["stages"]["emission"]["artifact_path"]
            if sys.platform in ("win32", "linux"):
                def py_ref(x: int, factor: int) -> int:
                    return (x * factor + 3) + ((x + 1) + (x + 2) + 5) + (10 + factor)
                vecs = [(4, 6), (0, 9), (-3, 5), (12, 3)]
                got = _load_and_close(art, "omni_main", vecs)
                self.assertEqual(got, [py_ref(x, k) for x, k in vecs])

    def test_03_python_try_except_zerodivision_and_finally_landing_pad(self) -> None:
        src = (
            "def omni_main(a: int, b: int) -> int:\n"
            "    out = 0\n"
            "    try:\n"
            "        if a < 0:\n"
            "            raise ValueError(50)\n"
            "        out = a // b\n"
            "    except ZeroDivisionError:\n"
            "        out = -100\n"
            "    finally:\n"
            "        out = out + 7\n"
            "    return out\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "try_app.py"), "w", encoding="utf-8") as f:
                f.write(src)
            comp = OmniRepoCompiler()
            try:
                res = comp.compile_repositories(
                    repo_paths=[tmp],
                    output_path=os.path.join(tmp, "c120_try"),
                    target_format="shared_lib",
                    entry_export="omni_main",
                    toolchain_mode="aot_only",
                    export_all=True,
                    emit_provenance=False,
                )
            finally:
                comp.close()

            art = res["stages"]["emission"]["artifact_path"]
            if sys.platform in ("win32", "linux"):
                # (20, 4) -> 5 + 7 = 12
                # (20, 0) -> -100 + 7 = -93 (safe ZeroDivisionError landing pad, no hardware crash!)
                # (-1, 3) -> -100 + 7 = -93 (raise jumps to except, runs finally!)
                got = _load_and_close(art, "omni_main", [(20, 4), (20, 0), (-1, 3), (42, 7)])
                self.assertEqual(got, [12, -93, -93, 13])


if __name__ == "__main__":
    unittest.main()
