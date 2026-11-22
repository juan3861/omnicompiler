"""
Alpha-C74 Validation Suite:
1. Structured `try / except / raise` (`Result`-style error propagation) in `AstToSsaLowering`
   and `OmniRepoCompiler` (`Native`, `LLVM`, and `Homeostasis`) with `finally` execution.
2. Explicit Type-Driven Generic Function Monomorphization (`fn<T>` in Rust & TypeScript ->
   `fn__mono_int` & `fn__mono_float`) compiled heterogeneously across repositories.
"""

import ctypes
import os
import sys
import tempfile
import unittest

from omni_repo_compiler import OmniRepoCompiler
from validation.validator import IndependentValidator


class TestAlphaC74GenericsMonomorphizationAndTryExcept(unittest.TestCase):
    def tearDown(self):
        IndependentValidator.close_persistent_worker()

    def test_01_structured_try_except_raise_and_finally_e2e(self):
        """
        Proves `try / except Exception as err / raise ValueError(code) / finally` lowers
        to structured SSA CFG branches and executes identically in Unicorn and `ctypes.CDLL`.
        """
        src = """
def omni_main(x: int) -> int:
    res = 0
    try:
        if x < 0:
            raise ValueError(42)
        res = x * 10 + 5
    except Exception as err:
        res = 1000 + err
    finally:
        res = res + 1
    return res
"""
        with tempfile.TemporaryDirectory() as td:
            rdir = os.path.join(td, "repo_try")
            os.makedirs(rdir, exist_ok=True)
            with open(os.path.join(rdir, "err_mod.py"), "w", encoding="utf-8") as f:
                f.write(src)
            with open(os.path.join(rdir, "omni.toml"), "w", encoding="utf-8") as f:
                f.write(
                    'repo_name = "repo_try"\n'
                    'version = "1.0.0"\n'
                    'exports = [{ name = "omni_main", file = "err_mod.py", args = ["x"], return_type = "int" }]\n'
                    'imports = []\n'
                )

            out_lib = os.path.join(td, "c74_try.dll" if sys.platform == "win32" else "libc74_try.so")
            compiler = OmniRepoCompiler()
            try:
                res = compiler.compile_repositories(
                    repo_paths=[rdir],
                    output_path=out_lib,
                    target_format="shared_lib",
                    entry_export="omni_main",
                    backend="homeostasis",
                )
            finally:
                compiler.close()

            self.assertTrue(res["success"])
            # x=10 -> 10*10+5 + 1 = 106
            self.assertEqual(res["stages"]["preflight_safety"]["simulated_return_value"], 106)

            lib = ctypes.CDLL(res["stages"]["emission"]["artifact_path"])
            fn = lib.omni_main
            fn.argtypes = [ctypes.c_int64]
            fn.restype = ctypes.c_int64
            self.assertEqual(fn(10), 106)
            self.assertEqual(fn(-5), 1043)  # 1000 + 42 + 1
            if sys.platform == "win32":
                ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(lib._handle))

    def test_02_polyglot_generic_monomorphization_rust_and_typescript(self):
        """
        Proves Rust `pub fn scale_gen<T>(x: T, factor: T) -> T` and TypeScript generic
        `export function bias_gen<T>(v: T, b: T): T` monomorphize into `__mono_int` and
        `__mono_float` clones at call sites and execute accurately via `ctypes.CDLL`.
        """
        with tempfile.TemporaryDirectory() as td:
            r_rs = os.path.join(td, "gen_rs")
            r_ts = os.path.join(td, "gen_ts")
            r_py = os.path.join(td, "app_py")
            for d in (r_rs, r_ts, r_py):
                os.makedirs(d, exist_ok=True)

            with open(os.path.join(r_rs, "Cargo.toml"), "w", encoding="utf-8") as f:
                f.write('[package]\nname = "gen_rs"\nversion = "0.1.0"\n')
            with open(os.path.join(r_rs, "lib.rs"), "w", encoding="utf-8") as f:
                f.write("pub fn scale_gen<T>(x: T, factor: T) -> T { return x * factor; }\n")

            with open(os.path.join(r_ts, "package.json"), "w", encoding="utf-8") as f:
                f.write('{"name": "gen_ts", "dependencies": {"gen_rs": "file:../gen_rs"}}')
            with open(os.path.join(r_ts, "lib.ts"), "w", encoding="utf-8") as f:
                f.write("export function bias_gen<T>(v: T, b: T): T { return v + b; }\n")

            with open(os.path.join(r_py, "main.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def omni_main(x: int) -> int:\n"
                    "    iv = scale_gen(x, 3)\n"
                    "    fv = bias_gen(float(x), 2.5)\n"
                    "    return iv + int(fv)\n"
                )
            with open(os.path.join(r_py, "omni.toml"), "w", encoding="utf-8") as f:
                f.write(
                    'repo_name = "app_py"\n'
                    'version = "1.0.0"\n'
                    'exports = [{ name = "omni_main", file = "main.py", args = ["x"], return_type = "int" }]\n'
                    'imports = []\n'
                )

            out_lib = os.path.join(td, "c74_mono.dll" if sys.platform == "win32" else "libc74_mono.so")
            compiler = OmniRepoCompiler()
            try:
                res = compiler.compile_repositories(
                    repo_paths=[r_rs, r_ts, r_py],
                    output_path=out_lib,
                    target_format="shared_lib",
                    entry_export="omni_main",
                    backend="homeostasis",
                )
            finally:
                compiler.close()

            self.assertTrue(res["success"])
            syms = res["stages"]["linking"]["exported_symbols"]
            self.assertIn("scale_gen__mono_int", syms)
            self.assertIn("bias_gen__mono_float", syms)
            # omni_main(10) = (10*3) + int(10.0 + 2.5) = 30 + 12 = 42
            self.assertEqual(res["stages"]["preflight_safety"]["simulated_return_value"], 42)

            lib = ctypes.CDLL(res["stages"]["emission"]["artifact_path"])
            fn = lib.omni_main
            fn.argtypes = [ctypes.c_int64]
            fn.restype = ctypes.c_int64
            self.assertEqual(fn(10), 42)
            self.assertEqual(fn(7), 30)  # 21 + int(9.5) = 30
            if sys.platform == "win32":
                ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(lib._handle))


if __name__ == "__main__":
    unittest.main()
