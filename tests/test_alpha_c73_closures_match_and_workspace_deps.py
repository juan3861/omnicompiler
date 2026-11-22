"""
Alpha-C73 Validation Suite:
1. Static Closure Conversion (`def` nested functions + `lambda` expressions with captured environment)
   and `match`/`case` pattern lowering in `AstToSsaLowering` + `OmniRepoCompiler` (`Native` & `LLVM`).
2. Transitive Local Workspace Dependency Auto-Expansion (`Cargo.toml` `path =`, `package.json` `file:`,
   `go.mod` `replace =>`) compiling multi-repo polyglot DAGs from just the root repository path.
"""

import ctypes
import os
import sys
import tempfile
import unittest

from omni_repo_compiler import OmniRepoCompiler
from validation.validator import IndependentValidator


class TestAlphaC73ClosuresMatchAndWorkspaceDeps(unittest.TestCase):
    def tearDown(self):
        IndependentValidator.close_persistent_worker()

    def test_01_nested_def_lambda_closures_and_match_case_e2e(self):
        """
        Proves `AstToSsaLowering` and `OmniRepoCompiler` lift nested `def` and `lambda` closures
        with captured variables (`scale`, `bias`), lower `match`/`case`, and execute via `ctypes.CDLL`.
        """
        src = """
def omni_main(x: int) -> int:
    scale = 4
    bias = 7
    def affine(v: int) -> int:
        return v * scale + bias
    bump = lambda z: z + scale
    match x:
        case 1:
            return affine(10)
        case 2:
            return bump(100)
        case _:
            return affine(x) + bump(x)
"""
        with tempfile.TemporaryDirectory() as td:
            rdir = os.path.join(td, "repo_closures")
            os.makedirs(rdir, exist_ok=True)
            with open(os.path.join(rdir, "closures.py"), "w", encoding="utf-8") as f:
                f.write(src)
            with open(os.path.join(rdir, "omni.toml"), "w", encoding="utf-8") as f:
                f.write(
                    'repo_name = "repo_closures"\n'
                    'version = "1.0.0"\n'
                    'exports = [{ name = "omni_main", file = "closures.py", args = ["x"], return_type = "int" }]\n'
                    'imports = []\n'
                )

            out_lib = os.path.join(td, "c73_closures.dll" if sys.platform == "win32" else "libc73_closures.so")
            compiler = OmniRepoCompiler()
            try:
                res = compiler.compile_repositories(
                    repo_paths=[rdir],
                    output_path=out_lib,
                    target_format="shared_lib",
                    entry_export="omni_main",
                    backend="homeostasis",
                    homeostasis_policy="throughput",
                )
            finally:
                compiler.close()

            self.assertTrue(res["success"])
            syms = res["stages"]["linking"]["exported_symbols"]
            self.assertIn("omni_main__closure_affine", syms)
            self.assertIn("omni_main__closure_bump", syms)
            # omni_main(10) = affine(10) + bump(10) = (10*4+7) + (10+4) = 47 + 14 = 61
            self.assertEqual(res["stages"]["preflight_safety"]["simulated_return_value"], 61)

            lib = ctypes.CDLL(res["stages"]["emission"]["artifact_path"])
            fn = lib.omni_main
            fn.argtypes = [ctypes.c_int64]
            fn.restype = ctypes.c_int64
            self.assertEqual(fn(1), 47)   # affine(10)
            self.assertEqual(fn(2), 104)  # bump(100)
            self.assertEqual(fn(10), 61)  # default case
            if sys.platform == "win32":
                ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(lib._handle))

    def test_02_transitive_local_workspace_expansion_from_root_repo(self):
        """
        Proves passing ONLY the root Go repository (`app_go`) automatically discovers and compiles
        `mid_ts` (`go.mod` `replace => ../mid_ts`) and `leaf_rs` (`package.json` `file:../leaf_rs`).
        """
        with tempfile.TemporaryDirectory() as td:
            r_leaf = os.path.join(td, "leaf_rs")
            r_mid = os.path.join(td, "mid_ts")
            r_root = os.path.join(td, "app_go")
            for d in (r_leaf, r_mid, r_root):
                os.makedirs(d, exist_ok=True)

            with open(os.path.join(r_leaf, "Cargo.toml"), "w", encoding="utf-8") as f:
                f.write('[package]\nname = "leaf_rs"\nversion = "0.1.0"\n')
            with open(os.path.join(r_leaf, "lib.rs"), "w", encoding="utf-8") as f:
                f.write("pub fn leaf_calc(x: i64) -> i64 { return x * 5 + 2; }\n")

            with open(os.path.join(r_mid, "package.json"), "w", encoding="utf-8") as f:
                f.write('{"name": "mid_ts", "dependencies": {"leaf_rs": "file:../leaf_rs"}}')
            with open(os.path.join(r_mid, "mid.ts"), "w", encoding="utf-8") as f:
                f.write("export function mid_calc(x: number): number { return leaf_calc(x) * 2; }\n")

            with open(os.path.join(r_root, "go.mod"), "w", encoding="utf-8") as f:
                f.write("module example.com/app_go\n\ngo 1.22\n\nreplace example.com/mid_ts => ../mid_ts\n")
            with open(os.path.join(r_root, "main.go"), "w", encoding="utf-8") as f:
                f.write("package main\nfunc omni_main(x int64) int64 { return mid_calc(x) + 3 }\n")

            out_lib = os.path.join(td, "c73_ws.dll" if sys.platform == "win32" else "libc73_ws.so")
            compiler = OmniRepoCompiler()
            try:
                res = compiler.compile_repositories(
                    repo_paths=[r_root],
                    output_path=out_lib,
                    target_format="shared_lib",
                    entry_export="omni_main",
                    backend="homeostasis",
                )
            finally:
                compiler.close()

            self.assertTrue(res["success"])
            # omni_main(10) = ((10 * 5 + 2) * 2) + 3 = 104 + 3 = 107
            self.assertEqual(res["stages"]["preflight_safety"]["simulated_return_value"], 107)
            lib = ctypes.CDLL(res["stages"]["emission"]["artifact_path"])
            fn = lib.omni_main
            fn.argtypes = [ctypes.c_int64]
            fn.restype = ctypes.c_int64
            self.assertEqual(fn(10), 107)
            self.assertEqual(fn(4), 47)
            if sys.platform == "win32":
                ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(lib._handle))


if __name__ == "__main__":
    unittest.main()
