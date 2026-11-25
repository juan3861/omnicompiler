"""
Alpha-C102 Empirical Verification Suite:
1. Genuine Multi-TU CMakeLists.txt C + C++17 project (`include/`, `-D` compile definitions, cross-TU call)
   automatically configured, compiled via GCC/G++, linked into ELF64 `.so` by `OmniRepoCompiler`,
   and executed live via `ctypes.CDLL` in WSL2 Linux!
2. Genuine `go.mod` + `*.go` module built via host Go 1.26 (`go build` -> `go:wasip1` Wasmtime-validated
   or `go:c-archive` static `.a`) inside `OmniRepoCompiler(..., toolchain_mode="federated_lto")`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from omni_repo_compiler import OmniRepoCompiler


def _wsl_ready() -> bool:
    if sys.platform != "win32":
        return bool(shutil.which("gcc") and shutil.which("g++"))
    try:
        r = subprocess.run(
            ["wsl", "python3", "-c", "import shutil; print(bool(shutil.which('gcc') and shutil.which('g++')))"],
            capture_output=True,
            text=True,
            timeout=20,
            stdin=subprocess.DEVNULL,
        )
        return r.returncode == 0 and "True" in r.stdout
    except Exception:
        return False


def _to_wsl(p: str) -> str:
    ap = os.path.abspath(p).replace("\\", "/")
    if len(ap) >= 2 and ap[1] == ":":
        return f"/mnt/{ap[0].lower()}{ap[2:]}"
    return ap


class TestAlphaC102CMakeAndGoFederation(unittest.TestCase):
    def test_c102_cmake_multifile_project_and_live_execution(self) -> None:
        if sys.platform == "win32" and not _wsl_ready():
            self.skipTest("WSL2 gcc/g++ required for CMake cross-Linux ELF verification")

        with tempfile.TemporaryDirectory() as td:
            cm_repo = os.path.join(td, "cmake_proj")
            inc_dir = os.path.join(cm_repo, "include")
            src_dir = os.path.join(cm_repo, "src")
            os.makedirs(inc_dir, exist_ok=True)
            os.makedirs(src_dir, exist_ok=True)

            with open(os.path.join(inc_dir, "config.h"), "w", encoding="utf-8") as f:
                f.write("#pragma once\n#define C102_BASE 200\n")

            with open(os.path.join(src_dir, "helper.c"), "w", encoding="utf-8") as f:
                f.write(
                    "#include \"config.h\"\n"
                    "long c102_c_offset(long x) { return x + C102_BASE; }\n"
                )

            with open(os.path.join(src_dir, "engine.cpp"), "w", encoding="utf-8") as f:
                f.write(
                    "#include \"config.h\"\n"
                    "extern \"C\" long c102_c_offset(long x);\n"
                    "template<int Mult>\n"
                    "static long scale_tpl(long v) { return v * Mult; }\n"
                    "extern \"C\" long c102_cmake_entry(long n) {\n"
                    "#ifdef OMNI_C102_FLAG\n"
                    "    return c102_c_offset(scale_tpl<4>(n));\n"
                    "#else\n"
                    "    return -1;\n"
                    "#endif\n"
                    "}\n"
                )

            with open(os.path.join(cm_repo, "CMakeLists.txt"), "w", encoding="utf-8") as f:
                f.write(
                    "cmake_minimum_required(VERSION 3.16)\n"
                    "project(omni_c102 LANGUAGES C CXX)\n"
                    "set(CMAKE_CXX_STANDARD 17)\n"
                    "include_directories(include)\n"
                    "add_definitions(-DOMNI_C102_FLAG=1)\n"
                    "add_library(engine STATIC src/helper.c src/engine.cpp)\n"
                )

            out_base = os.path.join(td, "c102_cmake_lib")
            comp = OmniRepoCompiler()
            try:
                res = comp.compile_repositories(
                    repo_paths=[cm_repo],
                    output_path=out_base,
                    entry_export="c102_cmake_entry",
                    target_os="linux",
                    target_arch="x86_64",
                    backend="native",
                    toolchain_mode="auto",
                )
            finally:
                comp.close()

            self.assertTrue(res["success"])
            fed = res["stages"]["federation"]
            self.assertGreaterEqual(fed["federated_units_count"], 2)
            out_so = res["stages"]["emission"]["artifact_path"]
            self.assertTrue(os.path.exists(out_so))

            # c102_cmake_entry(15) -> 15 * 4 + 200 = 260
            py_probe = (
                "import ctypes, sys; "
                "l = ctypes.CDLL(sys.argv[1]); "
                "l.c102_cmake_entry.argtypes = [ctypes.c_int64]; "
                "l.c102_cmake_entry.restype = ctypes.c_int64; "
                "print(l.c102_cmake_entry(15))"
            )
            if sys.platform == "win32":
                exec_cmd = ["wsl", "python3", "-c", py_probe, _to_wsl(out_so)]
            else:
                exec_cmd = [sys.executable, "-c", py_probe, out_so]
            p = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
            self.assertEqual(p.returncode, 0, msg=p.stderr)
            self.assertEqual(p.stdout.strip(), "260")

    def test_c102_go_module_real_toolchain_federation(self) -> None:
        if not shutil.which("go"):
            self.skipTest("Go toolchain required for live go build federation check")

        with tempfile.TemporaryDirectory() as td:
            go_repo = os.path.join(td, "repo_go_c102")
            os.makedirs(go_repo, exist_ok=True)
            with open(os.path.join(go_repo, "go.mod"), "w", encoding="utf-8") as f:
                f.write("module example.com/omnic102\ngo 1.21\n")
            with open(os.path.join(go_repo, "main.go"), "w", encoding="utf-8") as f:
                f.write(
                    "package main\n"
                    "func go_square_plus(x int64) int64 {\n"
                    "    return (x * x) + 9\n"
                    "}\n"
                    "func main() { println(go_square_plus(5)) }\n"
                )

            out_base = os.path.join(td, "c102_go_app")
            comp = OmniRepoCompiler()
            try:
                res = comp.compile_repositories(
                    repo_paths=[go_repo],
                    output_path=out_base,
                    entry_export="go_square_plus",
                    backend="native",
                    toolchain_mode="federated_lto",
                )
            finally:
                comp.close()

            self.assertTrue(res["success"])
            fed = res["stages"]["federation"]
            self.assertTrue(
                fed.get("wasm_build_units", 0) >= 1 or fed.get("static_archive_units", 0) >= 1,
                msg=fed,
            )
            self.assertTrue(
                any(t.startswith("go:") for t in fed.get("toolchains_invoked", [])),
                msg=fed,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
