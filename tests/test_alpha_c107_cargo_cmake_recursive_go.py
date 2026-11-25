"""Alpha-C107 verification: Cargo.toml workspace resolver, recursive CMakeLists.txt, and Go federation."""

import ctypes
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

import wasmtime

from compiler.object_linker import NativeObjectLinker, load_elf_object
from frontends.toolchain_federation import FederatedBuildAdapter


def _win_to_wsl(win_path: str) -> str:
    p = os.path.abspath(win_path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


class TestAlphaC107CargoCMakeGoFederation(unittest.TestCase):
    def test_01_cargo_toml_multi_crate_workspace_topological_resolution(self):
        adapter = FederatedBuildAdapter(target_os="linux" if sys.platform != "win32" else "windows")
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "Cargo.toml"), "w", encoding="utf-8") as f:
                f.write(
                    '[workspace]\n'
                    'members = ["crates/*"]\n'
                    '[workspace.dependencies]\n'
                    'core-math = { path = "crates/core_math" }\n'
                )
            core_dir = os.path.join(tmp, "crates", "core_math", "src")
            app_dir = os.path.join(tmp, "crates", "app_engine", "src")
            os.makedirs(core_dir, exist_ok=True)
            os.makedirs(app_dir, exist_ok=True)
            with open(os.path.join(tmp, "crates", "core_math", "Cargo.toml"), "w", encoding="utf-8") as f:
                f.write('[package]\nname = "core-math"\nversion = "0.1.0"\nedition = "2021"\n')
            with open(os.path.join(core_dir, "lib.rs"), "w", encoding="utf-8") as f:
                f.write("#[no_mangle]\npub extern \"C\" fn core_add(a: i32, b: i32) -> i32 { a + b }\n")
            with open(os.path.join(tmp, "crates", "app_engine", "Cargo.toml"), "w", encoding="utf-8") as f:
                f.write(
                    '[package]\nname = "app-engine"\nversion = "0.1.0"\nedition = "2021"\n'
                    '[dependencies]\ncore-math = { workspace = true }\n'
                )
            with open(os.path.join(app_dir, "lib.rs"), "w", encoding="utf-8") as f:
                f.write("#[no_mangle]\npub extern \"C\" fn app_compute(x: i32) -> i32 { core_math::core_add(x, 42) }\n")

            info = adapter.inspect_cargo_workspace(tmp)
            self.assertTrue(info["has_cargo"])
            self.assertTrue(info["is_workspace"])
            ordered_names = [c["crate_name"] for c in info["ordered_crates"]]
            self.assertEqual(ordered_names, ["core_math", "app_engine"])
            self.assertIn(("app_engine", "core_math"), info["path_edges"])

            if adapter.native_tools.get("rustc") or adapter.wsl_tools.get("rustc"):
                arts = adapter._compile_cargo_workspace(tmp, "cargo_ws_demo")
                self.assertEqual(len(arts), 2)
                self.assertEqual(arts[0].language, "rust")
                self.assertGreater(len(arts[0].payload), 0)

    def test_02_hierarchical_cmake_add_subdirectory_glob_and_var_substitution(self):
        with tempfile.TemporaryDirectory() as tmp:
            inc_dir = os.path.join(tmp, "include")
            src_dir = os.path.join(tmp, "src")
            sub_dir = os.path.join(tmp, "submod")
            os.makedirs(inc_dir, exist_ok=True)
            os.makedirs(src_dir, exist_ok=True)
            os.makedirs(sub_dir, exist_ok=True)

            with open(os.path.join(inc_dir, "c107_cfg.h"), "w", encoding="utf-8") as f:
                f.write("#pragma once\nextern \"C\" int submod_step(int x);\n")
            with open(os.path.join(src_dir, "driver.cpp"), "w", encoding="utf-8") as f:
                f.write(
                    "#include \"c107_cfg.h\"\n"
                    "extern \"C\" int c107_cmake_entry(int x) { return submod_step(x) * MULTIPLIER + 1; }\n"
                )
            with open(os.path.join(sub_dir, "sub_impl.cpp"), "w", encoding="utf-8") as f:
                f.write("extern \"C\" int submod_step(int x) { return x + 5; }\n")
            with open(os.path.join(sub_dir, "CMakeLists.txt"), "w", encoding="utf-8") as f:
                f.write("set(SUB_SRCS sub_impl.cpp)\nadd_library(submod OBJECT ${SUB_SRCS})\n")
            with open(os.path.join(tmp, "CMakeLists.txt"), "w", encoding="utf-8") as f:
                f.write(
                    "cmake_minimum_required(VERSION 3.16)\n"
                    "project(c107_hier LANGUAGES CXX)\n"
                    "set(CMAKE_CXX_STANDARD 17)\n"
                    "add_definitions(-DMULTIPLIER=7)\n"
                    "include_directories(${PROJECT_SOURCE_DIR}/include)\n"
                    "file(GLOB DRIVER_SRCS \"src/*.cpp\")\n"
                    "add_subdirectory(submod)\n"
                    "add_library(c107lib SHARED ${DRIVER_SRCS})\n"
                )

            adapter = FederatedBuildAdapter(target_os="linux", target_arch="x86_64")
            ok, units = adapter._collect_cmake_units(tmp)
            self.assertTrue(ok)
            basenames = {os.path.basename(u[0]) for u in units}
            self.assertIn("driver.cpp", basenames)
            self.assertIn("sub_impl.cpp", basenames)
            flat_flags = [fl for _, fls in units for fl in fls]
            self.assertIn("-DMULTIPLIER=7", flat_flags)

            arts = adapter.collect_federated_artifacts(
                [SimpleNamespace(repo_path=tmp, repo_name="c107_cmake_hier")],
                toolchain_mode="federated_lto",
            )
            has_linux_cpp = (
                (sys.platform == "linux" and platform.machine() in ("x86_64", "AMD64") and bool(adapter.native_tools.get("g++")))
                or (sys.platform == "win32" and bool(adapter.wsl_tools.get("g++")))
            )
            if has_linux_cpp and len(arts) >= 2:
                linker = NativeObjectLinker()
                for art in arts:
                    if art.object_format == "elf":
                        linker.add_module(load_elf_object(art.payload, repo_name=art.repo_name))
                so_out = os.path.join(tmp, "libc107cmake.so")
                linker.emit_linked_shared_library(so_out, export_name="c107_cmake_entry", target_format="elf_so")
                if sys.platform == "linux":
                    lib = ctypes.CDLL(so_out)
                    lib.c107_cmake_entry.argtypes = [ctypes.c_int]
                    lib.c107_cmake_entry.restype = ctypes.c_int
                    self.assertEqual(lib.c107_cmake_entry(3), 57)  # (3+5)*7 + 1 = 57
                else:
                    res = subprocess.run(
                        [
                            "wsl", "-e", "python3", "-c",
                            f"import ctypes; l=ctypes.CDLL('{_win_to_wsl(so_out)}'); "
                            "l.c107_cmake_entry.argtypes=[ctypes.c_int]; l.c107_cmake_entry.restype=ctypes.c_int; "
                            "v=l.c107_cmake_entry(3); assert v==57, v; print('C107_CMAKE_OK', v)",
                        ],
                        capture_output=True, text=True, check=True,
                    )
                    self.assertIn("C107_CMAKE_OK 57", res.stdout)

    def test_03_go_module_real_wasip1_execution_via_wasmtime(self):
        target_os = "windows" if sys.platform == "win32" else ("macos" if sys.platform == "darwin" else "linux")
        adapter = FederatedBuildAdapter(target_os=target_os)
        if not adapter.native_tools.get("go") and not adapter.wsl_tools.get("go"):
            self.fail("Expected `go` toolchain installed for Alpha-C107 validation")

        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "go.mod"), "w", encoding="utf-8") as f:
                f.write("module example.com/c107go\n\ngo 1.21\n")
            with open(os.path.join(tmp, "main.go"), "w", encoding="utf-8") as f:
                f.write(
                    "package main\n"
                    "import \"fmt\"\n"
                    "func fib(n int) int { if n <= 1 { return n }; return fib(n-1) + fib(n-2) }\n"
                    "func main() { fmt.Printf(\"C107_GO_WASI=%d\\n\", fib(12)) }\n"
                )
            art = adapter._compile_go_module(tmp, "c107_go_repo")
            self.assertIsNotNone(art)
            assert art is not None
            self.assertEqual(art.language, "go")
            self.assertEqual(art.artifact_kind, "wasm_module")
            self.assertEqual(art.payload[:4], b"\x00asm")

            stdout_log = os.path.join(tmp, "wasi_stdout.txt")
            engine = wasmtime.Engine()
            store = wasmtime.Store(engine)
            wasi_cfg = wasmtime.WasiConfig()
            wasi_cfg.stdout_file = stdout_log
            store.set_wasi(wasi_cfg)
            mod = wasmtime.Module(engine, art.payload)
            linker = wasmtime.Linker(engine)
            linker.define_wasi()
            inst = linker.instantiate(store, mod)
            start_fn = inst.exports(store)["_start"]
            try:
                start_fn(store)
            except wasmtime.ExitTrap as trap:
                self.assertEqual(trap.code, 0)
            with open(stdout_log, "r", encoding="utf-8") as sf:
                out_txt = sf.read()
            self.assertIn("C107_GO_WASI=144", out_txt)


if __name__ == "__main__":
    unittest.main()
