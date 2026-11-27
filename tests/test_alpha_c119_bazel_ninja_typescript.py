"""Alpha-C119 verification: Bazel (BUILD.bazel), Ninja (build.ninja) & TypeScript AOT Native."""

import ctypes
import json
import os
import platform
import subprocess
import sys
import tempfile
import unittest

from frontends.toolchain_federation import FederatedBuildAdapter
from frontends.typescript_frontend import TypeScriptFrontend
from omni_repo_compiler import OmniRepoCompiler


def _win_to_wsl(win_path: str) -> str:
    p = os.path.abspath(win_path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


class TestAlphaC119BazelNinjaTypescript(unittest.TestCase):
    def test_01_bazel_monorepo_build_starlark_deps_glob_and_live_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "core", "inc"), exist_ok=True)
            os.makedirs(os.path.join(tmp, "core", "src"), exist_ok=True)
            os.makedirs(os.path.join(tmp, "app"), exist_ok=True)

            with open(os.path.join(tmp, "MODULE.bazel"), "w", encoding="utf-8") as f:
                f.write('module(name = "c119_bazel_mono", version = "1.0.0")\n')
            with open(os.path.join(tmp, "core", "inc", "core_math.h"), "w", encoding="utf-8") as f:
                f.write("#pragma once\n#ifdef __cplusplus\nextern \"C\" {\n#endif\nint bazel_core_scale(int x);\n#ifdef __cplusplus\n}\n#endif\n")
            with open(os.path.join(tmp, "core", "src", "core_math.c"), "w", encoding="utf-8") as f:
                f.write('#include "core_math.h"\nint bazel_core_scale(int x) { return x * BAZEL_SCALE; }\n')
            with open(os.path.join(tmp, "core", "BUILD.bazel"), "w", encoding="utf-8") as f:
                f.write(
                    'CORE_SRCS = glob(["src/*.c"])\n'
                    'cc_library(\n'
                    '    name = "math",\n'
                    '    srcs = CORE_SRCS,\n'
                    '    hdrs = ["inc/core_math.h"],\n'
                    '    includes = ["inc"],\n'
                    '    defines = ["BAZEL_SCALE=7"],\n'
                    ')\n'
                )
            with open(os.path.join(tmp, "app", "engine.cpp"), "w", encoding="utf-8") as f:
                f.write(
                    '#include "core_math.h"\n'
                    'extern "C" int c119_bazel_entry(int x) { return bazel_core_scale(x) + 11; }\n'
                )
            with open(os.path.join(tmp, "app", "BUILD.bazel"), "w", encoding="utf-8") as f:
                f.write(
                    'cc_binary(\n'
                    '    name = "engine",\n'
                    '    srcs = ["engine.cpp"],\n'
                    '    copts = ["-std=c++17"],\n'
                    '    deps = ["//core:math"],\n'
                    ')\n'
                )

            t_os = "linux" if (sys.platform != "win32" or FederatedBuildAdapter(target_os="linux").wsl_tools.get("gcc")) else "windows"
            adapter = FederatedBuildAdapter(target_os=t_os, target_arch="x86_64")
            ok_bz, units_bz = adapter._collect_bazel_units(tmp)
            self.assertTrue(ok_bz)
            self.assertEqual({os.path.basename(u[0]) for u in units_bz}, {"core_math.c", "engine.cpp"})
            app_unit = next(u for u in units_bz if os.path.basename(u[0]) == "engine.cpp")
            self.assertIn("-DBAZEL_SCALE=7", app_unit[1])
            self.assertIn("-std=c++17", app_unit[1])

            has_linux_c = (
                (sys.platform == "linux" and platform.machine() in ("x86_64", "AMD64") and bool(adapter.native_tools.get("g++") or adapter.native_tools.get("clang++")))
                or (sys.platform == "win32" and bool(adapter.wsl_tools.get("g++") or adapter.wsl_tools.get("clang++")))
            )
            if has_linux_c:
                comp = OmniRepoCompiler()
                try:
                    res = comp.compile_repositories(
                        repo_paths=[tmp],
                        output_path=os.path.join(tmp, "libc119bazel"),
                        target_format="shared_lib",
                        entry_export="c119_bazel_entry",
                        target_os="linux",
                        target_arch="x86_64",
                        toolchain_mode="federated_lto",
                        export_all=True,
                        emit_provenance=False,
                    )
                finally:
                    comp.close()
                so_p = res["stages"]["emission"]["artifact_path"]
                if sys.platform == "linux":
                    lib = ctypes.CDLL(so_p)
                    lib.c119_bazel_entry.argtypes = [ctypes.c_int]
                    lib.c119_bazel_entry.restype = ctypes.c_int
                    self.assertEqual(lib.c119_bazel_entry(4), 39)
                else:
                    subprocess.run(
                        ["wsl", "-e", "python3", "-c", f"import ctypes; l=ctypes.CDLL('{_win_to_wsl(so_p)}'); assert l.c119_bazel_entry(4) == 39"],
                        check=True,
                    )

    def test_02_ninja_build_file_parsing_and_federated_compilation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "inc"), exist_ok=True)
            os.makedirs(os.path.join(tmp, "src"), exist_ok=True)
            with open(os.path.join(tmp, "inc", "nj_cfg.h"), "w", encoding="utf-8") as f:
                f.write("#define NJ_OFFSET 3\n")
            with open(os.path.join(tmp, "src", "nj_helper.c"), "w", encoding="utf-8") as f:
                f.write('#include "nj_cfg.h"\nint c119_ninja_fn(int x) { return (x * NINJA_K) + NJ_OFFSET; }\n')
            with open(os.path.join(tmp, "build.ninja"), "w", encoding="utf-8") as f:
                f.write(
                    "cflags = -O2 -DNINJA_K=13\n"
                    "includes = -Iinc\n"
                    "rule cc\n"
                    "  command = gcc $cflags $includes -c $in -o $out\n"
                    "build obj/nj_helper.o: cc $\n"
                    "  src/nj_helper.c\n"
                )
            adapter = FederatedBuildAdapter(target_os="linux", target_arch="x86_64")
            ok_nj, units_nj = adapter._collect_ninja_units(tmp)
            self.assertTrue(ok_nj)
            self.assertEqual([os.path.basename(u[0]) for u in units_nj], ["nj_helper.c"])
            self.assertIn("-DNINJA_K=13", units_nj[0][1])

            has_linux_c = (
                (sys.platform == "linux" and platform.machine() in ("x86_64", "AMD64") and bool(adapter.native_tools.get("gcc") or adapter.native_tools.get("clang")))
                or (sys.platform == "win32" and bool(adapter.wsl_tools.get("gcc") or adapter.wsl_tools.get("clang")))
            )
            if has_linux_c:
                comp = OmniRepoCompiler()
                try:
                    res = comp.compile_repositories(
                        repo_paths=[tmp],
                        output_path=os.path.join(tmp, "libc119ninja"),
                        target_format="shared_lib",
                        entry_export="c119_ninja_fn",
                        target_os="linux",
                        target_arch="x86_64",
                        toolchain_mode="federated_lto",
                        export_all=True,
                        emit_provenance=False,
                    )
                finally:
                    comp.close()
                so_p = res["stages"]["emission"]["artifact_path"]
                if sys.platform == "linux":
                    lib = ctypes.CDLL(so_p)
                    lib.c119_ninja_fn.argtypes = [ctypes.c_int]
                    lib.c119_ninja_fn.restype = ctypes.c_int
                    self.assertEqual(lib.c119_ninja_fn(3), 42)
                else:
                    subprocess.run(
                        ["wsl", "-e", "python3", "-c", f"import ctypes; l=ctypes.CDLL('{_win_to_wsl(so_p)}'); assert l.c119_ninja_fn(3) == 42"],
                        check=True,
                    )

    def test_03_typescript_aot_native_compilation_and_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "tsconfig.json"), "w", encoding="utf-8") as f:
                f.write('// strict TS AOT config\n{"compilerOptions": {"target": "ES2022", "strict": true}}\n')
            with open(os.path.join(tmp, "helper.ts"), "w", encoding="utf-8") as f:
                f.write(
                    "export const TS_FACTOR: number = 6;\n"
                    "export type KernelScalar = number;\n"
                    "export function ts_mix(a: KernelScalar, b: number): number {\n"
                    "    let acc: number = a * TS_FACTOR + b;\n"
                    "    return acc;\n"
                    "}\n"
                )
            with open(os.path.join(tmp, "app.ts"), "w", encoding="utf-8") as f:
                f.write(
                    'import { ts_mix } from "./helper";\n'
                    "export function omni_main(x: number): number {\n"
                    "    return ts_mix(x, 5) + 2;\n"
                    "}\n"
                )

            cfg = TypeScriptFrontend.load_tsconfig(tmp)
            self.assertEqual(cfg.get("compilerOptions", {}).get("target"), "ES2022")

            comp = OmniRepoCompiler()
            try:
                res = comp.compile_repositories(
                    repo_paths=[tmp],
                    output_path=os.path.join(tmp, "c119_ts_native"),
                    target_format="shared_lib",
                    entry_export="omni_main",
                    toolchain_mode="aot_only",
                    export_all=True,
                    emit_provenance=False,
                )
            finally:
                comp.close()
            self.assertTrue(res["success"])
            art = res["stages"]["emission"]["artifact_path"]
            if sys.platform == "win32":
                lib = ctypes.CDLL(art)
                try:
                    lib.omni_main.argtypes = [ctypes.c_int64]
                    lib.omni_main.restype = ctypes.c_int64
                    lib.ts_mix.argtypes = [ctypes.c_int64, ctypes.c_int64]
                    lib.ts_mix.restype = ctypes.c_int64
                    self.assertEqual(lib.omni_main(4), 31)
                    self.assertEqual(lib.ts_mix(10, 3), 63)
                finally:
                    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
                    k32.FreeLibrary.argtypes = [ctypes.c_void_p]
                    k32.FreeLibrary(ctypes.c_void_p(lib._handle))
            elif sys.platform == "linux":
                lib = ctypes.CDLL(art)
                lib.omni_main.argtypes = [ctypes.c_int64]
                lib.omni_main.restype = ctypes.c_int64
                self.assertEqual(lib.omni_main(4), 31)


if __name__ == "__main__":
    unittest.main()
