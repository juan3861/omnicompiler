"""
Alpha-C96 Empirical Verification Suite:
1. LLVM Bitcode (`.bc` + `.ll`) cross-module PassBuilder O3 LTO fusion via `LLVMBackend.link_bitcode_modules`
   and `OmniRepoCompiler` calling into federated bitcode symbols, executed live via `ctypes.CDLL`.
2. Real C++ template + `compile_commands.json` external toolchain federation (`clang++`/`g++`/WSL2)
   emitting relocatable ELF `.o` / `.bc` and linked seamlessly with Python/Polyglot callers into `.so`.
3. `ToolchainRegistry` discovery & offline `toolchain_mode="aot_only"` deterministic behavior.
"""

import ctypes
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

import llvmlite.binding as llvm

from frontends.toolchain_federation import FederatedBuildAdapter, ToolchainRegistry
from omni_repo_compiler import OmniRepoCompiler


class TestAlphaC96ToolchainFederation(unittest.TestCase):
    def test_01_llvm_bitcode_cross_module_lto_fusion_e2e(self):
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()
        host_triple = llvm.Target.from_default_triple().triple

        # Build two genuine LLVM modules serialized to binary Bitcode (.bc) and text IR (.ll)
        ir_a = f"""
target triple = "{host_triple}"
define i64 @bc_mix_step(i64 %x, i64 %y) {{
  %m = mul i64 %x, 5
  %r = add i64 %m, %y
  ret i64 %r
}}
"""
        ir_b = f"""
target triple = "{host_triple}"
declare i64 @bc_mix_step(i64, i64)
define i64 @bc_fused_kernel(i64 %n) {{
  %a = call i64 @bc_mix_step(i64 %n, i64 11)
  %b = xor i64 %a, 3
  ret i64 %b
}}
"""
        m_a = llvm.parse_assembly(ir_a)
        m_a.verify()
        bc_a = m_a.as_bitcode()

        with tempfile.TemporaryDirectory() as td:
            fed_dir = os.path.join(td, "repo_bitcode")
            py_dir = os.path.join(td, "repo_driver")
            os.makedirs(fed_dir, exist_ok=True)
            os.makedirs(py_dir, exist_ok=True)

            with open(os.path.join(fed_dir, "mix.bc"), "wb") as f:
                f.write(bc_a)
            with open(os.path.join(fed_dir, "kernel.ll"), "w", encoding="utf-8") as f:
                f.write(ir_b)

            with open(os.path.join(py_dir, "driver.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def fed_driver(v: int) -> int:\n"
                    "    return bc_fused_kernel(v) + 100\n"
                )

            ext = ".dll" if platform.system() == "Windows" else (".dylib" if platform.system() == "Darwin" else ".so")
            out_bin = os.path.join(td, f"c96_bc_lto{ext}")
            comp = OmniRepoCompiler()
            try:
                res = comp.compile_repositories(
                    [fed_dir, py_dir],
                    out_bin,
                    target_format="shared_lib",
                    entry_export="fed_driver",
                    export_all=True,
                    toolchain_mode="auto",
                )
                self.assertTrue(res["success"], res)
                fed = res["stages"]["federation"]
                self.assertTrue(fed["cross_lto_fused"])
                self.assertGreaterEqual(fed["bitcode_units"], 2)
                self.assertIn("bc_fused_kernel", fed["exported_symbols"])

                lib = ctypes.CDLL(out_bin)
                try:
                    fn = lib.fed_driver
                    fn.argtypes = [ctypes.c_int64]
                    fn.restype = ctypes.c_int64
                    # ((v * 5 + 11) ^ 3) + 100
                    for v in (0, 4, 15, -3):
                        self.assertEqual(fn(v), (((v * 5) + 11) ^ 3) + 100)
                finally:
                    if platform.system() == "Windows":
                        import _ctypes
                        _ctypes.FreeLibrary(lib._handle)
            finally:
                comp.close()

    def test_02_compile_commands_cpp_template_federation(self):
        adapter = FederatedBuildAdapter(target_os="linux", target_arch="x86_64")
        avail = adapter.available_summary()
        has_linux_cpp = bool(
            (sys.platform != "win32" and (avail["native"].get("g++") or avail["native"].get("clang++")))
            or avail["wsl"].get("g++")
            or avail["wsl"].get("clang++")
        )
        if not has_linux_cpp:
            self.skipTest("No native or WSL2 g++/clang++ available for external C++ template federation")

        cpp_src = """
#include <cstdint>
template <typename T>
static inline T poly_acc(T x, T scale) {
    return (x * scale) + 17;
}
extern "C" int64_t cpp_template_kernel(int64_t x) {
    return poly_acc<int64_t>(x, 6);
}
"""
        # Use workspace-local temp dir on Windows so WSL2 sees /mnt/... cleanly
        base_tmp = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "_c96_wsl_tmp")
        os.makedirs(base_tmp, exist_ok=True)
        try:
            with tempfile.TemporaryDirectory(dir=base_tmp) as td:
                cpp_repo = os.path.join(td, "cpp_lib")
                py_repo = os.path.join(td, "py_app")
                os.makedirs(cpp_repo, exist_ok=True)
                os.makedirs(py_repo, exist_ok=True)

                cpp_file = os.path.join(cpp_repo, "tmpl.cpp")
                with open(cpp_file, "w", encoding="utf-8") as f:
                    f.write(cpp_src)
                with open(os.path.join(cpp_repo, "compile_commands.json"), "w", encoding="utf-8") as f:
                    json.dump(
                        [{"directory": cpp_repo, "command": f"g++ -std=c++17 -O2 -c {cpp_file}", "file": "tmpl.cpp"}],
                        f,
                    )
                with open(os.path.join(py_repo, "app.py"), "w", encoding="utf-8") as f:
                    f.write(
                        "def poly_bridge_entry(v: int) -> int:\n"
                        "    return cpp_template_kernel(v) + 10\n"
                    )

                out_so = os.path.join(td, "libcpp_fed.so")
                comp = OmniRepoCompiler()
                try:
                    res = comp.compile_repositories(
                        [cpp_repo, py_repo],
                        out_so,
                        target_format="shared_lib",
                        entry_export="poly_bridge_entry",
                        target_os="linux",
                        target_arch="x86_64",
                        export_all=True,
                        toolchain_mode="federated_lto",
                    )
                    self.assertTrue(res["success"], res)
                    self.assertGreaterEqual(res["stages"]["federation"]["federated_units_count"], 1)
                    self.assertIn("cpp_template_kernel", res["stages"]["federation"]["exported_symbols"])

                    # Execute compiled Linux .so live (native on Linux, via WSL2 on Windows)
                    if sys.platform != "win32":
                        lib = ctypes.CDLL(out_so)
                        fn = lib.poly_bridge_entry
                        fn.argtypes = [ctypes.c_int64]
                        fn.restype = ctypes.c_int64
                        self.assertEqual(fn(7), 7 * 6 + 17 + 10)
                    else:
                        from frontends.toolchain_federation import _to_wsl_path
                        wsl_so = _to_wsl_path(out_so)
                        cmd = [
                            "wsl", "python3", "-c",
                            f"import ctypes; lib = ctypes.CDLL('{wsl_so}'); "
                            "fn = lib.poly_bridge_entry; fn.argtypes = [ctypes.c_int64]; fn.restype = ctypes.c_int64; "
                            "print(fn(7))",
                        ]
                        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL)
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        self.assertEqual(proc.stdout.strip(), str(7 * 6 + 17 + 10))
                finally:
                    comp.close()
        finally:
            shutil.rmtree(base_tmp, ignore_errors=True)

    def test_03_toolchain_registry_and_aot_only_isolation(self):
        tools = ToolchainRegistry.discover()
        self.assertIn("go", tools)
        self.assertIn("gcc", tools)

        with tempfile.TemporaryDirectory() as td:
            repo_dir = os.path.join(td, "py_only")
            os.makedirs(repo_dir, exist_ok=True)
            with open(os.path.join(repo_dir, "m.py"), "w", encoding="utf-8") as f:
                f.write("def pure_op(x: int) -> int:\n    return x * 3 + 1\n")

            ext = ".dll" if platform.system() == "Windows" else (".dylib" if platform.system() == "Darwin" else ".so")
            out_bin = os.path.join(td, f"aot_only{ext}")
            comp = OmniRepoCompiler()
            try:
                res = comp.compile_repositories(
                    [repo_dir], out_bin, target_format="shared_lib", entry_export="pure_op", toolchain_mode="aot_only"
                )
                self.assertTrue(res["success"])
                self.assertEqual(res["stages"]["federation"]["toolchain_mode"], "aot_only")
                self.assertEqual(res["stages"]["federation"]["federated_units_count"], 0)
            finally:
                comp.close()


if __name__ == "__main__":
    unittest.main()
