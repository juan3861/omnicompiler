"""
Alpha-C67 Cross-Target Tri-Ecosystem Homeostasis & Multi-Arch ARM64 Verification Suite:
1. True 3-Way Cross-Target Tri-Ecosystem ELF64 Hybrid Linking (`Native` + `GCC -O3` +
   Cross-Target `LLVM x86_64-unknown-linux-gnu`) via Python API & CLI `--homeostasis-overrides`,
   executed natively on Linux CI or via WSL2 on Windows.
2. Cross-Target Windows `PE32+` (`x86_64-pc-windows-msvc` LLVM + Omni Native) Hybrid DLL
   verified by `BinaryStructureAuditor` on both Linux and Windows hosts (+ live DLL call on Windows).
3. Cross-Architecture `ARM64` (`aarch64-unknown-linux-gnu` ELF64 & `aarch64-pc-windows-msvc` PE32+)
   Hybrid Homeostasis (`hybrid:llvm+native`) with `$x`/`$d` mapping symbol stripping,
   `ARM64_CALL26` relocation resolution, and real Unicorn AArch64 CPU execution proof.
4. SOTA Comparative Benchmark `benchmark_heterogeneous_hybrid()` verification.
"""

import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Any

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from compiler.gcc_backend import GCCBackend
from compiler.llvm_backend import LLVMBackend
from compiler.native_codegen import NativeCodeGenerator
from compiler.object_linker import NativeObjectLinker, ObjectModule, load_elf_object
from compiler.ssa_ir import lower_ast_to_ssa
from omni_repo_compiler import OmniRepoCompiler
from validation.silicon_safety_sandbox import SiliconSafetySandbox
import ast


def _unload_cdll(lib: Any) -> None:
    handle = getattr(lib, "_handle", None)
    del lib
    if sys.platform == "win32" and handle:
        import _ctypes
        _ctypes.FreeLibrary(handle)


class TestAlphaC67CrossTargetArm64AndTriHybrid(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="omni_alpha_c67_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_cross_target_3way_tri_ecosystem_elf64_hybrid_and_cli(self):
        """Compiles 3-way hybrid ELF64 (`native`+`gcc`+`llvm`) via API and CLI, running on Linux/WSL2."""
        r1 = os.path.join(self.test_dir, "repo_nat_gcc")
        r2 = os.path.join(self.test_dir, "repo_llvm_app")
        os.makedirs(r1)
        os.makedirs(r2)

        with open(os.path.join(r1, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_nat_gcc", "language": "python", "exports": ["f_nat", "f_gcc"], "dependencies": []}, f)
        with open(os.path.join(r1, "core.py"), "w", encoding="utf-8") as f:
            f.write(
                "def f_nat(x: int) -> int:\n"
                "    return (x * 5) + 11\n\n"
                "def f_gcc(x: int) -> int:\n"
                "    return f_nat(x) + 100\n"
            )

        with open(os.path.join(r2, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_llvm_app", "language": "python", "exports": ["omni_main"], "dependencies": ["repo_nat_gcc"]}, f)
        with open(os.path.join(r2, "app.py"), "w", encoding="utf-8") as f:
            f.write(
                "def omni_main(x: int) -> int:\n"
                "    ans = f_gcc(x) * 3\n"
                '    printf("TRI3=%lld\\n", ans)\n'
                "    return ans % 251\n"
            )

        gcc = GCCBackend(opt_level=3)
        if not gcc.supports_elf64:
            self.skipTest("ELF64 GCC compiler unavailable on host.")

        comp = OmniRepoCompiler(db_path=os.path.join(self.test_dir, "runs.db"))
        try:
            out_bin = os.path.join(self.test_dir, "tri_hybrid_elf")
            res = comp.compile_repositories(
                [r1, r2],
                out_bin,
                target_format="executable",
                target_os="linux",
                entry_export="omni_main",
                backend="homeostasis",
                homeostasis_policy="throughput",
                homeostasis_function_overrides={
                    "f_nat": "native",
                    "f_gcc": "gcc",
                    "omni_main": "llvm",
                },
                audit_nonce="c67-tri-elf",
            )
            self.assertTrue(res["stages"]["formal_audit"]["is_valid"])
            h = res["stages"]["homeostasis"]
            self.assertTrue(h["heterogeneous_link"])
            self.assertEqual(h["hybrid_emitters_used"], ["gcc", "llvm", "native"])
            self.assertEqual(h["binary_emitter_engine"], "hybrid:gcc+llvm+native")
            self.assertIn("x86_64", h["llvm_target_triple"])
            self.assertIn("linux", h["llvm_target_triple"])

            def _exec_elf(path_str: str, arg_s: str):
                if sys.platform == "win32":
                    w_p = "/mnt/" + path_str[0].lower() + path_str[2:].replace("\\", "/")
                    return subprocess.run(
                        ["wsl", "bash", "-c", f"chmod +x '{w_p}' && '{w_p}' {arg_s}"],
                        capture_output=True, text=True, timeout=25,
                    )
                os.chmod(path_str, 0o755)
                return subprocess.run([path_str, arg_s], capture_output=True, text=True, timeout=10)

            p_api = _exec_elf(out_bin, "12")
            self.assertIn("TRI3=513", p_api.stdout)
            self.assertEqual(p_api.returncode, 513 % 251)

            # Verify CLI `--homeostasis-overrides` end-to-end
            out_cli = os.path.join(self.test_dir, "tri_cli_elf")
            p_cli_build = subprocess.run(
                [
                    sys.executable,
                    os.path.join(ROOT_DIR, "omni_repo_compiler.py"),
                    "--repos", f"{r1},{r2}",
                    "--output", out_cli,
                    "--format", "executable",
                    "--target-os", "linux",
                    "--backend", "homeostasis",
                    "--homeostasis-policy", "throughput",
                    "--homeostasis-overrides", "f_nat=native,f_gcc=gcc,omni_main=llvm",
                    "--audit-nonce", "c67-cli",
                ],
                cwd=ROOT_DIR,
                capture_output=True,
                text=True,
                timeout=45,
            )
            self.assertEqual(p_cli_build.returncode, 0, p_cli_build.stderr)
            p_cli_run = _exec_elf(out_cli, "12")
            self.assertIn("TRI3=513", p_cli_run.stdout)
            self.assertEqual(p_cli_run.returncode, 513 % 251)
        finally:
            comp.close()

    def test_02_cross_target_windows_pe64_llvm_native_hybrid_from_any_host(self):
        """Compiles hybrid Windows PE32+ DLL (`llvm`+`native`) cross-platform and validates structure/execution."""
        r_a = os.path.join(self.test_dir, "win_a")
        os.makedirs(r_a)
        with open(os.path.join(r_a, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "win_a", "language": "python", "exports": ["f_nat", "f_win_llvm", "omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_a, "mod.py"), "w", encoding="utf-8") as f:
            f.write(
                "def f_nat(x: int) -> int:\n"
                "    return (x * 5) + 11\n\n"
                "def f_win_llvm(x: int) -> int:\n"
                "    return f_nat(x) * 4\n\n"
                "def omni_main() -> int:\n"
                "    return f_win_llvm(10)\n"
            )

        comp = OmniRepoCompiler(db_path=os.path.join(self.test_dir, "win_runs.db"))
        try:
            out_dll = os.path.join(self.test_dir, "cross_hybrid.dll")
            res = comp.compile_repositories(
                [r_a],
                out_dll,
                target_format="shared_lib",
                target_os="windows",
                target_arch="x86_64",
                entry_export="omni_main",
                backend="homeostasis",
                homeostasis_policy="throughput",
                homeostasis_function_overrides={
                    "f_nat": "native",
                    "f_win_llvm": "llvm",
                    "omni_main": "llvm",
                },
                audit_nonce="c67-win-pe",
            )
            self.assertTrue(res["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res["stages"]["formal_audit"]["format"], "PE32+")
            self.assertEqual(res["stages"]["formal_audit"]["machine_arch"], "x86-64")
            h = res["stages"]["homeostasis"]
            self.assertTrue(h["heterogeneous_link"])
            self.assertEqual(h["hybrid_emitters_used"], ["llvm", "native"])
            self.assertIn("windows", h["llvm_target_triple"])

            if sys.platform == "win32":
                lib = ctypes.CDLL(out_dll)
                try:
                    lib.f_win_llvm.argtypes = [ctypes.c_int64]
                    lib.f_win_llvm.restype = ctypes.c_int64
                    self.assertEqual(lib.f_win_llvm(10), (10 * 5 + 11) * 4)
                finally:
                    _unload_cdll(lib)
        finally:
            comp.close()

    def test_03_cross_arch_arm64_hybrid_llvm_native_unicorn_silicon_execution(self):
        """Tests ARM64 (`aarch64`) hybrid LLVM+Native ELF64 & PE32+ compilation, $x filtering, and Unicorn execution."""
        r_arm = os.path.join(self.test_dir, "repo_arm64")
        os.makedirs(r_arm)
        with open(os.path.join(r_arm, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_arm64", "language": "python", "exports": ["arm_leaf", "arm_top", "omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_arm, "arm_mod.py"), "w", encoding="utf-8") as f:
            f.write(
                "def arm_leaf(x: int) -> int:\n"
                "    return (x * 5) + 11\n\n"
                "def arm_top(x: int) -> int:\n"
                "    return arm_leaf(x) * 3\n\n"
                "def omni_main(x: int) -> int:\n"
                "    return arm_top(x)\n"
            )

        comp = OmniRepoCompiler(db_path=os.path.join(self.test_dir, "arm_runs.db"))
        try:
            for tgt_os, expected_fmt, fname, triple_sub in (
                ("linux", "ELF64", "hybrid_arm64_elf", "aarch64"),
                ("windows", "PE32+", "hybrid_arm64.exe", "aarch64"),
            ):
                out_p = os.path.join(self.test_dir, fname)
                res = comp.compile_repositories(
                    [r_arm],
                    out_p,
                    target_format="executable",
                    target_os=tgt_os,
                    target_arch="arm64",
                    entry_export="omni_main",
                    backend="homeostasis",
                    homeostasis_policy="throughput",
                    homeostasis_function_overrides={
                        "arm_leaf": "native",
                        "arm_top": "llvm",
                        "omni_main": "llvm",
                    },
                    audit_nonce=f"c67-arm64-{tgt_os}",
                )
                self.assertTrue(res["stages"]["formal_audit"]["is_valid"])
                self.assertEqual(res["stages"]["formal_audit"]["format"], expected_fmt)
                self.assertEqual(res["stages"]["formal_audit"]["machine_arch"], "ARM64")
                self.assertTrue(res["stages"]["preflight_safety"]["is_safe_for_silicon"])
                h = res["stages"]["homeostasis"]
                self.assertTrue(h["heterogeneous_link"])
                self.assertEqual(h["hybrid_emitters_used"], ["llvm", "native"])
                self.assertIn(triple_sub, h["llvm_target_triple"])
                # Mapping symbols ($x, $d) must not leak into exported symbol table
                self.assertFalse(any(s.startswith("$") for s in res["stages"]["linking"]["exported_symbols"]))

            # Direct Unicorn AArch64 hardware simulation check on linked LLVM+Native ARM64 image
            with open(os.path.join(r_arm, "arm_mod.py"), "r", encoding="utf-8") as sf:
                defs = [n for n in ast.parse(sf.read()).body if isinstance(n, ast.FunctionDef)]
            ssa_leaf = lower_ast_to_ssa(defs[0], optimize=True)
            ssa_top = lower_ast_to_ssa(defs[1], optimize=True)

            ll_arm = LLVMBackend(opt_level=3, target_triple="aarch64-unknown-linux-gnu")
            obj_top = ll_arm.emit_object(ll_arm.compile_ir(ll_arm.ssa_module_to_llvm_ir([ssa_top]), optimize=True))
            m_llvm = load_elf_object(obj_top, repo_name="arm_llvm")
            self.assertNotIn("$x", m_llvm.symbols)

            art_leaf = NativeCodeGenerator(arch="arm64", target_os="linux").compile_ssa(ssa_leaf)
            m_nat = ObjectModule("arm_nat")
            m_nat.add_symbol("arm_leaf", art_leaf.code_bytes, is_exported=True)

            lnk = NativeObjectLinker()
            lnk.add_module(m_llvm)
            lnk.add_module(m_nat)
            link_res = lnk.link(entry_symbol="arm_top")
            self.assertGreaterEqual(link_res["relocations_applied"], 1)

            emu = SiliconSafetySandbox().emulate_arm64(
                link_res["combined_code"],
                args=[10],
                start_offset=link_res["global_symbols"]["arm_top"],
            )
            self.assertTrue(emu.is_safe_for_silicon)
            self.assertEqual(emu.return_value, ((10 * 5 + 11) * 3))
        finally:
            comp.close()

    def test_04_comparative_benchmark_heterogeneous_hybrid_convergence(self):
        """Verifies SOTA comparative benchmark `benchmark_heterogeneous_hybrid()` executes cleanly."""
        from external_component_candidates.benchmarks.comparative_benchmark import benchmark_heterogeneous_hybrid
        hyb = benchmark_heterogeneous_hybrid()
        self.assertTrue(hyb["heterogeneous_link"])
        self.assertTrue(hyb["binary_emitter_engine"].startswith("hybrid:"))
        self.assertEqual(hyb["result"], ((10 * 7 + 13) + 100) * 3)


if __name__ == "__main__":
    unittest.main()
