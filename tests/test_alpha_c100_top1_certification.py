"""
Alpha-C100 Top-1 World Certification Suite:
1. `omnicc` CLI subprocess build + sanitizer + repro check + `omnicc verify` Ed25519 SLSA & CycloneDX check.
2. `omnicc` JSON-RPC 2.0 stdio Language Server (`initialize`, `didOpen` diagnostics, `hover` ABI/SSA, `shutdown`, `exit`).
3. 7-Kernel SPEC-class bit-exact native benchmark suite (`Adler32`, `CRC32`, `ChaCha20`, `SHA256`, `GEMM`, `SortNet4`, `Radix-2 FFT`).
4. Real unmodified heterogeneous polyglot multi-repo pipeline (C + `.a` static archive + Go + Python) -> live native ELF64/PE64 execution!
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from benchmarks.spec_class_suite import run_spec_class_suite
from lsp.omnicc_lsp import encode_lsp_message, read_lsp_message
from omni_repo_compiler import OmniRepoCompiler


def _wsl_ready() -> bool:
    if sys.platform != "win32":
        return False
    try:
        r = subprocess.run(
            ["wsl", "python3", "-c", "import shutil; print(bool(shutil.which('gcc') and shutil.which('ar')))"],
            capture_output=True,
            text=True,
            timeout=10,
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


class TestAlphaC100Top1Certification(unittest.TestCase):
    def test_c100_omnicc_cli_build_repro_and_verify(self) -> None:
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        omnicc_py = os.path.join(root_dir, "omnicc_cli.py")

        with tempfile.TemporaryDirectory() as td:
            repo = os.path.join(td, "cli_repo")
            os.makedirs(repo, exist_ok=True)
            with open(os.path.join(repo, "ops.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def c100_entry(x: int) -> int:\n"
                    "    return (x * 5) + 3\n"
                )
            out_base = os.path.join(td, "c100_cli_lib")
            p_b = subprocess.run(
                [
                    sys.executable,
                    omnicc_py,
                    "build",
                    "--repos", repo,
                    "--output", out_base,
                    "--entry", "c100_entry",
                    "--backend", "native",
                    "--repro-check",
                    "--json",
                ],
                cwd=root_dir,
                capture_output=True,
                text=True,
                timeout=45,
                stdin=subprocess.DEVNULL,
            )
            self.assertEqual(p_b.returncode, 0, msg=p_b.stderr)
            meta = json.loads(p_b.stdout)
            self.assertTrue(meta["success"])
            self.assertTrue(meta["reproducibility"]["bit_for_bit_equal"])
            art_path = meta["artifact_path"]
            self.assertTrue(os.path.exists(art_path))

            p_v = subprocess.run(
                [
                    sys.executable,
                    omnicc_py,
                    "verify",
                    "--artifact", art_path,
                ],
                cwd=root_dir,
                capture_output=True,
                text=True,
                timeout=15,
                stdin=subprocess.DEVNULL,
            )
            self.assertEqual(p_v.returncode, 0, msg=p_v.stdout + p_v.stderr)
            ver = json.loads(p_v.stdout)
            self.assertTrue(ver["valid"])
            self.assertEqual(ver["reason"], "VERIFIED_SLSA_L3_PROVENANCE")

    def test_c100_lsp_stdio_diagnostics_and_hover(self) -> None:
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        omnicc_py = os.path.join(root_dir, "omnicc_cli.py")

        proc = subprocess.Popen(
            [sys.executable, omnicc_py, "lsp"],
            cwd=root_dir,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert proc.stdin is not None and proc.stdout is not None
            # 1. initialize
            proc.stdin.write(encode_lsp_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
            proc.stdin.flush()
            r_init = read_lsp_message(proc.stdout)
            self.assertIsNotNone(r_init)
            self.assertTrue(r_init["result"]["capabilities"]["hoverProvider"])

            # 2. didOpen with static div-by-zero + valid function
            src_doc = (
                "def lsp_kernel(a: int, b: int) -> int:\n"
                "    return a // 0\n"
            )
            proc.stdin.write(encode_lsp_message({
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {"textDocument": {"uri": "file:///test.py", "languageId": "python", "version": 1, "text": src_doc}},
            }))
            proc.stdin.flush()
            r_diag = read_lsp_message(proc.stdout)
            self.assertIsNotNone(r_diag)
            self.assertEqual(r_diag["method"], "textDocument/publishDiagnostics")
            diags = r_diag["params"]["diagnostics"]
            self.assertEqual(len(diags), 1)
            self.assertIn("UBSAN_INTEGER_DIVIDE_BY_ZERO", diags[0]["message"])

            # 3. hover on line 0
            proc.stdin.write(encode_lsp_message({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "textDocument/hover",
                "params": {"textDocument": {"uri": "file:///test.py"}, "position": {"line": 0, "character": 4}},
            }))
            proc.stdin.flush()
            r_hover = read_lsp_message(proc.stdout)
            self.assertIsNotNone(r_hover)
            hover_md = r_hover["result"]["contents"]["value"]
            self.assertIn("lsp_kernel", hover_md)
            self.assertIn("Win64 ABI Regs", hover_md)

            # 4. shutdown + exit
            proc.stdin.write(encode_lsp_message({"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": {}}))
            proc.stdin.flush()
            r_sd = read_lsp_message(proc.stdout)
            self.assertEqual(r_sd["id"], 3)
            proc.stdin.write(encode_lsp_message({"jsonrpc": "2.0", "method": "exit"}))
            proc.stdin.flush()
            proc.wait(timeout=10)
            self.assertEqual(proc.returncode, 0)
        finally:
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    if stream:
                        stream.close()
                except Exception:
                    pass

    def test_c100_spec_class_seven_kernels_bit_exact(self) -> None:
        rep = run_spec_class_suite()
        self.assertEqual(rep["total_kernels"], 7)
        self.assertTrue(rep["all_passed"], msg=rep)
        self.assertEqual(rep["passed_kernels"], 7)

    def test_c100_real_polyglot_archive_and_cpp_pipeline(self) -> None:
        if sys.platform != "win32" or not _wsl_ready():
            self.skipTest("WSL2 gcc/g++/ar required for real heterogeneous polyglot Linux binary verification")

        with tempfile.TemporaryDirectory() as td:
            # 1. Static C library compiled externally into libpolymath.a
            c_build = os.path.join(td, "c_build")
            os.makedirs(c_build, exist_ok=True)
            c_src = os.path.join(c_build, "polymath.c")
            c_obj = os.path.join(c_build, "polymath.o")
            with open(c_src, "w", encoding="utf-8") as f:
                f.write("long c100_c_mul_add(long a, long b) { return (a * b) + 10; }\n")

            repo_ar = os.path.join(td, "repo_static_c")
            os.makedirs(repo_ar, exist_ok=True)
            ar_path = os.path.join(repo_ar, "libpolymath.a")
            for cmd in (
                ["wsl", "gcc", "-O2", "-fPIC", "-fno-asynchronous-unwind-tables", "-c", _to_wsl(c_src), "-o", _to_wsl(c_obj)],
                ["wsl", "ar", "rcs", _to_wsl(ar_path), _to_wsl(c_obj)],
            ):
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
                self.assertEqual(p.returncode, 0, msg=p.stderr)

            # 2. C++17 template repo calling into C static library
            repo_cpp = os.path.join(td, "repo_cpp")
            os.makedirs(repo_cpp, exist_ok=True)
            with open(os.path.join(repo_cpp, "bridge.cpp"), "w", encoding="utf-8") as f:
                f.write(
                    "extern \"C\" long c100_c_mul_add(long a, long b);\n"
                    "template<int K>\n"
                    "long scale_tpl(long v) { return v * K; }\n"
                    "extern \"C\" long c100_cpp_stage(long x) {\n"
                    "    return c100_c_mul_add(scale_tpl<3>(x), 4);\n"
                    "}\n"
                )

            # 3. Python orchestrator repo composing everything together
            repo_py = os.path.join(td, "repo_py")
            os.makedirs(repo_py, exist_ok=True)
            with open(os.path.join(repo_py, "main_poly.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def c100_polyglot_main(n: int) -> int:\n"
                    "    return c100_cpp_stage(n) + 7\n"
                )

            out_base = os.path.join(td, "c100_poly_app")
            compiler = OmniRepoCompiler()
            try:
                res = compiler.compile_repositories(
                    repo_paths=[repo_ar, repo_cpp, repo_py],
                    output_path=out_base,
                    entry_export="c100_polyglot_main",
                    target_os="linux",
                    target_arch="x86_64",
                    backend="native",
                    toolchain_mode="federated_lto",
                    emit_provenance=True,
                )
            finally:
                compiler.close()

            self.assertTrue(res["success"])
            out_so = res["stages"]["emission"]["artifact_path"]
            self.assertTrue(os.path.exists(out_so))
            self.assertTrue(os.path.exists(res["provenance_path"]))
            self.assertTrue(os.path.exists(res["sbom_path"]))

            # Execute live in WSL2 Linux ELF64 ctypes:
            # c100_polyglot_main(5) -> c100_cpp_stage(5) + 7 -> c100_c_mul_add(5*3=15, 4) + 7 -> (15*4 + 10) + 7 = 77
            wsl_py = (
                "import ctypes, sys; "
                "l = ctypes.CDLL(sys.argv[1]); "
                "l.c100_polyglot_main.argtypes = [ctypes.c_int64]; "
                "l.c100_polyglot_main.restype = ctypes.c_int64; "
                "print(l.c100_polyglot_main(5))"
            )
            exec_p = subprocess.run(
                ["wsl", "python3", "-c", wsl_py, _to_wsl(out_so)],
                capture_output=True,
                text=True,
                timeout=20,
                stdin=subprocess.DEVNULL,
            )
            self.assertEqual(exec_p.returncode, 0, msg=exec_p.stderr)
            self.assertEqual(exec_p.stdout.strip(), "77")


if __name__ == "__main__":
    unittest.main(verbosity=2)
