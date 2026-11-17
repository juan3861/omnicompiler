import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmarks.top100_ceiling_audit import run_top100_ceiling_audit

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI_PATH = os.path.join(REPO_ROOT, "omnicompiler_cli.py")


class TestAlphaC38CliAndTop100CeilingAudit(unittest.TestCase):
    def test_01_cli_compile_native_llvm_and_wasm_backends(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ext = ".dll" if sys.platform == "win32" else ".so"
            for bk, fmt, fname in [
                ("native", "shared_lib", f"cli_nat{ext}"),
                ("llvm", "shared_lib", f"cli_ll{ext}"),
                ("wasm", "shared_lib", "cli_w.wasm"),
            ]:
                out_f = os.path.join(tmpdir, fname)
                cp = subprocess.run(
                    [
                        sys.executable, CLI_PATH, "compile",
                        "--backend", bk,
                        "--format", fmt,
                        "-o", out_f,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=REPO_ROOT,
                )
                self.assertEqual(cp.returncode, 0, f"CLI compile backend={bk} failed:\n{cp.stdout}\n{cp.stderr}")
                self.assertTrue(os.path.exists(out_f), f"CLI output missing: {out_f}")
                self.assertGreater(os.path.getsize(out_f), 0)
                self.assertIn("STAGE 3B: Z3 SEP/BOUNDS", cp.stdout)
                self.assertIn("COMPLETE: 100% PROVED", cp.stdout)

    def test_02_top100_ceiling_audit_16_gears_and_benchmarks(self):
        report = run_top100_ceiling_audit(refresh_github=False)
        self.assertEqual(report["top100_count"], 100)
        self.assertEqual(report["omnicompiler_gear_score"], 18)
        self.assertEqual(report["max_gear_score"], 18)
        self.assertTrue(all(g["active"] for g in report["gears"]), report["gears"])

        bench = report["benchmarks"]
        self.assertTrue(bench["parity_ok"], bench)
        self.assertGreaterEqual(bench["native_vs_cpython_x"], 2.0)
        self.assertGreaterEqual(bench["llvm_vs_cpython_x"], 2.0)
        self.assertGreaterEqual(bench["salsa_cold_misses"], 1)
        self.assertGreaterEqual(bench["salsa_warm_hits"], 1)
        self.assertTrue(os.path.exists(report["markdown_report_path"]))
        self.assertGreater(os.path.getsize(report["markdown_report_path"]), 500)


if __name__ == "__main__":
    unittest.main()
