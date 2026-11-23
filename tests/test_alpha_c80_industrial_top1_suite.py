"""
Alpha-C80: Industrial Top-1 Verification Suite Unit Test.
"""

import unittest

from benchmarks.industrial_top1_suite import run_industrial_suite


class TestAlphaC80IndustrialTop1Suite(unittest.TestCase):
    def test_01_industrial_polybench_rbe_and_polyglot_manifests(self):
        report = run_industrial_suite()
        self.assertEqual(report["kernels"]["_polybench_gemm_kernel"]["verified_value"], 75794800)
        self.assertEqual(report["kernels"]["_jacobi_1d_kernel"]["verified_value"], 1354)
        self.assertEqual(report["kernels"]["_crypto_fnv_mix_kernel"]["verified_value"], 573974629)
        self.assertEqual(report["rbe_cas"]["actions"], 7)
        self.assertGreater(report["rbe_cas"]["speedup_x"], 1.0)
        self.assertEqual(report["polyglot_manifest_build"]["discovered_repos"], 4)
        self.assertEqual(
            report["polyglot_manifest_build"]["repo_types"],
            ["go", "python", "rust", "typescript"],
        )
