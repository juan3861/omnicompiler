"""Alpha-C109 verification: Multi-TU OSS C++17 CMake corpus live certification vs gcc -O3."""

import unittest

from benchmarks.oss_corpus_bench import run_oss_corpus_certification


class TestAlphaC109OssRealCorpus(unittest.TestCase):
    def test_01_multi_tu_oss_cpp17_lz77_raii_vs_gcc_o3_parity(self):
        rep = run_oss_corpus_certification()
        self.assertTrue(rep["all_passed"], f"OSS corpus certification failed: {rep}")
        self.assertTrue(rep["bit_exact_parity"])
        self.assertEqual(rep["cmake_units_discovered"], 3)
        self.assertTrue(rep["gc_sections_applied"])
        self.assertTrue(rep["icf_folding_applied"])


if __name__ == "__main__":
    unittest.main()
