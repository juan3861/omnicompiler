import json
import sys
import unittest

from benchmarks.oss_real_library_bench import run_lz4_oss_benchmark
from tests.test_alpha_c114_thinlto_and_oss_lz4 import TestAlphaC114ThinLtoAndOssLz4

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC114ThinLtoAndOssLz4)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    bench_rep = run_lz4_oss_benchmark(iterations=40)
    print(json.dumps(bench_rep, indent=2))
    sys.exit(0 if (res.wasSuccessful() and bench_rep.get("all_passed")) else 1)
