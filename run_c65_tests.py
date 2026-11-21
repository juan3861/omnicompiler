import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tests.test_alpha_c65_pgo_avx512_autofusion_and_benchmarks import TestAlphaC65PgoAvx512AutofusionAndBenchmarks

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC65PgoAvx512AutofusionAndBenchmarks)
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
