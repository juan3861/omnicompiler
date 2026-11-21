import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tests.test_alpha_c64_hardware_fma_avx512_and_dual_gcc import TestAlphaC64HardwareFmaAvx512AndDualGcc

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC64HardwareFmaAvx512AndDualGcc)
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
