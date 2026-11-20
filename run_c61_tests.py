"""Runner for Alpha-C61 Verification Suite (used by AetherMind_Strict_Auditor.py)."""

import os
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.dirname(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tests.test_alpha_c61_32bit_mul_and_avx2_8lane_pack import TestAlphaC6132BitMulAndAvx28LanePack

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC6132BitMulAndAvx28LanePack)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
