"""Runner for Alpha-C54 Verification Suite (used by AetherMind_Strict_Auditor.py)."""

import os
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.dirname(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tests.test_alpha_c54_strided_reverse_and_sse2_32bit import TestAlphaC54StridedReverseAndSSE232Bit

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC54StridedReverseAndSSE232Bit)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
