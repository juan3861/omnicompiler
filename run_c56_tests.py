"""Runner for Alpha-C56 Verification Suite (used by AetherMind_Strict_Auditor.py)."""

import os
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.dirname(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tests.test_alpha_c56_prefix_scan_linear_recurrence_and_sse2_hreduce import (
    TestAlphaC56PrefixScanLinearRecurrenceAndSSE2HReduce,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC56PrefixScanLinearRecurrenceAndSSE2HReduce)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
