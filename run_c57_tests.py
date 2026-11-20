"""Runner for Alpha-C57 Verification Suite (used by AetherMind_Strict_Auditor.py)."""

import os
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.dirname(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tests.test_alpha_c57_coupled_2x2_and_arm64_neon import TestAlphaC57Coupled2x2AndArm64Neon

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC57Coupled2x2AndArm64Neon)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
