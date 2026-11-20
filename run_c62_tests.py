"""Runner for Alpha-C62 Verification Suite (used by AetherMind_Strict_Auditor.py)."""

import os
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.dirname(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tests.test_alpha_c62_tri_ecosystem_homeostasis import TestAlphaC62TriEcosystemHomeostasis

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC62TriEcosystemHomeostasis)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
