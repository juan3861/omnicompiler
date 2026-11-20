import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tests.test_alpha_c63_quad_homeostasis_e2e import TestAlphaC63QuadHomeostasisE2E

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC63QuadHomeostasisE2E)
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
