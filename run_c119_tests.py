import sys
import unittest

from tests.test_alpha_c119_bazel_ninja_typescript import TestAlphaC119BazelNinjaTypescript

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC119BazelNinjaTypescript)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
