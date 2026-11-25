import sys
import unittest

from tests.test_alpha_c96_toolchain_federation import TestAlphaC96ToolchainFederation

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC96ToolchainFederation)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
