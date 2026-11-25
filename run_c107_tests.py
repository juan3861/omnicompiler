import sys
import unittest

from tests.test_alpha_c107_cargo_cmake_recursive_go import TestAlphaC107CargoCMakeGoFederation

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC107CargoCMakeGoFederation)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
