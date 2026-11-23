"""Runner for Alpha-C80 test suite."""
import sys
import unittest

from tests.test_alpha_c80_industrial_top1_suite import (
    TestAlphaC80IndustrialTop1Suite,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC80IndustrialTop1Suite
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
