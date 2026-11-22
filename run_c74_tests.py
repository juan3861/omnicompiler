"""Runner for Alpha-C74 test suite."""
import sys
import unittest

from tests.test_alpha_c74_generics_monomorphization_and_try_except import (
    TestAlphaC74GenericsMonomorphizationAndTryExcept,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC74GenericsMonomorphizationAndTryExcept
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
