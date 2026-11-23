"""Runner for Alpha-C77 test suite."""
import sys
import unittest

from tests.test_alpha_c77_rbe_cas_and_bit_reproducibility import (
    TestAlphaC77RbeCasAndBitReproducibility,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC77RbeCasAndBitReproducibility
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
