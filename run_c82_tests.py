"""Runner for Alpha-C82 test suite."""
import sys
import unittest

from tests.test_alpha_c82_unroll_strength_scheduling import (
    TestAlphaC82UnrollStrengthScheduling,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC82UnrollStrengthScheduling
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
