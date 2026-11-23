"""Runner for Alpha-C81 test suite."""
import sys
import unittest

from tests.test_alpha_c81_scev_and_vectorization import (
    TestAlphaC81SCEVAndReciprocalDiv,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC81SCEVAndReciprocalDiv
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
