"""Runner for Alpha-C75 test suite."""
import sys
import unittest

from tests.test_alpha_c75_atomics_multithread_and_arm64_ci import (
    TestAlphaC75AtomicsMultithreadAndArm64Ci,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC75AtomicsMultithreadAndArm64Ci
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
