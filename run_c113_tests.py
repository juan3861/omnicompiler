import sys
import unittest

from tests.test_alpha_c113_build_systems_and_arm64_unwind import TestAlphaC113BuildSystemsAndArm64Unwind

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC113BuildSystemsAndArm64Unwind)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
