import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tests.test_alpha_c67_cross_target_arm64_and_tri_hybrid import (
    TestAlphaC67CrossTargetArm64AndTriHybrid,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC67CrossTargetArm64AndTriHybrid
    )
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
