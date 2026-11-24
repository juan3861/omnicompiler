import sys
import unittest

from tests.test_alpha_c95_real_oss_workloads import TestAlphaC95RealOSSWorkloads

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC95RealOSSWorkloads)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
