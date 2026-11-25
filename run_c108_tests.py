import sys
import unittest

from tests.test_alpha_c108_autopgo_gc_icf import TestAlphaC108AutoPgoGcIcf

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC108AutoPgoGcIcf)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
