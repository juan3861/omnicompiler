import sys
import unittest

from tests.test_alpha_c111_msvc_seh_pdb import TestAlphaC111MsvcSehAndPdb

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC111MsvcSehAndPdb)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
