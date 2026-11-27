import sys
import unittest

from tests.test_alpha_c117_coff_implib_comdat_gnuhash import TestAlphaC117CoffImplibComdatGnuHash

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC117CoffImplibComdatGnuHash)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
