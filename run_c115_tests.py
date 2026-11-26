import sys
import unittest

from tests.test_alpha_c115_sarif_and_lsp_v317 import TestAlphaC115SarifAndLspV317

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC115SarifAndLspV317)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
