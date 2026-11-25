import sys
import unittest

from tests.test_alpha_c106_cpp_eh_and_win_crt_tls import TestAlphaC106CppEHAndWinCrtTls

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC106CppEHAndWinCrtTls)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
