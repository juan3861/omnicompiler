import sys
import unittest

sys.path.insert(0, r"F:\repository-compiler")

from tests.test_alpha_c18_irc_regalloc import TestAlphaC18IteratedRegisterCoalescing

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAlphaC18IteratedRegisterCoalescing)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
