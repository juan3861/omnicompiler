import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from tests.test_alpha_c83_alive2_ub_kinduction import TestAlphaC83Alive2AndKInduction


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC83Alive2AndKInduction)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
