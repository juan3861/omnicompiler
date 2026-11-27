import sys
import unittest

from tests.test_alpha_c120_python_dataclass_closures_try import TestAlphaC120PythonDataclassClosuresTry

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC120PythonDataclassClosuresTry)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
