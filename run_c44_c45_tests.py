import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName("tests.test_alpha_c44_c45_os_imports_and_11langs")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
