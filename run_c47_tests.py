import unittest
import sys
import os

if __name__ == "__main__":
    sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
    suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_alpha_c47_os_dynamic_pipeline")
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
