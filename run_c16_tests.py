import sys
import unittest

sys.path.insert(0, r"F:\repository-compiler")

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_alpha_c16_autovec_and_ffi")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
