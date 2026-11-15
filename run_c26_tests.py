import sys
import unittest

sys.path.insert(0, r"F:\repository-compiler")

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromName("tests.test_alpha_c26_inductive_and_backend_tv")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
