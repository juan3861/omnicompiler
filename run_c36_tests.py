import sys
import unittest

sys.path.insert(0, r"F:\repository-compiler")

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName("tests.test_alpha_c36_match_switch_and_rodata_luts")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
