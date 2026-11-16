import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromName("tests.test_alpha_c31_f64_memory_and_inductive_qfabvfp")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
