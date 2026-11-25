import sys
import unittest

sys.path.insert(0, ".")
loader = unittest.TestLoader()
suite = loader.loadTestsFromName("tests.test_alpha_c99_sanitizers_concurrency_fuzzer")
runner = unittest.TextTestRunner(verbosity=2)
res = runner.run(suite)
sys.exit(0 if res.wasSuccessful() else 1)
