import sys
import unittest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from tests.test_alpha_c23_sroa_devirt import TestAlphaC23SroaDevirt

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAlphaC23SroaDevirt)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
