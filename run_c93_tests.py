"""Runner for Alpha-C93 Verification Suite."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.discover("tests", pattern="test_alpha_c93*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
