import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=os.path.join(REPO_ROOT, "tests"), pattern="test_alpha_c52_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    return 0 if res.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
