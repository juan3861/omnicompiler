"""Runner for Alpha-C73 test suite."""
import sys
import unittest

from tests.test_alpha_c73_closures_match_and_workspace_deps import (
    TestAlphaC73ClosuresMatchAndWorkspaceDeps,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC73ClosuresMatchAndWorkspaceDeps
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
