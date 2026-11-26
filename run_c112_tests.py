import sys
import unittest

from tests.test_alpha_c112_cargo_lock_deps import TestAlphaC112CargoLockDeps

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC112CargoLockDeps)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
