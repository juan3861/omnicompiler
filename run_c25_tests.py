import sys
import unittest
from tests.test_alpha_c25_unified_smt_aot import TestAlphaC25UnifiedSmtAot


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC25UnifiedSmtAot)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
