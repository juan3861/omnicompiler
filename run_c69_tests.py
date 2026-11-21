"""Runner for Alpha-C69 test suite."""
import sys
import unittest

from tests.test_alpha_c69_arm64_rodata_macho_exec_and_transitive_ipsccp import (
    TestAlphaC69Arm64RodataMachoExecAndTransitiveIpSccp,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC69Arm64RodataMachoExecAndTransitiveIpSccp
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
