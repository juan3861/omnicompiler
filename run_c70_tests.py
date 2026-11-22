"""Runner for Alpha-C70 test suite."""
import sys
import unittest

from tests.test_alpha_c70_macho_dyld_bind_and_f64_ipsccp import (
    TestAlphaC70MachoDyldBindAndF64IpSccp,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC70MachoDyldBindAndF64IpSccp
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
