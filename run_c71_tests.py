"""Runner for Alpha-C71 test suite."""
import sys
import unittest

from tests.test_alpha_c71_cross_emitter_f64_abi_pdata_and_dwarf_subprograms import (
    TestAlphaC71CrossEmitterF64AbiPdataAndDwarfSubprograms,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC71CrossEmitterF64AbiPdataAndDwarfSubprograms
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
