import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tests.test_alpha_c66_heterogeneous_linking_wasm_libc_and_hygiene import (
    TestAlphaC66HeterogeneousLinkingWasmLibcAndHygiene,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC66HeterogeneousLinkingWasmLibcAndHygiene
    )
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
