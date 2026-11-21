import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tests.test_alpha_c68_wasm_coalescing_macho_and_polyglot_hybrid import (
    TestAlphaC68WasmCoalescingMachoAndPolyglotHybrid,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC68WasmCoalescingMachoAndPolyglotHybrid
    )
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
