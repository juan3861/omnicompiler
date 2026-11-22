"""Runner for Alpha-C76 test suite."""
import sys
import unittest

from tests.test_alpha_c76_tls_coalescing_heap_and_native_io import (
    TestAlphaC76TlsCoalescingHeapAndNativeIo,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC76TlsCoalescingHeapAndNativeIo
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
