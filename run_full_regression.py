import sys
import unittest

sys.path.insert(0, r"F:\repository-compiler")

test_modules = [
    "tests.test_alpha_c13_stateful_selection",
    "tests.test_alpha_c14_multiblock_lto_simd",
    "tests.test_alpha_c15_stack_promotion",
    "tests.test_alpha_c16_autovec_and_ffi",
    "tests.test_alpha_c17_aot_compiler",
    "tests.test_native_composite_collections",
    "tests.test_ceiling_engineering_complete",
]

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for mod in test_modules:
        suite.addTests(loader.loadTestsFromName(mod))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
