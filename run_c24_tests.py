import sys
import unittest
from tests.test_alpha_c24_smt_translation_validation import TestAlphaC24SmtTranslationValidation


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC24SmtTranslationValidation)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
