"""Runner for Alpha-C72 test suite."""
import sys
import unittest

from tests.test_alpha_c72_elf_dwarf_sections_and_ecosystem_manifests import (
    TestAlphaC72ElfDwarfSectionsAndEcosystemManifests,
)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestAlphaC72ElfDwarfSectionsAndEcosystemManifests
    )
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
