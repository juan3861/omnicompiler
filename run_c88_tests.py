import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from tests.test_alpha_c88_riscv64_spirv_dwarf_gdb import TestAlphaC88Riscv64SpirvDwarf, run_dwarf_gdb_check


if __name__ == "__main__":
    if "--dwarf-gdb-check" in sys.argv:
        info = run_dwarf_gdb_check()
        print("DWARF_GDB_CHECK:", info)
        assert info["pyelftools_dwarf"], "pyelftools DWARF check failed"
        assert info["readelf_verified"], "readelf DWARF v5 check failed"
        assert info["gdb_verified"], "GNU gdb DWARF v5 batch check failed"
        sys.exit(0)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC88Riscv64SpirvDwarf)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
