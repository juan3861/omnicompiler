import sys
import unittest

sys.path.insert(0, ".")
loader = unittest.TestLoader()
suite = loader.loadTestsFromName("tests.test_alpha_c104_workspace_lsp_and_gcc_bench")
runner = unittest.TextTestRunner(verbosity=2)
res = runner.run(suite)
sys.exit(0 if res.wasSuccessful() else 1)
