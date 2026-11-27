import json
import sys
import unittest

from benchmarks.oss_torture_suite import run_deflate_torture_benchmark
from tests.test_alpha_c121_pdb_dbi_and_deflate_torture import TestAlphaC121PdbDbiAndDeflateTorture

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC121PdbDbiAndDeflateTorture)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    rep = run_deflate_torture_benchmark(iterations=20)
    print(json.dumps(rep, indent=2))
    sys.exit(0 if (res.wasSuccessful() and rep.get("all_passed")) else 1)
