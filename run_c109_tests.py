import json
import sys
import unittest

from benchmarks.oss_corpus_bench import run_oss_corpus_certification
from tests.test_alpha_c109_oss_real_corpus import TestAlphaC109OssRealCorpus

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC109OssRealCorpus)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps(run_oss_corpus_certification(), indent=2))
    sys.exit(0 if res.wasSuccessful() else 1)
