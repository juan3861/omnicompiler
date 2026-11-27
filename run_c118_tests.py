import sys
import unittest

from tests.test_alpha_c118_cross_shard_thinlto_rbe import TestAlphaC118CrossShardThinLtoRbe

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAlphaC118CrossShardThinLtoRbe)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
