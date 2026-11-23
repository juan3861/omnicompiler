import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from compiler.self_hosted_core import (
    SelfHostedCoreEngine,
    _py_regalloc_spill_cost,
    _py_ssa_fnv1a_step,
    _py_trip_count_work,
    verify_stage1_stage2_bootstrap,
)


class TestAlphaC89SelfHostedCore(unittest.TestCase):
    def test_01_self_hosted_native_build_exact_parity_and_speedup(self):
        with SelfHostedCoreEngine() as core:
            self.assertGreaterEqual(core.scev_collapsed_count, 1)
            for acc, tag, ar in ((0, 3, 2), (1234567, 15, 4), (-99, 1, 0)):
                self.assertEqual(core.fnv_step(acc, tag, ar), _py_ssa_fnv1a_step(acc, tag, ar))
            for n, stride in ((0, 3), (1, 5), (50, 7), (400, 3)):
                self.assertEqual(core.trip_work(n, stride), _py_trip_count_work(n, stride))
            for deg, depth, uses in ((0, 0, 5), (4, 2, 12), (9, 5, 3)):
                self.assertEqual(core.spill_cost(deg, depth, uses), _py_regalloc_spill_cost(deg, depth, uses))

            bench = core.benchmark_vs_python(iterations=1500)
            self.assertGreater(bench["speedup_x"], 2.0)

    def test_02_stage1_stage2_bit_reproducible_fixpoint(self):
        res = verify_stage1_stage2_bootstrap()
        self.assertTrue(res["fixpoint_converged"], msg=res)
        self.assertEqual(res["stage1_sha256"], res["stage2_sha256"])
        self.assertGreaterEqual(res["scev_collapsed"], 1)


if __name__ == "__main__":
    unittest.main()
