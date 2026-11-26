"""Alpha-C114 verification: Sharded ThinLTO summary + RBE worker codegen + real LZ4 C benchmark."""

import unittest

from benchmarks.oss_real_library_bench import run_lz4_oss_benchmark
from compiler.llvm_backend import LLVMBackend


class TestAlphaC114ThinLtoAndOssLz4(unittest.TestCase):
    def test_01_llvm_thinlto_partition_summary_and_cross_shard_linking(self):
        lb = LLVMBackend()
        ir_u0 = 'define i32 @tl_base(i32 %x) { %r = mul i32 %x, 5\n ret i32 %r }\n'
        ir_u1 = (
            'declare i32 @tl_base(i32)\n'
            'define i32 @tl_caller(i32 %y) { %a = call i32 @tl_base(i32 %y)\n %b = add i32 %a, 3\n ret i32 %b }\n'
        )
        part = lb.thin_lto_partition([ir_u0, ir_u1], num_shards=2)
        self.assertEqual(part["num_shards"], 2)
        self.assertIn("tl_base", part["summary_symbols"])
        self.assertIn("tl_caller", part["summary_symbols"])
        self.assertIn((1, 0, "tl_base"), part["cross_module_edges"])
        self.assertEqual(len(part["shard_objects"]), 2)
        for obj_b in part["shard_objects"]:
            self.assertGreater(len(obj_b), 64)

    def test_02_real_lz4_makefile_64k_parity_vs_gcc_o3(self):
        rep = run_lz4_oss_benchmark(iterations=25)
        self.assertTrue(rep["all_passed"], f"LZ4 benchmark failed: {rep}")
        self.assertTrue(rep["bit_exact_parity"])
        self.assertEqual(rep["makefile_units"], 2)


if __name__ == "__main__":
    unittest.main()
