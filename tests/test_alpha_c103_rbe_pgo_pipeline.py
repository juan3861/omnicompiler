"""
Alpha-C103 Empirical Verification Suite:
1. Integrated `RBEClusterPool` multi-process execution inside `OmniRepoCompiler.compile_repositories(..., distributed_workers=2)`
   with live gRPC HTTP/2 worker PIDs & topological CAS DAG stats.
2. Profile-Guided Hot/Cold Code Layout Ordering (`profile_weights`): verifies `hot_fn` physically
   precedes `cold_fn` in linked `.text` offsets AND inside the emitted binary, while executing accurately via `ctypes.CDLL`.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from omni_repo_compiler import OmniRepoCompiler


class TestAlphaC103RbePgoPipeline(unittest.TestCase):
    def test_c103_distributed_rbe_and_hot_cold_layout_ordering(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo_cold = os.path.join(td, "aaa_cold_repo")
            repo_hot = os.path.join(td, "zzz_hot_repo")
            os.makedirs(repo_cold, exist_ok=True)
            os.makedirs(repo_hot, exist_ok=True)

            with open(os.path.join(repo_cold, "cold_mod.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def cold_fn(x: int) -> int:\n"
                    "    return (x * 2) + 1\n"
                )
            with open(os.path.join(repo_hot, "hot_mod.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def hot_fn(x: int) -> int:\n"
                    "    return (x * 10) + 5\n"
                )

            out_base = os.path.join(td, "c103_pgo_rbe")
            compiler = OmniRepoCompiler()
            try:
                # Even though repo_cold is passed first, hot_fn has profile weight 5000 vs 1,
                # so linker must place hot_fn physically earlier in .text for I-cache locality!
                res = compiler.compile_repositories(
                    repo_paths=[repo_cold, repo_hot],
                    output_path=out_base,
                    entry_export="hot_fn",
                    export_all=True,
                    backend="native",
                    distributed_workers=2,
                    profile_weights={"hot_fn": 5000, "cold_fn": 1},
                )
            finally:
                compiler.close()

            self.assertTrue(res["success"])
            linking = res["stages"]["linking"]
            self.assertTrue(linking["hot_first_applied"])
            layout_order = linking["layout_order"]
            self.assertIn("hot_fn", layout_order)
            self.assertIn("cold_fn", layout_order)
            self.assertLess(
                layout_order.index("hot_fn"),
                layout_order.index("cold_fn"),
                f"Expected hot_fn before cold_fn in .text layout, got {layout_order}",
            )

            rbe = res["stages"].get("rbe_cluster", {})
            self.assertTrue(rbe.get("enabled"))
            self.assertEqual(rbe.get("workers"), 2)
            self.assertEqual(len(set(rbe.get("worker_pids", []))), 2)
            self.assertEqual(rbe.get("total_actions"), 3)  # 2 repos + 1 final CAS link verification

            art_path = res["stages"]["emission"]["artifact_path"]
            probe = (
                "import ctypes, sys; "
                "d = ctypes.CDLL(sys.argv[1]); "
                "d.hot_fn.argtypes = [ctypes.c_int64]; d.hot_fn.restype = ctypes.c_int64; "
                "d.cold_fn.argtypes = [ctypes.c_int64]; d.cold_fn.restype = ctypes.c_int64; "
                "print(f'{d.hot_fn(4)},{d.cold_fn(4)}')"
            )
            p = subprocess.run(
                [sys.executable, "-c", probe, art_path],
                capture_output=True,
                text=True,
                timeout=15,
                stdin=subprocess.DEVNULL,
            )
            self.assertEqual(p.returncode, 0, msg=p.stderr)
            self.assertEqual(p.stdout.strip(), "45,9")


if __name__ == "__main__":
    unittest.main(verbosity=2)
