"""
Alpha-C77: Hermetic CAS, Distributed Multi-Worker RBE & Bit-for-Bit Reproducibility Tests.
"""

import os
import tempfile
import unittest

from orchestrator.persistent_salsa_cache import PersistentSalsaCache
from orchestrator.rbe_cas import (
    ActionSpec,
    ContentAddressableStore,
    HermeticSandboxExecutor,
    RBECoordinator,
    RBEWorkerNode,
    compute_sha256,
)


class TestAlphaC77RbeCasAndBitReproducibility(unittest.TestCase):
    def test_01_distributed_rbe_multi_worker_dag_and_action_cache_hit(self):
        """
        Proves real multi-node HTTP/TCP RBE workers execute topological build DAGs,
        persist SHA-256 blobs in CAS, and serve 100% ActionCache hits on rebuild.
        """
        with tempfile.TemporaryDirectory() as td:
            cas = ContentAddressableStore(os.path.join(td, "cas"))
            w1 = RBEWorkerNode("worker-1", cas)
            w2 = RBEWorkerNode("worker-2", cas)
            url1 = w1.start()
            url2 = w2.start()
            try:
                coord = RBECoordinator(cas, [url1, url2])
                actions = [
                    ActionSpec(
                        action_id="ir_a",
                        kind="compile_ir_unit",
                        payload={"func_name": "fn_a", "const_val": 11, "target_os": "linux"},
                    ),
                    ActionSpec(
                        action_id="ir_b",
                        kind="compile_ir_unit",
                        payload={"func_name": "fn_b", "const_val": 22, "target_os": "linux"},
                    ),
                    ActionSpec(
                        action_id="ir_c",
                        kind="compile_ir_unit",
                        payload={"func_name": "fn_c", "const_val": 33, "target_os": "windows"},
                    ),
                    ActionSpec(
                        action_id="bin_final",
                        kind="emit_standalone_binary",
                        payload={"target_format": "elf64", "exit_code": 42, "output_name": "final_elf"},
                        deps=["ir_a", "ir_b", "ir_c"],
                    ),
                ]

                res1 = coord.execute_dag(actions, max_workers=3)
                self.assertEqual(len(res1), 4)
                for aid, r in res1.items():
                    self.assertFalse(r.cache_hit, f"{aid} should be cache miss on cold build")
                    self.assertTrue(r.output_blobs)
                    for digest in r.output_blobs.values():
                        self.assertTrue(cas.has_blob(digest))
                        data = cas.get_blob(digest)
                        self.assertEqual(compute_sha256(data), digest)

                self.assertEqual(w1.executed_count + w2.executed_count, 4)
                self.assertGreaterEqual(w1.executed_count, 1)
                self.assertGreaterEqual(w2.executed_count, 1)

                # Warm rebuild via second coordinator -> 100% ActionCache hits, 0 worker executions
                prev_total = w1.executed_count + w2.executed_count
                coord2 = RBECoordinator(cas, [url1, url2])
                res2 = coord2.execute_dag(actions, max_workers=3)
                self.assertEqual(w1.executed_count + w2.executed_count, prev_total)
                for aid, r in res2.items():
                    self.assertTrue(r.cache_hit, f"{aid} must hit CAS ActionCache on warm rebuild")
                    self.assertEqual(r.output_blobs, res1[aid].output_blobs)
            finally:
                w1.stop()
                w2.stop()

    def test_02_bit_for_bit_reproducible_builds_across_clean_cas_and_salsa_bridge(self):
        """
        Proves bit-for-bit identical binary output across completely independent clean CAS roots
        (`elf64`, `pe64`, `arm64_macho`), PersistentSalsaCache CAS integration, and tamper detection.
        """
        with tempfile.TemporaryDirectory() as td_a, tempfile.TemporaryDirectory() as td_b:
            cas_a = ContentAddressableStore(os.path.join(td_a, "cas"))
            cas_b = ContentAddressableStore(os.path.join(td_b, "cas"))
            exec_a = HermeticSandboxExecutor(cas_a)
            exec_b = HermeticSandboxExecutor(cas_b)

            specs = [
                ActionSpec(
                    action_id="ir_det",
                    kind="compile_ir_unit",
                    payload={"func_name": "det_fn", "const_val": 77, "target_os": "linux"},
                ),
                ActionSpec(
                    action_id="elf_det",
                    kind="emit_standalone_binary",
                    payload={"target_format": "elf64", "exit_code": 42, "output_name": "det_elf"},
                ),
                ActionSpec(
                    action_id="pe_det",
                    kind="emit_standalone_binary",
                    payload={"target_format": "pe64", "exit_code": 42, "output_name": "det_pe.exe"},
                ),
                ActionSpec(
                    action_id="macho_det",
                    kind="emit_standalone_binary",
                    payload={"target_format": "arm64_macho", "exit_code": 42, "output_name": "det_macho"},
                ),
            ]

            for spec in specs:
                ra = exec_a.execute(spec)
                rb = exec_b.execute(spec)
                self.assertEqual(ra.action_digest, rb.action_digest)
                self.assertEqual(ra.output_blobs, rb.output_blobs)
                for out_name, digest in ra.output_blobs.items():
                    self.assertEqual(cas_a.get_blob(digest), cas_b.get_blob(digest))

            # PersistentSalsaCache CAS bridge + tamper detection
            salsa = PersistentSalsaCache(os.path.join(td_a, "salsa.db"))
            salsa.attach_cas(cas_a)
            sample_digest = salsa.put_cas_artifact("det_elf_key", cas_a.get_blob(exec_a.execute(specs[1]).output_blobs["det_elf"]))
            self.assertIsNotNone(sample_digest)
            restored = salsa.get_cas_artifact("det_elf_key")
            self.assertEqual(compute_sha256(restored), sample_digest)

            # Tamper blob on disk and verify CAS catches corruption
            blob_path = cas_a._blob_path(sample_digest)
            with open(blob_path, "r+b") as f:
                first_byte = f.read(1)
                f.seek(0)
                f.write(bytes([first_byte[0] ^ 0xFF]))
            with self.assertRaises(ValueError):
                cas_a.get_blob(sample_digest)
