import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestrator.rbe_cas import (
    ActionSpec,
    ContentAddressableStore,
    OSSandboxController,
    RBECoordinator,
    REAPIClient,
    RBEWorkerNode,
)


class TestAlphaC85REAPIBwoBSandbox(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="omni_c85_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_01_bazel_reapi_v2_capabilities_cas_actioncache_execution(self):
        cas = ContentAddressableStore(os.path.join(self.tmpdir, "cas"))
        worker = RBEWorkerNode("reapi-w1", cas)
        base_url = worker.start()
        try:
            client = REAPIClient(base_url)
            caps = client.get_capabilities()
            self.assertIn("SHA256", caps["cache_capabilities"]["digest_functions"])
            self.assertTrue(caps["execution_capabilities"]["exec_enabled"])
            self.assertTrue(caps["omni_extensions"]["bwob_supported"])

            blob_a = b"omni_reapi_v2_payload_blob"
            import hashlib
            dig_a = {"hash": hashlib.sha256(blob_a).hexdigest(), "size_bytes": len(blob_a)}
            missing = client.find_missing_blobs([dig_a])
            self.assertEqual(len(missing), 1)
            self.assertEqual(missing[0]["hash"], dig_a["hash"])

            up_res = client.batch_update_blobs([blob_a])
            self.assertEqual(up_res[0]["status"]["code"], 0)
            self.assertEqual(client.find_missing_blobs([dig_a]), [])

            read_back = client.batch_read_blobs([dig_a])
            self.assertEqual(read_back, [blob_a])

            spec = ActionSpec(
                action_id="reapi_unit_1",
                kind="compile_ir_unit",
                payload={"func_name": "reapi_fn", "const_val": 77, "arch": "x86_64", "target_os": "linux"},
            )
            op = client.execute_action(spec)
            self.assertTrue(op["done"])
            resp = op["response"]
            self.assertEqual(resp["status"]["code"], 0)
            self.assertFalse(resp["cached_result"])
            self.assertGreaterEqual(len(resp["result"]["output_files"]), 1)

            cached_ar = client.get_action_result(spec.compute_digest())
            self.assertIsNotNone(cached_ar)
            self.assertEqual(cached_ar["exit_code"], 0)

            op2 = client.execute_action(spec)
            self.assertTrue(op2["response"]["cached_result"])
        finally:
            worker.stop()

    def test_02_bwob_zero_intermediate_local_materialization(self):
        cas = ContentAddressableStore(os.path.join(self.tmpdir, "cas_bwob"))
        w1 = RBEWorkerNode("bwob-w1", cas)
        w2 = RBEWorkerNode("bwob-w2", cas)
        u1, u2 = w1.start(), w2.start()
        try:
            coord = RBECoordinator(cas, [u1, u2])
            src_blob = cas.put_blob(b"stage0=42")
            actions = [
                ActionSpec(
                    action_id="stage1",
                    kind="compile_ir_unit",
                    payload={"func_name": "s1_fn", "const_val": 11, "output_name": "s1.o.bin"},
                    input_blobs={"in.txt": src_blob},
                ),
                ActionSpec(
                    action_id="stage2",
                    kind="compile_ir_unit",
                    payload={"func_name": "s2_fn", "const_val": 22, "output_name": "s2.o.bin"},
                    deps=["stage1"],
                ),
                ActionSpec(
                    action_id="stage3_final",
                    kind="emit_standalone_binary",
                    payload={"target_format": "elf64", "exit_code": 9, "output_name": "final_app.elf"},
                    deps=["stage2"],
                ),
            ]
            out_dir = os.path.join(self.tmpdir, "final_only")
            bwob_out = coord.execute_dag_bwob(actions, materialize_finals_to=out_dir)
            tel = bwob_out["bwob_telemetry"]
            self.assertEqual(tel["intermediate_local_materializations"], 0)
            self.assertGreaterEqual(tel["blobs_skipped_local_download"], 2)
            self.assertGreater(tel["bytes_avoided_local_transfer"], 0)

            self.assertFalse(os.path.exists(os.path.join(out_dir, "stage1")))
            self.assertFalse(os.path.exists(os.path.join(out_dir, "stage2")))
            final_bin = os.path.join(out_dir, "stage3_final", "final_app.elf")
            self.assertTrue(os.path.exists(final_bin))
            with open(final_bin, "rb") as f:
                self.assertEqual(f.read(4), b"\x7fELF")
        finally:
            w1.stop()
            w2.stop()

    def test_03_os_kernel_worker_sandbox_enforcement(self):
        caps = OSSandboxController.probe_capabilities()
        self.assertIn(caps["backend"], ("win32_job_object", "linux_landlock_rlimit", "linux_rlimit", "darwin_rlimit"))

        cas = ContentAddressableStore(os.path.join(self.tmpdir, "cas_sb"))
        worker = RBEWorkerNode("sb-w1", cas)
        url = worker.start()
        try:
            client = REAPIClient(url)
            spec = ActionSpec(
                action_id="sb_exec_1",
                kind="run_sandboxed_tool",
                payload={"python_code": "import os; print('SANDBOX_OK:' + os.environ.get('TMPDIR', ''))", "output_name": "sb.txt"},
            )
            op = client.execute_action(spec)
            meta = op["response"]["result"]["execution_metadata"]
            self.assertTrue(meta["kernel_enforced"])
            self.assertEqual(meta["sandbox_kernel_backend"], caps["backend"])
            self.assertEqual(meta["exit_code"], 0)
            dig = op["response"]["result"]["output_files"][0]["digest"]
            stdout_txt = client.batch_read_blobs([dig])[0].decode("utf-8")
            self.assertIn("SANDBOX_OK:", stdout_txt)

            # Verify forced kernel/watchdog termination on timeout without leaking Job handles
            kill_res = OSSandboxController().run_sandboxed_subprocess(
                cmd=[sys.executable, "-c", "import time; time.sleep(5)"],
                sandbox_dir=self.tmpdir,
                timeout_sec=0.35,
            )
            self.assertNotEqual(kill_res["returncode"], 0)
            self.assertTrue(kill_res["kernel_enforced"])
        finally:
            worker.stop()


if __name__ == "__main__":
    unittest.main()
