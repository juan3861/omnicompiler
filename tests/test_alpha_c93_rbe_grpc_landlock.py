"""
Alpha-C93 Verification Suite:
1. Bazel REAPI v2 Merkle Tree (`Directory` / `Tree` CAS digests & hermetic materialization)
2. Real gRPC (`grpcio`) HTTP/2 + Protobuf (`google.protobuf.Struct`) REAPI v2 Server & Client
   driving `RBECoordinator.execute_dag_bwob`
3. OS Kernel Sandbox (`Win32 Job Object` on Windows; real Linux Kernel Landlock LSM
   `landlock_create_ruleset` + `landlock_add_rule` + `landlock_restrict_self` blocking
   filesystem escape attempts with `EACCES`/`PermissionError` on Linux).
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestrator.rbe_cas import (
    ActionSpec,
    ContentAddressableStore,
    OSSandboxController,
    RBECoordinator,
    REAPIGrpcClient,
    REAPIGrpcServer,
)


class TestAlphaC93RbeGrpcAndLandlock(unittest.TestCase):
    def test_01_bazel_merkle_tree_cas_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            cas_dir = os.path.join(td, "cas")
            src_dir = os.path.join(td, "src")
            dst_dir = os.path.join(td, "dst")
            os.makedirs(os.path.join(src_dir, "pkg", "sub"), exist_ok=True)
            with open(os.path.join(src_dir, "main.py"), "wb") as f:
                f.write(b"def main(): return 42\n")
            with open(os.path.join(src_dir, "pkg", "sub", "helper.rs"), "wb") as f:
                f.write(b"pub fn add(a: i64, b: i64) -> i64 { a + b }\n")

            cas = ContentAddressableStore(cas_dir)
            meta1 = cas.put_merkle_tree(src_dir)
            meta2 = cas.put_merkle_tree(src_dir)
            self.assertEqual(meta1["root_digest"], meta2["root_digest"])
            self.assertEqual(meta1["tree_digest"], meta2["tree_digest"])
            self.assertEqual(meta1["file_count"], 2)
            self.assertEqual(meta1["directory_count"], 3)

            restored = cas.materialize_merkle_tree(meta1["root_digest"], dst_dir)
            self.assertEqual(len(restored), 2)
            with open(os.path.join(dst_dir, "pkg", "sub", "helper.rs"), "rb") as f:
                self.assertEqual(f.read(), b"pub fn add(a: i64, b: i64) -> i64 { a + b }\n")

    def test_02_real_grpc_http2_reapi_v2_and_bwob_dag(self):
        with tempfile.TemporaryDirectory() as td:
            cas = ContentAddressableStore(os.path.join(td, "cas"))
            w1 = REAPIGrpcServer("grpc-worker-1", cas)
            w2 = REAPIGrpcServer("grpc-worker-2", cas)
            url1 = w1.start()
            url2 = w2.start()
            try:
                client = REAPIGrpcClient(url1)
                caps = client.get_capabilities()
                self.assertEqual(caps["omni_extensions"]["transport"], "grpc+http2+protobuf")
                self.assertIn("SHA256", caps["cache_capabilities"]["digest_functions"])

                blob_a = b"hello_grpc_reapi_v2"
                up = client.batch_update_blobs([blob_a])
                self.assertEqual(len(up), 1)
                self.assertEqual(int(up[0]["status"]["code"]), 0)
                dig_a = up[0]["digest"]

                missing = client.find_missing_blobs([dig_a, {"hash": "0" * 64, "size_bytes": 1}])
                self.assertEqual(len(missing), 1)
                self.assertEqual(missing[0]["hash"], "0" * 64)

                rd = client.batch_read_blobs([dig_a])
                self.assertEqual(rd, [blob_a])

                # Execute real 3-node DAG via BwoB over gRPC HTTP/2
                src_blob = cas.put_blob(b"grpc-dag-payload")
                coord = RBECoordinator(cas, [url1, url2])
                actions = [
                    ActionSpec("unit_a", "compile_ir_unit", {"func_name": "fn_a", "const_val": 11}),
                    ActionSpec("unit_b", "run_sandboxed_tool", {"python_code": "print('OK_SANDBOX')", "output_name": "sb.txt"}, input_blobs={"in.txt": src_blob}, deps=["unit_a"]),
                    ActionSpec("unit_c", "compile_ir_unit", {"func_name": "fn_c", "const_val": 99}, deps=["unit_a", "unit_b"]),
                ]
                out_dir = os.path.join(td, "finals")
                bwob = coord.execute_dag_bwob(actions, materialize_finals_to=out_dir)
                self.assertEqual(len(bwob["results"]), 3)
                self.assertEqual(bwob["bwob_telemetry"]["intermediate_local_materializations"], 0)
                self.assertGreaterEqual(bwob["bwob_telemetry"]["blobs_skipped_local_download"], 2)
                self.assertEqual(len(bwob["bwob_telemetry"]["final_materialized_files"]), 1)
                self.assertTrue(os.path.exists(bwob["bwob_telemetry"]["final_materialized_files"][0]))
            finally:
                w1.stop()
                w2.stop()

    def test_03_os_sandbox_and_linux_landlock_escape_enforcement(self):
        ctrl = OSSandboxController()
        caps = ctrl.probe_capabilities()
        self.assertTrue(caps["backend"])

        with tempfile.TemporaryDirectory() as td:
            sb_dir = os.path.join(td, "jail")
            outside_secret = os.path.join(td, "outside_secret.txt")
            os.makedirs(sb_dir, exist_ok=True)
            with open(outside_secret, "w", encoding="utf-8") as f:
                f.write("SECRET_TOKEN")

            ok_res = ctrl.run_sandboxed_subprocess(
                [sys.executable, "-c", "open('inside.txt','w').write('ok'); print('INSIDE_OK')"],
                sandbox_dir=sb_dir,
            )
            self.assertEqual(ok_res["returncode"], 0, ok_res)
            self.assertIn("INSIDE_OK", ok_res["stdout"])
            self.assertTrue(ok_res["kernel_enforced"])

            if sys.platform.startswith("linux") and caps.get("landlock"):
                escape_code = (
                    "import sys\n"
                    "try:\n"
                    f"    open({outside_secret!r}, 'r').read()\n"
                    "    sys.exit(0)\n"
                    "except PermissionError:\n"
                    "    print('LANDLOCK_EACCES_BLOCKED')\n"
                    "    sys.exit(42)\n"
                )
                esc_res = ctrl.run_sandboxed_subprocess(
                    [sys.executable, "-c", escape_code],
                    sandbox_dir=sb_dir,
                )
                self.assertTrue(esc_res["landlock_restricted"])
                self.assertEqual(esc_res["returncode"], 42, esc_res)
                self.assertIn("LANDLOCK_EACCES_BLOCKED", esc_res["stdout"])


if __name__ == "__main__":
    unittest.main()
