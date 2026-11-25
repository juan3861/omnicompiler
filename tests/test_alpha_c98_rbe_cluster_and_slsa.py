"""
Alpha-C98 Empirical Verification Suite:
1. RBEClusterPool multi-process worker cluster (`REAPIGrpcServer` over HTTP/2 + Win32 Job Objects),
   topological ActionSpec DAG execution, and second-run CAS ActionCache deduplication (`cache_hits == N`).
2. OSSandboxController kernel-enforced execution (`win32_job_object` on Windows, Landlock/rlimit on Linux).
3. Automatic CycloneDX 1.5 `.cdx.json` SBOM + Ed25519 DSSE SLSA v1.0 `.intoto.jsonl` verification
   + cold-cache bit-exact reproducibility (`sha256_run1 == sha256_run2`) in OmniRepoCompiler.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from omni_repo_compiler import OmniRepoCompiler
from orchestrator.rbe_cas import (
    ActionSpec,
    ContentAddressableStore,
    OSSandboxController,
    RBEClusterPool,
)
from packaging.slsa_provenance import SLSAProvenanceGenerator


class TestAlphaC98RbeClusterAndSlsa(unittest.TestCase):
    def test_c98_rbe_cluster_pool_multiprocess_dag_and_kernel_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cas = ContentAddressableStore(os.path.join(td, "cas"))
            in_a = cas.put_blob(b"module_alpha_payload")
            in_b = cas.put_blob(b"module_beta_payload")

            actions = [
                ActionSpec(
                    action_id="compile_alpha",
                    kind="emit_standalone_binary",
                    payload={"target_format": "elf64", "exit_code": 11, "output_name": "alpha.elf"},
                    input_blobs={"alpha.omni": in_a},
                ),
                ActionSpec(
                    action_id="compile_beta",
                    kind="emit_standalone_binary",
                    payload={"target_format": "elf64", "exit_code": 22, "output_name": "beta.elf"},
                    input_blobs={"beta.omni": in_b},
                ),
                ActionSpec(
                    action_id="link_bundle",
                    kind="emit_standalone_binary",
                    payload={"target_format": "elf64", "exit_code": 33, "output_name": "bundle.elf"},
                    input_blobs={"a.omni": in_a, "b.omni": in_b},
                    deps=["compile_alpha", "compile_beta"],
                ),
            ]

            with RBEClusterPool(cas, num_workers=2, prefer_grpc=True) as cluster:
                self.assertEqual(len(cluster.worker_pids), 2)
                self.assertEqual(len(set(cluster.worker_pids)), 2)

                run1 = cluster.execute_dag(actions)
                self.assertEqual(run1["total_actions"], 3)
                self.assertEqual(run1["executed_misses"], 3)
                self.assertEqual(run1["cache_hits"], 0)
                for aid in ("compile_alpha", "compile_beta", "link_bundle"):
                    out_blobs = run1["results"][aid].output_blobs
                    self.assertTrue(any(cas.has_blob(h) for h in out_blobs.values()))

                run2 = cluster.execute_dag(actions)
                self.assertEqual(run2["total_actions"], 3)
                self.assertEqual(run2["cache_hits"], 3)
                self.assertEqual(run2["executed_misses"], 0)

            sb_res = OSSandboxController().run_sandboxed_subprocess(
                [sys.executable, "-c", "print('sandbox_ok')"],
                sandbox_dir=td,
                timeout_sec=10.0,
                max_memory_mb=256,
            )
            self.assertEqual(sb_res["returncode"], 0)
            self.assertIn("sandbox_ok", sb_res["stdout"])
            if sys.platform == "win32":
                self.assertEqual(sb_res["sandbox_kernel_backend"], "win32_job_object")
                self.assertTrue(sb_res["kernel_enforced"])

    def test_c98_slsa_cyclonedx_sbom_and_bit_exact_reproducibility(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo_dir = os.path.join(td, "repro_repo")
            os.makedirs(repo_dir, exist_ok=True)
            with open(os.path.join(repo_dir, "kernel.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def c98_repro_compute(x: int) -> int:\n"
                    "    acc = 7\n"
                    "    for i in range(4):\n"
                    "        acc = (acc * 3) + (x ^ i)\n"
                    "    return acc\n"
                )

            out_base = os.path.join(td, "c98_repro_out")
            compiler = OmniRepoCompiler()
            try:
                res = compiler.compile_repositories(
                    repo_paths=[repo_dir],
                    output_path=out_base,
                    entry_export="c98_repro_compute",
                    backend="native",
                    emit_provenance=True,
                    verify_reproducibility=True,
                )
            finally:
                compiler.close()

            self.assertTrue(res["success"])
            art_path = res["stages"]["emission"]["artifact_path"]
            sbom_path = res["sbom_path"]
            prov_path = res["provenance_path"]
            self.assertTrue(os.path.exists(art_path))
            self.assertTrue(os.path.exists(sbom_path))
            self.assertTrue(os.path.exists(prov_path))

            with open(sbom_path, "r", encoding="utf-8") as sf:
                sbom_obj = json.load(sf)
            self.assertEqual(sbom_obj["bomFormat"], "CycloneDX")
            self.assertEqual(sbom_obj["specVersion"], "1.5")

            with open(prov_path, "r", encoding="utf-8") as pf:
                prov_env = json.loads(pf.read().strip())

            ver = SLSAProvenanceGenerator.verify_bundle(
                prov_env,
                subjects_data={os.path.basename(art_path): art_path},
                expected_sbom=sbom_obj,
            )
            self.assertTrue(ver["valid"], msg=ver)
            self.assertEqual(ver["reason"], "VERIFIED_SLSA_L3_PROVENANCE")

            repro = res["stages"]["reproducibility"]
            self.assertTrue(repro["verified"])
            self.assertTrue(repro["bit_for_bit_equal"])
            self.assertEqual(repro["sha256_run1"], repro["sha256_run2"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
