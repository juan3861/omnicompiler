"""
Unit Tests for Multi-Repository Manifest Ingestion & Inter-Project Topology
"""

import unittest
import tempfile
import os
import shutil
from orchestrator.repo_manifest_ingestor import RepoManifestIngestor, RepoTopologyResolver


class TestRepoManifestIngestor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

        # Repository 1: Core Math Engine (Python + C header)
        self.repo_core = os.path.join(self.temp_dir, "core_engine")
        os.makedirs(self.repo_core)
        with open(os.path.join(self.repo_core, "pyproject.toml"), "w", encoding="utf-8") as f:
            f.write("[project]\nname = 'core_engine'\n")
        with open(os.path.join(self.repo_core, "math_ops.py"), "w", encoding="utf-8") as f:
            f.write("def tensor_dot(a, b):\n    '''Performs dot product.'''\n    return a * b\n\ndef vector_norm(x):\n    return x\n")
        with open(os.path.join(self.repo_core, "native_core.h"), "w", encoding="utf-8") as f:
            f.write("int64_t fast_hardware_acc(int64_t input_val, int64_t scale);\n")

        # Repository 2: Consumer Service (Python calling core_engine)
        self.repo_service = os.path.join(self.temp_dir, "service_api")
        os.makedirs(self.repo_service)
        with open(os.path.join(self.repo_service, "pyproject.toml"), "w", encoding="utf-8") as f:
            f.write("[project]\nname = 'service_api'\n")
        with open(os.path.join(self.repo_service, "handlers.py"), "w", encoding="utf-8") as f:
            f.write("from core_engine.math_ops import tensor_dot\n\ndef api_handler(payload):\n    return tensor_dot(payload, 2)\n")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_manifest_ingestion(self):
        ingestor = RepoManifestIngestor()
        m_core = ingestor.ingest_repository(self.repo_core, "core_engine")
        m_service = ingestor.ingest_repository(self.repo_service, "service_api")

        # Validate core exports
        core_export_names = [e.name for e in m_core.exports]
        self.assertIn("tensor_dot", core_export_names)
        self.assertIn("vector_norm", core_export_names)
        self.assertIn("fast_hardware_acc", core_export_names)

        # Validate service imports
        service_import_names = [i.name for i in m_service.imports]
        self.assertIn("core_engine.math_ops.tensor_dot", service_import_names)

    def test_topology_resolution(self):
        ingestor = RepoManifestIngestor()
        m_core = ingestor.ingest_repository(self.repo_core, "core_engine")
        m_service = ingestor.ingest_repository(self.repo_service, "service_api")

        resolver = RepoTopologyResolver()
        topo = resolver.resolve_topology([m_core, m_service])

        self.assertEqual(topo["total_manifests"], 2)
        self.assertGreaterEqual(len(topo["resolved_bindings"]), 1)

        binding = topo["resolved_bindings"][0]
        self.assertEqual(binding["consumer_repo"], "service_api")
        self.assertEqual(binding["provider_repo"], "core_engine")
        self.assertEqual(binding["symbol"], "tensor_dot")


if __name__ == "__main__":
    unittest.main()
