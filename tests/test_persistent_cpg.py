"""
Unit Tests for Disk-Backed Persistent Code Property Graph (CPG) & Multi-Repo Slicer
"""

import unittest
import tempfile
import os
import ast
from slicer.persistent_cpg import PersistentCodePropertyGraph


class TestPersistentCPG(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_cpg.db")
        self.cpg = PersistentCodePropertyGraph(self.db_path)

    def tearDown(self):
        self.cpg.close()
        if os.path.exists(self.db_path):
            try: os.remove(self.db_path)
            except Exception: pass

    def test_node_and_edge_persistence(self):
        n1 = self.cpg.add_node("PARAM:TENANT", "tenant_id", repo_name="repo_a", properties={"secure": True})
        n2 = self.cpg.add_node("VAR", "buffer", repo_name="repo_a")
        n3 = self.cpg.add_node("SINK:EXPORT", "public_log", repo_name="repo_a")

        self.cpg.add_edge(n1, n2, "DDG_FLOW")
        self.cpg.add_edge(n2, n3, "DDG_FLOW")

        node = self.cpg.get_node(n1)
        self.assertIsNotNone(node)
        self.assertEqual(node.label, "tenant_id")
        self.assertEqual(node.properties.get("secure"), True)

        path = self.cpg.find_cross_repo_taint_path("tenant_id", "public_log")
        self.assertIsNotNone(path)
        self.assertEqual(path, [n1, n2, n3])

    def test_inter_repo_call_linking(self):
        # Repo Core function
        code_core = "def compute_hash(tenant_key):\n    h = tenant_key + 1\n    return h\n"
        fn_core = ast.parse(code_core).body[0]
        self.cpg.build_from_ast_function(fn_core, repo_name="core_repo")

        # Repo Service function calling compute_hash
        code_service = "def service_handler(tenant_token):\n    res = compute_hash(tenant_token)\n    return res\n"
        fn_service = ast.parse(code_service).body[0]
        self.cpg.build_from_ast_function(fn_service, repo_name="service_repo")

        # Link inter-repo call
        linked = self.cpg.link_inter_repo_call(caller_repo="service_repo", callee_repo="core_repo", target_fn_name="compute_hash")
        self.assertGreaterEqual(linked, 1)

        # Cross-repo taint verification: tenant_token in service_repo flows into core_repo return sink
        path = self.cpg.find_cross_repo_taint_path("tenant_token", "return")
        self.assertIsNotNone(path)
        self.assertGreaterEqual(len(path), 3)


if __name__ == "__main__":
    unittest.main()
