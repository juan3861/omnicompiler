import unittest
from orchestrator.repo_manifest_ingestor import RepoManifest, SymbolSignature, SymbolRequirement
from slicer.inter_repo_slicer import InterRepoSlicer


class TestInterRepoSlicer(unittest.TestCase):
    def setUp(self):
        self.slicer = InterRepoSlicer()

    def test_dead_code_pruning(self):
        # Create Repo A with 3 functions: active_fn, dead_fn_1, dead_fn_2
        sig_active = SymbolSignature("active_fn", ["x"])
        sig_dead1 = SymbolSignature("dead_fn_1", ["y"])
        sig_dead2 = SymbolSignature("dead_fn_2", ["z"])

        manifest_a = RepoManifest(
            repo_name="repo_a",
            repo_path="/dummy/a",
            repo_type="python",
            exports=[sig_active, sig_dead1, sig_dead2],
            imports=[]
        )

        # Create Repo B that calls active_fn from main
        sig_main = SymbolSignature("main", [])
        manifest_b = RepoManifest(
            repo_name="repo_b",
            repo_path="/dummy/b",
            repo_type="python",
            exports=[sig_main],
            imports=[SymbolRequirement("active_fn", source_file="b.py")]
        )

        call_graph = {
            "main": ["active_fn"]
        }

        res = self.slicer.slice_repositories(
            manifests=[manifest_a, manifest_b],
            root_symbols=["main"],
            call_graph=call_graph
        )

        self.assertEqual(res["total_before"], 4)
        self.assertEqual(res["total_after"], 2)
        self.assertEqual(res["pruned_count"], 2)
        self.assertIn("repo_a::dead_fn_1", res["pruned_symbols"])
        self.assertIn("repo_a::dead_fn_2", res["pruned_symbols"])
        self.assertNotIn("repo_a::active_fn", res["pruned_symbols"])

        # Check that manifest_a now only has active_fn
        self.assertEqual([e.name for e in manifest_a.exports], ["active_fn"])


if __name__ == "__main__":
    unittest.main()
