import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmarks.stress_metacognition_c40 import build_heavy_polyglot_workspace, run_stress_suite
from evolution.metacognitive_improver import MetacognitiveImprover
from omni_repo_compiler import OmniRepoCompiler


class TestAlphaC40StressMetacognition(unittest.TestCase):
    def test_01_heavy_polyglot_stress_timings_and_salsa_ssa_speedup(self):
        rep = run_stress_suite(verbose=False)
        self.assertEqual(rep["total_repos"], 9)
        self.assertGreaterEqual(rep["exported_symbols_count"], 30)
        self.assertEqual(rep["exec_val"] + 1000, rep["exec_val_edit"])
        self.assertGreaterEqual(rep["warm_speedup_x"], 3.0, f"Expected >= 3x warm speedup, got {rep}")
        self.assertEqual(rep["warm_ingestion"]["salsa_ast_hits"], 9)
        self.assertEqual(rep["edit1_ingestion"]["salsa_ast_misses"], 1)
        self.assertGreaterEqual(rep["edit1_ingestion"]["salsa_artifact_hits"], 35)
        self.assertIn("stage5_ssa_opt_smt", rep["cold_timings_ms"])
        self.assertLess(
            rep["edit1_timings_ms"]["stage5_ssa_opt_smt"],
            rep["cold_timings_ms"]["stage5_ssa_opt_smt"] * 0.35,
            "Salsa SSA cache should slash stage5_ssa_opt_smt on 1-file edit!",
        )

    def test_02_metacognitive_improver_generates_goals_and_report(self):
        improver = MetacognitiveImprover()
        with tempfile.TemporaryDirectory() as tmpdir:
            repos = build_heavy_polyglot_workspace(tmpdir, num_repos=4, fns_per_repo=2)
            ext = ".dll" if sys.platform == "win32" else ".so"
            comp = OmniRepoCompiler()
            res_cold = comp.compile_repositories(
                repos, os.path.join(tmpdir, f"m_cold{ext}"),
                target_format="shared_lib", entry_export="stress_master_entry",
                export_all=True, backend="native", audit_nonce="c40-meta-cold",
            )
            res_warm = comp.compile_repositories(
                repos, os.path.join(tmpdir, f"m_warm{ext}"),
                target_format="shared_lib", entry_export="stress_master_entry",
                export_all=True, backend="native", audit_nonce="c40-meta-warm",
            )
            a_cold = improver.analyze_run(res_cold, build_kind="cold")
            a_warm = improver.analyze_run(res_warm, build_kind="warm")
            self.assertGreaterEqual(a_cold["goals_count"], 1, a_cold)
            self.assertEqual(res_warm["stages"]["ingestion"]["salsa_ast_misses"], 0)

            out_md = os.path.join(tmpdir, "METACOGNITION_REPORT.md")
            improver.write_markdown_report(
                {
                    "total_repos": len(repos),
                    "exported_symbols_count": len(res_cold["stages"]["linking"]["exported_symbols"]),
                    "cold_total_ms": a_cold["total_measured_ms"],
                    "warm_total_ms": a_warm["total_measured_ms"],
                    "warm_speedup_x": round(a_cold["total_measured_ms"] / max(0.1, a_warm["total_measured_ms"]), 2),
                    "edit1_total_ms": a_warm["total_measured_ms"],
                    "edit1_timings_ms": res_warm["stages"]["timings_ms"],
                    "edit1_ingestion": res_warm["stages"]["ingestion"],
                },
                [a_cold, a_warm],
                out_md,
            )
            self.assertTrue(os.path.exists(out_md))
            self.assertGreater(os.path.getsize(out_md), 150)


if __name__ == "__main__":
    unittest.main()
