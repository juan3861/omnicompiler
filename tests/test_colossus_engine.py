"""
Colossus Engine: Comprehensive Multi-Repository Integration Test Suite
Validates the unification of the 5 Titan Satellites with OmniCompiler Core:
- Equality Saturation (egg / egglog style)
- Code Property Graph & Taint Flow (Joern & Glean style)
- SMT Translation Validation & Refinement (Alive2 & CompCert style)
- CEGIS Inductive Synthesis (Souper & Rosette style)
- AlphaDev MCTS Hardware Assembly Selection
- Native Object Linking, PE64 DLL Emission, and Silicon Execution
"""

import unittest
import sys
import os
import ctypes
from typing import Dict, Any

# Ensure satellite paths are registered on sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

SAT_DIR = os.path.join(BASE_DIR, "colossus_satellites")
for d in ("titan_egraph", "titan_cpg", "titan_alive_refinement", "titan_cegis_souper", "titan_alphadev_mcts", "omnicompiler_core"):
    subpath = os.path.join(SAT_DIR, d)
    if os.path.exists(subpath) and subpath not in sys.path:
        sys.path.insert(0, subpath)

from omni_repo_compiler import OmniRepoCompiler
from titan_egraph.engine import egraph_saturate_expression, egraph_extract_optimal_kernel
from titan_cpg.engine import cpg_trace_taint_path
from titan_alive_refinement.engine import alive_verify_refinement, alive_check_memory_bounds
from titan_cegis_souper.engine import cegis_synthesize_instruction_sequence, cegis_synthesize_abi_adapter
from titan_alphadev_mcts.engine import mcts_search_optimal_assembly
from omnicompiler_core.core_engine import colossus_unified_compile, colossus_entrypoint


class TestColossusEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        cls.sat_dir = os.path.join(cls.base_dir, "colossus_satellites")
        cls.compiler = OmniRepoCompiler()

    def test_01_titan_egraph_equality_saturation(self):
        expr = "x * 16 + 0"
        res = egraph_extract_optimal_kernel(expr)
        self.assertEqual(res["saturated_optimal_expr"], "(x << 4)")
        self.assertTrue(res["is_optimal"])
        self.assertLess(res["estimated_cost"], len(expr))

    def test_02_titan_cpg_interprocedural_taint_isolation(self):
        # Safe source to sink must be isolated
        res_safe = cpg_trace_taint_path("SAFE_SOURCE", "KERNEL_SINK")
        self.assertTrue(res_safe["isolation_preserved"])
        self.assertFalse(res_safe["path_found"])

        # Untrusted source to privileged sink must be flagged
        res_hostile = cpg_trace_taint_path("UNTRUSTED_INJECTOR", "KERNEL_PRIVILEGED_SINK")
        self.assertFalse(res_hostile["isolation_preserved"])
        self.assertTrue(res_hostile["path_found"])

    def test_03_titan_alive_refinement_smt_proof(self):
        # mul16 refines to shl4 without divergence
        res = alive_verify_refinement("mul16", "shl4")
        self.assertTrue(res["proved"])
        self.assertEqual(res["smt_status"], "unsat")

        # Memory bounds verification
        mem_res = alive_check_memory_bounds(base_ptr=0x10000000, offset=0x40, size=0x100)
        self.assertTrue(mem_res["is_safe"])
        self.assertTrue(mem_res["verified_by_smt"])

    def test_04_titan_cegis_inductive_synthesis(self):
        res = cegis_synthesize_instruction_sequence("kernel_opt")
        self.assertTrue(res["is_proven"])
        self.assertEqual(res["synthesized_sequence"], "(x << 4) + x")

        # Cross-repo ABI adapter synthesis
        caller_p = ["a", "b", "c"]
        callee_p = ["c", "b", "a"]
        bridge = cegis_synthesize_abi_adapter(caller_p, callee_p)
        self.assertTrue(bridge["synthesized"])
        self.assertEqual(len(bridge["permutations"]), 3)

    def test_05_titan_alphadev_mcts_hardware_selection(self):
        res = mcts_search_optimal_assembly("kernel_opt", iterations=40)
        self.assertTrue(res["is_hardware_optimal"])
        self.assertEqual(res["optimal_action"], "lea_scale")
        self.assertGreater(res["visits"], 0)

    def test_06_colossus_multi_organ_unification(self):
        res = colossus_unified_compile("x * 16 + 15")
        self.assertEqual(res["colossus_status"], "UNIFIED_SUPREME")
        self.assertEqual(res["egraph_saturated"], "(x << 4) + 15")
        self.assertTrue(res["cpg_isolation_verified"])
        self.assertTrue(res["alive_refinement_proved"])
        self.assertTrue(res["cegis_synthesis_proved"])
        self.assertEqual(res["mcts_optimal_action"], "lea_scale")

    def test_07_colossus_end_to_end_compilation_and_silicon_execution(self):
        repos = [
            os.path.join(self.sat_dir, d)
            for d in sorted(os.listdir(self.sat_dir))
            if os.path.isdir(os.path.join(self.sat_dir, d))
        ]
        self.assertEqual(len(repos), 6)

        out_dll = os.path.join(self.base_dir, "dist", "colossus_unified_engine.dll")
        res = self.compiler.compile_repositories(
            repo_paths=repos,
            output_path=out_dll,
            target_format="shared_lib",
            entry_export="colossus_entrypoint"
        )

        self.assertTrue(res["success"])
        stages = res["stages"]

        # 1. Ingestion
        self.assertEqual(stages["ingestion"]["total_repos"], 6)

        # 2. Topology
        self.assertGreaterEqual(stages["topology"]["resolved_bindings_count"], 10)

        # 3. ThinLTO Slicing
        self.assertGreater(stages["dead_code_slicing"]["pruned_count"], 0)

        # 4. CPG Isolation
        self.assertTrue(stages["cpg_security"]["isolation_preserved"])

        # 5. CEGIS Synthesis
        self.assertGreater(stages["synthesis"]["bridges_synthesized"], 0)

        # 6. Assembly Invariants & Silicon Sandbox
        self.assertTrue(stages["preflight_safety"]["is_safe_for_silicon"])
        self.assertTrue(stages["preflight_safety"]["assembly_invariants_valid"])

        # 7. Native Linking & Relocation
        self.assertTrue(stages["linking"]["success"])

        # 8. Formal Binary Specification Audit
        self.assertTrue(stages["formal_audit"]["is_valid"])
        self.assertIn("colossus_entrypoint", stages["formal_audit"]["exported_symbols"])

        # 9. Host Physical Execution (Silicon Verification)
        if sys.platform == "win32":
            self.assertTrue(os.path.exists(out_dll))
            lib = ctypes.WinDLL(out_dll)
            fn = getattr(lib, "colossus_entrypoint")
            fn.argtypes = [ctypes.c_int64]
            fn.restype = ctypes.c_int64

            # Evaluate colossus_entrypoint(10) -> (10 << 4) + 15 = 175
            val = fn(10)
            self.assertEqual(val, 175)

            # Clean memory handle free
            h = lib._handle
            del fn
            del lib
            ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(h))


if __name__ == "__main__":
    unittest.main()
