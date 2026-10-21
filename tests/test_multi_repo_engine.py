"""
OmniCompiler: Comprehensive Multi-Repository Integration Test Suite
Validates the unification of the 5 modular compiler subsystems with OmniCompiler Core:
- Equality Saturation & E-Matching (egg / egglog style)
- Code Property Graph & Taint Tracking (Joern & Glean style)
- SMT Translation Validation & Refinement (Alive2 & CompCert style)
- CEGIS Inductive Synthesis (Souper & Rosette style)
- AlphaDev MCTS Hardware Assembly Selection
- Native Object Linking, PE64 DLL / ELF64 Emission, and Dynamic CLI Silicon Execution
"""

import unittest
import sys
import os
import ctypes
from typing import Dict, Any

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

MODULES_DIR = os.path.join(BASE_DIR, "compiler_modules")
MODULE_NAMES = (
    "egraph_optimizer",
    "cpg_taint_analyzer",
    "smt_refinement_validator",
    "cegis_abi_synthesizer",
    "mcts_assembly_superoptimizer",
    "compiler_core",
)

for d in MODULE_NAMES:
    subpath = os.path.join(MODULES_DIR, d)
    if os.path.exists(subpath) and subpath not in sys.path:
        sys.path.insert(0, subpath)

from omni_repo_compiler import OmniRepoCompiler
from egraph_optimizer.engine import egraph_saturate_expression, egraph_extract_optimal_kernel
from cpg_taint_analyzer.engine import cpg_trace_taint_path
from smt_refinement_validator.engine import alive_verify_refinement, alive_check_memory_bounds
from cegis_abi_synthesizer.engine import cegis_synthesize_instruction_sequence, cegis_synthesize_abi_adapter
from mcts_assembly_superoptimizer.engine import mcts_search_optimal_assembly
from compiler_core.core_engine import unified_pipeline_compile, omnicompiler_entrypoint


class TestMultiRepoEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        cls.modules_dir = os.path.join(cls.base_dir, "compiler_modules")
        cls.compiler = OmniRepoCompiler()

    def test_01_egraph_equality_saturation(self):
        expr = "x * 16 + 0"
        res = egraph_extract_optimal_kernel(expr)
        self.assertEqual(res["saturated_optimal_expr"], "(x << 4)")
        self.assertTrue(res["is_optimal"])
        self.assertLess(res["estimated_cost"], len(expr))

    def test_02_cpg_interprocedural_taint_isolation(self):
        # Safe source to sink must be isolated
        res_safe = cpg_trace_taint_path("SAFE_SOURCE", "KERNEL_SINK")
        self.assertTrue(res_safe["isolation_preserved"])
        self.assertFalse(res_safe["path_found"])

        # Untrusted source to privileged sink must be flagged
        res_hostile = cpg_trace_taint_path("UNTRUSTED_INJECTOR", "KERNEL_PRIVILEGED_SINK")
        self.assertFalse(res_hostile["isolation_preserved"])
        self.assertTrue(res_hostile["path_found"])

    def test_03_smt_refinement_translation_validation(self):
        # mul16 refines to shl4 without divergence
        res = alive_verify_refinement("mul16", "shl4")
        self.assertTrue(res["proved"])
        self.assertEqual(res["smt_status"], "unsat")

        # Memory bounds verification
        mem_res = alive_check_memory_bounds(base_ptr=0x10000000, offset=0x40, size=0x100)
        self.assertTrue(mem_res["is_safe"])
        self.assertTrue(mem_res["verified_by_smt"])

    def test_04_cegis_inductive_synthesis(self):
        res = cegis_synthesize_instruction_sequence("kernel_opt")
        self.assertTrue(res["is_proven"])
        self.assertEqual(res["synthesized_sequence"], "(x << 4) + x")

        # Cross-repo ABI adapter synthesis
        caller_p = ["a", "b", "c"]
        callee_p = ["c", "b", "a"]
        bridge = cegis_synthesize_abi_adapter(caller_p, callee_p)
        self.assertTrue(bridge["synthesized"])
        self.assertEqual(len(bridge["permutations"]), 3)

    def test_05_mcts_assembly_superoptimization(self):
        res = mcts_search_optimal_assembly("kernel_opt", iterations=40)
        self.assertTrue(res["is_hardware_optimal"])
        self.assertEqual(res["optimal_action"], "lea_scale")
        self.assertGreater(res["visits"], 0)

    def test_06_unified_pipeline_execution(self):
        res = unified_pipeline_compile("x * 16 + 15")
        self.assertEqual(res["status"], "COMPILATION_VERIFIED")
        self.assertEqual(res["egraph_saturated"], "(x << 4) + 15")
        self.assertTrue(res["cpg_isolation_verified"])
        self.assertTrue(res["alive_refinement_proved"])
        self.assertTrue(res["cegis_synthesis_proved"])
        self.assertEqual(res["mcts_optimal_action"], "lea_scale")

    def test_07_end_to_end_shared_library_execution(self):
        repos = [
            os.path.join(self.modules_dir, d)
            for d in sorted(os.listdir(self.modules_dir))
            if os.path.isdir(os.path.join(self.modules_dir, d))
        ]
        self.assertEqual(len(repos), 6)

        out_dll = os.path.join(self.base_dir, "dist", "omnicompiler_unified_engine.dll")
        res = self.compiler.compile_repositories(
            repo_paths=repos,
            output_path=out_dll,
            target_format="shared_lib",
            entry_export="omnicompiler_entrypoint"
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
        self.assertIn("omnicompiler_entrypoint", stages["formal_audit"]["exported_symbols"])

        # 9. Host Physical Execution (Silicon Verification)
        if sys.platform == "win32":
            self.assertTrue(os.path.exists(out_dll))
            lib = ctypes.WinDLL(out_dll)
            fn = getattr(lib, "omnicompiler_entrypoint")
            fn.argtypes = [ctypes.c_int64]
            fn.restype = ctypes.c_int64

            # Evaluate omnicompiler_entrypoint(10) -> (10 << 4) + 15 = 175
            val = fn(10)
            self.assertEqual(val, 175)

            # Clean memory handle free
            h = lib._handle
            del fn
            del lib
            ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(h))

    def test_08_standalone_executable_dynamic_cli_execution(self):
        import subprocess
        repos = [
            os.path.join(self.modules_dir, d)
            for d in sorted(os.listdir(self.modules_dir))
            if os.path.isdir(os.path.join(self.modules_dir, d))
        ]
        out_exe = os.path.join(self.base_dir, "dist", "omnicompiler_standalone.exe" if sys.platform == "win32" else "omnicompiler_standalone")
        res = self.compiler.compile_repositories(
            repo_paths=repos,
            output_path=out_exe,
            target_format="executable",
            entry_export="omnicompiler_entrypoint"
        )
        self.assertTrue(res["success"])
        self.assertTrue(os.path.exists(out_exe))

        # Make executable on Linux
        if sys.platform != "win32":
            os.chmod(out_exe, 0o755)

        # 1. Run with default argument (no args) -> default argument 10 -> (10 << 4) + 15 = 175
        proc_default = subprocess.run([out_exe], capture_output=True)
        self.assertEqual(proc_default.returncode, 175)

        # 2. Run with dynamic CLI argument "5" -> (5 << 4) + 15 = 95
        proc_5 = subprocess.run([out_exe, "5"], capture_output=True)
        self.assertEqual(proc_5.returncode, 95)

        # 3. Run with dynamic CLI argument "7" -> (7 << 4) + 15 = 127
        proc_7 = subprocess.run([out_exe, "7"], capture_output=True)
        self.assertEqual(proc_7.returncode, 127)


if __name__ == "__main__":
    unittest.main()
