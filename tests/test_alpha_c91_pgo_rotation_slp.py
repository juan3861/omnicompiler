"""
Alpha-C91 Verification Suite:
1. LoopRotationPass (top-tested while -> bottom-tested do-while self-loop + exit PHI reconciliation)
2. Preheader Scaled-IV Strength Reduction (eliminating iv*C imul inside unrolled loops)
3. SLPVectorizationPass (isomorphic instruction clustering & SMT VerifiedPassRunner proof)
4. ProfileGuidedOptimizer (SSA trace profiling, 4x/8x unroll calibration, hot/cold BlockLayoutPass)
5. X64CodeGenerator Self-Loop Flag-Preserving PHI Copy Fusion & 3-address LEA
6. End-to-End OmniRepoCompiler native shared_lib execution across all industrial kernel edge cases.
"""

import ast
import ctypes
import inspect
import os
import platform
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import benchmarks.industrial_top1_suite as suite
from compiler.native_codegen import X64CodeGenerator, _x64_lea_add_imm, _x64_lea_add_rr, _x64_mov_ri
from compiler.pgo_optimizer import ProfileGuidedOptimizer
from compiler.polyhedral_tiler import LoopRotationPass, LoopUnrollPass, SLPVectorizationPass
from compiler.ssa_ir import AstToSsaLowering
from omni_repo_compiler import OmniRepoCompiler
from validation.ssa_translation_validator import VerifiedPassRunner


class TestAlphaC91OptimizerAndCodegen(unittest.TestCase):
    def test_loop_rotation_creates_bottom_tested_self_loop(self):
        fn = AstToSsaLowering().lower_function_def(
            ast.parse(inspect.getsource(suite.jacobi_1d_kernel)).body[0]
        )
        fn, unroll_st = LoopUnrollPass(unroll_factor=4).unroll_function(fn)
        self.assertGreaterEqual(unroll_st["unrolled_loops"], 1)

        fn, rot_st = LoopRotationPass().run_on_function(fn)
        self.assertEqual(rot_st["rotated_loops"], 2)

        body = next(b for b in fn.blocks if b.name == "for_body_3")
        self.assertTrue(len(body.phi_nodes) >= 4)
        self.assertEqual(body.instructions[-1].opcode, "br_cond")
        self.assertEqual(str(body.instructions[-1].operands[1]), "for_body_3")

    def test_preheader_scaled_iv_strength_reduction_eliminates_loop_iv_mul(self):
        fn = AstToSsaLowering().lower_function_def(
            ast.parse(inspect.getsource(suite.crypto_fnv_mix_kernel)).body[0]
        )
        prof = ProfileGuidedOptimizer().collect_ssa_profile(fn)
        self.assertEqual(prof.recommended_unroll, 8)

        fn, _ = LoopUnrollPass(unroll_factor=prof.recommended_unroll).unroll_function(fn)
        entry = fn.blocks[0]
        self.assertTrue(any(ins.opcode == "mul" for ins in entry.instructions))

        body = next(b for b in fn.blocks if b.name == "for_body_3")
        iv_phi_names = {p.result for p in body.phi_nodes} | set()
        # Note: in unrolled body BEFORE rotation, check no mul references %i_* induction var
        body_muls = [ins for ins in body.instructions if ins.opcode == "mul"]
        for m_ins in body_muls:
            for op in m_ins.operands:
                if hasattr(op, "name"):
                    self.assertFalse(op.name.startswith("i_"), f"Found unreduced iv mul: {m_ins}")

    def test_slp_and_pgo_pass_z3_translation_validation(self):
        runner = VerifiedPassRunner(
            timeout_ms=1000,
            enable_memory_theory=True,
            max_loop_unroll=4,
            enable_inductive_loops=True,
            enable_float_theory=True,
        )
        pgo = ProfileGuidedOptimizer()
        for kernel in (suite.jacobi_1d_kernel, suite.crypto_fnv_mix_kernel):
            fn = AstToSsaLowering().lower_function_def(ast.parse(inspect.getsource(kernel)).body[0])
            fn, _ = LoopUnrollPass(unroll_factor=4).unroll_function(fn)
            fn, st_slp, vr_slp = runner.run_verified_pass(fn, SLPVectorizationPass().run_on_function)
            self.assertTrue(vr_slp["verified"], f"SLP Z3 verify failed for {kernel.__name__}: {vr_slp}")
            self.assertGreater(st_slp["slp_clusters_formed"], 0)

            fn, st_pgo, vr_pgo = runner.run_verified_pass(fn, pgo.optimize_with_profile)
            self.assertTrue(vr_pgo["verified"], f"PGO layout Z3 verify failed for {kernel.__name__}: {vr_pgo}")

    def test_x64_flag_preserving_mov_zero_and_lea_encoding(self):
        mov0_fast = _x64_mov_ri("r8", 0, preserve_flags=False)
        mov0_flagsafe = _x64_mov_ri("r8", 0, preserve_flags=True)
        self.assertEqual(mov0_fast[1], 0x31)       # xor r8, r8
        self.assertEqual(mov0_flagsafe[1], 0xC7)   # mov r8, 0 (EFLAGS intact)

        lea_imm = _x64_lea_add_imm("rax", "r12", 16)
        self.assertEqual(lea_imm[:4], b"\x49\x8d\x44\x24")
        self.assertEqual(lea_imm[4], 16)

        lea_rr = _x64_lea_add_rr("rax", "rbp", "rcx")
        self.assertEqual(lea_rr, b"\x48\x8d\x44\x0d\x00")

    def test_e2e_industrial_kernels_bit_exact_and_metrics(self):
        host_os = "windows" if sys.platform == "win32" else ("macos" if sys.platform == "darwin" else "linux")
        host_arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"

        with tempfile.TemporaryDirectory() as td:
            src = "\n\n".join([
                inspect.getsource(suite.polybench_gemm_kernel),
                inspect.getsource(suite.jacobi_1d_kernel),
                inspect.getsource(suite.crypto_fnv_mix_kernel),
                inspect.getsource(suite.omni_bench_dispatch),
            ])
            with open(os.path.join(td, "kernels.py"), "w", encoding="utf-8") as f:
                f.write(src)

            compiler = OmniRepoCompiler()
            res = compiler.compile_repositories(
                [td],
                output_path=os.path.join(td, "c91_out"),
                target_format="shared_lib",
                target_os=host_os,
                target_arch=host_arch,
                entry_export="omni_bench_dispatch",
                export_all=True,
            )
            cg = res["stages"]["codegen"]
            self.assertGreaterEqual(cg.get("rotated_loops", 0), 4)
            self.assertGreaterEqual(cg.get("slp_clusters_formed", 0), 4)
            self.assertGreaterEqual(cg.get("pgo_profiled_functions", 0), 3)

            art_path = res["stages"]["emission"]["artifact_path"]
            self.assertTrue(os.path.exists(art_path))
            lib = ctypes.CDLL(art_path)
            try:
                fn = lib.omni_bench_dispatch
                fn.argtypes = [ctypes.c_int64, ctypes.c_int64]
                fn.restype = ctypes.c_int64
                for n in (0, 1, 2, 3, 4, 5, 7, 8, 9, 11, 16, 17, 40):
                    self.assertEqual(fn(0, n), suite.polybench_gemm_kernel(n))
                    self.assertEqual(fn(1, n), suite.jacobi_1d_kernel(n))
                    self.assertEqual(fn(2, n), suite.crypto_fnv_mix_kernel(n))
            finally:
                if sys.platform == "win32":
                    ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(lib._handle))


if __name__ == "__main__":
    unittest.main()
