"""
Alpha-C82: Scalar 4x Loop Unrolling, Induction Strength Reduction,
X64 Direct Register/Imm32 ALU + Macro-Op Branch Fusion,
Hybrid Register Allocation, Pre-IRC Critical-Path DAG Scheduling & ARM64 SMULH Verification.
"""

import ast
import ctypes
import inspect
import os
import platform
import sys
import tempfile
import textwrap
import unittest

from benchmarks.industrial_top1_suite import (
    polybench_gemm_kernel,
    jacobi_1d_kernel,
    crypto_fnv_mix_kernel,
    omni_bench_dispatch,
)
from compiler.licm_and_dse import LICMPass
from compiler.native_codegen import (
    Arm64CodeGenerator,
    NativeCodeGenerator,
    X64CodeGenerator,
    _schedule_basic_block_instructions,
)
from compiler.polyhedral_tiler import LoopUnrollPass, PolyhedralLoopTilerPass
from compiler.scev_analyzer import SCEVAnalyzer
from compiler.ssa_ir import (
    BasicBlock,
    SSAFunction,
    SSAInstruction,
    SSAVar,
    lower_ast_to_ssa,
)
from compiler.tco_and_layout import BlockLayoutPass
from compiler.thin_lto import ThinLTOOptimizer
from omni_repo_compiler import OmniRepoCompiler


def _is_x86_64() -> bool:
    return platform.machine().lower() in ("amd64", "x86_64")


def _jit_exec_x64_i64_many(code_bytes: bytes, args) -> list:
    if sys.platform == "win32":
        k32 = ctypes.windll.kernel32
        k32.VirtualAlloc.restype = ctypes.c_void_p
        k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
        k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
        k32.VirtualFree.restype = ctypes.c_int
        addr = k32.VirtualAlloc(None, len(code_bytes), 0x3000, 0x40)
        if not addr:
            raise MemoryError("VirtualAlloc failed")
        try:
            ctypes.memmove(addr, code_bytes, len(code_bytes))
            fn = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)(addr)
            return [int(fn(a)) for a in args]
        finally:
            k32.VirtualFree(addr, 0, 0x8000)
    else:
        import mmap
        buf = mmap.mmap(
            -1,
            max(4096, len(code_bytes)),
            prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
        )
        try:
            buf.write(code_bytes)
            addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
            fn = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)(addr)
            return [int(fn(a)) for a in args]
        finally:
            buf.close()


def _unload_cdll(lib: ctypes.CDLL) -> None:
    if sys.platform == "win32":
        ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(lib._handle))


class TestAlphaC82UnrollStrengthScheduling(unittest.TestCase):
    def test_01_x64_direct_reg_imm32_and_cmp_br_fusion(self):
        tree_fnv = ast.parse(inspect.getsource(crypto_fnv_mix_kernel))
        ssa_fnv = lower_ast_to_ssa(tree_fnv.body[0], optimize=True)
        art_fnv = X64CodeGenerator(target_os="windows" if sys.platform == "win32" else "linux").compile_function(ssa_fnv)

        self.assertTrue(art_fnv.leaf_register_mode)
        self.assertEqual(art_fnv.stack_frame_size, 0)
        # Compact fused + imm32 FNV kernel should fit well under 130 bytes (was 232 bytes in C81)
        self.assertLessEqual(len(art_fnv.code_bytes), 130)

        if _is_x86_64():
            test_ns = [-2, 0, 1, 2, 10, 100, 2000]
            results = _jit_exec_x64_i64_many(art_fnv.code_bytes, test_ns)
            for n, got in zip(test_ns, results):
                self.assertEqual(got, crypto_fnv_mix_kernel(n))

    def test_02_hybrid_reg_alloc_and_inlined_const_bypass(self):
        # 1. Verify omni_bench_dispatch retains leaf_register_mode=True, stack=0 even after ThinLTO + LICM + Layout
        lto = ThinLTOOptimizer()
        funcs = {}
        for f in (polybench_gemm_kernel, jacobi_1d_kernel, crypto_fnv_mix_kernel, omni_bench_dispatch):
            tree = ast.parse(inspect.getsource(f))
            ssa = lower_ast_to_ssa(tree.body[0], optimize=True)
            ssa, _ = SCEVAnalyzer().analyze_function(ssa)
            funcs[f.__name__] = ssa
            lto.index.add_function(lto.build_function_summary(f.__name__, "r", tree.body[0], ssa))

        disp, lto_stats = lto.optimize_interprocedural_ssa(funcs["omni_bench_dispatch"])
        self.assertEqual(lto_stats["inlined_calls"], 3)
        disp, _ = LICMPass().run_on_function(disp)
        disp, _ = BlockLayoutPass().run_on_function(disp)

        art_disp = X64CodeGenerator(target_os="windows" if sys.platform == "win32" else "linux").compile_function(disp)
        self.assertTrue(art_disp.leaf_register_mode)
        self.assertEqual(art_disp.stack_frame_size, 0)

        # 2. Verify high-pressure >12 simultaneous live variables uses hybrid spill cleanly without crashing
        src_high_pressure = textwrap.dedent("""
        def high_pressure_sum(x: int) -> int:
            v0 = x + 1
            v1 = x + 2
            v2 = x + 3
            v3 = x + 4
            v4 = x + 5
            v5 = x + 6
            v6 = x + 7
            v7 = x + 8
            v8 = x + 9
            v9 = x + 10
            v10 = x + 11
            v11 = x + 12
            v12 = x + 13
            return v0 + v1 + v2 + v3 + v4 + v5 + v6 + v7 + v8 + v9 + v10 + v11 + v12
        """)
        hp_fn = lower_ast_to_ssa(ast.parse(src_high_pressure).body[0], optimize=True)
        art_hp = X64CodeGenerator(target_os="windows" if sys.platform == "win32" else "linux").compile_function(hp_fn)
        self.assertTrue(art_hp.leaf_register_mode)
        if _is_x86_64():
            vals = _jit_exec_x64_i64_many(art_hp.code_bytes, [-10, 0, 5, 100])
            for x, got in zip([-10, 0, 5, 100], vals):
                self.assertEqual(got, sum(x + k for k in range(1, 14)))

    def test_03_scalar_4x_loop_unroll_and_strength_reduction(self):
        for py_fn, args in [
            (jacobi_1d_kernel, [-3, 0, 1, 2, 3, 4, 5, 7, 13, 500]),
            (crypto_fnv_mix_kernel, [-3, 0, 1, 2, 3, 4, 5, 7, 15, 2000]),
        ]:
            tree = ast.parse(inspect.getsource(py_fn))
            ssa = lower_ast_to_ssa(tree.body[0], optimize=True)
            unrolled_ssa, u_stats = LoopUnrollPass(unroll_factor=4).unroll_function(ssa)
            self.assertGreaterEqual(u_stats["unrolled_loops"], 1)
            self.assertTrue(any(b.name.startswith("unroll_tail_cond_") for b in unrolled_ssa.blocks))

            if py_fn is crypto_fnv_mix_kernel:
                # Verify IV multiplication strength reduction replaced inner muls with sr adds
                has_sr = any(
                    ins.result is not None and "_sr" in ins.result.name and ins.opcode == "add"
                    for b in unrolled_ssa.blocks
                    for ins in b.instructions
                )
                self.assertTrue(has_sr, "Expected IV strength reduction in 4x unrolled crypto_fnv_mix_kernel")

            if _is_x86_64():
                art = NativeCodeGenerator(arch="x86_64").compile_ssa(unrolled_ssa)
                results = _jit_exec_x64_i64_many(art.code_bytes, args)
                for a, got in zip(args, results):
                    self.assertEqual(got, py_fn(a), f"{py_fn.__name__}({a}): {got} != {py_fn(a)}")

    def test_04_pre_irc_dag_scheduling_and_e2e_shared_lib(self):
        # Verify scheduler keeps pinned cmp+br_cond anchor while reordering latency-weighted arithmetic
        vx = SSAVar("x", 0)
        vc3 = SSAVar("c3", 0)
        va = SSAVar("a", 0)
        vb = SSAVar("b", 0)
        vc = SSAVar("c", 0)
        v_cond = SSAVar("cond", 0)
        insts = [
            SSAInstruction(vc3, "const", [3]),
            SSAInstruction(va, "add", [vx, vc3]),
            SSAInstruction(vb, "mul", [vx, vc3]),
            SSAInstruction(vc, "add", [va, vb]),
            SSAInstruction(v_cond, "cmp_lt", [vc, vc3]),
            SSAInstruction(None, "br_cond", [v_cond, "then_b", "else_b"]),
        ]
        sched = _schedule_basic_block_instructions(insts, {v_cond: 1})
        self.assertEqual(sched[-2].opcode, "cmp_lt")
        self.assertEqual(sched[-1].opcode, "br_cond")

        # Full end-to-end compilation & native ctypes verification across all 4 kernels
        with tempfile.TemporaryDirectory() as td:
            rdir = os.path.join(td, "c82_repo")
            os.makedirs(rdir, exist_ok=True)
            src = "\n\n".join(inspect.getsource(f) for f in (
                polybench_gemm_kernel,
                jacobi_1d_kernel,
                crypto_fnv_mix_kernel,
                omni_bench_dispatch,
            ))
            with open(os.path.join(rdir, "kernels.py"), "w", encoding="utf-8") as f:
                f.write(src)
            res = OmniRepoCompiler().compile_repositories(
                [rdir],
                output_path=os.path.join(td, "c82_lib"),
                target_format="shared_lib",
                entry_export="omni_bench_dispatch",
                export_all=True,
            )
            cg = res["stages"]["codegen"]
            self.assertEqual(cg["smt_pass_rollbacks"], 0)
            self.assertGreaterEqual(cg["scev_reductions"], 2)
            self.assertGreaterEqual(cg["unrolled_loops"], 1)
            self.assertEqual(cg["thin_lto_inlines"], 3)

            if sys.platform in ("win32", "linux"):
                lib = ctypes.CDLL(res["stages"]["emission"]["artifact_path"])
                try:
                    disp_fn = getattr(lib, "omni_bench_dispatch")
                    disp_fn.argtypes = [ctypes.c_int64, ctypes.c_int64]
                    disp_fn.restype = ctypes.c_int64
                    self.assertEqual(disp_fn(0, 40), 75794800)
                    self.assertEqual(disp_fn(1, 500), 1354)
                    self.assertEqual(disp_fn(2, 2000), 573974629)
                finally:
                    _unload_cdll(lib)

    def test_05_arm64_smulh_and_shift_constant_division(self):
        gen = Arm64CodeGenerator()
        for op_name in ("sdiv", "srem"):
            for d in (2, 3, 4, 5, 7, 10, 15):
                vx = SSAVar("x", 0)
                vd = SSAVar("d", 0)
                vr = SSAVar("res", 0)
                bb = BasicBlock("entry")
                bb.instructions = [
                    SSAInstruction(vx, "param", ["x"]),
                    SSAInstruction(vd, "const", [d]),
                    SSAInstruction(vr, op_name, [vx, vd]),
                    SSAInstruction(None, "ret", [vr]),
                ]
                fn = SSAFunction(f"arm_{op_name}_{d}", params=["x"], param_types={"x": "i64"})
                fn.blocks = [bb]
                art = gen.compile_function(fn)
                self.assertGreater(len(art.code_bytes), 0)
                for off in range(0, len(art.code_bytes), 4):
                    word = int.from_bytes(art.code_bytes[off:off + 4], "little")
                    self.assertNotEqual(
                        word & 0xFFE0FC00,
                        0x9AC00C00,
                        f"Hardware SDIV found in ARM64 {op_name} by {d}",
                    )
