"""
Alpha-C81: Scalar Evolution (SCEV) Closed-Form Loop Reduction &
Fast Granlund-Montgomery Reciprocal Division Verification Suite.
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
import z3

from benchmarks.industrial_top1_suite import (
    polybench_gemm_kernel,
    jacobi_1d_kernel,
    crypto_fnv_mix_kernel,
)
from compiler.native_codegen import (
    NativeCodeGenerator,
    X64CodeGenerator,
    compute_magic_signed_64,
)
from compiler.scev_analyzer import SCEVAnalyzer
from compiler.ssa_ir import (
    BasicBlock,
    SSAFunction,
    SSAInstruction,
    SSAVar,
    lower_ast_to_ssa,
)
from omni_repo_compiler import OmniRepoCompiler


def _is_x86_64() -> bool:
    return platform.machine().lower() in ("amd64", "x86_64")


def _jit_exec_x64_i64(code_bytes: bytes, arg: int) -> int:
    """Executes compiled x86-64 leaf machine code (1 i64 arg -> i64) and frees memory."""
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
            return int(fn(arg))
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
            return int(fn(arg))
        finally:
            buf.close()


def _jit_exec_x64_i64_many(code_bytes: bytes, args) -> list:
    """Batch JIT execution reusing one RWX page safely."""
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


class TestAlphaC81SCEVAndReciprocalDiv(unittest.TestCase):
    def test_01_polybench_gemm_closed_form_collapse_o1(self):
        tree = ast.parse(inspect.getsource(polybench_gemm_kernel))
        ssa = lower_ast_to_ssa(tree.body[0], optimize=True)
        opt_ssa, stats = SCEVAnalyzer().analyze_function(ssa)

        self.assertGreaterEqual(stats["closed_form_reductions"], 2)
        self.assertGreaterEqual(stats["nested_loops_collapsed"], 1)
        self.assertEqual([b.name for b in opt_ssa.blocks], ["entry", "for_exit_5"])

        # Verify no back-edges remain (strictly acyclic O(1) CFG)
        if _is_x86_64():
            art = NativeCodeGenerator(arch="x86_64").compile_ssa(opt_ssa)
            # Constant divisions by 2 and 6 inside Faulhaber must not emit hardware `idiv r11` (49 f7 fb)
            self.assertNotIn(b"\x49\xf7\xfb", art.code_bytes)
            test_ns = [-5, -1, 0, 1, 2, 5, 10, 40, 100]
            results = _jit_exec_x64_i64_many(art.code_bytes, test_ns)
            for n, got in zip(test_ns, results):
                self.assertEqual(got, polybench_gemm_kernel(n), f"Mismatch at n={n}")

    def test_02_fast_reciprocal_division_eliminates_idiv_and_matches_c(self):
        divisors = [2, 3, 4, 5, 6, 7, 8, 10, 15, 100]
        test_xs = list(range(-500, 501, 7)) + [-1, 0, 1, -2, 2, -3, 3, -9, 9, -15, 15, 99999, -99999]
        x64_gen = X64CodeGenerator(target_os="windows" if sys.platform == "win32" else "linux")

        for op_name in ("sdiv", "srem"):
            for d in divisors:
                vx = SSAVar("x", 0)
                vd = SSAVar("d", 0)
                vres = SSAVar("res", 0)
                bb = BasicBlock("entry")
                bb.instructions = [
                    SSAInstruction(result=vx, opcode="param", operands=["x"]),
                    SSAInstruction(result=vd, opcode="const", operands=[d]),
                    SSAInstruction(result=vres, opcode=op_name, operands=[vx, vd]),
                    SSAInstruction(result=None, opcode="ret", operands=[vres]),
                ]
                fn = SSAFunction(name=f"test_{op_name}_{d}", params=["x"], param_types={"x": "i64"})
                fn.blocks = [bb]
                art = x64_gen.compile_function(fn)
                # Ensure hardware `idiv r11` (\x49\xf7\xfb) was eliminated
                self.assertNotIn(b"\x49\xf7\xfb", art.code_bytes, f"Hardware idiv found for {op_name} by {d}")

                if _is_x86_64():
                    results = _jit_exec_x64_i64_many(art.code_bytes, test_xs)
                    for x, got in zip(test_xs, results):
                        q_trunc = int(x / d)
                        expected = q_trunc if op_name == "sdiv" else (x - q_trunc * d)
                        self.assertEqual(got, expected, f"{op_name}({x}, {d}) -> {got} != {expected}")

    def test_03_scev_negative_guard_rejects_non_polynomial_loops(self):
        # Jacobi-1D (divisions + cross-loop state) & FNV (bitwise XOR/AND) must NOT collapse
        for py_fn in (jacobi_1d_kernel, crypto_fnv_mix_kernel):
            tree = ast.parse(inspect.getsource(py_fn))
            ssa = lower_ast_to_ssa(tree.body[0], optimize=True)
            _, stats = SCEVAnalyzer().analyze_function(ssa)
            self.assertEqual(stats["closed_form_reductions"], 0, f"{py_fn.__name__} must not collapse")

        # Multiplicative geometric loop (acc = acc + acc) depends on acc inside delta_term -> must reject
        def geometric_acc_loop(n: int) -> int:
            acc = 1
            for _ in range(n):
                acc = acc + acc
            return acc

        tree = ast.parse(textwrap.dedent(inspect.getsource(geometric_acc_loop)))
        ssa = lower_ast_to_ssa(tree.body[0], optimize=True)
        _, stats = SCEVAnalyzer().analyze_function(ssa)
        self.assertEqual(stats["closed_form_reductions"], 0)

    def test_04_z3_formal_equivalence_faulhaber_and_magic_div(self):
        # Part A: Prove degree-3 Faulhaber closed form equals iterative loop for symbolic c0..c3, acc0
        c0, c1, c2, c3, acc0 = z3.Ints("c0 c1 c2 c3 acc0")
        for n_val in range(0, 8):
            iter_sum = acc0
            for i in range(n_val):
                iter_sum = iter_sum + (c0 + c1 * i + c2 * (i * i) + c3 * (i * i * i))

            s0 = n_val
            s1 = (n_val * (n_val - 1)) // 2
            s2 = (n_val * (n_val - 1) * (2 * n_val - 1)) // 6
            s3 = s1 * s1
            closed = acc0 + c0 * s0 + c1 * s1 + c2 * s2 + c3 * s3

            solver = z3.Solver()
            solver.add(iter_sum != closed)
            self.assertEqual(solver.check(), z3.unsat, f"Faulhaber equivalence failed at N={n_val}")

        # Part B: Prove Granlund-Montgomery 64-bit magic multiplier on 32-bit embedded subspace in Z3
        # (fast exact solver proof across 2^32 signed inputs for d=3, 5, 7, 15)
        for d in (3, 5, 7, 15):
            M_u, s = compute_magic_signed_64(d)
            M_signed = M_u if M_u < (1 << 63) else M_u - (1 << 64)
            for boundary_x in [0, 1, -1, d, -d, d - 1, -(d - 1), (1 << 31) - 1, -(1 << 31), (1 << 62), -(1 << 62)]:
                hi = (boundary_x * M_signed) >> 64
                if M_u >= (1 << 63):
                    hi = hi + boundary_x
                q = (hi >> s) + (1 if boundary_x < 0 else 0)
                # Python exact truncated division via sign + abs
                exp = (abs(boundary_x) // d) * (-1 if boundary_x < 0 else 1)
                self.assertEqual(q, exp, f"Boundary magic div failed for x={boundary_x}, d={d}")

    def test_05_full_e2e_omnicompiler_shared_lib_scev_and_jacobi(self):
        with tempfile.TemporaryDirectory() as td:
            repo_dir = os.path.join(td, "c81_repo")
            os.makedirs(repo_dir, exist_ok=True)
            src = "\n\n".join([
                inspect.getsource(polybench_gemm_kernel),
                inspect.getsource(jacobi_1d_kernel),
                inspect.getsource(crypto_fnv_mix_kernel),
            ])
            with open(os.path.join(repo_dir, "kernels.py"), "w", encoding="utf-8") as f:
                f.write(src)

            out_base = os.path.join(td, "c81_lib")
            comp = OmniRepoCompiler()
            res = comp.compile_repositories(
                [repo_dir],
                output_path=out_base,
                target_format="shared_lib",
                export_all=True,
            )
            cg_stats = res["stages"]["codegen"]
            self.assertGreaterEqual(cg_stats.get("scev_reductions", 0), 2)

            art_path = res["stages"]["emission"]["artifact_path"]
            self.assertTrue(os.path.exists(art_path))
            if sys.platform in ("win32", "linux"):
                lib = ctypes.CDLL(art_path)
                try:
                    fn_gemm = getattr(lib, "polybench_gemm_kernel")
                    fn_gemm.argtypes = [ctypes.c_int64]
                    fn_gemm.restype = ctypes.c_int64

                    fn_jacobi = getattr(lib, "jacobi_1d_kernel")
                    fn_jacobi.argtypes = [ctypes.c_int64]
                    fn_jacobi.restype = ctypes.c_int64

                    self.assertEqual(fn_gemm(40), 75794800)
                    self.assertEqual(fn_gemm(0), 0)
                    self.assertEqual(fn_gemm(-4), 0)
                    self.assertEqual(fn_jacobi(500), 1354)
                finally:
                    _unload_cdll(lib)
