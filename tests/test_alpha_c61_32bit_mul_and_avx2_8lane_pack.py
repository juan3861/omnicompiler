"""
Alpha-C61 End-to-End Verification Suite (100% SIMD Symmetry & Ceiling Completeness):
1. 32-bit Integer Vector Multiplication (`vpmulld` `c4 e2 7d 40 c1` in AVX2 8-lane &
   `pmulld` `66 0f 38 40 c1` in SSE4.1 4-lane) in `X64CodeGenerator`, matching ARM64 NEON (`MUL V0.4S`),
   WebAssembly `v128` (`i32x4.mul`), and LLVM O3.
2. General 256-bit AVX2 8-Lane 32-bit Pack-and-Store (`vmovd`, `vpinsrd`, `vmovd r11d, xmm2`,
   `vinserti128`, `vmovdqu [r11], ymm0`, `vzeroupper`) for non-binary-load 32-bit `i32`/`f32` loops
   (`out32[i] = a32[i] * 3 + 1`, `fout32[i] = fa32[i] * 2.5 + 0.5`).
3. Quad-ISA Parity (x86-64 AVX2, ARM64 NEON Unicorn, Wasmtime v128, LLVM O3) on `i32` vector multiply.
"""

import ast
import ctypes
import os
import struct
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from compiler.llvm_backend import LLVMBackend
from compiler.loop_vectorizer import LoopVectorizerPass
from compiler.native_codegen import Arm64CodeGenerator, X64CodeGenerator, _host_supports_avx2
from compiler.native_jit import NativeJitCompiler
from compiler.ssa_ir import AstToSsaLowering
from compiler.wasm_backend import WasmBackend
from validation.assembly_invariant_auditor import AssemblyInvariantAuditor
from validation.silicon_safety_sandbox import SiliconSafetySandbox


class TestAlphaC6132BitMulAndAvx28LanePack(unittest.TestCase):
    def test_01_x64_32bit_mul_vpmulld_avx2_and_pmulld_sse41(self):
        """Verifies 32-bit `vpmulld` (AVX2 8-lane) and `pmulld` (SSE4.1 4-lane) opcodes + Quad-ISA parity."""
        src = """
def vec_mul_i32(base: int, n: int) -> int:
    i = 0
    while i < n:
        a = load_i32(base, i * 4)
        b = load_i32(base, 256 + i * 4)
        store_i32(base, 512 + i * 4, a * b)
        i += 1
    return n
"""
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)

        code_avx = X64CodeGenerator(enable_avx2=True).compile_function(vec_fn).code_bytes
        self.assertIn(b"\xc4\xe2\x7d\x40\xc1", code_avx, "Missing AVX2 vpmulld ymm0, ymm0, ymm1")
        self.assertIn(b"\xc5\xf8\x77", code_avx, "Missing vzeroupper")
        self.assertTrue(AssemblyInvariantAuditor().audit_function_code(code_avx, "vec_mul_i32").is_valid)

        code_sse = X64CodeGenerator(enable_avx2=False).compile_function(vec_fn).code_bytes
        self.assertIn(b"\x66\x0f\x38\x40\xc1", code_sse, "Missing SSE4.1 pmulld xmm0, xmm1")
        self.assertTrue(AssemblyInvariantAuditor().audit_function_code(code_sse, "vec_mul_i32").is_valid)

        arm_code = Arm64CodeGenerator().compile_function(vec_fn).code_bytes
        ll = LLVMBackend(opt_level=3)
        llvm_fn = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn)),
            "vec_mul_i32",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_int64, ctypes.c_int64],
        )

        n_items = 23
        init_arena = bytearray(1024)
        for k in range(n_items):
            struct.pack_into("<i", init_arena, k * 4, k * 11 - 30)
            struct.pack_into("<i", init_arena, 256 + k * 4, 7 - k * 2)

        llvm_buf = (ctypes.c_uint8 * 1024).from_buffer_copy(init_arena)
        self.assertEqual(llvm_fn(ctypes.addressof(llvm_buf), n_items), n_items)
        out_llvm = bytes(llvm_buf)[512 : 512 + n_items * 4]

        if _host_supports_avx2():
            x64_fn, _m, _ = NativeJitCompiler().compile_ssa(vec_fn)
            x64_buf = (ctypes.c_uint8 * 1024).from_buffer_copy(init_arena)
            self.assertEqual(x64_fn(ctypes.addressof(x64_buf), n_items), n_items)
            self.assertEqual(bytes(x64_buf)[512 : 512 + n_items * 4], out_llvm)

        emu_arm = SiliconSafetySandbox().emulate_arm64(
            arm_code, args=[0x400000, n_items], memory_regions={0x400000: bytes(init_arena)}
        )
        self.assertTrue(emu_arm.success, emu_arm.error)
        self.assertEqual(emu_arm.memory_snapshots[0x400000][512 : 512 + n_items * 4], out_llvm)

        wb = WasmBackend()
        if wb.is_available() if callable(wb.is_available) else wb.is_available:
            import wasmtime
            wat_text = wb.ssa_to_wat(vec_fn)
            self.assertIn("i32x4.mul", wat_text)
            engine = wasmtime.Engine()
            store = wasmtime.Store(engine)
            inst = wasmtime.Instance(store, wasmtime.Module(engine, wb.wat_to_wasm(wat_text)), [])
            mem = inst.exports(store)["memory"]
            mem.write(store, bytes(init_arena), 0x1000)
            self.assertEqual(inst.exports(store)["vec_mul_i32"](store, 0x1000, n_items), n_items)
            self.assertEqual(bytes(mem.read(store, 0x1000 + 512, 0x1000 + 512 + n_items * 4)), out_llvm)

    def test_02_avx2_8lane_32bit_general_pack_and_store_i32_and_f32(self):
        """Verifies 256-bit AVX2 8-lane pack-and-store (`vpinsrd`, `vinserti128`, `vmovdqu [r11], ymm0`) for affine i32/f32."""
        src = """
class Affine32:
    ai: Array[i32, 64]
    outi: Array[i32, 64]
    af: Array[f32, 64]
    outf: Array[f32, 64]

def affine_pack_32(s: Affine32, n: int) -> int:
    i = 0
    while i < n:
        s.outi[i] = s.ai[i] * 3 + 1
        s.outf[i] = s.af[i] * 2.5 + 0.5
        i += 1
    return n
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)

        code = X64CodeGenerator(enable_avx2=True).compile_function(vec_fn).code_bytes
        self.assertIn(b"\xc4\xc3\x79\x22\xc3\x01", code, "Missing vpinsrd xmm0, xmm0, r11d, 1")
        self.assertIn(b"\xc4\xc3\x71\x22\xcb\x03", code, "Missing vpinsrd xmm1, xmm1, r11d, 3")
        self.assertIn(b"\xc4\xe3\x7d\x18\xc1\x01", code, "Missing vinserti128 ymm0, ymm0, xmm1, 1")
        self.assertIn(b"\xc4\xc1\x7e\x7f\x03", code, "Missing vmovdqu [r11], ymm0")
        self.assertIn(b"\xc5\xf8\x77", code, "Missing vzeroupper")
        self.assertTrue(AssemblyInvariantAuditor().audit_function_code(code, "affine_pack_32").is_valid)

        if not _host_supports_avx2():
            self.skipTest("Host CPU does not advertise AVX2")

        class Affine32Struct(ctypes.Structure):
            _fields_ = [
                ("ai", ctypes.c_int32 * 64),
                ("outi", ctypes.c_int32 * 64),
                ("af", ctypes.c_float * 64),
                ("outf", ctypes.c_float * 64),
            ]

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        for n in (0, 1, 7, 8, 9, 19, 35):
            st = Affine32Struct()
            for k in range(64):
                st.ai[k] = k * 5 - 30
                st.af[k] = 1.0 + k * 0.25
            self.assertEqual(cf(ctypes.addressof(st), n), n)
            for k in range(n):
                self.assertEqual(st.outi[k], st.ai[k] * 3 + 1)
                self.assertAlmostEqual(st.outf[k], st.af[k] * 2.5 + 0.5, places=5)


if __name__ == "__main__":
    unittest.main()
