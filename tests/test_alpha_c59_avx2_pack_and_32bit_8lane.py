"""
Alpha-C59 End-to-End Verification Suite:
1. Direct 256-bit AVX2 Pack-and-Store (`vmovq`, `vpinsrq`, `vinserti128 ymm0, ymm0, xmm1, 1`,
   `vmovdqu [r11], ymm0`, `vzeroupper`) for non-binary-load 64-bit 4-lane stores (prefix scans & affine maps).
2. Direct 256-bit AVX2 8-Lane 32-bit Packed SIMD (`vpaddd` `c5 fd fe c1`, `vmulps` `c5 fc 59 c1`,
   `vmovdqu ymm0/ymm1`, `vzeroupper`) for 8x contiguous i32/f32 loads, ALU, and stores.
3. Quad-ISA Parity (x86-64 AVX2, ARM64 NEON Unicorn, Wasmtime v128, LLVM O3) for fused
   prefix-scan + affine pack-and-store + Order-3 Tribonacci recurrence.
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


def _s64(val: int) -> int:
    u = int(val) & 0xFFFFFFFFFFFFFFFF
    return u - 0x10000000000000000 if (u & 0x8000000000000000) else u


class TestAlphaC59Avx2PackAnd32Bit8Lane(unittest.TestCase):
    def test_01_avx2_256bit_pack_and_store_prefix_scan_and_scale(self):
        """Verifies 256-bit AVX2 pack-and-store (`vpinsrq`, `vinserti128`, `vmovdqu ymm`, `vzeroupper`) on prefix scan + scale."""
        src = """
class PackArena:
    inp: Array[i64, 64]
    scaled: Array[i64, 64]
    scan: Array[i64, 64]

def pack_and_scan(t: PackArena, n: int) -> int:
    s = 0
    i = 0
    while i < n:
        v = t.inp[i]
        t.scaled[i] = v * 3 + 1
        s += v
        t.scan[i] = s
        i += 1
    return s
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)

        cg = X64CodeGenerator(enable_avx2=True)
        code = cg.compile_function(vec_fn).code_bytes
        self.assertIn(b"\xc4\xc3\xf9\x22\xc3\x01", code, "Missing vpinsrq xmm0, xmm0, r11, 1")
        self.assertIn(b"\xc4\xc3\xf1\x22\xcb\x01", code, "Missing vpinsrq xmm1, xmm1, r11, 1")
        self.assertIn(b"\xc4\xe3\x7d\x18\xc1\x01", code, "Missing vinserti128 ymm0, ymm0, xmm1, 1")
        self.assertIn(b"\xc4\xc1\x7e\x7f\x03", code, "Missing vmovdqu [r11], ymm0")
        self.assertIn(b"\xc5\xf8\x77", code, "Missing vzeroupper")

        audit = AssemblyInvariantAuditor().audit_function_code(code, "pack_and_scan")
        self.assertTrue(audit.is_valid, audit.errors)

        if not _host_supports_avx2():
            self.skipTest("Host CPU does not advertise AVX2")

        class PackArenaStruct(ctypes.Structure):
            _fields_ = [
                ("inp", ctypes.c_int64 * 64),
                ("scaled", ctypes.c_int64 * 64),
                ("scan", ctypes.c_int64 * 64),
            ]

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        for n in (0, 1, 3, 4, 7, 16, 29):
            pa = PackArenaStruct()
            for k in range(64):
                pa.inp[k] = (k * 5) - 20
            got = cf(ctypes.addressof(pa), n)
            exp_s = 0
            for k in range(n):
                v = pa.inp[k]
                exp_s += v
                self.assertEqual(pa.scaled[k], v * 3 + 1)
                self.assertEqual(pa.scan[k], exp_s)
            self.assertEqual(got, exp_s)

    def test_02_avx2_256bit_8lane_32bit_packed_vpaddd_and_vmulps(self):
        """Verifies 256-bit AVX2 8-lane 32-bit packed `vpaddd` and `vmulps` fusion + live execution."""
        src = """
def avx2_8lane_32bit(dst_i: int, a_i: int, b_i: int, dst_f: int, a_f: int, b_f: int) -> int:
    o0 = 0
    o1 = 4
    o2 = 8
    o3 = 12
    o4 = 16
    o5 = 20
    o6 = 24
    o7 = 28
    i0 = load_i32(a_i, o0) + load_i32(b_i, o0)
    i1 = load_i32(a_i, o1) + load_i32(b_i, o1)
    i2 = load_i32(a_i, o2) + load_i32(b_i, o2)
    i3 = load_i32(a_i, o3) + load_i32(b_i, o3)
    i4 = load_i32(a_i, o4) + load_i32(b_i, o4)
    i5 = load_i32(a_i, o5) + load_i32(b_i, o5)
    i6 = load_i32(a_i, o6) + load_i32(b_i, o6)
    i7 = load_i32(a_i, o7) + load_i32(b_i, o7)
    store_i32(dst_i, o0, i0)
    store_i32(dst_i, o1, i1)
    store_i32(dst_i, o2, i2)
    store_i32(dst_i, o3, i3)
    store_i32(dst_i, o4, i4)
    store_i32(dst_i, o5, i5)
    store_i32(dst_i, o6, i6)
    store_i32(dst_i, o7, i7)
    f0 = load_f32(a_f, o0) * load_f32(b_f, o0)
    f1 = load_f32(a_f, o1) * load_f32(b_f, o1)
    f2 = load_f32(a_f, o2) * load_f32(b_f, o2)
    f3 = load_f32(a_f, o3) * load_f32(b_f, o3)
    f4 = load_f32(a_f, o4) * load_f32(b_f, o4)
    f5 = load_f32(a_f, o5) * load_f32(b_f, o5)
    f6 = load_f32(a_f, o6) * load_f32(b_f, o6)
    f7 = load_f32(a_f, o7) * load_f32(b_f, o7)
    store_f32(dst_f, o0, f0)
    store_f32(dst_f, o1, f1)
    store_f32(dst_f, o2, f2)
    store_f32(dst_f, o3, f3)
    store_f32(dst_f, o4, f4)
    store_f32(dst_f, o5, f5)
    store_f32(dst_f, o6, f6)
    store_f32(dst_f, o7, f7)
    return 1
"""
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        cg = X64CodeGenerator(enable_avx2=True)
        code = cg.compile_function(ssa_fn).code_bytes

        self.assertIn(b"\xc4\xc1\x7e\x6f\x03", code, "Missing vmovdqu ymm0, [r11]")
        self.assertIn(b"\xc4\xc1\x7e\x6f\x0b", code, "Missing vmovdqu ymm1, [r11]")
        self.assertIn(b"\xc5\xfd\xfe\xc1", code, "Missing vpaddd ymm0, ymm0, ymm1")
        self.assertIn(b"\xc5\xfc\x59\xc1", code, "Missing vmulps ymm0, ymm0, ymm1")
        self.assertIn(b"\xc4\xc1\x7e\x7f\x03", code, "Missing vmovdqu [r11], ymm0")
        self.assertIn(b"\xc5\xf8\x77", code, "Missing vzeroupper")

        audit = AssemblyInvariantAuditor().audit_function_code(code, "avx2_8lane_32bit")
        self.assertTrue(audit.is_valid, audit.errors)

        if not _host_supports_avx2():
            self.skipTest("Host CPU does not advertise AVX2")

        cf, _mem, _ = NativeJitCompiler().compile_ssa(ssa_fn)
        ai = (ctypes.c_int32 * 8)(*[10 + k * 7 for k in range(8)])
        bi = (ctypes.c_int32 * 8)(*[100 - k * 11 for k in range(8)])
        di = (ctypes.c_int32 * 8)()
        af = (ctypes.c_float * 8)(*[1.25 + k * 0.5 for k in range(8)])
        bf = (ctypes.c_float * 8)(*[4.0 - k * 0.25 for k in range(8)])
        df = (ctypes.c_float * 8)()

        rc = cf(
            ctypes.addressof(di), ctypes.addressof(ai), ctypes.addressof(bi),
            ctypes.addressof(df), ctypes.addressof(af), ctypes.addressof(bf),
        )
        self.assertEqual(rc, 1)
        for k in range(8):
            self.assertEqual(di[k], ai[k] + bi[k])
            self.assertAlmostEqual(df[k], af[k] * bf[k], places=5)

    def test_03_quad_isa_parity_fused_pack_scan_and_tribonacci(self):
        """Verifies Quad-ISA parity (x86-64 AVX2, ARM64 NEON Unicorn, Wasmtime v128, LLVM O3) with pack-and-store."""
        src = """
def quad_pack_scan_trib(base: int, n: int) -> int:
    i = 0
    s = 0
    a = 1
    b = 2
    c = 3
    while i < n:
        v = load_i64(base, i * 8)
        s += v
        store_i64(base, 256 + i * 8, v * 3 + 1)
        store_i64(base, 512 + i * 8, s)
        nxt = a + b + c + v
        a = b
        b = c
        c = nxt
        i += 1
    return s + a * 3 + b * 5 + c * 7
"""
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)

        x64_fn, _m, _ = NativeJitCompiler().compile_ssa(vec_fn)
        arm_code = Arm64CodeGenerator().compile_function(vec_fn).code_bytes
        ll = LLVMBackend(opt_level=3)
        llvm_fn = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn)),
            "quad_pack_scan_trib",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_int64, ctypes.c_int64],
        )

        n_items = 17
        init_arena = bytearray(2048)
        for k in range(n_items):
            struct.pack_into("<q", init_arena, k * 8, (k + 2) * 7 - 20)

        llvm_buf = (ctypes.c_uint8 * 2048).from_buffer_copy(init_arena)
        res_llvm = llvm_fn(ctypes.addressof(llvm_buf), n_items)
        out_llvm = bytes(llvm_buf)[256 : 512 + n_items * 8]

        if _host_supports_avx2():
            x64_buf = (ctypes.c_uint8 * 2048).from_buffer_copy(init_arena)
            res_x64 = x64_fn(ctypes.addressof(x64_buf), n_items)
            self.assertEqual(res_x64, res_llvm)
            self.assertEqual(bytes(x64_buf)[256 : 512 + n_items * 8], out_llvm)

        emu_arm = SiliconSafetySandbox().emulate_arm64(
            arm_code,
            args=[0x400000, n_items],
            memory_regions={0x400000: bytes(init_arena)},
        )
        self.assertTrue(emu_arm.success, emu_arm.error)
        self.assertEqual(_s64(emu_arm.return_value), res_llvm)
        self.assertEqual(emu_arm.memory_snapshots[0x400000][256 : 512 + n_items * 8], out_llvm)

        wb = WasmBackend()
        if wb.is_available() if callable(wb.is_available) else wb.is_available:
            import wasmtime
            wat_text = wb.ssa_to_wat(vec_fn)
            self.assertIn("v128.store", wat_text)
            engine = wasmtime.Engine()
            module = wasmtime.Module(engine, wb.wat_to_wasm(wat_text))
            store = wasmtime.Store(engine)
            inst = wasmtime.Instance(store, module, [])
            mem = inst.exports(store)["memory"]
            mem.write(store, bytes(init_arena), 0x1000)
            res_wasm = _s64(inst.exports(store)["quad_pack_scan_trib"](store, 0x1000, n_items))
            self.assertEqual(res_wasm, res_llvm)
            self.assertEqual(bytes(mem.read(store, 0x1000 + 256, 0x1000 + 512 + n_items * 8)), out_llvm)


if __name__ == "__main__":
    unittest.main()
