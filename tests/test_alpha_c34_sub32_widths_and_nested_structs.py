import ctypes
import os
import struct
import tempfile
import unittest

from compiler.llvm_backend import LLVMBackend
from compiler.native_codegen import Arm64CodeGenerator, X64CodeGenerator
from compiler.native_jit import NativeJitCompiler
from compiler.ssa_ir import lower_ast_to_ssa, lower_source_to_ssa
from compiler.wasm_backend import WasmBackend
from frontends.polyglot_ssa_lowering import lower_polyglot_source_to_ast
from omni_repo_compiler import OmniRepoCompiler
from runtime.native_ffi import omni_ffi_call3, omni_ffi_get_symbol, omni_ffi_load_lib
from validation.backend_translation_validator import BackendTranslationValidator


class CHeader(ctypes.Structure):
    _fields_ = [
        ("ver", ctypes.c_uint8),
        ("flags", ctypes.c_int8),
        ("port", ctypes.c_uint16),
        ("seq", ctypes.c_uint32),
    ]


class CPacketFrame(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_int8),
        ("hdr", CHeader),
        ("delta", ctypes.c_int16),
        ("pad_u16", ctypes.c_uint16),
        ("scale", ctypes.c_float),
        ("energy", ctypes.c_double),
    ]


def _f64_to_u64(v: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", float(v)))[0]


def _sign_extend_bits(val: int, bits: int) -> int:
    mask = (1 << bits) - 1
    v = val & mask
    if v & (1 << (bits - 1)):
        return v - (1 << bits)
    return v


class TestAlphaC34Sub32WidthsAndNestedStructs(unittest.TestCase):
    def test_sub32_signed_unsigned_and_nested_struct_tv_differential(self):
        # Verify exact ABI offset congruence against CPython ctypes.Structure
        self.assertEqual(ctypes.sizeof(CHeader), 8)
        self.assertEqual(ctypes.sizeof(CPacketFrame), 32)
        self.assertEqual(CPacketFrame.hdr.offset, 4)
        self.assertEqual(CPacketFrame.delta.offset, 12)
        self.assertEqual(CPacketFrame.pad_u16.offset, 14)
        self.assertEqual(CPacketFrame.scale.offset, 16)
        self.assertEqual(CPacketFrame.energy.offset, 24)

        src = """
class Header:
    ver: u8
    flags: i8
    port: u16
    seq: u32

class PacketFrame:
    kind: i8
    hdr: Header
    delta: i16
    pad_u16: u16
    scale: f32
    energy: f64

def process_frame(pkt: PacketFrame, inc_seq: int) -> int:
    pkt.hdr.flags += 2
    pkt.hdr.port = 8080
    pkt.hdr.seq += inc_seq
    pkt.delta -= 300
    pkt.pad_u16 += 1
    return pkt.kind + pkt.hdr.flags + pkt.hdr.ver + pkt.hdr.port + pkt.delta + pkt.pad_u16 + pkt.hdr.seq
"""
        ssa_fn = lower_source_to_ssa(src, fn_name="process_frame", optimize=True)
        self.assertEqual(ssa_fn.param_types, {"pkt": "ptr", "inc_seq": "i64"})
        self.assertEqual(ssa_fn.return_type, "i64")

        # Confirm LLVM IR and WAT translation validation prove bounded+inductive equivalence
        btv = BackendTranslationValidator(enable_float_theory=True)
        llvm_ir = LLVMBackend().ssa_to_llvm_ir(ssa_fn)
        wat_src = WasmBackend().ssa_to_wat(ssa_fn)
        res_ll_tv = btv.verify_ssa_to_llvm_ir(ssa_fn, llvm_ir)
        self.assertTrue(res_ll_tv["proven"], f"LLVM TV failed on nested sub-32 struct: {res_ll_tv}")
        res_wa_tv = btv.verify_ssa_to_wat(ssa_fn, wat_src)
        self.assertTrue(res_wa_tv["proven"], f"WAT TV failed on nested sub-32 struct: {res_wa_tv}")

        # Test sign-extension vs zero-extension edge values:
        # kind = -10 (i8), ver = 251 (u8, bit pattern 0xFB), flags = -5 (i8, bit pattern 0xFB) -> +2 = -3
        # port = 1000 -> 8080 (u16), seq = 0xFFFFFFFE + 1 = 0xFFFFFFFF = 4294967295 (u32, NOT -1)
        # delta = 50 -> -250 (i16), pad_u16 = 65535 + 1 -> 0 (16-bit wrap!)
        init_struct = CPacketFrame(
            kind=-10,
            hdr=CHeader(ver=251, flags=-5, port=1000, seq=0xFFFFFFFE),
            delta=50,
            pad_u16=65535,
            scale=2.5,
            energy=42.25,
        )
        raw_init = bytes(init_struct)
        self.assertEqual(len(raw_init), 32)

        diff = btv.verify_differential_execution(ssa_fn, [(bytearray(raw_init), 1)])
        self.assertTrue(diff["equivalent"], f"Differential parity failed on sub-32 nested struct: {diff}")

        expected_ret = -10 + (-3) + 251 + 8080 + (-250) + 0 + 0xFFFFFFFF
        self.assertEqual(diff["outputs_by_backend"]["native"][0], expected_ret)

        expected_final = CPacketFrame.from_buffer_copy(raw_init)
        expected_final.hdr.flags = -3
        expected_final.hdr.port = 8080
        expected_final.hdr.seq = 0xFFFFFFFF
        expected_final.delta = -250
        expected_final.pad_u16 = 0
        self.assertEqual(diff["memory_by_backend"]["native"][0]["pkt"], bytes(expected_final))

    def test_arm64_sub32_widths_and_nested_struct_unicorn_execution(self):
        from unicorn import UC_ARCH_ARM64, UC_MODE_ARM, Uc
        from unicorn.arm64_const import (
            UC_ARM64_REG_CPACR_EL1,
            UC_ARM64_REG_LR,
            UC_ARM64_REG_PC,
            UC_ARM64_REG_SP,
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
        )

        src = """
class Header:
    ver: u8
    flags: i8
    port: u16
    seq: u32

class PacketFrame:
    kind: i8
    hdr: Header
    delta: i16
    pad_u16: u16
    scale: f32
    energy: f64

def arm64_sub32_kernel(pkt: PacketFrame, inc_port: int) -> int:
    pkt.hdr.flags += 2
    pkt.hdr.port += inc_port
    pkt.delta -= 400
    return pkt.kind + pkt.hdr.ver + pkt.hdr.flags + pkt.hdr.port + pkt.delta + pkt.pad_u16 + pkt.hdr.seq
"""
        ssa_fn = lower_source_to_ssa(src, fn_name="arm64_sub32_kernel", optimize=True)
        art = Arm64CodeGenerator().compile_function(ssa_fn)
        self.assertFalse(art.relocations)

        CODE_ADDR = 0x100000
        STOP_ADDR = 0x180000
        STACK_ADDR = 0x200000
        MEM_ADDR = 0x300000

        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        mu.mem_map(CODE_ADDR, 0x10000)
        mu.mem_map(STOP_ADDR, 0x10000)
        mu.mem_map(STACK_ADDR, 0x10000)
        mu.mem_map(MEM_ADDR, 0x10000)
        try:
            cpacr = mu.reg_read(UC_ARM64_REG_CPACR_EL1)
            mu.reg_write(UC_ARM64_REG_CPACR_EL1, cpacr | (0x3 << 20))
        except Exception:
            pass

        mu.mem_write(CODE_ADDR, art.code_bytes)
        mu.mem_write(STOP_ADDR, struct.pack("<I", 0xD503201F))
        pkt_in = CPacketFrame(
            kind=-12,
            hdr=CHeader(ver=250, flags=-10, port=40000, seq=0x80000005),
            delta=100,
            pad_u16=50000,
            scale=1.5,
            energy=9.0,
        )
        mu.mem_write(MEM_ADDR, bytes(pkt_in))
        mu.reg_write(UC_ARM64_REG_SP, STACK_ADDR + 0x8000)
        mu.reg_write(UC_ARM64_REG_LR, STOP_ADDR)
        mu.reg_write(UC_ARM64_REG_X0, MEM_ADDR)
        mu.reg_write(UC_ARM64_REG_X1, 1000)

        mu.emu_start(CODE_ADDR, STOP_ADDR, count=200000)
        self.assertEqual(mu.reg_read(UC_ARM64_REG_PC), STOP_ADDR)
        ret_u64 = mu.reg_read(UC_ARM64_REG_X0)
        ret_i64 = ret_u64 if ret_u64 < (1 << 63) else ret_u64 - (1 << 64)

        # kind=-12, ver=250, flags=-8, port=41000, delta=-300, pad_u16=50000, seq=2147483653
        expected = -12 + 250 + (-8) + 41000 + (-300) + 50000 + 0x80000005
        self.assertEqual(ret_i64, expected)

        out_pkt = CPacketFrame.from_buffer_copy(bytes(mu.mem_read(MEM_ADDR, 32)))
        self.assertEqual(out_pkt.hdr.flags, -8)
        self.assertEqual(out_pkt.hdr.port, 41000)
        self.assertEqual(out_pkt.delta, -300)
        self.assertEqual(out_pkt.hdr.seq, 0x80000005)

    def test_polyglot_nested_structs_rust_go_ts_and_omnirepo_fusion(self):
        # Intentionally define Frame referencing Header across separate language repos!
        rs_src = """
        pub struct Header {
            pub ver: u8,
            pub flags: i8,
            pub port: u16,
            pub seq: u32,
        }
        pub fn rs_bump_hdr(f: &mut Frame, delta_flags: i64) -> i64 {
            f.hdr.flags += delta_flags;
            f.hdr.seq += 1;
            return f.hdr.flags + f.hdr.ver;
        }
        """
        go_src = """
        package proto
        type Frame struct {
            kind int8
            hdr Header
            delta int16
            pad_u16 uint16
            scale float32
            energy float64
        }
        func go_accumulate_frame(f *Frame, inc int64) float64 {
            f.delta += inc
            f.energy = f.energy + f.scale * f.delta + f.hdr.port
            return f.energy
        }
        """
        ts_src = """
        export function ts_step_frame(f: Frame, delta_flags: i64, inc: i64): f64 {
            rs_bump_hdr(f, delta_flags);
            return go_accumulate_frame(f, inc);
        }
        """

        with tempfile.TemporaryDirectory() as tmp:
            rs_dir = os.path.join(tmp, "repo_a_rs")
            go_dir = os.path.join(tmp, "repo_b_go")
            ts_dir = os.path.join(tmp, "repo_c_ts")
            for d in (rs_dir, go_dir, ts_dir):
                os.makedirs(d, exist_ok=True)
            with open(os.path.join(rs_dir, "hdr.rs"), "w", encoding="utf-8") as f:
                f.write(rs_src)
            with open(os.path.join(go_dir, "frame.go"), "w", encoding="utf-8") as f:
                f.write(go_src)
            with open(os.path.join(ts_dir, "pipe.ts"), "w", encoding="utf-8") as f:
                f.write(ts_src)

            res_nat = OmniRepoCompiler().compile_repositories(
                [rs_dir, go_dir, ts_dir], os.path.join(tmp, "nested_nat.bin"), entry_export="ts_step_frame", backend="native"
            )
            self.assertTrue(res_nat["success"], f"Native nested OmniRepo failed: {res_nat}")

            res_ll = OmniRepoCompiler().compile_repositories(
                [rs_dir, go_dir, ts_dir], os.path.join(tmp, "nested_ll.bin"), entry_export="ts_step_frame", backend="llvm"
            )
            self.assertTrue(res_ll["success"], f"LLVM nested OmniRepo failed: {res_ll}")
            self.assertEqual(res_ll["stages"]["backend_validation"]["refuted"], 0)

            out_wasm = os.path.join(tmp, "nested_frame.wasm")
            res_wa = OmniRepoCompiler().compile_repositories(
                [rs_dir, go_dir, ts_dir], out_wasm, entry_export="ts_step_frame", backend="wasm"
            )
            self.assertTrue(res_wa["success"], f"WASM nested OmniRepo failed: {res_wa}")

            from wasmtime import Engine, Instance, Module, Store
            engine = Engine()
            store = Store(engine)
            with open(out_wasm, "rb") as wf:
                mod = Module(engine, wf.read())
            inst = Instance(store, mod, [])
            ex = inst.exports(store)
            mem = ex["memory"]
            fn = ex["ts_step_frame"]
            off = 1024

            pkt_in = CPacketFrame(
                kind=-5,
                hdr=CHeader(ver=200, flags=-10, port=300, seq=10),
                delta=-10,
                pad_u16=7,
                scale=2.0,
                energy=100.0,
            )
            mem.write(store, bytes(pkt_in), off)
            # rs_bump_hdr: flags=-10 + 3 = -7, seq = 11
            # go_accumulate_frame(f, 15): delta = -10 + 15 = 5; energy = 100.0 + 2.0*5 + 300 = 410.0
            got_ret = fn(store, off, 3, 15)
            self.assertEqual(_f64_to_u64(got_ret), _f64_to_u64(410.0))

            pkt_out = CPacketFrame.from_buffer_copy(bytes(mem.read(store, off, off + 32)))
            self.assertEqual(pkt_out.kind, -5)
            self.assertEqual(pkt_out.hdr.ver, 200)
            self.assertEqual(pkt_out.hdr.flags, -7)
            self.assertEqual(pkt_out.hdr.port, 300)
            self.assertEqual(pkt_out.hdr.seq, 11)
            self.assertEqual(pkt_out.delta, 5)
            self.assertEqual(pkt_out.pad_u16, 7)
            self.assertAlmostEqual(pkt_out.energy, 410.0)

    def test_jit_heap_nested_struct_vs_ctypes_and_host_c_memcmp(self):
        libc = omni_ffi_load_lib("libc")
        self.assertGreater(libc, 0)
        memcmp_ptr = omni_ffi_get_symbol(libc, "memcmp")
        self.assertGreater(memcmp_ptr, 0)

        src = """
def build_and_compare_frame(
    ref_ptr: int,
    ver: int,
    flags: int,
    port: int,
    seq: int,
    delta: int,
    scale: float,
    energy: float,
    fn_memcmp: int
) -> int:
    buf = omni_alloc(32)
    store_i8(buf, 0, -7)
    store_u8(buf, 4, ver)
    store_i8(buf, 5, flags)
    store_u16(buf, 6, port)
    store_u32(buf, 8, seq)
    store_i16(buf, 12, delta)
    store_u16(buf, 14, 512)
    store_f32(buf, 16, scale)
    store_f64(buf, 24, energy)
    cmp_res = omni_ffi_call3(fn_memcmp, buf, ref_ptr, 32)
    return cmp_res
"""
        jit = NativeJitCompiler()
        cfunc, mem, _ = jit.compile_function(src, fn_name="build_and_compare_frame")
        self.assertTrue(mem.is_executable)

        ref_struct = CPacketFrame(
            kind=-7,
            hdr=CHeader(ver=254, flags=-9, port=443, seq=0xDEADBEEF),
            delta=-1234,
            pad_u16=512,
            scale=3.25,
            energy=1234.5,
        )
        # Ensure padding bytes (1..3 and 20..23) inside ref_struct are zeroed just like NativeHeapArena.alloc()
        ref_buf = (ctypes.c_uint8 * 32).from_buffer_copy(bytes(ref_struct))
        ref_buf[1] = 0
        ref_buf[2] = 0
        ref_buf[3] = 0
        for pad_i in range(20, 24):
            ref_buf[pad_i] = 0
        ref_addr = ctypes.addressof(ref_buf)

        # Note: Windows msvcrt memcmp returns 32-bit int in eax; exact equality is 0 in lower 32 bits
        res_eq = cfunc(ref_addr, 254, -9, 443, 0xDEADBEEF, -1234, 3.25, 1234.5, memcmp_ptr)
        self.assertEqual(res_eq & 0xFFFFFFFF, 0)

        # Mutate a single signed byte field (`flags` = -8 instead of -9) -> memcmp must be non-zero
        res_ne = cfunc(ref_addr, 254, -8, 443, 0xDEADBEEF, -1234, 3.25, 1234.5, memcmp_ptr)
        self.assertNotEqual(res_ne & 0xFFFFFFFF, 0)


if __name__ == "__main__":
    unittest.main()
