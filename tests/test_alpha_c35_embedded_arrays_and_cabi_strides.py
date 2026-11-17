import ctypes
import os
import struct
import tempfile
import unittest

from compiler.llvm_backend import LLVMBackend
from compiler.native_codegen import Arm64CodeGenerator
from compiler.native_jit import NativeJitCompiler
from compiler.ssa_ir import lower_source_to_ssa
from compiler.wasm_backend import WasmBackend
from omni_repo_compiler import OmniRepoCompiler
from runtime.native_ffi import omni_ffi_get_symbol, omni_ffi_load_lib
from validation.backend_translation_validator import BackendTranslationValidator


class CHeader(ctypes.Structure):
    _fields_ = [
        ("ver", ctypes.c_uint8),
        ("flags", ctypes.c_int8),
        ("port", ctypes.c_uint16),
        ("seq", ctypes.c_uint32),
    ]


class CTelemetryBatch(ctypes.Structure):
    _fields_ = [
        ("tag", ctypes.c_int8),
        ("tags", ctypes.c_uint8 * 4),
        ("headers", CHeader * 2),
        ("weights", ctypes.c_float * 4),
        ("total", ctypes.c_double),
    ]


def _f64_to_u64(v: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", float(v)))[0]


class TestAlphaC35EmbeddedArraysAndCABIStrides(unittest.TestCase):
    def test_embedded_fixed_arrays_and_array_of_structs_tv_and_differential(self):
        self.assertEqual(ctypes.sizeof(CHeader), 8)
        self.assertEqual(ctypes.sizeof(CTelemetryBatch), 48)
        self.assertEqual(CTelemetryBatch.tags.offset, 1)
        self.assertEqual(CTelemetryBatch.headers.offset, 8)
        self.assertEqual(CTelemetryBatch.weights.offset, 24)
        self.assertEqual(CTelemetryBatch.total.offset, 40)

        src = """
class Header:
    ver: u8
    flags: i8
    port: u16
    seq: u32

class TelemetryBatch:
    tag: i8
    tags: Array[u8, 4]
    headers: Array[Header, 2]
    weights: Array[f32, 4]
    total: f64

def reduce_and_update_batch(pkt: TelemetryBatch, bias: float) -> float:
    acc = 0.0
    i = 0
    while i < 4:
        pkt.weights[i] += bias
        acc += float(pkt.tags[i]) * pkt.weights[i]
        i += 1
    j = 0
    while j < 2:
        pkt.headers[j].port += 100
        acc += float(pkt.headers[j].port) + float(pkt.headers[j].flags)
        j += 1
    pkt.total = acc + float(pkt.tag)
    return pkt.total
"""
        ssa_fn = lower_source_to_ssa(src, fn_name="reduce_and_update_batch", optimize=True)
        self.assertEqual(ssa_fn.param_types, {"pkt": "ptr", "bias": "f64"})
        self.assertEqual(ssa_fn.return_type, "f64")

        btv = BackendTranslationValidator(enable_float_theory=True)
        llvm_ir = LLVMBackend().ssa_to_llvm_ir(ssa_fn)
        wat_src = WasmBackend().ssa_to_wat(ssa_fn)
        res_ll_tv = btv.verify_ssa_to_llvm_ir(ssa_fn, llvm_ir)
        self.assertTrue(res_ll_tv["proven"], f"LLVM TV failed on embedded fixed arrays: {res_ll_tv}")
        res_wa_tv = btv.verify_ssa_to_wat(ssa_fn, wat_src)
        self.assertTrue(res_wa_tv["proven"], f"WAT TV failed on embedded fixed arrays: {res_wa_tv}")

        batch_in = CTelemetryBatch(
            tag=-3,
            tags=(ctypes.c_uint8 * 4)(10, 20, 30, 40),
            headers=(CHeader * 2)(
                CHeader(ver=1, flags=-2, port=1000, seq=7),
                CHeader(ver=2, flags=-4, port=2000, seq=9),
            ),
            weights=(ctypes.c_float * 4)(0.5, 1.5, 2.5, 3.5),
            total=0.0,
        )
        raw_in = bytes(batch_in)
        diff = btv.verify_differential_execution(ssa_fn, [(bytearray(raw_in), 0.5)])
        self.assertTrue(diff["equivalent"], f"Differential parity failed on embedded arrays: {diff}")

        # Expected weights: [1.0, 2.0, 3.0, 4.0]
        # tags dot weights: 10*1 + 20*2 + 30*3 + 40*4 = 10 + 40 + 90 + 160 = 300.0
        # headers: (1100 + -2) + (2100 + -4) = 1098 + 2096 = 3194.0
        # total: 300 + 3194 - 3 = 3491.0
        self.assertEqual(_f64_to_u64(diff["outputs_by_backend"]["native"][0]), _f64_to_u64(3491.0))

        out_struct = CTelemetryBatch.from_buffer_copy(diff["memory_by_backend"]["native"][0]["pkt"])
        self.assertEqual([out_struct.weights[k] for k in range(4)], [1.0, 2.0, 3.0, 4.0])
        self.assertEqual([out_struct.headers[k].port for k in range(2)], [1100, 2100])
        self.assertEqual(out_struct.total, 3491.0)

    def test_arm64_embedded_array_of_structs_unicorn_execution(self):
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

class TelemetryBatch:
    tag: i8
    tags: Array[u8, 4]
    headers: Array[Header, 2]
    weights: Array[f32, 4]
    total: f64

def arm64_array_struct_kernel(pkt: TelemetryBatch, delta_p: int) -> int:
    s = 0
    k = 0
    while k < 2:
        pkt.headers[k].port += delta_p
        s += pkt.headers[k].port + pkt.headers[k].flags
        k += 1
    m = 0
    while m < 4:
        pkt.tags[m] += 1
        s += pkt.tags[m]
        m += 1
    return s + pkt.tag
"""
        ssa_fn = lower_source_to_ssa(src, fn_name="arm64_array_struct_kernel", optimize=True)
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
        batch_in = CTelemetryBatch(
            tag=-5,
            tags=(ctypes.c_uint8 * 4)(1, 2, 3, 250),
            headers=(CHeader * 2)(
                CHeader(ver=1, flags=-3, port=500, seq=11),
                CHeader(ver=2, flags=-7, port=800, seq=22),
            ),
            weights=(ctypes.c_float * 4)(1.0, 2.0, 3.0, 4.0),
            total=0.0,
        )
        mu.mem_write(MEM_ADDR, bytes(batch_in))
        mu.reg_write(UC_ARM64_REG_SP, STACK_ADDR + 0x8000)
        mu.reg_write(UC_ARM64_REG_LR, STOP_ADDR)
        mu.reg_write(UC_ARM64_REG_X0, MEM_ADDR)
        mu.reg_write(UC_ARM64_REG_X1, 50)

        mu.emu_start(CODE_ADDR, STOP_ADDR, count=200000)
        self.assertEqual(mu.reg_read(UC_ARM64_REG_PC), STOP_ADDR)
        ret_u64 = mu.reg_read(UC_ARM64_REG_X0)
        ret_i64 = ret_u64 if ret_u64 < (1 << 63) else ret_u64 - (1 << 64)

        # headers: (550 - 3) + (850 - 7) = 547 + 843 = 1390
        # tags incremented: 2 + 3 + 4 + 251 = 260
        # tag: -5 -> total = 1390 + 260 - 5 = 1645
        self.assertEqual(ret_i64, 1645)

        out_b = CTelemetryBatch.from_buffer_copy(bytes(mu.mem_read(MEM_ADDR, 48)))
        self.assertEqual([out_b.tags[k] for k in range(4)], [2, 3, 4, 251])
        self.assertEqual([out_b.headers[k].port for k in range(2)], [550, 850])

    def test_polyglot_embedded_arrays_rust_go_ts_omnirepo_fusion(self):
        rs_src = """
        pub struct Header {
            pub ver: u8,
            pub flags: i8,
            pub port: u16,
            pub seq: u32,
        }
        pub fn rs_scale_weights(pkt: &mut TelemetryBatch, bias: f64) -> f64 {
            let mut acc = 0.0;
            let mut i = 0;
            while i < 4 {
                pkt.weights[i] += bias;
                acc += pkt.weights[i];
                i += 1;
            }
            return acc;
        }
        """
        go_src = """
        package tele
        type TelemetryBatch struct {
            tag int8
            tags [4]uint8
            headers [2]Header
            weights [4]float32
            total float64
        }
        func go_shift_headers(pkt *TelemetryBatch, dport int64) float64 {
            j := 0
            acc := 0.0
            for j < 2 {
                pkt.headers[j].port += dport
                acc = acc + pkt.headers[j].port
                j++
            }
            return acc
        }
        """
        ts_src = """
        export function ts_step_batch(pkt: TelemetryBatch, bias: f64, dport: i64): f64 {
            let wsum = rs_scale_weights(pkt, bias);
            let hsum = go_shift_headers(pkt, dport);
            pkt.total = wsum + hsum + pkt.tag;
            return pkt.total;
        }
        """

        with tempfile.TemporaryDirectory() as tmp:
            rs_dir = os.path.join(tmp, "repo_rs")
            go_dir = os.path.join(tmp, "repo_go")
            ts_dir = os.path.join(tmp, "repo_ts")
            for d in (rs_dir, go_dir, ts_dir):
                os.makedirs(d, exist_ok=True)
            with open(os.path.join(rs_dir, "hdr.rs"), "w", encoding="utf-8") as f:
                f.write(rs_src)
            with open(os.path.join(go_dir, "batch.go"), "w", encoding="utf-8") as f:
                f.write(go_src)
            with open(os.path.join(ts_dir, "pipe.ts"), "w", encoding="utf-8") as f:
                f.write(ts_src)

            res_nat = OmniRepoCompiler().compile_repositories(
                [rs_dir, go_dir, ts_dir], os.path.join(tmp, "arr_nat.bin"), entry_export="ts_step_batch", backend="native"
            )
            self.assertTrue(res_nat["success"], f"Native embedded array OmniRepo failed: {res_nat}")

            res_ll = OmniRepoCompiler().compile_repositories(
                [rs_dir, go_dir, ts_dir], os.path.join(tmp, "arr_ll.bin"), entry_export="ts_step_batch", backend="llvm"
            )
            self.assertTrue(res_ll["success"], f"LLVM embedded array OmniRepo failed: {res_ll}")
            self.assertEqual(res_ll["stages"]["backend_validation"]["refuted"], 0)

            out_wasm = os.path.join(tmp, "arr_batch.wasm")
            res_wa = OmniRepoCompiler().compile_repositories(
                [rs_dir, go_dir, ts_dir], out_wasm, entry_export="ts_step_batch", backend="wasm"
            )
            self.assertTrue(res_wa["success"], f"WASM embedded array OmniRepo failed: {res_wa}")

            from wasmtime import Engine, Instance, Module, Store
            engine = Engine()
            store = Store(engine)
            with open(out_wasm, "rb") as wf:
                mod = Module(engine, wf.read())
            inst = Instance(store, mod, [])
            ex = inst.exports(store)
            mem = ex["memory"]
            fn = ex["ts_step_batch"]
            off = 1024

            pkt_in = CTelemetryBatch(
                tag=-5,
                tags=(ctypes.c_uint8 * 4)(1, 2, 3, 4),
                headers=(CHeader * 2)(
                    CHeader(ver=1, flags=0, port=100, seq=1),
                    CHeader(ver=2, flags=0, port=200, seq=2),
                ),
                weights=(ctypes.c_float * 4)(1.0, 2.0, 3.0, 4.0),
                total=0.0,
            )
            mem.write(store, bytes(pkt_in), off)
            # weights + 0.5 -> [1.5, 2.5, 3.5, 4.5] -> sum = 12.0
            # headers.port + 50 -> [150, 250] -> sum = 400.0
            # total = 12.0 + 400.0 - 5 = 407.0
            got_ret = fn(store, off, 0.5, 50)
            self.assertEqual(_f64_to_u64(got_ret), _f64_to_u64(407.0))

            pkt_out = CTelemetryBatch.from_buffer_copy(bytes(mem.read(store, off, off + 48)))
            self.assertEqual([pkt_out.weights[k] for k in range(4)], [1.5, 2.5, 3.5, 4.5])
            self.assertEqual([pkt_out.headers[k].port for k in range(2)], [150, 250])
            self.assertEqual(pkt_out.total, 407.0)

    def test_jit_heap_embedded_array_struct_vs_ctypes_memcmp(self):
        libc = omni_ffi_load_lib("libc")
        self.assertGreater(libc, 0)
        memcmp_ptr = omni_ffi_get_symbol(libc, "memcmp")
        self.assertGreater(memcmp_ptr, 0)

        # CTelemetryBatch offsets: tag@0, tags[0..3]@1..4, headers[0]@8, headers[1]@16, weights[0..3]@24..36, total@40
        src = """
def build_batch_on_heap(ref_ptr: int, base_port: int, scale: float, fn_memcmp: int) -> int:
    buf = omni_alloc(48)
    store_i8(buf, 0, -4)
    k = 0
    while k < 4:
        store_u8(buf, 1 + k, 10 + k)
        store_f32(buf, 24 + k * 4, scale + float(k))
        k += 1
    h = 0
    while h < 2:
        hb = 8 + h * 8
        store_u8(buf, hb + 0, 1 + h)
        store_i8(buf, hb + 1, -1 - h)
        store_u16(buf, hb + 2, base_port + h * 10)
        store_u32(buf, hb + 4, 1000 + h)
        h += 1
    store_f64(buf, 40, 99.5)
    return omni_ffi_call3(fn_memcmp, buf, ref_ptr, 48)
"""
        jit = NativeJitCompiler()
        cfunc, mem, _ = jit.compile_function(src, fn_name="build_batch_on_heap")
        self.assertTrue(mem.is_executable)

        ref_batch = CTelemetryBatch(
            tag=-4,
            tags=(ctypes.c_uint8 * 4)(10, 11, 12, 13),
            headers=(CHeader * 2)(
                CHeader(ver=1, flags=-1, port=8000, seq=1000),
                CHeader(ver=2, flags=-2, port=8010, seq=1001),
            ),
            weights=(ctypes.c_float * 4)(1.5, 2.5, 3.5, 4.5),
            total=99.5,
        )
        # Zero alignment padding bytes 5, 6, 7 so buffer matches zero-initialized omni_alloc(48)
        ref_raw = (ctypes.c_uint8 * 48).from_buffer_copy(bytes(ref_batch))
        ref_raw[5] = 0
        ref_raw[6] = 0
        ref_raw[7] = 0
        ref_addr = ctypes.addressof(ref_raw)

        self.assertEqual(cfunc(ref_addr, 8000, 1.5, memcmp_ptr) & 0xFFFFFFFF, 0)
        self.assertNotEqual(cfunc(ref_addr, 8001, 1.5, memcmp_ptr) & 0xFFFFFFFF, 0)


if __name__ == "__main__":
    unittest.main()
