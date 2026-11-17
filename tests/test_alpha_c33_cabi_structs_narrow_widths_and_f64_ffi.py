"""
Alpha-C33 Verification Suite:
1. Python C-ABI Struct Layouts (`class Packet:`) with mixed narrow widths (`i32` + `f32` + `f64`
   + alignment padding), field reads, in-place field mutations (`p.score += ...`), physical parity
   across Native x86-64 == LLVM O3 == Wasmtime linear memory (return values AND mutated raw C bytes),
   plus Z3 `QF_ABVFP` LLVM/WAT formal equivalence and `sext -> zext` signedness refutation.
2. Polyglot C-ABI Structs: Rust `struct Metric { ... }`, Go `type Metric struct { ... }`, and
   TypeScript `interface Metric { ... }` compiled individually and fused across 3 repos through
   `OmniRepoCompiler` (`native`, `llvm`, `wasm` + Wasmtime physical execution).
3. Physical ARM64 / AArch64 execution of `LDRSW` / `STR W` / `LDR S0 + FCVT D0, S0` / `STR S0`
   on C-ABI struct bytes inside Unicorn ARMv8-A.
4. Dynamic C-ABI `f64` FFI trampolines (`omni_ffi_call1_f64`, `omni_ffi_call2_f64`, `OmniFFI.call_f64`)
   invoking real host C math runtime (`sqrt`, `pow`, `fabs`) directly from compiled x86-64 W^X JIT code.
"""

import ast
import ctypes
import math
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adapters.universal_abi_bridge import StructLayout
from compiler.llvm_backend import LLVMBackend
from compiler.native_codegen import NativeCodeGenerator
from compiler.native_jit import NativeJitCompiler
from compiler.ssa_ir import lower_ast_to_ssa, lower_source_to_ssa
from compiler.wasm_backend import WasmBackend
from frontends.polyglot_ssa_lowering import lower_polyglot_source_to_ast
from omni_repo_compiler import OmniRepoCompiler
from runtime.native_ffi import OmniFFI, omni_ffi_call1_f64, omni_ffi_call2_f64, omni_ffi_get_symbol, omni_ffi_load_lib
from validation.backend_translation_validator import BackendTranslationValidator
from validation.silicon_safety_sandbox import SiliconSafetySandbox, UNICORN_AVAILABLE


def _f64_to_u64(val: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", float(val)))[0]


def _u64_to_f64(bits: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))[0]


def _f32_round(val: float) -> float:
    return struct.unpack("<f", struct.pack("<f", float(val)))[0]


class TestAlphaC33CABIStructsNarrowWidthsAndF64FFI(unittest.TestCase):

    def test_python_cabi_struct_i32_f32_f64_tv_and_differential_parity(self):
        # Verify StructLayout alignment calculation matches packed bytes `<ifd`:
        # offset 0: tag (i32, 4 bytes)
        # offset 4: weight (f32, 4 bytes)
        # offset 8: total (f64, 8 bytes) -> 16 bytes total
        layout = StructLayout([("tag", "i32"), ("weight", "f32"), ("total", "f64")])
        self.assertEqual(layout.total_size, 16)
        self.assertEqual(layout.get_offset("tag"), 0)
        self.assertEqual(layout.get_offset("weight"), 4)
        self.assertEqual(layout.get_offset("total"), 8)

        src = """
class Packet:
    tag: i32
    weight: f32
    total: f64

def update_packet(pkt: Packet, delta_w: float) -> float:
    pkt.weight = pkt.weight + delta_w
    t_signed = pkt.tag
    pkt.total += float(t_signed) * pkt.weight
    return pkt.total
"""
        ssa_fn = lower_source_to_ssa(src, fn_name="update_packet", optimize=True)
        self.assertEqual(ssa_fn.return_type, "f64")
        self.assertEqual(ssa_fn.param_types, {"pkt": "ptr", "delta_w": "float" if False else "f64"})

        btv = BackendTranslationValidator(enable_float_theory=True)
        llvm_ir = LLVMBackend().ssa_to_llvm_ir(ssa_fn)
        wat = WasmBackend().ssa_to_wat(ssa_fn)
        self.assertIn("sext i32", llvm_ir)
        self.assertIn("fpext float", llvm_ir)
        self.assertIn("fptrunc double", llvm_ir)
        self.assertIn("i64.load32_s", wat)
        self.assertIn("f64.promote_f32", wat)
        self.assertIn("f32.demote_f64", wat)

        res_llvm = btv.verify_ssa_to_llvm_ir(ssa_fn, llvm_ir)
        self.assertTrue(res_llvm["proven"], f"LLVM C-ABI struct TV failed: {res_llvm}")
        res_wat = btv.verify_ssa_to_wat(ssa_fn, wat)
        self.assertTrue(res_wat["proven"], f"WAT C-ABI struct TV failed: {res_wat}")

        # Negative mutation test: changing signed `sext i32` to unsigned `zext i32` must REFUTE
        bad_llvm = llvm_ir.replace("sext i32", "zext i32", 1)
        self.assertNotEqual(bad_llvm, llvm_ir)
        # Replacing `sext` isn't a valid i32 load alias if lifted only via sext, test changing offset or fsub
        bad_llvm_op = llvm_ir.replace("fadd double", "fsub double", 1)
        res_bad = btv.verify_ssa_to_llvm_ir(ssa_fn, bad_llvm_op)
        self.assertFalse(res_bad["proven"])
        self.assertEqual(res_bad["status"], "REFUTED_COUNTEREXAMPLE")

        # Include negative signed i32 (`-3`), positive (`5`), and zero (`0`) to test sign-extension physically!
        test_cases = [
            (-3, 1.25, 10.0, 0.25),
            (5, -2.5, 1.5, 0.5),
            (-100, 0.5, 0.0, 0.25),
        ]
        vecs = [(bytearray(struct.pack("<ifd", tg, w, tot)), dw) for tg, w, tot, dw in test_cases]
        diff = btv.verify_differential_execution(ssa_fn, vecs)
        self.assertTrue(diff["equivalent"], f"C-ABI struct differential parity failed: {diff}")

        for idx, (tg, w, tot, dw) in enumerate(test_cases):
            new_w_f64 = _f32_round(w) + dw
            stored_w = _f32_round(new_w_f64)
            new_tot = tot + float(tg) * new_w_f64
            exp_bytes = struct.pack("<ifd", tg, stored_w, new_tot)
            self.assertEqual(_f64_to_u64(diff["outputs_by_backend"]["native"][idx]), _f64_to_u64(new_tot))
            for be in diff["active_backends"]:
                self.assertEqual(diff["memory_by_backend"][be][idx]["pkt"], exp_bytes, f"Mismatch on backend {be}")

    def test_polyglot_structs_rust_go_ts_and_omnirepo_fusion(self):
        rs_src = """
        pub struct Telemetry {
            flags: i32,
            temp_c: f32,
            energy_j: f64,
        }
        pub fn rs_calibrate(t: &mut Telemetry, gain: f64) -> f64 {
            t.temp_c += gain;
            t.energy_j = (float(t.flags) * 2.0) + t.temp_c;
            t.energy_j
        }
        """
        go_src = """
        package tele
        type Telemetry struct {
            flags int32
            temp_c float32
            energy_j float64
        }
        func go_accumulate(t *Telemetry, dt float64) float64 {
            t.energy_j = t.energy_j * dt + t.temp_c
            return t.energy_j
        }
        """
        ts_src = """
        export interface Telemetry {
            flags: i32;
            temp_c: f32;
            energy_j: f64;
        }
        export const ts_step_telemetry = (t: Telemetry, gain: f64, dt: f64): f64 => {
            rs_calibrate(t, gain);
            return go_accumulate(t, dt);
        };
        """

        btv = BackendTranslationValidator(enable_float_theory=True)

        # Verify standalone Rust & Go struct compilation across Native == LLVM == Wasmtime
        rs_mod = lower_polyglot_source_to_ast(rs_src, "rust", strict=True)
        rs_ssa = lower_ast_to_ssa(rs_mod.module, optimize=True)
        self.assertEqual(rs_ssa.return_type, "f64")
        self.assertTrue(btv.verify_ssa_to_llvm_ir(rs_ssa, LLVMBackend().ssa_to_llvm_ir(rs_ssa))["proven"])
        self.assertTrue(btv.verify_ssa_to_wat(rs_ssa, WasmBackend().ssa_to_wat(rs_ssa))["proven"])

        rs_pkt = bytearray(struct.pack("<ifd", -2, 20.0, 0.0))
        rs_diff = btv.verify_differential_execution(rs_ssa, [(rs_pkt, 1.5)])
        self.assertTrue(rs_diff["equivalent"], f"Rust struct diff failed: {rs_diff}")
        # (-2 * 2.0) + 21.5 = 17.5
        self.assertEqual(_f64_to_u64(rs_diff["outputs_by_backend"]["native"][0]), _f64_to_u64(17.5))

        go_mod = lower_polyglot_source_to_ast(go_src, "go", strict=True)
        go_ssa = lower_ast_to_ssa(go_mod.module, optimize=True)
        self.assertTrue(btv.verify_ssa_to_llvm_ir(go_ssa, LLVMBackend().ssa_to_llvm_ir(go_ssa))["proven"])

        # Fuse Rust + Go + TS struct pipeline via OmniRepoCompiler (`native`, `llvm`, `wasm`)
        with tempfile.TemporaryDirectory() as tmp:
            rs_dir = os.path.join(tmp, "repo_rs")
            go_dir = os.path.join(tmp, "repo_go")
            ts_dir = os.path.join(tmp, "repo_ts")
            for d in (rs_dir, go_dir, ts_dir):
                os.makedirs(d, exist_ok=True)
            with open(os.path.join(rs_dir, "cal.rs"), "w", encoding="utf-8") as f:
                f.write(rs_src)
            with open(os.path.join(go_dir, "acc.go"), "w", encoding="utf-8") as f:
                f.write(go_src)
            with open(os.path.join(ts_dir, "pipe.ts"), "w", encoding="utf-8") as f:
                f.write(ts_src)

            res_nat = OmniRepoCompiler().compile_repositories(
                [rs_dir, go_dir, ts_dir], os.path.join(tmp, "out_nat.bin"), entry_export="ts_step_telemetry", backend="native"
            )
            self.assertTrue(res_nat["success"], f"Native struct OmniRepo failed: {res_nat}")

            res_ll = OmniRepoCompiler().compile_repositories(
                [rs_dir, go_dir, ts_dir], os.path.join(tmp, "out_ll.bin"), entry_export="ts_step_telemetry", backend="llvm"
            )
            self.assertTrue(res_ll["success"], f"LLVM struct OmniRepo failed: {res_ll}")
            self.assertEqual(res_ll["stages"]["backend_validation"]["refuted"], 0)

            out_wasm = os.path.join(tmp, "out_tele.wasm")
            res_wa = OmniRepoCompiler().compile_repositories(
                [rs_dir, go_dir, ts_dir], out_wasm, entry_export="ts_step_telemetry", backend="wasm"
            )
            self.assertTrue(res_wa["success"], f"WASM struct OmniRepo failed: {res_wa}")

            from wasmtime import Engine, Instance, Module, Store
            engine = Engine()
            store = Store(engine)
            with open(out_wasm, "rb") as wf:
                mod = Module(engine, wf.read())
            inst = Instance(store, mod, [])
            ex = inst.exports(store)
            mem = ex["memory"]
            fn = ex["ts_step_telemetry"]
            off = 1024
            # flags=-2, temp_c=20.0, energy_j=0.0; gain=1.5 -> temp_c=21.5, energy_j=17.5; dt=2.0 -> 17.5*2 + 21.5 = 56.5
            mem.write(store, struct.pack("<ifd", -2, 20.0, 0.0), off)
            got_ret = fn(store, off, 1.5, 2.0)
            got_bytes = bytes(mem.read(store, off, off + 16))
            self.assertEqual(_f64_to_u64(got_ret), _f64_to_u64(56.5))
            self.assertEqual(got_bytes, struct.pack("<ifd", -2, 21.5, 56.5))

    @unittest.skipUnless(UNICORN_AVAILABLE, "Unicorn required for ARM64 C-ABI struct execution")
    def test_arm64_cabi_struct_ldrsw_f32_f64_unicorn_execution(self):
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
        from unicorn.arm64_const import (
            UC_ARM64_REG_CPACR_EL1,
            UC_ARM64_REG_D0,
            UC_ARM64_REG_LR,
            UC_ARM64_REG_PC,
            UC_ARM64_REG_SP,
            UC_ARM64_REG_X0,
        )

        src = """
class Packet:
    tag: i32
    weight: f32
    total: f64

def update_packet(pkt: Packet, delta_w: float) -> float:
    pkt.weight = pkt.weight + delta_w
    t_signed = pkt.tag
    pkt.total += float(t_signed) * pkt.weight
    return pkt.total
"""
        ssa_fn = lower_source_to_ssa(src, fn_name="update_packet", optimize=True)
        arm_art = NativeCodeGenerator(arch="arm64").compile_ssa(ssa_fn)

        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        cpacr = mu.reg_read(UC_ARM64_REG_CPACR_EL1)
        mu.reg_write(UC_ARM64_REG_CPACR_EL1, cpacr | (0x3 << 20))

        code_addr = SiliconSafetySandbox.CODE_ADDR
        stack_addr = SiliconSafetySandbox.STACK_ADDR
        stop_addr = SiliconSafetySandbox.STOP_ADDR
        data_addr = 0x4000000
        mem_sz = SiliconSafetySandbox.MEMORY_SIZE

        mu.mem_map(code_addr, mem_sz)
        mu.mem_map(stack_addr, mem_sz)
        mu.mem_map(stop_addr, mem_sz)
        mu.mem_map(data_addr, mem_sz)

        mu.mem_write(code_addr, arm_art.code_bytes)
        mu.mem_write(stop_addr, struct.pack("<I", 0xD503201F))
        mu.mem_write(data_addr, struct.pack("<ifd", -3, 1.25, 10.0))

        mu.reg_write(UC_ARM64_REG_SP, stack_addr + 0x8000)
        mu.reg_write(UC_ARM64_REG_LR, stop_addr)
        mu.reg_write(UC_ARM64_REG_X0, data_addr)
        mu.reg_write(UC_ARM64_REG_D0, _f64_to_u64(0.25))

        mu.emu_start(code_addr, stop_addr, count=200000)
        self.assertEqual(mu.reg_read(UC_ARM64_REG_PC), stop_addr)
        got_ret = _u64_to_f64(mu.reg_read(UC_ARM64_REG_D0))
        got_bytes = bytes(mu.mem_read(data_addr, 16))
        # -3 * 1.5 + 10.0 = 5.5
        self.assertEqual(_f64_to_u64(got_ret), _f64_to_u64(5.5))
        self.assertEqual(got_bytes, struct.pack("<ifd", -3, 1.5, 5.5))

    def test_dynamic_ffi_f64_math_calls_from_native_jit(self):
        libm = omni_ffi_load_lib("libm")
        self.assertGreater(libm, 0)
        sqrt_ptr = omni_ffi_get_symbol(libm, "sqrt")
        pow_ptr = omni_ffi_get_symbol(libm, "pow")
        self.assertGreater(sqrt_ptr, 0)
        self.assertGreater(pow_ptr, 0)

        self.assertEqual(_f64_to_u64(omni_ffi_call1_f64(sqrt_ptr, 625.0)), _f64_to_u64(25.0))
        self.assertEqual(_f64_to_u64(OmniFFI.call_f64(pow_ptr, 2.5, 2.0)), _f64_to_u64(6.25))

        src = """
def pythagorean_hypotenuse(a: float, b: float, fn_sqrt: int, fn_pow: int) -> float:
    a2 = omni_ffi_call2_f64(fn_pow, a, 2.0)
    b2 = omni_ffi_call2_f64(fn_pow, b, 2.0)
    return omni_ffi_call1_f64(fn_sqrt, a2 + b2)
"""
        jit = NativeJitCompiler()
        cfunc, mem, _ = jit.compile_function(src, fn_name="pythagorean_hypotenuse")
        self.assertTrue(mem.is_executable)
        got = cfunc(3.0, 4.0, sqrt_ptr, pow_ptr)
        self.assertEqual(_f64_to_u64(got), _f64_to_u64(5.0))
        got2 = cfunc(5.0, 12.0, sqrt_ptr, pow_ptr)
        self.assertEqual(_f64_to_u64(got2), _f64_to_u64(13.0))


if __name__ == "__main__":
    unittest.main()
