import struct
import os
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


def _f64_to_u64(v: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", float(v)))[0]


def _u64_to_f64(bits: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))[0]


class TestAlphaC36MatchSwitchAndRodataLuts(unittest.TestCase):
    def test_python_match_pattern_and_rodata_lut_tv_differential(self):
        src = """
LUT_SCALES = [0.25, 0.5, 1.25, 2.5]
LUT_BIAS: Array[i32, 4] = [-10, 5, 15, 30]

def dispatch_with_luts(mode: int, idx: int, base: float) -> float:
    scale = LUT_SCALES[idx]
    bias = LUT_BIAS[idx]
    bonus = 0.0
    match mode:
        case 0:
            bonus = base * scale + float(bias)
        case 1 | 2:
            bonus = (base + float(bias)) * scale * 2.0
        case _:
            bonus = float(bias) - scale
    return bonus
"""
        ssa_fn = lower_source_to_ssa(src, fn_name="dispatch_with_luts", optimize=True)
        self.assertIn("LUT_SCALES", ssa_fn.luts)
        self.assertIn("LUT_BIAS", ssa_fn.luts)
        self.assertEqual(ssa_fn.return_type, "f64")

        btv = BackendTranslationValidator(enable_float_theory=True)
        llvm_ir = LLVMBackend().ssa_to_llvm_ir(ssa_fn)
        wat_src = WasmBackend().ssa_to_wat(ssa_fn)

        res_ll = btv.verify_ssa_to_llvm_ir(ssa_fn, llvm_ir)
        self.assertTrue(res_ll["proven"], f"LLVM TV failed on match + .rodata LUT: {res_ll}")
        res_wa = btv.verify_ssa_to_wat(ssa_fn, wat_src)
        self.assertTrue(res_wa["proven"], f"WAT TV failed on match + .rodata LUT: {res_wa}")

        vectors = [
            (0, 0, 8.0),   # 8.0*0.25 + (-10) = -8.0
            (1, 2, 5.0),   # (5.0+15)*1.25*2 = 50.0
            (2, 3, 10.0),  # (10.0+30)*2.5*2 = 200.0
            (9, 1, 10.0),  # 5 - 0.5 = 4.5
        ]
        diff = btv.verify_differential_execution(ssa_fn, vectors)
        self.assertTrue(diff["equivalent"], f"Differential parity failed on match + .rodata LUT: {diff}")
        expected = [-8.0, 50.0, 200.0, 4.5]
        for got, exp in zip(diff["outputs_by_backend"]["native"], expected):
            self.assertEqual(_f64_to_u64(got), _f64_to_u64(exp))

    def test_arm64_match_and_rodata_adr_unicorn_execution(self):
        from unicorn import UC_ARCH_ARM64, UC_MODE_ARM, Uc
        from unicorn.arm64_const import (
            UC_ARM64_REG_CPACR_EL1,
            UC_ARM64_REG_D0,
            UC_ARM64_REG_LR,
            UC_ARM64_REG_PC,
            UC_ARM64_REG_SP,
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
        )

        src = """
LUT_F = [1.5, 2.5, 3.5, 4.5]
LUT_I: Array[i32, 4] = [-4, 8, -12, 16]

def arm64_match_lut(mode: int, idx: int) -> float:
    s = LUT_F[idx]
    b = LUT_I[idx]
    out = 0.0
    match mode:
        case 0:
            out = s + float(b)
        case 1 | 2:
            out = s * 2.0 + float(b)
        case _:
            out = float(b) - s
    return out
"""
        ssa_fn = lower_source_to_ssa(src, fn_name="arm64_match_lut", optimize=True)
        art = Arm64CodeGenerator().compile_function(ssa_fn)
        self.assertGreater(art.code_end_offset, 0)
        self.assertGreater(len(art.code_bytes), art.code_end_offset)

        CODE_ADDR = 0x100000
        STOP_ADDR = 0x180000
        STACK_ADDR = 0x200000

        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        mu.mem_map(CODE_ADDR, 0x10000)
        mu.mem_map(STOP_ADDR, 0x10000)
        mu.mem_map(STACK_ADDR, 0x10000)
        try:
            cpacr = mu.reg_read(UC_ARM64_REG_CPACR_EL1)
            mu.reg_write(UC_ARM64_REG_CPACR_EL1, cpacr | (0x3 << 20))
        except Exception:
            pass
        mu.mem_write(CODE_ADDR, art.code_bytes)
        mu.mem_write(STOP_ADDR, struct.pack("<I", 0xD503201F))

        for mode, idx, exp in [(0, 0, -2.5), (2, 2, -5.0), (7, 3, 11.5)]:
            mu.reg_write(UC_ARM64_REG_SP, STACK_ADDR + 0x8000)
            mu.reg_write(UC_ARM64_REG_LR, STOP_ADDR)
            mu.reg_write(UC_ARM64_REG_X0, mode)
            mu.reg_write(UC_ARM64_REG_X1, idx)
            mu.emu_start(CODE_ADDR, STOP_ADDR, count=200000)
            self.assertEqual(mu.reg_read(UC_ARM64_REG_PC), STOP_ADDR)
            got = _u64_to_f64(mu.reg_read(UC_ARM64_REG_D0))
            self.assertEqual(_f64_to_u64(got), _f64_to_u64(exp))

    def test_polyglot_rust_match_go_ts_switch_and_rodata_fusion(self):
        rs_src = """
        pub const RUST_LUT: [f64; 4] = [0.5, 1.5, 2.5, 3.5];
        pub fn rs_classify(code: i64, idx: i64) -> f64 {
            return match code {
                0 => RUST_LUT[idx],
                1 | 2 => RUST_LUT[idx] * 2.0,
                _ => -1.0,
            };
        }
        """
        go_src = """
        package lutpkg
        var GO_BONUS = [4]int32{-5, 10, 20, 40}
        func go_bonus(tier int64, slot int64) int64 {
            switch tier {
            case 1, 2:
                return GO_BONUS[slot] + 100
            case 3:
                return GO_BONUS[slot] + 200
            default:
                return GO_BONUS[slot]
            }
        }
        """
        ts_src = """
        export function ts_dispatch_pipeline(mode: i64, slot: i64): f64 {
            let res = 0.0;
            switch (mode) {
                case 0:
                case 1:
                    res = rs_classify(mode, slot) + go_bonus(mode + 1, slot);
                    break;
                default:
                    res = rs_classify(9, slot) + go_bonus(3, slot);
                    break;
            }
            return res;
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            rs_dir = os.path.join(tmp, "repo_rs")
            go_dir = os.path.join(tmp, "repo_go")
            ts_dir = os.path.join(tmp, "repo_ts")
            for d in (rs_dir, go_dir, ts_dir):
                os.makedirs(d, exist_ok=True)
            with open(os.path.join(rs_dir, "cls.rs"), "w", encoding="utf-8") as f:
                f.write(rs_src)
            with open(os.path.join(go_dir, "bns.go"), "w", encoding="utf-8") as f:
                f.write(go_src)
            with open(os.path.join(ts_dir, "pipe.ts"), "w", encoding="utf-8") as f:
                f.write(ts_src)

            res_nat = OmniRepoCompiler().compile_repositories(
                [rs_dir, go_dir, ts_dir], os.path.join(tmp, "lut_nat.bin"), entry_export="ts_dispatch_pipeline", backend="native"
            )
            self.assertTrue(res_nat["success"], f"Native match/LUT OmniRepo failed: {res_nat}")

            res_ll = OmniRepoCompiler().compile_repositories(
                [rs_dir, go_dir, ts_dir], os.path.join(tmp, "lut_ll.bin"), entry_export="ts_dispatch_pipeline", backend="llvm"
            )
            self.assertTrue(res_ll["success"], f"LLVM match/LUT OmniRepo failed: {res_ll}")
            self.assertEqual(res_ll["stages"]["backend_validation"]["refuted"], 0)

            out_wasm = os.path.join(tmp, "lut_pipe.wasm")
            res_wa = OmniRepoCompiler().compile_repositories(
                [rs_dir, go_dir, ts_dir], out_wasm, entry_export="ts_dispatch_pipeline", backend="wasm"
            )
            self.assertTrue(res_wa["success"], f"WASM match/LUT OmniRepo failed: {res_wa}")

            from wasmtime import Engine, Instance, Module, Store
            engine = Engine()
            store = Store(engine)
            with open(out_wasm, "rb") as wf:
                mod = Module(engine, wf.read())
            inst = Instance(store, mod, [])
            fn = inst.exports(store)["ts_dispatch_pipeline"]

            # mode=0, slot=0: rs_classify(0,0)=0.5 + go_bonus(1,0)=(-5+100)=95 => 95.5
            self.assertEqual(_f64_to_u64(fn(store, 0, 0)), _f64_to_u64(95.5))
            # mode=1, slot=2 (fallthrough case 0: case 1:): rs_classify(1,2)=5.0 + go_bonus(2,2)=(20+100)=120 => 125.0
            self.assertEqual(_f64_to_u64(fn(store, 1, 2)), _f64_to_u64(125.0))
            # mode=4, slot=3 (default): rs_classify(9,3)=-1.0 + go_bonus(3,3)=(40+200)=240 => 239.0
            self.assertEqual(_f64_to_u64(fn(store, 4, 3)), _f64_to_u64(239.0))

    def test_jit_native_match_and_rodata_with_host_c_pow(self):
        libm = omni_ffi_load_lib("libm")
        pow_ptr = omni_ffi_get_symbol(libm, "pow")
        self.assertGreater(pow_ptr, 0)

        src = """
EXP_TABLE = [1.0, 2.0, 3.0, 4.0]

def match_lut_pow(mode: int, idx: int, base: float, fn_pow: int) -> float:
    exp_v = EXP_TABLE[idx]
    out = 0.0
    match mode:
        case 0:
            out = omni_ffi_call2_f64(fn_pow, base, exp_v)
        case 1 | 2:
            out = omni_ffi_call2_f64(fn_pow, base + 1.0, exp_v)
        case _:
            out = exp_v
    return out
"""
        jit = NativeJitCompiler()
        cfunc, mem, _ = jit.compile_function(src, fn_name="match_lut_pow")
        self.assertTrue(mem.is_executable)
        self.assertEqual(_f64_to_u64(cfunc(0, 2, 3.0, pow_ptr)), _f64_to_u64(27.0))
        self.assertEqual(_f64_to_u64(cfunc(2, 1, 4.0, pow_ptr)), _f64_to_u64(25.0))
        self.assertEqual(_f64_to_u64(cfunc(9, 3, 2.0, pow_ptr)), _f64_to_u64(4.0))


if __name__ == "__main__":
    unittest.main()
