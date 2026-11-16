"""
Alpha-C31 Verification Suite:
Typed IEEE-754 `f64` Linear Memory Arrays (`ptr_f64`), In-Place Mutation &
Unbounded `QF_ABVFP` Inductive Loop Verification Across:
  - Python (`ptr_f64`, `list[float]`) & Polyglot (`&mut [f64]`, `[]float64`, `Float64Array`)
  - Omni-SSA typed `f64` `load`, `store`, and pointer `AugAssign` (`a[i] += ...`)
  - LLVM `getelementptr double` / `load double` / `store double` + `LLVMIRToSSALifter`
  - WebAssembly `f64.load` / `f64.store` + `WATToSSALifter`
  - Physical Differential Execution (`Native x86-64 SSE2` == `LLVM O3 MCJIT` == `Wasmtime` linear memory)
    verifying bit-exact return value AND post-call mutated array buffer contents
  - Unbounded Inductive `QF_ABVFP` (`PROVEN_INDUCTIVE_EQUIVALENT`, `bounded=False`) loop proofs
    (1D LICM + 2D nested matrix loops) and mutation refutation (`REFUTED_COUNTEREXAMPLE`)
  - Native x86-64 AVX2 `emit_avx2_vector_add_f64` (`vaddpd`) & ARM64 NEON `emit_neon_vector_add_f64`
    (`FADD V0.2D`) + ARM64 scalar `f64` array loops on Unicorn ARMv8-A
"""

import ast
import ctypes
import os
import platform
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.llvm_backend import LLVMBackend
from compiler.native_codegen import Arm64CodeGenerator, NativeCodeGenerator, X64CodeGenerator
from compiler.ssa_ir import (
    BasicBlock,
    SSAFunction,
    SSAInstruction,
    SSAVar,
    lower_ast_to_ssa,
)
from compiler.wasm_backend import WasmBackend
from frontends.polyglot_ssa_lowering import lower_polyglot_source_to_ast
from validation.backend_translation_validator import BackendTranslationValidator, NativeJitMemory
from validation.silicon_safety_sandbox import SiliconSafetySandbox, UNICORN_AVAILABLE
from validation.ssa_translation_validator import SSATranslationValidator


def _f64_to_u64(val: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", float(val)))[0]


def _u64_to_f64(bits: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))[0]


class TestAlphaC31F64MemoryAndInductiveQFABVFP(unittest.TestCase):

    def test_python_f64_array_load_store_augassign_and_differential_parity(self):
        src = """
def fuse_accumulate(a: ptr_f64, b: list[float], n: int, scale: float) -> float:
    acc = 0.0
    for i in range(n):
        a[i] += b[i] * scale
        acc = acc + a[i]
    return acc
"""
        fdef = ast.parse(src).body[0]
        ssa_fn = lower_ast_to_ssa(fdef, optimize=True)
        self.assertEqual(ssa_fn.return_type, "f64")
        self.assertEqual(
            ssa_fn.param_types,
            {"a": "ptr_f64", "b": "ptr_f64", "n": "i64", "scale": "f64"},
        )

        btv = BackendTranslationValidator(enable_float_theory=True)
        llvm_ir = LLVMBackend().ssa_to_llvm_ir(ssa_fn)
        wat = WasmBackend().ssa_to_wat(ssa_fn)
        self.assertIn("load double", llvm_ir)
        self.assertIn("store double", llvm_ir)
        self.assertIn("f64.load", wat)
        self.assertIn("f64.store", wat)

        res_llvm = btv.verify_ssa_to_llvm_ir(ssa_fn, llvm_ir)
        self.assertTrue(res_llvm["proven"], f"LLVM f64 array TV failed: {res_llvm}")
        self.assertEqual(res_llvm["status"], "PROVEN_INDUCTIVE_EQUIVALENT")
        self.assertFalse(res_llvm["bounded"])

        res_wat = btv.verify_ssa_to_wat(ssa_fn, wat)
        self.assertTrue(res_wat["proven"], f"WAT f64 array TV failed: {res_wat}")
        self.assertEqual(res_wat["status"], "PROVEN_INDUCTIVE_EQUIVALENT")
        self.assertFalse(res_wat["bounded"])

        vectors = [
            ([1.0, 2.0, 3.0, 4.0], [0.5, -1.0, 2.0, 0.25], 4, 2.0),
            ([-1.5, 0.25, 3.75], [2.0, 4.0, -1.0], 3, -0.5),
            ([10.0, 20.0], [1.0, 2.0], 0, 5.0),
        ]
        diff = btv.verify_differential_execution(ssa_fn, vectors)
        self.assertTrue(diff["equivalent"], f"f64 array differential execution failed: {diff}")

        for idx, (a_in, b_in, n_in, sc) in enumerate(vectors):
            exp_a = list(a_in)
            exp_acc = 0.0
            for i in range(n_in):
                exp_a[i] = exp_a[i] + b_in[i] * sc
                exp_acc = exp_acc + exp_a[i]
            got_ret = diff["outputs_by_backend"]["native"][idx]
            self.assertEqual(_f64_to_u64(got_ret), _f64_to_u64(exp_acc))
            for be in diff["active_backends"]:
                got_mem_a = diff["memory_by_backend"][be][idx]["a"]
                self.assertEqual(
                    [_f64_to_u64(v) for v in got_mem_a],
                    [_f64_to_u64(v) for v in exp_a],
                    f"Backend {be} mutated buffer mismatch at vector {idx}",
                )

    def test_polyglot_f64_slices_rust_go_ts_and_differential_mutation(self):
        rs_src = """
        pub fn rs_saxpy(y: &mut [f64], x: &[f64], n: i64, alpha: f64) -> f64 {
            let mut total: f64 = 0.0;
            for i in 0..n {
                y[i] = y[i] + alpha * x[i];
                total = total + y[i];
            }
            total
        }
        """
        go_src = """
        package vec
        func go_scale_bias(buf []float64, n int64, factor float64, bias float64) float64 {
            var acc float64 = 0.0
            for i := 0; i < n; i++ {
                buf[i] = buf[i] * factor + bias
                acc = acc + buf[i]
            }
            return acc
        }
        """
        ts_src = """
        export const ts_weighted_update = (arr: Float64Array, n: number, w: f64): f64 => {
            let s: f64 = 0.0;
            for (let i = 0; i < n; i++) {
                arr[i] += w * 0.5;
                s += arr[i];
            }
            return s;
        };
        """

        btv = BackendTranslationValidator(enable_float_theory=True)

        # 1. Rust &mut [f64] / &[f64]
        rs_mod = lower_polyglot_source_to_ast(rs_src, "rust", strict=True)
        rs_ssa = lower_ast_to_ssa(rs_mod.functions[0], optimize=True)
        self.assertEqual(rs_ssa.param_types, {"y": "ptr_f64", "x": "ptr_f64", "n": "i64", "alpha": "f64"})
        self.assertEqual(rs_ssa.return_type, "f64")
        self.assertTrue(btv.verify_ssa_to_llvm_ir(rs_ssa, LLVMBackend().ssa_to_llvm_ir(rs_ssa))["proven"])
        self.assertTrue(btv.verify_ssa_to_wat(rs_ssa, WasmBackend().ssa_to_wat(rs_ssa))["proven"])
        rs_diff = btv.verify_differential_execution(
            rs_ssa,
            [([1.0, 2.0, 3.0], [4.0, -1.0, 0.5], 3, 1.5)],
        )
        self.assertTrue(rs_diff["equivalent"], f"Rust saxpy diff failed: {rs_diff}")
        # Expected y = [1+6=7.0, 2-1.5=0.5, 3+0.75=3.75], total = 11.25
        self.assertEqual(_f64_to_u64(rs_diff["outputs_by_backend"]["native"][0]), _f64_to_u64(11.25))
        self.assertEqual(
            [_f64_to_u64(v) for v in rs_diff["memory_by_backend"]["wasm"][0]["y"]],
            [_f64_to_u64(7.0), _f64_to_u64(0.5), _f64_to_u64(3.75)],
        )

        # 2. Go []float64
        go_mod = lower_polyglot_source_to_ast(go_src, "go", strict=True)
        go_ssa = lower_ast_to_ssa(go_mod.functions[0], optimize=True)
        self.assertEqual(go_ssa.param_types, {"buf": "ptr_f64", "n": "i64", "factor": "f64", "bias": "f64"})
        self.assertTrue(btv.verify_ssa_to_llvm_ir(go_ssa, LLVMBackend().ssa_to_llvm_ir(go_ssa))["proven"])
        self.assertTrue(btv.verify_ssa_to_wat(go_ssa, WasmBackend().ssa_to_wat(go_ssa))["proven"])
        go_diff = btv.verify_differential_execution(
            go_ssa,
            [([2.0, -4.0, 1.5], 3, 0.5, 1.0)],
        )
        self.assertTrue(go_diff["equivalent"], f"Go []float64 diff failed: {go_diff}")
        # Expected buf = [2.0, -1.0, 1.75], acc = 2.75
        self.assertEqual(_f64_to_u64(go_diff["outputs_by_backend"]["native"][0]), _f64_to_u64(2.75))

        # 3. TypeScript Float64Array
        ts_mod = lower_polyglot_source_to_ast(ts_src, "typescript", strict=True)
        ts_ssa = lower_ast_to_ssa(ts_mod.functions[0], optimize=True)
        self.assertEqual(ts_ssa.param_types["arr"], "ptr_f64")
        self.assertTrue(btv.verify_ssa_to_llvm_ir(ts_ssa, LLVMBackend().ssa_to_llvm_ir(ts_ssa))["proven"])
        self.assertTrue(btv.verify_ssa_to_wat(ts_ssa, WasmBackend().ssa_to_wat(ts_ssa))["proven"])
        ts_diff = btv.verify_differential_execution(
            ts_ssa,
            [([0.5, 1.5, 2.5], 3, 3.0)],
        )
        self.assertTrue(ts_diff["equivalent"], f"TS Float64Array diff failed: {ts_diff}")
        # Each element += 1.5 -> [2.0, 3.0, 4.0], sum = 9.0
        self.assertEqual(_f64_to_u64(ts_diff["outputs_by_backend"]["native"][0]), _f64_to_u64(9.0))

    def test_unbounded_inductive_qfabvfp_licm_and_nested_2d_loops(self):
        # 1. 1D f64 array loop with loop-invariant expression hoisted vs inside loop
        def build_1d_array_loop(hoisted: bool, mutate_store: bool = False) -> SSAFunction:
            fn = SSAFunction(
                "arr_licm_f64",
                ["a", "n", "scale", "bias"],
                param_types={"a": "ptr_f64", "n": "i64", "scale": "f64", "bias": "f64"},
                return_type="f64",
            )
            entry = BasicBlock("entry")
            hdr = BasicBlock("hdr")
            body = BasicBlock("body")
            latch = BasicBlock("latch")
            exit_bb = BasicBlock("exit")
            for b in (entry, hdr, body, latch, exit_bb):
                fn.add_block(b)
            fn.entry_block = entry
            entry.connect_to(hdr)
            hdr.connect_to(body)
            hdr.connect_to(exit_bb)
            body.connect_to(latch)
            latch.connect_to(hdr)

            va = SSAVar("a", 0, var_type="ptr_f64")
            vn = SSAVar("n", 0, var_type="i64")
            vsc = SSAVar("scale", 0, var_type="f64")
            vbi = SSAVar("bias", 0, var_type="f64")
            entry.add_instruction(SSAInstruction(va, "param", ["a"]))
            entry.add_instruction(SSAInstruction(vn, "param", ["n"]))
            entry.add_instruction(SSAInstruction(vsc, "param", ["scale"]))
            entry.add_instruction(SSAInstruction(vbi, "param", ["bias"]))
            c0 = SSAVar("c0", 1, var_type="i64")
            fc0 = SSAVar("fc0", 1, var_type="f64")
            c1 = SSAVar("c1", 1, var_type="i64")
            entry.add_instruction(SSAInstruction(c0, "const", [0]))
            entry.add_instruction(SSAInstruction(fc0, "fconst", [0.0]))
            entry.add_instruction(SSAInstruction(c1, "const", [1]))

            inv_var = SSAVar("inv", 1, var_type="f64")
            if hoisted:
                entry.add_instruction(SSAInstruction(inv_var, "fmul", [vsc, vbi]))
            entry.add_instruction(SSAInstruction(None, "br", ["hdr"]))

            i_phi = SSAVar("i", 1, var_type="i64")
            acc_phi = SSAVar("acc", 1, var_type="f64")
            i_next = SSAVar("i", 2, var_type="i64")
            acc_next = SSAVar("acc", 2, var_type="f64")
            hdr.phi_nodes.append(
                SSAInstruction(i_phi, "phi", [c0, i_next], phi_incoming=[("entry", c0), ("latch", i_next)])
            )
            hdr.phi_nodes.append(
                SSAInstruction(acc_phi, "phi", [fc0, acc_next], phi_incoming=[("entry", fc0), ("latch", acc_next)])
            )
            cmp_v = SSAVar("cmp", 1, var_type="i64")
            hdr.add_instruction(SSAInstruction(cmp_v, "cmp_lt", [i_phi, vn]))
            hdr.add_instruction(SSAInstruction(None, "br_cond", [cmp_v, "body", "exit"]))

            if not hoisted:
                body.add_instruction(SSAInstruction(inv_var, "fmul", [vsc, vbi]))
            ld_v = SSAVar("ld", 1, var_type="f64")
            body.add_instruction(SSAInstruction(ld_v, "load", [va, i_phi]))
            st_v = SSAVar("st", 1, var_type="f64")
            body.add_instruction(
                SSAInstruction(st_v, "fsub" if mutate_store else "fadd", [ld_v, inv_var])
            )
            body.add_instruction(SSAInstruction(None, "store", [va, i_phi, st_v]))
            body.add_instruction(SSAInstruction(acc_next, "fadd", [acc_phi, st_v]))
            body.add_instruction(SSAInstruction(None, "br", ["latch"]))

            latch.add_instruction(SSAInstruction(i_next, "add", [i_phi, c1]))
            latch.add_instruction(SSAInstruction(None, "br", ["hdr"]))

            exit_bb.add_instruction(SSAInstruction(None, "ret", [acc_phi]))
            return fn

        tv = SSATranslationValidator(
            enable_memory_theory=True,
            enable_inductive_loops=True,
            enable_float_theory=True,
            max_loop_unroll=4,
        )
        res_ok = tv.verify_equivalence(build_1d_array_loop(False), build_1d_array_loop(True))
        self.assertTrue(res_ok["proven"], f"Unbounded QF_ABVFP LICM proof failed: {res_ok}")
        self.assertEqual(res_ok["status"], "PROVEN_INDUCTIVE_EQUIVALENT")
        self.assertFalse(res_ok["bounded"])

        res_bad = tv.verify_equivalence(build_1d_array_loop(False), build_1d_array_loop(True, mutate_store=True))
        self.assertFalse(res_bad["proven"])
        self.assertEqual(res_bad["status"], "REFUTED_COUNTEREXAMPLE")

        # 2. 2D nested f64 array reduction loop
        src_2d_a = """
def mat_scale_sum(mat: ptr_f64, rows: int, cols: int, w: float) -> float:
    acc = 0.0
    for r in range(rows):
        for c in range(cols):
            acc = acc + mat[r * cols + c] * w
    return acc
"""
        src_2d_b = """
def mat_scale_sum(mat: ptr_f64, rows: int, cols: int, w: float) -> float:
    acc = 0.0
    for r in range(rows):
        row_base = r * cols
        for c in range(cols):
            acc = acc + mat[row_base + c] * w
    return acc
"""
        src_2d_mut = """
def mat_scale_sum(mat: ptr_f64, rows: int, cols: int, w: float) -> float:
    acc = 0.0
    for r in range(rows):
        for c in range(cols):
            acc = acc + mat[r * cols + c] * (w + 0.5)
    return acc
"""
        ssa_2d_a = lower_ast_to_ssa(ast.parse(src_2d_a).body[0], optimize=False)
        ssa_2d_b = lower_ast_to_ssa(ast.parse(src_2d_b).body[0], optimize=False)
        ssa_2d_mut = lower_ast_to_ssa(ast.parse(src_2d_mut).body[0], optimize=False)

        res_2d_ok = tv.verify_equivalence(ssa_2d_a, ssa_2d_b)
        self.assertTrue(res_2d_ok["proven"], f"2D nested QF_ABVFP proof failed: {res_2d_ok}")
        self.assertEqual(res_2d_ok["status"], "PROVEN_INDUCTIVE_EQUIVALENT")
        self.assertFalse(res_2d_ok["bounded"])

        res_2d_bad = tv.verify_equivalence(ssa_2d_a, ssa_2d_mut)
        self.assertFalse(res_2d_bad["proven"])
        self.assertEqual(res_2d_bad["status"], "REFUTED_COUNTEREXAMPLE")

    def test_avx2_vaddpd_and_arm64_neon_vfp_f64_array_execution(self):
        # 1. Physical x86-64 AVX2 256-bit `vaddpd` + scalar `addsd` tail execution
        target_os = "windows" if platform.system().lower().startswith("win") else "linux"
        x64_cg = X64CodeGenerator(target_os=target_os)
        avx2_code = x64_cg.emit_avx2_vector_add_f64()
        jit_mem = NativeJitMemory(len(avx2_code))
        jit_mem.write_code(avx2_code)
        cfunc = ctypes.CFUNCTYPE(
            ctypes.c_int64,
            ctypes.c_int64,
            ctypes.c_int64,
            ctypes.c_int64,
            ctypes.c_int64,
        )(jit_mem.ptr)

        a_vals = [1.25, -2.5, 3.75, 4.0, -0.5, 6.125, 10.0]
        b_vals = [0.75, 2.5, -1.25, 1.5, 2.5, -0.125, -3.5]
        n = len(a_vals)
        ca = (ctypes.c_double * n)(*a_vals)
        cb = (ctypes.c_double * n)(*b_vals)
        cout = (ctypes.c_double * n)(*([0.0] * n))

        rc = cfunc(ctypes.addressof(ca), ctypes.addressof(cb), ctypes.addressof(cout), n)
        self.assertEqual(rc, 1)
        for i in range(n):
            self.assertEqual(_f64_to_u64(cout[i]), _f64_to_u64(a_vals[i] + b_vals[i]))

        if not UNICORN_AVAILABLE:
            return

        # 2. Physical ARM64 NEON 128-bit `FADD V0.2D` + scalar VFP `FADD D0` tail on Unicorn ARMv8-A
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
        from unicorn.arm64_const import (
            UC_ARM64_REG_CPACR_EL1,
            UC_ARM64_REG_D0,
            UC_ARM64_REG_LR,
            UC_ARM64_REG_PC,
            UC_ARM64_REG_SP,
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
            UC_ARM64_REG_X2,
            UC_ARM64_REG_X3,
        )

        arm_cg = Arm64CodeGenerator()
        neon_code = arm_cg.emit_neon_vector_add_f64()

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

        mu.mem_write(code_addr, neon_code)
        mu.mem_write(stop_addr, struct.pack("<I", 0xD503201F))
        mu.reg_write(UC_ARM64_REG_SP, stack_addr + 0x8000)
        mu.reg_write(UC_ARM64_REG_LR, stop_addr)

        addr_a = data_addr
        addr_b = data_addr + 0x400
        addr_out = data_addr + 0x800
        mu.mem_write(addr_a, struct.pack(f"<{n}d", *a_vals))
        mu.mem_write(addr_b, struct.pack(f"<{n}d", *b_vals))

        mu.reg_write(UC_ARM64_REG_X0, addr_a)
        mu.reg_write(UC_ARM64_REG_X1, addr_b)
        mu.reg_write(UC_ARM64_REG_X2, addr_out)
        mu.reg_write(UC_ARM64_REG_X3, n)

        mu.emu_start(code_addr, stop_addr, count=200000)
        self.assertEqual(mu.reg_read(UC_ARM64_REG_PC), stop_addr)
        neon_out = struct.unpack(f"<{n}d", bytes(mu.mem_read(addr_out, n * 8)))
        for i in range(n):
            self.assertEqual(_f64_to_u64(neon_out[i]), _f64_to_u64(a_vals[i] + b_vals[i]))

        # 3. Physical ARM64 compiled SSA `f64` array loop (`load`/`store`/`fadd`/`fmul`) on fresh Unicorn VM
        src_arm_arr = """
def arm_scale_inplace(buf: ptr_f64, n: int, factor: float) -> float:
    acc = 0.0
    for i in range(n):
        buf[i] = buf[i] * factor
        acc = acc + buf[i]
    return acc
"""
        arm_ssa = lower_ast_to_ssa(ast.parse(src_arm_arr).body[0], optimize=True)
        arm_art = NativeCodeGenerator(arch="arm64").compile_ssa(arm_ssa)

        mu2 = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        cpacr2 = mu2.reg_read(UC_ARM64_REG_CPACR_EL1)
        mu2.reg_write(UC_ARM64_REG_CPACR_EL1, cpacr2 | (0x3 << 20))
        mu2.mem_map(code_addr, mem_sz)
        mu2.mem_map(stack_addr, mem_sz)
        mu2.mem_map(stop_addr, mem_sz)
        mu2.mem_map(data_addr, mem_sz)
        mu2.mem_write(code_addr, arm_art.code_bytes)
        mu2.mem_write(stop_addr, struct.pack("<I", 0xD503201F))

        in_buf = [2.0, -1.5, 4.25, 0.5]
        mu2.mem_write(addr_a, struct.pack("<4d", *in_buf))
        mu2.reg_write(UC_ARM64_REG_SP, stack_addr + 0x8000)
        mu2.reg_write(UC_ARM64_REG_LR, stop_addr)
        mu2.reg_write(UC_ARM64_REG_X0, addr_a)
        mu2.reg_write(UC_ARM64_REG_X1, 4)
        mu2.reg_write(UC_ARM64_REG_D0, _f64_to_u64(2.0))

        mu2.emu_start(code_addr, stop_addr, count=200000)
        self.assertEqual(mu2.reg_read(UC_ARM64_REG_PC), stop_addr)
        got_sum = _u64_to_f64(mu2.reg_read(UC_ARM64_REG_D0))
        got_buf = struct.unpack("<4d", bytes(mu2.mem_read(addr_a, 32)))
        self.assertEqual(_f64_to_u64(got_sum), _f64_to_u64(10.5))
        self.assertEqual(
            [_f64_to_u64(v) for v in got_buf],
            [_f64_to_u64(v * 2.0) for v in in_buf],
        )


if __name__ == "__main__":
    unittest.main()
