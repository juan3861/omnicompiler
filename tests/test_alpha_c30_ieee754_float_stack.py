"""
Alpha-C30 Verification Suite:
Full IEEE-754 Floating-Point (`f64`) Stack Across:
  - Polyglot (Rust `f64`, Go `float64`, TS `f64`/`double`, JS `allow_floats=True`) & Python AST
  - Omni-SSA IR (`return_type="f64"`, `fconst`, `fneg`, `fadd`/`fsub`/`fmul`/`fdiv`, `fcmp_*`,
    `select`, `sitofp`, `fptosi`, `phi` over loops & branches)
  - Native x86-64 SSE2 (`addsd`, `subsd`, `mulsd`, `divsd`, `ucomisd`, `cvtsi2sd`, `cvttsd2si`)
  - Native ARM64 / AArch64 VFPv8 (`fadd`, `fsub`, `fmul`, `fdiv`, `fcmp`+`cset`, `scvtf`, `fcvtzs`, `fmov`)
    executed physically inside Unicorn ARMv8-A CPU
  - LLVM `double` O3 MCJIT + Wasmtime `f64` execution parity
  - Z3 `QF_FP` (`Float64`) Translation Validation across SSA optimizations, LLVM IR lifting,
    and WAT lifting, including IEEE-754 non-associativity refutation
  - Backward compatibility with Alpha-C27 unannotated strict float rejection
"""

import ast
import math
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.llvm_backend import LLVMBackend
from compiler.native_codegen import NativeCodeGenerator
from compiler.ssa_ir import (
    BasicBlock,
    SSAFunction,
    SSAInstruction,
    SSAVar,
    lower_ast_to_ssa,
)
from compiler.wasm_backend import WasmBackend
from frontends.polyglot_ssa_lowering import (
    PolyglotLoweringError,
    lower_polyglot_source_to_ast,
)
from validation.backend_translation_validator import BackendTranslationValidator
from validation.silicon_safety_sandbox import SiliconSafetySandbox, UNICORN_AVAILABLE
from validation.ssa_translation_validator import SSATranslationValidator


def _f64_to_u64(val: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", float(val)))[0]


def _u64_to_f64(bits: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))[0]


def _emulate_arm64_f64(machine_code: bytes, args: list, arg_types: list) -> float:
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn.arm64_const import (
        UC_ARM64_REG_CPACR_EL1,
        UC_ARM64_REG_D0,
        UC_ARM64_REG_D1,
        UC_ARM64_REG_D2,
        UC_ARM64_REG_D3,
        UC_ARM64_REG_LR,
        UC_ARM64_REG_PC,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
    )

    code_addr = SiliconSafetySandbox.CODE_ADDR
    stack_addr = SiliconSafetySandbox.STACK_ADDR
    stop_addr = SiliconSafetySandbox.STOP_ADDR
    mem_sz = SiliconSafetySandbox.MEMORY_SIZE
    code_map_sz = max(mem_sz, ((len(machine_code) + 0xFFF) // 0x1000) * 0x1000)

    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    # Enable EL1/EL0 access to SIMD/FP registers (CPACR_EL1.FPEN = 0b11)
    cpacr = mu.reg_read(UC_ARM64_REG_CPACR_EL1)
    mu.reg_write(UC_ARM64_REG_CPACR_EL1, cpacr | (0x3 << 20))

    mu.mem_map(code_addr, code_map_sz)
    mu.mem_map(stack_addr, mem_sz)
    mu.mem_map(stop_addr, mem_sz)

    mu.mem_write(code_addr, machine_code)
    mu.mem_write(stop_addr, struct.pack("<I", 0xD503201F))
    mu.reg_write(UC_ARM64_REG_SP, stack_addr + 0x8000)
    mu.reg_write(UC_ARM64_REG_LR, stop_addr)

    x_regs = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3]
    d_regs = [UC_ARM64_REG_D0, UC_ARM64_REG_D1, UC_ARM64_REG_D2, UC_ARM64_REG_D3]
    x_idx = 0
    d_idx = 0
    for val, ty in zip(args, arg_types):
        if ty == "f64":
            mu.reg_write(d_regs[d_idx], _f64_to_u64(val))
            d_idx += 1
        else:
            mu.reg_write(x_regs[x_idx], int(val) & 0xFFFFFFFFFFFFFFFF)
            x_idx += 1

    mu.emu_start(code_addr, stop_addr, count=200000)
    final_pc = mu.reg_read(UC_ARM64_REG_PC)
    if final_pc != stop_addr:
        raise AssertionError(f"ARM64 did not reach RET (PC={hex(final_pc)})")
    return _u64_to_f64(mu.reg_read(UC_ARM64_REG_D0))


class TestAlphaC30IEEE754FloatStack(unittest.TestCase):

    def test_python_f64_arithmetic_branch_and_tv(self):
        src = """
def eval_f64(x: float, y: float) -> float:
    a = x * 1.5 - y / 2.0
    b = -a + 0.25
    if a > b:
        res = a + 3.5
    else:
        res = b - 1.25
    return res
"""
        tree = ast.parse(src)
        fdef = tree.body[0]
        ssa_unopt = lower_ast_to_ssa(fdef, optimize=False)
        ssa_opt = lower_ast_to_ssa(fdef, optimize=True)

        self.assertEqual(ssa_opt.return_type, "f64")
        self.assertEqual(ssa_opt.param_types, {"x": "f64", "y": "f64"})

        # Z3 QF_FP equivalence across SSA optimization
        ssa_tv = SSATranslationValidator(enable_float_theory=True)
        res_opt = ssa_tv.verify_equivalence(ssa_unopt, ssa_opt, timeout_ms=8000)
        self.assertTrue(res_opt["proven"], f"SSA float opt TV failed: {res_opt}")

        # Backend TV (LLVM double + WAT f64) + physical parity
        btv = BackendTranslationValidator(enable_float_theory=True)
        llvm_ir = LLVMBackend().ssa_to_llvm_ir(ssa_opt)
        wat = WasmBackend().ssa_to_wat(ssa_opt)

        res_llvm = btv.verify_ssa_to_llvm_ir(ssa_opt, llvm_ir)
        self.assertTrue(res_llvm["proven"], f"SSA<->LLVM float TV failed: {res_llvm}")

        res_wat = btv.verify_ssa_to_wat(ssa_opt, wat)
        self.assertTrue(res_wat["proven"], f"SSA<->WAT float TV failed: {res_wat}")

        def py_ref(x: float, y: float) -> float:
            a = x * 1.5 - y / 2.0
            b = -a + 0.25
            if a > b:
                return a + 3.5
            return b - 1.25

        vectors = [
            (2.5, 1.0),
            (-4.0, 3.0),
            (0.0, 0.0),
            (10.25, -5.5),
            (-0.125, -2.5),
        ]
        diff = btv.verify_differential_execution(ssa_opt, vectors)
        self.assertTrue(diff["equivalent"], f"Float differential parity failed: {diff}")
        expected = [py_ref(x, y) for x, y in vectors]
        for got, exp in zip(diff["outputs_by_backend"]["native"], expected):
            self.assertEqual(_f64_to_u64(got), _f64_to_u64(exp), f"got={got}, exp={exp}")

    def test_mixed_int_float_loops_sitofp_and_fptosi(self):
        src_loop_f64 = """
def harmonic_mix(n: int, scale: float) -> float:
    acc = 0.0
    for i in range(1, n + 1):
        acc = acc + (scale / float(i))
    return acc
"""
        src_loop_i64 = """
def scaled_round_sum(n: int, base: float) -> int:
    acc = base
    i = 0
    while i < n:
        acc += float(i) * 0.5
        i += 1
    return int(acc * 100.0)
"""
        btv = BackendTranslationValidator(enable_float_theory=True)

        fdef1 = ast.parse(src_loop_f64).body[0]
        ssa1_raw = lower_ast_to_ssa(fdef1, optimize=False)
        ssa1_opt = lower_ast_to_ssa(fdef1, optimize=True)
        self.assertEqual(ssa1_opt.return_type, "f64")
        self.assertEqual(ssa1_opt.param_types, {"n": "i64", "scale": "f64"})

        res_llvm1 = btv.verify_ssa_to_llvm_ir(ssa1_opt, LLVMBackend().ssa_to_llvm_ir(ssa1_opt))
        self.assertTrue(res_llvm1["proven"], f"Loop LLVM float TV failed: {res_llvm1}")
        res_wat1 = btv.verify_ssa_to_wat(ssa1_opt, WasmBackend().ssa_to_wat(ssa1_opt))
        self.assertTrue(res_wat1["proven"], f"Loop WAT float TV failed: {res_wat1}")

        def py_h(n: int, scale: float) -> float:
            acc = 0.0
            for i in range(1, n + 1):
                acc = acc + (scale / float(i))
            return acc

        vecs1 = [(0, 2.0), (1, 3.5), (5, 1.25), (8, -4.0)]
        diff1 = btv.verify_differential_execution(ssa1_opt, vecs1)
        self.assertTrue(diff1["equivalent"], f"Loop f64 diff parity failed: {diff1}")
        for got, exp in zip(diff1["outputs_by_backend"]["native"], [py_h(n, s) for n, s in vecs1]):
            self.assertEqual(_f64_to_u64(got), _f64_to_u64(exp))

        # Bounded Z3 QF_FP check across optimization for loop
        ssa_tv = SSATranslationValidator(
            enable_float_theory=True,
            max_loop_unroll=4,
            enable_inductive_loops=False,
        )
        res_u = ssa_tv.verify_equivalence(ssa1_raw, ssa1_opt, timeout_ms=10000)
        self.assertTrue(res_u["proven"], f"Bounded QF_FP loop TV failed: {res_u}")

        # Mixed float accumulation returning truncated signed i64 via fptosi
        fdef2 = ast.parse(src_loop_i64).body[0]
        ssa2 = lower_ast_to_ssa(fdef2, optimize=True)
        self.assertEqual(ssa2.return_type, "i64")
        self.assertEqual(ssa2.param_types, {"n": "i64", "base": "f64"})

        res_llvm2 = btv.verify_ssa_to_llvm_ir(ssa2, LLVMBackend().ssa_to_llvm_ir(ssa2))
        self.assertTrue(res_llvm2["proven"], f"fptosi LLVM TV failed: {res_llvm2}")
        res_wat2 = btv.verify_ssa_to_wat(ssa2, WasmBackend().ssa_to_wat(ssa2))
        self.assertTrue(res_wat2["proven"], f"fptosi WAT TV failed: {res_wat2}")

        def py_r(n: int, base: float) -> int:
            acc = base
            i = 0
            while i < n:
                acc += float(i) * 0.5
                i += 1
            return int(acc * 100.0)

        vecs2 = [(0, -3.25), (4, 1.125), (7, -10.5)]
        diff2 = btv.verify_differential_execution(ssa2, vecs2)
        self.assertTrue(diff2["equivalent"], f"fptosi diff parity failed: {diff2}")
        self.assertEqual(diff2["outputs_by_backend"]["native"], [py_r(n, b) for n, b in vecs2])

    def test_polyglot_f64_rust_go_ts_js_and_c27_compat(self):
        rs_src = """
        pub fn rs_affine(x: f64, y: f64) -> f64 {
            let z: f64 = x * 2.5 - y;
            if z < 0.0 {
                return -z;
            }
            z + 1.25
        }
        """
        go_src = """
        package calc
        func go_blend(a, b float64) float64 {
            if a <= b {
                return a * 1.5 + b * 0.5
            }
            return a - b * 0.25
        }
        """
        ts_src = """
        export const ts_clamp = (x: f64, lo: f64, hi: f64): double => {
            if (x < lo) { return lo; }
            if (x > hi) { return hi; }
            return x * 1.0;
        };
        """
        js_src = """
        function js_lerp(a, b) {
            return a + (b - a) * 0.25;
        }
        """

        btv = BackendTranslationValidator(enable_float_theory=True)

        # Rust auto-detects f64 annotations
        rs_mod = lower_polyglot_source_to_ast(rs_src, "rust", strict=True)
        rs_ssa = lower_ast_to_ssa(rs_mod.functions[0], optimize=True)
        self.assertEqual(rs_ssa.return_type, "f64")
        self.assertEqual(rs_ssa.param_types, {"x": "f64", "y": "f64"})
        self.assertTrue(btv.verify_ssa_to_llvm_ir(rs_ssa, LLVMBackend().ssa_to_llvm_ir(rs_ssa))["proven"])
        self.assertTrue(btv.verify_ssa_to_wat(rs_ssa, WasmBackend().ssa_to_wat(rs_ssa))["proven"])
        rs_vecs = [(1.0, 5.0), (4.0, 2.0), (-3.5, -1.0)]
        rs_diff = btv.verify_differential_execution(rs_ssa, rs_vecs)
        self.assertTrue(rs_diff["equivalent"], f"Rust f64 diff failed: {rs_diff}")
        rs_exp = [
            abs(x * 2.5 - y) if (x * 2.5 - y) < 0.0 else (x * 2.5 - y) + 1.25
            for x, y in rs_vecs
        ]
        for got, exp in zip(rs_diff["outputs_by_backend"]["native"], rs_exp):
            self.assertEqual(_f64_to_u64(got), _f64_to_u64(exp))

        # Go grouped float64 params & return
        go_mod = lower_polyglot_source_to_ast(go_src, "go", strict=True)
        go_ssa = lower_ast_to_ssa(go_mod.functions[0], optimize=True)
        self.assertEqual(go_ssa.return_type, "f64")
        self.assertEqual(go_ssa.param_types, {"a": "f64", "b": "f64"})
        self.assertTrue(btv.verify_ssa_to_llvm_ir(go_ssa, LLVMBackend().ssa_to_llvm_ir(go_ssa))["proven"])
        self.assertTrue(btv.verify_ssa_to_wat(go_ssa, WasmBackend().ssa_to_wat(go_ssa))["proven"])
        go_vecs = [(1.0, 4.0), (5.0, 2.0), (-2.0, -2.0)]
        go_diff = btv.verify_differential_execution(go_ssa, go_vecs)
        self.assertTrue(go_diff["equivalent"], f"Go float64 diff failed: {go_diff}")
        go_exp = [
            (a * 1.5 + b * 0.5) if a <= b else (a - b * 0.25)
            for a, b in go_vecs
        ]
        for got, exp in zip(go_diff["outputs_by_backend"]["native"], go_exp):
            self.assertEqual(_f64_to_u64(got), _f64_to_u64(exp))

        # TS arrow f64 + double
        ts_mod = lower_polyglot_source_to_ast(ts_src, "typescript", strict=True)
        ts_ssa = lower_ast_to_ssa(ts_mod.functions[0], optimize=True)
        self.assertEqual(ts_ssa.return_type, "f64")
        ts_vecs = [(-5.0, 0.0, 10.0), (15.0, 0.0, 10.0), (3.75, 0.0, 10.0)]
        ts_diff = btv.verify_differential_execution(ts_ssa, ts_vecs)
        self.assertTrue(ts_diff["equivalent"], f"TS double diff failed: {ts_diff}")
        for got, exp in zip(ts_diff["outputs_by_backend"]["native"], [0.0, 10.0, 3.75]):
            self.assertEqual(_f64_to_u64(got), _f64_to_u64(exp))

        # JS untyped float with explicit allow_floats=True
        js_mod = lower_polyglot_source_to_ast(js_src, "javascript", strict=True, allow_floats=True)
        js_ssa = lower_ast_to_ssa(js_mod.functions[0], optimize=True)
        self.assertEqual(js_ssa.return_type, "f64")
        js_diff = btv.verify_differential_execution(js_ssa, [(2.0, 10.0), (-4.0, 4.0)])
        self.assertTrue(js_diff["equivalent"], f"JS allow_floats diff failed: {js_diff}")
        for got, exp in zip(js_diff["outputs_by_backend"]["native"], [4.0, -2.0]):
            self.assertEqual(_f64_to_u64(got), _f64_to_u64(exp))

        # C27 strict backward-compatibility guard: unannotated float literal fails closed by default
        with self.assertRaises(PolyglotLoweringError):
            lower_polyglot_source_to_ast("function bad(x) { return 3.14; }", "javascript", strict=True)

    @unittest.skipUnless(UNICORN_AVAILABLE, "Unicorn required for ARM64 physical VFP execution")
    def test_arm64_vfp_f64_physical_unicorn_execution(self):
        src = """
def arm_mix(n: int, x: float, y: float) -> float:
    base = float(n) * 0.5 + x * y
    if base < 0.0:
        return -base + 1.5
    return base / 2.0
"""
        fdef = ast.parse(src).body[0]
        ssa_fn = lower_ast_to_ssa(fdef, optimize=True)
        arm_cg = NativeCodeGenerator(arch="arm64")
        arm_artifact = arm_cg.compile_ssa(ssa_fn)
        arm_bytes = arm_artifact.code_bytes
        self.assertGreater(len(arm_bytes), 0)

        def py_arm(n: int, x: float, y: float) -> float:
            base = float(n) * 0.5 + x * y
            if base < 0.0:
                return -base + 1.5
            return base / 2.0

        for n, x, y in [(4, 3.0, 2.5), (-10, 1.0, 2.0), (0, -2.5, 4.0)]:
            got = _emulate_arm64_f64(arm_bytes, [n, x, y], ["i64", "f64", "f64"])
            exp = py_arm(n, x, y)
            self.assertEqual(_f64_to_u64(got), _f64_to_u64(exp), f"ARM64 VFP mismatch: got={got}, exp={exp}")

    def test_z3_qffp_non_associativity_and_mutation_refutation(self):
        # IEEE-754 float addition is NON-associative: (a + b) + c != a + (b + c)
        def make_assoc_fn(left_assoc: bool) -> SSAFunction:
            fn = SSAFunction("assoc", ["a", "b", "c"], param_types={"a": "f64", "b": "f64", "c": "f64"}, return_type="f64")
            bb = BasicBlock("entry")
            fn.add_block(bb)
            fn.entry_block = bb
            va, vb, vc = SSAVar("a", 0, var_type="f64"), SSAVar("b", 0, var_type="f64"), SSAVar("c", 0, var_type="f64")
            bb.add_instruction(SSAInstruction(va, "param", ["a"]))
            bb.add_instruction(SSAInstruction(vb, "param", ["b"]))
            bb.add_instruction(SSAInstruction(vc, "param", ["c"]))
            t1 = SSAVar("t", 1, var_type="f64")
            t2 = SSAVar("t", 2, var_type="f64")
            if left_assoc:
                bb.add_instruction(SSAInstruction(t1, "fadd", [va, vb]))
                bb.add_instruction(SSAInstruction(t2, "fadd", [t1, vc]))
            else:
                bb.add_instruction(SSAInstruction(t1, "fadd", [vb, vc]))
                bb.add_instruction(SSAInstruction(t2, "fadd", [va, t1]))
            bb.add_instruction(SSAInstruction(None, "ret", [t2]))
            return fn

        tv = SSATranslationValidator(enable_float_theory=True)
        res_non_assoc = tv.verify_equivalence(make_assoc_fn(True), make_assoc_fn(False), timeout_ms=8000)
        self.assertFalse(res_non_assoc["proven"])
        self.assertEqual(res_non_assoc["status"], "REFUTED_COUNTEREXAMPLE")

        # LLVM mutation detection (change 1.5 -> 2.5 constant in LLVM IR)
        fdef = ast.parse("def k(x: float) -> float:\n    return x * 1.5 + 0.5\n").body[0]
        ssa_fn = lower_ast_to_ssa(fdef, optimize=True)
        llvm_ir = LLVMBackend().ssa_to_llvm_ir(ssa_fn)
        hx_old = f"0x{_f64_to_u64(1.5):016x}"
        hx_new = f"0x{_f64_to_u64(2.5):016x}"
        self.assertIn(hx_old, llvm_ir)
        mutated_ir = llvm_ir.replace(hx_old, hx_new, 1)

        btv = BackendTranslationValidator(enable_float_theory=True)
        res_bad = btv.verify_ssa_to_llvm_ir(ssa_fn, mutated_ir)
        self.assertFalse(res_bad["proven"])
        self.assertEqual(res_bad["status"], "REFUTED_COUNTEREXAMPLE")


if __name__ == "__main__":
    unittest.main()
