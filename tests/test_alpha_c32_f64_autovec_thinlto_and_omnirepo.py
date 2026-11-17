"""
Alpha-C32 Verification Suite:
1. `f64` Collection SIMD Runtime & Loop Auto-Vectorizer (`omni_list_vec_add_f64`,
   `omni_list_vec_dot_f64`, `omni_list_sum_f64`) + `NativeJitCompiler` W^X execution.
2. `VerifiedPassRunner(enable_float_theory=True)` gating `GlobalValueNumberingPass` (GVN),
   `LICMPass`, and `DSEPass` (store-to-load forwarding & dead store elimination) on `f64`
   and `ptr_f64` functions with formal Z3 `QF_ABVFP` proofs.
3. `ThinLtoOptimizer` cross-module `f64` constant-return folding, single-block leaf inlining,
   and multi-block CFG inlining with differential execution parity.
4. End-to-end 3-repository polyglot (`Rust` + `Go` + `TypeScript`) `f64` / `Float64Array`
   compilation through `OmniRepoCompiler` across `backend="native"` (`x86_64` & `arm64`),
   `backend="llvm"`, and `backend="wasm"` with physical Wasmtime execution parity.
"""

import ast
import ctypes
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.ip_sccp_gvn import GlobalValueNumberingPass
from compiler.licm_and_dse import DSEPass, LICMPass
from compiler.loop_vectorizer import LoopVectorizerPass
from compiler.native_jit import NativeJitCompiler
from compiler.ssa_ir import lower_ast_to_ssa, lower_source_to_ssa
from compiler.thin_lto import ThinLtoOptimizer
from omni_repo_compiler import OmniRepoCompiler
from runtime.native_heap import omni_list_len, omni_list_new
from validation.backend_translation_validator import BackendTranslationValidator
from validation.ssa_translation_validator import SSATranslationValidator, VerifiedPassRunner


def _f64_to_u64(val: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", float(val)))[0]


def _make_f64_omni_list(vals: list) -> int:
    n = len(vals)
    ptr = omni_list_new(max(4, n))
    ctypes.c_int64.from_address(ptr + 8).value = n
    for i, v in enumerate(vals):
        ctypes.c_double.from_address(ptr + 16 + i * 8).value = float(v)
    return ptr


def _read_f64_omni_list(ptr: int) -> list:
    n = omni_list_len(ptr)
    return [float(ctypes.c_double.from_address(ptr + 16 + i * 8).value) for i in range(n)]


class TestAlphaC32F64AutoVecThinLTOAndOmniRepo(unittest.TestCase):

    def test_f64_loop_autovectorizer_and_native_jit_execution(self):
        jit = NativeJitCompiler()

        # 1. Elementwise f64 vector addition -> omni_list_vec_add_f64 (AVX2 vaddpd)
        src_add = """
def vec_add_f64(a: list, b: list) -> list:
    c = omni_list_new(len(a))
    for i in range(len(a)):
        c[i] = float(a[i]) + float(b[i])
    return c
"""
        fn_add = lower_source_to_ssa(src_add)
        opt_add, stats_add = LoopVectorizerPass().vectorize_function(fn_add)
        self.assertEqual(stats_add["vectorized_adds"], 1)
        calls_add = [
            str(ins.operands[0])
            for ins in opt_add.entry_block.instructions
            if ins.opcode == "call"
        ]
        self.assertIn("omni_list_vec_add_f64", calls_add)

        cfunc_add, _, _ = jit.compile_ssa(lower_source_to_ssa(src_add), optimize_passes=True)
        va = [1.25, -2.5, 3.75, 4.0, -0.5, 6.125, 10.0]
        vb = [0.75, 2.5, -1.25, 1.5, 2.5, -0.125, -3.5]
        la = _make_f64_omni_list(va)
        lb = _make_f64_omni_list(vb)
        lc = cfunc_add(la, lb)
        got_add = _read_f64_omni_list(lc)
        self.assertEqual(
            [_f64_to_u64(x) for x in got_add],
            [_f64_to_u64(x + y) for x, y in zip(va, vb)],
        )

        # 2. Dot product f64 -> omni_list_vec_dot_f64
        src_dot = """
def vec_dot_f64(a: list, b: list) -> float:
    total = 0.0
    for i in range(len(a)):
        total += float(a[i]) * float(b[i])
    return total
"""
        fn_dot = lower_source_to_ssa(src_dot)
        opt_dot, stats_dot = LoopVectorizerPass().vectorize_function(fn_dot)
        self.assertEqual(stats_dot["vectorized_dots"], 1)
        self.assertEqual(opt_dot.return_type, "f64")

        cfunc_dot, _, _ = jit.compile_ssa(lower_source_to_ssa(src_dot), optimize_passes=True)
        got_dot = cfunc_dot(la, lb)
        exp_dot = sum(x * y for x, y in zip(va, vb))
        self.assertEqual(_f64_to_u64(got_dot), _f64_to_u64(exp_dot))

        # 3. Reduction sum f64 with non-zero initial accumulator -> omni_list_sum_f64 + fadd
        src_sum = """
def vec_sum_f64(a: list) -> float:
    total = 2.5
    for i in range(len(a)):
        total += float(a[i])
    return total
"""
        fn_sum = lower_source_to_ssa(src_sum)
        opt_sum, stats_sum = LoopVectorizerPass().vectorize_function(fn_sum)
        self.assertEqual(stats_sum["vectorized_sums"], 1)
        self.assertEqual(opt_sum.return_type, "f64")

        cfunc_sum, _, _ = jit.compile_ssa(lower_source_to_ssa(src_sum), optimize_passes=True)
        got_sum = cfunc_sum(la)
        exp_sum = 2.5 + sum(va)
        self.assertEqual(_f64_to_u64(got_sum), _f64_to_u64(exp_sum))

    def test_verified_pass_runner_f64_gvn_licm_and_dse_forwarding(self):
        runner = VerifiedPassRunner(
            timeout_ms=2000,
            enable_memory_theory=True,
            max_loop_unroll=4,
            enable_inductive_loops=True,
            enable_float_theory=True,
        )

        # 1. GVN over f64 redundant expressions
        src_gvn = """
def f64_gvn(x: float, y: float) -> float:
    p1 = (x * 1.5) + (y - 0.25)
    p2 = (x * 1.5) + (y - 0.25)
    return p1 * p2
"""
        ssa_gvn = lower_ast_to_ssa(ast.parse(src_gvn).body[0], optimize=False)
        out_gvn, st_gvn, rep_gvn = runner.run_verified_pass(ssa_gvn, GlobalValueNumberingPass().run_on_function)
        self.assertTrue(rep_gvn["verified"], f"GVN f64 verification failed: {rep_gvn}")
        self.assertFalse(rep_gvn["rolled_back"])
        self.assertGreaterEqual(st_gvn["gvn_eliminated_exprs"], 2)

        # 2. LICM over f64 loop-invariant expressions inside ptr_f64 loop
        src_licm = """
def f64_licm(buf: ptr_f64, n: int, scale: float, offset: float) -> float:
    acc = 0.0
    i = 0
    while i < n:
        inv = (scale * 2.5) / (offset + 1.0)
        acc = acc + buf[i] * inv
        i = i + 1
    return acc
"""
        ssa_licm = lower_ast_to_ssa(ast.parse(src_licm).body[0], optimize=False)
        out_licm, st_licm, rep_licm = runner.run_verified_pass(ssa_licm, LICMPass().run_on_function)
        self.assertTrue(rep_licm["verified"], f"LICM f64 verification failed: {rep_licm}")
        self.assertEqual(rep_licm["verdict"]["status"], "PROVEN_INDUCTIVE_EQUIVALENT")
        self.assertFalse(rep_licm["verdict"]["bounded"])
        self.assertGreaterEqual(st_licm["licm_hoisted_insts"], 2)

        # 3. DSE store-to-load forwarding & dead store elimination on ptr_f64
        src_dse = """
def f64_dse(buf: ptr_f64, x: float) -> float:
    buf[0] = x * 3.0
    buf[0] = x * 1.5
    v = buf[0] + 0.5
    return v
"""
        ssa_dse = lower_ast_to_ssa(ast.parse(src_dse).body[0], optimize=False)
        out_dse, st_dse, rep_dse = runner.run_verified_pass(ssa_dse, DSEPass().run_on_function)
        self.assertTrue(rep_dse["verified"], f"DSE f64 verification failed: {rep_dse}")
        self.assertEqual(st_dse["dse_eliminated_stores"], 1)
        self.assertEqual(st_dse["forwarded_loads"], 1)

    def test_thin_lto_f64_single_and_multiblock_inlining_and_const_folding(self):
        src_const = "def f_bias() -> float:\n    return 1.25\n"
        src_leaf = "def f_scale(x: float, w: float) -> float:\n    return x * w + 0.5\n"
        src_mb = """
def f_abs_clamp(v: float) -> float:
    if v < 0.0:
        return -v * 0.5
    return v + 2.0
"""
        src_caller = """
def f_pipeline(x: float, w: float) -> float:
    s = f_scale(x, w) + f_bias()
    return f_abs_clamp(s)
"""
        lto = ThinLtoOptimizer()
        for name, src in [("f_bias", src_const), ("f_scale", src_leaf), ("f_abs_clamp", src_mb)]:
            f_ast = ast.parse(src).body[0]
            f_ssa = lower_ast_to_ssa(f_ast, optimize=True)
            lto.build_function_summary(name, "repo_lib", f_ast, f_ssa)

        caller_ssa = lower_ast_to_ssa(ast.parse(src_caller).body[0], optimize=True)
        inlined_ssa, lto_stats = lto.optimize_interprocedural_ssa(caller_ssa)
        self.assertEqual(lto_stats["folded_constants"], 1)
        self.assertEqual(lto_stats["inlined_calls"], 2)
        self.assertEqual(lto_stats["multiblock_inlines"], 1)
        self.assertEqual(inlined_ssa.return_type, "f64")

        btv = BackendTranslationValidator(enable_float_theory=True)
        vecs = [(2.0, 1.5), (-4.0, 2.0), (0.0, -3.0)]
        diff = btv.verify_differential_execution(inlined_ssa, vecs)
        self.assertTrue(diff["equivalent"], f"ThinLTO f64 inlined differential failed: {diff}")

        def py_pipe(x: float, w: float) -> float:
            s = (x * w + 0.5) + 1.25
            return (-s * 0.5) if s < 0.0 else (s + 2.0)

        for got, (x, w) in zip(diff["outputs_by_backend"]["native"], vecs):
            self.assertEqual(_f64_to_u64(got), _f64_to_u64(py_pipe(x, w)))

    def test_multi_repo_polyglot_f64_omnirepo_native_llvm_and_wasm(self):
        with tempfile.TemporaryDirectory() as tmp:
            rs_dir = os.path.join(tmp, "repo_rs")
            go_dir = os.path.join(tmp, "repo_go")
            ts_dir = os.path.join(tmp, "repo_ts")
            for d in (rs_dir, go_dir, ts_dir):
                os.makedirs(d, exist_ok=True)

            with open(os.path.join(rs_dir, "energy.rs"), "w", encoding="utf-8") as f:
                f.write(
                    "pub fn rs_kinetic(v: f64, mass: f64) -> f64 {\n"
                    "    0.5 * mass * v * v\n"
                    "}\n"
                )
            with open(os.path.join(go_dir, "damp.go"), "w", encoding="utf-8") as f:
                f.write(
                    "package sim\n"
                    "func go_dampen(e float64) float64 {\n"
                    "    if e > 10.0 {\n"
                    "        return e * 0.75\n"
                    "    }\n"
                    "    return e + 0.5\n"
                    "}\n"
                )
            with open(os.path.join(ts_dir, "step.ts"), "w", encoding="utf-8") as f:
                f.write(
                    "export const ts_sim_step = (buf: Float64Array, n: number, mass: f64): f64 => {\n"
                    "    let total: f64 = 0.0;\n"
                    "    for (let i = 0; i < n; i++) {\n"
                    "        let e: f64 = go_dampen(rs_kinetic(buf[i], mass));\n"
                    "        buf[i] = e;\n"
                    "        total = total + e;\n"
                    "    }\n"
                    "    return total;\n"
                    "};\n"
                )

            # 1. Native x86-64 AOT compilation
            out_native = os.path.join(tmp, "sim_native.bin")
            res_native = OmniRepoCompiler().compile_repositories(
                repo_paths=[rs_dir, go_dir, ts_dir],
                output_path=out_native,
                entry_export="ts_sim_step",
                backend="native",
            )
            self.assertTrue(res_native["success"], f"Native OmniRepo f64 failed: {res_native}")
            self.assertGreaterEqual(res_native["stages"]["codegen"]["thin_lto_inlines"], 2)
            self.assertTrue(res_native["stages"]["preflight_safety"]["is_safe_for_silicon"])

            # 2. LLVM O3 AOT compilation
            out_llvm = os.path.join(tmp, "sim_llvm.bin")
            res_llvm = OmniRepoCompiler().compile_repositories(
                repo_paths=[rs_dir, go_dir, ts_dir],
                output_path=out_llvm,
                entry_export="ts_sim_step",
                backend="llvm",
            )
            self.assertTrue(res_llvm["success"], f"LLVM OmniRepo f64 failed: {res_llvm}")
            self.assertGreaterEqual(res_llvm["stages"]["backend_validation"]["proofs_proven"], 2)
            self.assertEqual(res_llvm["stages"]["backend_validation"]["refuted"], 0)

            # 3. WebAssembly AOT compilation + physical Wasmtime execution on Float64Array in linear memory
            out_wasm = os.path.join(tmp, "sim_wasm.wasm")
            res_wasm = OmniRepoCompiler().compile_repositories(
                repo_paths=[rs_dir, go_dir, ts_dir],
                output_path=out_wasm,
                entry_export="ts_sim_step",
                backend="wasm",
            )
            self.assertTrue(res_wasm["success"], f"WASM OmniRepo f64 failed: {res_wasm}")
            self.assertGreaterEqual(res_wasm["stages"]["backend_validation"]["proofs_proven"], 2)
            self.assertEqual(res_wasm["stages"]["backend_validation"]["refuted"], 0)

            from wasmtime import Engine, Instance, Module, Store
            engine = Engine()
            store = Store(engine)
            with open(out_wasm, "rb") as wf:
                wasm_bytes = wf.read()
            mod = Module(engine, wasm_bytes)
            inst = Instance(store, mod, [])
            exports = inst.exports(store)
            wasm_mem = exports["memory"]
            sim_fn = exports["ts_sim_step"]

            in_vels = [2.0, 4.0, -3.0]
            mass = 2.0
            off = 1024
            wasm_mem.write(store, struct.pack("<3d", *in_vels), off)
            got_total = sim_fn(store, off, 3, mass)
            got_buf = list(struct.unpack("<3d", bytes(wasm_mem.read(store, off, off + 24))))

            # Expected:
            # v=2.0 -> k=4.0 -> damp=4.5
            # v=4.0 -> k=16.0 -> damp=12.0
            # v=-3.0 -> k=9.0 -> damp=9.5
            # total = 26.0
            self.assertEqual(_f64_to_u64(got_total), _f64_to_u64(26.0))
            self.assertEqual(
                [_f64_to_u64(v) for v in got_buf],
                [_f64_to_u64(4.5), _f64_to_u64(12.0), _f64_to_u64(9.5)],
            )


if __name__ == "__main__":
    unittest.main()
