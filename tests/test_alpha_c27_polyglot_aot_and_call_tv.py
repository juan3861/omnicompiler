"""
Alpha-C27 Comprehensive Verification Suite:
1. True Polyglot AOT Lowering (JavaScript, TypeScript, Rust, Go -> Python AST -> Omni-SSA)
   with physical bit-exact differential execution across Native x86-64 JIT, LLVM O3, and Wasmtime.
2. Fail-closed diagnostics (`PolyglotLoweringError`) on unsupported syntax outside integer AOT subset.
3. Call Congruence in `SSATranslationValidator(enable_call_congruence=True)` + `call` lifting in
   `LLVMIRToSSALifter` and `WATToSSALifter` (`BackendTranslationValidator`) with counterexample refutation.
4. End-to-end 4-language multi-repo fusion via `OmniRepoCompiler.compile_repositories(...)`
   (Go + Rust + TypeScript + Python -> Native shared library executed via ctypes + valid `.wasm`).
5. `VLASimdEngine` target ISA vector metadata (`vla_simd_metadata`) wired into `codegen` telemetry.
"""

import ast
import ctypes
import os
import platform
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.llvm_backend import LLVMBackend
from compiler.ssa_ir import BasicBlock, SSAFunction, SSAInstruction, SSAVar, lower_ast_to_ssa
from compiler.wasm_backend import WasmBackend
from frontends.polyglot_ssa_lowering import PolyglotLoweringError, lower_polyglot_source_to_ast
from omni_repo_compiler import OmniRepoCompiler
from orchestrator.repo_manifest_ingestor import RepoManifestIngestor
from validation.backend_translation_validator import BackendTranslationValidator
from validation.ssa_translation_validator import SSATranslationValidator


def _as_i64(val: int) -> int:
    val &= (1 << 64) - 1
    if val >= (1 << 63):
        val -= 1 << 64
    return val


class TestAlphaC27PolyglotAndCallTV(unittest.TestCase):
    def test_polyglot_js_ts_rust_go_lowering_and_differential_jit(self):
        js_src = """
        // JavaScript weighted sum loop with break/continue & ternary
        function js_acc_mix(n, seed) {
            let acc = seed ^ 0x13;
            for (let i = 0; i < n; i++) {
                if (i == 3) {
                    continue;
                }
                acc = acc + (i * 3) + (i & 1 ? 5 : 1);
            }
            return acc;
        }
        """
        ts_src = """
        export function ts_bit_kernel(a: number, b: number): number {
            const x: number = (a << 2) ^ (b >> 1);
            let y: number = x > 10 ? x - 7 : x + 11;
            return (y * 5) | 1;
        }
        """
        rs_src = """
        pub fn rs_sum_inclusive(lo: i64, hi: i64) -> i64 {
            let mut total: i64 = 0;
            for k in lo..=hi {
                total += k * 2 + 1;
            }
            total
        }
        """
        go_src = """
        package main
        func go_while_accum(n int64, bias int64) int64 {
            acc := bias
            cur := n
            for cur > 0 {
                if (cur % 2) == 0 {
                    acc += cur * 4
                } else {
                    acc -= cur
                }
                cur -= 1
            }
            return acc
        }
        """

        tv = BackendTranslationValidator()

        # 1. JS -> SSA -> Differential Native/LLVM/Wasmtime
        js_ast = lower_polyglot_source_to_ast(js_src, "javascript", strict=True)
        self.assertEqual([f.name for f in js_ast.functions], ["js_acc_mix"])
        js_ssa = lower_ast_to_ssa(js_ast.functions[0], optimize=True)
        js_res = tv.verify_differential_execution(js_ssa, [(0, 4), (6, 10), (10, -3)])
        self.assertTrue(js_res["equivalent"], f"JS differential mismatch: {js_res}")
        self.assertEqual(js_res["outputs_by_backend"]["native"][1], _as_i64(
            (10 ^ 0x13) + sum(i * 3 + (5 if (i & 1) else 1) for i in range(6) if i != 3)
        ))

        # 2. TS -> SSA -> Formal LLVM/WAT TV + Differential Execution
        ts_ast = lower_polyglot_source_to_ast(ts_src, "typescript", strict=True)
        ts_ssa = lower_ast_to_ssa(ts_ast.functions[0], optimize=True)
        ts_llvm_ir = LLVMBackend().ssa_to_llvm_ir(ts_ssa)
        ts_wat = WasmBackend().ssa_to_wat(ts_ssa)
        self.assertTrue(tv.verify_ssa_to_llvm_ir(ts_ssa, ts_llvm_ir)["proven"])
        self.assertTrue(tv.verify_ssa_to_wat(ts_ssa, ts_wat)["proven"])
        ts_res = tv.verify_differential_execution(ts_ssa, [(5, 8), (-4, 9), (0, -20)])
        self.assertTrue(ts_res["equivalent"], f"TS differential mismatch: {ts_res}")

        # 3. Rust -> SSA -> Differential Execution (inclusive range + implicit tail expr)
        rs_ast = lower_polyglot_source_to_ast(rs_src, "rust", strict=True)
        rs_ssa = lower_ast_to_ssa(rs_ast.functions[0], optimize=True)
        rs_res = tv.verify_differential_execution(rs_ssa, [(1, 5), (-2, 3), (4, 2)])
        self.assertTrue(rs_res["equivalent"], f"Rust differential mismatch: {rs_res}")
        self.assertEqual(rs_res["outputs_by_backend"]["native"][0], sum(k * 2 + 1 for k in range(1, 6)))
        self.assertEqual(rs_res["outputs_by_backend"]["native"][2], 0)

        # 4. Go -> SSA -> Differential Execution
        go_ast = lower_polyglot_source_to_ast(go_src, "go", strict=True)
        go_ssa = lower_ast_to_ssa(go_ast.functions[0], optimize=True)
        go_res = tv.verify_differential_execution(go_ssa, [(5, 100), (0, 7), (12, -5)])
        self.assertTrue(go_res["equivalent"], f"Go differential mismatch: {go_res}")
        expected_go_0 = 100 + sum(c * 4 if c % 2 == 0 else -c for c in range(1, 6))
        self.assertEqual(go_res["outputs_by_backend"]["native"][0], expected_go_0)

    def test_polyglot_fail_closed_on_unsupported_syntax(self):
        with self.assertRaises(PolyglotLoweringError):
            lower_polyglot_source_to_ast("function bad(x) { return 3.14; }", "javascript", strict=True)

        with self.assertRaises(PolyglotLoweringError):
            lower_polyglot_source_to_ast("function bad(x) { return obj.method()(x); }", "typescript", strict=True)

        non_strict = lower_polyglot_source_to_ast(
            "fn good(x: i64) -> i64 { x + 1 }\nfn bad(x: i64) -> i64 { obj.m()(x) }",
            "rust",
            strict=False,
        )
        self.assertEqual([f.name for f in non_strict.functions], ["good"])
        self.assertTrue(len(non_strict.errors) >= 1)

    def test_call_congruence_and_backend_tv_llvm_wat(self):
        # Build SSA functions with pure callee invocation + algebraic operand reorder
        def make_caller_tree(src_py: str, fn_name: str) -> SSAFunction:
            mod = ast.parse(src_py)
            fdef = [n for n in mod.body if isinstance(n, ast.FunctionDef) and n.name == fn_name][0]
            return lower_ast_to_ssa(fdef, optimize=False)

        fn_before = make_caller_tree(
            "def caller(x, y):\n"
            "    if x > 0:\n"
            "        return helper(x + y) + 3\n"
            "    return helper(y + 1)\n",
            "caller",
        )
        fn_after_equiv = make_caller_tree(
            "def caller(x, y):\n"
            "    if x > 0:\n"
            "        return 3 + helper(y + x)\n"
            "    return helper(1 + y)\n",
            "caller",
        )
        fn_after_buggy_arg = make_caller_tree(
            "def caller(x, y):\n"
            "    if x > 0:\n"
            "        return 3 + helper(y - x)\n"
            "    return helper(1 + y)\n",
            "caller",
        )

        # Default validator preserves C24-C26 strictness (rejects call unless opted in)
        strict_tv = SSATranslationValidator(enable_call_congruence=False)
        res_strict = strict_tv.verify_equivalence(fn_before, fn_after_equiv)
        self.assertFalse(res_strict["proven"])

        # Call congruence enabled proves equivalence and catches argument/callee corruption
        call_tv = SSATranslationValidator(enable_call_congruence=True)
        res_ok = call_tv.verify_equivalence(fn_before, fn_after_equiv)
        self.assertTrue(res_ok["proven"], f"Expected congruent calls proven: {res_ok}")
        self.assertEqual(res_ok["status"], "PROVEN_EQUIVALENT")

        res_bad = call_tv.verify_equivalence(fn_before, fn_after_buggy_arg)
        self.assertFalse(res_bad["proven"])
        self.assertEqual(res_bad["status"], "REFUTED_COUNTEREXAMPLE")

        # Multi-function module containing calls lowers cleanly to LLVM IR & WAT and proves equivalent
        helper_ssa = make_caller_tree("def helper(v):\n    return (v * 3) ^ 5\n", "helper")
        llvm_ir = LLVMBackend().ssa_module_to_llvm_ir([helper_ssa, fn_before])
        wat_src = WasmBackend().ssa_module_to_wat([helper_ssa, fn_before])

        btv = BackendTranslationValidator(enable_call_congruence=True)
        v_llvm = btv.verify_ssa_to_llvm_ir(fn_before, llvm_ir)
        v_wat = btv.verify_ssa_to_wat(fn_before, wat_src)
        self.assertTrue(v_llvm["proven"], f"LLVM call TV failed: {v_llvm}")
        self.assertTrue(v_wat["proven"], f"WAT call TV failed: {v_wat}")

    def test_multi_repo_polyglot_omni_compiler_native_llvm_wasm(self):
        with tempfile.TemporaryDirectory() as tmp:
            go_dir = os.path.join(tmp, "repo_go")
            rs_dir = os.path.join(tmp, "repo_rs")
            ts_dir = os.path.join(tmp, "repo_ts")
            py_dir = os.path.join(tmp, "repo_py")
            for d in (go_dir, rs_dir, ts_dir, py_dir):
                os.makedirs(d, exist_ok=True)

            with open(os.path.join(go_dir, "math_core.go"), "w", encoding="utf-8") as f:
                f.write("package mathcore\nfunc go_scale(x int64) int64 {\n    return (x * 4) + 3\n}\n")
            with open(os.path.join(rs_dir, "kernel.rs"), "w", encoding="utf-8") as f:
                f.write("pub fn rs_step(x: i64) -> i64 {\n    (x ^ 7) + 2\n}\n")
            with open(os.path.join(ts_dir, "pipeline.ts"), "w", encoding="utf-8") as f:
                f.write(
                    "export function ts_poly_chain(n: number): number {\n"
                    "    let s: number = 0;\n"
                    "    for (let i: number = 1; i <= n; i++) {\n"
                    "        s += go_scale(i) + rs_step(i);\n"
                    "    }\n"
                    "    return s;\n"
                    "}\n"
                )
            with open(os.path.join(py_dir, "driver.py"), "w", encoding="utf-8") as f:
                f.write("def py_eval_chain(n: int) -> int:\n    return ts_poly_chain(n) + 10\n")

            # Verify RepoManifestIngestor sees Go, Rust, TypeScript, Python exports
            ingestor = RepoManifestIngestor()
            m_go = ingestor.ingest_repository(go_dir, "repo_go")
            m_rs = ingestor.ingest_repository(rs_dir, "repo_rs")
            m_ts = ingestor.ingest_repository(ts_dir, "repo_ts")
            self.assertEqual([e.language for e in m_go.exports], ["go"])
            self.assertEqual([e.language for e in m_rs.exports], ["rust"])
            self.assertEqual([e.language for e in m_ts.exports], ["typescript"])

            # Compile 4-repo polyglot project to shared library (.dll / .so) + .wasm
            ext = ".dll" if platform.system() == "Windows" else ".so"
            native_out = os.path.join(tmp, f"polyglot_fused{ext}")
            compiler = OmniRepoCompiler()
            res_native = compiler.compile_repositories(
                [go_dir, rs_dir, ts_dir, py_dir],
                native_out,
                target_format="shared_lib",
                target_os="windows" if platform.system() == "Windows" else "linux",
                target_arch="x86_64",
                export_all=True,
                backend="native",
            )
            self.assertTrue(res_native["success"], f"Polyglot native compile failed: {res_native}")
            self.assertGreaterEqual(res_native["stages"]["codegen"]["real_ast_functions_compiled"], 4)
            self.assertTrue(os.path.exists(native_out))

            lib = ctypes.CDLL(native_out)
            try:
                lib.py_eval_chain.argtypes = [ctypes.c_int64]
                lib.py_eval_chain.restype = ctypes.c_int64
                got = lib.py_eval_chain(4)
                expected = sum(((i * 4) + 3) + ((i ^ 7) + 2) for i in range(1, 5)) + 10
                self.assertEqual(got, expected)
            finally:
                if platform.system() == "Windows":
                    import _ctypes
                    _ctypes.FreeLibrary(lib._handle)

            # Also compile to WASM module
            wasm_out = os.path.join(tmp, "polyglot_fused.wasm")
            res_wasm = compiler.compile_repositories(
                [go_dir, rs_dir, ts_dir, py_dir],
                wasm_out,
                backend="wasm",
            )
            self.assertTrue(res_wasm["success"], f"Polyglot wasm compile failed: {res_wasm}")
            self.assertTrue(res_wasm["stages"]["wasm"]["valid_wasm_magic"])
            syms = set(res_wasm["stages"]["wasm"]["exported_symbols"])
            self.assertTrue({"go_scale", "rs_step", "ts_poly_chain", "py_eval_chain"}.issubset(syms))

    def test_vla_simd_engine_metadata_wired_into_codegen(self):
        with tempfile.TemporaryDirectory() as tmp:
            js_dir = os.path.join(tmp, "simd_repo")
            os.makedirs(js_dir, exist_ok=True)
            with open(os.path.join(js_dir, "vec_sum.js"), "w", encoding="utf-8") as f:
                f.write(
                    "function js_vec_loop(arr, n) {\n"
                    "    let acc = 0;\n"
                    "    for (let i = 0; i < n; i++) {\n"
                    "        acc += arr[i];\n"
                    "    }\n"
                    "    return acc;\n"
                    "}\n"
                )
            ext = ".dll" if platform.system() == "Windows" else ".so"
            out_path = os.path.join(tmp, f"simd_out{ext}")
            compiler = OmniRepoCompiler()
            res = compiler.compile_repositories([js_dir], out_path, backend="native")
            self.assertTrue(res["success"], f"Native SIMD compile failed: {res}")
            codegen = res["stages"]["codegen"]
            self.assertGreaterEqual(codegen["vectorized_loops"], 1)
            self.assertIsNotNone(codegen["vla_simd_metadata"])
            self.assertEqual(codegen["vla_simd_metadata"]["isa"], "AVX2_256")


if __name__ == "__main__":
    unittest.main(verbosity=2)
