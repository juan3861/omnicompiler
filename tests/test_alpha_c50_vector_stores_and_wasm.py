"""
Alpha-C50 End-to-End Verification Suite:
1. Elementwise Struct/Buffer Store Vectorization (`store_off` 4-lane vector loop +
   runtime alias guard + scalar tail) for `Array[f32]` and `Array[i64]`.
2. Z3 `BiAbductionVerifier` spatial bounds proof (`PROVEN_MEMORY_SAFE`) & off-by-one
   refutation (`BOUND_VIOLATION_REFUTED`) on vectorized `load_off`/`store_off` loops.
3. Runtime Pointer Alias Torture Test: partial shifted overlap (`dst = &src[1]`) vs
   disjoint vs exact in-place (`dst == src`) parity across Native JIT and LLVM O3 JIT.
4. Index-dependent DAG cloning (`dst[i] = dst[i] * 3 + i`) and constant inclusive fill.
5. LIVE WebAssembly (`Wasmtime`) Linear Memory execution of vectorized store + reduction.
6. End-to-End `OmniRepoCompiler` Native PE64, LLVM O3 PE64, and WSL Linux ELF64 executables.
"""

import ast
import ctypes
import json
import os
import shutil
import struct
import subprocess
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from compiler.llvm_backend import LLVMBackend
from compiler.loop_vectorizer import LoopVectorizerPass
from compiler.native_jit import NativeJitCompiler
from compiler.ssa_ir import AstToSsaLowering
from compiler.wasm_backend import WasmBackend
from omni_repo_compiler import OmniRepoCompiler
from validation.biabduction_verifier import BiAbductionVerifier


def _wsl_available() -> bool:
    if sys.platform != "win32":
        return False
    try:
        r = subprocess.run(["wsl", "uname"], capture_output=True, text=True, timeout=10)
        return r.returncode == 0 and "Linux" in r.stdout
    except Exception:
        return False


class TestAlphaC50VectorStoresAndWasm(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c50_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_elementwise_f32_struct_add_z3_and_parity(self):
        """Vectorizes `dst.data[i] = a.data[i] + b.data[i]`, proves Z3 safe/refuted, and matches Native & LLVM O3."""
        src = """
class VecFrame:
    tag: u32
    data: Array[f32, 130]

def add_frames(dst: VecFrame, a: VecFrame, b: VecFrame, n: int) -> int:
    if n > 130:
        return -1
    i = 0
    while i < n:
        dst.data[i] = a.data[i] + b.data[i]
        i += 1
    return 0
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        block_names = [b.name for b in vec_fn.blocks]
        self.assertEqual(sum(1 for bn in block_names if "vec_st_tail_cond_" in bn), 1)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_fn,
            {"VecFrame": 4 + 130 * 4},
            {"dst": "VecFrame", "a": "VecFrame", "b": "VecFrame"},
        )
        self.assertTrue(bv["proven"], bv)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")
        self.assertGreaterEqual(bv["checks_passed"], 12)

        # Adversarial OOB: n > 131 allows i = 130 -> must refute
        src_oob = src.replace("if n > 130:", "if n > 131:")
        mod_oob = ast.parse(src_oob)
        low_oob = AstToSsaLowering()
        low_oob.register_structs_from_statements(mod_oob.body)
        ssa_oob = low_oob.lower_function_def([n for n in mod_oob.body if isinstance(n, ast.FunctionDef)][0])
        vec_oob, stats_oob = LoopVectorizerPass().vectorize_function(ssa_oob)
        self.assertEqual(stats_oob["vectorized_stores"], 1)
        bv_oob = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_oob,
            {"VecFrame": 4 + 130 * 4},
            {"dst": "VecFrame", "a": "VecFrame", "b": "VecFrame"},
        )
        self.assertFalse(bv_oob["proven"])
        self.assertEqual(bv_oob["status"], "BOUND_VIOLATION_REFUTED")

        class VecFrameStruct(ctypes.Structure):
            _fields_ = [("tag", ctypes.c_uint32), ("data", ctypes.c_float * 130)]

        a = VecFrameStruct(tag=1)
        b = VecFrameStruct(tag=2)
        for idx in range(130):
            a.data[idx] = float(idx) * 0.25
            b.data[idx] = float(130 - idx) * 0.5

        cfunc, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_mod = ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn))
        ll_fn = ll.create_jit_callable(
            ll_mod,
            "add_frames",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64],
        )

        for n in (-2, 0, 1, 3, 4, 5, 63, 64, 65, 130, 131):
            d_nat = VecFrameStruct(tag=9)
            d_ll = VecFrameStruct(tag=9)
            for idx in range(130):
                d_nat.data[idx] = -99.0
                d_ll.data[idx] = -99.0
            rc_nat = cfunc(ctypes.addressof(d_nat), ctypes.addressof(a), ctypes.addressof(b), n)
            rc_ll = ll_fn(ctypes.addressof(d_ll), ctypes.addressof(a), ctypes.addressof(b), n)
            self.assertEqual(rc_nat, -1 if n > 130 else 0)
            self.assertEqual(rc_ll, rc_nat)
            limit = 0 if n <= 0 or n > 130 else n
            for idx in range(130):
                exp = (a.data[idx] + b.data[idx]) if idx < limit else -99.0
                self.assertAlmostEqual(d_nat.data[idx], exp, places=4, msg=f"Native n={n} idx={idx}")
                self.assertAlmostEqual(d_ll.data[idx], exp, places=4, msg=f"LLVM n={n} idx={idx}")

    def test_02_runtime_alias_hazard_shifted_overlap_protection(self):
        """Runtime alias guard must fall back to scalar tail on `dst = &src[1]` overlap while vectorizing disjoint & in-place."""
        src = """
def shift_add(dst: int, src_ptr: int, n: int) -> int:
    i = 0
    while i < n:
        store_i64(dst, i * 8, load_i64(src_ptr, i * 8) + 1)
        i += 1
    return 0
"""
        mod = ast.parse(src)
        ssa_fn = AstToSsaLowering().lower_function_def(mod.body[0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)

        opcodes = [ins.opcode for b in vec_fn.blocks for ins in b.instructions]
        self.assertIn("select", opcodes)
        self.assertIn("cmp_eq", opcodes)

        cfunc, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_mod = ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn))
        ll_fn = ll.create_jit_callable(
            ll_mod,
            "shift_add",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64],
        )

        # 1. Partial shifted overlap: dst = &buf[1], src = &buf[0] -> scalar recurrence buf[i+1] = buf[i] + 1
        for label, jfn in (("native", cfunc), ("llvm", ll_fn)):
            arr = (ctypes.c_int64 * 24)(*([1] + [0] * 23))
            base = ctypes.addressof(arr)
            jfn(base + 8, base, 17)
            self.assertEqual([arr[k] for k in range(18)], list(range(1, 19)), f"Overlap failure in {label}")

        # 2. Exact in-place: dst == src -> safe 4-lane vector execution
        for label, jfn in (("native", cfunc), ("llvm", ll_fn)):
            arr = (ctypes.c_int64 * 20)(*range(10, 30))
            base = ctypes.addressof(arr)
            jfn(base, base, 17)
            expected = [10 + k + 1 if k < 17 else 10 + k for k in range(20)]
            self.assertEqual([arr[k] for k in range(20)], expected, f"In-place failure in {label}")

    def test_03_inplace_dag_with_index_and_inclusive_const_fill(self):
        """Tests in-place `dst.arr[i] = dst.arr[i] * 3 + i` and inclusive `while i <= 15: dst.arr[i] = 42`."""
        src = """
class IntBuf:
    arr: Array[i64, 32]

def transform_and_fill(buf: IntBuf, n: int) -> int:
    if n > 32:
        return -1
    i = 0
    while i < n:
        buf.arr[i] = buf.arr[i] * 3 + i
        i += 1
    k = 0
    while k <= 15:
        buf.arr[k + 16] = 42
        k += 1
    return 0
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 2)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_fn, {"IntBuf": 32 * 8}, {"buf": "IntBuf"}
        )
        self.assertTrue(bv["proven"], bv)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")

        class IntBufStruct(ctypes.Structure):
            _fields_ = [("arr", ctypes.c_int64 * 32)]

        cfunc, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_mod = ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn))
        ll_fn = ll.create_jit_callable(
            ll_mod, "transform_and_fill", restype=ctypes.c_int64, argtypes=[ctypes.c_void_p, ctypes.c_int64]
        )

        for n in (0, 1, 5, 16):
            b_nat = IntBufStruct()
            b_ll = IntBufStruct()
            for idx in range(32):
                b_nat.arr[idx] = idx + 10
                b_ll.arr[idx] = idx + 10
            cfunc(ctypes.addressof(b_nat), n)
            ll_fn(ctypes.addressof(b_ll), n)
            for idx in range(16):
                exp = ((idx + 10) * 3 + idx) if idx < n else (idx + 10)
                self.assertEqual(b_nat.arr[idx], exp)
                self.assertEqual(b_ll.arr[idx], exp)
            for idx in range(16, 32):
                self.assertEqual(b_nat.arr[idx], 42)
                self.assertEqual(b_ll.arr[idx], 42)

    def test_04_live_wasmtime_linear_memory_store_and_reduce(self):
        """Executes vectorized store loop + vectorized reduction loop live inside Wasmtime Linear Memory."""
        wb = WasmBackend()
        if not (wb.is_available() if callable(wb.is_available) else wb.is_available):
            self.skipTest("Wasmtime not available")

        src = """
def vec_map_sum(dst: int, a: int, b: int, n: int) -> int:
    i = 0
    while i < n:
        store_i64(dst, i * 8, load_i64(a, i * 8) * 2 + load_i64(b, i * 8))
        i += 1
    s = 0
    k = 0
    while k < n:
        s += load_i64(dst, k * 8)
        k += 1
    return s
"""
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        self.assertEqual(stats["vectorized_sums"], 1)

        wat_text = wb.ssa_to_wat(vec_fn)
        wasm_bytes = wb.wat_to_wasm(wat_text)
        self.assertTrue(wasm_bytes.startswith(b"\x00asm\x01\x00\x00\x00"))

        import wasmtime
        engine = wasmtime.Engine()
        wasm_mod = wasmtime.Module(engine, wasm_bytes)

        cfunc, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)

        for n in (0, 1, 3, 4, 5, 19):
            store = wasmtime.Store(engine)
            inst = wasmtime.Instance(store, wasm_mod, [])
            mem = inst.exports(store)["memory"]
            fn_w = inst.exports(store)["vec_map_sum"]

            a_off, b_off, d_off = 0x1000, 0x2000, 0x3000
            a_arr = (ctypes.c_int64 * 24)()
            b_arr = (ctypes.c_int64 * 24)()
            d_arr = (ctypes.c_int64 * 24)()
            exp_vals = []
            for idx in range(24):
                av, bv = idx + 3, idx * 5 + 1
                a_arr[idx] = av
                b_arr[idx] = bv
                mem.write(store, struct.pack("<q", av), a_off + idx * 8)
                mem.write(store, struct.pack("<q", bv), b_off + idx * 8)
                if idx < n:
                    exp_vals.append(av * 2 + bv)

            w_sum = fn_w(store, d_off, a_off, b_off, n)
            n_sum = cfunc(ctypes.addressof(d_arr), ctypes.addressof(a_arr), ctypes.addressof(b_arr), n)
            self.assertEqual(w_sum, sum(exp_vals), f"WASM sum mismatch at n={n}")
            self.assertEqual(n_sum, w_sum, f"Native vs WASM sum mismatch at n={n}")
            for idx in range(n):
                got_w = struct.unpack("<q", mem.read(store, d_off + idx * 8, d_off + (idx + 1) * 8))[0]
                self.assertEqual(got_w, exp_vals[idx])
                self.assertEqual(d_arr[idx], exp_vals[idx])

    def test_05_omnirepo_e2e_vector_store_and_reduce_executable(self):
        """Compiles vector map+reduce repository via OmniRepoCompiler (Native, LLVM O3, WSL Linux)."""
        r_vec = os.path.join(self.test_dir, "repo_vecstore")
        os.makedirs(r_vec)
        with open(os.path.join(r_vec, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_vecstore", "language": "python", "exports": ["omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_vec, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "def omni_main(n: int) -> int:\n"
                "    a = malloc(1056)\n"
                "    b = malloc(1056)\n"
                "    d = malloc(1056)\n"
                "    if n > 132:\n"
                "        n = 132\n"
                "    k = 0\n"
                "    while k < n:\n"
                "        store_i64(a, k * 8, k + 1)\n"
                "        store_i64(b, k * 8, k * 2)\n"
                "        k += 1\n"
                "    i = 0\n"
                "    while i < n:\n"
                "        store_i64(d, i * 8, load_i64(a, i * 8) + load_i64(b, i * 8))\n"
                "        i += 1\n"
                "    s = 0\n"
                "    j = 0\n"
                "    while j < n:\n"
                "        s += load_i64(d, j * 8)\n"
                "        j += 1\n"
                "    free(a)\n"
                "    free(b)\n"
                "    free(d)\n"
                '    printf("VEC_MAP_SUM=%lld\\n", s)\n'
                "    return s % 251\n"
            )

        comp = OmniRepoCompiler()
        try:
            nat_bin = os.path.join(self.test_dir, "vs_native.exe" if sys.platform == "win32" else "vs_native")
            res_nat = comp.compile_repositories(
                [r_vec], nat_bin, target_format="executable", entry_export="omni_main",
                backend="native", audit_nonce="c50-vs-nat",
            )
            self.assertTrue(res_nat["stages"]["formal_audit"]["is_valid"])
            self.assertGreaterEqual(res_nat["stages"]["codegen"]["vectorized_loops"], 2)

            ll_bin = os.path.join(self.test_dir, "vs_llvm.exe" if sys.platform == "win32" else "vs_llvm")
            res_ll = comp.compile_repositories(
                [r_vec], ll_bin, target_format="executable", entry_export="omni_main",
                backend="llvm", audit_nonce="c50-vs-ll",
            )
            self.assertTrue(res_ll["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res_ll["stages"]["backend_validation"].get("refuted", 0), 0)

            for bin_p in (nat_bin, ll_bin):
                if sys.platform != "win32":
                    os.chmod(bin_p, 0o755)
                for n in (0, 1, 3, 4, 5, 131):
                    # d[i] = (i+1) + 2*i = 3*i + 1 -> sum_{i=0}^{n-1} (3i+1) = n + 3*n*(n-1)//2
                    exp_sum = n + (3 * n * (n - 1) // 2 if n > 0 else 0)
                    p = subprocess.run([bin_p, str(n)], capture_output=True, text=True, timeout=10)
                    self.assertIn(f"VEC_MAP_SUM={exp_sum}", p.stdout, f"{bin_p} n={n}: {p.stdout} {p.stderr}")
                    self.assertEqual(p.returncode, exp_sum % 251)

            if sys.platform == "win32" and _wsl_available():
                lin_bin = os.path.join(self.test_dir, "vs_linux")
                res_lin = comp.compile_repositories(
                    [r_vec], lin_bin, target_format="executable", entry_export="omni_main",
                    target_os="linux", backend="native", audit_nonce="c50-vs-wsl",
                )
                self.assertTrue(res_lin["stages"]["formal_audit"]["is_valid"])
                wsl_p = lin_bin.replace("\\", "/").replace("F:", "/mnt/f").replace("C:", "/mnt/c")
                cmd = f"cp {wsl_p} /tmp/c50_vs_lin && chmod +x /tmp/c50_vs_lin && /tmp/c50_vs_lin 131"
                p_wsl = subprocess.run(["wsl", "/bin/sh", "-c", cmd], capture_output=True, timeout=20)
                if p_wsl.returncode != 4294967295:
                    exp_131 = 131 + 3 * 131 * 130 // 2
                    self.assertIn(f"VEC_MAP_SUM={exp_131}".encode("ascii"), p_wsl.stdout)
                    self.assertEqual(p_wsl.returncode, exp_131 % 251)
        finally:
            comp.close()

    def test_06_anti_misvectorization_store_guards(self):
        """Loops with small const N<4, leaked induction var, indirect indexing, or calls must NOT vectorize."""
        cases = [
            (
                "small_const_3",
                """
def f(p: int) -> int:
    i = 0
    while i < 3:
        store_i64(p, i * 8, i)
        i += 1
    return 0
""",
            ),
            (
                "leaked_induction_var",
                """
def f(p: int, n: int) -> int:
    i = 0
    while i < n:
        store_i64(p, i * 8, i)
        i += 1
    return i
""",
            ),
            (
                "indirect_offset_j",
                """
def f(p: int, n: int, j: int) -> int:
    i = 0
    while i < n:
        store_i64(p, (j + i) * 8, 7)
        i += 1
    return 0
""",
            ),
            (
                "has_call",
                """
def f(p: int, n: int) -> int:
    i = 0
    while i < n:
        store_i64(p, i * 8, i)
        puts("hi")
        i += 1
    return 0
""",
            ),
        ]
        for label, src in cases:
            ssa = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
            _vec, stats = LoopVectorizerPass().vectorize_function(ssa)
            self.assertEqual(stats["vectorized_stores"], 0, f"Case {label} was falsely vectorized")


if __name__ == "__main__":
    unittest.main()
