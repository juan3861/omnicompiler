"""
Alpha-C51 End-to-End Verification Suite:
1. Branchless If-Conversion & Conditional Reductions (`if v > thresh: s += v`)
   across small-const tree reduction (N<=64), dynamic strip-mining, Z3 bounds,
   Native JIT, and LLVM O3 JIT parity.
2. `if-else` Conditional Store Diamond Flattening (`if v > thresh: dst[i] = ... else: dst[i] = ...`)
   with Z3 `PROVEN_MEMORY_SAFE`, plus negative safety guard against speculative
   branch-guarded `load_off` hoisting.
3. Multi-Store AoS Struct Interleaved Vectorization (`pts[i].x`, `pts[i].y` stride 16)
   and Zip Multi-Array Vectorization (`sum_arr`, `diff_arr`) with store-store
   runtime alias protection (`sum_arr == diff_arr`).
4. Multi-Load Struct/Buffer Dot Product (`s += a[i] * b[i]`) and LIVE Wasmtime
   Linear Memory execution of AoS + conditional reduction.
5. Full `OmniRepoCompiler` PE64 Native, LLVM O3, and WSL2 Linux ELF64 compilation.
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


class TestAlphaC51IfConvAosAndDot(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c51_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_if_converted_conditional_reduction_f32_and_const_tree(self):
        """Flattens & vectorizes conditional `if v > thresh: s += v` on both dynamic Array[f32, 130] and const N=19."""
        src = """
class BigFrame:
    flags: u32
    samples: Array[f32, 130]

def sum_above(pkt: BigFrame, n: int, thresh: float) -> float:
    if n > 130:
        return 0.0
    s = 5.0
    i = 0
    while i < n:
        v = pkt.samples[i]
        if v > thresh:
            s += v
        i += 1
    return s
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_sums"], 1)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_fn, {"BigFrame": 4 + 130 * 4}, {"pkt": "BigFrame"}
        )
        self.assertTrue(bv["proven"], bv)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")

        class BigFrameStruct(ctypes.Structure):
            _fields_ = [("flags", ctypes.c_uint32), ("samples", ctypes.c_float * 130)]

        frame = BigFrameStruct(flags=1)
        vals = [float((idx % 17) - 5) * 1.5 for idx in range(130)]
        for idx, v in enumerate(vals):
            frame.samples[idx] = v
        ptr = ctypes.addressof(frame)

        cfunc, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_mod = ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn))
        ll_fn = ll.create_jit_callable(
            ll_mod, "sum_above", restype=ctypes.c_double, argtypes=[ctypes.c_void_p, ctypes.c_int64, ctypes.c_double]
        )

        for n in (-3, 0, 1, 3, 4, 5, 19, 130, 131):
            thresh = 4.0
            expected = 0.0 if n > 130 else (5.0 + sum(v for v in vals[: max(0, n)] if v > thresh))
            self.assertAlmostEqual(cfunc(ptr, n, thresh), expected, places=3, msg=f"Native n={n}")
            self.assertAlmostEqual(ll_fn(ptr, n, thresh), expected, places=3, msg=f"LLVM n={n}")

        # Small constant unrolled conditional tree reduction (N=19 <= 64)
        src_small = """
class SmallArr:
    arr: Array[i64, 19]

def sum_pos_19(b: SmallArr) -> int:
    s = 10
    i = 0
    while i < 19:
        v = b.arr[i]
        if v > 0:
            s += v
        i += 1
    return s
"""
        mod_s = ast.parse(src_small)
        low_s = AstToSsaLowering()
        low_s.register_structs_from_statements(mod_s.body)
        ssa_s = low_s.lower_function_def([n for n in mod_s.body if isinstance(n, ast.FunctionDef)][0])
        vec_s, stats_s = LoopVectorizerPass().vectorize_function(ssa_s)
        self.assertEqual(stats_s["vectorized_sums"], 1)

        class SmallArrStruct(ctypes.Structure):
            _fields_ = [("arr", ctypes.c_int64 * 19)]

        sa = SmallArrStruct()
        s_vals = [(k * 7 - 25) for k in range(19)]
        for k, v in enumerate(s_vals):
            sa.arr[k] = v
        exp_s = 10 + sum(v for v in s_vals if v > 0)
        cf_s, _m2, _ = NativeJitCompiler().compile_ssa(vec_s)
        self.assertEqual(cf_s(ctypes.addressof(sa)), exp_s)

    def test_02_if_else_conditional_store_and_speculative_load_guard(self):
        """Coalesces pure `if-else` store diamond to vectorized `select`, while blocking unsafe speculative arm loads."""
        src = """
class Buf:
    arr: Array[i64, 64]

def clamp_upper(dst: Buf, a: Buf, n: int, cap: int) -> int:
    if n > 64:
        return -1
    i = 0
    while i < n:
        v = a.arr[i]
        if v > cap:
            dst.arr[i] = cap
        else:
            dst.arr[i] = v * 2
        i += 1
    return 0
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_fn, {"Buf": 64 * 8}, {"dst": "Buf", "a": "Buf"}
        )
        self.assertTrue(bv["proven"], bv)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")

        class BufStruct(ctypes.Structure):
            _fields_ = [("arr", ctypes.c_int64 * 64)]

        a = BufStruct()
        for k in range(64):
            a.arr[k] = k * 3
        cf, _m, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_fn = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn)),
            "clamp_upper",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64, ctypes.c_int64],
        )

        for n in (0, 1, 3, 4, 5, 19, 64):
            d_n, d_l = BufStruct(), BufStruct()
            cf(ctypes.addressof(d_n), ctypes.addressof(a), n, 20)
            ll_fn(ctypes.addressof(d_l), ctypes.addressof(a), n, 20)
            for k in range(n):
                v = a.arr[k]
                exp = 20 if v > 20 else v * 2
                self.assertEqual(d_n.arr[k], exp)
                self.assertEqual(d_l.arr[k], exp)

        # Negative test: load_off inside guarded branch must NOT speculate!
        src_unsafe = """
def guarded_load(dst: int, a: int, n: int) -> int:
    i = 0
    while i < n:
        if i > 0:
            dst_v = load_i64(a, (i - 1) * 8)
            store_i64(dst, i * 8, dst_v)
        else:
            store_i64(dst, i * 8, 0)
        i += 1
    return 0
"""
        ssa_u = AstToSsaLowering().lower_function_def(ast.parse(src_unsafe).body[0])
        _v_u, st_u = LoopVectorizerPass().vectorize_function(ssa_u)
        self.assertEqual(st_u["vectorized_stores"], 0)

    def test_03_multi_store_aos_interleaved_and_zip_alias_guard(self):
        """Vectorizes AoS interleaved fields (`x,y` stride 16) and zip dual outputs with runtime store-store alias protection."""
        src_aos = """
def fill_vec2_aos(pts: int, src_ptr: int, n: int) -> int:
    i = 0
    while i < n:
        v = load_i64(src_ptr, i * 8)
        store_i64(pts, i * 16, v + 10)
        store_i64(pts, i * 16 + 8, v * 3)
        i += 1
    return 0
"""
        ssa_aos = AstToSsaLowering().lower_function_def(ast.parse(src_aos).body[0])
        vec_aos, st_aos = LoopVectorizerPass().vectorize_function(ssa_aos)
        self.assertEqual(st_aos["vectorized_stores"], 1)

        cf_aos, _m, _ = NativeJitCompiler().compile_ssa(vec_aos)
        src_arr = (ctypes.c_int64 * 17)(*range(1, 18))
        pts_arr = (ctypes.c_int64 * 34)()
        cf_aos(ctypes.addressof(pts_arr), ctypes.addressof(src_arr), 17)
        for k in range(17):
            self.assertEqual(pts_arr[2 * k], (k + 1) + 10)
            self.assertEqual(pts_arr[2 * k + 1], (k + 1) * 3)

        # Dual output zip with store-store runtime alias hazard (`sum_arr == diff_arr`)
        src_zip = """
def zip_sum_diff(sum_arr: int, diff_arr: int, a: int, b: int, n: int) -> int:
    i = 0
    while i < n:
        av = load_i64(a, i * 8)
        bv = load_i64(b, i * 8)
        store_i64(sum_arr, i * 8, av + bv)
        store_i64(diff_arr, i * 8, av - bv)
        i += 1
    return 0
"""
        ssa_zip = AstToSsaLowering().lower_function_def(ast.parse(src_zip).body[0])
        vec_zip, st_zip = LoopVectorizerPass().vectorize_function(ssa_zip)
        self.assertEqual(st_zip["vectorized_stores"], 1)

        cf_zip, _m2, _ = NativeJitCompiler().compile_ssa(vec_zip)
        ll = LLVMBackend(opt_level=3)
        ll_zip = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_zip)),
            "zip_sum_diff",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64],
        )

        a_arr = (ctypes.c_int64 * 19)(*[k + 5 for k in range(19)])
        b_arr = (ctypes.c_int64 * 19)(*[k * 2 for k in range(19)])
        for label, jfn in (("native", cf_zip), ("llvm", ll_zip)):
            s_out = (ctypes.c_int64 * 19)()
            d_out = (ctypes.c_int64 * 19)()
            jfn(ctypes.addressof(s_out), ctypes.addressof(d_out), ctypes.addressof(a_arr), ctypes.addressof(b_arr), 19)
            for k in range(19):
                self.assertEqual(s_out[k], a_arr[k] + b_arr[k], label)
                self.assertEqual(d_out[k], a_arr[k] - b_arr[k], label)

            # Aliased outputs (`sum_arr == diff_arr`): second store wins deterministically!
            alias_out = (ctypes.c_int64 * 19)()
            jfn(ctypes.addressof(alias_out), ctypes.addressof(alias_out), ctypes.addressof(a_arr), ctypes.addressof(b_arr), 19)
            for k in range(19):
                self.assertEqual(alias_out[k], a_arr[k] - b_arr[k], f"Aliased store-store mismatch in {label}")

    def test_04_dot_product_and_live_wasmtime_aos_plus_filtered_sum(self):
        """Tests struct-buffer dot product + AoS multi-store + conditional sum inside Wasmtime Linear Memory."""
        wb = WasmBackend()
        if not (wb.is_available() if callable(wb.is_available) else wb.is_available):
            self.skipTest("Wasmtime not available")

        src = """
def aos_and_dot(pts: int, a: int, b: int, n: int, thresh: int) -> int:
    i = 0
    while i < n:
        av = load_i64(a, i * 8)
        bv = load_i64(b, i * 8)
        store_i64(pts, i * 16, av * 2)
        store_i64(pts, i * 16 + 8, av - bv)
        i += 1
    dot = 0
    k = 0
    while k < n:
        dot += load_i64(a, k * 8) * load_i64(b, k * 8)
        k += 1
    filt = 0
    m = 0
    while m < n:
        px = load_i64(pts, m * 16)
        if px > thresh:
            filt += px
        m += 1
    return dot + filt
"""
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        self.assertEqual(stats["vectorized_sums"], 2)

        wasm_bytes = wb.wat_to_wasm(wb.ssa_to_wat(vec_fn))
        import wasmtime
        engine = wasmtime.Engine()
        wasm_mod = wasmtime.Module(engine, wasm_bytes)
        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)

        for n in (0, 1, 3, 4, 5, 19):
            store = wasmtime.Store(engine)
            inst = wasmtime.Instance(store, wasm_mod, [])
            mem = inst.exports(store)["memory"]
            fn_w = inst.exports(store)["aos_and_dot"]

            a_off, b_off, p_off = 0x1000, 0x2000, 0x3000
            a_arr = (ctypes.c_int64 * 24)()
            b_arr = (ctypes.c_int64 * 24)()
            p_arr = (ctypes.c_int64 * 48)()
            exp_dot = 0
            exp_filt = 0
            thresh = 10
            for idx in range(24):
                av, bv = idx + 2, (idx % 5) + 1
                a_arr[idx] = av
                b_arr[idx] = bv
                mem.write(store, struct.pack("<q", av), a_off + idx * 8)
                mem.write(store, struct.pack("<q", bv), b_off + idx * 8)
                if idx < n:
                    exp_dot += av * bv
                    if av * 2 > thresh:
                        exp_filt += av * 2

            w_res = fn_w(store, p_off, a_off, b_off, n, thresh)
            n_res = cf(ctypes.addressof(p_arr), ctypes.addressof(a_arr), ctypes.addressof(b_arr), n, thresh)
            self.assertEqual(w_res, exp_dot + exp_filt, f"WASM mismatch n={n}")
            self.assertEqual(n_res, w_res, f"Native vs WASM mismatch n={n}")
            for idx in range(n):
                wx = struct.unpack("<q", mem.read(store, p_off + idx * 16, p_off + idx * 16 + 8))[0]
                wy = struct.unpack("<q", mem.read(store, p_off + idx * 16 + 8, p_off + idx * 16 + 16))[0]
                self.assertEqual(wx, a_arr[idx] * 2)
                self.assertEqual(wy, a_arr[idx] - b_arr[idx])

    def test_05_omnirepo_e2e_ifconv_and_multistore_executable(self):
        """Compiles conditional reduction + dual-store zip via OmniRepoCompiler (Native, LLVM O3, WSL Linux)."""
        r_dir = os.path.join(self.test_dir, "repo_c51")
        os.makedirs(r_dir)
        with open(os.path.join(r_dir, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_c51", "language": "python", "exports": ["omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "def omni_main(n: int) -> int:\n"
                "    a = malloc(1056)\n"
                "    b = malloc(1056)\n"
                "    s_arr = malloc(1056)\n"
                "    d_arr = malloc(1056)\n"
                "    if n > 130:\n"
                "        n = 130\n"
                "    k = 0\n"
                "    while k < n:\n"
                "        store_i64(a, k * 8, k + 2)\n"
                "        store_i64(b, k * 8, k % 5)\n"
                "        k += 1\n"
                "    i = 0\n"
                "    while i < n:\n"
                "        av = load_i64(a, i * 8)\n"
                "        bv = load_i64(b, i * 8)\n"
                "        store_i64(s_arr, i * 8, av + bv)\n"
                "        store_i64(d_arr, i * 8, av - bv)\n"
                "        i += 1\n"
                "    tot = 0\n"
                "    j = 0\n"
                "    while j < n:\n"
                "        v = load_i64(s_arr, j * 8)\n"
                "        if v > 10:\n"
                "            tot += v\n"
                "        j += 1\n"
                "    free(a)\n"
                "    free(b)\n"
                "    free(s_arr)\n"
                "    free(d_arr)\n"
                '    printf("C51_TOT=%lld\\n", tot)\n'
                "    return tot % 251\n"
            )

        comp = OmniRepoCompiler()
        try:
            nat_bin = os.path.join(self.test_dir, "c51_nat.exe" if sys.platform == "win32" else "c51_nat")
            res_nat = comp.compile_repositories(
                [r_dir], nat_bin, target_format="executable", entry_export="omni_main",
                backend="native", audit_nonce="c51-nat",
            )
            self.assertTrue(res_nat["stages"]["formal_audit"]["is_valid"])
            self.assertGreaterEqual(res_nat["stages"]["codegen"]["vectorized_loops"], 2)

            ll_bin = os.path.join(self.test_dir, "c51_ll.exe" if sys.platform == "win32" else "c51_ll")
            res_ll = comp.compile_repositories(
                [r_dir], ll_bin, target_format="executable", entry_export="omni_main",
                backend="llvm", audit_nonce="c51-ll",
            )
            self.assertTrue(res_ll["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res_ll["stages"]["backend_validation"].get("refuted", 0), 0)

            for bin_p in (nat_bin, ll_bin):
                if sys.platform != "win32":
                    os.chmod(bin_p, 0o755)
                for n in (0, 5, 19, 130):
                    exp_tot = sum((k + 2 + (k % 5)) for k in range(n) if (k + 2 + (k % 5)) > 10)
                    p = subprocess.run([bin_p, str(n)], capture_output=True, text=True, timeout=10)
                    self.assertIn(f"C51_TOT={exp_tot}", p.stdout, f"{bin_p} n={n}: {p.stdout} {p.stderr}")
                    self.assertEqual(p.returncode, exp_tot % 251)

            if sys.platform == "win32" and _wsl_available():
                lin_bin = os.path.join(self.test_dir, "c51_linux")
                res_lin = comp.compile_repositories(
                    [r_dir], lin_bin, target_format="executable", entry_export="omni_main",
                    target_os="linux", backend="native", audit_nonce="c51-wsl",
                )
                self.assertTrue(res_lin["stages"]["formal_audit"]["is_valid"])
                wsl_p = lin_bin.replace("\\", "/").replace("F:", "/mnt/f").replace("C:", "/mnt/c")
                cmd = f"cp {wsl_p} /tmp/c51_lin && chmod +x /tmp/c51_lin && /tmp/c51_lin 130"
                p_wsl = subprocess.run(["wsl", "/bin/sh", "-c", cmd], capture_output=True, timeout=20)
                if p_wsl.returncode != 4294967295:
                    exp_130 = sum((k + 2 + (k % 5)) for k in range(130) if (k + 2 + (k % 5)) > 10)
                    self.assertIn(f"C51_TOT={exp_130}".encode("ascii"), p_wsl.stdout)
                    self.assertEqual(p_wsl.returncode, exp_130 % 251)
        finally:
            comp.close()


if __name__ == "__main__":
    unittest.main()
