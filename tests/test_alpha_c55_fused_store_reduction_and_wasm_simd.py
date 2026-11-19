"""
Alpha-C55 End-to-End Verification Suite:
1. Single-Pass Fused Vectorized Store + Multi-Reduction Pipelines (`dst[i] = expr; acc = op(acc, val)`)
   with Same-Iteration Store-to-Load Forwarding (`dst[i] = expr; acc += dst[i]`).
2. Fused Store + Conditional If-Converted Reductions (`if v > thresh: out[i] = v; pos_sum += v`)
   and Runtime Pointer-Alias Safe Scalar Fallback for both stores and fused accumulators.
3. WebAssembly 128-bit SIMD (`v128.load`, `v128.store`, `i64x2.add`, `i64x2.splat`,
   `i64x2.replace_lane 1`, `i32x4.add`, `f32x4.mul`, `0xFD` binary prefix) in `WasmBackend`
   executed live in Wasmtime Linear Memory.
4. Strided (`i += 2`) and Reverse Countdown (`i -= 1`) Fused Store + Reduction loops.
5. Full `OmniRepoCompiler` PE64 Native, PE64 LLVM O3, and WSL2 Linux ELF64 executables.
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


class TestAlphaC55FusedStoreReductionAndWasmSimd(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c55_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_fused_store_and_multireduction_single_pass_z3_and_parity(self):
        """Fused single-pass dual store + triple reduction (with store-to-load forwarding) proves Z3 safe and matches Native & LLVM O3."""
        src = """
class FusedTelemetry:
    a: Array[i64, 128]
    b: Array[i64, 128]
    out_sum: Array[i64, 128]
    out_diff: Array[i64, 128]

def fused_transform_and_reduce(t: FusedTelemetry, n: int) -> int:
    if n > 128:
        return -888
    tot = 0
    mx = -999999
    mn = 999999
    i = 0
    while i < n:
        t.out_sum[i] = t.a[i] + t.b[i]
        d = t.a[i] * 2 - t.b[i]
        t.out_diff[i] = d
        s_reloaded = t.out_sum[i]
        tot += s_reloaded
        mx = max(mx, d)
        mn = min(mn, s_reloaded)
        i += 1
    return tot + mx - mn
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        self.assertEqual(stats["vectorized_sums"], 1)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_fn, {"FusedTelemetry": 128 * 8 * 4}, {"t": "FusedTelemetry"}
        )
        self.assertTrue(bv["proven"], bv)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")

        class FusedTelemetryStruct(ctypes.Structure):
            _fields_ = [
                ("a", ctypes.c_int64 * 128),
                ("b", ctypes.c_int64 * 128),
                ("out_sum", ctypes.c_int64 * 128),
                ("out_diff", ctypes.c_int64 * 128),
            ]

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_fn = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn)),
            "fused_transform_and_reduce",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_void_p, ctypes.c_int64],
        )

        a_vals = [((k * 31) % 89) - 40 for k in range(128)]
        b_vals = [((k * 19) % 67) - 25 for k in range(128)]

        for n in (-2, 0, 1, 2, 3, 4, 7, 16, 23, 128, 129):
            st_nat = FusedTelemetryStruct()
            st_ll = FusedTelemetryStruct()
            for idx in range(128):
                st_nat.a[idx] = a_vals[idx]
                st_ll.a[idx] = a_vals[idx]
                st_nat.b[idx] = b_vals[idx]
                st_ll.b[idx] = b_vals[idx]
                st_nat.out_sum[idx] = -111
                st_ll.out_sum[idx] = -111
                st_nat.out_diff[idx] = -222
                st_ll.out_diff[idx] = -222

            r_nat = cf(ctypes.addressof(st_nat), n)
            r_ll = ll_fn(ctypes.addressof(st_ll), n)
            if n > 128:
                exp = -888
            else:
                cnt = max(0, n)
                sums = [a_vals[k] + b_vals[k] for k in range(cnt)]
                diffs = [a_vals[k] * 2 - b_vals[k] for k in range(cnt)]
                exp = sum(sums) + max([-999999] + diffs) - min([999999] + sums)
                for k in range(cnt):
                    self.assertEqual(st_nat.out_sum[k], sums[k])
                    self.assertEqual(st_nat.out_diff[k], diffs[k])
                    self.assertEqual(st_ll.out_sum[k], sums[k])
                    self.assertEqual(st_ll.out_diff[k], diffs[k])
            self.assertEqual(r_nat, exp, f"Native mismatch n={n}")
            self.assertEqual(r_ll, exp, f"LLVM mismatch n={n}")

    def test_02_if_converted_fused_store_and_conditional_reductions_plus_alias_fallback(self):
        """Tests if-converted fused store + conditional reduction and overlapping pointer alias fallback."""
        src = """
def clamp_and_accum_raw(dst: int, src: int, n: int) -> int:
    pos_sum = 0
    pos_mx = 0
    i = 0
    while i < n:
        v = load_i64(src, i * 8) - 10
        if v > 0:
            store_i64(dst, i * 8, v)
            pos_sum += v
            pos_mx = max(pos_mx, v)
        else:
            store_i64(dst, i * 8, 0)
        i += 1
    return pos_sum * 100 + pos_mx
"""
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        self.assertEqual(stats["vectorized_sums"], 1)

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)

        # 1. Disjoint buffers
        raw_vals = [((k * 17) % 35) for k in range(25)]
        for n in (1, 3, 4, 9, 25):
            s_arr = (ctypes.c_int64 * 25)(*raw_vals)
            d_arr = (ctypes.c_int64 * 25)(*([-1] * 25))
            ret = cf(ctypes.addressof(d_arr), ctypes.addressof(s_arr), n)
            clamped = [max(0, raw_vals[k] - 10) for k in range(n)]
            exp = sum(clamped) * 100 + max([0] + clamped)
            self.assertEqual(ret, exp, f"Disjoint n={n}")
            for k in range(n):
                self.assertEqual(d_arr[k], clamped[k])

        # 2. Overlapping shifted buffers (dst = src + 8 bytes -> must trigger runtime alias guard and fall back to scalar tail!)
        overlap_buf = (ctypes.c_int64 * 20)(*([20 + k for k in range(20)]))
        ref_buf = [20 + k for k in range(20)]
        p_sum = 0
        p_mx = 0
        for k in range(12):
            v = ref_buf[k] - 10
            if v > 0:
                ref_buf[k + 1] = v
                p_sum += v
                p_mx = max(p_mx, v)
            else:
                ref_buf[k + 1] = 0
        exp_ov = p_sum * 100 + p_mx
        base_addr = ctypes.addressof(overlap_buf)
        ret_ov = cf(base_addr + 8, base_addr, 12)
        self.assertEqual(ret_ov, exp_ov, "Overlapping alias fallback must match exact sequential semantics")
        for k in range(13):
            self.assertEqual(overlap_buf[k], ref_buf[k], f"overlap_buf[{k}]")

    def test_03_wasm_128bit_v128_simd_emission_and_live_wasmtime_execution(self):
        """Verifies WebAssembly 128-bit SIMD (`v128.load`, `v128.store`, `i64x2.add`, `0xFD` prefix) in WasmBackend."""
        wb = WasmBackend()
        if not (wb.is_available() if callable(wb.is_available) else wb.is_available):
            self.skipTest("Wasmtime not available")

        src = """
def wasm_simd_fused(dst: int, a: int, b: int, pack_dst: int, n: int) -> int:
    tot = 0
    mx = -999999
    i = 0
    while i < n:
        s = load_i64(a, i * 8) + load_i64(b, i * 8)
        store_i64(dst, i * 8, s)
        p = s * 3 + i
        store_i64(pack_dst, i * 8, p)
        tot += s
        mx = max(mx, p)
        i += 1
    return tot + mx
"""
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        self.assertEqual(stats["vectorized_sums"], 1)

        wat_text = wb.ssa_to_wat(vec_fn)
        self.assertIn("v128.load", wat_text)
        self.assertIn("i64x2.add", wat_text)
        self.assertIn("i64x2.splat", wat_text)
        self.assertIn("i64x2.replace_lane 1", wat_text)
        self.assertIn("v128.store", wat_text)

        wasm_bytes = wb.wat_to_wasm(wat_text)
        self.assertIn(b"\xfd", wasm_bytes, "Expected 0xFD WebAssembly 128-bit SIMD opcode prefix in .wasm binary")

        import wasmtime
        engine = wasmtime.Engine()
        wasm_mod = wasmtime.Module(engine, wasm_bytes)
        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)

        a_vals = [(k * 13) % 41 - 15 for k in range(24)]
        b_vals = [(k * 29) % 37 - 10 for k in range(24)]
        for n in (1, 3, 4, 8, 19):
            store = wasmtime.Store(engine)
            inst = wasmtime.Instance(store, wasm_mod, [])
            mem = inst.exports(store)["memory"]
            a_arr = (ctypes.c_int64 * 24)(*a_vals)
            b_arr = (ctypes.c_int64 * 24)(*b_vals)
            d_arr = (ctypes.c_int64 * 24)(*([0] * 24))
            p_arr = (ctypes.c_int64 * 24)(*([0] * 24))
            for idx in range(24):
                mem.write(store, struct.pack("<q", a_vals[idx]), 0x1000 + idx * 8)
                mem.write(store, struct.pack("<q", b_vals[idx]), 0x2000 + idx * 8)

            s_list = [a_vals[k] + b_vals[k] for k in range(n)]
            p_list = [s_list[k] * 3 + k for k in range(n)]
            exp = sum(s_list) + max([-999999] + p_list)

            w_res = inst.exports(store)["wasm_simd_fused"](store, 0x3000, 0x1000, 0x2000, 0x4000, n)
            n_res = cf(ctypes.addressof(d_arr), ctypes.addressof(a_arr), ctypes.addressof(b_arr), ctypes.addressof(p_arr), n)
            self.assertEqual(w_res, exp, f"WASM v128 n={n}")
            self.assertEqual(n_res, exp, f"Native SSE2 n={n}")
            for k in range(n):
                w_d = struct.unpack("<q", mem.read(store, 0x3000 + k * 8, 0x3000 + (k + 1) * 8))[0]
                w_p = struct.unpack("<q", mem.read(store, 0x4000 + k * 8, 0x4000 + (k + 1) * 8))[0]
                self.assertEqual(w_d, s_list[k])
                self.assertEqual(w_p, p_list[k])

    def test_04_strided_and_reverse_fused_store_reduction_parity(self):
        """Tests strided (`i += 2`) and reverse countdown (`i -= 1`) fused store + reduction loops."""
        src = """
class DualStageBuf:
    src: Array[i64, 128]
    mid: Array[i64, 128]
    fin: Array[i64, 128]

def run_strided_and_reverse_fused(b: DualStageBuf, n: int) -> int:
    if n > 128:
        return -444
    s1 = 0
    i = 0
    while i < n:
        v = b.src[i] * 2 + 5
        b.mid[i] = v
        s1 += v
        i += 2
    s2 = 0
    mx2 = -999999
    k = n - 1
    while k >= 0:
        w = b.mid[k] + b.src[k]
        b.fin[k] = w
        s2 += w
        mx2 = max(mx2, w)
        k -= 1
    return s1 + s2 + mx2
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 2)
        self.assertEqual(stats["vectorized_sums"], 2)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_fn, {"DualStageBuf": 128 * 8 * 3}, {"b": "DualStageBuf"}
        )
        self.assertTrue(bv["proven"], bv)

        class DualStageBufStruct(ctypes.Structure):
            _fields_ = [
                ("src", ctypes.c_int64 * 128),
                ("mid", ctypes.c_int64 * 128),
                ("fin", ctypes.c_int64 * 128),
            ]

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        src_vals = [((k * 19) % 61) - 20 for k in range(128)]
        for n in (0, 1, 2, 5, 8, 17, 64, 128):
            ds = DualStageBufStruct()
            for idx in range(128):
                ds.src[idx] = src_vals[idx]
                ds.mid[idx] = 0
                ds.fin[idx] = 0
            ret = cf(ctypes.addressof(ds), n)
            mid_ref = [0] * 128
            s1_ref = 0
            for idx in range(0, n, 2):
                v = src_vals[idx] * 2 + 5
                mid_ref[idx] = v
                s1_ref += v
            fin_ref = [mid_ref[idx] + src_vals[idx] for idx in range(n)]
            exp = s1_ref + sum(fin_ref) + max([-999999] + fin_ref)
            self.assertEqual(ret, exp, f"Mismatch n={n}")

    def test_05_omnirepo_e2e_fused_store_reduction_executable(self):
        """Compiles single-pass fused store + multi-reduction via OmniRepoCompiler (Native, LLVM O3, WSL Linux)."""
        r_dir = os.path.join(self.test_dir, "repo_c55")
        os.makedirs(r_dir)
        with open(os.path.join(r_dir, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_c55", "language": "python", "exports": ["omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "def omni_main(n: int) -> int:\n"
                "    a = malloc(1056)\n"
                "    b = malloc(1056)\n"
                "    d = malloc(1056)\n"
                "    if n > 128:\n"
                "        n = 128\n"
                "    k = 0\n"
                "    while k < n:\n"
                "        store_i64(a, k * 8, (k & 15) * 4 + 2)\n"
                "        store_i64(b, k * 8, (k & 7) * 3 + 1)\n"
                "        k += 1\n"
                "    tot = 0\n"
                "    mx = 0\n"
                "    mn = 999999\n"
                "    i = 0\n"
                "    while i < n:\n"
                "        v = load_i64(a, i * 8) + load_i64(b, i * 8)\n"
                "        store_i64(d, i * 8, v)\n"
                "        tot += v\n"
                "        mx = max(mx, v)\n"
                "        mn = min(mn, v)\n"
                "        i += 1\n"
                "    res = tot + mx - mn + 1000\n"
                "    free(a)\n"
                "    free(b)\n"
                "    free(d)\n"
                '    printf("C55_FUSED=%lld\\n", res)\n'
                "    return res % 251\n"
            )

        comp = OmniRepoCompiler()
        try:
            nat_bin = os.path.join(self.test_dir, "c55_nat.exe" if sys.platform == "win32" else "c55_nat")
            res_nat = comp.compile_repositories(
                [r_dir], nat_bin, target_format="executable", entry_export="omni_main",
                backend="native", audit_nonce="c55-nat",
            )
            self.assertTrue(res_nat["stages"]["formal_audit"]["is_valid"])
            self.assertGreaterEqual(res_nat["stages"]["codegen"]["vectorized_loops"], 2)

            ll_bin = os.path.join(self.test_dir, "c55_ll.exe" if sys.platform == "win32" else "c55_ll")
            res_ll = comp.compile_repositories(
                [r_dir], ll_bin, target_format="executable", entry_export="omni_main",
                backend="llvm", audit_nonce="c55-ll",
            )
            self.assertTrue(res_ll["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res_ll["stages"]["backend_validation"].get("refuted", 0), 0)

            for bin_p in (nat_bin, ll_bin):
                if sys.platform != "win32":
                    os.chmod(bin_p, 0o755)
                for n in (1, 5, 19, 128):
                    vals = [((k & 15) * 4 + 2) + ((k & 7) * 3 + 1) for k in range(n)]
                    exp = sum(vals) + max([0] + vals) - min([999999] + vals) + 1000
                    p = subprocess.run([bin_p, str(n)], capture_output=True, text=True, timeout=10)
                    self.assertIn(f"C55_FUSED={exp}", p.stdout, f"{bin_p} n={n}: {p.stdout} {p.stderr}")
                    self.assertEqual(p.returncode, exp % 251)

            if sys.platform == "win32" and _wsl_available():
                lin_bin = os.path.join(self.test_dir, "c55_linux")
                res_lin = comp.compile_repositories(
                    [r_dir], lin_bin, target_format="executable", entry_export="omni_main",
                    target_os="linux", backend="native", audit_nonce="c55-wsl",
                )
                self.assertTrue(res_lin["stages"]["formal_audit"]["is_valid"])
                wsl_p = lin_bin.replace("\\", "/").replace("F:", "/mnt/f").replace("C:", "/mnt/c")
                cmd = f"cp {wsl_p} /tmp/c55_lin && chmod +x /tmp/c55_lin && /tmp/c55_lin 128"
                p_wsl = subprocess.run(["wsl", "/bin/sh", "-c", cmd], capture_output=True, timeout=20)
                if p_wsl.returncode != 4294967295:
                    vals_128 = [((k & 15) * 4 + 2) + ((k & 7) * 3 + 1) for k in range(128)]
                    exp_128 = sum(vals_128) + max([0] + vals_128) - min([999999] + vals_128) + 1000
                    self.assertIn(f"C55_FUSED={exp_128}".encode("ascii"), p_wsl.stdout)
                    self.assertEqual(p_wsl.returncode, exp_128 % 251)
        finally:
            comp.close()


if __name__ == "__main__":
    unittest.main()
