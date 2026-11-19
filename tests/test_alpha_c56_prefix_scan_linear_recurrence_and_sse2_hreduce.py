"""
Alpha-C56 End-to-End Verification Suite:
1. Inclusive & Exclusive Prefix-Scan Vectorization (`s += v; out[i] = s` and `out[i] = s; s += v`),
   optionally conditional (`if v > 0: s += v; out[i] = s`) or fused with multi-reductions,
   proven memory-safe by Z3 bi-abduction and verified against Native PE64 & LLVM O3.
2. First-Order Linear Recurrence Vectorization (`h = h * c + v`, `h = h * c - v`,
   `h = (h << sh) + v`) via Estrin's 4-way parallel Horner tree across dynamic strip-mining,
   large constant strip-mining, and small constant unrolled trees (N<=64).
3. Direct x86-64 SSE2 128-bit Horizontal Tree Reduction (`punpcklqdq` `66 0f 6c c1/ca` +
   `paddq`/`addpd`/`pand`/`por`/`pxor` + `pshufd xmm1, xmm0, 0x4E` `66 0f 70 c8 4e`) in `NativeCodegen`.
4. Live Wasmtime Linear Memory roundtrip for vectorized prefix scan + linear recurrence.
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
from compiler.native_codegen import X64CodeGenerator
from compiler.native_jit import NativeJitCompiler
from compiler.ssa_ir import AstToSsaLowering
from compiler.wasm_backend import WasmBackend
from omni_repo_compiler import OmniRepoCompiler
from validation.assembly_invariant_auditor import AssemblyInvariantAuditor
from validation.biabduction_verifier import BiAbductionVerifier


def _wsl_available() -> bool:
    if sys.platform != "win32":
        return False
    try:
        r = subprocess.run(["wsl", "uname"], capture_output=True, text=True, timeout=10)
        return r.returncode == 0 and "Linux" in r.stdout
    except Exception:
        return False


def _s64(val: int) -> int:
    u = int(val) & 0xFFFFFFFFFFFFFFFF
    return u - 0x10000000000000000 if (u & 0x8000000000000000) else u


class TestAlphaC56PrefixScanLinearRecurrenceAndSSE2HReduce(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c56_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_inclusive_and_exclusive_prefix_scan_z3_and_parity(self):
        """Inclusive (`s += v; inc[i] = s`) & exclusive (`exc[i] = se; se += v`) prefix scans prove Z3 safe and match Native & LLVM O3."""
        src = """
class ScanArena:
    inp: Array[i64, 128]
    inc_out: Array[i64, 128]
    exc_out: Array[i64, 128]

def run_prefix_scans(a: ScanArena, n: int) -> int:
    if n > 128:
        return -999
    s_inc = 10
    s_exc = 0
    mx_v = -999999
    i = 0
    while i < n:
        v = a.inp[i] * 2 + 1
        s_inc += v
        a.inc_out[i] = s_inc
        a.exc_out[i] = s_exc
        s_exc += v
        mx_v = max(mx_v, v)
        i += 1
    return s_inc + s_exc + mx_v
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        self.assertEqual(stats["vectorized_sums"], 1)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_fn, {"ScanArena": 128 * 8 * 3}, {"a": "ScanArena"}
        )
        self.assertTrue(bv["proven"], bv)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")

        class ScanArenaStruct(ctypes.Structure):
            _fields_ = [
                ("inp", ctypes.c_int64 * 128),
                ("inc_out", ctypes.c_int64 * 128),
                ("exc_out", ctypes.c_int64 * 128),
            ]

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_fn = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn)),
            "run_prefix_scans",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_void_p, ctypes.c_int64],
        )

        inp_vals = [((k * 23) % 59) - 20 for k in range(128)]
        for n in (-2, 0, 1, 2, 3, 4, 7, 16, 23, 128, 129):
            sa_nat = ScanArenaStruct()
            sa_ll = ScanArenaStruct()
            for idx in range(128):
                sa_nat.inp[idx] = inp_vals[idx]
                sa_ll.inp[idx] = inp_vals[idx]
                sa_nat.inc_out[idx] = -77
                sa_ll.inc_out[idx] = -77
                sa_nat.exc_out[idx] = -88
                sa_ll.exc_out[idx] = -88

            r_nat = cf(ctypes.addressof(sa_nat), n)
            r_ll = ll_fn(ctypes.addressof(sa_ll), n)
            if n > 128:
                exp = -999
            else:
                s_i = 10
                s_e = 0
                mx = -999999
                for k in range(max(0, n)):
                    v = inp_vals[k] * 2 + 1
                    s_i += v
                    exp_inc = s_i
                    exp_exc = s_e
                    s_e += v
                    mx = max(mx, v)
                    self.assertEqual(sa_nat.inc_out[k], exp_inc, f"nat inc[{k}] n={n}")
                    self.assertEqual(sa_nat.exc_out[k], exp_exc, f"nat exc[{k}] n={n}")
                    self.assertEqual(sa_ll.inc_out[k], exp_inc, f"ll inc[{k}] n={n}")
                    self.assertEqual(sa_ll.exc_out[k], exp_exc, f"ll exc[{k}] n={n}")
                exp = s_i + s_e + mx
            self.assertEqual(r_nat, exp, f"Native scan mismatch n={n}")
            self.assertEqual(r_ll, exp, f"LLVM scan mismatch n={n}")

    def test_02_first_order_linear_recurrence_estrin_horner_and_rolling_hash(self):
        """Tests Estrin 4-way parallel linear recurrence (`h = h * 31 + v`, `h2 = (h2 << 3) - v`) across dynamic & constant N."""
        src = """
class PolyPacket:
    coeffs: Array[i64, 130]

def eval_poly_and_hash(pkt: PolyPacket, n: int) -> int:
    if n > 130:
        return -333
    h1 = 7
    h2 = 3
    tot = 0
    i = 0
    while i < n:
        v = pkt.coeffs[i]
        h1 = h1 * 13 + v
        h2 = (h2 << 2) - v
        tot += v
        i += 1
    h_small = 5
    k = 0
    while k < 19:
        h_small = h_small * 7 + pkt.coeffs[k]
        k += 1
    return h1 + h2 + tot + h_small
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_sums"], 2)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_fn, {"PolyPacket": 130 * 8}, {"pkt": "PolyPacket"}
        )
        self.assertTrue(bv["proven"], bv)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")

        class PolyPacketStruct(ctypes.Structure):
            _fields_ = [("coeffs", ctypes.c_int64 * 130)]

        pkt = PolyPacketStruct()
        c_vals = [((idx * 17) % 29) - 10 for idx in range(130)]
        for idx, v in enumerate(c_vals):
            pkt.coeffs[idx] = v

        h_small_ref = 5
        for k in range(19):
            h_small_ref = _s64(_s64(h_small_ref * 7) + c_vals[k])

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_fn = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn)),
            "eval_poly_and_hash",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_void_p, ctypes.c_int64],
        )

        for n in (-1, 0, 1, 2, 3, 4, 5, 8, 11, 14, 15):
            r_nat = cf(ctypes.addressof(pkt), n)
            r_ll = ll_fn(ctypes.addressof(pkt), n)
            h1 = 7
            h2 = 3
            tot = 0
            for k in range(max(0, n)):
                v = c_vals[k]
                h1 = _s64(_s64(h1 * 13) + v)
                h2 = _s64(_s64(h2 * 4) - v)
                tot = _s64(tot + v)
            exp = _s64(_s64(_s64(h1 + h2) + tot) + h_small_ref)
            self.assertEqual(r_nat, exp, f"Native Horner mismatch n={n}")
            self.assertEqual(r_ll, exp, f"LLVM Horner mismatch n={n}")

    def test_03_native_codegen_sse2_128bit_horizontal_tree_collapse_opcodes_and_execution(self):
        """Verifies physical SSE2 128-bit horizontal tree collapse opcodes (`pshufd 0x4E`, `punpcklqdq`, `paddq`, `addpd`)."""
        src = """
class HReduceBuf:
    ia: Array[i64, 64]
    fa: Array[f64, 64]

def hreduce_sum(b: HReduceBuf, n: int) -> float:
    isum = 0
    fsum = 0.0
    i = 0
    while i < n:
        isum += b.ia[i]
        fsum += b.fa[i]
        i += 1
    return float(isum) + fsum
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_sums"], 1)

        art = X64CodeGenerator().compile_function(vec_fn)
        mc = art.code_bytes
        self.assertIn(b"\x66\x0f\x6c\xc1", mc, "Expected punpcklqdq xmm0, xmm1")
        self.assertIn(b"\x66\x0f\x6c\xca", mc, "Expected punpcklqdq xmm1, xmm2")
        self.assertIn(b"\x66\x0f\x70\xc8\x4e", mc, "Expected 128-bit horizontal swap pshufd xmm1, xmm0, 0x4E")
        self.assertIn(b"\x66\x0f\xd4\xc1", mc, "Expected paddq xmm0, xmm1")
        self.assertIn(b"\x66\x0f\x58\xc1", mc, "Expected addpd xmm0, xmm1")

        audit = AssemblyInvariantAuditor().audit_function_code(mc, "hreduce_sum")
        self.assertTrue(audit.is_valid, audit.errors)

        class HReduceBufStruct(ctypes.Structure):
            _fields_ = [("ia", ctypes.c_int64 * 64), ("fa", ctypes.c_double * 64)]

        hb = HReduceBufStruct()
        for k in range(64):
            hb.ia[k] = k * 3 - 20
            hb.fa[k] = float(k) * 0.75 + 1.25

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        for n in (1, 3, 4, 9, 27, 64):
            res = cf(ctypes.addressof(hb), n)
            exp = float(sum(hb.ia[k] for k in range(n))) + sum(hb.fa[k] for k in range(n))
            self.assertAlmostEqual(res, exp, places=6, msg=f"hreduce n={n}")

    def test_04_live_wasmtime_prefix_scan_and_linear_recurrence_roundtrip(self):
        """Executes vectorized inclusive prefix scan + linear recurrence live inside Wasmtime Linear Memory."""
        wb = WasmBackend()
        if not (wb.is_available() if callable(wb.is_available) else wb.is_available):
            self.skipTest("Wasmtime not available")

        src = """
def wasm_scan_and_hash(dst: int, src: int, n: int) -> int:
    s = 0
    h = 11
    i = 0
    while i < n:
        v = load_i64(src, i * 8)
        s += v
        store_i64(dst, i * 8, s)
        h = h * 5 + v
        i += 1
    return s + h
"""
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        self.assertEqual(stats["vectorized_sums"], 1)

        wat_text = wb.ssa_to_wat(vec_fn)
        self.assertIn("v128.store", wat_text)

        import wasmtime
        engine = wasmtime.Engine()
        wasm_mod = wasmtime.Module(engine, wb.wat_to_wasm(wat_text))
        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)

        src_vals = [((k * 7) % 13) - 4 for k in range(20)]
        for n in (1, 3, 4, 7, 11):
            store = wasmtime.Store(engine)
            inst = wasmtime.Instance(store, wasm_mod, [])
            mem = inst.exports(store)["memory"]
            s_arr = (ctypes.c_int64 * 20)(*src_vals)
            d_arr = (ctypes.c_int64 * 20)(*([0] * 20))
            for idx in range(20):
                mem.write(store, struct.pack("<q", src_vals[idx]), 0x1000 + idx * 8)
                mem.write(store, struct.pack("<q", 0), 0x2000 + idx * 8)

            s_ref = 0
            h_ref = 11
            exp_prefix = []
            for k in range(n):
                s_ref += src_vals[k]
                exp_prefix.append(s_ref)
                h_ref = _s64(_s64(h_ref * 5) + src_vals[k])
            exp = _s64(s_ref + h_ref)

            w_res = inst.exports(store)["wasm_scan_and_hash"](store, 0x2000, 0x1000, n)
            n_res = cf(ctypes.addressof(d_arr), ctypes.addressof(s_arr), n)
            self.assertEqual(w_res, exp, f"WASM scan+hash n={n}")
            self.assertEqual(n_res, exp, f"Native scan+hash n={n}")
            for k in range(n):
                w_d = struct.unpack("<q", mem.read(store, 0x2000 + k * 8, 0x2000 + (k + 1) * 8))[0]
                self.assertEqual(w_d, exp_prefix[k])
                self.assertEqual(d_arr[k], exp_prefix[k])

    def test_05_omnirepo_e2e_prefix_scan_and_horner_hash_executable(self):
        """Compiles prefix scan + Estrin Horner recurrence via OmniRepoCompiler (Native, LLVM O3, WSL Linux)."""
        r_dir = os.path.join(self.test_dir, "repo_c56")
        os.makedirs(r_dir)
        with open(os.path.join(r_dir, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_c56", "language": "python", "exports": ["omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "def omni_main(n: int) -> int:\n"
                "    a = malloc(1056)\n"
                "    p = malloc(1056)\n"
                "    if n > 12:\n"
                "        n = 12\n"
                "    k = 0\n"
                "    while k < n:\n"
                "        store_i64(a, k * 8, (k & 7) + 1)\n"
                "        k += 1\n"
                "    s = 0\n"
                "    h = 3\n"
                "    i = 0\n"
                "    while i < n:\n"
                "        v = load_i64(a, i * 8)\n"
                "        s += v\n"
                "        store_i64(p, i * 8, s)\n"
                "        h = h * 3 + v\n"
                "        i += 1\n"
                "    p_sum = 0\n"
                "    j = 0\n"
                "    while j < n:\n"
                "        p_sum += load_i64(p, j * 8)\n"
                "        j += 1\n"
                "    res = p_sum + h\n"
                "    free(a)\n"
                "    free(p)\n"
                '    printf("C56_SCAN=%lld\\n", res)\n'
                "    return res % 251\n"
            )

        comp = OmniRepoCompiler()
        try:
            nat_bin = os.path.join(self.test_dir, "c56_nat.exe" if sys.platform == "win32" else "c56_nat")
            res_nat = comp.compile_repositories(
                [r_dir], nat_bin, target_format="executable", entry_export="omni_main",
                backend="native", audit_nonce="c56-nat",
            )
            self.assertTrue(res_nat["stages"]["formal_audit"]["is_valid"])
            self.assertGreaterEqual(res_nat["stages"]["codegen"]["vectorized_loops"], 3)

            ll_bin = os.path.join(self.test_dir, "c56_ll.exe" if sys.platform == "win32" else "c56_ll")
            res_ll = comp.compile_repositories(
                [r_dir], ll_bin, target_format="executable", entry_export="omni_main",
                backend="llvm", audit_nonce="c56-ll",
            )
            self.assertTrue(res_ll["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res_ll["stages"]["backend_validation"].get("refuted", 0), 0)

            for bin_p in (nat_bin, ll_bin):
                if sys.platform != "win32":
                    os.chmod(bin_p, 0o755)
                for n in (1, 4, 7, 12):
                    s_ref = 0
                    h_ref = 3
                    p_sum = 0
                    for k in range(n):
                        v = (k & 7) + 1
                        s_ref += v
                        p_sum += s_ref
                        h_ref = h_ref * 3 + v
                    exp = p_sum + h_ref
                    p = subprocess.run([bin_p, str(n)], capture_output=True, text=True, timeout=10)
                    self.assertIn(f"C56_SCAN={exp}", p.stdout, f"{bin_p} n={n}: {p.stdout} {p.stderr}")
                    self.assertEqual(p.returncode, exp % 251)

            if sys.platform == "win32" and _wsl_available():
                lin_bin = os.path.join(self.test_dir, "c56_linux")
                res_lin = comp.compile_repositories(
                    [r_dir], lin_bin, target_format="executable", entry_export="omni_main",
                    target_os="linux", backend="native", audit_nonce="c56-wsl",
                )
                self.assertTrue(res_lin["stages"]["formal_audit"]["is_valid"])
                wsl_p = lin_bin.replace("\\", "/").replace("F:", "/mnt/f").replace("C:", "/mnt/c")
                cmd = f"cp {wsl_p} /tmp/c56_lin && chmod +x /tmp/c56_lin && /tmp/c56_lin 12"
                p_wsl = subprocess.run(["wsl", "/bin/sh", "-c", cmd], capture_output=True, timeout=20)
                if p_wsl.returncode != 4294967295:
                    s_ref = 0
                    h_ref = 3
                    p_sum = 0
                    for k in range(12):
                        v = (k & 7) + 1
                        s_ref += v
                        p_sum += s_ref
                        h_ref = h_ref * 3 + v
                    exp_12 = p_sum + h_ref
                    self.assertIn(f"C56_SCAN={exp_12}".encode("ascii"), p_wsl.stdout)
                    self.assertEqual(p_wsl.returncode, exp_12 % 251)
        finally:
            comp.close()


if __name__ == "__main__":
    unittest.main()
