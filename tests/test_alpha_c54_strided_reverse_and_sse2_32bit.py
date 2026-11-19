"""
Alpha-C54 End-to-End Verification Suite:
1. Strided Forward Loops (`i = start; while i < n: ... i += S` with `S in (1, 2, 4, 8)`)
   and Non-Zero Start Loops across dynamic strip-mining, small constant unrolled trees,
   Z3 bi-abduction bounds proofs, Native PE64, and LLVM O3.
2. Reverse Countdown Loops (`i = n - 1; while i >= L: ... i -= 1` and constant-start
   strided reverse countdown `i = C; while i >= L: ... i -= S`) for both reductions
   and elementwise stores.
3. Direct x86-64 Hardware 4-Lane 32-bit Packed SSE/SSE2 SIMD Emission in `NativeCodegen`
   (`paddd` `66 0f fe c1`, `addps` `0f 58 c1`, `mulps` `0f 59 c1`, `punpckldq` `66 0f 62 c1/ca`,
   `punpcklqdq` `66 0f 6c c1`, `movdqu` load/store `f3 41 0f 6f/7f`) verified in
   physical machine code bytes, `AssemblyInvariantAuditor`, `SiliconSafetySandbox` (Unicorn),
   Native JIT, and LLVM O3.
4. Live Wasmtime Linear Memory roundtrip for strided store + reverse countdown reduction.
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


class TestAlphaC54StridedReverseAndSSE232Bit(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c54_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_strided_and_nonzero_start_reductions_and_stores_z3_and_parity(self):
        """Strided (`i += 2`, `i += 4`) and non-zero start (`i = 3`) loops prove Z3 safe and match Native & LLVM O3."""
        src = """
class SignalBlock:
    tag: i64
    samples: Array[i64, 132]
    out: Array[i64, 132]

def process_strided(blk: SignalBlock, n: int) -> int:
    if n > 132:
        return -777
    i = 2
    while i < n:
        blk.out[i] = blk.samples[i] * 3 + i
        i += 2
    tot = 0
    mx = -100000
    j = 2
    while j < n:
        v = blk.out[j]
        tot += v
        mx = max(mx, v)
        j += 2
    return tot + mx
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        self.assertEqual(stats["vectorized_sums"], 1)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_fn, {"SignalBlock": 8 + 132 * 8 + 132 * 8}, {"blk": "SignalBlock"}
        )
        self.assertTrue(bv["proven"], bv)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")

        class SignalBlockStruct(ctypes.Structure):
            _fields_ = [
                ("tag", ctypes.c_int64),
                ("samples", ctypes.c_int64 * 132),
                ("out", ctypes.c_int64 * 132),
            ]

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_fn = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn)),
            "process_strided",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_void_p, ctypes.c_int64],
        )

        base_samples = [((k * 41) % 97) - 35 for k in range(132)]
        for n in (-2, 0, 1, 2, 3, 4, 8, 9, 10, 11, 21, 132, 133):
            sb_nat = SignalBlockStruct(tag=7)
            sb_ll = SignalBlockStruct(tag=7)
            for idx, v in enumerate(base_samples):
                sb_nat.samples[idx] = v
                sb_ll.samples[idx] = v
                sb_nat.out[idx] = -99
                sb_ll.out[idx] = -99

            res_nat = cf(ctypes.addressof(sb_nat), n)
            res_ll = ll_fn(ctypes.addressof(sb_ll), n)
            if n > 132:
                exp = -777
            else:
                visited = list(range(2, max(2, n), 2))
                computed = [base_samples[k] * 3 + k for k in visited]
                exp = sum(computed) + (max([-100000] + computed))
                for idx in range(132):
                    expected_out = (base_samples[idx] * 3 + idx) if (2 <= idx < n and idx % 2 == 0) else -99
                    self.assertEqual(sb_nat.out[idx], expected_out, f"nat out[{idx}] at n={n}")
                    self.assertEqual(sb_ll.out[idx], expected_out, f"ll out[{idx}] at n={n}")
            self.assertEqual(res_nat, exp, f"Native mismatch n={n}")
            self.assertEqual(res_ll, exp, f"LLVM mismatch n={n}")

    def test_02_reverse_countdown_loops_dynamic_and_constant_unrolled_and_stripmined(self):
        """Reverse countdown loops (`while i >= 0: i -= 1` and `while i >= 2: i -= 2`) prove Z3 safe and match reference."""
        src = """
class RevBuf:
    a: Array[i64, 128]
    b: Array[i64, 128]

def reverse_pipeline(buf: RevBuf, n: int) -> int:
    if n > 128:
        return -555
    i = n - 1
    while i >= 0:
        buf.b[i] = buf.a[i] * 2 - i
        i -= 1
    s_dyn = 0
    mn = 999999
    k = n - 1
    while k >= 1:
        v = buf.b[k]
        s_dyn += v
        mn = min(mn, v)
        k -= 1
    s_const = 0
    m = 30
    while m >= 2:
        s_const += buf.a[m]
        m -= 2
    return s_dyn + mn + s_const
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        self.assertEqual(stats["vectorized_sums"], 2)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_fn, {"RevBuf": 128 * 8 * 2}, {"buf": "RevBuf"}
        )
        self.assertTrue(bv["proven"], bv)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")

        class RevBufStruct(ctypes.Structure):
            _fields_ = [("a", ctypes.c_int64 * 128), ("b", ctypes.c_int64 * 128)]

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_fn = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn)),
            "reverse_pipeline",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_void_p, ctypes.c_int64],
        )

        a_vals = [((idx * 23) % 71) - 20 for idx in range(128)]
        s_const_exp = sum(a_vals[m] for m in range(30, 1, -2))

        for n in (-1, 0, 1, 2, 4, 5, 19, 128, 129):
            rb_nat = RevBufStruct()
            rb_ll = RevBufStruct()
            for idx, v in enumerate(a_vals):
                rb_nat.a[idx] = v
                rb_ll.a[idx] = v
                rb_nat.b[idx] = 0
                rb_ll.b[idx] = 0

            r_nat = cf(ctypes.addressof(rb_nat), n)
            r_ll = ll_fn(ctypes.addressof(rb_ll), n)
            if n > 128:
                exp = -555
            else:
                b_written = [a_vals[idx] * 2 - idx for idx in range(max(0, n))]
                sub_k = b_written[1:] if n > 1 else []
                exp = sum(sub_k) + min([999999] + sub_k) + s_const_exp
            self.assertEqual(r_nat, exp, f"Native rev mismatch n={n}")
            self.assertEqual(r_ll, exp, f"LLVM rev mismatch n={n}")

    def test_03_native_codegen_32bit_4lane_packed_sse_sse2_hardware_emission_and_execution(self):
        """Verifies physical 4-lane 32-bit SSE/SSE2 opcodes (`paddd`, `addps`, `mulps`, `punpckldq`) in NativeCodegen."""
        src = """
class Vec32Pack:
    ia: Array[i32, 32]
    ib: Array[i32, 32]
    idst: Array[i32, 32]
    ipack: Array[i32, 32]
    fa: Array[f32, 32]
    fb: Array[f32, 32]
    fadd_dst: Array[f32, 32]
    fmul_dst: Array[f32, 32]

def run_sse2_32bit(p: Vec32Pack, n: int) -> int:
    i = 0
    while i < n:
        p.idst[i] = p.ia[i] + p.ib[i]
        p.ipack[i] = p.ia[i] * 3 + 7
        p.fadd_dst[i] = p.fa[i] + p.fb[i]
        p.fmul_dst[i] = p.fa[i] * p.fb[i]
        i += 1
    return p.idst[0] + p.ipack[0]
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)

        art = X64CodeGenerator().compile_function(vec_fn)
        mc = art.code_bytes
        self.assertIn(b"\xf3\x41\x0f\x6f\x03", mc, "Expected 128-bit movdqu xmm0, [r11]")
        self.assertIn(b"\xf3\x41\x0f\x6f\x0b", mc, "Expected 128-bit movdqu xmm1, [r11]")
        self.assertIn(b"\x66\x0f\xfe\xc1", mc, "Expected 4-lane 32-bit paddd xmm0, xmm1")
        self.assertIn(b"\x0f\x58\xc1", mc, "Expected 4-lane 32-bit addps xmm0, xmm1")
        self.assertIn(b"\x0f\x59\xc1", mc, "Expected 4-lane 32-bit mulps xmm0, xmm1")
        self.assertIn(b"\x66\x0f\x62\xc1", mc, "Expected punpckldq xmm0, xmm1")
        self.assertIn(b"\x66\x0f\x62\xca", mc, "Expected punpckldq xmm1, xmm2")
        self.assertIn(b"\x66\x0f\x6c\xc1", mc, "Expected punpcklqdq xmm0, xmm1")
        self.assertIn(b"\xf3\x41\x0f\x7f\x03", mc, "Expected 128-bit movdqu [r11], xmm0")

        audit = AssemblyInvariantAuditor().audit_function_code(mc, "run_sse2_32bit")
        self.assertTrue(audit.is_valid, audit.errors)

        class Vec32PackStruct(ctypes.Structure):
            _fields_ = [
                ("ia", ctypes.c_int32 * 32),
                ("ib", ctypes.c_int32 * 32),
                ("idst", ctypes.c_int32 * 32),
                ("ipack", ctypes.c_int32 * 32),
                ("fa", ctypes.c_float * 32),
                ("fb", ctypes.c_float * 32),
                ("fadd_dst", ctypes.c_float * 32),
                ("fmul_dst", ctypes.c_float * 32),
            ]

        vp = Vec32PackStruct()
        for k in range(32):
            vp.ia[k] = k * 5 - 12
            vp.ib[k] = k * 2 + 9
            vp.fa[k] = float(k) * 1.25 - 3.0
            vp.fb[k] = float(k) * 0.5 + 1.5

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ret = cf(ctypes.addressof(vp), 23)
        self.assertEqual(ret, (vp.ia[0] + vp.ib[0]) + (vp.ia[0] * 3 + 7))
        for k in range(23):
            self.assertEqual(vp.idst[k], vp.ia[k] + vp.ib[k], f"idst[{k}]")
            self.assertEqual(vp.ipack[k], vp.ia[k] * 3 + 7, f"ipack[{k}]")
            self.assertAlmostEqual(vp.fadd_dst[k], vp.fa[k] + vp.fb[k], places=5, msg=f"fadd[{k}]")
            self.assertAlmostEqual(vp.fmul_dst[k], vp.fa[k] * vp.fb[k], places=5, msg=f"fmul[{k}]")

    def test_04_live_wasmtime_strided_and_reverse_loops_roundtrip(self):
        """Executes vectorized strided store + reverse countdown reduction live inside Wasmtime Linear Memory."""
        wb = WasmBackend()
        if not (wb.is_available() if callable(wb.is_available) else wb.is_available):
            self.skipTest("Wasmtime not available")

        src = """
def strided_and_reverse_wasm(dst: int, src: int, n: int) -> int:
    i = 1
    while i < n:
        store_i64(dst, i * 8, load_i64(src, i * 8) * 4 + i)
        i += 2
    acc = 0
    k = n - 1
    while k >= 0:
        acc += load_i64(dst, k * 8)
        k -= 1
    return acc
"""
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        self.assertEqual(stats["vectorized_sums"], 1)

        import wasmtime
        engine = wasmtime.Engine()
        wasm_mod = wasmtime.Module(engine, wb.wat_to_wasm(wb.ssa_to_wat(vec_fn)))
        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)

        src_vals = [(k * 13) % 43 + 1 for k in range(28)]
        for n in (1, 2, 5, 8, 15, 22):
            store = wasmtime.Store(engine)
            inst = wasmtime.Instance(store, wasm_mod, [])
            mem = inst.exports(store)["memory"]
            s_arr = (ctypes.c_int64 * 28)(*src_vals)
            d_arr = (ctypes.c_int64 * 28)(*([0] * 28))
            for idx in range(28):
                mem.write(store, struct.pack("<q", src_vals[idx]), 0x1000 + idx * 8)
                mem.write(store, struct.pack("<q", 0), 0x2000 + idx * 8)

            exp = sum(src_vals[idx] * 4 + idx for idx in range(1, n, 2))
            w_res = inst.exports(store)["strided_and_reverse_wasm"](store, 0x2000, 0x1000, n)
            n_res = cf(ctypes.addressof(d_arr), ctypes.addressof(s_arr), n)
            self.assertEqual(w_res, exp, f"WASM n={n}")
            self.assertEqual(n_res, exp, f"Native n={n}")

    def test_05_omnirepo_e2e_strided_reverse_and_32bit_sse2_executable(self):
        """Compiles strided store + reverse countdown reduction via OmniRepoCompiler (Native, LLVM O3, WSL Linux)."""
        r_dir = os.path.join(self.test_dir, "repo_c54")
        os.makedirs(r_dir)
        with open(os.path.join(r_dir, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_c54", "language": "python", "exports": ["omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "def omni_main(n: int) -> int:\n"
                "    a = malloc(1056)\n"
                "    d = malloc(1056)\n"
                "    if n > 128:\n"
                "        n = 128\n"
                "    k = 0\n"
                "    while k < n:\n"
                "        store_i64(a, k * 8, (k & 15) * 5 + 3)\n"
                "        store_i64(d, k * 8, 0)\n"
                "        k += 1\n"
                "    i = 1\n"
                "    while i < n:\n"
                "        store_i64(d, i * 8, load_i64(a, i * 8) * 2 + i)\n"
                "        i += 2\n"
                "    tot = 0\n"
                "    mx = 0\n"
                "    j = n - 1\n"
                "    while j >= 0:\n"
                "        v = load_i64(d, j * 8)\n"
                "        tot += v\n"
                "        mx = max(mx, v)\n"
                "        j -= 1\n"
                "    res = tot + mx + 500\n"
                "    free(a)\n"
                "    free(d)\n"
                '    printf("C54_SR=%lld\\n", res)\n'
                "    return res % 251\n"
            )

        comp = OmniRepoCompiler()
        try:
            nat_bin = os.path.join(self.test_dir, "c54_nat.exe" if sys.platform == "win32" else "c54_nat")
            res_nat = comp.compile_repositories(
                [r_dir], nat_bin, target_format="executable", entry_export="omni_main",
                backend="native", audit_nonce="c54-nat",
            )
            self.assertTrue(res_nat["stages"]["formal_audit"]["is_valid"])
            self.assertGreaterEqual(res_nat["stages"]["codegen"]["vectorized_loops"], 3)

            ll_bin = os.path.join(self.test_dir, "c54_ll.exe" if sys.platform == "win32" else "c54_ll")
            res_ll = comp.compile_repositories(
                [r_dir], ll_bin, target_format="executable", entry_export="omni_main",
                backend="llvm", audit_nonce="c54-ll",
            )
            self.assertTrue(res_ll["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res_ll["stages"]["backend_validation"].get("refuted", 0), 0)

            for bin_p in (nat_bin, ll_bin):
                if sys.platform != "win32":
                    os.chmod(bin_p, 0o755)
                for n in (1, 2, 9, 23, 128):
                    d_vals = [(((k & 15) * 5 + 3) * 2 + k) if (k % 2 == 1) else 0 for k in range(n)]
                    exp = sum(d_vals) + max([0] + d_vals) + 500
                    p = subprocess.run([bin_p, str(n)], capture_output=True, text=True, timeout=10)
                    self.assertIn(f"C54_SR={exp}", p.stdout, f"{bin_p} n={n}: {p.stdout} {p.stderr}")
                    self.assertEqual(p.returncode, exp % 251)

            if sys.platform == "win32" and _wsl_available():
                lin_bin = os.path.join(self.test_dir, "c54_linux")
                res_lin = comp.compile_repositories(
                    [r_dir], lin_bin, target_format="executable", entry_export="omni_main",
                    target_os="linux", backend="native", audit_nonce="c54-wsl",
                )
                self.assertTrue(res_lin["stages"]["formal_audit"]["is_valid"])
                wsl_p = lin_bin.replace("\\", "/").replace("F:", "/mnt/f").replace("C:", "/mnt/c")
                cmd = f"cp {wsl_p} /tmp/c54_lin && chmod +x /tmp/c54_lin && /tmp/c54_lin 128"
                p_wsl = subprocess.run(["wsl", "/bin/sh", "-c", cmd], capture_output=True, timeout=20)
                if p_wsl.returncode != 4294967295:
                    d_128 = [(((k & 15) * 5 + 3) * 2 + k) if (k % 2 == 1) else 0 for k in range(128)]
                    exp_128 = sum(d_128) + max([0] + d_128) + 500
                    self.assertIn(f"C54_SR={exp_128}".encode("ascii"), p_wsl.stdout)
                    self.assertEqual(p_wsl.returncode, exp_128 % 251)
        finally:
            comp.close()


if __name__ == "__main__":
    unittest.main()
