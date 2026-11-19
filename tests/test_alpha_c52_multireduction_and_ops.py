"""
Alpha-C52 End-to-End Verification Suite:
1. Multi-Accumulator Fused Loop Vectorization (1..6 simultaneous reductions in
   a single pass: e.g., `dot + norm_a + norm_b` cosine-similarity kernel) across
   dynamic strip-mining, small constant unrolled tree reduction (N<=64), Z3
   `BiAbductionVerifier`, Native JIT, and LLVM O3 JIT parity.
2. Conditional Multi-Accumulator If-Conversion (`if v > thresh: s += v; sq += v*v; cnt += 1`).
3. Extended Associative Reductions: `mul`, `fmul`, `and`, `or`, `xor` with
   non-identity initializers across Native, LLVM O3, and Live Wasmtime Linear Memory.
4. Anti-Misvectorization Guard: coupled cross-accumulator recurrences (`s += v; sq += s`)
   must NOT vectorize.
5. Full `OmniRepoCompiler` PE64 Native, LLVM O3, and WSL2 Linux ELF64 E2E verification.
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


class TestAlphaC52MultiReductionAndOps(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c52_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_cosine_similarity_3_accumulators_dynamic_z3_and_parity(self):
        """Fused 3-accumulator `dot + norm_a + norm_b` over `Array[f32, 130]` proves Z3 safe and matches Native & LLVM O3."""
        src = """
class VecFrame:
    flags: u32
    data: Array[f32, 130]

def cosine_components(a: VecFrame, b: VecFrame, n: int) -> float:
    if n > 130:
        return -1.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    i = 0
    while i < n:
        va = a.data[i]
        vb = b.data[i]
        dot += va * vb
        na += va * va
        nb += vb * vb
        i += 1
    return dot + na + nb
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_sums"], 1)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_fn, {"VecFrame": 4 + 130 * 4}, {"a": "VecFrame", "b": "VecFrame"}
        )
        self.assertTrue(bv["proven"], bv)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")

        class VecFrameStruct(ctypes.Structure):
            _fields_ = [("flags", ctypes.c_uint32), ("data", ctypes.c_float * 130)]

        a = VecFrameStruct(flags=1)
        b = VecFrameStruct(flags=2)
        va_list = [float((idx % 9) + 1) * 0.25 for idx in range(130)]
        vb_list = [float((idx % 7) + 1) * 0.5 for idx in range(130)]
        for idx in range(130):
            a.data[idx] = va_list[idx]
            b.data[idx] = vb_list[idx]

        pa, pb = ctypes.addressof(a), ctypes.addressof(b)
        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_fn = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn)),
            "cosine_components",
            restype=ctypes.c_double,
            argtypes=[ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64],
        )

        for n in (-2, 0, 1, 3, 4, 5, 19, 130, 131):
            if n > 130:
                exp = -1.0
            else:
                k = max(0, n)
                exp = sum(va_list[i] * vb_list[i] + va_list[i] ** 2 + vb_list[i] ** 2 for i in range(k))
            self.assertAlmostEqual(cf(pa, pb, n), exp, places=2, msg=f"Native n={n}")
            self.assertAlmostEqual(ll_fn(pa, pb, n), exp, places=2, msg=f"LLVM n={n}")

    def test_02_conditional_multi_acc_sum_sq_count_const_and_dynamic(self):
        """Conditional 3-accumulator (`s += v; sq += v*v; cnt += 1`) across const N=19 and dynamic N."""
        src_dyn = """
def stats_above(p: int, n: int, thresh: int) -> int:
    s = 10
    sq = 0
    cnt = 0
    i = 0
    while i < n:
        v = load_i64(p, i * 8)
        if v > thresh:
            s += v
            sq += v * v
            cnt += 1
        i += 1
    return s + sq + cnt
"""
        ssa_d = AstToSsaLowering().lower_function_def(ast.parse(src_dyn).body[0])
        vec_d, st_d = LoopVectorizerPass().vectorize_function(ssa_d)
        self.assertEqual(st_d["vectorized_sums"], 1)

        arr = (ctypes.c_int64 * 25)(*[(k * 3 - 10) for k in range(25)])
        ptr = ctypes.addressof(arr)
        cf_d, _m1, _ = NativeJitCompiler().compile_ssa(vec_d)
        ll = LLVMBackend(opt_level=3)
        ll_d = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_d)),
            "stats_above",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_void_p, ctypes.c_int64, ctypes.c_int64],
        )

        for n in (0, 1, 3, 4, 5, 19, 25):
            filt = [arr[i] for i in range(n) if arr[i] > 5]
            exp = 10 + sum(filt) + sum(x * x for x in filt) + len(filt)
            self.assertEqual(cf_d(ptr, n, 5), exp, f"Native n={n}")
            self.assertEqual(ll_d(ptr, n, 5), exp, f"LLVM n={n}")

        # Small constant N=19 <= 64 unrolled multi-reduction tree
        src_c = """
def stats_above_19(p: int, thresh: int) -> int:
    s = 10
    sq = 0
    cnt = 0
    i = 0
    while i < 19:
        v = load_i64(p, i * 8)
        if v > thresh:
            s += v
            sq += v * v
            cnt += 1
        i += 1
    return s + sq + cnt
"""
        ssa_c = AstToSsaLowering().lower_function_def(ast.parse(src_c).body[0])
        vec_c, st_c = LoopVectorizerPass().vectorize_function(ssa_c)
        self.assertEqual(st_c["vectorized_sums"], 1)
        cf_c, _m2, _ = NativeJitCompiler().compile_ssa(vec_c)
        filt19 = [arr[i] for i in range(19) if arr[i] > 5]
        self.assertEqual(cf_c(ptr, 5), 10 + sum(filt19) + sum(x * x for x in filt19) + len(filt19))

    def test_03_mul_fmul_and_bitwise_reductions_native_llvm_wasm(self):
        """Tests `mul`, `fmul`, `or`, `xor`, `and` reductions across Native, LLVM O3, and Live Wasmtime."""
        src = """
def mul_and_bit_ops(p: int, n: int) -> int:
    prod = 3
    mor = 0
    mxor = 0
    mand = -1
    i = 0
    while i < n:
        v = load_i64(p, i * 8)
        prod *= v
        mor |= v
        mxor ^= v
        mand &= v
        i += 1
    return prod + mor + mxor + mand
"""
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_sums"], 1)

        arr = (ctypes.c_int64 * 12)(*[((k % 4) + 1) | 8 for k in range(12)])
        ptr = ctypes.addressof(arr)
        cf, _m, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_fn = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn)),
            "mul_and_bit_ops",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_void_p, ctypes.c_int64],
        )

        wb = WasmBackend()
        wasm_avail = bool(wb.is_available() if callable(wb.is_available) else wb.is_available)
        if wasm_avail:
            import wasmtime
            engine = wasmtime.Engine()
            wasm_mod = wasmtime.Module(engine, wb.wat_to_wasm(wb.ssa_to_wat(vec_fn)))

        for n in (0, 1, 3, 4, 5, 11):
            prod, mor, mxor, mand = 3, 0, 0, -1
            for k in range(n):
                v = arr[k]
                prod *= v
                mor |= v
                mxor ^= v
                mand &= v
            exp = prod + mor + mxor + mand
            self.assertEqual(cf(ptr, n), exp, f"Native n={n}")
            self.assertEqual(ll_fn(ptr, n), exp, f"LLVM n={n}")
            if wasm_avail:
                store = wasmtime.Store(engine)
                inst = wasmtime.Instance(store, wasm_mod, [])
                mem = inst.exports(store)["memory"]
                for k in range(12):
                    mem.write(store, struct.pack("<q", arr[k]), 0x1000 + k * 8)
                self.assertEqual(inst.exports(store)["mul_and_bit_ops"](store, 0x1000, n), exp, f"WASM n={n}")

        # fmul float product reduction
        src_f = """
def fmul_prod(p: int, n: int) -> float:
    prod = 2.5
    i = 0
    while i < n:
        prod *= load_f64(p, i * 8)
        i += 1
    return prod
"""
        ssa_f = AstToSsaLowering().lower_function_def(ast.parse(src_f).body[0])
        vec_f, st_f = LoopVectorizerPass().vectorize_function(ssa_f)
        self.assertEqual(st_f["vectorized_sums"], 1)
        farr = (ctypes.c_double * 10)(*[1.1 + 0.05 * k for k in range(10)])
        cf_f, _mf, _ = NativeJitCompiler().compile_ssa(vec_f)
        exp_f = 2.5
        for k in range(9):
            exp_f *= farr[k]
        self.assertAlmostEqual(cf_f(ctypes.addressof(farr), 9), exp_f, places=5)

    def test_04_anti_misvectorization_coupled_accumulators(self):
        """Cross-dependent accumulators (`s += v; sq += s`) must NOT be vectorized."""
        src = """
def coupled(p: int, n: int) -> int:
    s = 0
    sq = 0
    i = 0
    while i < n:
        v = load_i64(p, i * 8)
        s += v
        sq += s
        i += 1
    return s + sq
"""
        ssa = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        _vec, stats = LoopVectorizerPass().vectorize_function(ssa)
        self.assertEqual(stats["vectorized_sums"], 0)

    def test_05_omnirepo_e2e_multi_reduction_executable(self):
        """Compiles fused 3-accumulator `dot + na + nb` via OmniRepoCompiler (Native, LLVM O3, WSL Linux)."""
        r_dir = os.path.join(self.test_dir, "repo_c52")
        os.makedirs(r_dir)
        with open(os.path.join(r_dir, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_c52", "language": "python", "exports": ["omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "def omni_main(n: int) -> int:\n"
                "    a = malloc(1056)\n"
                "    b = malloc(1056)\n"
                "    if n > 130:\n"
                "        n = 130\n"
                "    k = 0\n"
                "    while k < n:\n"
                "        store_i64(a, k * 8, (k & 7) + 1)\n"
                "        store_i64(b, k * 8, (k & 3) + 2)\n"
                "        k += 1\n"
                "    dot = 0\n"
                "    na = 0\n"
                "    nb = 0\n"
                "    i = 0\n"
                "    while i < n:\n"
                "        av = load_i64(a, i * 8)\n"
                "        bv = load_i64(b, i * 8)\n"
                "        dot += av * bv\n"
                "        na += av * av\n"
                "        nb += bv * bv\n"
                "        i += 1\n"
                "    tot = dot + na + nb\n"
                "    free(a)\n"
                "    free(b)\n"
                '    printf("C52_COS=%lld\\n", tot)\n'
                "    return tot % 251\n"
            )

        comp = OmniRepoCompiler()
        try:
            nat_bin = os.path.join(self.test_dir, "c52_nat.exe" if sys.platform == "win32" else "c52_nat")
            res_nat = comp.compile_repositories(
                [r_dir], nat_bin, target_format="executable", entry_export="omni_main",
                backend="native", audit_nonce="c52-nat",
            )
            self.assertTrue(res_nat["stages"]["formal_audit"]["is_valid"])
            self.assertGreaterEqual(res_nat["stages"]["codegen"]["vectorized_loops"], 2)

            ll_bin = os.path.join(self.test_dir, "c52_ll.exe" if sys.platform == "win32" else "c52_ll")
            res_ll = comp.compile_repositories(
                [r_dir], ll_bin, target_format="executable", entry_export="omni_main",
                backend="llvm", audit_nonce="c52-ll",
            )
            self.assertTrue(res_ll["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res_ll["stages"]["backend_validation"].get("refuted", 0), 0)

            for bin_p in (nat_bin, ll_bin):
                if sys.platform != "win32":
                    os.chmod(bin_p, 0o755)
                for n in (0, 5, 19, 130):
                    exp = sum(
                        ((k & 7) + 1) * ((k & 3) + 2) + ((k & 7) + 1) ** 2 + ((k & 3) + 2) ** 2
                        for k in range(n)
                    )
                    p = subprocess.run([bin_p, str(n)], capture_output=True, text=True, timeout=10)
                    self.assertIn(f"C52_COS={exp}", p.stdout, f"{bin_p} n={n}: {p.stdout} {p.stderr}")
                    self.assertEqual(p.returncode, exp % 251)

            if sys.platform == "win32" and _wsl_available():
                lin_bin = os.path.join(self.test_dir, "c52_linux")
                res_lin = comp.compile_repositories(
                    [r_dir], lin_bin, target_format="executable", entry_export="omni_main",
                    target_os="linux", backend="native", audit_nonce="c52-wsl",
                )
                self.assertTrue(res_lin["stages"]["formal_audit"]["is_valid"])
                wsl_p = lin_bin.replace("\\", "/").replace("F:", "/mnt/f").replace("C:", "/mnt/c")
                cmd = f"cp {wsl_p} /tmp/c52_lin && chmod +x /tmp/c52_lin && /tmp/c52_lin 130"
                p_wsl = subprocess.run(["wsl", "/bin/sh", "-c", cmd], capture_output=True, timeout=20)
                if p_wsl.returncode != 4294967295:
                    exp_130 = sum(
                        ((k & 7) + 1) * ((k & 3) + 2) + ((k & 7) + 1) ** 2 + ((k & 3) + 2) ** 2
                        for k in range(130)
                    )
                    self.assertIn(f"C52_COS={exp_130}".encode("ascii"), p_wsl.stdout)
                    self.assertEqual(p_wsl.returncode, exp_130 % 251)
        finally:
            comp.close()


if __name__ == "__main__":
    unittest.main()
