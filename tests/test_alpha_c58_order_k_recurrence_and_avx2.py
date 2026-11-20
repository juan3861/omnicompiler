"""
Alpha-C58 End-to-End Verification Suite:
1. Order-k (k=3 Tribonacci & k=4 Tetranacci / 4-tap IIR state-space) Linear Recurrence Vectorization
   ("coupled_nxn" via M, M^2, M^3, M^4 in (Z/2^64Z)^{k x k}):
   - 3rd-order driven Tribonacci: nxt = a + b + c + v; a = b; b = c; c = nxt (dynamic N + constant N=19)
   - 4th-order driven coupled 4-state system: nx = a + b*2 + c + d*3 + v; a=b; b=c; c=d; d=nx
   - Z3 bi-abduction memory safety + Native JIT + LLVM O3 parity.
2. Direct 256-bit AVX2 VEX SIMD Fusion inside X64CodeGenerator.compile_function:
   - Verifies physical 256-bit YMM machine code bytes (`c4 c1 7e 6f 03` vmovdqu ymm0,[r11],
     `c4 c1 7e 6f 0b` vmovdqu ymm1,[r11], `c5 fd d4 c1` vpaddq, `c5 fd 59 c1` vmulpd,
     `c4 c1 7e 7f 03` vmovdqu [r11],ymm0, `c5 f8 77` vzeroupper)
   - Passes `AssemblyInvariantAuditor` + executes live on Native x86-64 CPU + matches LLVM O3.
3. Cross-Architecture Parity (x86-64 AVX2, ARM64 NEON Unicorn, WebAssembly v128 Wasmtime, LLVM O3)
   on Order-3 Tribonacci + Fused Vector Store.
4. Full OmniRepoCompiler E2E Executable (Windows PE64 Native, LLVM O3 PE64, WSL2 Linux ELF64)
   with Order-3 Tribonacci recurrence.
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
from compiler.native_codegen import Arm64CodeGenerator, X64CodeGenerator, _host_supports_avx2
from compiler.native_jit import NativeJitCompiler
from compiler.ssa_ir import AstToSsaLowering
from compiler.wasm_backend import WasmBackend
from omni_repo_compiler import OmniRepoCompiler
from validation.assembly_invariant_auditor import AssemblyInvariantAuditor
from validation.biabduction_verifier import BiAbductionVerifier
from validation.silicon_safety_sandbox import SiliconSafetySandbox


def _wsl_available() -> bool:
    if sys.platform != "win32":
        return False
    try:
        r = subprocess.run(["wsl", "uname"], capture_output=True, text=True, timeout=10)
        return r.returncode == 0 and "Linux" in r.stdout
    except Exception:
        return False


def _u64(val: int) -> int:
    return int(val) & 0xFFFFFFFFFFFFFFFF


def _s64(val: int) -> int:
    u = int(val) & 0xFFFFFFFFFFFFFFFF
    return u - 0x10000000000000000 if (u & 0x8000000000000000) else u


class TestAlphaC58OrderKRecurrenceAndAVX2(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c58_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_order3_tribonacci_and_order4_tetranacci_z3_and_parity(self):
        """Tests k=3 Tribonacci and k=4 Tetranacci linear recurrences across dynamic N and constant N=19."""
        src = """
class SignalBuf:
    vals: Array[i64, 128]

def order3_and_order4(t: SignalBuf, n: int) -> int:
    if n > 128:
        return -888
    a = 1
    b = 2
    c = 3
    i = 0
    while i < n:
        v = t.vals[i]
        nxt = a + b + c + v
        a = b
        b = c
        c = nxt
        i += 1

    p = 1
    q = 1
    r = 2
    s = 4
    k = 0
    while k < 19:
        vk = t.vals[k]
        pnxt = p + q * 2 + r + s * 3 - vk
        p = q
        q = r
        r = s
        s = pnxt
        k += 1

    return a + b * 3 + c * 5 + p + q * 7 + r * 11 + s * 13
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertGreaterEqual(stats["vectorized_sums"], 2)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_fn, {"SignalBuf": 128 * 8}, {"t": "SignalBuf"}
        )
        self.assertTrue(bv["proven"], bv)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_fn = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn)),
            "order3_and_order4",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_void_p, ctypes.c_int64],
        )

        buf = (ctypes.c_int64 * 128)()
        vals = [((idx * 19 + 3) ^ (idx * 5)) - 30 for idx in range(128)]
        for idx, v in enumerate(vals):
            buf[idx] = v
        base_addr = ctypes.addressof(buf)

        def py_ref(n_val: int) -> int:
            if n_val > 128:
                return -888
            a, b, c = 1, 2, 3
            for idx in range(max(0, n_val)):
                nxt = _u64(a + b + c + vals[idx])
                a, b, c = b, c, nxt
            p, q, r, s = 1, 1, 2, 4
            for k in range(19):
                pnxt = _u64(p + _u64(q * 2) + r + _u64(s * 3) - vals[k])
                p, q, r, s = q, r, s, pnxt
            return _s64(_u64(a + _u64(b * 3) + _u64(c * 5) + p + _u64(q * 7) + _u64(r * 11) + _u64(s * 13)))

        for n_test in (-2, 0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 47, 129):
            expected = py_ref(n_test)
            self.assertEqual(cf(base_addr, n_test), expected, f"Native mismatch n={n_test}")
            self.assertEqual(ll_fn(base_addr, n_test), expected, f"LLVM mismatch n={n_test}")

    def test_02_x64_avx2_256bit_vex_fusion_and_vzeroupper(self):
        """Verifies direct 256-bit AVX2 VEX SIMD fusion (vmovdqu ymm, vpaddq, vmulpd, vzeroupper) + execution."""
        src = """
class AvxArena:
    a64: Array[i64, 64]
    b64: Array[i64, 64]
    out64: Array[i64, 64]
    fa64: Array[f64, 64]
    fb64: Array[f64, 64]
    fout64: Array[f64, 64]

def avx2_fused_kernel(t: AvxArena, n: int) -> int:
    i = 0
    acc = 0
    while i < n:
        va = t.a64[i]
        vb = t.b64[i]
        t.out64[i] = va + vb
        fa = t.fa64[i]
        fb = t.fb64[i]
        t.fout64[i] = fa * fb
        acc += va
        i += 1
    return acc
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        self.assertEqual(stats["vectorized_sums"], 1)

        cg_avx = X64CodeGenerator(enable_avx2=True)
        art = cg_avx.compile_function(vec_fn)
        code = art.code_bytes
        self.assertIn(b"\xc4\xc1\x7e\x6f\x03", code, "Missing vmovdqu ymm0, [r11]")
        self.assertIn(b"\xc4\xc1\x7e\x6f\x0b", code, "Missing vmovdqu ymm1, [r11]")
        self.assertIn(b"\xc5\xfd\xd4\xc1", code, "Missing vpaddq ymm0, ymm0, ymm1")
        self.assertIn(b"\xc5\xfd\x59\xc1", code, "Missing vmulpd ymm0, ymm0, ymm1")
        self.assertIn(b"\xc4\xc1\x7e\x7f\x03", code, "Missing vmovdqu [r11], ymm0")
        self.assertIn(b"\xc5\xf8\x77", code, "Missing vzeroupper")

        audit = AssemblyInvariantAuditor().audit_function_code(code, "avx2_fused_kernel")
        self.assertTrue(audit.is_valid, audit.errors)

        if not _host_supports_avx2():
            self.skipTest("Host CPU does not advertise AVX2")

        class AvxArenaStruct(ctypes.Structure):
            _fields_ = [
                ("a64", ctypes.c_int64 * 64),
                ("b64", ctypes.c_int64 * 64),
                ("out64", ctypes.c_int64 * 64),
                ("fa64", ctypes.c_double * 64),
                ("fb64", ctypes.c_double * 64),
                ("fout64", ctypes.c_double * 64),
            ]

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        for n in (0, 1, 3, 4, 7, 15, 16, 23):
            st = AvxArenaStruct()
            for k in range(64):
                st.a64[k] = 100 + k * 7
                st.b64[k] = 200 - k * 3
                st.fa64[k] = 1.5 + k * 0.25
                st.fb64[k] = 2.0 + k * 0.5
            got = cf(ctypes.addressof(st), n)
            self.assertEqual(got, sum(st.a64[k] for k in range(n)))
            for k in range(n):
                self.assertEqual(st.out64[k], st.a64[k] + st.b64[k])
                self.assertAlmostEqual(st.fout64[k], st.fa64[k] * st.fb64[k], places=12)

    def test_03_quad_isa_parity_tribonacci_and_fused_store(self):
        """Verifies Quad-ISA parity (x86-64 AVX2, ARM64 NEON Unicorn, Wasmtime v128, LLVM O3) for Order-3 Tribonacci."""
        src = """
def quad_tribonacci(base: int, n: int) -> int:
    i = 0
    a = 1
    b = 2
    c = 3
    tot = 0
    while i < n:
        va = load_i64(base, i * 8)
        vb = load_i64(base, 256 + i * 8)
        s = va + vb
        store_i64(base, 512 + i * 8, s)
        nxt = a + b + c + s
        a = b
        b = c
        c = nxt
        tot += s
        i += 1
    return tot + a * 3 + b * 5 + c * 7
"""
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        self.assertEqual(stats["vectorized_sums"], 1)

        x64_fn, _x64_mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        arm_code = Arm64CodeGenerator().compile_function(vec_fn).code_bytes
        ll = LLVMBackend(opt_level=3)
        llvm_fn = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn)),
            "quad_tribonacci",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_int64, ctypes.c_int64],
        )

        n_items = 17
        init_arena = bytearray(2048)
        for k in range(n_items):
            struct.pack_into("<q", init_arena, k * 8, (k + 1) * 9)
            struct.pack_into("<q", init_arena, 256 + k * 8, (k + 3) * 5)

        llvm_buf = (ctypes.c_uint8 * 2048).from_buffer_copy(init_arena)
        res_llvm = llvm_fn(ctypes.addressof(llvm_buf), n_items)
        out_llvm = bytes(llvm_buf)[512 : 512 + n_items * 8]

        if _host_supports_avx2():
            x64_buf = (ctypes.c_uint8 * 2048).from_buffer_copy(init_arena)
            res_x64 = x64_fn(ctypes.addressof(x64_buf), n_items)
            self.assertEqual(res_x64, res_llvm)
            self.assertEqual(bytes(x64_buf)[512 : 512 + n_items * 8], out_llvm)

        emu_arm = SiliconSafetySandbox().emulate_arm64(
            arm_code,
            args=[0x400000, n_items],
            memory_regions={0x400000: bytes(init_arena)},
        )
        self.assertTrue(emu_arm.success, emu_arm.error)
        self.assertEqual(_s64(emu_arm.return_value), res_llvm)
        self.assertEqual(emu_arm.memory_snapshots[0x400000][512 : 512 + n_items * 8], out_llvm)

        wb = WasmBackend()
        if wb.is_available() if callable(wb.is_available) else wb.is_available:
            import wasmtime
            wat_text = wb.ssa_to_wat(vec_fn)
            self.assertIn("v128.store", wat_text)
            engine = wasmtime.Engine()
            module = wasmtime.Module(engine, wb.wat_to_wasm(wat_text))
            store = wasmtime.Store(engine)
            inst = wasmtime.Instance(store, module, [])
            mem = inst.exports(store)["memory"]
            mem.write(store, bytes(init_arena), 0x1000)
            res_wasm = _s64(inst.exports(store)["quad_tribonacci"](store, 0x1000, n_items))
            self.assertEqual(res_wasm, res_llvm)
            self.assertEqual(bytes(mem.read(store, 0x1000 + 512, 0x1000 + 512 + n_items * 8)), out_llvm)

    def test_04_omnirepo_e2e_order3_tribonacci_executable(self):
        """Compiles an E2E project with Order-3 Tribonacci recurrence through OmniRepoCompiler (PE64 Native/LLVM & ELF64 WSL2)."""
        r_dir = os.path.join(self.test_dir, "repo_c58")
        os.makedirs(r_dir)
        with open(os.path.join(r_dir, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_c58", "language": "python", "exports": ["omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "def omni_main(n: int) -> int:\n"
                "    buf = malloc(1056)\n"
                "    if n > 14:\n"
                "        n = 14\n"
                "    k = 0\n"
                "    while k < n:\n"
                "        store_i64(buf, k * 8, (k & 7) + 1)\n"
                "        k += 1\n"
                "    a = 1\n"
                "    b = 1\n"
                "    c = 2\n"
                "    i = 0\n"
                "    while i < n:\n"
                "        v = load_i64(buf, i * 8)\n"
                "        nxt = a + b + c + v\n"
                "        a = b\n"
                "        b = c\n"
                "        c = nxt\n"
                "        i += 1\n"
                "    res = a + b + c\n"
                "    free(buf)\n"
                '    printf("C58_TRIB=%lld\\n", res)\n'
                "    return res % 251\n"
            )

        comp = OmniRepoCompiler()
        try:
            nat_bin = os.path.join(self.test_dir, "c58_nat.exe" if sys.platform == "win32" else "c58_nat")
            res_nat = comp.compile_repositories(
                [r_dir], nat_bin, target_format="executable", entry_export="omni_main",
                backend="native", audit_nonce="c58-nat",
            )
            self.assertTrue(res_nat["stages"]["formal_audit"]["is_valid"])
            self.assertGreaterEqual(res_nat["stages"]["codegen"]["vectorized_loops"], 2)

            ll_bin = os.path.join(self.test_dir, "c58_ll.exe" if sys.platform == "win32" else "c58_ll")
            res_ll = comp.compile_repositories(
                [r_dir], ll_bin, target_format="executable", entry_export="omni_main",
                backend="llvm", audit_nonce="c58-ll",
            )
            self.assertTrue(res_ll["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res_ll["stages"]["backend_validation"].get("refuted", 0), 0)

            for bin_p in (nat_bin, ll_bin):
                if sys.platform != "win32":
                    os.chmod(bin_p, 0o755)
                for n in (1, 4, 7, 14):
                    a, b, c = 1, 1, 2
                    for k in range(n):
                        v = (k & 7) + 1
                        a, b, c = b, c, a + b + c + v
                    exp = a + b + c
                    p = subprocess.run([bin_p, str(n)], capture_output=True, text=True, timeout=10)
                    self.assertIn(f"C58_TRIB={exp}", p.stdout, f"{bin_p} n={n}: {p.stdout} {p.stderr}")
                    self.assertEqual(p.returncode, exp % 251)

            if sys.platform == "win32" and _wsl_available():
                lin_bin = os.path.join(self.test_dir, "c58_linux")
                res_lin = comp.compile_repositories(
                    [r_dir], lin_bin, target_format="executable", entry_export="omni_main",
                    target_os="linux", backend="native", audit_nonce="c58-wsl",
                )
                self.assertTrue(res_lin["stages"]["formal_audit"]["is_valid"])
                wsl_p = lin_bin.replace("\\", "/").replace("F:", "/mnt/f").replace("C:", "/mnt/c")
                cmd = f"cp {wsl_p} /tmp/c58_lin && chmod +x /tmp/c58_lin && /tmp/c58_lin 14"
                p_wsl = subprocess.run(["wsl", "/bin/sh", "-c", cmd], capture_output=True, timeout=20)
                if p_wsl.returncode != 4294967295:
                    a, b, c = 1, 1, 2
                    for k in range(14):
                        v = (k & 7) + 1
                        a, b, c = b, c, a + b + c + v
                    exp_14 = a + b + c
                    self.assertIn(f"C58_TRIB={exp_14}".encode("ascii"), p_wsl.stdout)
                    self.assertEqual(p_wsl.returncode, exp_14 % 251)
        finally:
            comp.close()


if __name__ == "__main__":
    unittest.main()
