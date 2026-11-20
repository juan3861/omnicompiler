"""
Alpha-C57 End-to-End Verification Suite:
1. Coupled 2-State & Second-Order Linear Recurrence Vectorization ("coupled_2x2") via 2x2 Matrix Exponentiation
   (M, M^2, M^3, M^4 in (Z/2^64Z)^{2x2}):
   - Driven 2nd-order Fibonacci/Lucas recurrence: nxt = a + b + v; a = b; b = nxt
   - Coupled 2D linear state system: nx = x * 3 + y * 2 + v; ny = x + y * 5 - v
   - Small constant bound unrolled 2x2 recurrence (k < 19)
2. Direct 128-bit ARM64 NEON / ASIMD Hardware Emission in Arm64CodeGenerator:
   - 64-bit 2-lane vector loads/stores/ALU (LDR Q0, LDR Q1, STR Q0, ADD V0.2D, FMUL V0.2D)
   - 64-bit 4-to-1 horizontal reduction collapse (ADD V0.2D + ADDP D0, V0.2D + UMOV X9, V0.D[1])
   - 32-bit 4-lane vector loads/stores/ALU (ADD V0.4S, FMUL V0.4S)
   - Live execution in SiliconSafetySandbox.emulate_arm64 (Unicorn UC_ARCH_ARM64) with memory_regions
3. Cross-Architecture Quad-ISA Parity (x86-64 SSE2, ARM64 NEON, WebAssembly v128, LLVM O3 JIT).
4. Single-pass Fused Store + Inclusive Prefix Scan + Coupled 2x2 Recurrence + Max Reduction Pipeline.
5. Full OmniRepoCompiler E2E PE64 Native, PE64 LLVM O3, and WSL2 Linux ELF64 executables.
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
from compiler.native_codegen import Arm64CodeGenerator
from compiler.native_jit import NativeJitCompiler
from compiler.ssa_ir import AstToSsaLowering
from compiler.wasm_backend import WasmBackend
from omni_repo_compiler import OmniRepoCompiler
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


class TestAlphaC57Coupled2x2AndArm64Neon(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c57_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_coupled_2x2_second_order_fibonacci_and_state_space_z3_and_parity(self):
        """
        Tests coupled 2-state & second-order linear recurrences via 2x2 matrix exponentiation:
        - Driven 2nd-order Fibonacci recurrence: nxt = a + b + v; a = b; b = nxt
        - Coupled 2D linear state system: nx = x * 3 + y * 2 + v; ny = x + y * 5 - v
        - Small constant bound unrolled 2x2 recurrence (k < 19)
        """
        src = """
class Telemetry:
    vals: Array[i64, 128]

def coupled_recurrences(t: Telemetry, n: int) -> int:
    if n > 128:
        return -777
    i = 0
    a = 1
    b = 2
    x = 3
    y = 5
    while i < n:
        v = t.vals[i]
        nxt = a + b + v
        a = b
        b = nxt
        nx = x * 3 + y * 2 + v
        ny = x + y * 5 - v
        x = nx
        y = ny
        i += 1

    k = 0
    fa = 1
    fb = 1
    while k < 19:
        fv = t.vals[k]
        fnxt = fa + fb + fv
        fa = fb
        fb = fnxt
        k += 1

    return a + b * 3 + x * 7 + y * 11 + fa + fb
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertGreaterEqual(stats["vectorized_sums"], 2)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_fn, {"Telemetry": 128 * 8}, {"t": "Telemetry"}
        )
        self.assertTrue(bv["proven"], bv)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_fn = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn)),
            "coupled_recurrences",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_void_p, ctypes.c_int64],
        )

        buf = (ctypes.c_int64 * 128)()
        vals = [((idx * 17 + 5) ^ (idx * 3)) - 40 for idx in range(128)]
        for idx, v in enumerate(vals):
            buf[idx] = v
        base_addr = ctypes.addressof(buf)

        def py_ref(n_val: int) -> int:
            if n_val > 128:
                return -777
            a, b = 1, 2
            x, y = 3, 5
            for idx in range(max(0, n_val)):
                v = vals[idx]
                nxt = _u64(a + b + v)
                a, b = b, nxt
                nx = _u64(_u64(x * 3) + _u64(y * 2) + v)
                ny = _u64(_u64(x + _u64(y * 5)) - v)
                x, y = nx, ny
            fa, fb = 1, 1
            for k in range(19):
                fnxt = _u64(fa + fb + vals[k])
                fa, fb = fb, fnxt
            return _s64(_u64(a + _u64(b * 3) + _u64(x * 7) + _u64(y * 11) + fa + fb))

        for n_test in (-3, 0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 47, 129):
            expected = py_ref(n_test)
            got_native = cf(base_addr, n_test)
            got_llvm = ll_fn(base_addr, n_test)
            self.assertEqual(got_native, expected, f"Native mismatch for n={n_test}: {got_native} != {expected}")
            self.assertEqual(got_llvm, expected, f"LLVM mismatch for n={n_test}: {got_llvm} != {expected}")

    def test_02_arm64_neon_128bit_simd_store_pair_quad_and_addp_unicorn_execution(self):
        """
        Verifies direct 128-bit ARM64 NEON / ASIMD code generation and live Unicorn emulation:
        - 64-bit 2-lane vector loads/stores/ALU (LDR Q0, LDR Q1, STR Q0, ADD V0.2D, FMUL V0.2D)
        - 64-bit 4-to-1 horizontal reduction collapse (ADD V0.2D + ADDP D0, V0.2D + UMOV X9, V0.D[1])
        - 32-bit 4-lane vector loads/stores/ALU (ADD V0.4S, FMUL V0.4S)
        """
        src = """
class NeonBuf:
    a64: Array[i64, 32]
    b64: Array[i64, 32]
    out64: Array[i64, 32]
    fa64: Array[f64, 32]
    fb64: Array[f64, 32]
    fout64: Array[f64, 32]
    a32: Array[i32, 64]
    b32: Array[i32, 64]
    out32: Array[i32, 64]
    fa32: Array[f32, 64]
    fb32: Array[f32, 64]
    fout32: Array[f32, 64]

def neon_kernel(t: NeonBuf, n: int) -> int:
    i = 0
    acc = 0
    while i < n:
        va = t.a64[i]
        vb = t.b64[i]
        t.out64[i] = va + vb
        fa = t.fa64[i]
        fb = t.fb64[i]
        t.fout64[i] = fa * fb
        va32 = t.a32[i]
        vb32 = t.b32[i]
        t.out32[i] = va32 + vb32
        fa32 = t.fa32[i]
        fb32 = t.fb32[i]
        t.fout32[i] = fa32 * fb32
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

        arm_gen = Arm64CodeGenerator()
        arm_bytes = arm_gen.compile_function(vec_fn).code_bytes
        words = [struct.unpack_from("<I", arm_bytes, off)[0] for off in range(0, len(arm_bytes), 4)]

        # Physical ARM64 NEON 128-bit opcodes
        self.assertIn(0x3DC00120, words, "Missing LDR Q0, [X9] (0x3DC00120)")
        self.assertIn(0x3DC00121, words, "Missing LDR Q1, [X9] (0x3DC00121)")
        self.assertIn(0x3D800120, words, "Missing STR Q0, [X9] (0x3D800120)")
        self.assertIn(0x4EE18400, words, "Missing ADD V0.2D, V0.2D, V1.2D (0x4EE18400)")
        self.assertIn(0x6E61DC00, words, "Missing FMUL V0.2D, V0.2D, V1.2D (0x6E61DC00)")
        self.assertIn(0x4EA18400, words, "Missing ADD V0.4S, V0.4S, V1.4S (0x4EA18400)")
        self.assertIn(0x6E21DC00, words, "Missing FMUL V0.4S, V0.4S, V1.4S (0x6E21DC00)")
        self.assertIn(0x4E181D60, words, "Missing INS V0.D[1], X11 (0x4E181D60)")
        self.assertIn(0x5EF1B800, words, "Missing ADDP D0, V0.2D (0x5EF1B800)")

        # Prepare 4KB memory region at 0x400000 for live Unicorn ARM64 emulation
        mem_buf = bytearray(4096)
        n_items = 14
        a64_vals = [100 + k * 7 for k in range(n_items)]
        b64_vals = [200 + k * 3 for k in range(n_items)]
        fa64_vals = [1.5 + k * 0.25 for k in range(n_items)]
        fb64_vals = [2.0 + k * 0.5 for k in range(n_items)]
        a32_vals = [10 + k * 5 for k in range(n_items)]
        b32_vals = [30 + k * 2 for k in range(n_items)]
        fa32_vals = [0.5 + k * 0.5 for k in range(n_items)]
        fb32_vals = [4.0 - k * 0.25 for k in range(n_items)]

        for k in range(n_items):
            struct.pack_into("<q", mem_buf, 0 + k * 8, a64_vals[k])
            struct.pack_into("<q", mem_buf, 256 + k * 8, b64_vals[k])
            struct.pack_into("<d", mem_buf, 768 + k * 8, fa64_vals[k])
            struct.pack_into("<d", mem_buf, 1024 + k * 8, fb64_vals[k])
            struct.pack_into("<i", mem_buf, 1536 + k * 4, a32_vals[k])
            struct.pack_into("<i", mem_buf, 1792 + k * 4, b32_vals[k])
            struct.pack_into("<f", mem_buf, 2304 + k * 4, fa32_vals[k])
            struct.pack_into("<f", mem_buf, 2560 + k * 4, fb32_vals[k])

        sandbox = SiliconSafetySandbox()
        emu = sandbox.emulate_arm64(
            arm_bytes,
            args=[0x400000, n_items],
            memory_regions={0x400000: bytes(mem_buf)},
        )
        self.assertTrue(emu.success, f"ARM64 NEON Unicorn emulation failed: {emu.error}")
        self.assertEqual(emu.return_value, sum(a64_vals))

        snap = emu.memory_snapshots[0x400000]
        for k in range(n_items):
            got_out64 = struct.unpack_from("<q", snap, 512 + k * 8)[0]
            got_fout64 = struct.unpack_from("<d", snap, 1280 + k * 8)[0]
            got_out32 = struct.unpack_from("<i", snap, 2048 + k * 4)[0]
            got_fout32 = struct.unpack_from("<f", snap, 2816 + k * 4)[0]
            self.assertEqual(got_out64, a64_vals[k] + b64_vals[k])
            self.assertAlmostEqual(got_fout64, fa64_vals[k] * fb64_vals[k], places=12)
            self.assertEqual(got_out32, a32_vals[k] + b32_vals[k])
            self.assertAlmostEqual(got_fout32, fa32_vals[k] * fb32_vals[k], places=6)

    def test_03_cross_arch_quad_isa_parity_x64_sse2_arm64_neon_wasm_v128_llvm(self):
        """
        Compiles and executes a unified vectorized fused store + coupled 2-state recurrence + reduction
        kernel across all 4 targets:
        1. x86-64 SSE2 Native JIT
        2. ARM64 NEON in Unicorn (UC_ARCH_ARM64)
        3. WebAssembly v128 SIMD in Wasmtime
        4. LLVM O3 Native JIT
        """
        src = """
def quad_isa_kernel(base: int, n: int) -> int:
    i = 0
    fa = 1
    fb = 2
    tot = 0
    while i < n:
        va = load_i64(base, i * 8)
        vb = load_i64(base, 256 + i * 8)
        s = va + vb
        store_i64(base, 512 + i * 8, s)
        fnxt = fa + fb + s
        fa = fb
        fb = fnxt
        tot += s
        i += 1
    return tot + fa * 3 + fb * 5
"""
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        self.assertEqual(stats["vectorized_sums"], 1)

        # 1. x86-64 SSE2
        x64_fn, _x64_mem, _ = NativeJitCompiler().compile_ssa(vec_fn)

        # 2. ARM64 NEON
        arm_gen = Arm64CodeGenerator()
        arm_code = arm_gen.compile_function(vec_fn).code_bytes

        # 3. LLVM O3
        ll = LLVMBackend(opt_level=3)
        llvm_fn = ll.create_jit_callable(
            ll.compile_ir(ll.ssa_to_llvm_ir(vec_fn)),
            "quad_isa_kernel",
            restype=ctypes.c_int64,
            argtypes=[ctypes.c_int64, ctypes.c_int64],
        )

        n_items = 19
        init_arena = bytearray(2048)
        for k in range(n_items):
            struct.pack_into("<q", init_arena, 0 + k * 8, (k + 1) * 11)
            struct.pack_into("<q", init_arena, 256 + k * 8, (k + 2) * 7)

        # Run x86-64
        x64_buf = (ctypes.c_uint8 * 2048).from_buffer_copy(init_arena)
        res_x64 = x64_fn(ctypes.addressof(x64_buf), n_items)
        out_x64 = bytes(x64_buf)[512 : 512 + n_items * 8]

        # Run LLVM O3
        llvm_buf = (ctypes.c_uint8 * 2048).from_buffer_copy(init_arena)
        res_llvm = llvm_fn(ctypes.addressof(llvm_buf), n_items)
        out_llvm = bytes(llvm_buf)[512 : 512 + n_items * 8]

        # Run ARM64 NEON in Unicorn
        sandbox = SiliconSafetySandbox()
        emu_arm = sandbox.emulate_arm64(
            arm_code,
            args=[0x400000, n_items],
            memory_regions={0x400000: bytes(init_arena)},
        )
        self.assertTrue(emu_arm.success, emu_arm.error)
        res_arm = _s64(emu_arm.return_value)
        out_arm = emu_arm.memory_snapshots[0x400000][512 : 512 + n_items * 8]

        self.assertEqual(res_x64, res_llvm)
        self.assertEqual(res_arm, res_llvm)
        self.assertEqual(out_x64, out_llvm)
        self.assertEqual(out_arm, out_llvm)

        # 4. Run WebAssembly v128 in Wasmtime
        wb = WasmBackend()
        if wb.is_available() if callable(wb.is_available) else wb.is_available:
            wat_text = wb.ssa_to_wat(vec_fn)
            self.assertIn("v128.store", wat_text)
            import wasmtime

            engine = wasmtime.Engine()
            module = wasmtime.Module(engine, wb.wat_to_wasm(wat_text))
            store = wasmtime.Store(engine)
            instance = wasmtime.Instance(store, module, [])
            wasm_mem = instance.exports(store)["memory"]
            wasm_base = 0x1000
            wasm_mem.write(store, bytes(init_arena), wasm_base)
            wasm_fn = instance.exports(store)["quad_isa_kernel"]
            res_wasm = _s64(wasm_fn(store, wasm_base, n_items))
            out_wasm = bytes(wasm_mem.read(store, wasm_base + 512, wasm_base + 512 + n_items * 8))
            self.assertEqual(res_wasm, res_llvm)
            self.assertEqual(out_wasm, out_llvm)

    def test_04_fused_store_and_coupled_2x2_recurrence_pipeline(self):
        """
        Tests single-pass fusion of vector store, inclusive prefix scan, coupled 2-state recurrence,
        and max reduction in one loop.
        """
        src = """
class FusedState:
    inp: Array[i64, 64]
    doubled: Array[i64, 64]
    scan: Array[i64, 64]

def fused_coupled_pipeline(t: FusedState, n: int) -> int:
    i = 0
    a = 2
    b = 3
    pref = 0
    mx = -999999
    while i < n:
        v = t.inp[i]
        d = v * 2
        t.doubled[i] = d
        pref += v
        t.scan[i] = pref
        nxt = a + b + d
        a = b
        b = nxt
        mx = max(mx, d)
        i += 1
    return a + b + pref + mx
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])
        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_stores"], 1)
        self.assertEqual(stats["vectorized_sums"], 1)

        cf, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        vals = [((k * 13) ^ 7) - 25 for k in range(48)]
        for n_test in (0, 1, 3, 4, 7, 8, 15, 16, 23):
            raw = bytearray(4096)
            for k, v in enumerate(vals):
                struct.pack_into("<q", raw, k * 8, v)
            c_buf = (ctypes.c_uint8 * 4096).from_buffer_copy(raw)
            got = cf(ctypes.addressof(c_buf), n_test)

            a, b, pref, mx = 2, 3, 0, -999999
            exp_doubled = []
            exp_scan = []
            for k in range(n_test):
                v = vals[k]
                d = v * 2
                exp_doubled.append(d)
                pref = _s64(_u64(pref + v))
                exp_scan.append(pref)
                nxt = _s64(_u64(a + b + d))
                a, b = b, nxt
                if d > mx:
                    mx = d
            exp_ret = _s64(_u64(a + b + pref + mx))
            self.assertEqual(got, exp_ret, f"Mismatch at n={n_test}: {got} != {exp_ret}")
            out_bytes = bytes(c_buf)
            for k in range(n_test):
                self.assertEqual(struct.unpack_from("<q", out_bytes, 512 + k * 8)[0], exp_doubled[k])
                self.assertEqual(struct.unpack_from("<q", out_bytes, 1024 + k * 8)[0], exp_scan[k])

    def test_05_omnirepo_e2e_coupled_2x2_executable(self):
        """
        Compiles an E2E project with coupled 2x2 recurrence through OmniRepoCompiler across
        Windows PE64 Native, Windows PE64 LLVM O3, and WSL2 Linux ELF64.
        """
        r_dir = os.path.join(self.test_dir, "repo_c57")
        os.makedirs(r_dir)
        with open(os.path.join(r_dir, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_c57", "language": "python", "exports": ["omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "def omni_main(n: int) -> int:\n"
                "    buf = malloc(1056)\n"
                "    if n > 15:\n"
                "        n = 15\n"
                "    k = 0\n"
                "    while k < n:\n"
                "        store_i64(buf, k * 8, (k & 7) + 1)\n"
                "        k += 1\n"
                "    a = 1\n"
                "    b = 2\n"
                "    i = 0\n"
                "    while i < n:\n"
                "        v = load_i64(buf, i * 8)\n"
                "        nxt = a + b + v\n"
                "        a = b\n"
                "        b = nxt\n"
                "        i += 1\n"
                "    res = a + b\n"
                "    free(buf)\n"
                '    printf("C57_COUPLED=%lld\\n", res)\n'
                "    return res % 251\n"
            )

        comp = OmniRepoCompiler()
        try:
            nat_bin = os.path.join(self.test_dir, "c57_nat.exe" if sys.platform == "win32" else "c57_nat")
            res_nat = comp.compile_repositories(
                [r_dir], nat_bin, target_format="executable", entry_export="omni_main",
                backend="native", audit_nonce="c57-nat",
            )
            self.assertTrue(res_nat["stages"]["formal_audit"]["is_valid"])
            self.assertGreaterEqual(res_nat["stages"]["codegen"]["vectorized_loops"], 2)

            ll_bin = os.path.join(self.test_dir, "c57_ll.exe" if sys.platform == "win32" else "c57_ll")
            res_ll = comp.compile_repositories(
                [r_dir], ll_bin, target_format="executable", entry_export="omni_main",
                backend="llvm", audit_nonce="c57-ll",
            )
            self.assertTrue(res_ll["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res_ll["stages"]["backend_validation"].get("refuted", 0), 0)

            for bin_p in (nat_bin, ll_bin):
                if sys.platform != "win32":
                    os.chmod(bin_p, 0o755)
                for n in (1, 4, 7, 15):
                    a, b = 1, 2
                    for k in range(n):
                        v = (k & 7) + 1
                        a, b = b, a + b + v
                    exp = a + b
                    p = subprocess.run([bin_p, str(n)], capture_output=True, text=True, timeout=10)
                    self.assertIn(f"C57_COUPLED={exp}", p.stdout, f"{bin_p} n={n}: {p.stdout} {p.stderr}")
                    self.assertEqual(p.returncode, exp % 251)

            if sys.platform == "win32" and _wsl_available():
                lin_bin = os.path.join(self.test_dir, "c57_linux")
                res_lin = comp.compile_repositories(
                    [r_dir], lin_bin, target_format="executable", entry_export="omni_main",
                    target_os="linux", backend="native", audit_nonce="c57-wsl",
                )
                self.assertTrue(res_lin["stages"]["formal_audit"]["is_valid"])
                wsl_p = lin_bin.replace("\\", "/").replace("F:", "/mnt/f").replace("C:", "/mnt/c")
                cmd = f"cp {wsl_p} /tmp/c57_lin && chmod +x /tmp/c57_lin && /tmp/c57_lin 15"
                p_wsl = subprocess.run(["wsl", "/bin/sh", "-c", cmd], capture_output=True, timeout=20)
                if p_wsl.returncode != 4294967295:
                    a, b = 1, 2
                    for k in range(15):
                        v = (k & 7) + 1
                        a, b = b, a + b + v
                    exp_15 = a + b
                    self.assertIn(f"C57_COUPLED={exp_15}".encode("ascii"), p_wsl.stdout)
                    self.assertEqual(p_wsl.returncode, exp_15 % 251)
        finally:
            comp.close()


if __name__ == "__main__":
    unittest.main()
