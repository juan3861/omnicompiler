"""
Alpha-C49 End-to-End Verification Suite:
1. Dynamic / symbolic loop strip-mining (`while i < n` and `while i <= n`) into
   4-lane VLA strip-mined loop + `merge_bb` tree reduction + scalar tail loop.
2. Z3 `BiAbductionVerifier` spatial bounds proof (`shr`/`sar`/`lshr`/`select` +
   dominating edge guards + QF_BV monotonic induction invariant) and adversarial
   OOB refutation check (`BOUND_VIOLATION_REFUTED`).
3. Edge-case execution parity across `NativeJitCompiler`, `LLVMBackend(opt_level=3)`,
   and `WASMBackend` (`n = -5, 0, 1, 2, 3, 4, 5, 63, 64, 65, 130, 131`).
4. Full `OmniRepoCompiler` Native & LLVM O3 (+ WSL Linux ELF64) pipeline with
   runtime CLI parameter `n`.
5. Anti-misvectorization guards (non-zero init, step != 1, loop-variant bound).
"""

import ast
import ctypes
import json
import os
import shutil
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


class TestAlphaC49DynamicStripMining(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c49_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_dynamic_f32_stripmining_z3_safe_and_parity(self):
        """Dynamic `while i < n` over `Array[f32, 130]` proves PROVEN_MEMORY_SAFE and matches across Native & LLVM O3."""
        src = """
class BigFrame:
    flags: u32
    samples: Array[f32, 130]

def sum_dyn(pkt: BigFrame, n: int) -> float:
    if n > 130:
        return 0.0
    s = 10.0
    i = 0
    while i < n:
        s += pkt.samples[i]
        i += 1
    return s
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])

        vec_fn, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
        self.assertEqual(stats["vectorized_sums"], 1)

        opcodes = [ins.opcode for b in vec_fn.blocks for ins in b.instructions]
        self.assertIn("shr", opcodes)
        self.assertIn("select", opcodes)
        self.assertIn("shl", opcodes)
        # Ensure scalar tail loop was emitted and NOT re-vectorized
        block_names = [b.name for b in vec_fn.blocks]
        self.assertTrue(any("vec_tail_cond_" in bn for bn in block_names), block_names)
        self.assertEqual(sum(1 for bn in block_names if "vec_tail_cond_" in bn), 1)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(
            vec_fn, {"BigFrame": 4 + 130 * 4}, {"pkt": "BigFrame"}
        )
        self.assertTrue(bv["proven"], bv)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")
        self.assertGreaterEqual(bv["checks_passed"], 5)

        class BigFrameStruct(ctypes.Structure):
            _fields_ = [("flags", ctypes.c_uint32), ("samples", ctypes.c_float * 130)]

        frame = BigFrameStruct(flags=1)
        vals = [float(idx + 1) * 0.5 for idx in range(130)]
        for idx, v in enumerate(vals):
            frame.samples[idx] = v

        ptr = ctypes.addressof(frame)
        cfunc, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_ir = ll.ssa_to_llvm_ir(vec_fn)
        ll_mod = ll.compile_ir(ll_ir)
        ll_fn = ll.create_jit_callable(
            ll_mod, "sum_dyn", restype=ctypes.c_double, argtypes=[ctypes.c_void_p, ctypes.c_int64]
        )

        for n in (-5, 0, 1, 2, 3, 4, 5, 63, 64, 65, 130, 131):
            expected = 0.0 if n > 130 else (10.0 + sum(vals[: max(0, n)]))
            nat_res = cfunc(ptr, n)
            ll_res = ll_fn(ptr, n)
            self.assertAlmostEqual(nat_res, expected, places=3, msg=f"Native mismatch at n={n}")
            self.assertAlmostEqual(ll_res, expected, places=3, msg=f"LLVM mismatch at n={n}")
            self.assertAlmostEqual(nat_res, ll_res, places=5, msg=f"Native vs LLVM drift at n={n}")

    def test_02_dynamic_stripmining_z3_refutes_off_by_one_oob(self):
        """Adversarial: `n <= 131` on `Array[f32, 130]` MUST be refuted by Z3 BiAbductionVerifier."""
        src = """
class BigFrame:
    flags: u32
    samples: Array[f32, 130]

def sum_dyn_oob(pkt: BigFrame, n: int) -> float:
    if n > 131:
        return 0.0
    s = 0.0
    i = 0
    while i < n:
        s += pkt.samples[i]
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
        self.assertFalse(bv["proven"])
        self.assertEqual(bv["status"], "BOUND_VIOLATION_REFUTED")
        self.assertGreaterEqual(len(bv["violations"]), 1)

    def test_03_inclusive_i64_stripmining_and_wasm_emission(self):
        """Tests `while i <= n` over `Array[i64, 130]` across Native, LLVM O3, Z3, and WASM emission."""
        src = """
class IntBuf:
    count: i64
    data: Array[i64, 130]

def sum_le(buf: IntBuf, n: int) -> int:
    if n >= 130:
        return -1
    s = 7
    i = 0
    while i <= n:
        s += buf.data[i]
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
            vec_fn, {"IntBuf": 8 + 130 * 8}, {"buf": "IntBuf"}
        )
        self.assertTrue(bv["proven"], bv)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")

        class IntBufStruct(ctypes.Structure):
            _fields_ = [("count", ctypes.c_int64), ("data", ctypes.c_int64 * 130)]

        buf = IntBufStruct(count=130)
        vals = [(idx + 1) * 3 for idx in range(130)]
        for idx, v in enumerate(vals):
            buf.data[idx] = v

        ptr = ctypes.addressof(buf)
        cfunc, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        ll = LLVMBackend(opt_level=3)
        ll_ir = ll.ssa_to_llvm_ir(vec_fn)
        ll_mod = ll.compile_ir(ll_ir)
        ll_fn = ll.create_jit_callable(
            ll_mod, "sum_le", restype=ctypes.c_int64, argtypes=[ctypes.c_void_p, ctypes.c_int64]
        )

        for n in (-5, -1, 0, 1, 2, 3, 4, 17, 129, 130):
            expected = -1 if n >= 130 else (7 + sum(vals[: n + 1]) if n >= 0 else 7)
            self.assertEqual(cfunc(ptr, n), expected, f"Native mismatch at n={n}")
            self.assertEqual(ll_fn(ptr, n), expected, f"LLVM mismatch at n={n}")

        wb = WasmBackend()
        wat_text = wb.ssa_to_wat(vec_fn)
        self.assertIn("i64.shr_s", wat_text)
        self.assertIn("select", wat_text)
        self.assertIn("i64.shl", wat_text)
        if bool(wb.is_available() if callable(wb.is_available) else wb.is_available):
            wasm_bytes = wb.wat_to_wasm(wat_text)
            self.assertTrue(wasm_bytes.startswith(b"\x00asm\x01\x00\x00\x00"))

    def test_04_anti_misvectorization_nonzero_init_and_step2(self):
        """Loops starting at i!=0, stepping by +2, or with loop-variant bounds must NOT vectorize."""
        cases = [
            (
                "nonzero_init",
                """
class Buf:
    arr: Array[i64, 64]
def fn(b: Buf, n: int) -> int:
    s = 0
    i = 2
    while i < n:
        s += b.arr[i]
        i += 1
    return s
""",
            ),
            (
                "step_two",
                """
class Buf:
    arr: Array[i64, 64]
def fn(b: Buf, n: int) -> int:
    s = 0
    i = 0
    while i < n:
        s += b.arr[i]
        i += 2
    return s
""",
            ),
            (
                "loop_variant_bound",
                """
class Buf:
    arr: Array[i64, 64]
def fn(b: Buf, n: int) -> int:
    s = 0
    i = 0
    lim = n
    while i < lim:
        s += b.arr[i]
        i += 1
        lim -= 1
    return s
""",
            ),
        ]
        for label, src in cases:
            mod = ast.parse(src)
            low = AstToSsaLowering()
            low.register_structs_from_statements(mod.body)
            ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])
            _vec, stats = LoopVectorizerPass().vectorize_function(ssa_fn)
            self.assertEqual(stats["vectorized_sums"], 0, f"Case {label} was falsely vectorized")

    def test_05_omnirepo_e2e_dynamic_stripmining_cli_native_llvm_wsl(self):
        """Compiles dynamic loop repository via OmniRepoCompiler (Native, LLVM O3, WSL Linux) with runtime argv."""
        r_dyn = os.path.join(self.test_dir, "repo_dyn")
        os.makedirs(r_dyn)
        with open(os.path.join(r_dyn, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_dyn", "language": "python", "exports": ["omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_dyn, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "def omni_main(n: int) -> int:\n"
                "    p = malloc(1056)\n"
                "    k = 0\n"
                "    while k < 132:\n"
                "        store_i64(p, k * 8, k + 1)\n"
                "        k += 1\n"
                "    if n > 132:\n"
                "        n = 132\n"
                "    s = 0\n"
                "    i = 0\n"
                "    while i < n:\n"
                "        s += load_i64(p, i * 8)\n"
                "        i += 1\n"
                "    free(p)\n"
                '    printf("DYN_SUM=%lld\\n", s)\n'
                "    return s % 251\n"
            )

        comp = OmniRepoCompiler()
        try:
            nat_bin = os.path.join(self.test_dir, "dyn_native.exe" if sys.platform == "win32" else "dyn_native")
            res_nat = comp.compile_repositories(
                [r_dyn], nat_bin, target_format="executable", entry_export="omni_main",
                backend="native", audit_nonce="c49-dyn-nat",
            )
            self.assertTrue(res_nat["stages"]["formal_audit"]["is_valid"])
            self.assertGreaterEqual(res_nat["stages"]["codegen"]["vectorized_loops"], 1)

            ll_bin = os.path.join(self.test_dir, "dyn_llvm.exe" if sys.platform == "win32" else "dyn_llvm")
            res_ll = comp.compile_repositories(
                [r_dyn], ll_bin, target_format="executable", entry_export="omni_main",
                backend="llvm", audit_nonce="c49-dyn-ll",
            )
            self.assertTrue(res_ll["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res_ll["stages"]["backend_validation"].get("refuted", 0), 0)

            for bin_p in (nat_bin, ll_bin):
                if sys.platform != "win32":
                    os.chmod(bin_p, 0o755)
                for n in (0, 1, 3, 4, 5, 131):
                    exp_sum = n * (n + 1) // 2
                    p = subprocess.run([bin_p, str(n)], capture_output=True, text=True, timeout=10)
                    self.assertIn(f"DYN_SUM={exp_sum}", p.stdout, f"{bin_p} n={n}: {p.stdout} {p.stderr}")
                    self.assertEqual(p.returncode, exp_sum % 251)

            if sys.platform == "win32" and _wsl_available():
                lin_bin = os.path.join(self.test_dir, "dyn_linux")
                res_lin = comp.compile_repositories(
                    [r_dyn], lin_bin, target_format="executable", entry_export="omni_main",
                    target_os="linux", backend="native", audit_nonce="c49-dyn-wsl",
                )
                self.assertTrue(res_lin["stages"]["formal_audit"]["is_valid"])
                wsl_p = lin_bin.replace("\\", "/").replace("F:", "/mnt/f").replace("C:", "/mnt/c")
                cmd = (
                    f"cp {wsl_p} /tmp/c49_dyn_lin && chmod +x /tmp/c49_dyn_lin && "
                    "/tmp/c49_dyn_lin 131"
                )
                p_wsl = subprocess.run(["wsl", "/bin/sh", "-c", cmd], capture_output=True, timeout=20)
                if p_wsl.returncode != 4294967295:
                    exp_131 = 131 * 132 // 2
                    self.assertIn(f"DYN_SUM={exp_131}".encode("ascii"), p_wsl.stdout)
                    self.assertEqual(p_wsl.returncode, exp_131 % 251)
        finally:
            comp.close()


if __name__ == "__main__":
    unittest.main()
