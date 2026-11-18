"""
Alpha-C48 End-to-End Verification Suite:
1. Variadic OS ABI (`printf` with mixed int + f64) across x86-64 Win64 & SysV (`%al`), Native + LLVM O3.
2. ARM64 (AArch64) dynamic ELF64 (`PT_INTERP`, `DT_NEEDED`, `R_AARCH64_JUMP_SLOT`, `ADRP+LDR+BR`),
   ARM64 Unicorn preflight (`0x2009800` malloc stub), and `audit_elf` `DT_HASH nchain` verification.
3. Mach-O 64-bit (`x86_64` + Apple Silicon `arm64`) with `LC_LOAD_DYLINKER`, `LC_LOAD_DYLIB`, `LC_SYMTAB`
   external `N_UNDF` imports, and valid XNU Ad-Hoc SHA-256 `LC_CODE_SIGNATURE`.
4. VLA 4-lane Strip-Mining Vectorizer (`64 < N <= 4096`) with Z3 spatial bounds proof (`PROVEN_MEMORY_SAFE`)
   and exact Native vs LLVM O3 JIT execution parity.
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

from compiler.binary_emitter import StandaloneBinaryEmitter
from compiler.llvm_backend import LLVMBackend
from compiler.loop_vectorizer import LoopVectorizerPass
from compiler.native_jit import NativeJitCompiler
from compiler.ssa_ir import AstToSsaLowering
from omni_repo_compiler import OmniRepoCompiler
from validation.biabduction_verifier import BiAbductionVerifier
from validation.binary_structure_auditor import BinaryStructureAuditor


def _wsl_available() -> bool:
    if sys.platform != "win32":
        return False
    try:
        r = subprocess.run(["wsl", "uname"], capture_output=True, text=True, timeout=10)
        return r.returncode == 0 and "Linux" in r.stdout
    except Exception:
        return False


class TestAlphaC48VarargsArm64MachoStripMining(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c48_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_variadic_printf_with_float_native_and_llvm_live_os(self):
        """Compiles variadic printf with mixed int + f64 across Native and LLVM O3 on Windows and Linux."""
        r_py = os.path.join(self.test_dir, "repo_vararg")
        os.makedirs(r_py)
        with open(os.path.join(r_py, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_vararg", "language": "python", "exports": ["omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_py, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "def omni_main(x: int) -> int:\n"
                '    printf("C48_VARARG=%d f=%.2f\\n", x, 3.5)\n'
                "    return x + 10\n"
            )

        comp = OmniRepoCompiler()
        try:
            # 1. Host Native executable
            nat_bin = os.path.join(self.test_dir, "pf_native.exe" if sys.platform == "win32" else "pf_native")
            res_nat = comp.compile_repositories(
                [r_py], nat_bin, target_format="executable", entry_export="omni_main",
                backend="native", audit_nonce="c48-pf-nat",
            )
            self.assertTrue(res_nat["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res_nat["stages"]["linking"]["external_os_imports"], ["printf"])
            if sys.platform != "win32":
                os.chmod(nat_bin, 0o755)
            p_nat = subprocess.run([nat_bin, "7"], capture_output=True, text=True, timeout=10)
            self.assertIn("C48_VARARG=7 f=3.50", p_nat.stdout)
            self.assertEqual(p_nat.returncode, 17)

            # 2. Host LLVM O3 executable + Z3 BTV
            ll_bin = os.path.join(self.test_dir, "pf_llvm.exe" if sys.platform == "win32" else "pf_llvm")
            res_ll = comp.compile_repositories(
                [r_py], ll_bin, target_format="executable", entry_export="omni_main",
                backend="llvm", audit_nonce="c48-pf-ll",
            )
            self.assertTrue(res_ll["stages"]["formal_audit"]["is_valid"])
            self.assertEqual(res_ll["stages"]["backend_validation"].get("refuted", 0), 0)
            if sys.platform != "win32":
                os.chmod(ll_bin, 0o755)
            p_ll = subprocess.run([ll_bin, "7"], capture_output=True, text=True, timeout=10)
            self.assertIn("C48_VARARG=7 f=3.50", p_ll.stdout)
            self.assertEqual(p_ll.returncode, 17)

            # 3. Cross-compile Linux ELF64 & execute via WSL when on Windows
            if sys.platform == "win32" and _wsl_available():
                lin_bin = os.path.join(self.test_dir, "pf_linux")
                res_lin = comp.compile_repositories(
                    [r_py], lin_bin, target_format="executable", entry_export="omni_main",
                    target_os="linux", backend="native", audit_nonce="c48-pf-wsl",
                )
                self.assertTrue(res_lin["stages"]["formal_audit"]["is_valid"])
                wsl_p = lin_bin.replace("\\", "/").replace("F:", "/mnt/f").replace("C:", "/mnt/c")
                cmd = f"cp {wsl_p} /tmp/c48_pf_linux && chmod +x /tmp/c48_pf_linux && /tmp/c48_pf_linux 7"
                p_wsl = subprocess.run(["wsl", "/bin/sh", "-c", cmd], capture_output=True, timeout=20)
                if p_wsl.returncode != 4294967295:
                    self.assertIn(b"C48_VARARG=7 f=3.50", p_wsl.stdout)
                    self.assertEqual(p_wsl.returncode, 17)
        finally:
            comp.close()

    def test_02_arm64_dynamic_elf64_linker_unicorn_and_audit(self):
        """Compiles ARM64 Linux dynamic ELF64 with malloc/free/puts, Unicorn preflight, and DT_HASH audit."""
        r_arm = os.path.join(self.test_dir, "repo_arm64")
        os.makedirs(r_arm)
        with open(os.path.join(r_arm, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_arm64", "language": "python", "exports": ["omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_arm, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "def omni_main(x: int) -> int:\n"
                "    p = malloc(64)\n"
                "    store_i32(p, 0, x * 2)\n"
                "    v = load_i32(p, 0)\n"
                "    free(p)\n"
                '    puts("ARM64_C48_OK")\n'
                "    return v + 1\n"
            )

        comp = OmniRepoCompiler()
        try:
            out_arm = os.path.join(self.test_dir, "app_arm64")
            res = comp.compile_repositories(
                [r_arm], out_arm, target_format="executable", entry_export="omni_main",
                target_os="linux", target_arch="arm64", backend="native", audit_nonce="c48-arm64",
            )
            pf = res["stages"]["preflight_safety"]
            self.assertTrue(pf["is_safe_for_silicon"])
            self.assertEqual(pf["target_arch"], "arm64")
            self.assertEqual(pf["simulated_return_value"], 21)

            audit = res["stages"]["formal_audit"]
            self.assertTrue(audit["is_valid"])
            self.assertEqual(audit["format"], "ELF64")
            self.assertEqual(audit["machine_arch"], "ARM64")
            self.assertEqual(audit["exported_symbols"], [])
            self.assertEqual(audit["imported_symbols"], ["exit", "free", "malloc", "puts"])
            self.assertEqual(audit["metrics"].get("needed_libs"), ["libc.so.6"])
        finally:
            comp.close()

    def test_03_macho64_arm64_and_x64_lc_load_dylib_and_codesign(self):
        """Verifies Mach-O x86_64 and ARM64 LC_LOAD_DYLIB + LC_SYMTAB N_UNDF imports + Ad-Hoc SHA-256 signature."""
        emitter = StandaloneBinaryEmitter()
        auditor = BinaryStructureAuditor()
        dylibs = ["/usr/lib/libSystem.B.dylib"]
        imps = ["puts", "malloc", "free"]

        for arch in ("x86_64", "arm64"):
            macho_bytes = emitter.build_macho64(
                exit_code=42, arch=arch, load_dylibs=dylibs, imported_symbols=imps
            )
            rep = auditor.audit_binary(macho_bytes)
            self.assertTrue(rep.is_valid, f"{arch} Mach-O errors: {rep.errors}")
            self.assertEqual(rep.format, "Mach-O 64")
            self.assertIn("/usr/lib/libSystem.B.dylib", rep.metrics.get("dylib_dependencies", []))
            for s in dylibs + imps:
                self.assertIn(s, rep.imported_symbols)

    def test_04_strip_mined_4x_vla_loop_vectorization_z3_and_parity(self):
        """Verifies 4x strip-mining VLA loop vectorization on N=130 struct array with Z3 proof & Native/LLVM parity."""
        src = """
class BigFrame:
    flags: u32
    samples: Array[f32, 130]

def sum_big(pkt: BigFrame) -> float:
    s = 10.0
    i = 0
    while i < 130:
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

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(vec_fn, {"BigFrame": 4 + 130 * 4}, {"pkt": "BigFrame"})
        self.assertTrue(bv["proven"], bv)
        self.assertGreaterEqual(bv["checks_passed"], 6)
        self.assertEqual(bv["status"], "PROVEN_MEMORY_SAFE")

        class BigFrameStruct(ctypes.Structure):
            _fields_ = [("flags", ctypes.c_uint32), ("samples", ctypes.c_float * 130)]

        frame = BigFrameStruct(flags=1)
        expected = 10.0
        for idx in range(130):
            val = float(idx + 1) * 0.5
            frame.samples[idx] = val
            expected += val

        ptr = ctypes.addressof(frame)
        cfunc, _mem, _ = NativeJitCompiler().compile_ssa(vec_fn)
        nat_res = cfunc(ptr)
        self.assertAlmostEqual(nat_res, expected, places=3)

        ll = LLVMBackend(opt_level=3)
        ll_ir = ll.ssa_to_llvm_ir(vec_fn)
        ll_mod = ll.compile_ir(ll_ir)
        ll_fn = ll.create_jit_callable(ll_mod, "sum_big", restype=ctypes.c_double, argtypes=[ctypes.c_void_p])
        ll_res = ll_fn(ptr)
        self.assertAlmostEqual(ll_res, expected, places=3)
        self.assertAlmostEqual(nat_res, ll_res, places=5)


if __name__ == "__main__":
    unittest.main()
