"""
Alpha-C64 Final Engineering Seal:
Hardware CPUID Discovery, VEX 256-bit FMA (`vfmadd213pd`/`vfmadd213sd`),
EVEX 512-bit AVX-512 Encoder (`vmovdqu64`/`vpaddq`/`vfmadd213pd zmm`), Dual-Target
Canary-Verified `GCCBackend` (ELF64 SysV + Windows PE/COFF), & Full Capstone Homeostasis.
"""

import ast
import ctypes
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from compiler.gcc_backend import GCCBackend, _to_wsl_path
from compiler.homeostasis_router import HomeostasisRouter
from compiler.loop_vectorizer import LoopVectorizerPass
from compiler.native_codegen import X64CodeGenerator, detect_host_simd_features
from compiler.native_jit import NativeJitCompiler
from compiler.object_linker import load_coff_object, load_elf_object
from compiler.ssa_ir import AstToSsaLowering
from omni_repo_compiler import OmniRepoCompiler
from validation.biabduction_verifier import BiAbductionVerifier


def _make_fma_vec_ssa():
    src = """
class FmaArena:
    a: Array[f64, 32]
    b: Array[f64, 32]
    c: Array[f64, 32]
    out: Array[f64, 32]

def fma_vec_kernel(t: FmaArena, n: int) -> float:
    if n < 0:
        return -1.0
    if n > 32:
        return -2.0
    i = 0
    acc = 0.0
    while i < n:
        va = t.a[i]
        vb = t.b[i]
        vc = t.c[i]
        y = va * vb + vc
        t.out[i] = y
        acc += y
        i += 1
    return acc
"""
    mod = ast.parse(src)
    low = AstToSsaLowering()
    low.register_structs_from_statements(mod.body)
    fn_def = [n for n in mod.body if isinstance(n, ast.FunctionDef)][0]
    ssa_fn = low.lower_function_def(fn_def)
    vec_fn, _ = LoopVectorizerPass().vectorize_function(ssa_fn)
    return vec_fn


class TestAlphaC64HardwareFmaAvx512AndDualGcc(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c64_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_hardware_cpuid_and_vex_fma_silicon_and_quad_consensus(self):
        """Executes W^X CPUID probe, VEX `vfmadd213pd`/`sd` on silicon, and quad-ecosystem FMA consensus."""
        feats = detect_host_simd_features()
        self.assertEqual(feats["arch"], "x86_64")
        self.assertIn("recommended_tier", feats)

        if not feats.get("fma", False):
            self.skipTest("Host CPU lacks OS-enabled hardware FMA")

        jit = NativeJitCompiler()
        fn_fma, mem_fma, hex_fma = jit.compile_avx2_fma_pd()
        try:
            self.assertIn("c4e2f5a8c2", hex_fma)  # vfmadd213pd ymm0, ymm1, ymm2
            self.assertIn("c4e2f1a9c2", hex_fma)  # vfmadd213sd xmm0, xmm1, xmm2

            count = 39
            a = (ctypes.c_double * count)(*[(i * 1.25) - 7.5 for i in range(count)])
            b = (ctypes.c_double * count)(*[((i % 9) + 0.5) * 0.75 for i in range(count)])
            c = (ctypes.c_double * count)(*[(i * -0.35) + 4.0 for i in range(count)])
            out = (ctypes.c_double * count)()

            rc = fn_fma(
                ctypes.addressof(a),
                ctypes.addressof(b),
                ctypes.addressof(c),
                ctypes.addressof(out),
                count,
            )
            self.assertEqual(rc, 1)
            for i in range(count):
                self.assertAlmostEqual(out[i], a[i] * b[i] + c[i], places=12)
        finally:
            mem_fma.free()

        # Verify LoopVectorizer -> X64CodeGenerator emits 256-bit VEX FMA + Homeostasis quad consensus
        vec_fn = _make_fma_vec_ssa()
        bv = BiAbductionVerifier().verify_ssa_memory_bounds(vec_fn, {"FmaArena": 32 * 8 * 4}, {"t": "FmaArena"})
        self.assertTrue(bv["proven"], bv)

        cg = X64CodeGenerator()
        art = cg.compile_function(vec_fn)
        self.assertIn(b"\xc4\xe2\xf5\xa8\xc2", art.code_bytes)  # vfmadd213pd ymm0, ymm1, ymm2

        n_elems = 18
        arena = bytearray(32 * 8 * 4)
        exp_vals = []
        for i in range(n_elems):
            va = (i + 1) * 1.5
            vb = (i + 2) * 0.25
            vc = (i - 5) * 0.5
            struct.pack_into("<d", arena, i * 8, va)
            struct.pack_into("<d", arena, 32 * 8 + i * 8, vb)
            struct.pack_into("<d", arena, 64 * 8 + i * 8, vc)
            exp_vals.append(va * vb + vc)

        router = HomeostasisRouter()
        rep = router.execute_differential(
            [vec_fn],
            "fma_vec_kernel",
            args=[0x400000, n_elems],
            memory_regions={0x400000: bytes(arena)},
            policy="consensus",
        )
        self.assertTrue(rep.consensus_reached, rep.divergences)
        self.assertAlmostEqual(float(rep.consensus_value), sum(exp_vals), places=9)
        for i in range(n_elems):
            got = struct.unpack_from("<d", rep.consensus_snapshots[0x400000], 96 * 8 + i * 8)[0]
            self.assertAlmostEqual(got, exp_vals[i], places=9)

    def test_02_evex_512bit_avx512_encoder_disassembly_and_cpuid_gate(self):
        """Verifies EVEX 512-bit ZMM encoding with GNU objdump and CPUID-guarded native execution."""
        cg = X64CodeGenerator()
        zmm_add = cg.emit_avx512_evex_vec_add_i64()
        zmm_fma = cg.emit_avx512_evex_fma_pd()

        # Verify authentic 4-byte Intel EVEX instructions for ZMM0..ZMM2
        self.assertIn(b"\x62\xd1\xfe\x48\x6f\x02", zmm_add)  # vmovdqu64 zmm0, [r10]
        self.assertIn(b"\x62\xf1\xfd\x48\xd4\xc1", zmm_add)  # vpaddq zmm0, zmm0, zmm1
        self.assertIn(b"\x62\xd1\xfe\x48\x7f\x01", zmm_add)  # vmovdqu64 [r9], zmm0
        self.assertIn(b"\x62\xf2\xf5\x48\xa8\xc2", zmm_fma)  # vfmadd213pd zmm0, zmm1, zmm2

        objdump_cmd = None
        if sys.platform != "win32" and shutil.which("objdump"):
            objdump_cmd = ["objdump"]
        elif sys.platform == "win32" and GCCBackend().supports_elf64:
            objdump_cmd = ["wsl", "/usr/bin/objdump"]

        if objdump_cmd is not None:
            with tempfile.NamedTemporaryFile(dir=self.test_dir, suffix=".bin", delete=False) as tf:
                tf.write(zmm_add + b"\x90" + zmm_fma)
                bin_path = tf.name
            target_arg = _to_wsl_path(bin_path) if objdump_cmd[0] == "wsl" else bin_path
            d = subprocess.run(
                objdump_cmd + ["-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel", target_arg],
                capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL,
            )
            self.assertEqual(d.returncode, 0, d.stderr)
            self.assertIn("vmovdqu64", d.stdout)
            self.assertIn("vpaddq", d.stdout)
            self.assertIn("zmm0", d.stdout)
            self.assertIn("vfmadd213pd", d.stdout)

        jit = NativeJitCompiler()
        feats = detect_host_simd_features()
        if feats.get("avx512f", False):
            fn_z, mem_z, _ = jit.compile_avx512_vec_add_i64()
            try:
                cnt = 21
                a = (ctypes.c_int64 * cnt)(*range(1, cnt + 1))
                b = (ctypes.c_int64 * cnt)(*[i * 10 for i in range(cnt)])
                out = (ctypes.c_int64 * cnt)()
                self.assertEqual(fn_z(ctypes.addressof(a), ctypes.addressof(b), ctypes.addressof(out), cnt), 1)
                for i in range(cnt):
                    self.assertEqual(out[i], a[i] + b[i])
            finally:
                mem_z.free()
        else:
            with self.assertRaises(RuntimeError):
                jit.compile_avx512_vec_add_i64()

    def test_03_dual_target_gcc_elf64_and_coff_canary_with_fma(self):
        """Verifies GCCBackend `-mavx2 -mfma` telemetry and Dual-Target ELF64/COFF capabilities."""
        gcc = GCCBackend(opt_level=3)
        vec_fn = _make_fma_vec_ssa()

        if gcc.supports_elf64:
            asm_txt = gcc.emit_assembly([vec_fn], target_os="linux")
            self.assertIn("fma_vec_kernel", asm_txt)
            stats = gcc.inspect_optimization_stats(asm_txt)
            self.assertGreater(stats["simd_instruction_count"], 0, stats)
            elf_obj = gcc.emit_object([vec_fn], target_os="linux")
            mod = load_elf_object(elf_obj, repo_name="c64_gcc_elf")
            self.assertIn("fma_vec_kernel", mod.symbols)

        if gcc.supports_windows_coff:
            coff_obj = gcc.emit_object([vec_fn], target_os="windows")
            mod_c = load_coff_object(coff_obj, repo_name="c64_gcc_coff")
            self.assertIn("fma_vec_kernel", mod_c.symbols)
        elif gcc.supports_elf64:
            with self.assertRaises(RuntimeError):
                gcc.emit_object([vec_fn], target_os="windows")

    def test_04_omnirepo_compiler_capstone_homeostasis_e2e(self):
        """Compiles repository through OmniRepoCompiler with CPUID host telemetry + FMA probes end-to-end."""
        r_dir = os.path.join(self.test_dir, "repo_c64")
        os.makedirs(r_dir)
        with open(os.path.join(r_dir, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_c64", "language": "python", "exports": ["omni_main", "scale_kernel"], "dependencies": []}, f)
        with open(os.path.join(r_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "class C64State:\n"
                "    x: Array[i64, 32]\n"
                "    y: Array[i64, 32]\n"
                "    out: Array[i64, 32]\n\n"
                "def scale_kernel(t: C64State, n: int) -> int:\n"
                "    if n < 0:\n"
                "        return -1\n"
                "    if n > 32:\n"
                "        return -2\n"
                "    i = 0\n"
                "    acc = 0\n"
                "    while i < n:\n"
                "        vx = t.x[i]\n"
                "        vy = t.y[i]\n"
                "        s = vx + vy\n"
                "        t.out[i] = s\n"
                "        acc += s\n"
                "        i += 1\n"
                "    return acc\n\n"
                "def omni_main(n: int) -> int:\n"
                "    nc = n\n"
                "    if nc < 0:\n"
                "        nc = 0\n"
                "    if nc > 20:\n"
                "        nc = 20\n"
                "    buf = malloc(768)\n"
                "    k = 0\n"
                "    while k < nc:\n"
                "        store_i64(buf, k * 8, k * 7 + 1)\n"
                "        store_i64(buf, 256 + k * 8, k * 3 + 2)\n"
                "        k += 1\n"
                "    tot = scale_kernel(buf, nc)\n"
                "    free(buf)\n"
                '    printf("C64_SEAL=%lld\\n", tot)\n'
                "    return tot % 251\n"
            )

        arena = bytearray(768)
        for k in range(14):
            struct.pack_into("<q", arena, k * 8, k * 7 + 1)
            struct.pack_into("<q", arena, 256 + k * 8, k * 3 + 2)

        comp = OmniRepoCompiler()
        try:
            out_bin = os.path.join(self.test_dir, "c64_seal.exe" if sys.platform == "win32" else "c64_seal")
            res = comp.compile_repositories(
                [r_dir],
                out_bin,
                target_format="executable",
                entry_export="omni_main",
                backend="homeostasis",
                homeostasis_policy="throughput",
                homeostasis_probes={"scale_kernel": [([0x400000, 14], {0x400000: bytes(arena)})]},
                audit_nonce="c64-capstone",
            )
            self.assertTrue(res["stages"]["formal_audit"]["is_valid"])
            h_stage = res["stages"]["homeostasis"]
            self.assertIn("host_simd_features", h_stage)
            self.assertEqual(h_stage["host_simd_features"]["arch"], "x86_64")
            self.assertTrue(h_stage["consensus_all_passed"])
            self.assertEqual(h_stage["verified_probe_count"], 1)
            self.assertIn("vla_simd_metadata", res["stages"]["codegen"])
            self.assertIsNotNone(res["stages"]["codegen"]["vla_simd_metadata"])

            if sys.platform != "win32":
                os.chmod(out_bin, 0o755)
            for n in (0, 8, 14, 20):
                exp = sum((k * 7 + 1) + (k * 3 + 2) for k in range(n))
                p = subprocess.run([out_bin, str(n)], capture_output=True, text=True, timeout=10)
                self.assertIn(f"C64_SEAL={exp}", p.stdout)
                self.assertEqual(p.returncode, exp % 251)
        finally:
            comp.close()


if __name__ == "__main__":
    unittest.main()
