"""
Alpha-C65 Verification Suite:
1. Auto-Vectorized 512-bit EVEX (`AVX-512F`) ZMM Loop Fusion inside `X64CodeGenerator.compile_function` (8-way `i64` & `f64` FMA) + GNU `objdump` disassembly & CPUID-gated silicon execution.
2. Hardware 256-bit VEX FMA Dot-Product Reduction (`vfmadd231pd` + `vhaddpd`) in `NativeJitCompiler.compile_avx2_fma_dot_pd`.
3. Persistent SQLite WAL PGO Store (`HomeostasisProfileStore`) with cross-restart survival & reliability penalty routing.
4. `OmniRepoCompiler` PGO calibration + live 4-engine SOTA Comparative Benchmark (`comparative_benchmark.py`).
"""

import ast
import ctypes
import json
import math
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
from compiler.homeostasis_router import EngineExecutionResult, HomeostasisRouter
from compiler.native_codegen import X64CodeGenerator, detect_host_simd_features
from compiler.native_jit import NativeJitCompiler, NativeJitMemory
from compiler.ssa_ir import AstToSsaLowering, BasicBlock, SSAFunction, SSAInstruction, SSAVar
from omni_repo_compiler import OmniRepoCompiler


def _make_8way_zmm_test_funcs():
    """Constructs 8-lane unrolled `i64` add + 8-lane `f64` FMA SSA functions to exercise ZMM EVEX auto-fusion."""
    # 1) 8-way i64 add: out[0..7] = a[0..7] + b[0..7]
    fn_i64 = SSAFunction("zmm_add8_i64", ["a", "b", "out"], param_types={"a": "i64", "b": "i64", "out": "i64"}, return_type="i64")
    bb = BasicBlock("entry")
    pa, pb, po = SSAVar("a", 0), SSAVar("b", 0), SSAVar("out", 0)
    bb.add_instruction(SSAInstruction(pa, "param", ["a"]))
    bb.add_instruction(SSAInstruction(pb, "param", ["b"]))
    bb.add_instruction(SSAInstruction(po, "param", ["out"]))
    va_l, vb_l, vs_l = [], [], []
    for k in range(8):
        va, vb = SSAVar(f"va_{k}", 1), SSAVar(f"vb_{k}", 1)
        off = k * 8
        bb.add_instruction(SSAInstruction(va, "load_off", [pa, off, "i64"]))
        bb.add_instruction(SSAInstruction(vb, "load_off", [pb, off, "i64"]))
        va_l.append(va)
        vb_l.append(vb)
    for k in range(8):
        vs = SSAVar(f"vs_{k}", 1)
        bb.add_instruction(SSAInstruction(vs, "add", [va_l[k], vb_l[k]]))
        vs_l.append(vs)
    for k in range(8):
        bb.add_instruction(SSAInstruction(None, "store_off", [po, k * 8, vs_l[k], "i64"]))
    vr = SSAVar("retv", 1)
    bb.add_instruction(SSAInstruction(vr, "const", [1]))
    bb.add_instruction(SSAInstruction(None, "ret", [vr]))
    fn_i64.add_block(bb)

    # 2) 8-way f64 FMA: out[0..7] = a[0..7] * b[0..7] + c[0..7]
    fn_fma = SSAFunction(
        "zmm_fma8_f64",
        ["a", "b", "c", "out"],
        param_types={"a": "i64", "b": "i64", "c": "i64", "out": "i64"},
        return_type="i64",
    )
    bf = BasicBlock("entry")
    fa, fb, fc, fo = SSAVar("a", 0), SSAVar("b", 0), SSAVar("c", 0), SSAVar("out", 0)
    bf.add_instruction(SSAInstruction(fa, "param", ["a"]))
    bf.add_instruction(SSAInstruction(fb, "param", ["b"]))
    bf.add_instruction(SSAInstruction(fc, "param", ["c"]))
    bf.add_instruction(SSAInstruction(fo, "param", ["out"]))
    la_l, lb_l, lc_l, py_l = [], [], [], []
    for k in range(8):
        la, lb, lc = SSAVar(f"la_{k}", 1, "f64"), SSAVar(f"lb_{k}", 1, "f64"), SSAVar(f"lc_{k}", 1, "f64")
        off = k * 8
        bf.add_instruction(SSAInstruction(la, "load_off", [fa, off, "f64"]))
        bf.add_instruction(SSAInstruction(lb, "load_off", [fb, off, "f64"]))
        bf.add_instruction(SSAInstruction(lc, "load_off", [fc, off, "f64"]))
        la_l.append(la)
        lb_l.append(lb)
        lc_l.append(lc)
    for k in range(8):
        pm, py = SSAVar(f"pm_{k}", 1, "f64"), SSAVar(f"py_{k}", 1, "f64")
        bf.add_instruction(SSAInstruction(pm, "fmul", [la_l[k], lb_l[k]]))
        bf.add_instruction(SSAInstruction(py, "fadd", [pm, lc_l[k]]))
        py_l.append(py)
    for k in range(8):
        bf.add_instruction(SSAInstruction(None, "store_off", [fo, k * 8, py_l[k], "f64"]))
    vfr = SSAVar("retf", 1)
    bf.add_instruction(SSAInstruction(vfr, "const", [1]))
    bf.add_instruction(SSAInstruction(None, "ret", [vfr]))
    fn_fma.add_block(bf)
    return fn_i64, fn_fma


class TestAlphaC65PgoAvx512AutofusionAndBenchmarks(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c65_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_avx512_autofusion_8lane_zmm_codegen_and_disassembly(self):
        """Proves X64CodeGenerator auto-fuses 8-lane i64 add & f64 FMA SSA graphs into EVEX 512-bit ZMM."""
        fn_i64, fn_fma = _make_8way_zmm_test_funcs()
        cg = X64CodeGenerator(enable_avx2=True, enable_fma=True, enable_avx512=True, enable_avx512dq=True)
        art_i64 = cg.compile_function(fn_i64)
        art_fma = cg.compile_function(fn_fma)

        self.assertIn(b"\x62\xd1\xfe\x48\x6f\x03", art_i64.code_bytes)  # vmovdqu64 zmm0, [r11]
        self.assertIn(b"\x62\xf1\xfd\x48\xd4\xc1", art_i64.code_bytes)  # vpaddq zmm0, zmm0, zmm1
        self.assertIn(b"\x62\xd1\xfe\x48\x7f\x03", art_i64.code_bytes)  # vmovdqu64 [r11], zmm0
        self.assertIn(b"\x62\xf2\xf5\x48\xa8\xc2", art_fma.code_bytes)  # vfmadd213pd zmm0, zmm1, zmm2

        objdump_cmd = None
        if sys.platform != "win32" and shutil.which("objdump"):
            objdump_cmd = ["objdump"]
        elif sys.platform == "win32" and GCCBackend().supports_elf64:
            objdump_cmd = ["wsl", "/usr/bin/objdump"]
        if objdump_cmd is not None:
            bp = os.path.join(self.test_dir, "zmm_autofuse.bin")
            with open(bp, "wb") as f:
                f.write(art_i64.code_bytes + b"\x90" + art_fma.code_bytes)
            targ = _to_wsl_path(bp) if objdump_cmd[0] == "wsl" else bp
            d = subprocess.run(
                objdump_cmd + ["-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel", targ],
                capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL,
            )
            self.assertEqual(d.returncode, 0, d.stderr)
            self.assertIn("vpaddq", d.stdout)
            self.assertIn("vfmadd213pd", d.stdout)
            self.assertIn("zmm0", d.stdout)

        if detect_host_simd_features().get("avx512f", False):
            # Physical ZMM silicon execution on AVX-512F hosts (e.g., CI ubuntu-latest)
            m = NativeJitMemory(max(4096, len(art_i64.code_bytes)))
            try:
                m.write_code(art_i64.code_bytes)
                fn_c = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64)(m.ptr)
                a = (ctypes.c_int64 * 8)(*[i * 3 + 1 for i in range(8)])
                b = (ctypes.c_int64 * 8)(*[i * 7 + 5 for i in range(8)])
                o = (ctypes.c_int64 * 8)()
                self.assertEqual(fn_c(ctypes.addressof(a), ctypes.addressof(b), ctypes.addressof(o)), 1)
                for i in range(8):
                    self.assertEqual(o[i], a[i] + b[i])
            finally:
                m.free()

    def test_02_hardware_avx2_fma_dot_product_silicon(self):
        """Executes 256-bit `vfmadd231pd` + `vhaddpd` FMA dot product on silicon across vector & tail elements."""
        feats = detect_host_simd_features()
        if not feats.get("fma", False):
            self.skipTest("Host CPU lacks OS-enabled hardware FMA")

        jit = NativeJitCompiler()
        fn_dot, mem_dot, hex_dot = jit.compile_avx2_fma_dot_pd()
        try:
            self.assertIn("c4e2fdb8d1", hex_dot)    # vfmadd231pd ymm2, ymm0, ymm1
            self.assertIn("c4e37d19d101", hex_dot)  # vextractf128 xmm1, ymm2, 1
            self.assertIn("c5f97cc0", hex_dot)      # vhaddpd xmm0, xmm0, xmm0

            cnt = 47
            a = (ctypes.c_double * cnt)(*[math.sin(i + 1) * 3.5 for i in range(cnt)])
            b = (ctypes.c_double * cnt)(*[math.cos(i + 2) * 2.25 for i in range(cnt)])
            got = fn_dot(ctypes.addressof(a), ctypes.addressof(b), cnt)
            exp = math.fsum(a[i] * b[i] for i in range(cnt))
            self.assertAlmostEqual(got, exp, places=11)
        finally:
            mem_dot.free()

    def test_03_persistent_pgo_homeostasis_store_and_adaptive_routing(self):
        """Proves PGO telemetry persists across router restarts and avoids previously diverging engines."""
        src = """
class PgoVec:
    x: Array[i64, 16]
    y: Array[i64, 16]

def pgo_kernel(p: PgoVec, n: int) -> int:
    i = 0
    s = 0
    while i < n:
        v = p.x[i] + p.y[i]
        p.x[i] = v
        s += v
        i += 1
    return s
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        fn_def = [n for n in mod.body if isinstance(n, ast.FunctionDef)][0]
        ssa_fn = low.lower_function_def(fn_def)

        pgo_db = os.path.join(self.test_dir, "pgo_profiles.db")
        arena = bytearray(16 * 8 * 2)
        for k in range(10):
            struct.pack_into("<q", arena, k * 8, k + 3)
            struct.pack_into("<q", arena, 16 * 8 + k * 8, k * 2 + 1)

        r1 = HomeostasisRouter(profile_db_path=pgo_db)
        try:
            def bad_custom(ssa_funcs, entry_fn, args, mem_map):
                return EngineExecutionResult(engine="faulty_fast", success=True, return_value=-999999, elapsed_ms=0.0001)

            rep = r1.execute_differential(
                [ssa_fn],
                "pgo_kernel",
                args=[0x400000, 10],
                memory_regions={0x400000: bytes(arena)},
                policy="throughput",
                custom_executors={"faulty_fast": bad_custom},
            )
            self.assertTrue(rep.consensus_reached)
            self.assertEqual(rep.isolated_engines, ["faulty_fast"])
        finally:
            r1.close()

        # Re-open fresh router pointing at same persistent SQLite DB
        r2 = HomeostasisRouter(profile_db_path=pgo_db)
        try:
            best, meta = r2.recommend_engine(
                [ssa_fn],
                candidate_engines=["faulty_fast", "native", "llvm", "wasm"],
                policy="throughput",
            )
            self.assertIsNotNone(best)
            self.assertNotEqual(best, "faulty_fast")
            self.assertIn("native", meta["scores"])
            self.assertNotIn("faulty_fast", meta["scores"])
        finally:
            r2.close()

    def test_04_omnirepo_pgo_homeostasis_and_comparative_benchmark_e2e(self):
        """Runs OmniRepoCompiler with persistent PGO DB across compilations + live 4-engine CI benchmark."""
        r_dir = os.path.join(self.test_dir, "repo_c65")
        os.makedirs(r_dir)
        with open(os.path.join(r_dir, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_c65", "language": "python", "exports": ["omni_main", "c65_vec"], "dependencies": []}, f)
        with open(os.path.join(r_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "class C65Buf:\n"
                "    a: Array[i64, 16]\n"
                "    b: Array[i64, 16]\n"
                "    out: Array[i64, 16]\n\n"
                "def c65_vec(p: C65Buf, n: int) -> int:\n"
                "    if n < 0:\n"
                "        return -1\n"
                "    if n > 16:\n"
                "        return -2\n"
                "    i = 0\n"
                "    tot = 0\n"
                "    while i < n:\n"
                "        s = p.a[i] + p.b[i]\n"
                "        p.out[i] = s\n"
                "        tot += s\n"
                "        i += 1\n"
                "    return tot\n\n"
                "def omni_main(n: int) -> int:\n"
                "    nc = n\n"
                "    if nc < 0:\n"
                "        nc = 0\n"
                "    if nc > 16:\n"
                "        nc = 16\n"
                "    buf = malloc(384)\n"
                "    k = 0\n"
                "    while k < nc:\n"
                "        store_i64(buf, k * 8, k + 2)\n"
                "        store_i64(buf, 128 + k * 8, k * 4 + 1)\n"
                "        k += 1\n"
                "    r = c65_vec(buf, nc)\n"
                "    free(buf)\n"
                '    printf("C65_PGO=%lld\\n", r)\n'
                "    return r % 251\n"
            )

        arena = bytearray(384)
        for k in range(10):
            struct.pack_into("<q", arena, k * 8, k + 2)
            struct.pack_into("<q", arena, 128 + k * 8, k * 4 + 1)

        db_base = os.path.join(self.test_dir, "c65_state.db")
        out_bin = os.path.join(self.test_dir, "c65_bin.exe" if sys.platform == "win32" else "c65_bin")

        # Run #1 populates persistent PGO DB; Run #2 reads warm PGO recommendation
        c1 = OmniRepoCompiler(db_path=db_base)
        try:
            r1 = c1.compile_repositories(
                [r_dir], out_bin, target_format="executable", entry_export="omni_main",
                backend="homeostasis", homeostasis_policy="throughput",
                homeostasis_probes={"c65_vec": [([0x400000, 10], {0x400000: bytes(arena)})]},
                audit_nonce="c65-run1",
            )
            self.assertTrue(r1["stages"]["homeostasis"]["consensus_all_passed"])
        finally:
            c1.close()

        c2 = OmniRepoCompiler(db_path=db_base)
        try:
            r2 = c2.compile_repositories(
                [r_dir], out_bin, target_format="executable", entry_export="omni_main",
                backend="homeostasis", homeostasis_policy="throughput",
                audit_nonce="c65-run2",
            )
            h2 = r2["stages"]["homeostasis"]
            self.assertIsNotNone(h2["pgo_profile_signature"])
            self.assertIsNotNone(h2["pgo_recommended_engine"])
            self.assertTrue(h2["consensus_all_passed"])
        finally:
            c2.close()

        bench_script = os.path.join(REPO_ROOT, "external_component_candidates", "benchmarks", "comparative_benchmark.py")
        pb = subprocess.run([sys.executable, bench_script], cwd=REPO_ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(pb.returncode, 0, pb.stderr)
        with open(os.path.join(REPO_ROOT, "external_component_candidates", "benchmarks", "benchmark_results.json"), encoding="utf-8") as bf:
            bres = json.load(bf)
        self.assertIn("omni_native_jit", bres["execution"])
        self.assertIn("llvm_o3_jit", bres["execution"])
        self.assertTrue(bres["homeostasis_quad"]["consensus_reached"])


if __name__ == "__main__":
    unittest.main()
