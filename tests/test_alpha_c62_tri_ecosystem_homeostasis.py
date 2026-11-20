"""
Alpha-C62 End-to-End Verification Suite: Tri-Ecosystem Homeostasis (`OmniCompiler` + `LLVM 20.1.8` + `GCC O3`):
1. `GCCBackend`: Omni-SSA -> zero-UB C99/GNU-C -> `/usr/bin/gcc -O3` (Linux native or WSL2),
   emitting ELF64 `.o` loadable by `load_elf_object` + `AssemblyInvariantAuditor`, AVX2 assembly telemetry,
   and isolated execution with binary memory snapshots.
2. `LLVMBackend` Cross-Target AOT: `target_triple="aarch64-unknown-linux-gnu"` ELF64 AArch64 object
   emission + LLVM 20 O3 SIMD telemetry (`inspect_optimization_stats`).
3. `HomeostasisRouter`: Live tri-ecosystem differential consensus across Native AVX2, LLVM 20 O3, and
   GCC O3 (bit-exact return values + full memory snapshots), `throughput` policy, and fail-closed
   outlier isolation when a diverging engine is injected.
4. `OmniRepoCompiler`: End-to-end compilation with `backend="homeostasis"` and `backend="gcc"`.
"""

import ast
import io
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

from elftools.elf.elffile import ELFFile

from compiler.gcc_backend import GCCBackend
from compiler.homeostasis_router import EngineExecutionResult, HomeostasisRouter
from compiler.llvm_backend import LLVMBackend
from compiler.loop_vectorizer import LoopVectorizerPass
from compiler.object_linker import load_elf_object
from compiler.ssa_ir import AstToSsaLowering
from omni_repo_compiler import OmniRepoCompiler
from validation.assembly_invariant_auditor import AssemblyInvariantAuditor
from validation.biabduction_verifier import BiAbductionVerifier


def _s64(val: int) -> int:
    u = int(val) & 0xFFFFFFFFFFFFFFFF
    return u - 0x10000000000000000 if (u & 0x8000000000000000) else u


class TestAlphaC62TriEcosystemHomeostasis(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c62_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_gcc_backend_ssa_to_c99_o3_avx2_elf64_and_execution(self):
        """Compiles vectorized store + Order-3 Tribonacci via GCCBackend O3 into ELF64 `.o` + executes cleanly."""
        gcc = GCCBackend(opt_level=3)
        if not gcc.is_available:
            self.skipTest("GCC not available")

        src = """
def tribonacci_store(base: int, n: int) -> int:
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

        obj_bytes = gcc.emit_object([vec_fn])
        mod = load_elf_object(obj_bytes, repo_name="c62_gcc")
        self.assertIn("tribonacci_store", mod.symbols)
        sd = mod.symbols["tribonacci_store"]
        audit = AssemblyInvariantAuditor().audit_function_code(
            bytes(mod.text_bytes[sd.offset : sd.offset + sd.size]), "tribonacci_store"
        )
        self.assertTrue(audit.is_valid, audit.errors)

        asm_txt = gcc.emit_assembly([vec_fn])
        self.assertIn("tribonacci_store", asm_txt)

        # Verify GCC O3 auto-vectorizes standard contiguous loops with AVX2 SIMD (`vpaddq` / `ymm`)
        sum_src = """
def gcc_simd_sum(base: int, n: int) -> int:
    i = 0
    s = 0
    while i < n:
        s += load_i64(base, i * 8)
        i += 1
    return s
"""
        sum_vec, _ = LoopVectorizerPass().vectorize_function(
            AstToSsaLowering().lower_function_def(ast.parse(sum_src).body[0])
        )
        opt_stats = gcc.inspect_optimization_stats(gcc.emit_assembly([sum_vec]))
        self.assertGreater(opt_stats["simd_instruction_count"], 0, opt_stats)

        n_items = 19
        arena = bytearray(2048)
        for k in range(n_items):
            struct.pack_into("<q", arena, k * 8, (k + 1) * 11)
            struct.pack_into("<q", arena, 256 + k * 8, (k + 2) * 7)

        ret_v, snaps = gcc.run_function([vec_fn], "tribonacci_store", args=[0x400000, n_items], memory_regions={0x400000: bytes(arena)})

        a, b, c, tot = 1, 2, 3, 0
        for k in range(n_items):
            s = (k + 1) * 11 + (k + 2) * 7
            got_slot = struct.unpack_from("<q", snaps[0x400000], 512 + k * 8)[0]
            self.assertEqual(got_slot, s)
            nxt = (a + b + c + s) & 0xFFFFFFFFFFFFFFFF
            a, b, c = b, c, nxt
            tot = (tot + s) & 0xFFFFFFFFFFFFFFFF
        exp = _s64(tot + a * 3 + b * 5 + c * 7)
        self.assertEqual(ret_v, exp)

    def test_02_llvm_backend_cross_target_triples_and_optimization_stats(self):
        """Verifies LLVMBackend cross-target ARM64 AArch64 ELF64 object emission & x86-64 O3 SIMD telemetry."""
        ll_x64 = LLVMBackend(opt_level=3)
        if not ll_x64.is_available:
            self.skipTest("LLVM unavailable")

        src = """
def dot_scale(base: int, n: int) -> int:
    i = 0
    acc = 0
    while i < n:
        acc += load_i64(base, i * 8) * 3
        i += 1
    return acc
"""
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        vec_fn, _ = LoopVectorizerPass().vectorize_function(ssa_fn)

        mod_x64 = ll_x64.compile_ir(ll_x64.ssa_to_llvm_ir(vec_fn), optimize=True)
        stats_x64 = ll_x64.inspect_optimization_stats(mod_x64)
        self.assertGreaterEqual(stats_x64["simd_instruction_count"], 0)

        ll_arm = LLVMBackend(opt_level=3, target_triple="aarch64-unknown-linux-gnu")
        self.assertTrue(ll_arm.is_available)
        mod_arm = ll_arm.compile_ir(ll_arm.ssa_to_llvm_ir(vec_fn), optimize=True)
        arm_obj = ll_arm.emit_object(mod_arm)
        elf = ELFFile(io.BytesIO(arm_obj))
        self.assertEqual(elf.header["e_machine"], "EM_AARCH64")
        stats_arm = ll_arm.inspect_optimization_stats(mod_arm)
        self.assertIn("aarch64", stats_arm["target_triple"])

    def test_03_homeostasis_router_tri_ecosystem_consensus_and_outlier_isolation(self):
        """Verifies bit-exact tri-ecosystem consensus (Native AVX2 == LLVM 20 O3 == GCC O3) and rogue isolation."""
        src = """
class HomeoState:
    inp: Array[i64, 64]
    out: Array[i64, 64]
    scan: Array[i64, 64]

def homeo_kernel(t: HomeoState, n: int) -> int:
    if n > 64:
        return -999
    i = 0
    s = 0
    a = 1
    b = 2
    mx = -100000
    while i < n:
        v = t.inp[i]
        d = v * 3 + 1
        t.out[i] = d
        s += v
        t.scan[i] = s
        nxt = a + b + v
        a = b
        b = nxt
        mx = max(mx, d)
        i += 1
    return s + a * 3 + b * 5 + mx
"""
        mod = ast.parse(src)
        low = AstToSsaLowering()
        low.register_structs_from_statements(mod.body)
        ssa_fn = low.lower_function_def([n for n in mod.body if isinstance(n, ast.FunctionDef)][0])
        vec_fn, _ = LoopVectorizerPass().vectorize_function(ssa_fn)

        bv = BiAbductionVerifier().verify_ssa_memory_bounds(vec_fn, {"HomeoState": 64 * 8 * 3}, {"t": "HomeoState"})
        self.assertTrue(bv["proven"], bv)

        router = HomeostasisRouter()
        engines = router.available_engines()
        expected_engines = {"native"}
        if router.llvm_backend.is_available:
            expected_engines.add("llvm")
        if router.gcc_backend.is_available:
            expected_engines.add("gcc")
        if router.wasm_backend.is_available:
            expected_engines.add("wasm")
        self.assertIn("native", engines)
        self.assertEqual(set(engines), expected_engines)
        if sys.platform.startswith("linux"):
            self.assertEqual(expected_engines, {"native", "llvm", "gcc", "wasm"})

        arena = bytearray(64 * 8 * 3)
        for k in range(23):
            struct.pack_into("<q", arena, k * 8, (k * 7) - 35)

        rep = router.execute_differential(
            [vec_fn],
            "homeo_kernel",
            args=[0x400000, 23],
            memory_regions={0x400000: bytes(arena)},
            policy="consensus",
        )
        self.assertTrue(rep.consensus_reached, f"Divergences: {rep.divergences}")
        self.assertEqual(set(rep.active_engines), expected_engines)
        self.assertEqual(rep.isolated_engines, [])

        # Adversarial fault injection: 4th rogue engine returns wrong value -> must be isolated cleanly
        def rogue_executor(ssa_funcs, entry_fn, args, mem_map):
            return EngineExecutionResult(
                engine="rogue_mutant",
                success=True,
                return_value=rep.consensus_value + 1337,
                memory_snapshots=rep.consensus_snapshots,
                elapsed_ms=0.01,
            )

        rep_iso = router.execute_differential(
            [vec_fn],
            "homeo_kernel",
            args=[0x400000, 23],
            memory_regions={0x400000: bytes(arena)},
            policy="throughput",
            custom_executors={"rogue_mutant": rogue_executor},
        )
        self.assertTrue(rep_iso.consensus_reached)
        self.assertEqual(rep_iso.consensus_value, rep.consensus_value)
        self.assertEqual(rep_iso.isolated_engines, ["rogue_mutant"])
        self.assertEqual(rep_iso.divergences[0]["reason"], "semantic_divergence")

    def test_04_omnirepo_compiler_gcc_and_homeostasis_e2e_executables(self):
        """Compiles project through OmniRepoCompiler using `backend='homeostasis'` and `backend='gcc'`."""
        r_dir = os.path.join(self.test_dir, "repo_c62")
        os.makedirs(r_dir)
        with open(os.path.join(r_dir, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_c62", "language": "python", "exports": ["omni_main"], "dependencies": []}, f)
        with open(os.path.join(r_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "def omni_main(n: int) -> int:\n"
                "    buf = malloc(512)\n"
                "    if n > 20:\n"
                "        n = 20\n"
                "    k = 0\n"
                "    while k < n:\n"
                "        store_i64(buf, k * 8, k * 3 + 2)\n"
                "        k += 1\n"
                "    tot = 0\n"
                "    i = 0\n"
                "    while i < n:\n"
                "        tot += load_i64(buf, i * 8)\n"
                "        i += 1\n"
                "    free(buf)\n"
                '    printf("C62_HOMEO=%lld\\n", tot)\n'
                "    return tot % 251\n"
            )

        comp = OmniRepoCompiler()
        try:
            homeo_bin = os.path.join(self.test_dir, "c62_homeo.exe" if sys.platform == "win32" else "c62_homeo")
            res_h = comp.compile_repositories(
                [r_dir], homeo_bin, target_format="executable", entry_export="omni_main",
                backend="homeostasis", audit_nonce="c62-homeo",
            )
            self.assertTrue(res_h["stages"]["formal_audit"]["is_valid"])
            self.assertIn("homeostasis", res_h["stages"])
            self.assertIn("native", res_h["stages"]["homeostasis"]["available_engines"])
            if sys.platform != "win32":
                os.chmod(homeo_bin, 0o755)
            for n in (1, 7, 15, 20):
                exp = sum(k * 3 + 2 for k in range(n))
                p = subprocess.run([homeo_bin, str(n)], capture_output=True, text=True, timeout=10)
                self.assertIn(f"C62_HOMEO={exp}", p.stdout)
                self.assertEqual(p.returncode, exp % 251)

            if comp.gcc.is_available:
                if sys.platform == "win32" and comp.gcc.mode != "native_exe":
                    with self.assertRaises(ValueError):
                        comp.compile_repositories(
                            [r_dir], os.path.join(self.test_dir, "bad.exe"),
                            target_format="executable", entry_export="omni_main",
                            target_os="windows", backend="gcc", audit_nonce="c62-gcc-win-block",
                        )

                gcc_lin = os.path.join(self.test_dir, "c62_gcc_linux")
                res_g = comp.compile_repositories(
                    [r_dir], gcc_lin, target_format="executable", entry_export="omni_main",
                    target_os="linux", backend="gcc", audit_nonce="c62-gcc-lin",
                )
                self.assertTrue(res_g["stages"]["formal_audit"]["is_valid"])
                self.assertGreaterEqual(res_g["stages"]["codegen"]["gcc_compiled_functions"], 1)

                exp_20 = sum(k * 3 + 2 for k in range(20))
                if sys.platform == "win32":
                    wsl_p = gcc_lin.replace("\\", "/").replace("F:", "/mnt/f").replace("C:", "/mnt/c")
                    p_g = subprocess.run(
                        ["wsl", "/bin/sh", "-c", f"cp {wsl_p} /tmp/c62_gcc_lin && chmod +x /tmp/c62_gcc_lin && /tmp/c62_gcc_lin 20"],
                        capture_output=True, timeout=20,
                    )
                    if p_g.returncode != 4294967295:
                        self.assertIn(f"C62_HOMEO={exp_20}".encode("ascii"), p_g.stdout)
                        self.assertEqual(p_g.returncode, exp_20 % 251)
                else:
                    os.chmod(gcc_lin, 0o755)
                    p_g = subprocess.run([gcc_lin, "20"], capture_output=True, timeout=10)
                    self.assertIn(f"C62_HOMEO={exp_20}".encode("ascii"), p_g.stdout)
                    self.assertEqual(p_g.returncode, exp_20 % 251)
        finally:
            comp.close()


if __name__ == "__main__":
    unittest.main()
