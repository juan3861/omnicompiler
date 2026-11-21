"""
Alpha-C63 End-to-End Verification Suite:
Quad-Ecosystem Homeostasis (`Omni Native AVX2` == `LLVM 20 O3` == `GCC O3` == `Wasmtime v128`)
and Active Build-Time Verification inside `OmniRepoCompiler`:
1. `WasmBackend`: `v128` 128-bit SIMD fusion + `$__omni_sp` `alloca` linear-memory execution (`run_ssa_with_memory`) with fuel metering.
2. `HomeostasisRouter`: Live Quad-Ecosystem bit-exact differential consensus (`Native`, `LLVM 20`, `GCC O3`, `Wasmtime v128`) including `alloca` scratch buffers + silent memory corruption outlier isolation.
3. `OmniRepoCompiler(..., backend="homeostasis")`: Active build-time differential consensus (`homeostasis_probes`), multi-ecosystem SIMD telemetry (`llvm`, `gcc`, `wasm`), Z3 `verify_ssa_to_wat` + `verify_ssa_to_llvm_ir`, and standalone PE64/ELF64 execution.
4. Fail-closed verification on invalid policy / unresolved consensus split ties.
"""

import ast
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

from compiler.homeostasis_router import EngineExecutionResult, HomeostasisRouter
from compiler.loop_vectorizer import LoopVectorizerPass
from compiler.ssa_ir import AstToSsaLowering, BasicBlock, SSAFunction, SSAInstruction, SSAVar
from compiler.wasm_backend import WasmBackend
from omni_repo_compiler import OmniRepoCompiler
from validation.biabduction_verifier import BiAbductionVerifier


def _s64(val: int) -> int:
    u = int(val) & 0xFFFFFFFFFFFFFFFF
    return u - 0x10000000000000000 if (u & 0x8000000000000000) else u


def _make_alloca_scratch_ssa() -> SSAFunction:
    """Builds a multi-block `SSAFunction` allocating a 64-byte stack frame via `alloca`."""
    fn = SSAFunction("alloca_mix", ["seed", "n"], param_types={"seed": "i64", "n": "i64"}, return_type="i64")
    b_entry = BasicBlock("entry")
    b_hdr = BasicBlock("loop_hdr")
    b_body = BasicBlock("loop_body")
    b_exit = BasicBlock("exit")

    p_seed = SSAVar("seed", 0)
    p_n = SSAVar("n", 0)
    v_buf = SSAVar("buf", 1)
    v_i0 = SSAVar("i", 0)
    v_i = SSAVar("i", 1)
    v_i_nxt = SSAVar("i", 2)
    v_acc0 = SSAVar("acc", 0)
    v_acc = SSAVar("acc", 1)
    v_acc_nxt = SSAVar("acc", 2)
    v_lim = SSAVar("lim", 1)
    v_cond = SSAVar("cond", 1)
    v_off = SSAVar("off", 1)
    v_val = SSAVar("val", 1)
    v_t = SSAVar("tmp", 1)
    v_ld = SSAVar("ld", 1)

    b_entry.add_instruction(SSAInstruction(p_seed, "param", ["seed"]))
    b_entry.add_instruction(SSAInstruction(p_n, "param", ["n"]))
    b_entry.add_instruction(SSAInstruction(v_buf, "alloca", [64]))
    b_entry.add_instruction(SSAInstruction(v_lim, "and", [p_n, 7]))
    b_entry.add_instruction(SSAInstruction(v_i0, "const", [0]))
    b_entry.add_instruction(SSAInstruction(v_acc0, "const", [0]))
    b_entry.add_instruction(SSAInstruction(None, "br", ["loop_hdr"]))
    b_entry.connect_to(b_hdr)

    phi_i = SSAInstruction(v_i, "phi", [v_i0, v_i_nxt])
    phi_i.phi_incoming = [("entry", v_i0), ("loop_body", v_i_nxt)]
    phi_acc = SSAInstruction(v_acc, "phi", [v_acc0, v_acc_nxt])
    phi_acc.phi_incoming = [("entry", v_acc0), ("loop_body", v_acc_nxt)]
    b_hdr.phi_nodes.extend([phi_i, phi_acc])
    b_hdr.add_instruction(SSAInstruction(v_cond, "cmp_lt", [v_i, v_lim]))
    b_hdr.add_instruction(SSAInstruction(None, "br_cond", [v_cond, "loop_body", "exit"]))
    b_hdr.connect_to(b_body)
    b_hdr.connect_to(b_exit)

    b_body.add_instruction(SSAInstruction(v_off, "shl", [v_i, 3]))
    b_body.add_instruction(SSAInstruction(v_t, "mul", [v_i, 17]))
    b_body.add_instruction(SSAInstruction(v_val, "xor", [p_seed, v_t]))
    b_body.add_instruction(SSAInstruction(None, "store_off", [v_buf, v_off, v_val, "i64"]))
    b_body.add_instruction(SSAInstruction(v_ld, "load_off", [v_buf, v_off, "i64"]))
    b_body.add_instruction(SSAInstruction(v_acc_nxt, "add", [v_acc, v_ld]))
    b_body.add_instruction(SSAInstruction(v_i_nxt, "add", [v_i, 1]))
    b_body.add_instruction(SSAInstruction(None, "br", ["loop_hdr"]))
    b_body.connect_to(b_hdr)

    b_exit.add_instruction(SSAInstruction(None, "ret", [v_acc]))

    fn.blocks = [b_entry, b_hdr, b_body, b_exit]
    return fn


def _make_vec_pair_ssa() -> SSAFunction:
    src = """
class VecPair:
    x: Array[i64, 32]
    y: Array[i64, 32]
    out: Array[i64, 32]

def vec_pair_sum(p: VecPair, n: int) -> int:
    if n < 0:
        return -1
    if n > 32:
        return -2
    i = 0
    acc = 0
    while i < n:
        vx = p.x[i]
        vy = p.y[i]
        s = vx + vy
        p.out[i] = s
        acc += s
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


class TestAlphaC63QuadHomeostasisE2E(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(REPO_ROOT, ".proof", "alpha_c63_tmp")
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_wasm_backend_linear_memory_v128_and_alloca(self):
        """Executes vectorized v128 linear-memory kernel + stack `alloca` in Wasmtime with fuel telemetry."""
        wb = WasmBackend()
        if not wb.is_available:
            self.skipTest("Wasmtime runtime unavailable")

        vec_fn = _make_vec_pair_ssa()
        arena = bytearray(32 * 8 * 3)
        n_items = 17
        expected_out = []
        for k in range(n_items):
            xv = (k + 1) * 13
            yv = (k + 3) * 5 - 10
            struct.pack_into("<q", arena, k * 8, xv)
            struct.pack_into("<q", arena, 32 * 8 + k * 8, yv)
            expected_out.append(xv + yv)

        ret_v, snaps, stats = wb.run_ssa_with_memory(
            [vec_fn],
            "vec_pair_sum",
            args=[0x400000, n_items],
            memory_regions={0x400000: bytes(arena)},
            fuel_budget=5_000_000,
        )
        self.assertGreater(stats["v128_instruction_count"], 0, stats)
        self.assertGreater(stats["fuel_consumed"], 0)
        self.assertEqual(ret_v, sum(expected_out))
        for k in range(n_items):
            got = struct.unpack_from("<q", snaps[0x400000], 64 * 8 + k * 8)[0]
            self.assertEqual(got, expected_out[k])

        alloca_fn = _make_alloca_scratch_ssa()
        r1, _, s1 = wb.run_ssa_with_memory([alloca_fn], "alloca_mix", args=[1234567, 6], fuel_budget=1_000_000)
        r2, _, _ = wb.run_ssa_with_memory([alloca_fn], "alloca_mix", args=[1234567, 6], fuel_budget=1_000_000)
        exp_mix = sum(_s64(1234567 ^ (k * 17)) for k in range(6))
        self.assertEqual(r1, exp_mix)
        self.assertEqual(r2, exp_mix)
        self.assertGreater(s1["fuel_consumed"], 0)

    def test_02_quad_ecosystem_alloca_and_simd_consensus_parity(self):
        """Proves bit-exact consensus across Native, LLVM 20, GCC O3, and Wasmtime v128 + silent memory tamper isolation."""
        router = HomeostasisRouter()
        expected_engines = {"native"}
        if router.llvm_backend.is_available:
            expected_engines.add("llvm")
        if router.gcc_backend.is_available:
            expected_engines.add("gcc")
        if router.wasm_backend.is_available:
            expected_engines.add("wasm")
        if sys.platform.startswith("linux"):
            self.assertEqual(expected_engines, {"native", "llvm", "gcc", "wasm"})
        self.assertGreaterEqual(len(expected_engines), 2)

        vec_fn = _make_vec_pair_ssa()
        bv = BiAbductionVerifier().verify_ssa_memory_bounds(vec_fn, {"VecPair": 32 * 8 * 3}, {"p": "VecPair"})
        self.assertTrue(bv["proven"], bv)

        arena = bytearray(32 * 8 * 3)
        for k in range(19):
            struct.pack_into("<q", arena, k * 8, k * 19 - 50)
            struct.pack_into("<q", arena, 32 * 8 + k * 8, k * 7 + 9)

        rep_vec = router.execute_differential(
            [vec_fn],
            "vec_pair_sum",
            args=[0x400000, 19],
            memory_regions={0x400000: bytes(arena)},
            policy="consensus",
        )
        self.assertTrue(rep_vec.consensus_reached, rep_vec.divergences)
        self.assertEqual(set(rep_vec.active_engines), expected_engines)
        self.assertEqual(rep_vec.isolated_engines, [])

        # Adversarial silent memory tamper: returns exact integer but flips 1 byte in memory snapshot
        def silent_mem_corruptor(ssa_funcs, entry_fn, args, mem_map):
            bad_snaps = {k: bytearray(v) for k, v in rep_vec.consensus_snapshots.items()}
            first_k = next(iter(bad_snaps))
            bad_snaps[first_k][512] ^= 0x01
            return EngineExecutionResult(
                engine="silent_mem_corruptor",
                success=True,
                return_value=rep_vec.consensus_value,
                memory_snapshots={k: bytes(v) for k, v in bad_snaps.items()},
                elapsed_ms=0.001,
            )

        rep_corrupt = router.execute_differential(
            [vec_fn],
            "vec_pair_sum",
            args=[0x400000, 19],
            memory_regions={0x400000: bytes(arena)},
            policy="throughput",
            custom_executors={"silent_mem_corruptor": silent_mem_corruptor},
        )
        self.assertTrue(rep_corrupt.consensus_reached)
        self.assertEqual(rep_corrupt.isolated_engines, ["silent_mem_corruptor"])
        self.assertNotEqual(rep_corrupt.selected_engine, "silent_mem_corruptor")

        alloca_fn = _make_alloca_scratch_ssa()
        rep_alloca = router.execute_differential([alloca_fn], "alloca_mix", args=[987654, 7], policy="consensus")
        self.assertTrue(rep_alloca.consensus_reached, rep_alloca.divergences)
        self.assertEqual(set(rep_alloca.active_engines), expected_engines)
        self.assertEqual(rep_alloca.consensus_value, sum(_s64(987654 ^ (k * 17)) for k in range(7)))

    def test_03_omnirepo_compiler_active_build_homeostasis_e2e(self):
        """Compiles repository with `backend='homeostasis'`, live probes, Z3 WAT/LLVM proofs & multi-engine SIMD telemetry."""
        r_dir = os.path.join(self.test_dir, "repo_c63")
        os.makedirs(r_dir)
        with open(os.path.join(r_dir, "omni_repo.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "repo_c63", "language": "python", "exports": ["omni_main", "vec_kernel"], "dependencies": []}, f)
        with open(os.path.join(r_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "class HomeoVecBuf:\n"
                "    inp: Array[i64, 32]\n"
                "    bias: Array[i64, 32]\n"
                "    out: Array[i64, 32]\n\n"
                "def vec_kernel(b: HomeoVecBuf, n: int) -> int:\n"
                "    if n < 0:\n"
                "        return -1\n"
                "    if n > 32:\n"
                "        return -2\n"
                "    i = 0\n"
                "    acc = 0\n"
                "    while i < n:\n"
                "        va = b.inp[i]\n"
                "        vb = b.bias[i]\n"
                "        s = va + vb\n"
                "        b.out[i] = s\n"
                "        acc += s\n"
                "        i += 1\n"
                "    return acc\n\n"
                "def omni_main(n: int) -> int:\n"
                "    n_cl = n\n"
                "    if n_cl < 0:\n"
                "        n_cl = 0\n"
                "    if n_cl > 24:\n"
                "        n_cl = 24\n"
                "    buf = malloc(768)\n"
                "    k = 0\n"
                "    while k < n_cl:\n"
                "        store_i64(buf, k * 8, k * 5 + 3)\n"
                "        store_i64(buf, 256 + k * 8, k * 2 + 1)\n"
                "        k += 1\n"
                "    tot = vec_kernel(buf, n_cl)\n"
                "    free(buf)\n"
                '    printf("C63_QUAD=%lld\\n", tot)\n'
                "    return tot % 251\n"
            )

        probe_arena = bytearray(768)
        for k in range(12):
            struct.pack_into("<q", probe_arena, k * 8, k * 5 + 3)
            struct.pack_into("<q", probe_arena, 256 + k * 8, k * 2 + 1)

        comp = OmniRepoCompiler()
        try:
            out_bin = os.path.join(self.test_dir, "c63_quad.exe" if sys.platform == "win32" else "c63_quad")
            res = comp.compile_repositories(
                [r_dir],
                out_bin,
                target_format="executable",
                entry_export="omni_main",
                backend="homeostasis",
                homeostasis_policy="throughput",
                homeostasis_probes={"vec_kernel": [([0x400000, 12], {0x400000: bytes(probe_arena)})]},
                audit_nonce="c63-quad-homeo",
            )
            self.assertTrue(res["stages"]["formal_audit"]["is_valid"])
            h_stage = res["stages"]["homeostasis"]
            self.assertEqual(h_stage["policy"], "throughput")
            self.assertEqual(h_stage["verified_probe_count"], 1)
            self.assertTrue(h_stage["consensus_all_passed"])
            self.assertEqual(h_stage["isolated_engines"], [])

            telemetry = h_stage["simd_telemetry_by_engine"]["repo_c63"]
            if comp.wasm.is_available:
                self.assertIn("wasm", telemetry)
                self.assertGreater(telemetry["wasm"]["v128_instruction_count"], 0)
                self.assertGreater(telemetry["wasm"]["wasm_binary_bytes"], 0)
            if comp.llvm.is_available:
                self.assertIn("llvm", telemetry)
            if comp.gcc.is_available:
                self.assertIn("gcc", telemetry)

            if sys.platform != "win32":
                os.chmod(out_bin, 0o755)
            for n in (0, 5, 12, 20):
                exp = sum((k * 5 + 3) + (k * 2 + 1) for k in range(n))
                p = subprocess.run([out_bin, str(n)], capture_output=True, text=True, timeout=10)
                self.assertIn(f"C63_QUAD={exp}", p.stdout)
                self.assertEqual(p.returncode, exp % 251)

            if comp.gcc.supports_elf64:
                lin_bin = os.path.join(self.test_dir, "c63_quad_linux")
                res_lin = comp.compile_repositories(
                    [r_dir],
                    lin_bin,
                    target_format="executable",
                    entry_export="omni_main",
                    target_os="linux",
                    backend="homeostasis",
                    homeostasis_policy="throughput",
                    homeostasis_probes={"vec_kernel": [([0x400000, 12], {0x400000: bytes(probe_arena)})]},
                    audit_nonce="c63-quad-linux",
                )
                self.assertTrue(res_lin["stages"]["formal_audit"]["is_valid"])
                self.assertTrue(res_lin["stages"]["homeostasis"]["consensus_all_passed"])
                if not sys.platform == "win32":
                    os.chmod(lin_bin, 0o755)
                    p_lin = subprocess.run([lin_bin, "20"], capture_output=True, text=True, timeout=10)
                    exp_20 = sum((k * 5 + 3) + (k * 2 + 1) for k in range(20))
                    self.assertIn(f"C63_QUAD={exp_20}", p_lin.stdout)
                    self.assertEqual(p_lin.returncode, exp_20 % 251)
        finally:
            comp.close()

    def test_04_homeostasis_fail_closed_on_split_consensus(self):
        """Verifies fail-closed rejection on invalid policies and unresolvable consensus ties."""
        router = HomeostasisRouter()
        fn = _make_alloca_scratch_ssa()

        def eng_a(ssa_funcs, entry_fn, args, mem_map):
            return EngineExecutionResult(engine="eng_a", success=True, return_value=111, memory_snapshots={}, elapsed_ms=1.0)

        def eng_b(ssa_funcs, entry_fn, args, mem_map):
            return EngineExecutionResult(engine="eng_b", success=True, return_value=222, memory_snapshots={}, elapsed_ms=0.5)

        rep = router.execute_differential(
            [fn],
            "alloca_mix",
            args=[10, 3],
            engines=["eng_a", "eng_b"],
            custom_executors={"eng_a": eng_a, "eng_b": eng_b},
        )
        self.assertFalse(rep.consensus_reached)
        self.assertIsNone(rep.selected_engine)
        self.assertEqual(rep.isolated_engines, ["eng_a"])
        self.assertEqual(rep.divergences[0]["reason"], "semantic_divergence")

        comp = OmniRepoCompiler()
        try:
            with self.assertRaises(ValueError):
                comp.compile_repositories(
                    [], os.path.join(self.test_dir, "unused.exe"),
                    backend="homeostasis", homeostasis_policy="invalid_policy",
                )
        finally:
            comp.close()


if __name__ == "__main__":
    unittest.main()
