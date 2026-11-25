"""
Alpha-C99 Empirical Verification Suite:
1. Compile-time SanitizerInstrumentationPass (`asan,ubsan`) + freestanding `__omni_sanitizer_trap`:
   - Safe input returns exact value (`c99_safe_div(30, 5) == 16`).
   - Undefined-behavior / OOB input trips hardware `ud2` trap cleanly in isolated child process.
2. Z3 SMT ConcurrencyRaceProver:
   - Proves race-freedom & deadlock-freedom (`UNSAT`) for properly synchronized graphs.
   - Detects concurrent unprotected write/read race with Z3 model witness.
   - Detects AB-BA lock inversion deadlock cycle (`L1 -> L2 -> L1`).
3. Cross-ISA DifferentialFuzzer:
   - Compares `native`, `llvm` (O3 MCJIT), and `wasm` (Wasmtime) across 30 corner + PRNG vectors with 0 mismatches.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from compiler.sanitizer_pass import SanitizerInstrumentationPass
from compiler.ssa_ir import BasicBlock, SSAFunction, SSAInstruction, SSAVar, lower_ast_to_ssa
from omni_repo_compiler import OmniRepoCompiler
from validation.concurrency_race_prover import ConcurrencyRaceProver, MemoryEvent
from validation.differential_fuzzer import DifferentialFuzzer


class TestAlphaC99SanitizersConcurrencyFuzzer(unittest.TestCase):
    def test_c99_ubsan_div_zero_and_asan_bounds_instrumentation(self) -> None:
        # 1. Verify ASan + UBSan SSA pass inserts null + bounds traps on alloca/load_off
        fn = SSAFunction("check_buf", ["idx"])
        entry = BasicBlock("entry")
        buf = SSAVar("buf", 1)
        off = SSAVar("off", 2)
        c8 = SSAVar("c8", 3)
        val = SSAVar("val", 4)
        entry.add_instruction(SSAInstruction(buf, "alloca", [16], source_line=10))
        entry.add_instruction(SSAInstruction(c8, "const", [8], source_line=11))
        entry.add_instruction(SSAInstruction(off, "mul", [SSAVar("idx", 0), c8], source_line=11))
        entry.add_instruction(SSAInstruction(val, "load_off", [buf, off], source_line=12))
        entry.add_instruction(SSAInstruction(None, "ret", [val], source_line=13))
        fn.add_block(entry)

        s_rep = SanitizerInstrumentationPass("asan,ubsan").instrument_function(fn)
        self.assertGreaterEqual(s_rep.asan_null_checks, 1)
        self.assertGreaterEqual(s_rep.asan_bounds_checks, 2)
        self.assertGreaterEqual(s_rep.trap_blocks_inserted, 3)

        # 2. Full OmniRepoCompiler end-to-end UBSan binary test (`div_by_zero` hardware trap!)
        with tempfile.TemporaryDirectory() as td:
            repo_dir = os.path.join(td, "san_repo")
            os.makedirs(repo_dir, exist_ok=True)
            with open(os.path.join(repo_dir, "safe_math.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def c99_safe_div(a: int, b: int) -> int:\n"
                    "    q = a // b\n"
                    "    return q + 10\n"
                )

            out_base = os.path.join(td, "c99_san_lib")
            compiler = OmniRepoCompiler()
            try:
                res = compiler.compile_repositories(
                    repo_paths=[repo_dir],
                    output_path=out_base,
                    entry_export="c99_safe_div",
                    backend="native",
                    sanitize="asan,ubsan",
                    emit_provenance=False,
                )
            finally:
                compiler.close()

            self.assertTrue(res["success"])
            san_stage = res["stages"].get("sanitizers", {})
            self.assertTrue(san_stage.get("enabled"))
            self.assertGreaterEqual(san_stage.get("total_traps_inserted", 0), 1)
            lib_path = res["stages"]["emission"]["artifact_path"]
            self.assertTrue(os.path.exists(lib_path))

            # Safe invocation (30 // 5 + 10 == 16)
            ok_cmd = (
                "import ctypes, sys; "
                "l = ctypes.CDLL(sys.argv[1]); "
                "l.c99_safe_div.argtypes = [ctypes.c_int64, ctypes.c_int64]; "
                "l.c99_safe_div.restype = ctypes.c_int64; "
                "print(l.c99_safe_div(30, 5))"
            )
            p_ok = subprocess.run(
                [sys.executable, "-c", ok_cmd, lib_path],
                capture_output=True,
                text=True,
                timeout=15,
                stdin=subprocess.DEVNULL,
            )
            self.assertEqual(p_ok.returncode, 0, msg=p_ok.stderr)
            self.assertEqual(p_ok.stdout.strip(), "16")

            # Unsafe invocation (divisor == 0) MUST trip __omni_sanitizer_trap (ud2 -> non-zero fault)
            trap_cmd = (
                "import ctypes, sys; "
                "l = ctypes.CDLL(sys.argv[1]); "
                "l.c99_safe_div.argtypes = [ctypes.c_int64, ctypes.c_int64]; "
                "l.c99_safe_div.restype = ctypes.c_int64; "
                "print(l.c99_safe_div(30, 0))"
            )
            p_trap = subprocess.run(
                [sys.executable, "-c", trap_cmd, lib_path],
                capture_output=True,
                text=True,
                timeout=15,
                stdin=subprocess.DEVNULL,
            )
            self.assertNotEqual(p_trap.returncode, 0, "Zero-divisor MUST trap via __omni_sanitizer_trap")

    def test_c99_z3_concurrency_race_prover(self) -> None:
        prover = ConcurrencyRaceProver()

        # Case A: Synchronized via Happens-Before & mutex locks + atomic op -> PROVEN safe
        safe_events = [
            MemoryEvent("e1", "t_main", "buf[0]", is_write=True),
            MemoryEvent("e2", "t_worker", "buf[0]", is_write=False, hb_after=("e1",)),
            MemoryEvent("e3", "t_main", "ctr", is_write=True, locks_held=("mu_a",)),
            MemoryEvent("e4", "t_worker", "ctr", is_write=True, locks_held=("mu_a",)),
            MemoryEvent("e5", "t_worker2", "flag", is_write=True, is_atomic=True),
            MemoryEvent("e6", "t_main", "flag", is_write=False, is_atomic=True),
        ]
        safe_rep = prover.verify(
            safe_events,
            lock_acquisitions=[("t1", ("L_outer", "L_inner")), ("t2", ("L_outer", "L_inner"))],
        )
        self.assertTrue(safe_rep.race_free_proven)
        self.assertTrue(safe_rep.deadlock_free_proven)
        self.assertEqual(safe_rep.detected_races, [])

        # Case B: Unsynchronized write/read on shared_acc -> Z3 refutes with race
        racy_events = [
            MemoryEvent("r1", "t1", "shared_acc", is_write=True),
            MemoryEvent("r2", "t2", "shared_acc", is_write=False),
        ]
        racy_rep = prover.verify(
            racy_events,
            lock_acquisitions=[("t1", ("L1", "L2")), ("t2", ("L2", "L1"))],
        )
        self.assertFalse(racy_rep.race_free_proven)
        self.assertEqual(len(racy_rep.detected_races), 1)
        self.assertEqual(racy_rep.detected_races[0]["location"], "shared_acc")
        self.assertFalse(racy_rep.deadlock_free_proven)
        self.assertGreaterEqual(len(racy_rep.deadlock_cycles), 1)

    def test_c99_cross_isa_differential_fuzzer(self) -> None:
        src = (
            "def c99_fuzz_kernel(a: int, b: int) -> int:\n"
            "    acc = (a * 3) + (b ^ 7)\n"
            "    for i in range(5):\n"
            "        if (acc & 1) == 0:\n"
            "            acc = acc + i + 2\n"
            "        else:\n"
            "            acc = acc - i\n"
            "    return acc\n"
        )
        fn_ast = ast.parse(src).body[0]
        ssa_fn = lower_ast_to_ssa(fn_ast, optimize=True)
        fuzzer = DifferentialFuzzer(seed=20261124, num_random_vectors=20)
        rep = fuzzer.fuzz_ssa_function(ssa_fn, backends=("native", "llvm", "wasm"))
        self.assertEqual(rep.backends_compared, ["llvm", "native", "wasm"])
        self.assertEqual(rep.vectors_tested, 30)
        self.assertEqual(rep.mismatches, [], msg=rep.mismatches)
        self.assertTrue(rep.passed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
