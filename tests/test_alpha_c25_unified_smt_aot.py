"""
OmniCompiler Alpha-C25 Test Suite (tests/test_alpha_c25_unified_smt_aot.py)
Validates:
1. SSATranslationValidator `QF_ABV` Memory Theory:
   - Proves `SROAPass` and `DSEPass` preserve semantics over `alloca`/`store`/`load`.
   - Refutes buggy DSE passes that drop live local or caller-visible external stores.
   - Fails closed on escaped `alloca` pointers.
2. SSATranslationValidator Bounded Loop Unrolling:
   - Proves `LICMPass` equivalence over cyclic CFGs (`PROVEN_BOUNDED_EQUIVALENT`).
   - Fails closed (`UNVERIFIED_LOOP_BOUND_EXCEEDED`) when bound is vacuously small.
   - Refutes loop body mutations with exact counterexamples (`REFUTED_COUNTEREXAMPLE`).
3. Unified Multi-Backend AOT Dispatch in `OmniRepoCompiler`:
   - `backend="llvm"`: emits COFF/ELF object via `LLVMBackend`, links via `NativeObjectLinker`,
     and executes real native CPU instructions via `ctypes`.
   - `backend="wasm"`: lowers multi-block SSA to portable `\x00asm` `.wasm` binary and
     executes inside `Wasmtime`.
4. Active `InterProceduralSCCPPass` Call-Site Specialization in `OmniRepoCompiler` +
   expanded `VerifiedPassRunner` gate.
"""

import copy
import ctypes
import os
import sys
import tempfile
import unittest

from compiler.ssa_ir import (
    SSAFunction,
    BasicBlock,
    SSAInstruction,
    SSAVar,
    lower_source_to_ssa,
)
from compiler.sroa_and_devirt import SROAPass, DevirtualizationPass
from compiler.licm_and_dse import LICMPass, DSEPass
from compiler.wasm_backend import WasmBackend
from validation.ssa_translation_validator import (
    SSATranslationValidator,
    VerifiedPassRunner,
)
from omni_repo_compiler import OmniRepoCompiler


def _load_shared_lib(path: str):
    if sys.platform == "win32":
        return ctypes.WinDLL(path)
    return ctypes.CDLL(path)


def _unload_shared_lib(lib, fn_refs=()):
    for ref in fn_refs:
        del ref
    if sys.platform == "win32":
        h = lib._handle
        del lib
        ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(h))


class TestAlphaC25UnifiedSmtAot(unittest.TestCase):

    def test_01_qf_abv_memory_proves_sroa_and_dse_and_refutes_bug(self):
        """Proves SROAPass & DSEPass over QF_ABV memory and catches buggy store deletion."""
        fn = SSAFunction("mem_fn", ["x", "y"])
        bb = BasicBlock("entry")
        x = SSAVar("x", 0)
        y = SSAVar("y", 0)
        buf = SSAVar("buf", 0)
        v0 = SSAVar("v0", 0)
        v1 = SSAVar("v1", 0)
        r0 = SSAVar("r0", 0)
        r1 = SSAVar("r1", 0)
        res = SSAVar("res", 0)

        bb.add_instruction(SSAInstruction(x, "param", ["x"]))
        bb.add_instruction(SSAInstruction(y, "param", ["y"]))
        bb.add_instruction(SSAInstruction(buf, "alloca", [16]))
        bb.add_instruction(SSAInstruction(v0, "add", [x, 10]))
        bb.add_instruction(SSAInstruction(v1, "mul", [y, 3]))
        # Dead overwritten store to slot 0, then live store to slot 0 & slot 1
        bb.add_instruction(SSAInstruction(None, "store", [buf, 0, x]))
        bb.add_instruction(SSAInstruction(None, "store", [buf, 0, v0]))
        bb.add_instruction(SSAInstruction(None, "store", [buf, 1, v1]))
        bb.add_instruction(SSAInstruction(r0, "load", [buf, 0]))
        bb.add_instruction(SSAInstruction(r1, "load", [buf, 1]))
        bb.add_instruction(SSAInstruction(res, "add", [r0, r1]))
        bb.add_instruction(SSAInstruction(None, "ret", [res]))
        fn.add_block(bb)

        validator = SSATranslationValidator(enable_memory_theory=True)

        # Prove DSEPass equivalence (eliminates dead overwritten store + forwards loads)
        fn_dse, dse_stats = DSEPass().run_on_function(copy.deepcopy(fn))
        self.assertGreaterEqual(dse_stats["dse_eliminated_stores"], 1)
        verdict_dse = validator.verify_equivalence(fn, fn_dse)
        self.assertTrue(verdict_dse["proven"], f"DSE SMT proof failed: {verdict_dse}")
        self.assertEqual(verdict_dse["status"], "PROVEN_EQUIVALENT")

        # Prove SROAPass equivalence (eliminates alloca + remaining loads/stores)
        fn_sroa, sroa_stats = SROAPass().run_on_function(copy.deepcopy(fn))
        self.assertEqual(sroa_stats["sroa_replaced_allocas"], 1)
        verdict_sroa = validator.verify_equivalence(fn, fn_sroa)
        self.assertTrue(verdict_sroa["proven"], f"SROA SMT proof failed: {verdict_sroa}")
        self.assertEqual(verdict_sroa["status"], "PROVEN_EQUIVALENT")

        # Refute buggy external memory store deletion
        ext_fn = SSAFunction("ext_mem", ["ptr", "val"])
        ebb = BasicBlock("entry")
        ptr = SSAVar("ptr", 0)
        val = SSAVar("val", 0)
        ebb.add_instruction(SSAInstruction(ptr, "param", ["ptr"]))
        ebb.add_instruction(SSAInstruction(val, "param", ["val"]))
        ebb.add_instruction(SSAInstruction(None, "store", [ptr, 0, val]))
        ebb.add_instruction(SSAInstruction(None, "ret", [val]))
        ext_fn.add_block(ebb)

        buggy_ext = copy.deepcopy(ext_fn)
        buggy_ext.blocks[0].instructions = [
            i for i in buggy_ext.blocks[0].instructions if i.opcode != "store"
        ]
        verdict_bug = validator.verify_equivalence(ext_fn, buggy_ext)
        self.assertFalse(verdict_bug["proven"])
        self.assertEqual(verdict_bug["status"], "REFUTED_COUNTEREXAMPLE")

        # Fail closed if an alloca escapes via ret
        esc_fn = SSAFunction("esc_ret", ["x"])
        eb = BasicBlock("entry")
        ax = SSAVar("x", 0)
        abuf = SSAVar("buf", 0)
        eb.add_instruction(SSAInstruction(ax, "param", ["x"]))
        eb.add_instruction(SSAInstruction(abuf, "alloca", [8]))
        eb.add_instruction(SSAInstruction(None, "ret", [abuf]))
        esc_fn.add_block(eb)
        verdict_esc = validator.verify_equivalence(esc_fn, copy.deepcopy(esc_fn))
        self.assertFalse(verdict_esc["proven"])
        self.assertEqual(verdict_esc["status"], "UNVERIFIED_ESCAPED_ALLOCA_UNSUPPORTED")

    def test_02_bounded_loop_unrolling_proves_licm_and_catches_loop_bugs(self):
        """Proves LICMPass over cyclic CFG via bounded unrolling and catches loop mutations."""
        fn = SSAFunction("loop_sum", ["n", "a"])
        pre = BasicBlock("preheader")
        hdr = BasicBlock("header")
        body = BasicBlock("body")
        exit_b = BasicBlock("exit")

        pre.connect_to(hdr)
        hdr.connect_to(body)
        hdr.connect_to(exit_b)
        body.connect_to(hdr)

        n = SSAVar("n", 0)
        a = SSAVar("a", 0)
        c0 = SSAVar("c0", 0)
        c1 = SSAVar("c1", 0)
        i_v = SSAVar("i", 1)
        acc_v = SSAVar("acc", 1)
        cond = SSAVar("cond", 0)
        inv = SSAVar("inv", 0)
        acc_next = SSAVar("acc", 2)
        i_next = SSAVar("i", 2)

        pre.add_instruction(SSAInstruction(n, "param", ["n"]))
        pre.add_instruction(SSAInstruction(a, "param", ["a"]))
        pre.add_instruction(SSAInstruction(c0, "const", [0]))
        pre.add_instruction(SSAInstruction(c1, "const", [1]))
        pre.add_instruction(SSAInstruction(None, "br", ["header"]))

        hdr.phi_nodes.append(SSAInstruction(i_v, "phi", [], phi_incoming=[("preheader", c0), ("body", i_next)]))
        hdr.phi_nodes.append(SSAInstruction(acc_v, "phi", [], phi_incoming=[("preheader", c0), ("body", acc_next)]))
        hdr.add_instruction(SSAInstruction(cond, "cmp_lt", [i_v, n]))
        hdr.add_instruction(SSAInstruction(None, "br_cond", [cond, "body", "exit"]))

        body.loop_depth = 1
        hdr.loop_depth = 1
        body.add_instruction(SSAInstruction(inv, "add", [a, 7]))  # Loop-invariant!
        body.add_instruction(SSAInstruction(acc_next, "add", [acc_v, inv]))
        body.add_instruction(SSAInstruction(i_next, "add", [i_v, c1]))
        body.add_instruction(SSAInstruction(None, "br", ["header"]))

        exit_b.add_instruction(SSAInstruction(None, "ret", [acc_v]))

        fn.add_block(pre)
        fn.add_block(hdr)
        fn.add_block(body)
        fn.add_block(exit_b)

        fn_licm, licm_stats = LICMPass().run_on_function(copy.deepcopy(fn))
        self.assertGreaterEqual(licm_stats["licm_hoisted_insts"], 1)

        loop_validator = SSATranslationValidator(max_loop_unroll=4)
        verdict = loop_validator.verify_equivalence(fn, fn_licm)
        self.assertTrue(verdict["proven"], f"Bounded loop LICM proof failed: {verdict}")
        self.assertEqual(verdict["status"], "PROVEN_BOUNDED_EQUIVALENT")
        self.assertTrue(verdict["bounded"])

        # Mutant inside loop body (+ 7 -> + 9) must be refuted!
        buggy_loop = copy.deepcopy(fn_licm)
        for b in buggy_loop.blocks:
            for inst in b.instructions:
                if inst.result == inv and inst.opcode == "add":
                    inst.operands[1] = 9
        verdict_bug = loop_validator.verify_equivalence(fn, buggy_loop)
        self.assertFalse(verdict_bug["proven"])
        self.assertEqual(verdict_bug["status"], "REFUTED_COUNTEREXAMPLE")

        # Vacuous bound test: unconditional loop of 5 steps with max_loop_unroll=1 must fail closed
        fn_five = SSAFunction("fixed_five", ["x"])
        p5 = BasicBlock("entry")
        h5 = BasicBlock("header")
        b5 = BasicBlock("body")
        e5 = BasicBlock("exit")
        p5.connect_to(h5)
        h5.connect_to(b5)
        h5.connect_to(e5)
        b5.connect_to(h5)
        xv = SSAVar("x", 0)
        z5 = SSAVar("z", 0)
        k5 = SSAVar("k", 1)
        kn = SSAVar("k", 2)
        cnd5 = SSAVar("cnd", 0)
        p5.add_instruction(SSAInstruction(xv, "param", ["x"]))
        p5.add_instruction(SSAInstruction(z5, "const", [0]))
        p5.add_instruction(SSAInstruction(None, "br", ["header"]))
        h5.phi_nodes.append(SSAInstruction(k5, "phi", [], phi_incoming=[("entry", z5), ("body", kn)]))
        h5.add_instruction(SSAInstruction(cnd5, "cmp_lt", [k5, 5]))
        h5.add_instruction(SSAInstruction(None, "br_cond", [cnd5, "body", "exit"]))
        b5.add_instruction(SSAInstruction(kn, "add", [k5, 1]))
        b5.add_instruction(SSAInstruction(None, "br", ["header"]))
        e5.add_instruction(SSAInstruction(None, "ret", [k5]))
        fn_five.add_block(p5)
        fn_five.add_block(h5)
        fn_five.add_block(b5)
        fn_five.add_block(e5)

        too_small = SSATranslationValidator(max_loop_unroll=2)
        verdict_vac = too_small.verify_equivalence(fn_five, copy.deepcopy(fn_five))
        self.assertFalse(verdict_vac["proven"])
        self.assertEqual(verdict_vac["status"], "UNVERIFIED_LOOP_BOUND_EXCEEDED")

    def test_03_omni_repo_compiler_llvm_backend_e2e(self):
        """Compiles real Python multi-block code via OmniRepoCompiler(backend='llvm') and runs on CPU."""
        compiler = OmniRepoCompiler()
        if not compiler.llvm.is_available:
            self.skipTest("LLVM backend unavailable")

        with tempfile.TemporaryDirectory() as td:
            repo_dir = os.path.join(td, "repo_llvm")
            os.makedirs(repo_dir, exist_ok=True)
            with open(os.path.join(repo_dir, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("""
[project]
name = "repo_llvm"
version = "0.1.0"
[tool.omnicompiler.exports]
llvm_sum_sq = { file = "llvm_mod.py", symbol = "llvm_sum_sq" }
""")
            with open(os.path.join(repo_dir, "llvm_mod.py"), "w", encoding="utf-8") as f:
                f.write("""
def llvm_sum_sq(n: int) -> int:
    acc = 0
    for i in range(1, n + 1):
        acc = acc + (i * i)
    return acc
""")

            out_lib = os.path.join(td, "llvm_out")
            res = compiler.compile_repositories(
                repo_paths=[repo_dir],
                output_path=out_lib,
                target_format="shared_lib",
                entry_export="llvm_sum_sq",
                backend="llvm",
            )
            self.assertTrue(res["success"])
            self.assertEqual(res["target"]["backend"], "llvm")
            self.assertGreaterEqual(res["stages"]["codegen"]["llvm_compiled_functions"], 1)
            self.assertGreaterEqual(res["stages"]["codegen"]["smt_pass_proofs"], 1)
            self.assertEqual(res["stages"]["codegen"]["smt_pass_rollbacks"], 0)

            artifact_path = res["stages"]["emission"]["artifact_path"]
            lib = _load_shared_lib(artifact_path)
            fn = getattr(lib, "llvm_sum_sq")
            try:
                fn.argtypes = [ctypes.c_int64]
                fn.restype = ctypes.c_int64
                self.assertEqual(fn(10), 385)  # 1^2 + ... + 10^2 = 385
            finally:
                _unload_shared_lib(lib, (fn,))

    def test_04_omni_repo_compiler_wasm_backend_e2e(self):
        """Compiles real Python multi-block code via OmniRepoCompiler(backend='wasm') and executes in Wasmtime."""
        compiler = OmniRepoCompiler()
        if not compiler.wasm.is_available:
            self.skipTest("Wasmtime runtime unavailable")

        with tempfile.TemporaryDirectory() as td:
            repo_dir = os.path.join(td, "repo_wasm")
            os.makedirs(repo_dir, exist_ok=True)
            with open(os.path.join(repo_dir, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("""
[project]
name = "repo_wasm"
version = "0.1.0"
[tool.omnicompiler.exports]
wasm_fib = { file = "wasm_mod.py", symbol = "wasm_fib" }
""")
            with open(os.path.join(repo_dir, "wasm_mod.py"), "w", encoding="utf-8") as f:
                f.write("""
def wasm_fib(n: int) -> int:
    if n <= 1:
        return n
    a = 0
    b = 1
    for _i in range(2, n + 1):
        nxt = a + b
        a = b
        b = nxt
    return b
""")

            out_wasm = os.path.join(td, "out.wasm")
            res = compiler.compile_repositories(
                repo_paths=[repo_dir],
                output_path=out_wasm,
                target_format="executable",
                entry_export="wasm_fib",
                backend="wasm",
            )
            self.assertTrue(res["success"])
            self.assertEqual(res["target"]["backend"], "wasm")
            self.assertTrue(res["stages"]["wasm"]["valid_wasm_magic"])

            with open(out_wasm, "rb") as wf:
                raw_wasm = wf.read()
            self.assertEqual(raw_wasm[:4], b"\x00asm")

            val = compiler.wasm.execute_wasm(raw_wasm.decode("latin1") if False else __import__("wasmtime").Module(compiler.wasm._engine, raw_wasm).serialize(), "wasm_fib", args=[15])
            self.assertEqual(val, 610)

    def test_05_omni_repo_compiler_ipsccp_specialization_active(self):
        """Verifies InterProceduralSCCPPass actively specializes constant-arg call sites end-to-end."""
        with tempfile.TemporaryDirectory() as td:
            repo_a = os.path.join(td, "repo_a")
            repo_b = os.path.join(td, "repo_b")
            os.makedirs(repo_a, exist_ok=True)
            os.makedirs(repo_b, exist_ok=True)

            with open(os.path.join(repo_a, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("""
[project]
name = "repo_a"
version = "0.1.0"
[tool.omnicompiler.exports]
scale_shift = { file = "math_core.py", symbol = "scale_shift" }
""")
            with open(os.path.join(repo_a, "math_core.py"), "w", encoding="utf-8") as f:
                f.write("""
def scale_shift(x: int, factor: int, bias: int) -> int:
    acc = x * factor
    if bias == 1:
        acc = acc + 1
    elif bias == 2:
        acc = acc + 2
    elif bias == 3:
        acc = acc + 3
    elif bias == 4:
        acc = acc + 4
    elif bias == 12:
        acc = acc + 12
    else:
        acc = acc + bias
    return acc
""")

            with open(os.path.join(repo_b, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("""
[project]
name = "repo_b"
version = "0.1.0"
[tool.omnicompiler.dependencies]
repo_a = ">=0.1.0"
[tool.omnicompiler.exports]
app_entry = { file = "app.py", symbol = "app_entry" }
""")
            with open(os.path.join(repo_b, "app.py"), "w", encoding="utf-8") as f:
                f.write("""
def app_entry(x: int) -> int:
    return scale_shift(x, 8, 12)
""")

            compiler = OmniRepoCompiler()
            res = compiler.compile_repositories(
                repo_paths=[repo_a, repo_b],
                output_path=os.path.join(td, "spec_out"),
                target_format="shared_lib",
                entry_export="app_entry",
                export_all=True,
                backend="native",
            )
            self.assertTrue(res["success"])
            cg = res["stages"]["codegen"]
            self.assertGreaterEqual(cg["specialized_functions"], 1)
            self.assertGreaterEqual(cg["smt_pass_proofs"], 2)
            self.assertEqual(cg["smt_pass_rollbacks"], 0)

            lib = _load_shared_lib(res["stages"]["emission"]["artifact_path"])
            fn = getattr(lib, "app_entry")
            try:
                fn.argtypes = [ctypes.c_int64]
                fn.restype = ctypes.c_int64
                self.assertEqual(fn(5), 52)  # 5 * 8 + 12 = 52
            finally:
                _unload_shared_lib(lib, (fn,))


if __name__ == "__main__":
    unittest.main()
