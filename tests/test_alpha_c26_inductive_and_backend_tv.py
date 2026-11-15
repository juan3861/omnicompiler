"""
Alpha-C26 Comprehensive Verification Suite:
1. Unbounded 1-inductive loop translation validation (`PROVEN_INDUCTIVE_EQUIVALENT`, `bounded=False`)
   for arbitrary symbolic bounds, plus counterexample refutation & auto-rollback.
2. Formal Z3 SSA -> LLVM IR translation validation & mutation detection.
3. Formal Z3 SSA -> WebAssembly WAT translation validation & mutation detection.
4. Physical cross-backend differential equivalence (`Native x86-64 JIT` == `LLVM O3 MCJIT` == `Wasmtime`)
   covering `shr` signed shift, `neg`, `not`, `if/else`, and loops, plus Unicorn ARM64 `neg`/`not`/`sar`.
5. End-to-end `OmniRepoCompiler` wiring of `BiAbductionVerifier` (`separation_logic`) and
   `BackendTranslationValidator` (`backend_validation`) on both `backend="llvm"` and `backend="wasm"`.
"""

import ast
import copy
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.ssa_ir import SSAFunction, BasicBlock, SSAInstruction, SSAVar, lower_ast_to_ssa
from compiler.licm_and_dse import LICMPass
from compiler.llvm_backend import LLVMBackend
from compiler.wasm_backend import WasmBackend
from compiler.native_codegen import NativeCodeGenerator
from validation.ssa_translation_validator import SSATranslationValidator, VerifiedPassRunner
from validation.backend_translation_validator import BackendTranslationValidator
from validation.silicon_safety_sandbox import SiliconSafetySandbox
from omni_repo_compiler import OmniRepoCompiler


def _build_symbolic_loop_ssa(fn_name: str = "sym_loop") -> SSAFunction:
    """
    Symbolic unbounded loop equivalent to:
      def sym_loop(a, n):
          i = 0
          acc = 0
          while i < n:
              k = a * 3 + 7  # loop-invariant inside body (hoisted by LICM)
              acc = acc + k
              i = i + 1
          return acc
    """
    fn = SSAFunction(fn_name, ["a", "n"])
    entry = BasicBlock("entry")
    header = BasicBlock("header")
    body = BasicBlock("body")
    exit_b = BasicBlock("exit")
    header.loop_depth = 1
    body.loop_depth = 1

    entry.connect_to(header)
    header.connect_to(body)
    header.connect_to(exit_b)
    body.connect_to(header)

    pa = SSAVar("a", 0)
    pn = SSAVar("n", 0)
    z = SSAVar("z", 0)
    i_phi = SSAVar("i", 1)
    acc_phi = SSAVar("acc", 1)
    cond = SSAVar("cond", 0)
    t1 = SSAVar("t", 1)
    inv = SSAVar("inv", 1)
    acc_next = SSAVar("acc", 2)
    i_next = SSAVar("i", 2)

    entry.add_instruction(SSAInstruction(pa, "param", ["a"]))
    entry.add_instruction(SSAInstruction(pn, "param", ["n"]))
    entry.add_instruction(SSAInstruction(z, "const", [0]))
    entry.add_instruction(SSAInstruction(None, "br", ["header"]))

    header.phi_nodes.append(
        SSAInstruction(i_phi, "phi", [z, i_next], phi_incoming=[("entry", z), ("body", i_next)])
    )
    header.phi_nodes.append(
        SSAInstruction(acc_phi, "phi", [z, acc_next], phi_incoming=[("entry", z), ("body", acc_next)])
    )
    header.add_instruction(SSAInstruction(cond, "cmp_lt", [i_phi, pn]))
    header.add_instruction(SSAInstruction(None, "br_cond", [cond, "body", "exit"]))

    body.add_instruction(SSAInstruction(t1, "mul", [pa, 3]))
    body.add_instruction(SSAInstruction(inv, "add", [t1, 7]))
    body.add_instruction(SSAInstruction(acc_next, "add", [acc_phi, inv]))
    body.add_instruction(SSAInstruction(i_next, "add", [i_phi, 1]))
    body.add_instruction(SSAInstruction(None, "br", ["header"]))

    exit_b.add_instruction(SSAInstruction(None, "ret", [acc_phi]))

    fn.add_block(entry)
    fn.add_block(header)
    fn.add_block(body)
    fn.add_block(exit_b)
    fn.entry_block = entry
    return fn


class TestAlphaC26InductiveAndBackendTV(unittest.TestCase):
    def test_01_unbounded_inductive_loop_proves_licm_and_catches_loop_bugs(self):
        """Proves LICMPass over unbounded symbolic loop without finite unrolling & refutes step/hoist bugs."""
        fn = _build_symbolic_loop_ssa()

        # Test pure inductive mode (max_loop_unroll=0, enable_inductive_loops=True)
        ind_validator = SSATranslationValidator(
            enable_memory_theory=True,
            max_loop_unroll=0,
            enable_inductive_loops=True,
        )
        licm_after, licm_stats = LICMPass().run_on_function(copy.deepcopy(fn))
        self.assertGreaterEqual(licm_stats.get("licm_hoisted_insts", 0), 1)

        verdict = ind_validator.verify_equivalence(fn, licm_after, timeout_ms=1000)
        self.assertTrue(verdict["proven"], f"Expected unbounded inductive proof, got: {verdict}")
        self.assertEqual(verdict["status"], "PROVEN_INDUCTIVE_EQUIVALENT")
        self.assertFalse(verdict["bounded"])

        # Also verify hybrid mode (max_loop_unroll=4, enable_inductive_loops=True) upgrades to unbounded proof
        hybrid_runner = VerifiedPassRunner(
            timeout_ms=1000,
            enable_memory_theory=True,
            max_loop_unroll=4,
            enable_inductive_loops=True,
        )

        # Buggy pass A: corrupts step (`i += 2` instead of `i += 1`) -> must refute & rollback
        def buggy_step_pass(f: SSAFunction):
            bad = copy.deepcopy(f)
            for blk in bad.blocks:
                if blk.name == "body":
                    for inst in blk.instructions:
                        if inst.opcode == "add" and inst.result and inst.result.name == "i":
                            inst.operands[1] = 2
            return bad, {"mutated": 1}

        res_fn, _, rep_a = hybrid_runner.run_verified_pass(copy.deepcopy(fn), buggy_step_pass)
        self.assertTrue(rep_a["rolled_back"])
        self.assertFalse(rep_a["verified"])
        self.assertEqual(rep_a["verdict"]["status"], "REFUTED_COUNTEREXAMPLE")
        self.assertIsNotNone(rep_a["verdict"]["counterexample"])

        # Buggy pass B: corrupts hoisted invariant (`a * 3 + 99`) -> must refute & rollback
        def buggy_hoist_pass(f: SSAFunction):
            bad, st = LICMPass().run_on_function(copy.deepcopy(f))
            for blk in bad.blocks:
                for inst in blk.instructions:
                    if inst.opcode == "add" and inst.result and inst.result.name == "inv":
                        inst.operands[1] = 99
            return bad, st

        _, _, rep_b = hybrid_runner.run_verified_pass(copy.deepcopy(fn), buggy_hoist_pass)
        self.assertTrue(rep_b["rolled_back"])
        self.assertEqual(rep_b["verdict"]["status"], "REFUTED_COUNTEREXAMPLE")

    def test_02_formal_ssa_to_llvm_ir_translation_validation_and_mutation_catch(self):
        """Proves emitted LLVM IR equivalent to source SSAFunction (including loops/shr/neg/not) & detects bugs."""
        src = """
def arith_branch(x, y):
    a = x >> 2
    b = -y
    c = not a
    if a < 0:
        return a + b + c
    return a - b
"""
        fn_ast = ast.parse(src).body[0]
        ssa_fn = lower_ast_to_ssa(fn_ast, optimize=True)
        llvm_be = LLVMBackend(opt_level=3)
        llvm_ir = llvm_be.ssa_to_llvm_ir(ssa_fn)

        btv = BackendTranslationValidator()
        ver = btv.verify_ssa_to_llvm_ir(ssa_fn, llvm_ir, timeout_ms=1000)
        self.assertTrue(ver["proven"], f"Expected LLVM IR TV proof, got: {ver}")
        self.assertEqual(ver["status"], "PROVEN_EQUIVALENT")

        # Also prove SSA loop -> LLVM IR
        loop_ssa = _build_symbolic_loop_ssa("llvm_sym_loop")
        loop_ir = llvm_be.ssa_to_llvm_ir(loop_ssa)
        ver_loop = btv.verify_ssa_to_llvm_ir(loop_ssa, loop_ir, timeout_ms=1000)
        self.assertTrue(ver_loop["proven"], f"Expected inductive/bounded LLVM loop proof, got: {ver_loop}")

        # Inject mutation 1: `ashr` -> `lshr`
        bad_ir_shift = llvm_ir.replace("ashr i64", "lshr i64", 1)
        self.assertNotEqual(bad_ir_shift, llvm_ir)
        ver_bad1 = btv.verify_ssa_to_llvm_ir(ssa_fn, bad_ir_shift, timeout_ms=1000)
        self.assertFalse(ver_bad1["proven"])
        self.assertEqual(ver_bad1["status"], "REFUTED_COUNTEREXAMPLE")

        # Inject mutation 2: `icmp slt` -> `icmp sgt`
        bad_ir_cmp = llvm_ir.replace("icmp slt i64", "icmp sgt i64", 1)
        self.assertNotEqual(bad_ir_cmp, llvm_ir)
        ver_bad2 = btv.verify_ssa_to_llvm_ir(ssa_fn, bad_ir_cmp, timeout_ms=1000)
        self.assertFalse(ver_bad2["proven"])
        self.assertEqual(ver_bad2["status"], "REFUTED_COUNTEREXAMPLE")

    def test_03_formal_ssa_to_wat_translation_validation_and_mutation_catch(self):
        """Proves emitted WebAssembly WAT equivalent to source SSAFunction (including loops) & detects bugs."""
        src = """
def branch_shift(x, y):
    s = x >> 2
    z = -s
    if s < y:
        return z + 11
    return s * 3
"""
        fn_ast = ast.parse(src).body[0]
        ssa_fn = lower_ast_to_ssa(fn_ast, optimize=True)
        wasm_be = WasmBackend()
        wat = wasm_be.ssa_to_wat(ssa_fn)

        btv = BackendTranslationValidator()
        ver = btv.verify_ssa_to_wat(ssa_fn, wat, timeout_ms=1000)
        self.assertTrue(ver["proven"], f"Expected WAT TV proof, got: {ver}")

        # Loop SSA -> WAT inductive proof
        loop_ssa = _build_symbolic_loop_ssa("wat_sym_loop")
        loop_wat = wasm_be.ssa_to_wat(loop_ssa)
        ver_loop = btv.verify_ssa_to_wat(loop_ssa, loop_wat, timeout_ms=1000)
        self.assertTrue(ver_loop["proven"], f"Expected inductive WAT loop proof, got: {ver_loop}")

        # Inject mutation: `i64.shr_s` -> `i64.shr_u`
        bad_wat = wat.replace("i64.shr_s", "i64.shr_u", 1)
        self.assertNotEqual(bad_wat, wat)
        ver_bad = btv.verify_ssa_to_wat(ssa_fn, bad_wat, timeout_ms=1000)
        self.assertFalse(ver_bad["proven"])
        self.assertEqual(ver_bad["status"], "REFUTED_COUNTEREXAMPLE")

    def test_04_cross_backend_differential_equivalence_and_shr_neg_not_silicon(self):
        """Executes shr/neg/not/branch/loop identically across Native JIT, LLVM MCJIT, Wasmtime & Unicorn ARM64."""
        src = """
def complex_kernel(x, n):
    acc = -(x >> 2)
    flag = not acc
    i = 0
    while i < n:
        acc = acc + (i * 2) - flag
        i = i + 1
    return acc
"""
        ssa_fn = lower_ast_to_ssa(ast.parse(src).body[0], optimize=True)
        btv = BackendTranslationValidator()
        vectors = [
            (-16, 0),
            (-16, 4),
            (0, 5),
            (1, 3),
            (7, 6),
            (42, 8),
        ]
        diff = btv.verify_differential_execution(ssa_fn, vectors, backends=("native", "llvm", "wasm"))
        self.assertTrue(diff["equivalent"], f"Differential mismatch across backends: {diff}")
        self.assertGreaterEqual(len(diff["active_backends"]), 2)
        if LLVMBackend(opt_level=3).is_available and WasmBackend().is_available:
            self.assertEqual(set(diff["active_backends"]), {"native", "llvm", "wasm"})
        self.assertEqual(diff["mismatches"], [])

        # Verify expected mathematical output for (-16, 4):
        # x >> 2 = -4 -> acc = 4, flag = 0; sum(0,2,4,6) = 12 -> 4 + 12 = 16
        self.assertEqual(diff["outputs_by_backend"]["native"][1], 16)
        # (0, 5): x >> 2 = 0 -> acc = 0, flag = 1; i=0..4 -> sum(0,2,4,6,8)-5 = 20-5 = 15
        self.assertEqual(diff["outputs_by_backend"]["native"][2], 15)

        # Verify ARM64 neg, not, sar opcodes in Unicorn CPU emulator
        arm_src = """
def arm_ops(x):
    a = x >> 1
    b = -a
    c = not b
    return b + c
"""
        arm_ssa = lower_ast_to_ssa(ast.parse(arm_src).body[0], optimize=True)
        arm_art = NativeCodeGenerator(arch="arm64", target_os="linux").compile_ssa(arm_ssa)
        sandbox = SiliconSafetySandbox()
        sim1 = sandbox.emulate_arm64(arm_art.code_bytes, args=[-10])
        self.assertTrue(sim1.is_safe_for_silicon)
        self.assertEqual(sim1.return_value, 5)  # (-10 >> 1) = -5 -> neg = 5 -> not = 0 -> 5
        sim2 = sandbox.emulate_arm64(arm_art.code_bytes, args=[0])
        self.assertTrue(sim2.is_safe_for_silicon)
        self.assertEqual(sim2.return_value, 1)  # 0 >> 1 = 0 -> neg = 0 -> not = 1 -> 1

    def test_05_omni_repo_compiler_c26_e2e_separation_and_backend_validation(self):
        """Verifies OmniRepoCompiler reports real BiAbduction separation proofs and backend validation."""
        compiler = OmniRepoCompiler()

        with tempfile.TemporaryDirectory() as td:
            repo_a = os.path.join(td, "repo_a")
            repo_b = os.path.join(td, "repo_b")
            os.makedirs(repo_a, exist_ok=True)
            os.makedirs(repo_b, exist_ok=True)

            with open(os.path.join(repo_a, "mod_a.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def scale_shift(x):\n"
                    "    a = x >> 1\n"
                    "    b = -a\n"
                    "    return (x + b) * 3\n"
                )
            with open(os.path.join(repo_a, "omnicompiler_manifest.json"), "w", encoding="utf-8") as f:
                f.write(
                    '{"repo_name": "repo_a", "version": "1.0.0", "exports": '
                    '[{"name": "scale_shift", "params": ["x"], "return_type": "int"}], "imports": []}'
                )

            with open(os.path.join(repo_b, "mod_b.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def branch_eval(x, y):\n"
                    "    if x > y:\n"
                    "        return x - y\n"
                    "    return y - x\n"
                )
            with open(os.path.join(repo_b, "omnicompiler_manifest.json"), "w", encoding="utf-8") as f:
                f.write(
                    '{"repo_name": "repo_b", "version": "1.0.0", "exports": '
                    '[{"name": "branch_eval", "params": ["x", "y"], "return_type": "int"}], '
                    '"imports": [{"symbol": "scale_shift", "from_repo": "repo_a"}]}'
                )

            if compiler.llvm.is_available:
                out_ext = ".dll" if os.name == "nt" else ".so"
                out_llvm = os.path.join(td, f"c26_llvm{out_ext}")
                res_llvm = compiler.compile_repositories(
                    repo_paths=[repo_a, repo_b],
                    output_path=out_llvm,
                    target_format="shared_lib",
                    entry_export="scale_shift",
                    export_all=True,
                    backend="llvm",
                )
                self.assertTrue(res_llvm["success"])
                self.assertTrue(res_llvm["stages"]["separation_logic"]["heap_disjointness_proven"])
                self.assertGreaterEqual(res_llvm["stages"]["separation_logic"]["pairs_verified"], 1)
                self.assertGreaterEqual(res_llvm["stages"]["backend_validation"]["proofs_proven"], 2)
                self.assertEqual(res_llvm["stages"]["backend_validation"]["refuted"], 0)
                self.assertEqual(res_llvm["stages"]["codegen"]["smt_pass_rollbacks"], 0)

            if compiler.wasm.is_available:
                out_wasm = os.path.join(td, "c26_wasm.wasm")
                res_wasm = compiler.compile_repositories(
                    repo_paths=[repo_a, repo_b],
                    output_path=out_wasm,
                    target_format="shared_lib",
                    entry_export="scale_shift",
                    export_all=True,
                    backend="wasm",
                )
                self.assertTrue(res_wasm["success"])
                self.assertTrue(res_wasm["stages"]["separation_logic"]["heap_disjointness_proven"])
                self.assertGreaterEqual(res_wasm["stages"]["backend_validation"]["proofs_proven"], 2)
                self.assertEqual(res_wasm["stages"]["backend_validation"]["refuted"], 0)

            # Now inject conflicting top-level shared mutable state across both repos and verify detection
            with open(os.path.join(repo_a, "mod_a.py"), "a", encoding="utf-8") as f:
                f.write("\nSHARED_CACHE_PTR = 100\n")
            with open(os.path.join(repo_b, "mod_b.py"), "a", encoding="utf-8") as f:
                f.write("\nSHARED_CACHE_PTR = 200\n")

            out_conflict = os.path.join(td, "c26_conflict.so" if os.name != "nt" else "c26_conflict.dll")
            res_conf = OmniRepoCompiler().compile_repositories(
                repo_paths=[repo_a, repo_b],
                output_path=out_conflict,
                target_format="shared_lib",
                entry_export="scale_shift",
                export_all=True,
                backend="native",
            )
            self.assertFalse(res_conf["stages"]["separation_logic"]["heap_disjointness_proven"])
            self.assertFalse(res_conf["stages"]["audit_ledger"]["formal_proofs_passed"]["heap_biabduction"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
