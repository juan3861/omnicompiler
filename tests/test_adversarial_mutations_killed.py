"""
OmniCompiler Independent Adversarial Mutation & Hostile Invariant Verification Suite.
Authored by Agent 2 (Independent Adversarial Auditor).

This suite systematically injects controlled mutants into:
1. Low-level assembly bytes (stack imbalance, missing RET, infinite loops).
2. Slicer dependency graphs (cycles, disconnects, symbol conservation).
3. Compiler pipeline safety gates (verifying pre-flight halts before physical execution).
4. Physical sandbox boundary containment (memory violation, illegal opcodes).
"""

import unittest
import struct
from validation.assembly_invariant_auditor import AssemblyInvariantAuditor
from validation.silicon_safety_sandbox import SiliconSafetySandbox, UNICORN_AVAILABLE
from slicer.inter_repo_slicer import InterRepoSlicer
from orchestrator.repo_manifest_ingestor import RepoManifest, SymbolSignature
from adapters.universal_abi_bridge import UniversalAbiBridge


class TestAdversarialAssemblyMutations(unittest.TestCase):
    def setUp(self):
        self.auditor = AssemblyInvariantAuditor()

    def test_kill_mutant_stack_imbalance_underflow(self):
        """Mutant 1: Allocates 0x40 bytes, but frees 0x20 bytes."""
        # sub rsp, 0x40; mov rax, 1; add rsp, 0x20; ret
        mutant_code = b"\x48\x83\xec\x40\xb8\x01\x00\x00\x00\x48\x83\xc4\x20\xc3"
        report = self.auditor.audit_function_code(mutant_code, "mutant_underflow")
        self.assertFalse(report.is_valid, "Auditor failed to kill stack underflow mutant!")
        self.assertFalse(report.stack_balanced)
        self.assertTrue(any("Stack frame imbalance" in err for err in report.errors))

    def test_kill_mutant_stack_imbalance_overflow(self):
        """Mutant 2: Allocates 0x20 bytes, but frees 0x40 bytes (corrupting return address)."""
        # sub rsp, 0x20; mov rax, 1; add rsp, 0x40; ret
        mutant_code = b"\x48\x83\xec\x20\xb8\x01\x00\x00\x00\x48\x83\xc4\x40\xc3"
        report = self.auditor.audit_function_code(mutant_code, "mutant_overflow")
        self.assertFalse(report.is_valid, "Auditor failed to kill stack overflow mutant!")
        self.assertFalse(report.stack_balanced)
        self.assertTrue(any("Stack frame imbalance" in err for err in report.errors))

    def test_kill_mutant_missing_ret_termination(self):
        """Mutant 3: Valid function logic but truncated without RET (executes into garbage)."""
        # mov rax, 42; nop
        mutant_code = b"\xb8\x2a\x00\x00\x00\x90"
        report = self.auditor.audit_function_code(mutant_code, "mutant_no_ret")
        self.assertFalse(report.is_valid, "Auditor failed to kill missing RET mutant!")
        self.assertFalse(report.termination_valid)
        self.assertTrue(any("does not terminate with RET" in err for err in report.errors))

    def test_kill_mutant_empty_byte_stream(self):
        """Mutant 4: Empty byte sequence passed to auditor."""
        report = self.auditor.audit_function_code(b"", "empty_func")
        self.assertFalse(report.is_valid)
        self.assertEqual(report.total_bytes_inspected, 0)
        self.assertIn("Function code is empty", report.errors[0])

    def test_detect_infinite_spinloop_warning(self):
        """Mutant 5: Unescapable spin-loop (EB FE) trapped inside function body."""
        # sub rsp, 8; jmp $; add rsp, 8; ret
        code = b"\x48\x83\xec\x08\xeb\xfe\x48\x83\xc4\x08\xc3"
        report = self.auditor.audit_function_code(code, "spinloop_func")
        self.assertTrue(any("contains unescapable spin-loop" in w for w in report.warnings))


class TestAdversarialSlicerMutations(unittest.TestCase):
    def setUp(self):
        self.slicer = InterRepoSlicer()

    def test_kill_mutant_cyclic_dependency_graph(self):
        """Mutant 6: Mutual cyclic recursion between Repo A and Repo B."""
        # repo_a has fn_a (calls fn_b)
        # repo_b has fn_b (calls fn_a)
        sig_a = SymbolSignature("fn_a", ["x"])
        sig_b = SymbolSignature("fn_b", ["y"])
        sig_dead = SymbolSignature("fn_dead", ["z"])

        manifest_a = RepoManifest(
            repo_name="repo_a", repo_path="/a", repo_type="python",
            exports=[sig_a, sig_dead], imports=[]
        )
        manifest_b = RepoManifest(
            repo_name="repo_b", repo_path="/b", repo_type="python",
            exports=[sig_b], imports=[]
        )

        call_graph = {
            "fn_a": ["fn_b"],
            "fn_b": ["fn_a"]
        }

        # Root is fn_a: both fn_a and fn_b must be reachable, fn_dead pruned
        res = self.slicer.slice_repositories(
            manifests=[manifest_a, manifest_b],
            root_symbols=["fn_a"],
            call_graph=call_graph
        )

        self.assertIn("fn_a", res["reachable_symbols"])
        self.assertIn("fn_b", res["reachable_symbols"])
        self.assertEqual(res["pruned_count"], 1)
        self.assertIn("repo_a::fn_dead", res["pruned_symbols"])
        self.assertEqual(res["total_after"], 2)

    def test_slicer_symbol_conservation_and_disjoint_partition(self):
        """Mutant 7: Ensure total_before == total_after + pruned_count."""
        manifests = [
            RepoManifest(
                repo_name="core", repo_path="/core", repo_type="c",
                exports=[
                    SymbolSignature("live_1", []),
                    SymbolSignature("live_2", []),
                    SymbolSignature("dead_1", []),
                    SymbolSignature("dead_2", [])
                ],
                imports=[]
            )
        ]
        call_graph = {"live_1": ["live_2"]}
        res = self.slicer.slice_repositories(manifests, root_symbols=["live_1"], call_graph=call_graph)

        self.assertEqual(res["total_before"], 4)
        self.assertEqual(res["total_after"], 2)
        self.assertEqual(res["pruned_count"], 2)
        self.assertEqual(res["total_before"], res["total_after"] + res["pruned_count"])

    def test_slicer_idempotency(self):
        """Mutant 8: Slicing an already-sliced manifest set must be an idempotent identity operation."""
        manifest = RepoManifest(
            repo_name="repo", repo_path="/repo", repo_type="c",
            exports=[SymbolSignature("live", []), SymbolSignature("dead", [])],
            imports=[]
        )
        # Pass 1
        res1 = self.slicer.slice_repositories([manifest], root_symbols=["live"], call_graph={})
        self.assertEqual(res1["pruned_count"], 1)

        # Pass 2 on the resulting manifest
        res2 = self.slicer.slice_repositories([manifest], root_symbols=["live"], call_graph={})
        self.assertEqual(res2["pruned_count"], 0)
        self.assertEqual(res2["total_before"], res2["total_after"])


class TestAdversarialSiliconSafetyGate(unittest.TestCase):
    def setUp(self):
        if not UNICORN_AVAILABLE:
            self.skipTest("Unicorn engine not available")
        self.sandbox = SiliconSafetySandbox()

    def test_kill_mutant_unmapped_null_pointer_dereference(self):
        """Mutant 9: Machine code dereferences NULL pointer (mov rax, [0x0])."""
        # mov rax, [0x0]; ret
        code = b"\x48\x8b\x04\x25\x00\x00\x00\x00\xc3"
        res = self.sandbox.emulate_x86_64(code)
        self.assertFalse(res.success, "Sandbox allowed NULL pointer read!")
        self.assertFalse(res.is_safe_for_silicon)

    def test_kill_mutant_infinite_loop_timeout_containment(self):
        """Mutant 10: Infinite spin-loop must be safely terminated by step limit."""
        code = b"\xeb\xfe"  # jmp $
        res = self.sandbox.emulate_x86_64(code, max_steps=100)
        self.assertFalse(res.is_safe_for_silicon)
        self.assertEqual(res.steps_executed, 100)


class TestAdversarialCompilerPipelineHaltOnAssemblyInvariantFailure(unittest.TestCase):
    def test_pipeline_halts_before_linking_on_corrupt_assembly(self):
        """
        Mutant 11: End-to-end pipeline must abort at Stage 5.5 if assembly auditor flags defect,
        NEVER allowing broken code to be emitted or physically executed.
        """
        import os
        import tempfile
        import shutil
        from omni_repo_compiler import OmniRepoCompiler

        temp_dir = tempfile.mkdtemp(prefix="adv_test_")
        try:
            repo_path = os.path.join(temp_dir, "test_repo")
            os.makedirs(repo_path)
            with open(os.path.join(repo_path, "pyproject.toml"), "w") as f:
                f.write("[project]\nname = 'test_repo'\nversion = '1.0'\n")
            with open(os.path.join(repo_path, "mod.py"), "w") as f:
                f.write("def foo(x): return x + 1\n")

            compiler = OmniRepoCompiler(db_path=os.path.join(temp_dir, "cpg.db"))

            # Monkeypatch the auditor to simulate a detected stack imbalance
            original_audit = compiler.asm_auditor.audit_function_code
            try:
                def poisoned_audit(code_bytes, symbol_name="anon"):
                    rep = original_audit(code_bytes, symbol_name)
                    rep.is_valid = False
                    rep.errors.append("Controlled Fault: Injected stack imbalance mutant")
                    return rep

                compiler.asm_auditor.audit_function_code = poisoned_audit

                output_dll = os.path.join(temp_dir, "out.dll")
                with self.assertRaises(RuntimeError) as ctx:
                    compiler.compile_repositories([repo_path], output_path=output_dll)

                self.assertIn("Assembly invariant audit failed", str(ctx.exception))
                self.assertFalse(os.path.exists(output_dll), "Pipeline produced output binary despite invariant failure!")
            finally:
                compiler.cpg.close()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
