"""
OmniCompiler Independent Adversarial Boundary & Stress Audit Suite.
Authored by Agent 2 (Independent Adversarial Auditor).
Falsifies edge cases, boundary invariants, and malformed inputs.
"""

import unittest
import struct
import tempfile
import os
import sys
import shutil

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from validation.assembly_invariant_auditor import AssemblyInvariantAuditor
from validation.silicon_safety_sandbox import SiliconSafetySandbox, UNICORN_AVAILABLE
from slicer.inter_repo_slicer import InterRepoSlicer
from orchestrator.repo_manifest_ingestor import RepoManifest, SymbolSignature, RepoTopologyResolver, SymbolRequirement
from compiler.object_linker import NativeObjectLinker, ObjectModule, RelocationEntry
from slicer.persistent_cpg import PersistentCodePropertyGraph


class TestHostileBoundaryAdversarial(unittest.TestCase):

    def setUp(self):
        self.auditor = AssemblyInvariantAuditor()

    def test_truncated_stack_allocation_instructions(self):
        """Hostile Test 1: Truncated stack opcodes (48 83 ec without imm8, 48 81 ec without full imm32)."""
        # Truncated sub rsp imm8 (only 3 bytes) followed by ret
        code_truncated_imm8 = b"\x48\x83\xec\xc3"  # \xc3 is seen as imm8=0xc3=195, ret is missing!
        rep = self.auditor.audit_function_code(code_truncated_imm8, "trunc_imm8")
        self.assertFalse(rep.is_valid, "Failed to reject truncated imm8 opcode without ret")

        # Truncated sub rsp imm32 (only 2 bytes of imm32 provided before ret)
        code_truncated_imm32 = b"\x48\x81\xec\x00\x10\xc3"
        rep2 = self.auditor.audit_function_code(code_truncated_imm32, "trunc_imm32")
        self.assertFalse(rep2.is_valid, "Failed to reject truncated imm32 opcode without ret")

    def test_truncated_call_relative_displacement(self):
        """Hostile Test 2: Call instruction (E8) truncated with fewer than 4 bytes of displacement."""
        code_truncated_call = b"\xe8\x12\x34\xc3"
        rep = self.auditor.audit_function_code(code_truncated_call, "trunc_call")
        # E8 followed by 3 bytes ends with 0xc3, but E8 needs 4 displacement bytes.
        # Check that auditor does not crash and processes safely
        self.assertIsInstance(rep.is_valid, bool)

    def test_random_malformed_fuzz_buffers(self):
        """Hostile Test 3: Random/adversarial byte patterns must never cause unhandled Python exceptions."""
        malformed_samples = [
            b"\x00" * 100,
            b"\xff" * 100,
            b"\x48\x89" * 50,
            b"\xcc" * 10,
            b"\x90" * 1000 + b"\xc3",
            b"\x48\x83\xec\x10\x90\x48\x83\xc4\x10\xc3",  # balanced
        ]
        for idx, sample in enumerate(malformed_samples):
            rep = self.auditor.audit_function_code(sample, f"fuzz_{idx}")
            self.assertIsNotNone(rep)
            self.assertIsInstance(rep.is_valid, bool)

    def test_linker_unresolved_symbol_rejection(self):
        """Hostile Test 4: Relocation referencing missing external symbol must raise LinkerError."""
        from compiler.object_linker import LinkerError
        linker = NativeObjectLinker()
        mod = ObjectModule("mod_faulty")
        # Function contains call to non-existent 'phantom_kernel'
        mod.add_symbol("caller_fn", b"\xe8\x00\x00\x00\x00\xc3")
        mod.relocations.append(RelocationEntry(
            section=".text",
            offset=1,
            symbol_name="phantom_kernel",
            reloc_type="REL32",
            addend=-4
        ))
        linker.add_module(mod)
        with self.assertRaises(LinkerError) as ctx:
            linker.link()
        self.assertIn("phantom_kernel", str(ctx.exception))

    def test_slicer_empty_roots_and_isolated_islands(self):
        """Hostile Test 5: Slicer given empty root list or disconnected islands."""
        slicer = InterRepoSlicer()
        m1 = RepoManifest("r1", "/r1", "py", [SymbolSignature("s1", [])], [])
        m2 = RepoManifest("r2", "/r2", "py", [SymbolSignature("s2", [])], [])

        # Empty root symbols: fallback retains designated entry or prunes deterministically
        res = slicer.slice_repositories([m1, m2], root_symbols=[])
        self.assertIsInstance(res["total_after"], int)
        self.assertGreaterEqual(res["total_after"], 0)
        self.assertEqual(res["total_before"], res["total_after"] + res["pruned_count"])

    def test_topology_three_way_cycle_containment(self):
        """Hostile Test 6: 3-way cyclic dependencies (A -> B -> C -> A) must not infinite loop."""
        resolver = RepoTopologyResolver()
        m_a = RepoManifest("repo_a", "/a", "python", [SymbolSignature("fn_a", [])], [SymbolRequirement("fn_b")])
        m_b = RepoManifest("repo_b", "/b", "python", [SymbolSignature("fn_b", [])], [SymbolRequirement("fn_c")])
        m_c = RepoManifest("repo_c", "/c", "python", [SymbolSignature("fn_c", [])], [SymbolRequirement("fn_a")])

        topo = resolver.resolve_topology([m_a, m_b, m_c])
        self.assertEqual(len(topo["compile_order"]), 3)
        self.assertEqual(set(topo["compile_order"]), {"repo_a", "repo_b", "repo_c"})

    def test_cpg_multi_tenant_taint_isolation_adversarial(self):
        """Hostile Test 7: Adversarial attempt to bridge tenant A confidential data into tenant B public sink."""
        temp_dir = tempfile.mkdtemp(prefix="adv_cpg_")
        try:
            db_path = os.path.join(temp_dir, "adv_cpg.db")
            cpg = PersistentCodePropertyGraph(db_path=db_path)

            # Tenant A: Secret source
            n1 = cpg.add_node("PARAM:SECRET", "tenant_a_secret", repo_name="repo_a", properties={"tenant": "tenant_a"})
            n2 = cpg.add_node("VAR", "calc_a", repo_name="repo_a", properties={"tenant": "tenant_a"})
            cpg.add_edge(n1, n2, "DDG_FLOW")

            # Tenant B: Public sink
            n3 = cpg.add_node("VAR", "calc_b", repo_name="repo_b", properties={"tenant": "tenant_b"})
            n4 = cpg.add_node("SINK:EXPORT", "public_sink_b", repo_name="repo_b", properties={"tenant": "tenant_b"})
            cpg.add_edge(n3, n4, "DDG_FLOW")

            # Check for path between tenant_a secret and tenant_b public sink
            path = cpg.find_cross_repo_taint_path("tenant_a_secret", "public_sink_b")
            self.assertIsNone(path, "Taint flow leaked between isolated tenants!")

            cpg.close()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_silicon_safety_division_by_zero_trap(self):
        """Hostile Test 8: Division by zero trap in Unicorn virtual CPU."""
        if not UNICORN_AVAILABLE:
            self.skipTest("Unicorn not available")
        sandbox = SiliconSafetySandbox()
        # xor rdx, rdx; xor rcx, rcx; idiv rcx; ret
        # \x48\x31\xd2\x48\x31\xc9\x48\xf7\xf9\xc3
        div_zero_code = b"\x48\x31\xd2\x48\x31\xc9\x48\xf7\xf9\xc3"
        res = sandbox.emulate_x86_64(div_zero_code)
        self.assertFalse(res.is_safe_for_silicon, "Silicon sandbox failed to trap division by zero!")
        self.assertFalse(res.success)


if __name__ == "__main__":
    unittest.main()
