"""
Unit Tests for OmniCompiler Cryptographic Audit Ledger & Relocation Bounds (Protocol ALPHA-C5)
Validates C5.2 Authenticated Evidence, Section 8B Bound Identity, and Linker Boundary Invariants.
"""

import os
import copy
import hashlib
import unittest
from compiler.audit_ledger import (
    create_compilation_audit_ledger,
    verify_audit_ledger,
    compute_source_merkle_root,
    compute_ledger_signature,
    DEFAULT_AUDIT_SALT
)
from compiler.object_linker import (
    NativeObjectLinker,
    ObjectModule,
    RelocationEntry,
    RelocationOutOfBoundsError,
    LinkerError
)


class TestCompilationAuditLedger(unittest.TestCase):
    def setUp(self):
        self.sample_bytes = b"\xb8\x2a\x00\x00\x00\xc3"  # mov eax, 42; ret
        self.nonce = "NONCE-C5-20261023-OMNI01"
        self.builder_id = "SESSION-BUILDER-C5-c406d4a9"
        self.runner_id = "RUNNER-TRUSTED-CPYTHON311-WIN64"

    def test_ledger_creation_and_verification_success(self):
        ledger = create_compilation_audit_ledger(
            audit_nonce=self.nonce,
            builder_session_id=self.builder_id,
            runner_id=self.runner_id,
            target_os="windows",
            arch="x86_64",
            format_type="shared_lib",
            binary_bytes=self.sample_bytes
        )
        is_valid, msg = verify_audit_ledger(ledger, binary_bytes=self.sample_bytes)
        self.assertTrue(is_valid, f"Verification failed: {msg}")
        self.assertEqual(msg, "VALID_AUTHENTICATED_LEDGER")
        self.assertEqual(ledger["audit_nonce"], self.nonce)
        self.assertEqual(ledger["verified"], True)
        self.assertEqual(ledger["trusted_runner"], True)

    def test_reject_tampered_payload_signature(self):
        ledger = create_compilation_audit_ledger(
            audit_nonce=self.nonce,
            builder_session_id=self.builder_id,
            runner_id=self.runner_id,
            target_os="windows",
            arch="x86_64",
            format_type="shared_lib",
            binary_bytes=self.sample_bytes
        )
        # Tamper payload
        tampered = copy.deepcopy(ledger)
        tampered["target_config"]["target_os"] = "linux"
        is_valid, msg = verify_audit_ledger(tampered, binary_bytes=self.sample_bytes)
        self.assertFalse(is_valid)
        self.assertIn("signature mismatch", msg)

    def test_reject_tampered_binary_bytes(self):
        ledger = create_compilation_audit_ledger(
            audit_nonce=self.nonce,
            builder_session_id=self.builder_id,
            runner_id=self.runner_id,
            target_os="windows",
            arch="x86_64",
            format_type="shared_lib",
            binary_bytes=self.sample_bytes
        )
        corrupt_bytes = b"\x90\x90\x90\x90\x90\xc3"
        is_valid, msg = verify_audit_ledger(ledger, binary_bytes=corrupt_bytes)
        self.assertFalse(is_valid)
        self.assertIn("Binary SHA-256 mismatch", msg)

    def test_reject_string_booleans_in_verified(self):
        ledger = create_compilation_audit_ledger(
            audit_nonce=self.nonce,
            builder_session_id=self.builder_id,
            runner_id=self.runner_id,
            target_os="windows",
            arch="x86_64",
            format_type="shared_lib",
            binary_bytes=self.sample_bytes
        )
        # Section 8B explicitly requires literal booleans, rejecting "true" string
        tampered = copy.deepcopy(ledger)
        tampered["verified"] = "true"  # String instead of True
        tampered["hmac_signature"] = compute_ledger_signature(tampered)
        is_valid, msg = verify_audit_ledger(tampered, binary_bytes=self.sample_bytes)
        self.assertFalse(is_valid)
        self.assertIn("must be boolean True", msg)

    def test_reject_unverified_formal_proof(self):
        proofs = {
            "heap_biabduction": True,
            "assembly_invariants": False,  # Failed proof
            "silicon_safety": True,
            "structural_audit": True
        }
        ledger = create_compilation_audit_ledger(
            audit_nonce=self.nonce,
            builder_session_id=self.builder_id,
            runner_id=self.runner_id,
            target_os="windows",
            arch="x86_64",
            format_type="shared_lib",
            binary_bytes=self.sample_bytes,
            formal_proofs_passed=proofs
        )
        is_valid, msg = verify_audit_ledger(ledger, binary_bytes=self.sample_bytes)
        self.assertFalse(is_valid)
        self.assertIn("assembly_invariants", msg)

    def test_source_merkle_root_determinism(self):
        root1 = compute_source_merkle_root(["compiler", "validation"])
        root2 = compute_source_merkle_root(["compiler", "validation"])
        self.assertEqual(root1, root2)
        self.assertEqual(len(root1), 64)


class TestObjectLinkerRelocationBounds(unittest.TestCase):
    def setUp(self):
        self.linker = NativeObjectLinker()

    def test_valid_relocation_linking(self):
        mod_caller = ObjectModule("caller")
        # E8 00 00 00 00 (call disp32); C3 (ret)
        mod_caller.add_symbol("call_target", b"\xe8\x00\x00\x00\x00\xc3")
        mod_caller.add_call_relocation(offset_in_text=1, target_symbol="callee_func")

        mod_callee = ObjectModule("callee")
        # B8 2A 00 00 00 (mov eax, 42); C3 (ret)
        mod_callee.add_symbol("callee_func", b"\xb8\x2a\x00\x00\x00\xc3")

        self.linker.add_module(mod_caller)
        self.linker.add_module(mod_callee)

        res = self.linker.link()
        self.assertTrue(res["success"])
        self.assertEqual(res["relocations_applied"], 1)

    def test_reject_out_of_bounds_relocation_offset(self):
        mod = ObjectModule("corrupt_offset")
        mod.add_symbol("func1", b"\xb8\x01\x00\x00\x00\xc3")
        # Relocation at offset 10 in a 6-byte text section
        mod.relocations.append(RelocationEntry(
            section=".text",
            offset=10,
            symbol_name="func1",
            reloc_type="REL32"
        ))
        self.linker.add_module(mod)
        with self.assertRaises(RelocationOutOfBoundsError):
            self.linker.link()

    def test_reject_negative_relocation_offset(self):
        mod = ObjectModule("negative_offset")
        mod.add_symbol("func2", b"\xb8\x01\x00\x00\x00\xc3")
        mod.relocations.append(RelocationEntry(
            section=".text",
            offset=-4,
            symbol_name="func2",
            reloc_type="REL32"
        ))
        self.linker.add_module(mod)
        with self.assertRaises(RelocationOutOfBoundsError):
            self.linker.link()

    def test_reject_unresolved_external_symbol(self):
        mod = ObjectModule("unresolved")
        mod.add_symbol("caller", b"\xe8\x00\x00\x00\x00\xc3")
        mod.add_call_relocation(offset_in_text=1, target_symbol="nonexistent_function")
        self.linker.add_module(mod)
        with self.assertRaises(LinkerError):
            self.linker.link()


if __name__ == "__main__":
    unittest.main()
