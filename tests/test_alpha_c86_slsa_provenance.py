import base64
import json
import os
import shutil
import tempfile
import unittest

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestrator.rbe_cas import ActionSpec, ContentAddressableStore, HermeticSandboxExecutor
from packaging.packager import PackagerEngine
from packaging.slsa_provenance import (
    SLSAProvenanceGenerator,
    ed25519_generate_keypair,
    ed25519_sign,
    ed25519_verify,
)


class TestAlphaC86SLSAProvenance(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="omni_c86_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_01_rfc8032_ed25519_test_vectors_and_interop(self):
        # RFC 8032 Section 7.1 TEST 1 (empty message)
        sk1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        expected_pk1 = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        expected_sig1 = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        _, pk1 = ed25519_generate_keypair(sk1)
        self.assertEqual(pk1, expected_pk1)
        sig1 = ed25519_sign(sk1, b"")
        self.assertEqual(sig1, expected_sig1)
        self.assertTrue(ed25519_verify(pk1, b"", sig1))

        # RFC 8032 Section 7.1 TEST 2 (1-byte message 0x72)
        sk2 = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        expected_pk2 = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        expected_sig2 = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        _, pk2 = ed25519_generate_keypair(sk2)
        self.assertEqual(pk2, expected_pk2)
        sig2 = ed25519_sign(sk2, b"\x72")
        self.assertEqual(sig2, expected_sig2)
        self.assertTrue(ed25519_verify(pk2, b"\x72", sig2))
        self.assertFalse(ed25519_verify(pk2, b"\x73", sig2))

    def test_02_rbe_cas_sbom_slsa_l3_end_to_end_and_tamper_rejection(self):
        cas = ContentAddressableStore(os.path.join(self.tmpdir, "cas"))
        in_hash = cas.put_blob(b"source_unit_v1")
        spec = ActionSpec(
            action_id="build_elf_slsa",
            kind="emit_standalone_binary",
            payload={"target_format": "elf64", "exit_code": 0, "output_name": "app.elf"},
            input_blobs={"src/main.omni": in_hash},
        )
        executor = HermeticSandboxExecutor(cas)
        act_res = executor.execute(spec)

        out_bin_path = os.path.join(self.tmpdir, "app.elf")
        with open(out_bin_path, "wb") as f:
            f.write(cas.get_blob(act_res.output_blobs["app.elf"]))

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"name": "omnicompiler-runtime", "version": "2.0.0"}],
        }
        prov_path = os.path.join(self.tmpdir, "app.intoto.jsonl")
        envelope, pubkey = PackagerEngine().generate_slsa_provenance(
            subjects=[out_bin_path],
            action_spec=spec,
            action_result=act_res,
            cas=cas,
            sbom=sbom,
            out_path=prov_path,
        )
        self.assertTrue(os.path.exists(prov_path))

        # Full cryptographic verification
        ver = SLSAProvenanceGenerator.verify_bundle(
            envelope,
            public_key=pubkey,
            subjects_data={"app.elf": out_bin_path},
            cas=cas,
            expected_sbom=sbom,
        )
        self.assertTrue(ver["valid"], msg=ver)
        self.assertEqual(ver["statement"]["predicateType"], "https://slsa.dev/provenance/v1")

        # 1. Wrong public key rejected
        _, wrong_pk = ed25519_generate_keypair()
        self.assertEqual(SLSAProvenanceGenerator.verify_bundle(envelope, public_key=wrong_pk)["reason"], "INVALID_ED25519_SIGNATURE")

        # 2. Tampered DSSE payload rejected
        tampered_env = dict(envelope)
        raw_p = bytearray(base64.b64decode(envelope["payload"]))
        raw_p[10] ^= 0x01
        tampered_env["payload"] = base64.b64encode(bytes(raw_p)).decode("ascii")
        self.assertEqual(
            SLSAProvenanceGenerator.verify_bundle(tampered_env, public_key=pubkey)["reason"],
            "INVALID_ED25519_SIGNATURE",
        )

        # 3. Tampered output binary on disk rejected
        with open(out_bin_path, "r+b") as f:
            b0 = f.read(1)
            f.seek(0)
            f.write(bytes([b0[0] ^ 0xFF]))
        self.assertEqual(
            SLSAProvenanceGenerator.verify_bundle(envelope, public_key=pubkey, subjects_data={"app.elf": out_bin_path})["reason"],
            "SUBJECT_DIGEST_MISMATCH_app.elf",
        )

        # 4. Modified SBOM rejected
        bad_sbom = dict(sbom, specVersion="1.6")
        self.assertEqual(
            SLSAProvenanceGenerator.verify_bundle(envelope, public_key=pubkey, expected_sbom=bad_sbom)["reason"],
            "SBOM_DIGEST_MISMATCH",
        )


if __name__ == "__main__":
    unittest.main()
