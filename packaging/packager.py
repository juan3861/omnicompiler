"""
RC-10 Packager Engine: Assembles release candidate from accepted product candidate and evidence.
Verifies artifact integrity against certified evidence digests to prevent tampering.
Generates self-contained distribution bundles and operational commands.
"""

import os
import sys
from datetime import datetime, timezone
from contracts.models import ProductCandidate, EvidenceBundle, ReleaseCandidate
from snapshots.engine import hash_file


class PackagerEngine:
    def __init__(self, schema_version: str = "0.1"):
        self.schema_version = schema_version

    def package_release(
        self,
        product: ProductCandidate,
        evidence: EvidenceBundle
    ) -> ReleaseCandidate:
        if evidence.verdict != "ACCEPTED_FOR_SPEC":
            raise ValueError(f"Cannot package product with verdict {evidence.verdict}. Acceptance required.")

        workspace = product.workspace_dir

        # Integrity Check: verify that files in workspace match evidence.artifacts_digests
        for rel_path, expected_hash in evidence.artifacts_digests.items():
            full_path = os.path.join(workspace, rel_path)
            if not os.path.exists(full_path):
                raise ValueError(f"Integrity violation: file missing after certification: {rel_path}")
            current_hash = hash_file(full_path)
            if current_hash != expected_hash:
                raise ValueError(f"Integrity violation: file modified after certification: {rel_path}")

        cmd_wrapper = os.path.join(workspace, "run.cmd")
        py_bin = sys.executable
        with open(cmd_wrapper, "w", encoding="utf-8") as f:
            f.write(f"@echo off\n\"{py_bin}\" \"%~dp0app\\main.py\" %*\n")

        sh_wrapper = os.path.join(workspace, "run.sh")
        with open(sh_wrapper, "w", encoding="utf-8") as f:
            f.write(f"#!/bin/sh\nexec \"{py_bin}\" \"$(dirname \"$0\")/app/main.py\" \"$@\"\n")
        try:
            os.chmod(sh_wrapper, 0o755)
        except Exception:
            pass

        manifest_file = os.path.join(workspace, "manifests", "composition.lock.json")
        evidence_file = os.path.join(workspace, "evidence", "evidence_bundle.json")

        return ReleaseCandidate(
            schema_version=self.schema_version,
            run_id=evidence.run_id,
            package_dir=workspace,
            entrypoint_command=f"\"{py_bin}\" \"{os.path.join(workspace, 'app', 'main.py')}\"",
            health_check_command=f"\"{py_bin}\" \"{os.path.join(workspace, 'run', 'health.py')}\"",
            stop_command=f"\"{py_bin}\" \"{os.path.join(workspace, 'run', 'health.py')}\"",
            manifest_file=manifest_file,
            evidence_file=evidence_file,
            created_at=datetime.now(timezone.utc).isoformat()
        )

    def generate_slsa_provenance(
        self,
        subjects,
        action_spec=None,
        action_result=None,
        cas=None,
        sbom=None,
        signer_seed=None,
        out_path: str = None,
    ):
        """Produces a cryptographically signed in-toto v1 / SLSA Level 3 provenance attestation."""
        import json
        from packaging.slsa_provenance import SLSAProvenanceGenerator

        gen = SLSAProvenanceGenerator(signer_seed=signer_seed)
        envelope = gen.generate_and_sign(
            subjects=subjects,
            action_spec=action_spec,
            action_result=action_result,
            cas=cas,
            sbom=sbom,
        )
        if out_path:
            os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(envelope, sort_keys=True) + "\n")
        return envelope, gen.public_key

    def build_cyclonedx_sbom(
        self,
        artifact_name: str,
        artifact_sha256: str,
        components: list,
        out_path: str = None,
    ) -> dict:
        """Builds a canonical deterministic CycloneDX 1.5 SBOM JSON document."""
        import json

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "serialNumber": f"urn:uuid:00000000-0000-4000-8000-{artifact_sha256[:12]}",
            "metadata": {
                "component": {
                    "type": "application",
                    "name": artifact_name,
                    "hashes": [{"alg": "SHA-256", "content": artifact_sha256}],
                },
                "tools": [{"vendor": "OmniCompiler", "name": "omnicc", "version": "2.0.0"}],
            },
            "components": list(components),
        }
        if out_path:
            os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(sbom, sort_keys=True, indent=2) + "\n")
        return sbom
