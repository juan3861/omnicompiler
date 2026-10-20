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
