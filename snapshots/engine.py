"""
RC-02 Snapshot Engine: Content-addressed acquisition and deterministic Merkle tree hashing.
Ensures source repositories are strictly read-only and immutably pinned into a frozen store.
"""

import os
import shutil
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Set, Optional
from contracts.models import RepoSnapshot, sha256_digest


EXCLUDED_DIRS: Set[str] = {
    ".git", ".svn", "__pycache__", ".pytest_cache", "node_modules",
    ".idea", ".vscode", ".tox", ".mypy_cache"
}

EXCLUDED_FILES: Set[str] = {
    ".DS_Store", "Thumbs.db"
}


def hash_file(file_path: str) -> str:
    with open(file_path, "rb") as f:
        if hasattr(hashlib, "file_digest"):
            return hashlib.file_digest(f, "sha256").hexdigest()
        hasher = hashlib.sha256()
        while chunk := f.read(65536):
            hasher.update(chunk)
        return hasher.hexdigest()


class SnapshotEngine:
    def __init__(self, schema_version: str = "0.1", snapshots_storage_dir: Optional[str] = None):
        self.schema_version = schema_version
        self.snapshots_storage_dir = snapshots_storage_dir

    def take_snapshot(self, repo_id: str, root_path: str, storage_dir: Optional[str] = None) -> RepoSnapshot:
        if not os.path.exists(root_path):
            raise FileNotFoundError(f"Repository path does not exist: {root_path}")
        if not os.path.isdir(root_path):
            raise ValueError(f"Repository path must be a directory, not a file: {root_path}")

        file_hashes: Dict[str, str] = {}
        manifests: List[str] = []

        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]

            for fname in sorted(filenames):
                if fname in EXCLUDED_FILES or fname.endswith(('.pyc', '.pyo')):
                    continue

                full_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(full_path, root_path).replace("\\", "/")

                fhash = hash_file(full_path)
                file_hashes[rel_path] = fhash

                if fname in ("package.json", "pyproject.toml", "requirements.txt", "setup.py", "Cargo.toml", "pom.xml"):
                    manifests.append(rel_path)

        # Merkle tree digest computed from sorted (rel_path, fhash) pairs
        tree_input = "".join(f"{p}:{h}\n" for p, h in sorted(file_hashes.items()))
        tree_digest = sha256_digest(tree_input)

        now_iso = datetime.now(timezone.utc).isoformat()

        # Create frozen content-addressed snapshot copy if storage directory is set
        store = storage_dir or self.snapshots_storage_dir
        if store:
            frozen_dir = os.path.join(store, repo_id, tree_digest)
            os.makedirs(frozen_dir, exist_ok=True)
            for rel_path in file_hashes.keys():
                src_file = os.path.join(root_path, rel_path)
                dst_file = os.path.join(frozen_dir, rel_path)
                if not os.path.exists(dst_file):
                    os.makedirs(os.path.dirname(dst_file), exist_ok=True)
                    shutil.copyfile(src_file, dst_file)
            effective_root = frozen_dir
        else:
            effective_root = os.path.abspath(root_path)

        return RepoSnapshot(
            schema_version=self.schema_version,
            repo_id=repo_id,
            root_path=os.path.abspath(root_path),
            snapshot_root=effective_root,
            tree_digest=tree_digest,
            file_hashes=file_hashes,
            manifests=sorted(manifests),
            created_at=now_iso
        )
