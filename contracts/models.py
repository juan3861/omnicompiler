"""
Repository Compiler - Core Data Contracts
Corresponds to RC-01 through RC-12 data schemas defined in BLUEPRINT.md.
Provides immutable, hashable, canonical JSON models for integration lifecycle.
"""

from __future__ import annotations
import json
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone

try:
    import orjson as _orjson
except ImportError:
    _orjson = None


def _json_default(obj: Any) -> Any:
    if isinstance(obj, tuple):
        return list(obj)
    if isinstance(obj, set):
        return sorted(list(obj))
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)


def canonical_json(data: Any) -> str:
    """Produces deterministic, sorted, whitespace-trimmed JSON string (accelerated via Rust SIMD orjson)."""
    if _orjson is not None:
        try:
            return _orjson.dumps(
                data,
                option=_orjson.OPT_SORT_KEYS | _orjson.OPT_NON_STR_KEYS,
                default=_json_default
            ).decode("utf-8")
        except Exception:
            pass
    return json.dumps(data, sort_keys=True, separators=(',', ':'), default=_json_default, ensure_ascii=False)


def sha256_digest(content: str | bytes) -> str:
    if isinstance(content, str):
        content = content.encode('utf-8')
    return hashlib.sha256(content).hexdigest()


def blake3_hash(content: str | bytes) -> str:
    try:
        from crypto.blake3_engine import blake3_digest
        return blake3_digest(content)
    except Exception:
        return sha256_digest(content)


def dual_digest(content: str | bytes) -> Dict[str, str]:
    try:
        from crypto.blake3_engine import dual_content_digest
        return dual_content_digest(content)
    except Exception:
        s = sha256_digest(content)
        return {"sha256": s, "blake3": s, "composite_id": f"s256_{s[:16]}"}


@dataclass(frozen=True)
class IntegrationSpec:
    """RC-01: Immutable integration requirement frozen at intake."""
    schema_version: str
    spec_id: str
    source_refs: Dict[str, Dict[str, str]]  # repo_id -> {path, revision, role}
    objective: str
    target_profile: Dict[str, str]          # language, runtime, platform
    required_capabilities: Tuple[str, ...]
    acceptance_scenarios: Tuple[Dict[str, Any], ...]
    invariants: Tuple[str, ...]
    allowed_side_effects: Tuple[str, ...]
    dependency_policy: str
    release_policy: str
    budget: Dict[str, Any]                  # max_plans, max_repair_attempts, timeout_seconds

    def __init__(
        self,
        schema_version: str,
        spec_id: str,
        source_refs: Dict[str, Dict[str, str]],
        objective: str,
        target_profile: Dict[str, str],
        required_capabilities: Any,
        acceptance_scenarios: Any,
        invariants: Any,
        allowed_side_effects: Any,
        dependency_policy: str,
        release_policy: str,
        budget: Dict[str, Any]
    ):
        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(self, "spec_id", spec_id)
        object.__setattr__(self, "source_refs", dict(source_refs))
        object.__setattr__(self, "objective", objective)
        object.__setattr__(self, "target_profile", dict(target_profile))
        object.__setattr__(self, "required_capabilities", tuple(required_capabilities or ()))
        object.__setattr__(self, "acceptance_scenarios", tuple(acceptance_scenarios or ()))
        object.__setattr__(self, "invariants", tuple(invariants or ()))
        object.__setattr__(self, "allowed_side_effects", tuple(allowed_side_effects or ()))
        object.__setattr__(self, "dependency_policy", dependency_policy)
        object.__setattr__(self, "release_policy", release_policy)
        object.__setattr__(self, "budget", dict(budget or {}))

    def digest(self) -> str:
        d = {
            "schema_version": self.schema_version,
            "spec_id": self.spec_id,
            "source_refs": self.source_refs,
            "objective": self.objective,
            "target_profile": self.target_profile,
            "required_capabilities": list(self.required_capabilities),
            "acceptance_scenarios": list(self.acceptance_scenarios),
            "invariants": list(self.invariants),
            "allowed_side_effects": list(self.allowed_side_effects),
            "dependency_policy": self.dependency_policy,
            "release_policy": self.release_policy,
            "budget": self.budget
        }
        return sha256_digest(canonical_json(d))


@dataclass(frozen=True)
class RepoSnapshot:
    """RC-02: Content-addressed snapshot of a repository revision."""
    schema_version: str
    repo_id: str
    root_path: str
    tree_digest: str
    file_hashes: Dict[str, str]             # relative_path -> sha256
    manifests: List[str]
    created_at: str
    snapshot_root: str = ""                 # Path to the frozen, immutable copy

    def digest(self) -> str:
        d = {
            "schema_version": self.schema_version,
            "repo_id": self.repo_id,
            "root_path": self.root_path,
            "tree_digest": self.tree_digest,
            "file_hashes": self.file_hashes,
            "manifests": sorted(list(self.manifests)),
            "created_at": self.created_at
        }
        return sha256_digest(canonical_json(d))


@dataclass(frozen=True)
class BaselineReport:
    """RC-03: Pre-existing build and test state before integration."""
    schema_version: str
    repo_id: str
    snapshot_digest: str
    build_passed: bool
    tests_passed: bool
    total_tests: int
    failed_tests: List[str]
    environment: Dict[str, str]
    created_at: str

    def digest(self) -> str:
        return sha256_digest(canonical_json(asdict(self)))


@dataclass(frozen=True)
class FactBundle:
    """RC-04: Extracted code facts, symbols, signatures, and confidence."""
    schema_version: str
    repo_id: str
    snapshot_digest: str
    symbols: List[Dict[str, Any]]
    types: List[Dict[str, Any]]
    imports: List[Dict[str, str]]
    entrypoints: List[str]
    confidence_map: Dict[str, str]

    def digest(self) -> str:
        return sha256_digest(canonical_json(asdict(self)))


@dataclass(frozen=True)
class CapabilityContract:
    """RC-05: Formal specification of a capability discovered in code."""
    schema_version: str
    capability_id: str
    source_repo_id: str
    entrypoint: Dict[str, Any]
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    effects: List[str]
    requires: List[str]
    protocol: Dict[str, Any]
    evidence: List[Dict[str, str]]
    unknowns: List[str]

    def digest(self) -> str:
        return sha256_digest(canonical_json(asdict(self)))


@dataclass(frozen=True)
class CompositionPlan:
    """RC-06: Candidate architectural plan connecting capabilities."""
    schema_version: str
    plan_id: str
    topology: str
    components: Dict[str, str]
    bindings: List[Dict[str, Any]]
    adapters_needed: List[str]
    isolation_mode: str
    runtime_config: Dict[str, Any]
    resolved_requirements: List[str]
    risks: List[str]
    rank_score: float
    dataflows: List[Dict[str, Any]] = field(default_factory=list)

    def digest(self) -> str:
        d = {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "topology": self.topology,
            "components": self.components,
            "bindings": self.bindings,
            "adapters_needed": sorted(list(self.adapters_needed)),
            "isolation_mode": self.isolation_mode,
            "runtime_config": self.runtime_config,
            "resolved_requirements": sorted(list(self.resolved_requirements)),
            "risks": sorted(list(self.risks)),
            "rank_score": self.rank_score,
            "dataflows": self.dataflows
        }
        return sha256_digest(canonical_json(d))


@dataclass(frozen=True)
class AdapterCandidate:
    """RC-07: Synthesized glue code or typed adapter."""
    schema_version: str
    adapter_id: str
    level: str
    source_capability_id: str
    target_requirement_id: str
    file_name: str
    code_content: str
    obligations: List[Dict[str, Any]]

    def digest(self) -> str:
        return sha256_digest(canonical_json(asdict(self)))


@dataclass(frozen=True)
class ProductCandidate:
    """RC-08: Materialized product in a fresh isolated workspace."""
    schema_version: str
    product_id: str
    plan_digest: str
    workspace_dir: str
    files_written: List[str]
    entrypoint_script: str
    created_at: str

    def digest(self) -> str:
        return sha256_digest(canonical_json(asdict(self)))


@dataclass(frozen=True)
class EvidenceBundle:
    """RC-09: Uncompromising verification proof bundle."""
    schema_version: str
    run_id: str
    spec_digest: str
    plan_digest: str
    artifacts_digests: Dict[str, str]
    acceptance_results: List[Dict[str, Any]]
    adversarial_results: List[Dict[str, Any]]
    obligations_status: Dict[str, str]
    all_obligations_passed: bool
    verdict: str
    certified_at: str

    def digest(self) -> str:
        return sha256_digest(canonical_json(asdict(self)))


@dataclass(frozen=True)
class ReleaseCandidate:
    """RC-10: Packaged executable delivery."""
    schema_version: str
    run_id: str
    package_dir: str
    entrypoint_command: str
    health_check_command: str
    stop_command: str
    manifest_file: str
    evidence_file: str
    created_at: str

    def digest(self) -> str:
        return sha256_digest(canonical_json(asdict(self)))
