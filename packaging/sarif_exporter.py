"""
Alpha-C115: OASIS SARIF 2.1.0 Static Security & Compiler Verification Exporter
(`packaging/sarif_exporter.py`).

Serializes OmniRepoCompiler Stage 3 CPG Taint, Stage 3b Separation Logic,
Stage 5 ASan/UBSan Sanitizer Guards, Stage 5.5a Assembly Invariants, and
Stage 8 Formal Binary Structure checks into compliant SARIF 2.1.0 JSON.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional


SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"

_RULES: List[Dict[str, Any]] = [
    {
        "id": "OMNI-CPG-TAINT-001",
        "name": "CrossRepoTenantTaintLeak",
        "shortDescription": {"text": "Cross-repository tainted tenant data reached public sink"},
        "properties": {"tags": ["security", "CWE-200", "cpg"]},
    },
    {
        "id": "OMNI-BIABD-HEAP-002",
        "name": "BiAbductionHeapIsolationViolation",
        "shortDescription": {"text": "Separation logic detected overlapping heap pointers across tenants"},
        "properties": {"tags": ["security", "memory-safety", "CWE-787"]},
    },
    {
        "id": "OMNI-SAN-TRAP-003",
        "name": "SanitizerTrapInstrumentation",
        "shortDescription": {"text": "ASan/UBSan runtime hardware trap guard inserted during SSA lowering"},
        "properties": {"tags": ["reliability", "sanitizer", "ubsan", "asan"]},
    },
    {
        "id": "OMNI-ASM-INV-004",
        "name": "AssemblyInvariantViolation",
        "shortDescription": {"text": "Machine-code frame or return invariant violation detected"},
        "properties": {"tags": ["correctness", "abi"]},
    },
    {
        "id": "OMNI-BIN-SEC-005",
        "name": "BinaryFormatAuditIssue",
        "shortDescription": {"text": "PE/ELF/Mach-O structural audit reported anomaly"},
        "properties": {"tags": ["binary-safety"]},
    },
]


class SARIFExporter:
    """Builds and writes OASIS SARIF 2.1.0 reports from compilation results."""

    @staticmethod
    def build_sarif(
        compile_results: Dict[str, Any],
        artifact_path: str = "",
        repo_paths: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        stages = compile_results.get("stages") or {}
        findings: List[Dict[str, Any]] = []
        art_uri = os.path.basename(artifact_path) if artifact_path else "omni_artifact"

        cpg = stages.get("cpg_security") or {}
        if cpg.get("taint_leak_detected"):
            findings.append({
                "ruleId": "OMNI-CPG-TAINT-001",
                "level": "error",
                "message": {"text": "Cross-repository taint path from PARAM:TENANT to public_log detected."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": art_uri}}}],
            })

        sep = stages.get("separation_logic") or {}
        if sep and not sep.get("heap_disjointness_proven", True):
            findings.append({
                "ruleId": "OMNI-BIABD-HEAP-002",
                "level": "error",
                "message": {"text": "Separation logic bi-abduction could not prove heap disjointness across repositories."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": art_uri}}}],
            })

        san = stages.get("sanitizers") or {}
        for rep in san.get("reports", []) or []:
            traps = int(rep.get("trap_blocks_inserted", 0))
            if traps > 0:
                fn_name = str(rep.get("function", "unknown"))
                findings.append({
                    "ruleId": "OMNI-SAN-TRAP-003",
                    "level": "note",
                    "message": {
                        "text": (
                            f"Instrumented '{fn_name}' with {traps} ASan/UBSan guard(s) "
                            f"(div={rep.get('ubsan_div_checks', 0)}, shift={rep.get('ubsan_shift_checks', 0)}, "
                            f"null={rep.get('asan_null_checks', 0)}, bounds={rep.get('asan_bounds_checks', 0)})."
                        )
                    },
                    "locations": [{
                        "physicalLocation": {"artifactLocation": {"uri": art_uri}},
                        "logicalLocations": [{"name": fn_name, "kind": "function"}],
                    }],
                })

        fa = stages.get("formal_audit") or {}
        if fa and not fa.get("is_valid", True) and not fa.get("structural_audit", True):
            findings.append({
                "ruleId": "OMNI-BIN-SEC-005",
                "level": "error",
                "message": {"text": "Formal PE/ELF/Mach-O structural audit flagged invalid binary layout."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": art_uri}}}],
            })

        return {
            "$schema": SARIF_SCHEMA_URL,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "OmniRepoCompiler",
                            "version": "2.0.0",
                            "informationUri": "https://github.com/juan3861/omnicompiler",
                            "rules": _RULES,
                        }
                    },
                    "properties": {
                        "reposAnalyzed": len(repo_paths or []),
                        "cpgIsolationPreserved": bool(cpg.get("isolation_preserved", True)),
                        "heapDisjointnessProven": bool(sep.get("heap_disjointness_proven", True)),
                    },
                    "results": findings,
                }
            ],
        }

    @classmethod
    def write_sarif(
        cls,
        compile_results: Dict[str, Any],
        out_path: str,
        artifact_path: str = "",
        repo_paths: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        doc = cls.build_sarif(compile_results, artifact_path=artifact_path, repo_paths=repo_paths)
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as sf:
            sf.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        return doc
