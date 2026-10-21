"""
Multi-Repository Manifest Ingestor & Inter-Project Topology Engine
Ingests arbitrary code repositories (Python, C/C++, Rust), extracts exported symbols,
imported dependencies, and computes the inter-repository binding topology DAG.
Integrates with SalsaQueryEngine for incremental reactive caching.
"""

import os
import re
import ast
from typing import Dict, List, Set, Tuple, Any, Optional
from crypto.blake3_engine import blake3_digest
from orchestrator.salsa_query_engine import SalsaQueryEngine


class SymbolSignature:
    """Represents a callable function or symbol boundary in a repository."""
    __slots__ = ("name", "params", "return_type", "doc", "visibility", "language", "source_file")

    def __init__(
        self,
        name: str,
        params: List[str],
        return_type: str = "i64",
        doc: str = "",
        visibility: str = "public",
        language: str = "python",
        source_file: str = ""
    ):
        self.name = name
        self.params = params
        self.return_type = return_type
        self.doc = doc
        self.visibility = visibility
        self.language = language
        self.source_file = source_file

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "params": self.params,
            "return_type": self.return_type,
            "visibility": self.visibility,
            "language": self.language,
            "source_file": self.source_file
        }

    def __repr__(self) -> str:
        return f"SymbolSignature({self.language}::{self.name}({', '.join(self.params)}) -> {self.return_type})"


class SymbolRequirement:
    """Represents an unresolved external symbol required by a repository."""
    __slots__ = ("name", "calling_convention", "expected_params", "source_file")

    def __init__(
        self,
        name: str,
        calling_convention: str = "cdecl",
        expected_params: Optional[List[str]] = None,
        source_file: str = ""
    ):
        self.name = name
        self.calling_convention = calling_convention
        self.expected_params = expected_params or []
        self.source_file = source_file

    def __repr__(self) -> str:
        return f"SymbolRequirement({self.name}, params={self.expected_params})"


class RepoManifest:
    """Formal description of a repository's public interface and dependency footprint."""

    def __init__(
        self,
        repo_name: str,
        repo_path: str,
        repo_type: str,
        exports: List[SymbolSignature],
        imports: List[SymbolRequirement],
        manifest_digest: str = ""
    ):
        self.repo_name = repo_name
        self.repo_path = repo_path
        self.repo_type = repo_type
        self.exports = exports
        self.imports = imports
        self.manifest_digest = manifest_digest

    def get_export(self, name: str) -> Optional[SymbolSignature]:
        for exp in self.exports:
            if exp.name == name:
                return exp
        return None

    def __repr__(self) -> str:
        return f"RepoManifest({self.repo_name}:{self.repo_type}, exports={len(self.exports)}, imports={len(self.imports)})"


class RepoManifestIngestor:
    """
    Parses repository directory trees to extract public APIs, types, and dependencies.
    Supports Python, C/C++ headers, and Rust project manifests.
    """

    def __init__(self, salsa_engine: Optional[SalsaQueryEngine] = None):
        self.salsa = salsa_engine or SalsaQueryEngine()

    def ingest_repository(self, repo_path: str, repo_name: Optional[str] = None) -> RepoManifest:
        repo_path = os.path.abspath(repo_path)
        name = repo_name or os.path.basename(repo_path)

        repo_type = self._detect_repo_type(repo_path)
        exports: List[SymbolSignature] = []
        imports: List[SymbolRequirement] = []
        all_bytes = bytearray()

        # Walk repo tree
        for root, _, files in os.walk(repo_path):
            if any(p in root for p in (".git", "__pycache__", ".venv", "node_modules", "target", "build")):
                continue

            for f in files:
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, repo_path)

                if f.endswith(".py"):
                    exp, imp, b = self._parse_python_file(full_path, rel_path)
                    exports.extend(exp)
                    imports.extend(imp)
                    all_bytes.extend(b)

                elif f.endswith((".h", ".hpp", ".c", ".cpp")):
                    exp, imp, b = self._parse_c_header_file(full_path, rel_path)
                    exports.extend(exp)
                    imports.extend(imp)
                    all_bytes.extend(b)

                elif f.endswith(".rs"):
                    exp, imp, b = self._parse_rust_file(full_path, rel_path)
                    exports.extend(exp)
                    imports.extend(imp)
                    all_bytes.extend(b)

        digest = blake3_digest(bytes(all_bytes)) if all_bytes else blake3_digest(name.encode("utf-8"))
        manifest = RepoManifest(
            repo_name=name,
            repo_path=repo_path,
            repo_type=repo_type,
            exports=exports,
            imports=imports,
            manifest_digest=digest
        )

        # Cache in Salsa Query DB
        self.salsa.set_input("repo_manifest", name, manifest)
        return manifest

    def _detect_repo_type(self, path: str) -> str:
        has_py = os.path.exists(os.path.join(path, "pyproject.toml")) or os.path.exists(os.path.join(path, "setup.py"))
        has_c = os.path.exists(os.path.join(path, "CMakeLists.txt")) or os.path.exists(os.path.join(path, "Makefile"))
        has_rs = os.path.exists(os.path.join(path, "Cargo.toml"))

        if has_py and not (has_c or has_rs): return "python"
        if has_c and not (has_py or has_rs): return "c_cpp"
        if has_rs and not (has_py or has_c): return "rust"
        return "polyglot"

    def _parse_python_file(self, path: str, rel_path: str) -> Tuple[List[SymbolSignature], List[SymbolRequirement], bytes]:
        exports: List[SymbolSignature] = []
        imports: List[SymbolRequirement] = []
        try:
            with open(path, "rb") as f:
                content = f.read()
            tree = ast.parse(content)
            for node in tree.body:
                if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
                    params = [arg.arg for arg in node.args.args]
                    doc = ast.get_docstring(node) or ""
                    exports.append(SymbolSignature(
                        name=node.name,
                        params=params,
                        return_type="any",
                        doc=doc,
                        visibility="public",
                        language="python",
                        source_file=rel_path
                    ))
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports.append(SymbolRequirement(name=alias.name, source_file=rel_path))
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        for alias in node.names:
                            imports.append(SymbolRequirement(name=f"{node.module}.{alias.name}", source_file=rel_path))
            return exports, imports, content
        except Exception:
            return exports, imports, b""

    def _parse_c_header_file(self, path: str, rel_path: str) -> Tuple[List[SymbolSignature], List[SymbolRequirement], bytes]:
        exports: List[SymbolSignature] = []
        imports: List[SymbolRequirement] = []
        try:
            with open(path, "rb") as f:
                content = f.read()
            text = content.decode("utf-8", errors="ignore")

            # Regex for C prototypes: e.g. int64_t func_name(int64_t a, int64_t b);
            # or void func_name(int x);
            proto_re = re.compile(r'^\s*(?:extern\s+)?([a-zA-Z0-9_]+(?:\s*\*+)?)\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*;', re.MULTILINE)
            for match in proto_re.finditer(text):
                ret_type, fn_name, params_str = match.groups()
                params = []
                if params_str.strip() and params_str.strip() != "void":
                    for p in params_str.split(","):
                        tokens = p.strip().split()
                        if tokens:
                            param_name = tokens[-1].lstrip("*")
                            params.append(param_name)

                exports.append(SymbolSignature(
                    name=fn_name,
                    params=params,
                    return_type=ret_type.strip(),
                    visibility="public",
                    language="c",
                    source_file=rel_path
                ))
            return exports, imports, content
        except Exception:
            return exports, imports, b""

    def _parse_rust_file(self, path: str, rel_path: str) -> Tuple[List[SymbolSignature], List[SymbolRequirement], bytes]:
        exports: List[SymbolSignature] = []
        imports: List[SymbolRequirement] = []
        try:
            with open(path, "rb") as f:
                content = f.read()
            text = content.decode("utf-8", errors="ignore")

            # Match: pub fn func_name(param1: type, ...) -> ret_type
            fn_re = re.compile(r'pub\s+fn\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)(?:\s*->\s*([a-zA-Z0-9_<>]+))?', re.MULTILINE)
            for match in fn_re.finditer(text):
                fn_name, params_str, ret_type = match.groups()
                params = []
                if params_str.strip():
                    for p in params_str.split(","):
                        if ":" in p:
                            p_name = p.split(":")[0].strip()
                            params.append(p_name)

                exports.append(SymbolSignature(
                    name=fn_name,
                    params=params,
                    return_type=ret_type.strip() if ret_type else "()",
                    visibility="public",
                    language="rust",
                    source_file=rel_path
                ))
            return exports, imports, content
        except Exception:
            return exports, imports, b""


class RepoTopologyResolver:
    """
    Computes inter-repository bindings and builds dependency resolution graphs across projects.
    """

    def resolve_topology(self, manifests: List[RepoManifest]) -> Dict[str, Any]:
        """
        Determines caller-to-callee connections, unfulfilled dependencies,
        and dependency topological execution order.
        """
        export_catalog: Dict[str, Tuple[str, SymbolSignature]] = {}
        for m in manifests:
            for exp in m.exports:
                export_catalog[exp.name] = (m.repo_name, exp)

        resolved_bindings: List[Dict[str, Any]] = []
        unresolved_imports: List[Dict[str, Any]] = []
        dag_edges: List[Tuple[str, str]] = []  # (caller_repo, callee_repo)

        for m in manifests:
            for imp in m.imports:
                short_name = imp.name.split(".")[-1]
                if imp.name in export_catalog:
                    callee_repo, sig = export_catalog[imp.name]
                    resolved_bindings.append({
                        "consumer_repo": m.repo_name,
                        "provider_repo": callee_repo,
                        "symbol": imp.name,
                        "signature": sig.to_dict()
                    })
                    dag_edges.append((m.repo_name, callee_repo))
                elif short_name in export_catalog:
                    callee_repo, sig = export_catalog[short_name]
                    resolved_bindings.append({
                        "consumer_repo": m.repo_name,
                        "provider_repo": callee_repo,
                        "symbol": short_name,
                        "signature": sig.to_dict()
                    })
                    dag_edges.append((m.repo_name, callee_repo))
                else:
                    unresolved_imports.append({
                        "repo": m.repo_name,
                        "symbol": imp.name
                    })

        # Calculate topological compile order
        compile_order = self._compute_topo_order([m.repo_name for m in manifests], dag_edges)

        return {
            "total_manifests": len(manifests),
            "total_exports": len(export_catalog),
            "resolved_bindings": resolved_bindings,
            "unresolved_imports": unresolved_imports,
            "compile_order": compile_order,
            "dag_edges": dag_edges
        }

    def _compute_topo_order(self, nodes: List[str], edges: List[Tuple[str, str]]) -> List[str]:
        """Kahn's algorithm for topological ordering (callees compiled before callers)."""
        adj: Dict[str, Set[str]] = {n: set() for n in nodes}
        in_degree: Dict[str, int] = {n: 0 for n in nodes}

        for caller, callee in edges:
            if caller in adj and callee in adj:
                if callee not in adj[caller]:
                    adj[caller].add(callee)
                    in_degree[callee] += 1

        # Queue nodes with in_degree 0
        queue = [n for n in nodes if in_degree[n] == 0]
        order = []
        while queue:
            curr = queue.pop(0)
            order.append(curr)
            for neighbor in adj[curr]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        # Remaining nodes in case of cycles or disconnected components
        for n in nodes:
            if n not in order:
                order.append(n)
        return order
