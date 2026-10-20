"""
RC-04 Python Language Frontend: AST + LibCST + ast-grep-py + NetworkX Call Graph & Slicing.
Emits deterministic FactBundle with provenance, confidence classification,
lossless CST validation, PageRank centrality, and transitive program slices.
Preserves class scopes, positional/keyword-only arguments, and detects snapshot drift.
"""

import ast
import os
import hashlib
from typing import Dict, List, Any, Set
import networkx as nx
import libcst as cst
try:
    from ast_grep_py import SgRoot
except ImportError:
    SgRoot = None
from contracts.models import FactBundle, RepoSnapshot


class PythonFrontend:
    _CST_LOSSLESS_CACHE: Dict[str, bool] = {}
    _SG_CALLS_CACHE: Dict[str, List[str]] = {}

    def __init__(self, schema_version: str = "0.1"):
        self.schema_version = schema_version

    def analyze_repository(self, snapshot: RepoSnapshot) -> FactBundle:
        symbols: List[Dict[str, Any]] = []
        types: List[Dict[str, Any]] = []
        imports: List[Dict[str, str]] = []
        entrypoints: List[str] = []
        confidence_map: Dict[str, str] = {}
        call_graph = nx.DiGraph()

        # Prefer immutable snapshot_root if available
        base_dir = snapshot.snapshot_root or snapshot.root_path

        for rel_path in sorted(snapshot.file_hashes.keys()):
            if not rel_path.endswith(".py"):
                continue

            full_path = os.path.join(base_dir, rel_path)
            if not os.path.exists(full_path):
                # Fallback to root_path if not in snapshot_root
                full_path = os.path.join(snapshot.root_path, rel_path)

            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Verify hash against snapshot to prevent drift
                current_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
                expected_hash = snapshot.file_hashes.get(rel_path)
                if expected_hash and current_hash != expected_hash:
                    # Drift detected! Flag as unknown/drifted
                    confidence_map[f"{rel_path}:drift_detected"] = "unknown"

                tree = ast.parse(content, filename=rel_path)
            except Exception:
                confidence_map[f"{rel_path}:parse_error"] = "unknown"
                continue

            # Lossless Concrete Syntax Tree check via Meta LibCST (content-addressed memoized)
            if current_hash in self._CST_LOSSLESS_CACHE:
                cst_lossless = self._CST_LOSSLESS_CACHE[current_hash]
            else:
                try:
                    cst_mod = cst.parse_module(content)
                    cst_lossless = (cst_mod.code == content)
                except Exception:
                    cst_lossless = False
                self._CST_LOSSLESS_CACHE[current_hash] = cst_lossless

            # Structural pattern scan via Rust ast-grep-py (Tree-sitter, content-addressed memoized)
            if current_hash in self._SG_CALLS_CACHE:
                structural_calls = self._SG_CALLS_CACHE[current_hash]
            else:
                structural_calls = []
                if SgRoot is not None:
                    try:
                        sg_root = SgRoot(content, "python")
                        sg_node = sg_root.root()
                        for match in sg_node.find_all(pattern="$FUNC($$$ARGS)"):
                            fn_node = match.get_match("FUNC")
                            if fn_node:
                                structural_calls.append(fn_node.text())
                    except Exception:
                        pass
                self._SG_CALLS_CACHE[current_hash] = structural_calls

            self._extract_from_ast(
                tree=tree,
                rel_path=rel_path,
                symbols=symbols,
                types=types,
                imports=imports,
                entrypoints=entrypoints,
                confidence_map=confidence_map,
                call_graph=call_graph,
                cst_lossless=cst_lossless,
                structural_calls=structural_calls
            )

        # Compute PageRank centrality and Program Slices (transitive closure) via NetworkX
        pagerank_scores: Dict[str, float] = {}
        if len(call_graph.nodes) > 0:
            try:
                pagerank_scores = nx.pagerank(call_graph, alpha=0.85)
            except Exception:
                pagerank_scores = {n: 1.0 / len(call_graph.nodes) for n in call_graph.nodes}

        for sym in symbols:
            qname = sym["qualified_name"]
            short_name = sym["name"]
            sym["pagerank"] = round(pagerank_scores.get(short_name, 0.0), 6)
            if short_name in call_graph:
                try:
                    desc = sorted(list(nx.descendants(call_graph, short_name)))
                    sym["transitive_slice"] = desc
                except Exception:
                    sym["transitive_slice"] = []
            else:
                sym["transitive_slice"] = []

        return FactBundle(
            schema_version=self.schema_version,
            repo_id=snapshot.repo_id,
            snapshot_digest=snapshot.tree_digest,
            symbols=symbols,
            types=types,
            imports=imports,
            entrypoints=sorted(list(set(entrypoints))),
            confidence_map=confidence_map
        )

    def _extract_from_ast(
        self,
        tree: ast.AST,
        rel_path: str,
        symbols: List[Dict[str, Any]],
        types: List[Dict[str, Any]],
        imports: List[Dict[str, str]],
        entrypoints: List[str],
        confidence_map: Dict[str, str],
        call_graph: nx.DiGraph,
        cst_lossless: bool,
        structural_calls: List[str]
    ) -> None:
        module_name = rel_path.replace(".py", "").replace("/", ".").replace("\\", ".")

        # Traverse with parent tracking to preserve class scopes
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                setattr(child, "parent", node)

            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append({"module": alias.name, "as": alias.asname or alias.name, "source_file": rel_path})
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    imports.append({"module": f"{mod}.{alias.name}", "as": alias.asname or alias.name, "source_file": rel_path})

            elif isinstance(node, ast.ClassDef):
                sym_id = f"{module_name}.{node.name}"
                types.append({
                    "name": node.name,
                    "qualified_name": sym_id,
                    "file_path": rel_path,
                    "bases": [ast.unparse(b) for b in node.bases],
                    "docstring": ast.get_docstring(node) or ""
                })
                confidence_map[sym_id] = "statically_observed"

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parent_class = getattr(node, "parent", None)
                is_method = isinstance(parent_class, ast.ClassDef)

                if is_method:
                    sym_id = f"{module_name}.{parent_class.name}.{node.name}"
                    kind = "method"
                else:
                    sym_id = f"{module_name}.{node.name}"
                    kind = "function"

                call_graph.add_node(node.name, qualified_name=sym_id, file_path=rel_path)
                local_calls: Set[str] = set()
                for subnode in ast.walk(node):
                    if isinstance(subnode, ast.Call):
                        if isinstance(subnode.func, ast.Name):
                            callee = subnode.func.id
                            local_calls.add(callee)
                            call_graph.add_edge(node.name, callee)
                        elif isinstance(subnode.func, ast.Attribute):
                            callee = subnode.func.attr
                            local_calls.add(callee)
                            call_graph.add_edge(node.name, callee)

                params = []
                # Handle positional-only args
                for arg in getattr(node.args, "posonlyargs", []):
                    type_ann = ast.unparse(arg.annotation) if arg.annotation else "Any"
                    params.append({"name": arg.arg, "type": type_ann, "kind": "posonly", "required": True})

                # Handle normal args
                num_defaults = len(node.args.defaults)
                num_regular = len(node.args.args)
                default_offset = num_regular - num_defaults

                for idx, arg in enumerate(node.args.args):
                    if is_method and idx == 0 and arg.arg in ("self", "cls"):
                        continue
                    type_ann = ast.unparse(arg.annotation) if arg.annotation else "Any"
                    has_default = idx >= default_offset
                    params.append({"name": arg.arg, "type": type_ann, "kind": "regular", "required": not has_default})

                # Handle keyword-only args
                kw_defaults = node.args.kw_defaults
                for idx, arg in enumerate(node.args.kwonlyargs):
                    type_ann = ast.unparse(arg.annotation) if arg.annotation else "Any"
                    has_default = idx < len(kw_defaults) and kw_defaults[idx] is not None
                    params.append({"name": arg.arg, "type": type_ann, "kind": "kwonly", "required": not has_default})

                ret_type = ast.unparse(node.returns) if node.returns else "Any"
                doc = ast.get_docstring(node) or ""

                if node.name in ("main", "run", "serve", "start", "execute") or "entrypoint" in doc.lower():
                    entrypoints.append(sym_id)

                symbol_entry = {
                    "name": node.name,
                    "qualified_name": sym_id,
                    "kind": kind,
                    "file_path": rel_path,
                    "line_start": node.lineno,
                    "line_end": getattr(node, "end_lineno", node.lineno),
                    "parameters": params,
                    "return_type": ret_type,
                    "is_async": isinstance(node, ast.AsyncFunctionDef),
                    "docstring": doc,
                    "class_name": parent_class.name if is_method else None,
                    "cst_lossless": cst_lossless,
                    "local_calls": sorted(list(local_calls)),
                    "ast_grep_calls_count": len(structural_calls)
                }
                symbols.append(symbol_entry)

                confidence = "declared" if (node.returns and all(p['type'] != 'Any' for p in params)) else "statically_observed"
                confidence_map[sym_id] = confidence

