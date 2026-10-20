"""
RC-07b Surgical Capsule Extractor (Program Slicing via Meta LibCST + NetworkX).
Isolates only the required capabilities and their transitive dependency closure
(functions, classes, module state, and active imports), amputating dead functions
and unused/broken imports from donor repositories.
"""

import ast
from typing import Set, List, Dict, Any
import networkx as nx
import libcst as cst


class _SurgicalCSTTransformer(cst.CSTTransformer):
    """
    Lossless CST Transformer that retains only top-level definitions and imports
    that belong to the transitive dependency slice of the target capabilities.
    """
    def __init__(self, reachable_symbols: Set[str]):
        self.reachable = reachable_symbols
        self.removed_functions: List[str] = []
        self.removed_imports: List[str] = []

    def leave_FunctionDef(
        self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef
    ) -> cst.BaseStatement | cst.RemovalSentinel:
        fn_name = original_node.name.value
        # Never strip dunder methods inside classes; top-level functions must be in reachable
        if fn_name.startswith("__") and fn_name.endswith("__"):
            return updated_node
        if fn_name not in self.reachable:
            self.removed_functions.append(fn_name)
            return cst.RemoveFromParent()
        return updated_node

    def leave_ClassDef(
        self, original_node: cst.ClassDef, updated_node: cst.ClassDef
    ) -> cst.BaseStatement | cst.RemovalSentinel:
        cls_name = original_node.name.value
        if cls_name not in self.reachable:
            self.removed_functions.append(cls_name)
            return cst.RemoveFromParent()
        return updated_node

    def leave_Import(
        self, original_node: cst.Import, updated_node: cst.Import
    ) -> cst.BaseSmallStatement | cst.RemovalSentinel:
        kept_aliases = []
        for alias in updated_node.names:
            if isinstance(alias.name, cst.Attribute):
                # e.g. import importlib.util -> bound root is importlib
                root_node = alias.name
                while isinstance(root_node, cst.Attribute):
                    root_node = root_node.value
                bound_name = alias.asname.name.value if alias.asname else getattr(root_node, "value", "")
            else:
                bound_name = alias.asname.name.value if alias.asname else alias.name.value

            if bound_name in self.reachable:
                kept_aliases.append(alias)
            else:
                self.removed_imports.append(bound_name)

        if not kept_aliases:
            return cst.RemoveFromParent()
        return updated_node.with_changes(names=kept_aliases)

    def leave_ImportFrom(
        self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> cst.BaseSmallStatement | cst.RemovalSentinel:
        # Always preserve __future__ imports
        if isinstance(updated_node.module, cst.Name) and updated_node.module.value == "__future__":
            return updated_node
        if isinstance(updated_node.names, cst.ImportStar):
            return updated_node

        kept_aliases = []
        for alias in updated_node.names:
            bound_name = alias.asname.name.value if alias.asname else alias.name.value
            if bound_name in self.reachable:
                kept_aliases.append(alias)
            else:
                self.removed_imports.append(bound_name)

        if not kept_aliases:
            return cst.RemoveFromParent()
        return updated_node.with_changes(names=kept_aliases)


class CapsuleExtractor:
    """
    Computes the intra-module dependency graph with NetworkX and slices Python modules
    using Meta LibCST so only the live organ (transitive closure of required capabilities)
    is materialized into the product.
    Includes Salsa-style content-addressed memoization and zero-copy fast-path when 100% of
    top-level definitions/imports belong to the live slice.
    """
    _CAPSULE_CACHE: Dict[ Any, Dict[str, Any]] = {}

    def extract_capsule(self, source_code: str, target_operations: Set[str]) -> Dict[str, Any]:
        if not target_operations:
            return {
                "code": source_code,
                "reachable_symbols": [],
                "removed_functions": [],
                "removed_imports": []
            }

        import hashlib
        cache_key = (
            hashlib.sha256(source_code.encode("utf-8")).hexdigest(),
            tuple(sorted(target_operations))
        )
        if cache_key in self._CAPSULE_CACHE:
            return dict(self._CAPSULE_CACHE[cache_key])

        try:
            tree = ast.parse(source_code)
        except Exception:
            return {
                "code": source_code,
                "reachable_symbols": sorted(list(target_operations)),
                "removed_functions": [],
                "removed_imports": []
            }

        if "*" in target_operations:
            all_names = {sub.id for sub in ast.walk(tree) if isinstance(sub, ast.Name)}
            for sub in ast.walk(tree):
                if isinstance(sub, (ast.Import, ast.ImportFrom)):
                    for al in sub.names:
                        all_names.add(al.asname or al.name.split(".")[0])
            res_star = {
                "code": source_code,
                "reachable_symbols": sorted(list(all_names)),
                "removed_functions": [],
                "removed_imports": []
            }
            self._CAPSULE_CACHE[cache_key] = res_star
            return dict(res_star)

        dep_graph = nx.DiGraph()
        seed_symbols: Set[str] = set(target_operations)
        top_defs: Set[str] = set()
        top_imports: Set[str] = set()

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_name = node.name
                if not (fn_name.startswith("__") and fn_name.endswith("__")):
                    top_defs.add(fn_name)
                dep_graph.add_node(fn_name)
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Name):
                        dep_graph.add_edge(fn_name, sub.id)
            elif isinstance(node, ast.ClassDef):
                cls_name = node.name
                top_defs.add(cls_name)
                dep_graph.add_node(cls_name)
                # Check if any method inside this class is a target operation
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        dep_graph.add_edge(cls_name, item.name)
                        dep_graph.add_edge(item.name, cls_name)
                        if item.name in target_operations:
                            seed_symbols.add(cls_name)
                        for sub in ast.walk(item):
                            if isinstance(sub, ast.Name):
                                dep_graph.add_edge(item.name, sub.id)
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Name):
                        dep_graph.add_edge(cls_name, sub.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.ImportFrom) and (node.module == "__future__" or any(a.name == "*" for a in node.names)):
                    continue
                for alias in node.names:
                    bound = alias.asname or alias.name.split(".")[0]
                    top_imports.add(bound)
            elif isinstance(node, ast.Assign):
                targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
                used_names = [sub.id for sub in ast.walk(node.value) if isinstance(sub, ast.Name)]
                for t_name in targets:
                    dep_graph.add_node(t_name)
                    for u_name in used_names:
                        dep_graph.add_edge(t_name, u_name)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                t_name = node.target.id
                dep_graph.add_node(t_name)
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Name) and sub.id != t_name:
                        dep_graph.add_edge(t_name, sub.id)
            else:
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Name):
                        seed_symbols.add(sub.id)

        reachable: Set[str] = set(seed_symbols)
        for seed in list(seed_symbols):
            if seed in dep_graph:
                reachable |= nx.descendants(dep_graph, seed)

        # Compute 64-bit Reachability Bitmap & Topological Shannon Entropy H(G) = -sum p(v) log2 p(v)
        # (from github.com/juan3861/fastmft §4 & bitmap.go)
        import math
        sorted_defs = sorted(list(top_defs))
        reachability_bitmap_u64 = 0
        for idx, d_name in enumerate(sorted_defs[:64]):
            if d_name in reachable:
                reachability_bitmap_u64 |= (1 << idx)

        deg_weights = [dep_graph.degree(v) + 1 for v in dep_graph.nodes()]
        total_w = sum(deg_weights) or 1
        topological_entropy_bits = round(
            -sum((w / total_w) * math.log2(w / total_w) for w in deg_weights if w > 0),
            4
        )

        # Zero-Copy Fast-Path: if 100% of top-level definitions and imports are reachable,
        # no CST removal is needed.
        if top_defs.issubset(reachable) and top_imports.issubset(reachable):
            fast_res = {
                "code": source_code,
                "reachable_symbols": sorted(list(reachable)),
                "removed_functions": [],
                "removed_imports": [],
                "reachability_bitmap_u64": reachability_bitmap_u64,
                "topological_entropy_bits": topological_entropy_bits
            }
            self._CAPSULE_CACHE[cache_key] = fast_res
            return dict(fast_res)

        try:
            cst_module = cst.parse_module(source_code)
            transformer = _SurgicalCSTTransformer(reachable_symbols=reachable)
            sliced_module = cst_module.visit(transformer)
            # Verify that the sliced module parses cleanly
            ast.parse(sliced_module.code)
            out_res = {
                "code": sliced_module.code,
                "reachable_symbols": sorted(list(reachable)),
                "removed_functions": transformer.removed_functions,
                "removed_imports": transformer.removed_imports,
                "reachability_bitmap_u64": reachability_bitmap_u64,
                "topological_entropy_bits": topological_entropy_bits
            }
            self._CAPSULE_CACHE[cache_key] = out_res
            return dict(out_res)
        except Exception:
            fallback_res = {
                "code": source_code,
                "reachable_symbols": sorted(list(reachable)),
                "removed_functions": [],
                "removed_imports": []
            }
            self._CAPSULE_CACHE[cache_key] = fallback_res
            return dict(fallback_res)

    def extract_repository_capsule(
        self,
        comp_root: str,
        entry_ops_by_rel_path: Dict[str, Set[str]],
        prune_unreferenced_files: bool = True
    ) -> Dict[str, Any]:
        """
        Cross-file (inter-module) transitive program slicer across a component directory.
        Traces local imports from entrypoint modules, slices helper modules for only the
        imported symbols, and optionally prunes unreferenced .py files.
        """
        import os

        worklist: List[tuple[str, Set[str]]] = [
            (rel_p.replace("\\", "/"), set(ops))
            for rel_p, ops in entry_ops_by_rel_path.items()
        ]
        targets_by_file: Dict[str, Set[str]] = {}
        sliced_results: Dict[str, Dict[str, Any]] = {}

        while worklist:
            rel_path, req_ops = worklist.pop(0)
            prev_ops = targets_by_file.get(rel_path, set())
            combined_ops = prev_ops | req_ops
            if rel_path in targets_by_file and combined_ops == prev_ops:
                continue
            targets_by_file[rel_path] = combined_ops

            full_path = os.path.join(comp_root, rel_path)
            if not os.path.exists(full_path) or not full_path.endswith(".py"):
                continue

            # Ensure package __init__.py is also traced if we enter a package subdirectory
            cur_dir = os.path.dirname(rel_path)
            if cur_dir:
                pkg_init = f"{cur_dir}/__init__.py"
                if os.path.exists(os.path.join(comp_root, pkg_init)) and pkg_init not in targets_by_file:
                    worklist.append((pkg_init, {"*"}))

            with open(full_path, "r", encoding="utf-8") as f:
                src_code = f.read()

            res = self.extract_capsule(src_code, combined_ops)
            sliced_results[rel_path] = res
            reachable_set = set(res["reachable_symbols"])

            # Inspect AST of sliced code to discover local cross-file imports
            try:
                sliced_tree = ast.parse(res["code"])
            except Exception:
                continue

            for node in ast.walk(sliced_tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    mod_base = node.module.replace(".", "/")
                    mod_rel = mod_base + ".py"
                    candidates = [mod_rel]
                    if cur_dir:
                        candidates.insert(0, f"{cur_dir}/{mod_rel}")
                    matched_file = False
                    for cand in candidates:
                        cand_full = os.path.join(comp_root, cand)
                        if os.path.exists(cand_full):
                            imported_syms = {
                                alias.name for alias in node.names
                                if (alias.asname or alias.name) in reachable_set or alias.name == "*" or "*" in combined_ops
                            }
                            if imported_syms:
                                worklist.append((cand.replace("\\", "/"), imported_syms))
                            matched_file = True
                            break
                    if not matched_file:
                        # Check if node.module is a package directory and alias.name is a submodule .py file
                        dir_candidates = [mod_base]
                        if cur_dir:
                            dir_candidates.insert(0, f"{cur_dir}/{mod_base}")
                        for d_cand in dir_candidates:
                            if os.path.isdir(os.path.join(comp_root, d_cand)):
                                for alias in node.names:
                                    bound = alias.asname or alias.name
                                    if bound not in reachable_set and "*" not in combined_ops:
                                        continue
                                    sub_mod = f"{d_cand}/{alias.name}.py".replace("\\", "/")
                                    if os.path.exists(os.path.join(comp_root, sub_mod)):
                                        worklist.append((sub_mod, {"*"}))
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        bound = alias.asname or alias.name.split(".")[0]
                        if bound not in reachable_set and "*" not in combined_ops:
                            continue
                        mod_rel = alias.name.replace(".", "/") + ".py"
                        candidates = [mod_rel]
                        if cur_dir:
                            candidates.insert(0, f"{cur_dir}/{mod_rel}")
                        for cand in candidates:
                            cand_full = os.path.join(comp_root, cand)
                            if os.path.exists(cand_full):
                                attr_syms = set()
                                for sub in ast.walk(sliced_tree):
                                    if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id == bound:
                                        attr_syms.add(sub.attr)
                                worklist.append((cand.replace("\\", "/"), attr_syms if attr_syms else {"*"}))
                                break

        # Write sliced code to disk for all reachable files
        reports: Dict[str, Any] = {}
        for rel_path, res in sliced_results.items():
            full_path = os.path.join(comp_root, rel_path)
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(res["code"])
            reports[rel_path] = {
                "target_operations": sorted(list(targets_by_file[rel_path])),
                "reachable_symbols": res["reachable_symbols"],
                "removed_functions": res["removed_functions"],
                "removed_imports": res["removed_imports"]
            }

        pruned_files: List[str] = []
        if prune_unreferenced_files and targets_by_file:
            for root, _, files in os.walk(comp_root):
                for fname in sorted(files):
                    if not fname.endswith(".py") or fname == "__init__.py":
                        continue
                    f_full = os.path.join(root, fname)
                    f_rel = os.path.relpath(f_full, comp_root).replace("\\", "/")
                    if f_rel not in targets_by_file:
                        os.remove(f_full)
                        pruned_files.append(f_rel)

        return {
            "sliced_files": reports,
            "pruned_files": pruned_files
        }

