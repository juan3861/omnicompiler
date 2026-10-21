"""
OmniCompiler Inter-Repository Dead-Code Slicer (ThinLTO-style GC).
Performs interprocedural reachability and backward program slicing across
multiple software repositories. Prunes uncalled dead functions and unreferenced
global symbols before register allocation and machine code emission.
"""

from typing import List, Set, Dict, Any, Optional
from orchestrator.repo_manifest_ingestor import RepoManifest, SymbolSignature


class InterRepoSlicer:
    """
    Computes transitive call closures across repository boundaries.
    Prunes unreferenced functions to eliminate binary bloat.
    """

    def __init__(self):
        pass

    def slice_repositories(
        self,
        manifests: List[RepoManifest],
        root_symbols: List[str],
        call_graph: Optional[Dict[str, List[str]]] = None
    ) -> Dict[str, Any]:
        """
        Calculates reachable symbols starting from root entry points and prunes
        unreferenced functions from manifests.

        Parameters:
            manifests: List of RepoManifest instances
            root_symbols: List of entrypoint symbol names (e.g. ['omni_main'])
            call_graph: Optional explicit mapping of {caller_symbol: [callee_symbols]}
        """
        all_exports: Dict[str, SymbolSignature] = {}
        for m in manifests:
            for exp in m.exports:
                all_exports[exp.name] = exp

        # If no explicit call graph is provided, build from manifests and imports
        graph: Dict[str, Set[str]] = {}
        for sym in all_exports:
            graph[sym] = set()

        if call_graph:
            for caller, callees in call_graph.items():
                if caller not in graph:
                    graph[caller] = set()
                for c in callees:
                    graph[caller].add(c)

        # Transitive Reachability via Breadth-First Search
        reachable: Set[str] = set()
        queue: List[str] = [r for r in root_symbols if r in all_exports or r in graph]

        # If no root is in the manifest exports (e.g. root is synthesized like 'omni_main'),
        # all symbols called by the root or explicitly bound are preserved
        for r in root_symbols:
            reachable.add(r)
            if r in graph:
                for target in graph[r]:
                    if target not in reachable:
                        reachable.add(target)
                        queue.append(target)

        while queue:
            curr = queue.pop(0)
            if curr in graph:
                for neighbor in graph[curr]:
                    if neighbor not in reachable:
                        reachable.add(neighbor)
                        queue.append(neighbor)

        # Identify dead symbols
        pruned_symbols: List[str] = []
        for m in manifests:
            retained_exports: List[SymbolSignature] = []
            for exp in m.exports:
                # If symbol is reachable OR is the sole root of the repo, retain it
                if exp.name in reachable:
                    retained_exports.append(exp)
                else:
                    pruned_symbols.append(f"{m.repo_name}::{exp.name}")

            # If all symbols in a repo would be pruned, keep at least the explicitly exported ones
            if not retained_exports and m.exports:
                retained_exports = [m.exports[0]]
                if f"{m.repo_name}::{m.exports[0].name}" in pruned_symbols:
                    pruned_symbols.remove(f"{m.repo_name}::{m.exports[0].name}")

            m.exports = retained_exports

        total_before = len(all_exports)
        total_after = sum(len(m.exports) for m in manifests)

        return {
            "total_before": total_before,
            "total_after": total_after,
            "reachable_symbols": list(reachable),
            "pruned_symbols": pruned_symbols,
            "pruned_count": len(pruned_symbols),
            "reduction_percentage": ((total_before - total_after) / total_before * 100.0) if total_before > 0 else 0.0
        }
