"""
Code Property Graph Taint Analyzer: Interprocedural CPG & Taint Analysis Engine (Joern & Glean style).
Unifies AST, Control Flow (CFG), and Program Dependence (PDG) across inter-project boundaries.
"""

from cpg_taint_analyzer.engine import (
    CodePropertyGraph,
    cpg_build_inter_repo_graph,
    cpg_trace_taint_path,
)

__all__ = [
    "CodePropertyGraph",
    "cpg_build_inter_repo_graph",
    "cpg_trace_taint_path",
]
