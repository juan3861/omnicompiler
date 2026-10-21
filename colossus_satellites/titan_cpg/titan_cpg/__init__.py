"""
Titan CPG: Code Property Graph & Interprocedural Taint Flow Engine (Joern & Glean style)
"""
from titan_cpg.engine import (
    cpg_build_inter_repo_graph,
    cpg_trace_taint_path
)

__all__ = [
    "cpg_build_inter_repo_graph",
    "cpg_trace_taint_path"
]
