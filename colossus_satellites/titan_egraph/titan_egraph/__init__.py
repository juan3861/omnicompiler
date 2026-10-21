"""
Titan E-Graph: Equality Saturation Engine (egg / egglog style)
"""
from titan_egraph.engine import (
    EClass,
    EGraph,
    egraph_saturate_expression,
    egraph_extract_optimal_kernel
)

__all__ = [
    "EClass",
    "EGraph",
    "egraph_saturate_expression",
    "egraph_extract_optimal_kernel"
]
