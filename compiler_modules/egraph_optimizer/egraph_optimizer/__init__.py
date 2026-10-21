"""
E-Graph Optimizer: Equality Saturation & Relational E-Matching Engine (egg / egglog style).
Provides non-destructive algebraic rewriting through equivalence classes.
"""

from egraph_optimizer.engine import (
    EGraph,
    ENode,
    EClass,
    egraph_saturate_expression,
    egraph_extract_optimal_kernel,
)

__all__ = [
    "EGraph",
    "ENode",
    "EClass",
    "egraph_saturate_expression",
    "egraph_extract_optimal_kernel",
]
