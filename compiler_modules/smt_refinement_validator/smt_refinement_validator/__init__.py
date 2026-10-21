"""
SMT Refinement Validator: SMT Translation Validation & Memory Model Refinement (Alive2 & CompCert style).
Uses Z3 BitVector logics to prove semantic refinement (Tgt ⊑ Src) and strict memory frame bounds.
"""

from smt_refinement_validator.engine import (
    alive_verify_refinement,
    alive_check_memory_bounds,
)

__all__ = [
    "alive_verify_refinement",
    "alive_check_memory_bounds",
]
