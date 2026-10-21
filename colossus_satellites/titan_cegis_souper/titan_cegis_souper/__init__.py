"""
Titan CEGIS Souper: Counterexample-Guided Inductive Synthesis (Souper & Rosette style)
"""
from titan_cegis_souper.engine import (
    cegis_synthesize_instruction_sequence,
    cegis_synthesize_abi_adapter
)

__all__ = [
    "cegis_synthesize_instruction_sequence",
    "cegis_synthesize_abi_adapter"
]
