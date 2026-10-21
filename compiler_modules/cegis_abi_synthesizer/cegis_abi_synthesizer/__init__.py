"""
CEGIS ABI Synthesizer: Counterexample-Guided Inductive Synthesis & ABI Adaptation (Souper & Rosette style).
Synthesizes verified instruction sequences and cross-language ABI marshalling adapters.
"""

from cegis_abi_synthesizer.engine import (
    cegis_synthesize_instruction_sequence,
    cegis_synthesize_abi_adapter,
)

__all__ = [
    "cegis_synthesize_instruction_sequence",
    "cegis_synthesize_abi_adapter",
]
