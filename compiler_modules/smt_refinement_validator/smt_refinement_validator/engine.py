"""
SMT Refinement Validator: SMT Translation Validation & Memory Model Refinement (Alive2 & CompCert style)
Uses Z3 BitVector logics to prove semantic refinement (Tgt <= Src) and strict memory frame bounds.
Strictly Fail-Closed: delegates expression refinement to SymbolicAstToZ3Compiler.
"""

from typing import Dict, Any
import z3
from validation.smt_refinement import SmtRefinementVerifier


def alive_verify_refinement(src_type: str, tgt_type: str, bit_width: int = 64) -> Dict[str, Any]:
    """
    Formally verifies that an optimization step is a strict bit-exact refinement:
    Target preserves Source semantics without introducing undefined behavior (UB).
    """
    verifier = SmtRefinementVerifier(timeout_ms=2000)
    res = verifier.verify_arithmetic_refinement(src_type, tgt_type, bit_width=bit_width)
    is_valid = bool(res.get("proven", False))

    return {
        "source": src_type,
        "target": tgt_type,
        "is_refined": is_valid,
        "bit_width": bit_width,
        "smt_status": "unsat" if is_valid else ("sat" if res.get("refinement_status") == "SEMANTIC_DIVERGENCE_DETECTED" else "unknown"),
        "refinement_status": res.get("refinement_status"),
        "counterexamples": res.get("counterexamples", []),
        "proved": is_valid
    }


def alive_check_memory_bounds(base_ptr: int, offset: int, size: int) -> Dict[str, Any]:
    """
    Proves that a memory reference (base + offset + size) does not violate
    64-bit virtual memory address space invariants or wrap around.
    """
    solver = z3.Solver()
    base = z3.BitVecVal(base_ptr, 64)
    off = z3.BitVecVal(offset, 64)
    sz = z3.BitVecVal(size, 64)

    total = base + off + sz
    overflow_cond = z3.Or(
        z3.ULT(base + off, base),
        z3.ULT(total, base + off)
    )

    solver.add(overflow_cond)
    res = solver.check()
    is_safe = (res == z3.unsat)

    return {
        "base_ptr": hex(base_ptr),
        "offset": offset,
        "size": size,
        "is_safe": is_safe,
        "verified_by_smt": True
    }
