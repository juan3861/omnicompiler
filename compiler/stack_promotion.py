"""
OmniCompiler Stack Allocation Promotion Optimization Pass (stack_promotion.py).
Transforms heap-allocated non-escaping dynamic collections (OmniList)
into zero-cost thread stack frame allocations (alloca), eliminating heap overhead
and memory fragmentation for temporary buffers.
"""

from typing import Dict, Tuple, Any, List, Set, Optional

from compiler.ssa_ir import SSAFunction, BasicBlock, SSAInstruction, SSAVar, optimize_ssa
from compiler.escape_analysis import EscapeAnalysisPass, EscapeState


class StackPromotionPass:
    """Promotes heap allocations with NO_ESCAPE status into stack alloca instructions."""

    def __init__(self):
        self.escape_analyzer = EscapeAnalysisPass()

    def promote_function(self, fn: SSAFunction) -> Tuple[SSAFunction, Dict[str, Any]]:
        stats = {
            "promoted_lists": 0,
            "promoted_strings": 0,
            "bytes_promoted_to_stack": 0,
        }

        allocations = self.escape_analyzer.analyze_function(fn)
        if not allocations:
            return fn, stats

        # Build constant map to resolve SSAVars holding capacities
        const_vals: Dict[SSAVar, int] = {}
        for b in fn.blocks:
            for inst in b.instructions:
                if inst.opcode == "const" and inst.result and inst.operands and isinstance(inst.operands[0], int):
                    const_vals[inst.result] = inst.operands[0]

        def resolve_int(val: Any) -> Optional[int]:
            if isinstance(val, int):
                return val
            if isinstance(val, SSAVar):
                return const_vals.get(val)
            return None

        promoted_vars: Set[SSAVar] = set()

        for var, record in allocations.items():
            if record.is_stack_promotable:
                inst = record.instruction
                if inst.opcode == "call" and inst.operands:
                    func_name = str(inst.operands[0])

                    # 1. Promote OmniList
                    if func_name == "omni_list_new" and len(inst.operands) >= 2:
                        cap = resolve_int(inst.operands[1])
                        if cap is not None and cap > 0:
                            # 16 bytes header (capacity at 0, length at 8) + cap * 8 bytes items
                            bytes_needed = 16 + cap * 8
                            inst.opcode = "alloca"
                            inst.operands = [bytes_needed]
                            promoted_vars.add(var)
                            stats["promoted_lists"] += 1
                            stats["bytes_promoted_to_stack"] += bytes_needed

                            # Insert header initialization immediately after alloca
                            for b in fn.blocks:
                                if inst in b.instructions:
                                    idx = b.instructions.index(inst)
                                    cap_var = SSAVar(f"cap_{var.name}", var.version + 900)
                                    zero_var = SSAVar(f"len_{var.name}", var.version + 901)
                                    c_init1 = SSAInstruction(cap_var, "const", [cap], source_line=inst.source_line)
                                    c_init2 = SSAInstruction(zero_var, "const", [0], source_line=inst.source_line)
                                    st_cap = SSAInstruction(None, "store", [var, 0, cap_var], source_line=inst.source_line)
                                    st_len = SSAInstruction(None, "store", [var, 1, zero_var], source_line=inst.source_line)
                                    b.instructions[idx + 1:idx + 1] = [c_init1, c_init2, st_cap, st_len]
                                    break

                    # 2. Promote SSO OmniString
                    elif func_name == "omni_str_new_from_bytes" and len(inst.operands) >= 2:
                        raw_data = inst.operands[1]
                        if isinstance(raw_data, bytes) and len(raw_data) <= 15:
                            bytes_needed = 24
                            inst.opcode = "alloca"
                            inst.operands = [bytes_needed]
                            promoted_vars.add(var)
                            stats["promoted_strings"] += 1
                            stats["bytes_promoted_to_stack"] += bytes_needed

        return fn, stats
