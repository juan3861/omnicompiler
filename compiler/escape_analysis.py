"""
OmniCompiler Inter-Procedural Escape Analysis Engine (escape_analysis.py).
Analyzes SSA IR variables to determine object lifetime and escape state:
- NO_ESCAPE: Object does not escape current function scope; eligible for stack allocation (alloca).
- ARG_ESCAPE: Object is passed to a callee function that does not retain it.
- GLOBAL_ESCAPE: Object is returned, stored in an escaping container, or assigned to global state.
"""

from enum import Enum, auto
from typing import Dict, Set, List, Tuple, Any, Optional

from compiler.ssa_ir import SSAFunction, BasicBlock, SSAInstruction, SSAVar


class EscapeState(Enum):
    NO_ESCAPE = auto()      # Purely thread/frame local; safe to promote to stack
    ARG_ESCAPE = auto()     # Passed as function parameter (read-only)
    GLOBAL_ESCAPE = auto()  # Escapes via ret, container embedding, or heap leak


class AllocationRecord:
    def __init__(self, var: SSAVar, alloc_opcode: str, instruction: SSAInstruction):
        self.var = var
        self.alloc_opcode = alloc_opcode
        self.instruction = instruction
        self.escape_state = EscapeState.NO_ESCAPE
        self.uses: List[Tuple[BasicBlock, SSAInstruction, int]] = []  # (block, inst, op_idx)

    @property
    def is_stack_promotable(self) -> bool:
        return self.escape_state == EscapeState.NO_ESCAPE


class EscapeAnalysisPass:
    """Performs whole-function escape analysis on an SSAFunction."""

    ALLOC_FUNCTIONS = frozenset({"omni_list_new", "omni_dict_new", "omni_str_new_from_bytes", "omni_alloc"})

    def __init__(self):
        self.allocations: Dict[SSAVar, AllocationRecord] = {}

    def analyze_function(self, fn: SSAFunction) -> Dict[SSAVar, AllocationRecord]:
        self.allocations.clear()

        # Step 1: Detect all dynamic allocations
        for b in fn.blocks:
            for inst in b.instructions:
                if inst.result and inst.opcode == "call" and inst.operands:
                    func_name = str(inst.operands[0])
                    if func_name in self.ALLOC_FUNCTIONS:
                        self.allocations[inst.result] = AllocationRecord(inst.result, func_name, inst)

        # Step 2: Build def-use chains for each allocation
        for b in fn.blocks:
            # Check Phi nodes
            for phi in b.phi_nodes:
                for idx, op in enumerate(phi.operands):
                    if isinstance(op, SSAVar) and op in self.allocations:
                        self.allocations[op].uses.append((b, phi, idx))

            # Check instructions
            for inst in b.instructions:
                for idx, op in enumerate(inst.operands):
                    if isinstance(op, SSAVar) and op in self.allocations:
                        self.allocations[op].uses.append((b, inst, idx))

        # Step 3: Classify escape states iteratively
        for var, record in self.allocations.items():
            for b, inst, op_idx in record.uses:
                # If used as return operand -> GLOBAL_ESCAPE
                if inst.opcode == "ret":
                    record.escape_state = EscapeState.GLOBAL_ESCAPE
                    break

                # If stored into another container -> GLOBAL_ESCAPE
                if inst.opcode == "call" and inst.operands:
                    callee = str(inst.operands[0])
                    # If stored into another container -> GLOBAL_ESCAPE
                    if callee in ("omni_list_set", "omni_dict_set", "omni_item_set"):
                        if op_idx == 3:  # Stored as value inside another container
                            record.escape_state = EscapeState.GLOBAL_ESCAPE
                            break
                        continue  # Being modified as container target (op_idx == 1) does not cause escape

                    if callee == "omni_list_append":
                        if op_idx == 2:  # Appended as item
                            record.escape_state = EscapeState.GLOBAL_ESCAPE
                            break
                        continue  # Being appended to (op_idx == 1) does not cause escape

                    # If passed to non-collection query function -> ARG_ESCAPE
                    if callee not in (
                        "omni_item_len", "omni_item_get", "omni_list_len", "omni_list_get",
                        "omni_dict_len", "omni_dict_get", "omni_str_len", "omni_str_get_byte",
                        "omni_str_slice", "omni_str_startswith", "omni_str_eq", "omni_list_sum",
                        "omni_list_vec_add", "omni_list_vec_dot"
                    ):
                        if record.escape_state != EscapeState.GLOBAL_ESCAPE:
                            record.escape_state = EscapeState.ARG_ESCAPE

        return self.allocations
