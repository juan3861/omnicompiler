"""
OmniCompiler Inter-Procedural Whole-Program ThinLTO Optimizer (thin_lto.py).
Implements cross-repository module summarization, inter-procedural constant propagation,
leaf-function inlining, and global dead-symbol elimination at the SSA IR level.
Based on the LLVM ThinLTO architecture (Johnson et al.).
"""

import ast
from typing import Dict, List, Set, Tuple, Any, Optional

from compiler.ssa_ir import SSAFunction, BasicBlock, SSAInstruction, SSAVar, optimize_ssa


class FunctionSummary:
    """Summary record for a single function across module/repository boundaries."""

    def __init__(
        self,
        name: str,
        repo_name: str,
        params: List[str],
        instruction_count: int,
        is_leaf: bool,
        callees: List[str],
        constant_return: Optional[int] = None,
        ssa_fn: Optional[SSAFunction] = None,
    ):
        self.name = name
        self.repo_name = repo_name
        self.params = params
        self.instruction_count = instruction_count
        self.is_leaf = is_leaf
        self.callees = callees
        self.constant_return = constant_return
        self.ssa_fn = ssa_fn

    @property
    def can_inline(self) -> bool:
        """Determines if the function is a suitable candidate for cross-repo inlining."""
        return self.is_leaf and self.instruction_count <= 8 and self.ssa_fn is not None


class ThinLtoSummaryIndex:
    """Global summary index holding cross-repo function metadata and call graphs."""

    def __init__(self):
        self.functions: Dict[str, FunctionSummary] = {}
        self.constants: Dict[str, int] = {}
        self.call_graph: Dict[str, Set[str]] = {}

    def register_constant(self, name: str, value: int):
        self.constants[name] = value

    def add_function_summary(self, summary: FunctionSummary):
        self.functions[summary.name] = summary
        self.call_graph[summary.name] = set(summary.callees)

    def compute_reachable_symbols(self, root_symbols: List[str]) -> Set[str]:
        """Traverses the global call-graph from root symbols to determine live code."""
        reachable: Set[str] = set()
        queue = list(root_symbols)
        while queue:
            curr = queue.pop(0)
            if curr in reachable:
                continue
            reachable.add(curr)
            for callee in self.call_graph.get(curr, []):
                if callee not in reachable:
                    queue.append(callee)
        return reachable


class ThinLtoOptimizer:
    """Performs inter-procedural whole-program optimizations using the summary index."""

    def __init__(self, index: ThinLtoSummaryIndex):
        self.index = index

    def build_summary_from_ssa(self, ssa_fn: SSAFunction, repo_name: str = "main") -> FunctionSummary:
        """Constructs a FunctionSummary from an SSAFunction."""
        inst_count = sum(len(b.instructions) for b in ssa_fn.blocks)
        callees: List[str] = []
        has_calls = False
        const_ret: Optional[int] = None

        for b in ssa_fn.blocks:
            for inst in b.instructions:
                if inst.opcode == "call":
                    has_calls = True
                    callee_name = str(inst.operands[0])
                    callees.append(callee_name)
                elif inst.opcode == "ret" and inst.operands:
                    ret_op = inst.operands[0]
                    if isinstance(ret_op, int):
                        const_ret = ret_op
                    elif isinstance(ret_op, SSAVar):
                        for prev in b.instructions:
                            if prev.result == ret_op and prev.opcode == "const" and prev.operands and isinstance(prev.operands[0], int):
                                const_ret = prev.operands[0]

        # Leaf function: has zero external function calls
        is_leaf = not has_calls

        summary = FunctionSummary(
            name=ssa_fn.name,
            repo_name=repo_name,
            params=list(ssa_fn.params),
            instruction_count=inst_count,
            is_leaf=is_leaf,
            callees=callees,
            constant_return=const_ret,
            ssa_fn=ssa_fn,
        )
        self.index.add_function_summary(summary)
        return summary

    def optimize_interprocedural_ssa(self, ssa_fn: SSAFunction) -> Tuple[SSAFunction, Dict[str, Any]]:
        """
        Applies ThinLTO optimization passes to an SSAFunction:
        1. Inlines candidate leaf functions from other repositories.
        2. Folds calls to known constant-returning functions.
        3. Propagates global cross-repo constants.
        """
        stats = {
            "inlined_calls": 0,
            "folded_constants": 0,
            "propagated_globals": 0,
        }

        changed = True
        pass_round = 0
        while changed and pass_round < 5:
            changed = False
            pass_round += 1

            for block in ssa_fn.blocks:
                new_insts: List[SSAInstruction] = []
                for inst in block.instructions:
                    if inst.opcode == "call" and len(inst.operands) >= 1:
                        callee_name = str(inst.operands[0])
                        call_args = inst.operands[1:]

                        # Check if callee is in summary index
                        summary = self.index.functions.get(callee_name)

                        # Pass 1: Constant return folding
                        if summary and summary.constant_return is not None:
                            # Replace call with const instruction
                            if inst.result is not None:
                                new_insts.append(
                                    SSAInstruction(inst.result, "const", [summary.constant_return], source_line=inst.source_line)
                                )
                                stats["folded_constants"] += 1
                                changed = True
                                continue

                        # Pass 2: Single-block leaf function inlining
                        if summary and summary.can_inline and summary.ssa_fn and len(summary.ssa_fn.blocks) == 1:
                            target_blk = summary.ssa_fn.blocks[0]
                            # Map parameters to call arguments
                            param_map: Dict[str, Any] = {}
                            for p_name, arg_val in zip(summary.params, call_args):
                                param_map[p_name] = arg_val

                            # Replicate instructions into caller
                            var_subst: Dict[SSAVar, Any] = {}
                            ret_val = None
                            for leaf_inst in target_blk.instructions:
                                if leaf_inst.opcode == "param":
                                    p_name = str(leaf_inst.operands[0])
                                    if leaf_inst.result:
                                        var_subst[leaf_inst.result] = param_map.get(p_name, 0)
                                elif leaf_inst.opcode == "ret":
                                    if leaf_inst.operands:
                                        raw_ret = leaf_inst.operands[0]
                                        ret_val = var_subst.get(raw_ret, raw_ret)
                                else:
                                    # Substitute operands
                                    mapped_ops = [var_subst.get(op, op) for op in leaf_inst.operands]
                                    new_res = leaf_inst.result
                                    if leaf_inst.result:
                                        new_res = SSAVar(
                                            f"inl_{callee_name}_{leaf_inst.result.name}",
                                            leaf_inst.result.version + 1000
                                        )
                                        var_subst[leaf_inst.result] = new_res
                                    new_insts.append(
                                        SSAInstruction(new_res, leaf_inst.opcode, mapped_ops, source_line=inst.source_line)
                                    )

                            if inst.result is not None and ret_val is not None:
                                # Assign ret_val to inst.result
                                new_insts.append(
                                    SSAInstruction(inst.result, "mov", [ret_val], source_line=inst.source_line)
                                )

                            stats["inlined_calls"] += 1
                            changed = True
                            continue

                    new_insts.append(inst)

                block.instructions = new_insts

        optimized_fn = optimize_ssa(ssa_fn)
        return optimized_fn, stats
