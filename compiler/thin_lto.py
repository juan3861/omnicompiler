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
        return self.is_leaf and self.instruction_count <= 8 and self.ssa_fn is not None and len(self.ssa_fn.blocks) == 1

    @property
    def can_inline_multiblock(self) -> bool:
        """Determines if the function is a candidate for multi-block CFG inlining."""
        return (
            self.is_leaf
            and self.instruction_count <= 48
            and self.ssa_fn is not None
            and 1 < len(self.ssa_fn.blocks) <= 8
        )


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

    def _inline_multiblock_callee(
        self,
        caller_fn: SSAFunction,
        caller_block: BasicBlock,
        call_idx: int,
        summary: FunctionSummary,
        call_args: List[Any],
        inline_id: int,
    ) -> BasicBlock:
        """Splits caller_block at call_idx, clones callee CFG, and wires control-flow edges."""
        call_inst = caller_block.instructions[call_idx]
        callee_fn = summary.ssa_fn
        assert callee_fn is not None

        # 1. Split caller_block into head (stays in caller_block) and tail
        head_insts = caller_block.instructions[:call_idx]
        tail_insts = caller_block.instructions[call_idx + 1:]
        caller_block.instructions = head_insts

        tail_block = BasicBlock(f"{caller_block.name}_tail_{inline_id}")
        tail_block.instructions = tail_insts
        tail_block.successors = list(caller_block.successors)

        for succ in caller_block.successors:
            succ.predecessors = [tail_block if p == caller_block else p for p in succ.predecessors]
            for phi in succ.phi_nodes:
                phi.phi_incoming = [
                    (tail_block.name if blk == caller_block.name else blk, val)
                    for blk, val in phi.phi_incoming
                ]
        caller_block.successors.clear()

        # 2. Clone callee blocks with unique names
        cloned_blocks: Dict[str, BasicBlock] = {}
        for b in callee_fn.blocks:
            cloned_b = BasicBlock(f"{b.name}_inl_{inline_id}_{summary.name}")
            cloned_blocks[b.name] = cloned_b

        param_map: Dict[str, Any] = {p_name: arg for p_name, arg in zip(summary.params, call_args)}
        var_map: Dict[SSAVar, Any] = {}
        ret_sites: List[Tuple[BasicBlock, Any]] = []

        # Pass A: allocate new SSAVars for callee definitions
        for b in callee_fn.blocks:
            for phi in b.phi_nodes:
                if phi.result:
                    new_res = SSAVar(f"inl_{phi.result.name}_{inline_id}", phi.result.version + inline_id * 1000)
                    var_map[phi.result] = new_res
            for inst in b.instructions:
                if inst.opcode == "param":
                    p_name = str(inst.operands[0])
                    if inst.result:
                        var_map[inst.result] = param_map.get(p_name, 0)
                elif inst.opcode != "ret" and inst.result:
                    new_res = SSAVar(f"inl_{inst.result.name}_{inline_id}", inst.result.version + inline_id * 1000)
                    var_map[inst.result] = new_res

        # Pass B: populate cloned block instructions and connect internal CFG edges
        for b in callee_fn.blocks:
            cloned_b = cloned_blocks[b.name]
            for phi in b.phi_nodes:
                new_res = var_map.get(phi.result, phi.result)
                mapped_ops = [var_map.get(op, op) for op in phi.operands]
                mapped_inc = [
                    (cloned_blocks[p_name].name if p_name in cloned_blocks else p_name, var_map.get(v, v))
                    for p_name, v in phi.phi_incoming
                ]
                cloned_b.phi_nodes.append(
                    SSAInstruction(new_res, "phi", mapped_ops, phi_incoming=mapped_inc, source_line=phi.source_line)
                )

            for inst in b.instructions:
                if inst.opcode == "param":
                    continue
                elif inst.opcode == "ret":
                    ret_val = var_map.get(inst.operands[0], inst.operands[0]) if inst.operands else 0
                    ret_sites.append((cloned_b, ret_val))
                    cloned_b.connect_to(tail_block)
                    cloned_b.add_instruction(SSAInstruction(None, "br", [tail_block.name], source_line=inst.source_line))
                elif inst.opcode == "br":
                    target_name = str(inst.operands[0])
                    target_b = cloned_blocks.get(target_name)
                    if target_b:
                        cloned_b.connect_to(target_b)
                        cloned_b.add_instruction(SSAInstruction(None, "br", [target_b.name], source_line=inst.source_line))
                elif inst.opcode == "br_cond":
                    cond_v = var_map.get(inst.operands[0], inst.operands[0])
                    t_name = str(inst.operands[1])
                    f_name = str(inst.operands[2])
                    t_b = cloned_blocks.get(t_name)
                    f_b = cloned_blocks.get(f_name)
                    if t_b and f_b:
                        cloned_b.connect_to(t_b)
                        cloned_b.connect_to(f_b)
                        cloned_b.add_instruction(
                            SSAInstruction(None, "br_cond", [cond_v, t_b.name, f_b.name], source_line=inst.source_line)
                        )
                else:
                    mapped_ops = [var_map.get(op, op) for op in inst.operands]
                    new_res = var_map.get(inst.result, inst.result)
                    cloned_b.add_instruction(
                        SSAInstruction(new_res, inst.opcode, mapped_ops, source_line=inst.source_line)
                    )

        # 3. Connect caller_block to callee entry block
        callee_entry = callee_fn.entry_block or callee_fn.blocks[0]
        cloned_entry = cloned_blocks[callee_entry.name]
        caller_block.connect_to(cloned_entry)
        caller_block.add_instruction(
            SSAInstruction(None, "br", [cloned_entry.name], source_line=call_inst.source_line)
        )

        # 4. Handle return value in tail_block
        if call_inst.result is not None:
            if len(ret_sites) == 1:
                tail_block.instructions.insert(
                    0, SSAInstruction(call_inst.result, "mov", [ret_sites[0][1]], source_line=call_inst.source_line)
                )
            elif len(ret_sites) > 1:
                phi_inc = [(b.name, val) for b, val in ret_sites]
                phi_ops = [val for _, val in ret_sites]
                tail_block.phi_nodes.insert(
                    0, SSAInstruction(call_inst.result, "phi", phi_ops, phi_incoming=phi_inc, source_line=call_inst.source_line)
                )
            else:
                tail_block.instructions.insert(
                    0, SSAInstruction(call_inst.result, "const", [0], source_line=call_inst.source_line)
                )

        # 5. Insert cloned blocks and tail_block into caller_fn.blocks
        blk_idx = caller_fn.blocks.index(caller_block)
        inserted_blocks = list(cloned_blocks.values()) + [tail_block]
        caller_fn.blocks[blk_idx + 1:blk_idx + 1] = inserted_blocks

        return tail_block

    def optimize_interprocedural_ssa(self, ssa_fn: SSAFunction) -> Tuple[SSAFunction, Dict[str, Any]]:
        """
        Applies ThinLTO optimization passes to an SSAFunction:
        1. Inlines candidate leaf functions (single-block and multi-block CFG) from other repositories.
        2. Folds calls to known constant-returning functions.
        3. Propagates global cross-repo constants.
        """
        stats = {
            "inlined_calls": 0,
            "multiblock_inlines": 0,
            "folded_constants": 0,
            "propagated_globals": 0,
        }

        changed = True
        pass_round = 0
        inline_counter = 0

        while changed and pass_round < 5:
            changed = False
            pass_round += 1

            for block in list(ssa_fn.blocks):
                # Search for calls in block
                multiblock_done = False
                for idx, inst in enumerate(list(block.instructions)):
                    if inst.opcode == "call" and len(inst.operands) >= 1:
                        callee_name = str(inst.operands[0])
                        call_args = inst.operands[1:]

                        summary = self.index.functions.get(callee_name)

                        # Pass 1: Constant return folding
                        if summary and summary.constant_return is not None:
                            block.instructions[idx] = SSAInstruction(
                                inst.result, "const", [summary.constant_return], source_line=inst.source_line
                            )
                            stats["folded_constants"] += 1
                            changed = True
                            continue

                        # Pass 2: Single-block leaf function inlining
                        if summary and summary.can_inline and summary.ssa_fn and len(summary.ssa_fn.blocks) == 1:
                            target_blk = summary.ssa_fn.blocks[0]
                            param_map: Dict[str, Any] = {
                                p_name: arg for p_name, arg in zip(summary.params, call_args)
                            }
                            var_subst: Dict[SSAVar, Any] = {}
                            ret_val = None
                            splice_insts: List[SSAInstruction] = []

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
                                    mapped_ops = [var_subst.get(op, op) for op in leaf_inst.operands]
                                    new_res = leaf_inst.result
                                    if leaf_inst.result:
                                        new_res = SSAVar(
                                            f"inl_{callee_name}_{leaf_inst.result.name}",
                                            leaf_inst.result.version + 1000 + inline_counter
                                        )
                                        var_subst[leaf_inst.result] = new_res
                                    splice_insts.append(
                                        SSAInstruction(new_res, leaf_inst.opcode, mapped_ops, source_line=inst.source_line)
                                    )

                            if inst.result is not None and ret_val is not None:
                                splice_insts.append(
                                    SSAInstruction(inst.result, "mov", [ret_val], source_line=inst.source_line)
                                )

                            # Replace call instruction with splice_insts
                            block.instructions[idx:idx + 1] = splice_insts
                            stats["inlined_calls"] += 1
                            inline_counter += 1
                            changed = True
                            break

                        # Pass 3: Multi-block CFG inlining
                        if summary and summary.can_inline_multiblock and summary.ssa_fn:
                            inline_counter += 1
                            self._inline_multiblock_callee(
                                ssa_fn, block, idx, summary, call_args, inline_counter
                            )
                            stats["inlined_calls"] += 1
                            stats["multiblock_inlines"] += 1
                            changed = True
                            multiblock_done = True
                            break

                if multiblock_done:
                    break

        optimized_fn = optimize_ssa(ssa_fn)
        return optimized_fn, stats
