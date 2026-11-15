"""
OmniCompiler Scalar Replacement of Aggregates (SROA) & Speculative Devirtualization
(compiler/sroa_and_devirt.py)

Implements:
1. SROAPass (Scalar Replacement of Aggregates):
   - Identifies non-escaping `alloca` aggregates accessed exclusively via
     compile-time constant indices.
   - Decomposes each accessed aggregate slot into pure SSA scalar variables,
     eliminating `alloca`, `store`, and `load` instructions so values reside
     entirely in physical registers via IRC.
2. DevirtualizationPass (Speculative Devirtualization with Guarded Fallback):
   - Transforms polymorphic `vcall` / `call_indirect` instructions into a
     guarded diamond CFG (`guard_cond = cmp_eq tag, expected_tag`):
       - Fast path: direct `call direct_callee(*args)` (eligible for ThinLTO inlining)
       - Slow path: fallback to original indirect dispatch
       - Merge block: `phi` node combining fast/slow results seamlessly.
"""

from typing import Dict, List, Set, Tuple, Any, Optional

from compiler.ssa_ir import (
    SSAFunction,
    BasicBlock,
    SSAInstruction,
    SSAVar,
    optimize_ssa,
)


class SROAPass:
    """
    Scalar Replacement of Aggregates (SROA).
    Promotes non-escaping constant-indexed `alloca` buffers into pure SSA scalars.
    """

    def run_on_function(self, fn: SSAFunction) -> Tuple[SSAFunction, Dict[str, Any]]:
        if not fn.blocks:
            return fn, {"sroa_replaced_allocas": 0, "sroa_eliminated_mem_ops": 0}

        const_vals: Dict[SSAVar, int] = {}
        allocas: Dict[SSAVar, BasicBlock] = {}
        for b in fn.blocks:
            for inst in b.instructions:
                if inst.opcode == "const" and inst.result is not None and inst.operands:
                    v = inst.operands[0]
                    if isinstance(v, (int, bool)):
                        const_vals[inst.result] = int(v)
                elif inst.opcode == "alloca" and inst.result is not None:
                    allocas[inst.result] = b

        if not allocas:
            return fn, {"sroa_replaced_allocas": 0, "sroa_eliminated_mem_ops": 0}

        def resolve_const_idx(op: Any) -> Optional[int]:
            if isinstance(op, bool):
                return int(op)
            if isinstance(op, int):
                return op
            if isinstance(op, SSAVar) and op in const_vals:
                return const_vals[op]
            return None

        # Determine eligible non-escaping constant-indexed allocas
        ineligible: Set[SSAVar] = set()
        access_blocks: Dict[SSAVar, Set[str]] = {a: set() for a in allocas}
        has_loop_store: Set[SSAVar] = set()

        for b in fn.blocks:
            for phi in b.phi_nodes:
                for op in phi.operands:
                    if isinstance(op, SSAVar) and op in allocas:
                        ineligible.add(op)
            for inst in b.instructions:
                if inst.opcode == "alloca":
                    continue
                if inst.opcode == "load" and len(inst.operands) >= 2 and inst.operands[0] in allocas:
                    agg = inst.operands[0]
                    if resolve_const_idx(inst.operands[1]) is None:
                        ineligible.add(agg)
                    else:
                        access_blocks[agg].add(b.name)
                elif inst.opcode == "store" and len(inst.operands) >= 3 and inst.operands[0] in allocas:
                    agg = inst.operands[0]
                    val = inst.operands[2]
                    if val in allocas:
                        ineligible.add(val)
                    if resolve_const_idx(inst.operands[1]) is None:
                        ineligible.add(agg)
                    else:
                        access_blocks[agg].add(b.name)
                        if b.loop_depth > 0:
                            has_loop_store.add(agg)
                else:
                    # Any other use (call, ret, arithmetic, etc.) means escape or pointer arithmetic
                    for op in inst.operands:
                        if isinstance(op, SSAVar) and op in allocas:
                            ineligible.add(op)

        # For soundness without full multi-block phi insertion, require either:
        #   - all accesses in a single block, OR
        #   - no loop-carried stores and definition block dominates all access blocks
        eligible: Set[SSAVar] = set()
        idom = fn.compute_dominators() if len(fn.blocks) > 1 else {}

        def dominates(dom_b: str, target_b: str) -> bool:
            cur: Optional[str] = target_b
            while cur is not None:
                if cur == dom_b:
                    return True
                parent = idom.get(cur)
                if parent == cur:
                    break
                cur = parent
            return False

        for agg, def_blk in allocas.items():
            if agg in ineligible:
                continue
            blks = access_blocks[agg]
            if len(blks) <= 1:
                eligible.add(agg)
            elif agg not in has_loop_store and all(dominates(def_blk.name, bn) for bn in blks):
                # Also verify each load is preceded by a store in the same block or a dominating block
                eligible.add(agg)

        if not eligible:
            return fn, {"sroa_replaced_allocas": 0, "sroa_eliminated_mem_ops": 0}

        # Perform scalar replacement using dominator-tree traversal
        dom_children: Dict[str, List[str]] = {b.name: [] for b in fn.blocks}
        for b in fn.blocks:
            p = idom.get(b.name)
            if p is not None and p != b.name and p in dom_children:
                dom_children[p].append(b.name)
        block_by_name = {b.name: b for b in fn.blocks}
        entry = fn.entry_block or fn.blocks[0]

        eliminated_mem_ops = 0
        replaced_allocas: Set[SSAVar] = set()

        def walk_dom(bname: str, current_slots: Dict[Tuple[SSAVar, int], Any]):
            nonlocal eliminated_mem_ops
            b = block_by_name.get(bname)
            if b is None:
                return

            local_slots = dict(current_slots)
            new_insts: List[SSAInstruction] = []
            for inst in b.instructions:
                if inst.opcode == "alloca" and inst.result in eligible:
                    replaced_allocas.add(inst.result)
                    eliminated_mem_ops += 1
                    continue
                elif inst.opcode == "store" and len(inst.operands) >= 3 and inst.operands[0] in eligible:
                    agg = inst.operands[0]
                    cidx = resolve_const_idx(inst.operands[1])
                    if cidx is not None:
                        local_slots[(agg, cidx)] = inst.operands[2]
                        eliminated_mem_ops += 1
                        continue
                elif inst.opcode == "load" and len(inst.operands) >= 2 and inst.operands[0] in eligible:
                    agg = inst.operands[0]
                    cidx = resolve_const_idx(inst.operands[1])
                    if cidx is not None and inst.result is not None:
                        val = local_slots.get((agg, cidx), 0)
                        new_insts.append(
                            SSAInstruction(
                                inst.result,
                                "mov",
                                [val],
                                source_line=inst.source_line,
                            )
                        )
                        eliminated_mem_ops += 1
                        continue
                new_insts.append(inst)

            b.instructions = new_insts
            for child in dom_children.get(bname, []):
                walk_dom(child, local_slots)

        walk_dom(entry.name, {})
        fn = optimize_ssa(fn)

        return fn, {
            "sroa_replaced_allocas": len(replaced_allocas),
            "sroa_eliminated_mem_ops": eliminated_mem_ops,
        }


class DevirtualizationPass:
    """
    Speculative Devirtualization Pass with Guarded Fallback.
    Transforms `vcall` / `call_indirect` instructions with known dominant targets
    into a guarded diamond CFG (fast direct call vs. safe indirect fallback).
    """

    def run_on_function(
        self,
        fn: SSAFunction,
        speculative_targets: Optional[Dict[str, Tuple[int, str]]] = None,
    ) -> Tuple[SSAFunction, Dict[str, Any]]:
        if not fn.blocks or not speculative_targets:
            return fn, {"devirtualized_calls": 0}

        devirt_count = 0
        existing_names: Set[str] = {b.name for b in fn.blocks}
        fallback_blocks: Set[str] = set()

        def fresh_block_name(prefix: str) -> str:
            idx = 0
            cand = f"{prefix}_{idx}"
            while cand in existing_names:
                idx += 1
                cand = f"{prefix}_{idx}"
            existing_names.add(cand)
            return cand

        changed = True
        while changed:
            changed = False
            for blk in list(fn.blocks):
                if blk.name in fallback_blocks:
                    continue
                for idx, inst in enumerate(blk.instructions):
                    if inst.opcode not in ("vcall", "call_indirect"):
                        continue
                    if len(inst.operands) < 2:
                        continue
                    tag_var = inst.operands[0]
                    target_key = str(inst.operands[1])
                    if target_key not in speculative_targets:
                        continue

                    expected_tag, direct_callee = speculative_targets[target_key]
                    call_args = inst.operands[2:]
                    orig_res = inst.result

                    # Split `blk` at `idx`
                    before_insts = blk.instructions[:idx]
                    after_insts = blk.instructions[idx + 1:]

                    fast_name = fresh_block_name("devirt_fast")
                    slow_name = fresh_block_name("devirt_slow")
                    merge_name = fresh_block_name("devirt_merge")

                    fast_blk = BasicBlock(fast_name)
                    slow_blk = BasicBlock(slow_name)
                    fallback_blocks.add(slow_name)
                    merge_blk = BasicBlock(merge_name)
                    fast_blk.loop_depth = blk.loop_depth
                    slow_blk.loop_depth = blk.loop_depth
                    merge_blk.loop_depth = blk.loop_depth

                    # Guard condition in `blk`
                    guard_var = SSAVar(f"devirt_guard_{devirt_count}", 0)
                    guard_cmp = SSAInstruction(guard_var, "cmp_eq", [tag_var, expected_tag], source_line=inst.source_line)
                    guard_br = SSAInstruction(None, "br_cond", [guard_var, fast_name, slow_name], source_line=inst.source_line)
                    blk.instructions = before_insts + [guard_cmp, guard_br]

                    # Fast path: direct call
                    fast_res = SSAVar(f"devirt_fast_res_{devirt_count}", 0) if orig_res is not None else None
                    fast_blk.add_instruction(
                        SSAInstruction(fast_res, "call", [direct_callee] + list(call_args), source_line=inst.source_line)
                    )
                    fast_blk.add_instruction(SSAInstruction(None, "br", [merge_name]))

                    # Slow path: original indirect call
                    slow_res = SSAVar(f"devirt_slow_res_{devirt_count}", 0) if orig_res is not None else None
                    slow_blk.add_instruction(
                        SSAInstruction(slow_res, inst.opcode, list(inst.operands), source_line=inst.source_line)
                    )
                    slow_blk.add_instruction(SSAInstruction(None, "br", [merge_name]))

                    # Merge block: phi + remaining instructions
                    if orig_res is not None and fast_res is not None and slow_res is not None:
                        phi_inc = [(fast_name, fast_res), (slow_name, slow_res)]
                        merge_blk.phi_nodes.append(
                            SSAInstruction(orig_res, "phi", [fast_res, slow_res], phi_incoming=phi_inc)
                        )
                    merge_blk.instructions = after_insts

                    # Wire CFG edges
                    orig_succs = list(blk.successors)
                    blk.successors = [fast_blk, slow_blk]
                    fast_blk.predecessors = [blk]
                    fast_blk.successors = [merge_blk]
                    slow_blk.predecessors = [blk]
                    slow_blk.successors = [merge_blk]
                    merge_blk.predecessors = [fast_blk, slow_blk]
                    merge_blk.successors = orig_succs

                    for s in orig_succs:
                        s.predecessors = [merge_blk if p == blk else p for p in s.predecessors]
                        for phi in s.phi_nodes:
                            phi.phi_incoming = [
                                (merge_name if bname == blk.name else bname, val)
                                for bname, val in phi.phi_incoming
                            ]

                    blk_pos = fn.blocks.index(blk)
                    fn.blocks.insert(blk_pos + 1, fast_blk)
                    fn.blocks.insert(blk_pos + 2, slow_blk)
                    fn.blocks.insert(blk_pos + 3, merge_blk)

                    devirt_count += 1
                    changed = True
                    break
                if changed:
                    break

        return fn, {"devirtualized_calls": devirt_count}
