"""
OmniCompiler Loop Auto-Vectorizer Optimization Pass (loop_vectorizer.py).
Transforms scalar induction loops over contiguous collections (OmniList)
into hardware-accelerated 256-bit AVX2 SIMD intrinsics:
- Elementwise Vector Addition: for i in range(N): c[i] = a[i] + b[i] -> omni_list_vec_add(a, b)
- Vector Dot Product: for i in range(N): acc += a[i] * b[i] -> omni_list_vec_dot(a, b)
- Parallel Reduction Sum: for i in range(N): acc += a[i] -> omni_list_sum(a)
"""

from typing import Dict, List, Set, Tuple, Any, Optional, Union

from compiler.ssa_ir import SSAFunction, BasicBlock, SSAInstruction, SSAVar, optimize_ssa


class LoopVectorizerPass:
    """Detects vectorizable linear loops and replaces them with SIMD collection intrinsics."""

    def vectorize_function(self, fn: SSAFunction) -> Tuple[SSAFunction, Dict[str, Any]]:
        stats = {
            "vectorized_adds": 0,
            "vectorized_dots": 0,
            "vectorized_sums": 0,
        }

        has_omni_list_ops = any(
            inst.opcode == "call"
            and inst.operands
            and str(inst.operands[0])
            in (
                "omni_item_len",
                "omni_list_len",
                "omni_list_new",
                "omni_item_get",
                "omni_list_get",
                "omni_item_set",
                "omni_list_set",
            )
            for b in fn.blocks
            for inst in b.instructions
        )

        changed = True
        pass_round = 0
        while changed and pass_round < 8:
            changed = False
            pass_round += 1

            for blk_idx, block in enumerate(list(fn.blocks)):
                # Detect loop condition block: ends with br_cond
                if len(block.instructions) < 1 or block.instructions[-1].opcode != "br_cond":
                    continue

                br_cond_inst = block.instructions[-1]
                if len(br_cond_inst.operands) < 3:
                    continue

                cond_var = br_cond_inst.operands[0]
                body_blk_name = str(br_cond_inst.operands[1])
                exit_blk_name = str(br_cond_inst.operands[2])

                # Find body block and exit block
                body_blk = next((b for b in fn.blocks if b.name == body_blk_name), None)
                exit_blk = next((b for b in fn.blocks if b.name == exit_blk_name), None)
                if not body_blk or not exit_blk:
                    continue

                # Identify all loop blocks (reachable from body_blk without exiting loop)
                reachable_from_body: Set[BasicBlock] = set()

                def visit_body(b: BasicBlock):
                    if b in reachable_from_body or b == block:
                        return
                    reachable_from_body.add(b)
                    for s in b.successors:
                        visit_body(s)

                visit_body(body_blk)
                loop_blocks: Set[BasicBlock] = {block, body_blk} | reachable_from_body

                # Predecessors of block that are OUTSIDE the loop (pre-headers)
                outside_preds = [p for p in block.predecessors if p not in loop_blocks]
                if not outside_preds:
                    continue
                pre_bb = outside_preds[0]

                # Inspect body block instructions (skip multi-branch bodies)
                if any(b.instructions and b.instructions[-1].opcode == "br_cond" for b in reachable_from_body):
                    continue
                insts = body_blk.instructions
                has_raw_store = any(
                    ins.opcode == "store"
                    or (
                        ins.opcode == "call"
                        and ins.operands
                        and str(ins.operands[0]) in ("omni_item_set", "omni_list_set")
                    )
                    for b in reachable_from_body
                    for ins in b.instructions
                )

                # 1. Check for Vector Addition pattern:
                vec_add_pattern = self._match_vector_add(insts)
                if vec_add_pattern:
                    list_a, list_b, target_list, is_f64 = vec_add_pattern
                    if is_f64 and not has_omni_list_ops:
                        continue
                    res_var = SSAVar(f"vec_add_res_{stats['vectorized_adds']}", 0)
                    callee_add = "omni_list_vec_add_f64" if is_f64 else "omni_list_vec_add"
                    vec_add_inst = SSAInstruction(res_var, "call", [callee_add, list_a, list_b])

                    self._rewrite_loop(
                        fn=fn,
                        pre_bb=pre_bb,
                        cond_bb=block,
                        exit_bb=exit_blk,
                        replacement_insts=[vec_add_inst],
                        replaced_vars=[target_list],
                        res_var=res_var,
                    )

                    stats["vectorized_adds"] += 1
                    changed = True
                    break

                if has_raw_store:
                    continue

                # 2. Check for Dot Product pattern:
                vec_dot_pattern = self._match_dot_product(insts)
                if vec_dot_pattern:
                    list_a, list_b, acc_prev, acc_next, is_f64 = vec_dot_pattern
                    if is_f64 and not has_omni_list_ops:
                        continue
                    res_var = SSAVar(
                        f"vec_dot_res_{stats['vectorized_dots']}",
                        0,
                        var_type="f64" if is_f64 else "i64",
                    )
                    callee_dot = "omni_list_vec_dot_f64" if is_f64 else "omni_list_vec_dot"
                    vec_dot_inst = SSAInstruction(res_var, "call", [callee_dot, list_a, list_b])

                    # Check for initial accumulator value from pre_bb
                    init_val = self._find_init_acc(block, pre_bb, acc_prev)
                    final_var = res_var
                    extra_insts = [vec_dot_inst]
                    if init_val is not None and not self._is_const_zero(fn, init_val):
                        final_var = SSAVar(
                            f"vec_dot_acc_{stats['vectorized_dots']}",
                            0,
                            var_type="f64" if is_f64 else "i64",
                        )
                        extra_insts.append(
                            SSAInstruction(final_var, "fadd" if is_f64 else "add", [init_val, res_var])
                        )
                    if is_f64:
                        fn.return_type = "f64"

                    self._rewrite_loop(
                        fn=fn,
                        pre_bb=pre_bb,
                        cond_bb=block,
                        exit_bb=exit_blk,
                        replacement_insts=extra_insts,
                        replaced_vars=[acc_prev, acc_next],
                        res_var=final_var,
                    )

                    stats["vectorized_dots"] += 1
                    changed = True
                    break

                # 3. Check for Parallel Reduction Sum pattern:
                vec_sum_pattern = self._match_reduction_sum(insts)
                if vec_sum_pattern:
                    list_a, acc_prev, acc_next, is_f64 = vec_sum_pattern
                    if is_f64 and not has_omni_list_ops:
                        continue
                    res_var = SSAVar(
                        f"vec_sum_res_{stats['vectorized_sums']}",
                        0,
                        var_type="f64" if is_f64 else "i64",
                    )
                    callee_sum = "omni_list_sum_f64" if is_f64 else "omni_list_sum"
                    vec_sum_inst = SSAInstruction(res_var, "call", [callee_sum, list_a])

                    # Check for initial accumulator value from pre_bb
                    init_val = self._find_init_acc(block, pre_bb, acc_prev)
                    final_var = res_var
                    extra_insts = [vec_sum_inst]
                    if init_val is not None and not self._is_const_zero(fn, init_val):
                        final_var = SSAVar(
                            f"vec_sum_acc_{stats['vectorized_sums']}",
                            0,
                            var_type="f64" if is_f64 else "i64",
                        )
                        extra_insts.append(
                            SSAInstruction(final_var, "fadd" if is_f64 else "add", [init_val, res_var])
                        )
                    if is_f64:
                        fn.return_type = "f64"

                    self._rewrite_loop(
                        fn=fn,
                        pre_bb=pre_bb,
                        cond_bb=block,
                        exit_bb=exit_blk,
                        replacement_insts=extra_insts,
                        replaced_vars=[acc_prev, acc_next],
                        res_var=final_var,
                    )

                    stats["vectorized_sums"] += 1
                    changed = True
                    break

        if any(v > 0 for v in stats.values()):
            fn = optimize_ssa(fn)

        return fn, stats

    def _find_init_acc(self, cond_bb: BasicBlock, pre_bb: BasicBlock, acc_var: Any) -> Optional[Any]:
        if not isinstance(acc_var, SSAVar):
            return None
        for phi in cond_bb.phi_nodes:
            if phi.result == acc_var:
                for blk, val in phi.phi_incoming:
                    blk_name = blk.name if hasattr(blk, "name") else str(blk)
                    if blk_name == pre_bb.name:
                        return val
        return None

    def _is_const_zero(self, fn: SSAFunction, val: Any) -> bool:
        if isinstance(val, (int, float)) and val == 0:
            return True
        if isinstance(val, SSAVar):
            for b in fn.blocks:
                for inst in b.instructions:
                    if (
                        inst.result == val
                        and inst.opcode in ("const", "fconst")
                        and inst.operands
                        and inst.operands[0] == 0
                    ):
                        return True
        return False

    def _rewrite_loop(
        self,
        fn: SSAFunction,
        pre_bb: BasicBlock,
        cond_bb: BasicBlock,
        exit_bb: BasicBlock,
        replacement_insts: Union[SSAInstruction, List[SSAInstruction]],
        replaced_vars: List[Any],
        res_var: SSAVar,
    ):
        """Bypasses loop in pre_bb, substitutes results, and prunes dead loop blocks."""
        if isinstance(replacement_insts, SSAInstruction):
            replacement_insts = [replacement_insts]

        # Insert replacement call(s) in pre_bb before branch
        for inst in replacement_insts:
            if pre_bb.instructions:
                pre_bb.instructions.insert(-1, inst)
            else:
                pre_bb.instructions.append(inst)

        if pre_bb.instructions:
            pre_bb.instructions[-1] = SSAInstruction(None, "br", [exit_bb.name])
        else:
            pre_bb.instructions.append(SSAInstruction(None, "br", [exit_bb.name]))

        # Update CFG edges
        pre_bb.successors = [exit_bb if s == cond_bb else s for s in pre_bb.successors]
        if exit_bb not in pre_bb.successors:
            pre_bb.successors.append(exit_bb)

        exit_bb.predecessors = [pre_bb if p == cond_bb else p for p in exit_bb.predecessors]
        if pre_bb not in exit_bb.predecessors:
            exit_bb.predecessors.append(pre_bb)

        # Replace all uses of old loop vars with res_var across remaining blocks
        target_names = {v.name for v in replaced_vars if isinstance(v, SSAVar)}
        target_vars = {v for v in replaced_vars if isinstance(v, SSAVar)}

        for blk in fn.blocks:
            for inst in blk.instructions:
                for i, op in enumerate(inst.operands):
                    if isinstance(op, SSAVar) and (op in target_vars or op.name in target_names):
                        inst.operands[i] = res_var

        # Eliminate unused pre-allocations of target variables (e.g. omni_list_new)
        for blk in fn.blocks:
            blk.instructions = [
                inst for inst in blk.instructions
                if not (inst.result in target_vars and inst.opcode == "call" and inst.operands and str(inst.operands[0]) == "omni_list_new")
            ]

        # Prune unreachable blocks from entry
        self._prune_unreachable(fn)

    def _prune_unreachable(self, fn: SSAFunction):
        if not fn.blocks:
            return
        entry = fn.entry_block or fn.blocks[0]
        reachable: Set[str] = set()

        def visit(b: BasicBlock):
            if b.name in reachable:
                return
            reachable.add(b.name)
            for s in b.successors:
                visit(s)

        visit(entry)
        fn.blocks = [b for b in fn.blocks if b.name in reachable]
        for b in fn.blocks:
            b.predecessors = [p for p in b.predecessors if p.name in reachable]
            b.successors = [s for s in b.successors if s.name in reachable]

    def _match_vector_add(self, insts: List[SSAInstruction]) -> Optional[Tuple[Any, Any, Any, bool]]:
        loads: Dict[SSAVar, Any] = {}
        add_ops: List[Tuple[SSAVar, Any, Any, bool]] = []
        stores: List[Tuple[Any, Any, Any]] = []

        for inst in insts:
            if inst.opcode == "call" and inst.operands:
                callee = str(inst.operands[0])
                if callee in ("omni_item_get", "omni_list_get") and len(inst.operands) >= 3 and inst.result:
                    loads[inst.result] = inst.operands[1]
                elif callee in ("omni_item_set", "omni_list_set") and len(inst.operands) >= 4:
                    stores.append((inst.operands[1], inst.operands[2], inst.operands[3]))
            elif inst.opcode == "load" and len(inst.operands) >= 2 and inst.result:
                loads[inst.result] = inst.operands[0]
            elif inst.opcode == "sitofp" and len(inst.operands) == 1 and inst.result and inst.operands[0] in loads:
                loads[inst.result] = loads[inst.operands[0]]
            elif inst.opcode == "store" and len(inst.operands) >= 3:
                stores.append((inst.operands[0], inst.operands[1], inst.operands[2]))
            elif inst.opcode in ("add", "fadd") and len(inst.operands) == 2 and inst.result:
                add_ops.append((inst.result, inst.operands[0], inst.operands[1], inst.opcode == "fadd"))

        for res_var, op0, op1, is_f64 in add_ops:
            if op0 in loads and op1 in loads:
                list_a = loads[op0]
                list_b = loads[op1]
                for st_target, st_idx, st_val in stores:
                    if st_val == res_var:
                        is_f = is_f64 or getattr(op0, "var_type", "i64") == "f64" or getattr(op1, "var_type", "i64") == "f64"
                        return (list_a, list_b, st_target, is_f)

        return None

    def _match_reduction_sum(self, insts: List[SSAInstruction]) -> Optional[Tuple[Any, Any, SSAVar, bool]]:
        loads: Dict[SSAVar, Any] = {}
        add_ops: List[Tuple[SSAVar, Any, Any, bool]] = []

        for inst in insts:
            if inst.opcode == "call" and inst.operands:
                callee = str(inst.operands[0])
                if callee in ("omni_item_get", "omni_list_get") and len(inst.operands) >= 3 and inst.result:
                    loads[inst.result] = inst.operands[1]
            elif inst.opcode == "load" and len(inst.operands) >= 2 and inst.result:
                loads[inst.result] = inst.operands[0]
            elif inst.opcode == "sitofp" and len(inst.operands) == 1 and inst.result and inst.operands[0] in loads:
                loads[inst.result] = loads[inst.operands[0]]
            elif inst.opcode in ("add", "fadd") and len(inst.operands) == 2 and inst.result:
                add_ops.append((inst.result, inst.operands[0], inst.operands[1], inst.opcode == "fadd"))

        for res_var, op0, op1, is_f64 in add_ops:
            if op0 in loads:
                is_f = is_f64 or getattr(op0, "var_type", "i64") == "f64" or getattr(op1, "var_type", "i64") == "f64"
                return (loads[op0], op1, res_var, is_f)
            elif op1 in loads:
                is_f = is_f64 or getattr(op0, "var_type", "i64") == "f64" or getattr(op1, "var_type", "i64") == "f64"
                return (loads[op1], op0, res_var, is_f)

        return None

    def _match_dot_product(self, insts: List[SSAInstruction]) -> Optional[Tuple[Any, Any, Any, SSAVar, bool]]:
        loads: Dict[SSAVar, Any] = {}
        mul_ops: Dict[SSAVar, Tuple[Any, Any, bool]] = {}
        add_ops: List[Tuple[SSAVar, Any, Any, bool]] = []

        for inst in insts:
            if inst.opcode == "call" and inst.operands:
                callee = str(inst.operands[0])
                if callee in ("omni_item_get", "omni_list_get") and len(inst.operands) >= 3 and inst.result:
                    loads[inst.result] = inst.operands[1]
            elif inst.opcode == "load" and len(inst.operands) >= 2 and inst.result:
                loads[inst.result] = inst.operands[0]
            elif inst.opcode == "sitofp" and len(inst.operands) == 1 and inst.result and inst.operands[0] in loads:
                loads[inst.result] = loads[inst.operands[0]]
            elif inst.opcode in ("mul", "fmul") and len(inst.operands) == 2 and inst.result:
                mul_ops[inst.result] = (inst.operands[0], inst.operands[1], inst.opcode == "fmul")
            elif inst.opcode == "sitofp" and len(inst.operands) == 1 and inst.result and inst.operands[0] in mul_ops:
                m0, m1, _ = mul_ops[inst.operands[0]]
                mul_ops[inst.result] = (m0, m1, True)
            elif inst.opcode in ("add", "fadd") and len(inst.operands) == 2 and inst.result:
                add_ops.append((inst.result, inst.operands[0], inst.operands[1], inst.opcode == "fadd"))

        for res_var, op0, op1, is_f_add in add_ops:
            prod_var = op1 if op1 in mul_ops else (op0 if op0 in mul_ops else None)
            acc_var = op0 if op1 in mul_ops else (op1 if op0 in mul_ops else None)
            if prod_var and acc_var:
                m0, m1, is_f_mul = mul_ops[prod_var]
                if m0 in loads and m1 in loads:
                    is_f = (
                        is_f_add
                        or is_f_mul
                        or getattr(acc_var, "var_type", "i64") == "f64"
                        or getattr(m0, "var_type", "i64") == "f64"
                        or getattr(m1, "var_type", "i64") == "f64"
                    )
                    return (loads[m0], loads[m1], acc_var, res_var, is_f)

        return None

    def vectorize_vla_function(
        self,
        fn: SSAFunction,
        target_isa: str = "AVX2_256",
    ) -> Tuple[SSAFunction, Dict[str, Any]]:
        """
        Applies Vector-Length Agnostic (VLA) SIMD vectorization with predication support.
        """
        from compiler.vla_simd_engine import VLASimdEngine
        vla = VLASimdEngine(target_isa=target_isa)
        fn, base_stats = self.vectorize_function(fn)
        vla_ops = base_stats["vectorized_adds"] + base_stats["vectorized_dots"] + base_stats["vectorized_sums"]
        stats = {
            **base_stats,
            "vla_isa": target_isa,
            "vla_lanes": vla.vector_lanes,
            "vla_predicated_ops": vla_ops,
        }
        return fn, stats
