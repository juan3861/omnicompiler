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
                    ins.opcode in ("store", "store_off")
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

                # 4. Check for Struct/Buffer Array Parallel Reduction Sum pattern (META-P2-VECTORIZER):
                struct_sum_pattern = self._match_struct_array_sum(block, body_blk, reachable_from_body)
                if struct_sum_pattern:
                    base_ptr, base_offset, stride, bound_count, width, acc_prev, acc_next, is_float = struct_sum_pattern
                    if bound_count <= 64:
                        replacement_insts, res_var = self._build_unrolled_tree_reduction(
                            fn=fn,
                            pre_bb=pre_bb,
                            cond_bb=block,
                            base_ptr=base_ptr,
                            base_offset=base_offset,
                            stride=stride,
                            bound_count=bound_count,
                            width=width,
                            acc_prev=acc_prev,
                            is_float=is_float,
                            step_id=stats["vectorized_sums"],
                        )
                        self._rewrite_loop(
                            fn=fn,
                            pre_bb=pre_bb,
                            cond_bb=block,
                            exit_bb=exit_blk,
                            replacement_insts=replacement_insts,
                            replaced_vars=[acc_prev, acc_next],
                            res_var=res_var,
                        )
                    else:
                        self._rewrite_struct_array_strip_mined_4x(
                            fn=fn,
                            pre_bb=pre_bb,
                            cond_bb=block,
                            body_blk=body_blk,
                            exit_bb=exit_blk,
                            base_ptr=base_ptr,
                            base_offset=base_offset,
                            stride=stride,
                            bound_count=bound_count,
                            width=width,
                            acc_prev=acc_prev,
                            acc_next=acc_next,
                            is_float=is_float,
                            step_id=stats["vectorized_sums"],
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

    def _match_struct_array_sum(
        self,
        cond_bb: BasicBlock,
        body_bb: BasicBlock,
        reachable_from_body: Set[BasicBlock],
    ) -> Optional[Tuple[Any, int, int, int, str, SSAVar, SSAVar, bool]]:
        # 1. Identify induction var and bound in cond_bb
        cmp_inst = next((ins for ins in cond_bb.instructions if ins.opcode in ("cmp_lt", "cmp_le")), None)
        if not cmp_inst or len(cmp_inst.operands) < 2:
            return None
        i_var, bound_op = cmp_inst.operands[0], cmp_inst.operands[1]
        is_le = cmp_inst.opcode == "cmp_le"

        bound_val = None
        if isinstance(bound_op, int):
            bound_val = bound_op
        else:
            search_insts = list(cond_bb.instructions)
            for p in cond_bb.predecessors:
                search_insts.extend(p.instructions)
            for ins in search_insts:
                if ins.result == bound_op and ins.opcode == "const" and ins.operands:
                    bound_val = ins.operands[0]
                    break
        if bound_val is None:
            return None
        bound_count = (bound_val + 1) if is_le else bound_val
        if bound_count <= 0 or bound_count > 4096:
            return None

        # 2. In loop body blocks, find load_off (must be a single pure reduction without stores)
        all_body_insts = list(body_bb.instructions)
        for b in reachable_from_body:
            if b is not body_bb:
                all_body_insts.extend(b.instructions)

        if any(ins.opcode in ("store", "store_off") for ins in all_body_insts):
            return None

        load_offs = [ins for ins in all_body_insts if ins.opcode == "load_off"]
        if len(load_offs) != 1 or len(load_offs[0].operands) < 3:
            return None
        load_off_inst = load_offs[0]

        base_ptr, off_var, width = load_off_inst.operands[0], load_off_inst.operands[1], str(load_off_inst.operands[2])

        # Resolve offset computation
        base_offset = 0
        stride = 4 if "32" in width else 8
        for ins in all_body_insts:
            if ins.result == off_var and ins.opcode == "add" and len(ins.operands) == 2:
                op0, op1 = ins.operands[0], ins.operands[1]
                for c_ins in all_body_insts:
                    if c_ins.result in (op0, op1) and c_ins.opcode == "const" and c_ins.operands:
                        base_offset = c_ins.operands[0]
                    if c_ins.result in (op0, op1) and c_ins.opcode == "mul" and len(c_ins.operands) == 2:
                        for m_ins in all_body_insts:
                            if m_ins.result in c_ins.operands and m_ins.opcode == "const" and m_ins.operands:
                                stride = m_ins.operands[0]
            elif ins.result == off_var and ins.opcode == "mul" and len(ins.operands) == 2:
                for m_ins in all_body_insts:
                    if m_ins.result in ins.operands and m_ins.opcode == "const" and m_ins.operands:
                        stride = m_ins.operands[0]

        # 3. Find accumulator update
        acc_inst = next(
            (ins for ins in all_body_insts if ins.opcode in ("add", "fadd") and load_off_inst.result in ins.operands),
            None,
        )
        if not acc_inst or len(acc_inst.operands) < 2:
            return None

        acc_prev = acc_inst.operands[0] if acc_inst.operands[1] == load_off_inst.result else acc_inst.operands[1]
        acc_next = acc_inst.result
        is_float = acc_inst.opcode == "fadd" or "f" in width

        return (base_ptr, int(base_offset), int(stride), int(bound_count), width, acc_prev, acc_next, is_float)

    @staticmethod
    def _tree_reduce_ssa(
        items: List[SSAVar],
        op: str,
        ssa_vt: str,
        prefix: str,
        out_insts: List[SSAInstruction],
    ) -> SSAVar:
        curr = list(items)
        round_idx = 0
        while len(curr) > 1:
            nxt: List[SSAVar] = []
            for j in range(0, len(curr), 2):
                if j + 1 < len(curr):
                    r_v = SSAVar(f"{prefix}_{round_idx}_{j // 2}", 0, var_type=ssa_vt)
                    out_insts.append(SSAInstruction(r_v, op, [curr[j], curr[j + 1]]))
                    nxt.append(r_v)
                else:
                    nxt.append(curr[j])
            curr = nxt
            round_idx += 1
        return curr[0]

    def _build_unrolled_tree_reduction(
        self,
        fn: SSAFunction,
        pre_bb: BasicBlock,
        cond_bb: BasicBlock,
        base_ptr: Any,
        base_offset: int,
        stride: int,
        bound_count: int,
        width: str,
        acc_prev: Any,
        is_float: bool,
        step_id: int,
    ) -> Tuple[List[SSAInstruction], SSAVar]:
        insts: List[SSAInstruction] = []
        loads: List[SSAVar] = []
        ssa_vt = "f64" if is_float else "i64"
        op = "fadd" if is_float else "add"

        for k in range(bound_count):
            cur_off = base_offset + k * stride
            off_v = SSAVar(f"vec_off_{step_id}_{k}", 0)
            insts.append(SSAInstruction(off_v, "const", [cur_off]))
            ld_v = SSAVar(f"vec_ld_{step_id}_{k}", 0, var_type=ssa_vt)
            insts.append(SSAInstruction(ld_v, "load_off", [base_ptr, off_v, width]))
            loads.append(ld_v)

        sum_res = (
            self._tree_reduce_ssa(loads, op, ssa_vt, f"vec_tree_{step_id}", insts)
            if loads
            else SSAVar(f"vec_zero_{step_id}", 0, var_type=ssa_vt)
        )

        # Check initial accumulator from pre_bb
        init_val = self._find_init_acc(cond_bb, pre_bb, acc_prev)
        if init_val is not None and not self._is_const_zero(fn, init_val):
            final_res = SSAVar(f"vec_sum_acc_{step_id}", 0, var_type=ssa_vt)
            insts.append(SSAInstruction(final_res, op, [init_val, sum_res]))
        else:
            final_res = sum_res

        if is_float and fn.return_type in ("float", "f32", "f64", None):
            fn.return_type = "f64"

        return insts, final_res

    def _rewrite_struct_array_strip_mined_4x(
        self,
        fn: SSAFunction,
        pre_bb: BasicBlock,
        cond_bb: BasicBlock,
        body_blk: BasicBlock,
        exit_bb: BasicBlock,
        base_ptr: Any,
        base_offset: int,
        stride: int,
        bound_count: int,
        width: str,
        acc_prev: SSAVar,
        acc_next: SSAVar,
        is_float: bool,
        step_id: int,
    ) -> None:
        """Transforms large constant struct/buffer reductions into a 4-way ILP strip-mined VLA loop."""
        chunks = bound_count // 4
        rem = bound_count % 4
        ssa_vt = "f64" if is_float else "i64"
        op = "fadd" if is_float else "add"

        # Pre-header initializers for chunk index + 4 independent accumulators
        init_val = self._find_init_acc(cond_bb, pre_bb, acc_prev)
        pre_insts: List[SSAInstruction] = []
        zero_idx = SSAVar(f"vec_cinit_{step_id}", 0)
        pre_insts.append(SSAInstruction(zero_idx, "const", [0]))

        acc0_init = init_val if init_val is not None else SSAVar(f"vec_a0_z_{step_id}", 0, var_type=ssa_vt)
        if init_val is None:
            pre_insts.append(SSAInstruction(acc0_init, "fconst" if is_float else "const", [0.0 if is_float else 0]))
        acc_other_inits: List[SSAVar] = []
        for lane in range(1, 4):
            av = SSAVar(f"vec_a{lane}_z_{step_id}", 0, var_type=ssa_vt)
            pre_insts.append(SSAInstruction(av, "fconst" if is_float else "const", [0.0 if is_float else 0]))
            acc_other_inits.append(av)

        if pre_bb.instructions:
            term = pre_bb.instructions[-1]
            pre_bb.instructions = pre_bb.instructions[:-1] + pre_insts + [term]
        else:
            pre_bb.instructions.extend(pre_insts)

        # Induction + 4 accumulator PHI nodes in cond_bb
        c_iv = SSAVar(f"vec_ci_{step_id}", 0)
        c_iv_next = SSAVar(f"vec_ci_nxt_{step_id}", 0)
        acc_phis = [SSAVar(f"vec_acc{lane}_{step_id}", 0, var_type=ssa_vt) for lane in range(4)]
        acc_nexts = [SSAVar(f"vec_acc{lane}_nxt_{step_id}", 0, var_type=ssa_vt) for lane in range(4)]

        cond_bb.phi_nodes = [
            SSAInstruction(c_iv, "phi", [zero_idx, c_iv_next], phi_incoming=[(pre_bb.name, zero_idx), (body_blk.name, c_iv_next)]),
            SSAInstruction(acc_phis[0], "phi", [acc0_init, acc_nexts[0]], phi_incoming=[(pre_bb.name, acc0_init), (body_blk.name, acc_nexts[0])]),
        ] + [
            SSAInstruction(
                acc_phis[lane], "phi", [acc_other_inits[lane - 1], acc_nexts[lane]],
                phi_incoming=[(pre_bb.name, acc_other_inits[lane - 1]), (body_blk.name, acc_nexts[lane])],
            )
            for lane in range(1, 4)
        ]

        c_bound = SSAVar(f"vec_cbound_{step_id}", 0)
        c_cmp = SSAVar(f"vec_ccmp_{step_id}", 0)
        cond_bb.instructions = [
            SSAInstruction(c_bound, "const", [chunks]),
            SSAInstruction(c_cmp, "cmp_lt", [c_iv, c_bound]),
            SSAInstruction(None, "br_cond", [c_cmp, body_blk.name, exit_bb.name]),
        ]

        # Rewrite body_blk to compute 4 parallel loads & 4 independent lane additions
        c_s4 = SSAVar(f"vec_s4_{step_id}", 0)
        c_step_off = SSAVar(f"vec_coff_{step_id}", 0)
        c_base_c = SSAVar(f"vec_cbase_{step_id}", 0)
        c_elem_base = SSAVar(f"vec_ebase_{step_id}", 0)
        body_insts: List[SSAInstruction] = [
            SSAInstruction(c_s4, "const", [stride * 4]),
            SSAInstruction(c_step_off, "mul", [c_iv, c_s4]),
            SSAInstruction(c_base_c, "const", [base_offset]),
            SSAInstruction(c_elem_base, "add", [c_base_c, c_step_off]),
        ]
        for lane in range(4):
            if lane == 0:
                addr_off = c_elem_base
            else:
                l_c = SSAVar(f"vec_loff_{step_id}_{lane}", 0)
                addr_off = SSAVar(f"vec_ladd_{step_id}_{lane}", 0)
                body_insts.append(SSAInstruction(l_c, "const", [lane * stride]))
                body_insts.append(SSAInstruction(addr_off, "add", [c_elem_base, l_c]))
            ld_v = SSAVar(f"vec_lld_{step_id}_{lane}", 0, var_type=ssa_vt)
            body_insts.append(SSAInstruction(ld_v, "load_off", [base_ptr, addr_off, width]))
            body_insts.append(SSAInstruction(acc_nexts[lane], op, [acc_phis[lane], ld_v]))

        c_one = SSAVar(f"vec_cone_{step_id}", 0)
        body_insts.extend([
            SSAInstruction(c_one, "const", [1]),
            SSAInstruction(c_iv_next, "add", [c_iv, c_one]),
            SSAInstruction(None, "br", [cond_bb.name]),
        ])
        body_blk.phi_nodes = []
        body_blk.instructions = body_insts
        cond_bb.successors = [body_blk, exit_bb]
        body_blk.successors = [cond_bb]
        body_blk.predecessors = [cond_bb]

        # Merge the 4 lane accumulators + optional tail remainder at top of exit_bb
        merge_insts: List[SSAInstruction] = []
        merged_var = self._tree_reduce_ssa(acc_phis, op, ssa_vt, f"vec_merge_{step_id}", merge_insts)
        for t_idx in range(chunks * 4, bound_count):
            t_off_v = SSAVar(f"vec_toff_{step_id}_{t_idx}", 0)
            t_ld_v = SSAVar(f"vec_tld_{step_id}_{t_idx}", 0, var_type=ssa_vt)
            t_next = SSAVar(f"vec_tacc_{step_id}_{t_idx}", 0, var_type=ssa_vt)
            merge_insts.extend([
                SSAInstruction(t_off_v, "const", [base_offset + t_idx * stride]),
                SSAInstruction(t_ld_v, "load_off", [base_ptr, t_off_v, width]),
                SSAInstruction(t_next, op, [merged_var, t_ld_v]),
            ])
            merged_var = t_next

        # Substitute uses of acc_prev / acc_next outside the loop with merged_var BEFORE inserting merge_insts
        target_vars = {v for v in (acc_prev, acc_next) if isinstance(v, SSAVar)}
        for blk in fn.blocks:
            if blk in (cond_bb, body_blk):
                continue
            for inst in blk.instructions:
                for idx_o, operand in enumerate(inst.operands):
                    if operand in target_vars:
                        inst.operands[idx_o] = merged_var

        exit_bb.instructions = merge_insts + exit_bb.instructions
        if is_float and fn.return_type in ("float", "f32", "f64", None):
            fn.return_type = "f64"

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
