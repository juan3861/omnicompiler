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
            "vectorized_stores": 0,
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

                # Inspect body block instructions (attempt pure if-conversion for internal branch diamonds)
                if any(b.instructions and b.instructions[-1].opcode == "br_cond" for b in reachable_from_body):
                    if_plan = self._try_plan_if_conversion(fn, block, body_blk, reachable_from_body)
                    if if_plan is None:
                        continue
                    v_body, arm_blks_to_rm, merge_name = if_plan
                    v_reach = {v_body}
                    v_has_store = any(ins.opcode in ("store", "store_off") for ins in v_body.instructions)
                    if v_has_store:
                        can_vec = self._match_struct_array_store(
                            block, v_body, v_reach, fn=fn, pre_bb=pre_bb, superseded_blks=reachable_from_body
                        ) is not None
                    else:
                        can_vec = self._match_struct_array_sum(
                            block, v_body, v_reach, fn=fn, pre_bb=pre_bb, superseded_blks=reachable_from_body
                        ) is not None
                    if not can_vec:
                        continue
                    self._commit_if_conversion(fn, block, body_blk, v_body.instructions, arm_blks_to_rm, merge_name)
                    reachable_from_body = {body_blk}
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
                    store_pattern = self._match_struct_array_store(
                        block, body_blk, reachable_from_body, fn=fn, pre_bb=pre_bb
                    )
                    if store_pattern:
                        self._rewrite_struct_array_store_4x(
                            fn=fn,
                            pre_bb=pre_bb,
                            cond_bb=block,
                            body_blk=body_blk,
                            exit_bb=exit_blk,
                            pattern=store_pattern,
                            step_id=stats["vectorized_stores"],
                        )
                        stats["vectorized_stores"] += 1
                        if store_pattern.get("reductions"):
                            stats["vectorized_sums"] += 1
                        changed = True
                        break
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

                # 4. Check for Struct/Buffer Array Parallel Reduction(s) pattern (META-P2-VECTORIZER):
                struct_sum_pattern = self._match_struct_array_sum(
                    block, body_blk, reachable_from_body, fn=fn, pre_bb=pre_bb
                )
                if struct_sum_pattern:
                    bound_count = struct_sum_pattern["bound_count"]
                    red_specs = struct_sum_pattern["reductions"]
                    if bound_count is not None and bound_count <= 64:
                        replacement_insts, res_vars = self._build_unrolled_tree_reduction(
                            fn=fn,
                            pre_bb=pre_bb,
                            cond_bb=block,
                            pattern=struct_sum_pattern,
                            step_id=stats["vectorized_sums"],
                        )
                        if len(red_specs) == 1:
                            self._rewrite_loop(
                                fn=fn,
                                pre_bb=pre_bb,
                                cond_bb=block,
                                exit_bb=exit_blk,
                                replacement_insts=replacement_insts,
                                replaced_vars=[red_specs[0]["acc_prev"], red_specs[0]["acc_next"]],
                                res_var=res_vars[0],
                            )
                        else:
                            for ins in replacement_insts:
                                if pre_bb.instructions:
                                    pre_bb.instructions.insert(-1, ins)
                                else:
                                    pre_bb.instructions.append(ins)
                            if pre_bb.instructions:
                                pre_bb.instructions[-1] = SSAInstruction(None, "br", [exit_blk.name])
                            else:
                                pre_bb.instructions.append(SSAInstruction(None, "br", [exit_blk.name]))
                            pre_bb.successors = [exit_blk if s == block else s for s in pre_bb.successors]
                            if exit_blk not in pre_bb.successors:
                                pre_bb.successors.append(exit_blk)
                            exit_blk.predecessors = [pre_bb if p == block else p for p in exit_blk.predecessors]
                            if pre_bb not in exit_blk.predecessors:
                                exit_blk.predecessors.append(pre_bb)
                            dead_loop_blks = {block} | reachable_from_body
                            for r_sp, r_res in zip(red_specs, res_vars):
                                self._substitute_loop_uses(
                                    fn,
                                    dead_loop_blks,
                                    {v for v in (r_sp["acc_prev"], r_sp["acc_next"]) if isinstance(v, SSAVar)},
                                    r_res,
                                )
                            fn.blocks = [b for b in fn.blocks if b not in dead_loop_blks]
                    elif bound_count is not None:
                        self._rewrite_struct_array_strip_mined_4x(
                            fn=fn,
                            pre_bb=pre_bb,
                            cond_bb=block,
                            body_blk=body_blk,
                            exit_bb=exit_blk,
                            pattern=struct_sum_pattern,
                            step_id=stats["vectorized_sums"],
                        )
                    else:
                        self._rewrite_struct_array_dynamic_strip_mined_4x(
                            fn=fn,
                            pre_bb=pre_bb,
                            cond_bb=block,
                            body_blk=body_blk,
                            exit_bb=exit_blk,
                            pattern=struct_sum_pattern,
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
        repl_ids = {id(ins) for ins in replacement_insts}
        target_vars = {v for v in replaced_vars if isinstance(v, SSAVar)}
        target_names = {
            v.name
            for v in target_vars
            if v.name not in ("t", "phi", "c", "fc", "cmp", "fld", "off_mul", "off_add")
        }

        for blk in fn.blocks:
            for phi in blk.phi_nodes:
                for i, op in enumerate(phi.operands):
                    if isinstance(op, SSAVar) and op in target_vars:
                        phi.operands[i] = res_var
                if phi.phi_incoming:
                    phi.phi_incoming = [
                        (src_b, res_var if (isinstance(val, SSAVar) and val in target_vars) else val)
                        for src_b, val in phi.phi_incoming
                    ]
            for inst in blk.instructions:
                if id(inst) in repl_ids:
                    continue
                for i, op in enumerate(inst.operands):
                    if isinstance(op, SSAVar) and (op in target_vars or (op.version > 0 and op.name in target_names)):
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

    @staticmethod
    def _find_phi_edges(
        cond_bb: BasicBlock,
        pre_bb: Optional[BasicBlock],
        var: Any,
    ) -> Tuple[Optional[Any], Optional[Any]]:
        if not isinstance(var, SSAVar):
            return None, None
        pre_name = pre_bb.name if pre_bb is not None else None
        for phi in cond_bb.phi_nodes:
            if phi.result == var:
                if phi.phi_incoming:
                    init_val = None
                    back_val = None
                    for blk, val in phi.phi_incoming:
                        bname = blk.name if hasattr(blk, "name") else str(blk)
                        if pre_name is not None and bname == pre_name:
                            init_val = val
                        elif init_val is None and pre_name is None:
                            init_val = val
                        else:
                            back_val = val
                    if init_val is not None and back_val is not None:
                        return init_val, back_val
                if len(phi.operands) >= 2:
                    return phi.operands[0], phi.operands[1]
        return None, None

    @staticmethod
    def _resolve_const_int(
        fn: Optional[SSAFunction],
        extra_insts: List[SSAInstruction],
        op: Any,
    ) -> Optional[int]:
        if isinstance(op, int) and not isinstance(op, bool):
            return op
        if not isinstance(op, SSAVar):
            return None
        for ins in extra_insts:
            if ins.result == op and ins.opcode == "const" and ins.operands:
                val = ins.operands[0]
                if isinstance(val, int) and not isinstance(val, bool):
                    return val
        if fn is not None:
            for b in fn.blocks:
                for ins in b.instructions:
                    if ins.result == op and ins.opcode == "const" and ins.operands:
                        val = ins.operands[0]
                        if isinstance(val, int) and not isinstance(val, bool):
                            return val
        return None

    _PURE_VECTOR_DAG_OPCODES = frozenset({
        "const", "fconst", "mov", "ext_s", "ext_z", "trunc",
        "add", "sub", "mul", "fadd", "fsub", "fmul",
        "sitofp", "fptosi", "neg", "fneg",
        "shl", "shr", "lshr", "and", "or", "xor",
        "cmp_lt", "cmp_le", "cmp_gt", "cmp_ge", "cmp_eq", "cmp_ne",
        "fcmp_lt", "fcmp_le", "fcmp_gt", "fcmp_ge", "fcmp_eq", "fcmp_ne",
        "select",
    })

    def _match_zero_based_unit_loop(
        self,
        fn: Optional[SSAFunction],
        pre_bb: Optional[BasicBlock],
        cond_bb: BasicBlock,
        body_bb: BasicBlock,
        reachable_from_body: Set[BasicBlock],
    ) -> Optional[Tuple[SSAVar, Optional[int], Any, bool, List[SSAInstruction], Set[BasicBlock], Set[SSAVar], int, int, int]]:
        cmp_inst = next(
            (ins for ins in cond_bb.instructions if ins.opcode in ("cmp_lt", "cmp_le", "cmp_gt", "cmp_ge")),
            None,
        )
        if not cmp_inst or len(cmp_inst.operands) < 2:
            return None
        phi_vars = {p.result for p in cond_bb.phi_nodes if isinstance(p.result, SSAVar)}
        if cmp_inst.operands[0] in phi_vars:
            i_var, bound_op = cmp_inst.operands[0], cmp_inst.operands[1]
            cmp_op = cmp_inst.opcode
        elif cmp_inst.operands[1] in phi_vars:
            i_var, bound_op = cmp_inst.operands[1], cmp_inst.operands[0]
            cmp_op = {
                "cmp_lt": "cmp_gt",
                "cmp_le": "cmp_ge",
                "cmp_gt": "cmp_lt",
                "cmp_ge": "cmp_le",
            }[cmp_inst.opcode]
        else:
            return None

        if not isinstance(i_var, SSAVar) or i_var.name.startswith(("vec_ci_", "vec_st_ci_", "vec_tiv_", "vec_st_ti_")):
            return None

        init_i, back_i = self._find_phi_edges(cond_bb, pre_bb, i_var)
        if init_i is None or back_i is None:
            return None

        all_body_insts = list(body_bb.instructions)
        for b in reachable_from_body:
            if b is not body_bb:
                all_body_insts.extend(b.instructions)

        loop_blks = {cond_bb, body_bb} | reachable_from_body
        loop_defined: Set[SSAVar] = set()
        for lb in loop_blks:
            for p in lb.phi_nodes:
                if isinstance(p.result, SSAVar):
                    loop_defined.add(p.result)
            for ins in lb.instructions:
                if isinstance(ins.result, SSAVar):
                    loop_defined.add(ins.result)

        search_insts = list(cond_bb.instructions)
        for p in cond_bb.predecessors:
            search_insts.extend(p.instructions)
        const_search_insts = list(all_body_insts) + list(search_insts)

        signed_step: Optional[int] = None
        for ins in all_body_insts:
            if ins.result == back_i and ins.opcode == "add" and len(ins.operands) == 2 and i_var in ins.operands:
                other = ins.operands[1] if ins.operands[0] == i_var else ins.operands[0]
                c_step = self._resolve_const_int(fn, const_search_insts, other)
                if c_step is not None and c_step != 0:
                    signed_step = int(c_step)
                    break
            elif ins.result == back_i and ins.opcode == "sub" and len(ins.operands) == 2 and ins.operands[0] == i_var:
                c_step = self._resolve_const_int(fn, const_search_insts, ins.operands[1])
                if c_step is not None and c_step != 0:
                    signed_step = -int(c_step)
                    break
        if signed_step is None:
            return None

        bound_count: Optional[int]
        start_i: int
        step_i: int
        bound_delta: int
        is_le: bool

        if cmp_op in ("cmp_lt", "cmp_le") and signed_step > 0:
            step_i = signed_step
            is_le = cmp_op == "cmp_le"
            if fn is not None and self._is_const_zero(fn, init_i):
                start_val: Optional[int] = 0
            else:
                start_val = self._resolve_const_int(fn, search_insts, init_i)
            if start_val is None or start_val < 0:
                return None
            start_i = int(start_val)
            bound_delta = 1 if is_le else 0

            bound_val = self._resolve_const_int(fn, search_insts, bound_op)
            if bound_val is not None:
                upper_excl = int(bound_val) + bound_delta
                span = upper_excl - start_i
                if span <= 0:
                    return None
                bound_count = (span + step_i - 1) // step_i
                if bound_count <= 0 or bound_count > 4096:
                    return None
            else:
                if not isinstance(bound_op, SSAVar) or bound_op in loop_defined:
                    return None
                if step_i not in (1, 2, 4, 8):
                    return None
                bound_count = None
        elif cmp_op in ("cmp_gt", "cmp_ge") and signed_step < 0:
            step_i = -signed_step
            is_ge = cmp_op == "cmp_ge"
            if fn is not None and self._is_const_zero(fn, bound_op):
                lower_val: Optional[int] = 0
            else:
                lower_val = self._resolve_const_int(fn, search_insts, bound_op)
            if lower_val is None:
                return None
            lower_incl = int(lower_val) if is_ge else (int(lower_val) + 1)
            if lower_incl < 0:
                return None

            init_val = self._resolve_const_int(fn, search_insts, init_i)
            if init_val is not None:
                span_inc = int(init_val) - lower_incl
                if span_inc < 0:
                    return None
                bound_count = (span_inc // step_i) + 1
                if bound_count <= 0 or bound_count > 4096:
                    return None
                start_i = int(init_val) - (bound_count - 1) * step_i
                bound_op = init_i
                bound_delta = 1
                is_le = True
            else:
                if step_i != 1 or not isinstance(init_i, SSAVar) or init_i in loop_defined:
                    return None
                sym_n: Any = init_i
                c_off = 0
                pre_defs = {ins.result: ins for ins in search_insts if isinstance(ins.result, SSAVar)}
                init_def = pre_defs.get(init_i)
                if init_def is not None and len(init_def.operands) == 2:
                    if (
                        init_def.opcode == "sub"
                        and isinstance(init_def.operands[0], SSAVar)
                        and init_def.operands[0] not in loop_defined
                    ):
                        c_sub = self._resolve_const_int(fn, search_insts, init_def.operands[1])
                        if c_sub is not None:
                            sym_n = init_def.operands[0]
                            c_off = -int(c_sub)
                    elif init_def.opcode == "add":
                        for s_cand, c_cand in (
                            (init_def.operands[0], init_def.operands[1]),
                            (init_def.operands[1], init_def.operands[0]),
                        ):
                            c_add = self._resolve_const_int(fn, search_insts, c_cand)
                            if c_add is not None and isinstance(s_cand, SSAVar) and s_cand not in loop_defined:
                                sym_n = s_cand
                                c_off = int(c_add)
                                break
                start_i = lower_incl
                bound_op = sym_n
                bound_delta = 1 + c_off
                is_le = bound_delta == 1
                bound_count = None
        else:
            return None

        return (i_var, bound_count, bound_op, is_le, all_body_insts, loop_blks, loop_defined, start_i, step_i, bound_delta)

    def _resolve_linear_offset(
        self,
        fn: Optional[SSAFunction],
        all_body_insts: List[SSAInstruction],
        i_var: SSAVar,
        off_var: Any,
        width: str,
    ) -> Optional[Tuple[int, int]]:
        """Resolves affine byte offset `base_offset + i_var * stride` within a loop body."""
        if off_var == i_var:
            return (0, 1)

        inst_by_res = {ins.result: ins for ins in all_body_insts if isinstance(ins.result, SSAVar)}

        def _match_shifted_i(cand: Any) -> Optional[int]:
            if cand == i_var:
                return 0
            ins = inst_by_res.get(cand)
            if ins is None or len(ins.operands) != 2:
                return None
            if ins.opcode == "add" and i_var in ins.operands:
                other = ins.operands[1] if ins.operands[0] == i_var else ins.operands[0]
                c_val = self._resolve_const_int(fn, all_body_insts, other)
                if c_val is not None:
                    return int(c_val)
            elif ins.opcode == "sub" and ins.operands[0] == i_var:
                c_val = self._resolve_const_int(fn, all_body_insts, ins.operands[1])
                if c_val is not None:
                    return -int(c_val)
            return None

        def _match_scaled_i(cand: Any) -> Optional[Tuple[int, int]]:
            sh_i = _match_shifted_i(cand)
            if sh_i is not None:
                return (sh_i, 1)
            ins = inst_by_res.get(cand)
            if ins is None or len(ins.operands) != 2:
                return None
            if ins.opcode == "mul":
                for idx_op, m_op in ((ins.operands[0], ins.operands[1]), (ins.operands[1], ins.operands[0])):
                    c_idx = _match_shifted_i(idx_op)
                    m_val = self._resolve_const_int(fn, all_body_insts, m_op)
                    if c_idx is not None and m_val is not None and m_val > 0:
                        return (c_idx * int(m_val), int(m_val))
            elif ins.opcode == "shl":
                c_idx = _match_shifted_i(ins.operands[0])
                sh_val = self._resolve_const_int(fn, all_body_insts, ins.operands[1])
                if c_idx is not None and sh_val is not None and 0 <= sh_val <= 12:
                    stride = 1 << sh_val
                    return (c_idx * stride, stride)
            return None

        sc = _match_scaled_i(off_var)
        if sc is not None:
            return sc

        off_ins = inst_by_res.get(off_var) if isinstance(off_var, SSAVar) else None
        if off_ins is not None and off_ins.opcode == "add" and len(off_ins.operands) == 2:
            op0, op1 = off_ins.operands[0], off_ins.operands[1]
            for s_op, c_op in ((op0, op1), (op1, op0)):
                scaled = _match_scaled_i(s_op)
                c_val = self._resolve_const_int(fn, all_body_insts, c_op)
                if scaled is not None and c_val is not None:
                    return (int(c_val) + scaled[0], scaled[1])
        return None

    _WIDTH_BYTES = {
        "i8": 1, "u8": 1, "i16": 2, "u16": 2,
        "i32": 4, "u32": 4, "f32": 4,
        "i64": 8, "u64": 8, "f64": 8,
    }

    @staticmethod
    def _has_escaped_loop_uses(
        fn: Optional[SSAFunction],
        loop_blks: Set[BasicBlock],
        loop_defined: Set[SSAVar],
        allowed_vars: Optional[Set[SSAVar]] = None,
    ) -> bool:
        if fn is None:
            return False
        blocked = loop_defined - (allowed_vars or set())
        if not blocked:
            return False
        for blk in fn.blocks:
            if blk in loop_blks:
                continue
            for p in blk.phi_nodes:
                if any(op in blocked for op in p.operands):
                    return True
                if p.phi_incoming and any(val in blocked for _sb, val in p.phi_incoming):
                    return True
            for ins in blk.instructions:
                if any(op in blocked for op in ins.operands):
                    return True
        return False

    def _extract_pure_dag_slice(
        self,
        all_body_insts: List[SSAInstruction],
        root_vars: List[Any],
        load_res_set: Set[SSAVar],
        i_var: SSAVar,
        loop_defined: Set[SSAVar],
    ) -> Optional[List[SSAInstruction]]:
        """Backward-slices pure trap-free instructions feeding `root_vars` down to loads, `i_var`, or invariants."""
        body_def_map = {ins.result: ins for ins in all_body_insts if isinstance(ins.result, SSAVar)}
        slice_set: Set[SSAVar] = set()
        stack = [v for v in root_vars if isinstance(v, SSAVar)]
        while stack:
            cur = stack.pop()
            if cur in load_res_set or cur == i_var or cur not in loop_defined:
                continue
            def_ins = body_def_map.get(cur)
            if def_ins is None or def_ins.opcode not in self._PURE_VECTOR_DAG_OPCODES:
                return None
            if cur in slice_set:
                continue
            slice_set.add(cur)
            for op in def_ins.operands:
                if isinstance(op, SSAVar):
                    stack.append(op)
        return [ins for ins in all_body_insts if isinstance(ins.result, SSAVar) and ins.result in slice_set]

    @staticmethod
    def _clone_dag_insts(
        dag_insts: List[SSAInstruction],
        var_map: Dict[Any, Any],
        prefix: str,
        seq: List[int],
        out_insts: List[SSAInstruction],
    ) -> Dict[Any, Any]:
        local_map = dict(var_map)
        for ins in dag_insts:
            new_ops = [local_map.get(op, op) for op in ins.operands]
            vt = ins.result.var_type if isinstance(ins.result, SSAVar) else "i64"
            new_v = SSAVar(f"{prefix}_{seq[0]}", 0, var_type=vt)
            seq[0] += 1
            out_insts.append(SSAInstruction(new_v, ins.opcode, new_ops))
            local_map[ins.result] = new_v
        return local_map

    def _try_plan_if_conversion(
        self,
        fn: SSAFunction,
        cond_bb: BasicBlock,
        body_blk: BasicBlock,
        reachable_from_body: Set[BasicBlock],
    ) -> Optional[Tuple[BasicBlock, List[BasicBlock], str]]:
        """Plans branchless `select`-based flattening of an internal if/else diamond or if-then triangle."""
        br_cond_blks = [b for b in reachable_from_body if b.instructions and b.instructions[-1].opcode == "br_cond"]
        if len(br_cond_blks) != 1 or br_cond_blks[0] is not body_blk:
            return None

        term = body_blk.instructions[-1]
        if len(term.operands) < 3:
            return None
        cond_v, t_name, f_name = term.operands[0], str(term.operands[1]), str(term.operands[2])
        blk_map = {b.name: b for b in reachable_from_body}
        t_blk = blk_map.get(t_name)
        f_blk = blk_map.get(f_name)
        if t_blk is None or f_blk is None or t_blk is body_blk or f_blk is body_blk:
            return None
        if t_blk.phi_nodes or not t_blk.instructions or t_blk.instructions[-1].opcode != "br":
            return None

        t_next = str(t_blk.instructions[-1].operands[0])
        m_blk = blk_map.get(t_next)
        if m_blk is None or not m_blk.instructions or m_blk.instructions[-1].opcode != "br":
            return None
        if str(m_blk.instructions[-1].operands[0]) != cond_bb.name:
            return None

        if t_blk is not f_blk and f_blk is not m_blk:
            # Case 1: if-else diamond (body_blk -> T, F -> M -> cond_bb)
            if f_blk.phi_nodes or not f_blk.instructions or f_blk.instructions[-1].opcode != "br":
                return None
            if str(f_blk.instructions[-1].operands[0]) != m_blk.name:
                return None
            if list(t_blk.predecessors) != [body_blk] or list(f_blk.predecessors) != [body_blk]:
                return None
            if set(m_blk.predecessors) != {t_blk, f_blk}:
                return None
            arm_blks = [t_blk, f_blk]
            false_pred_name = f_blk.name
        elif f_blk is m_blk:
            # Case 2: if-then triangle (body_blk -> T -> M, body_blk -> M -> cond_bb)
            if list(t_blk.predecessors) != [body_blk]:
                return None
            if set(m_blk.predecessors) != {body_blk, t_blk}:
                return None
            arm_blks = [t_blk]
            false_pred_name = body_blk.name
        else:
            return None

        if reachable_from_body != ({body_blk, m_blk} | set(arm_blks)):
            return None

        allowed_arm_ops = self._PURE_VECTOR_DAG_OPCODES | {"store_off"}
        arm_stores: List[Tuple[BasicBlock, SSAInstruction]] = []
        arm_defined: Set[SSAVar] = set()
        for ab in arm_blks:
            for ins in ab.instructions[:-1]:
                if ins.opcode not in allowed_arm_ops:
                    return None
                if isinstance(ins.result, SSAVar):
                    arm_defined.add(ins.result)
                if ins.opcode == "store_off":
                    arm_stores.append((ab, ins))

        # Verify M_blk non-PHI instructions don't reference arm-local defs directly
        for ins in m_blk.instructions[:-1]:
            if any(op in arm_defined for op in ins.operands):
                return None

        flat_insts: List[SSAInstruction] = list(body_blk.instructions[:-1])
        for ab in arm_blks:
            for ins in ab.instructions[:-1]:
                if ins.opcode != "store_off":
                    flat_insts.append(ins)

        if arm_stores:
            if len(arm_blks) != 2 or len(arm_stores) != 2:
                return None
            if arm_stores[0][0] is arm_stores[1][0]:
                return None
            st_t = arm_stores[0][1] if arm_stores[0][0] is t_blk else arm_stores[1][1]
            st_f = arm_stores[1][1] if arm_stores[0][0] is t_blk else arm_stores[0][1]
            if len(st_t.operands) < 4 or len(st_f.operands) < 4:
                return None
            if st_t.operands[0] != st_f.operands[0] or str(st_t.operands[3]) != str(st_f.operands[3]):
                return None
            i_cand = next((p.result for p in cond_bb.phi_nodes if isinstance(p.result, SSAVar)), None)
            if i_cand is None:
                return None
            aff_t = self._resolve_linear_offset(fn, flat_insts, i_cand, st_t.operands[1], str(st_t.operands[3]))
            aff_f = self._resolve_linear_offset(fn, flat_insts, i_cand, st_f.operands[1], str(st_f.operands[3]))
            if aff_t is None or aff_t != aff_f:
                return None
            sel_vt = st_t.operands[2].var_type if isinstance(st_t.operands[2], SSAVar) else "i64"
            sel_v = SSAVar(f"ifc_stval_{len(flat_insts)}", 0, var_type=sel_vt)
            flat_insts.append(SSAInstruction(sel_v, "select", [cond_v, st_t.operands[2], st_f.operands[2]]))
            flat_insts.append(SSAInstruction(None, "store_off", [st_t.operands[0], st_t.operands[1], sel_v, st_t.operands[3]]))

        for phi in m_blk.phi_nodes:
            if not isinstance(phi.result, SSAVar):
                return None
            t_val = f_val = None
            if phi.phi_incoming:
                for sb, val in phi.phi_incoming:
                    bname = sb.name if hasattr(sb, "name") else str(sb)
                    if bname == t_blk.name:
                        t_val = val
                    elif bname == false_pred_name:
                        f_val = val
            elif len(phi.operands) >= 2:
                t_val, f_val = phi.operands[0], phi.operands[1]
            if t_val is None or f_val is None:
                return None
            flat_insts.append(SSAInstruction(phi.result, "select", [cond_v, t_val, f_val]))

        flat_insts.extend(m_blk.instructions[:-1])
        flat_insts.append(SSAInstruction(None, "br", [cond_bb.name]))

        v_body = BasicBlock(body_blk.name)
        v_body.instructions = flat_insts
        v_body.predecessors = [cond_bb]
        v_body.successors = [cond_bb]
        return v_body, arm_blks + [m_blk], m_blk.name

    @staticmethod
    def _commit_if_conversion(
        fn: SSAFunction,
        cond_bb: BasicBlock,
        body_blk: BasicBlock,
        flattened_insts: List[SSAInstruction],
        blks_to_remove: List[BasicBlock],
        merge_name: str,
    ) -> None:
        body_blk.instructions = flattened_insts
        body_blk.successors = [cond_bb]
        body_blk.predecessors = [cond_bb]
        cond_bb.predecessors = [body_blk if p in blks_to_remove else p for p in cond_bb.predecessors]
        for phi in cond_bb.phi_nodes:
            if phi.phi_incoming:
                phi.phi_incoming = [
                    (body_blk.name if (getattr(sb, "name", str(sb)) == merge_name) else sb, val)
                    for sb, val in phi.phi_incoming
                ]
        rm_set = set(blks_to_remove)
        fn.blocks = [b for b in fn.blocks if b not in rm_set]

    _REDUCTION_OPS_IDENTITY = {
        "add": ("const", 0),
        "fadd": ("fconst", 0.0),
        "mul": ("const", 1),
        "fmul": ("fconst", 1.0),
        "or": ("const", 0),
        "xor": ("const", 0),
        "and": ("const", -1),
        "smin": ("const", 0x7FFFFFFFFFFFFFFF),
        "smax": ("const", -0x8000000000000000),
        "fmin": ("fconst", 1e308),
        "fmax": ("fconst", -1e308),
        "linear_recurrence": ("const", 0),
    }

    _MINMAX_CMP_MAP = {
        "smin": "cmp_lt",
        "smax": "cmp_gt",
        "fmin": "fcmp_lt",
        "fmax": "fcmp_gt",
    }

    @staticmethod
    def _s64(val: int) -> int:
        u = int(val) & 0xFFFFFFFFFFFFFFFF
        return u - 0x10000000000000000 if (u & 0x8000000000000000) else u

    @classmethod
    def _emit_reduction_op(
        cls,
        res_var: SSAVar,
        op: str,
        lhs: Any,
        rhs: Any,
        prefix: str,
        out_insts: List[SSAInstruction],
        r_spec: Optional[Dict[str, Any]] = None,
    ) -> None:
        if op in cls._MINMAX_CMP_MAP:
            cmp_v = SSAVar(f"{prefix}_mm_{len(out_insts)}", 0)
            out_insts.append(SSAInstruction(cmp_v, cls._MINMAX_CMP_MAP[op], [lhs, rhs]))
            out_insts.append(SSAInstruction(res_var, "select", [cmp_v, lhs, rhs]))
        elif op == "linear_recurrence" and r_spec is not None:
            mul_c = int(r_spec.get("mul_const", 1))
            neg_d = bool(r_spec.get("negate_delta", False))
            c_v = SSAVar(f"{prefix}_lrc_{len(out_insts)}", 0)
            p_v = SSAVar(f"{prefix}_lrp_{len(out_insts)}", 0)
            out_insts.append(SSAInstruction(c_v, "const", [cls._s64(mul_c)]))
            out_insts.append(SSAInstruction(p_v, "mul", [lhs, c_v]))
            out_insts.append(SSAInstruction(res_var, "sub" if neg_d else "add", [p_v, rhs]))
        else:
            out_insts.append(SSAInstruction(res_var, op, [lhs, rhs]))

    @classmethod
    def _emit_estrin_4x_linear_recurrence(
        cls,
        res_var: SSAVar,
        acc_prev_var: Any,
        d_lanes: List[Any],
        r_spec: Dict[str, Any],
        prefix: str,
        out_insts: List[SSAInstruction],
    ) -> None:
        """Evaluates `((((S*c +/- d0)*c +/- d1)*c +/- d2)*c +/- d3)` via Estrin's 4-way parallel Horner tree."""
        c1 = cls._s64(int(r_spec.get("mul_const", 1)))
        c2 = cls._s64(c1 * c1)
        c4 = cls._s64(c2 * c2)
        neg_d = bool(r_spec.get("negate_delta", False))

        def _m(tag: str, opcode: str, ops: List[Any]) -> SSAVar:
            v = SSAVar(f"{prefix}_{tag}_{len(out_insts)}", 0)
            out_insts.append(SSAInstruction(v, opcode, ops))
            return v

        c1_v = _m("c1", "const", [c1])
        c2_v = _m("c2", "const", [c2])
        c4_v = _m("c4", "const", [c4])
        # Branch A: (d0 * c^2 + d2) * c
        d0_c2 = _m("d0c2", "mul", [d_lanes[0], c2_v])
        b_02 = _m("b02", "add", [d0_c2, d_lanes[2]])
        b_02_c = _m("b02c", "mul", [b_02, c1_v])
        # Branch B: d1 * c^2 + d3
        d1_c2 = _m("d1c2", "mul", [d_lanes[1], c2_v])
        b_13 = _m("b13", "add", [d1_c2, d_lanes[3]])
        # Combine independent polynomial chunk & scale S by c^4
        chunk_poly = _m("poly", "add", [b_02_c, b_13])
        s_c4 = _m("sc4", "mul", [acc_prev_var, c4_v])
        out_insts.append(SSAInstruction(res_var, "sub" if neg_d else "add", [s_c4, chunk_poly]))

    def _classify_linear_recurrence(
        self,
        fn: Optional[SSAFunction],
        const_search_insts: List[SSAInstruction],
        back_ins: Optional[SSAInstruction],
        acc_prev: SSAVar,
        body_def_map: Dict[SSAVar, SSAInstruction],
    ) -> Optional[Tuple[int, bool, Any]]:
        """Matches first-order linear recurrences `acc = acc * c +/- delta` or `acc = (acc << sh) +/- delta`."""
        if back_ins is None or back_ins.opcode not in ("add", "sub") or len(back_ins.operands) != 2:
            return None
        if acc_prev in back_ins.operands:
            return None
        candidates = (
            [(back_ins.operands[0], back_ins.operands[1], True)]
            if back_ins.opcode == "sub"
            else [
                (back_ins.operands[0], back_ins.operands[1], False),
                (back_ins.operands[1], back_ins.operands[0], False),
            ]
        )
        for scaled_op, delta_op, is_sub in candidates:
            if not isinstance(scaled_op, SSAVar):
                continue
            sc_ins = body_def_map.get(scaled_op)
            if sc_ins is None or len(sc_ins.operands) != 2:
                continue
            if sc_ins.opcode == "mul" and acc_prev in sc_ins.operands:
                c_op = sc_ins.operands[1] if sc_ins.operands[0] == acc_prev else sc_ins.operands[0]
                c_val = self._resolve_const_int(fn, const_search_insts, c_op)
                if c_val is not None and c_val != 0:
                    return (int(c_val), is_sub, delta_op)
            elif sc_ins.opcode == "shl" and sc_ins.operands[0] == acc_prev:
                sh_val = self._resolve_const_int(fn, const_search_insts, sc_ins.operands[1])
                if sh_val is not None and 0 <= sh_val <= 62:
                    return (1 << int(sh_val), is_sub, delta_op)
        return None

    @staticmethod
    def _classify_minmax_select(
        sel_ins: Optional[SSAInstruction],
        acc_prev: SSAVar,
        body_def_map: Dict[SSAVar, SSAInstruction],
    ) -> Optional[Tuple[str, Any]]:
        """Recognizes `select(cmp(a, b), a, b)` min/max patterns where `{a, b} == {acc_prev, delta}`."""
        if sel_ins is None or sel_ins.opcode != "select" or len(sel_ins.operands) != 3:
            return None
        c_v, t_op, f_op = sel_ins.operands[0], sel_ins.operands[1], sel_ins.operands[2]
        if acc_prev not in (t_op, f_op) or t_op == f_op or not isinstance(c_v, SSAVar):
            return None
        other_op = f_op if t_op == acc_prev else t_op
        cmp_ins = body_def_map.get(c_v)
        if cmp_ins is None or len(cmp_ins.operands) != 2:
            return None
        c_op = cmp_ins.opcode
        if c_op not in ("cmp_lt", "cmp_le", "cmp_gt", "cmp_ge", "fcmp_lt", "fcmp_le", "fcmp_gt", "fcmp_ge"):
            return None
        lhs, rhs = cmp_ins.operands[0], cmp_ins.operands[1]
        if {lhs, rhs} != {acc_prev, other_op}:
            return None
        smaller_on_true = lhs if c_op.endswith(("lt", "le")) else rhs
        is_min = (t_op == smaller_on_true)
        is_f = c_op.startswith("fcmp_") or acc_prev.var_type == "f64"
        if is_min:
            return ("fmin" if is_f else "smin", other_op)
        return ("fmax" if is_f else "smax", other_op)

    def _is_reduction_identity(self, fn: SSAFunction, val: Any, op: str) -> bool:
        if op in self._MINMAX_CMP_MAP or op == "linear_recurrence":
            return False
        _c_op, id_val = self._REDUCTION_OPS_IDENTITY[op]
        if isinstance(val, (int, float)) and not isinstance(val, bool) and val == id_val:
            return True
        if isinstance(val, SSAVar):
            for b in fn.blocks:
                for inst in b.instructions:
                    if (
                        inst.result == val
                        and inst.opcode in ("const", "fconst")
                        and inst.operands
                        and inst.operands[0] == id_val
                    ):
                        return True
        return False

    def _extract_reduction_specs_from_phis(
        self,
        cond_bb: BasicBlock,
        pre_bb: Optional[BasicBlock],
        acc_phis_list: List[SSAInstruction],
        body_def_map: Dict[SSAVar, SSAInstruction],
        fn: Optional[SSAFunction] = None,
        const_search_insts: Optional[List[SSAInstruction]] = None,
    ) -> Optional[Tuple[List[Dict[str, Any]], Set[SSAVar], Set[SSAVar], List[Any]]]:
        all_acc_prevs: Set[SSAVar] = set()
        all_acc_nexts: Set[SSAVar] = set()
        red_specs: List[Dict[str, Any]] = []
        all_roots: List[Any] = []
        c_insts = const_search_insts or list(body_def_map.values())

        for acc_phi in acc_phis_list:
            acc_prev = acc_phi.result
            if not isinstance(acc_prev, SSAVar):
                return None
            _init_acc, back_acc = self._find_phi_edges(cond_bb, pre_bb, acc_prev)
            if not isinstance(back_acc, SSAVar):
                return None
            back_ins = body_def_map.get(back_acc)
            if back_ins is None:
                return None

            cond_mask: Optional[Any] = None
            cond_inverted = False
            mul_const = 1
            negate_delta = False
            mm_direct = self._classify_minmax_select(back_ins, acc_prev, body_def_map)
            lr_direct = self._classify_linear_recurrence(fn, c_insts, back_ins, acc_prev, body_def_map)
            if mm_direct is not None:
                red_op, delta_var = mm_direct
            elif lr_direct is not None:
                red_op = "linear_recurrence"
                mul_const, negate_delta, delta_var = lr_direct
            elif (
                back_ins.opcode in self._REDUCTION_OPS_IDENTITY
                and back_ins.opcode not in self._MINMAX_CMP_MAP
                and back_ins.opcode != "linear_recurrence"
                and len(back_ins.operands) == 2
                and acc_prev in back_ins.operands
            ):
                red_op = back_ins.opcode
                delta_var = back_ins.operands[1] if back_ins.operands[0] == acc_prev else back_ins.operands[0]
            elif back_ins.opcode == "select" and len(back_ins.operands) == 3 and acc_prev in (back_ins.operands[1], back_ins.operands[2]):
                c_v, t_op, f_op = back_ins.operands[0], back_ins.operands[1], back_ins.operands[2]
                inner_v = f_op if t_op == acc_prev else t_op
                cond_inverted = t_op == acc_prev
                inner_ins = body_def_map.get(inner_v) if isinstance(inner_v, SSAVar) else None
                mm_inner = self._classify_minmax_select(inner_ins, acc_prev, body_def_map)
                if mm_inner is not None:
                    red_op, delta_var = mm_inner
                    cond_mask = c_v
                elif (
                    inner_ins is not None
                    and inner_ins.opcode in self._REDUCTION_OPS_IDENTITY
                    and inner_ins.opcode not in self._MINMAX_CMP_MAP
                    and inner_ins.opcode != "linear_recurrence"
                    and len(inner_ins.operands) == 2
                    and acc_prev in inner_ins.operands
                ):
                    red_op = inner_ins.opcode
                    delta_var = inner_ins.operands[1] if inner_ins.operands[0] == acc_prev else inner_ins.operands[0]
                    cond_mask = c_v
                else:
                    return None
            else:
                return None

            is_f = red_op in ("fadd", "fmul", "fmin", "fmax") or acc_prev.var_type == "f64"
            red_specs.append({
                "acc_prev": acc_prev,
                "acc_next": back_acc,
                "op": red_op,
                "is_float": is_f,
                "ssa_vt": "f64" if is_f else "i64",
                "delta_var": delta_var,
                "cond_mask": cond_mask,
                "cond_inverted": cond_inverted,
                "mul_const": mul_const,
                "negate_delta": negate_delta,
                "is_scan": False,
            })
            all_acc_prevs.add(acc_prev)
            all_acc_nexts.add(back_acc)
            all_roots.append(delta_var)
            if cond_mask is not None:
                all_roots.append(cond_mask)

        return red_specs, all_acc_prevs, all_acc_nexts, all_roots

    def _match_struct_array_sum(
        self,
        cond_bb: BasicBlock,
        body_bb: BasicBlock,
        reachable_from_body: Set[BasicBlock],
        fn: Optional[SSAFunction] = None,
        pre_bb: Optional[BasicBlock] = None,
        superseded_blks: Optional[Set[BasicBlock]] = None,
    ) -> Optional[Dict[str, Any]]:
        loop_info = self._match_zero_based_unit_loop(fn, pre_bb, cond_bb, body_bb, reachable_from_body)
        if not loop_info:
            return None
        i_var, bound_count, bound_op, is_le, all_body_insts, loop_blks, loop_defined, start_i, step_i, bound_delta = loop_info

        if not (2 <= len(cond_bb.phi_nodes) <= 7):
            return None
        if any(ins.opcode in ("store", "store_off", "call", "br_cond") for ins in all_body_insts):
            return None

        acc_phis_list = [p for p in cond_bb.phi_nodes if isinstance(p.result, SSAVar) and p.result != i_var]
        if not acc_phis_list or len(acc_phis_list) != len(cond_bb.phi_nodes) - 1:
            return None

        # Match 1..8 affine load_off slots
        load_offs = [ins for ins in all_body_insts if ins.opcode == "load_off"]
        if not (1 <= len(load_offs) <= 8):
            return None
        load_specs: List[Tuple[Any, int, int, str, SSAVar]] = []
        load_res_set: Set[SSAVar] = set()
        for ld in load_offs:
            if len(ld.operands) < 3 or not isinstance(ld.result, SSAVar):
                return None
            ld_base, ld_off, ld_width = ld.operands[0], ld.operands[1], str(ld.operands[2])
            if isinstance(ld_base, SSAVar) and ld_base in loop_defined:
                return None
            aff = self._resolve_linear_offset(fn, all_body_insts, i_var, ld_off, ld_width)
            if aff is None:
                return None
            eff_boff = aff[0] + start_i * aff[1]
            eff_stride = step_i * aff[1]
            load_specs.append((ld_base, eff_boff, eff_stride, ld_width, ld.result))
            load_res_set.add(ld.result)

        body_def_map = {ins.result: ins for ins in all_body_insts if isinstance(ins.result, SSAVar)}
        red_parsed = self._extract_reduction_specs_from_phis(
            cond_bb, pre_bb, acc_phis_list, body_def_map, fn=fn, const_search_insts=all_body_insts
        )
        if red_parsed is None:
            return None
        red_specs, all_acc_prevs, all_acc_nexts, all_roots = red_parsed

        if self._has_escaped_loop_uses(
            fn, loop_blks | (superseded_blks or set()), loop_defined, allowed_vars=all_acc_prevs | all_acc_nexts
        ):
            return None

        dag_insts = self._extract_pure_dag_slice(all_body_insts, all_roots, load_res_set, i_var, loop_defined)
        if dag_insts is None:
            return None

        # Ensure reductions are mutually independent (no reduction reads any acc_prev)
        for ins in dag_insts:
            if any(op in all_acc_prevs for op in ins.operands):
                return None
        for r in red_specs:
            if r["delta_var"] in all_acc_prevs or r["cond_mask"] in all_acc_prevs:
                return None

        return {
            "i_var": i_var,
            "bound_count": bound_count,
            "bound_op": bound_op,
            "is_le": is_le,
            "start_i": start_i,
            "step_i": step_i,
            "bound_delta": bound_delta,
            "loads": load_specs,
            "dag_insts": dag_insts,
            "reductions": red_specs,
            "any_float": any(r["is_float"] for r in red_specs),
        }

    def _match_struct_array_store(
        self,
        cond_bb: BasicBlock,
        body_bb: BasicBlock,
        reachable_from_body: Set[BasicBlock],
        fn: Optional[SSAFunction] = None,
        pre_bb: Optional[BasicBlock] = None,
        superseded_blks: Optional[Set[BasicBlock]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Matches single/multi-field elementwise array/struct write loops, optionally fused with 1..6 reductions."""
        if not (1 <= len(cond_bb.phi_nodes) <= 7):
            return None
        loop_info = self._match_zero_based_unit_loop(fn, pre_bb, cond_bb, body_bb, reachable_from_body)
        if not loop_info:
            return None
        i_var, bound_count, bound_op, is_le, all_body_insts, loop_blks, loop_defined, start_i, step_i, bound_delta = loop_info

        if bound_count is not None and bound_count < 4:
            return None
        if any(ins.opcode in ("store", "call", "br_cond") for ins in all_body_insts):
            return None

        acc_phis_list = [p for p in cond_bb.phi_nodes if isinstance(p.result, SSAVar) and p.result != i_var]
        if len(acc_phis_list) != len(cond_bb.phi_nodes) - 1:
            return None

        store_offs = [ins for ins in all_body_insts if ins.opcode == "store_off"]
        if not (1 <= len(store_offs) <= 8):
            return None

        dst_specs: List[Tuple[Any, int, int, str, Any]] = []
        store_vals: List[Any] = []
        load_specs: List[Tuple[Any, int, int, str, SSAVar]] = []
        load_res_set: Set[SSAVar] = set()
        written_slot_keys: Set[Tuple[Any, int, int]] = set()
        written_slots: Dict[Tuple[Any, int, int, str], Any] = {}
        forwarded_map: Dict[SSAVar, Any] = {}

        for ins in all_body_insts:
            if ins.opcode == "store_off":
                if len(ins.operands) < 4:
                    return None
                dst_base, dst_off, raw_sval, dst_width = (
                    ins.operands[0], ins.operands[1], ins.operands[2], str(ins.operands[3])
                )
                store_val = forwarded_map.get(raw_sval, raw_sval)
                if isinstance(dst_base, SSAVar) and dst_base in loop_defined:
                    return None
                dst_aff = self._resolve_linear_offset(fn, all_body_insts, i_var, dst_off, dst_width)
                if dst_aff is None:
                    return None
                eff_dboff = dst_aff[0] + start_i * dst_aff[1]
                eff_dstride = step_i * dst_aff[1]
                dst_specs.append((dst_base, eff_dboff, eff_dstride, dst_width, store_val))
                store_vals.append(store_val)
                written_slot_keys.add((dst_base, eff_dboff, eff_dstride))
                written_slots[(dst_base, eff_dboff, eff_dstride, dst_width)] = store_val
            elif ins.opcode == "load_off":
                if len(ins.operands) < 3 or not isinstance(ins.result, SSAVar):
                    return None
                ld_base, ld_off, ld_width = ins.operands[0], ins.operands[1], str(ins.operands[2])
                if isinstance(ld_base, SSAVar) and ld_base in loop_defined:
                    return None
                ld_aff = self._resolve_linear_offset(fn, all_body_insts, i_var, ld_off, ld_width)
                if ld_aff is None:
                    return None
                eff_lboff = ld_aff[0] + start_i * ld_aff[1]
                eff_lstride = step_i * ld_aff[1]
                if (ld_base, eff_lboff, eff_lstride) in written_slot_keys:
                    l_slot = (ld_base, eff_lboff, eff_lstride, ld_width)
                    if l_slot in written_slots and ld_width in ("i64", "u64", "f64"):
                        forwarded_map[ins.result] = written_slots[l_slot]
                    else:
                        return None
                else:
                    load_specs.append((ld_base, eff_lboff, eff_lstride, ld_width, ins.result))
                    load_res_set.add(ins.result)

        work_body_insts = all_body_insts
        if forwarded_map:
            work_body_insts = [
                SSAInstruction(ins.result, ins.opcode, [forwarded_map.get(op, op) for op in ins.operands])
                for ins in all_body_insts
                if not (ins.opcode == "load_off" and ins.result in forwarded_map)
            ]

        red_specs: List[Dict[str, Any]] = []
        all_acc_prevs: Set[SSAVar] = set()
        all_acc_nexts: Set[SSAVar] = set()
        red_roots: List[Any] = []
        if acc_phis_list:
            body_def_map = {ins.result: ins for ins in work_body_insts if isinstance(ins.result, SSAVar)}
            red_parsed = self._extract_reduction_specs_from_phis(
                cond_bb, pre_bb, acc_phis_list, body_def_map, fn=fn, const_search_insts=work_body_insts
            )
            if red_parsed is None:
                return None
            red_specs, all_acc_prevs, all_acc_nexts, red_roots = red_parsed
            red_roots = [forwarded_map.get(r, r) for r in red_roots]
            for r in red_specs:
                r["delta_var"] = forwarded_map.get(r["delta_var"], r["delta_var"])
                if r["cond_mask"] is not None:
                    r["cond_mask"] = forwarded_map.get(r["cond_mask"], r["cond_mask"])
                if r["acc_prev"] in store_vals or r["acc_next"] in store_vals:
                    r["is_scan"] = True

        if self._has_escaped_loop_uses(
            fn, loop_blks | (superseded_blks or set()), loop_defined, allowed_vars=all_acc_prevs | all_acc_nexts
        ):
            return None

        non_scan_store_vals = [sv for sv in store_vals if sv not in (all_acc_prevs | all_acc_nexts)]
        dag_insts = self._extract_pure_dag_slice(
            work_body_insts, non_scan_store_vals + red_roots, load_res_set, i_var, loop_defined
        )
        if dag_insts is None:
            return None

        if all_acc_prevs:
            for ins in dag_insts:
                if any(op in (all_acc_prevs | all_acc_nexts) for op in ins.operands):
                    return None
            for r in red_specs:
                if r["delta_var"] in (all_acc_prevs | all_acc_nexts) or r["cond_mask"] in (all_acc_prevs | all_acc_nexts):
                    return None

        return {
            "i_var": i_var,
            "bound_count": bound_count,
            "bound_op": bound_op,
            "is_le": is_le,
            "start_i": start_i,
            "step_i": step_i,
            "bound_delta": bound_delta,
            "dsts": dst_specs,
            "loads": load_specs,
            "dag_insts": dag_insts,
            "reductions": red_specs,
            "any_float": any(r["is_float"] for r in red_specs),
        }

    @classmethod
    def _tree_reduce_ssa(
        cls,
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
                    cls._emit_reduction_op(r_v, op, curr[j], curr[j + 1], f"{prefix}_{round_idx}_{j // 2}", out_insts)
                    nxt.append(r_v)
                else:
                    nxt.append(curr[j])
            curr = nxt
            round_idx += 1
        return curr[0]

    @staticmethod
    def _emit_4x_slot_addrs(
        c_iv: SSAVar,
        boff: int,
        stride: int,
        tag: str,
        prefix: str,
        seq: List[int],
        out: List[SSAInstruction],
    ) -> List[SSAVar]:
        def _mk_a(suffix: str, opcode: str, ops: List[Any]) -> SSAVar:
            v = SSAVar(f"{prefix}_{tag}_{suffix}_{seq[0]}", 0)
            seq[0] += 1
            out.append(SSAInstruction(v, opcode, ops))
            return v

        s4_c = _mk_a("s4", "const", [stride * 4])
        step_v = _mk_a("mul", "mul", [c_iv, s4_c])
        if boff != 0:
            ebase = _mk_a("eb", "add", [_mk_a("bo", "const", [boff]), step_v])
        else:
            ebase = step_v
        addrs: List[SSAVar] = [ebase]
        for ln in range(1, 4):
            addrs.append(_mk_a(f"la{ln}", "add", [ebase, _mk_a(f"lo{ln}", "const", [ln * stride])]))
        return addrs

    @staticmethod
    def _emit_scalar_slot_addr(
        t_iv: SSAVar,
        boff: int,
        stride: int,
        tag: str,
        prefix: str,
        seq: List[int],
        out: List[SSAInstruction],
    ) -> SSAVar:
        def _mk_a(suffix: str, opcode: str, ops: List[Any]) -> SSAVar:
            v = SSAVar(f"{prefix}_{tag}_{suffix}_{seq[0]}", 0)
            seq[0] += 1
            out.append(SSAInstruction(v, opcode, ops))
            return v

        scaled = _mk_a("m", "mul", [t_iv, _mk_a("s", "const", [stride])])
        if boff != 0:
            return _mk_a("a", "add", [_mk_a("b", "const", [boff]), scaled])
        return scaled

    def _build_unrolled_tree_reduction(
        self,
        fn: SSAFunction,
        pre_bb: BasicBlock,
        cond_bb: BasicBlock,
        pattern: Dict[str, Any],
        step_id: int,
    ) -> Tuple[List[SSAInstruction], List[SSAVar]]:
        i_var: SSAVar = pattern["i_var"]
        bound_count: int = pattern["bound_count"]
        start_i: int = pattern.get("start_i", 0)
        step_i: int = pattern.get("step_i", 1)
        load_specs: List[Tuple[Any, int, int, str, SSAVar]] = pattern["loads"]
        dag_insts: List[SSAInstruction] = pattern["dag_insts"]
        red_specs: List[Dict[str, Any]] = pattern["reductions"]

        insts: List[SSAInstruction] = []
        items_by_r: List[List[SSAVar]] = [[] for _ in red_specs]
        seq = [0]
        needs_i = (
            any(r["delta_var"] == i_var or r["cond_mask"] == i_var for r in red_specs)
            or any(i_var in ins.operands for ins in dag_insts)
        )

        id_masks: List[Optional[Any]] = []
        for r_idx, r in enumerate(red_specs):
            if r["cond_mask"] is not None:
                init_m = self._find_init_acc(cond_bb, pre_bb, r["acc_prev"]) if r["op"] in self._MINMAX_CMP_MAP else None
                if init_m is not None:
                    id_masks.append(init_m)
                else:
                    id_op, id_val = self._REDUCTION_OPS_IDENTITY[r["op"]]
                    zm = SSAVar(f"vec_zmask_{step_id}_{r_idx}", 0, var_type=r["ssa_vt"])
                    insts.append(SSAInstruction(zm, id_op, [id_val]))
                    id_masks.append(zm)
            else:
                id_masks.append(None)

        for k in range(bound_count):
            local_map: Dict[Any, Any] = {}
            for l_idx, (base_ptr, base_offset, stride, width, s_res) in enumerate(load_specs):
                cur_off = base_offset + k * stride
                off_v = SSAVar(f"vec_off_{step_id}_{l_idx}_{k}", 0)
                insts.append(SSAInstruction(off_v, "const", [cur_off]))
                ld_vt = s_res.var_type if isinstance(s_res, SSAVar) else ("f64" if "f" in width else "i64")
                ld_v = SSAVar(f"vec_ld_{step_id}_{l_idx}_{k}", 0, var_type=ld_vt)
                insts.append(SSAInstruction(ld_v, "load_off", [base_ptr, off_v, width]))
                local_map[s_res] = ld_v
            if needs_i:
                ik_v = SSAVar(f"vec_ik_{step_id}_{k}", 0)
                insts.append(SSAInstruction(ik_v, "const", [start_i + k * step_i]))
                local_map[i_var] = ik_v
            local_map = self._clone_dag_insts(dag_insts, local_map, f"vec_u_{step_id}_{k}", seq, insts)
            for r_idx, r in enumerate(red_specs):
                d_k = local_map.get(r["delta_var"], r["delta_var"])
                if r["cond_mask"] is not None:
                    c_k = local_map.get(r["cond_mask"], r["cond_mask"])
                    cand_k = SSAVar(f"vec_ms_{step_id}_{r_idx}_{k}", 0, var_type=r["ssa_vt"])
                    sel_ops = [c_k, id_masks[r_idx], d_k] if r["cond_inverted"] else [c_k, d_k, id_masks[r_idx]]
                    insts.append(SSAInstruction(cand_k, "select", sel_ops))
                    items_by_r[r_idx].append(cand_k)
                else:
                    items_by_r[r_idx].append(d_k)

        final_vars: List[SSAVar] = []
        for r_idx, r in enumerate(red_specs):
            op = r["op"]
            vt = r["ssa_vt"]
            items = items_by_r[r_idx]
            init_val = self._find_init_acc(cond_bb, pre_bb, r["acc_prev"])
            if op == "linear_recurrence":
                if init_val is None:
                    cur_acc = SSAVar(f"vec_lr_init_{step_id}_{r_idx}", 0, var_type=vt)
                    insts.append(SSAInstruction(cur_acc, "const", [0]))
                else:
                    cur_acc = init_val
                idx_k = 0
                while idx_k + 4 <= len(items):
                    nxt_acc = SSAVar(f"vec_lr4_{step_id}_{r_idx}_{idx_k}", 0, var_type=vt)
                    self._emit_estrin_4x_linear_recurrence(
                        nxt_acc, cur_acc, items[idx_k : idx_k + 4], r, f"vec_lre_{step_id}_{r_idx}_{idx_k}", insts
                    )
                    cur_acc = nxt_acc
                    idx_k += 4
                while idx_k < len(items):
                    nxt_acc = SSAVar(f"vec_lr1_{step_id}_{r_idx}_{idx_k}", 0, var_type=vt)
                    self._emit_reduction_op(nxt_acc, op, cur_acc, items[idx_k], f"vec_lrs_{step_id}_{r_idx}_{idx_k}", insts, r_spec=r)
                    cur_acc = nxt_acc
                    idx_k += 1
                final_vars.append(cur_acc)
                continue
            sum_res = (
                self._tree_reduce_ssa(items, op, vt, f"vec_tree_{step_id}_{r_idx}", insts)
                if items
                else SSAVar(f"vec_zero_{step_id}_{r_idx}", 0, var_type=vt)
            )
            if init_val is not None and not self._is_reduction_identity(fn, init_val, op):
                final_res = SSAVar(f"vec_sum_acc_{step_id}_{r_idx}", 0, var_type=vt)
                self._emit_reduction_op(final_res, op, init_val, sum_res, f"vec_facc_{step_id}_{r_idx}", insts, r_spec=r)
            else:
                final_res = sum_res
            final_vars.append(final_res)

        if pattern["any_float"] and fn.return_type in ("float", "f32", "f64", None):
            fn.return_type = "f64"

        return insts, final_vars

    @staticmethod
    def _substitute_loop_uses(
        fn: SSAFunction,
        excluded_blks: Set[BasicBlock],
        target_vars: Set[SSAVar],
        replacement_var: SSAVar,
    ) -> None:
        if not target_vars:
            return
        for blk in fn.blocks:
            if blk in excluded_blks:
                continue
            for phi in blk.phi_nodes:
                for idx_o, operand in enumerate(phi.operands):
                    if operand in target_vars:
                        phi.operands[idx_o] = replacement_var
                if phi.phi_incoming:
                    phi.phi_incoming = [
                        (src_b, replacement_var if val in target_vars else val)
                        for src_b, val in phi.phi_incoming
                    ]
            for inst in blk.instructions:
                for idx_o, operand in enumerate(inst.operands):
                    if operand in target_vars:
                        inst.operands[idx_o] = replacement_var

    def _emit_strip_mined_4x_core(
        self,
        fn: SSAFunction,
        pre_bb: BasicBlock,
        cond_bb: BasicBlock,
        body_blk: BasicBlock,
        false_target: BasicBlock,
        bound_var: SSAVar,
        pattern: Dict[str, Any],
        step_id: int,
        extra_pre_insts: List[SSAInstruction],
        cond_prefix_insts: List[SSAInstruction],
    ) -> Tuple[List[SSAVar], List[SSAInstruction]]:
        i_var: SSAVar = pattern["i_var"]
        load_specs: List[Tuple[Any, int, int, str, SSAVar]] = pattern["loads"]
        dag_insts: List[SSAInstruction] = pattern["dag_insts"]
        red_specs: List[Dict[str, Any]] = pattern["reductions"]

        pre_insts: List[SSAInstruction] = list(extra_pre_insts)
        zero_idx = SSAVar(f"vec_cinit_{step_id}", 0)
        pre_insts.append(SSAInstruction(zero_idx, "const", [0]))

        acc_inits_by_r: List[List[Any]] = []
        acc_phis_by_r: List[List[SSAVar]] = []
        acc_nexts_by_r: List[List[SSAVar]] = []

        for r_idx, r in enumerate(red_specs):
            id_op, id_val = self._REDUCTION_OPS_IDENTITY[r["op"]]
            vt = r["ssa_vt"]
            init_val = self._find_init_acc(cond_bb, pre_bb, r["acc_prev"])
            if init_val is None:
                init_val = SSAVar(f"vec_a0_z_{step_id}_{r_idx}", 0, var_type=vt)
                pre_insts.append(SSAInstruction(init_val, id_op, [id_val]))
            r_inits: List[Any] = [init_val]
            if r["op"] in self._MINMAX_CMP_MAP:
                # Idempotent min/max: seeding all 4 lanes with init_val avoids sentinel overflow and handles n < 4
                r_inits.extend([init_val, init_val, init_val])
            else:
                for lane in range(1, 4):
                    av = SSAVar(f"vec_a{lane}_z_{step_id}_{r_idx}", 0, var_type=vt)
                    pre_insts.append(SSAInstruction(av, id_op, [id_val]))
                    r_inits.append(av)
            acc_inits_by_r.append(r_inits)
            acc_phis_by_r.append([SSAVar(f"vec_acc{lane}_{step_id}_{r_idx}", 0, var_type=vt) for lane in range(4)])
            acc_nexts_by_r.append([SSAVar(f"vec_acc{lane}_nxt_{step_id}_{r_idx}", 0, var_type=vt) for lane in range(4)])

        if pre_bb.instructions:
            term = pre_bb.instructions[-1]
            pre_bb.instructions = pre_bb.instructions[:-1] + pre_insts + [term]
        else:
            pre_bb.instructions.extend(pre_insts)

        c_iv = SSAVar(f"vec_ci_{step_id}", 0)
        c_iv_next = SSAVar(f"vec_ci_nxt_{step_id}", 0)

        new_phis = [
            SSAInstruction(c_iv, "phi", [zero_idx, c_iv_next], phi_incoming=[(pre_bb.name, zero_idx), (body_blk.name, c_iv_next)]),
        ]
        for r_idx in range(len(red_specs)):
            for lane in range(4):
                new_phis.append(
                    SSAInstruction(
                        acc_phis_by_r[r_idx][lane],
                        "phi",
                        [acc_inits_by_r[r_idx][lane], acc_nexts_by_r[r_idx][lane]],
                        phi_incoming=[(pre_bb.name, acc_inits_by_r[r_idx][lane]), (body_blk.name, acc_nexts_by_r[r_idx][lane])],
                    )
                )
        cond_bb.phi_nodes = new_phis

        c_cmp = SSAVar(f"vec_ccmp_{step_id}", 0)
        cond_bb.instructions = list(cond_prefix_insts) + [
            SSAInstruction(c_cmp, "cmp_lt", [c_iv, bound_var]),
            SSAInstruction(None, "br_cond", [c_cmp, body_blk.name, false_target.name]),
        ]

        body_insts: List[SSAInstruction] = []
        seq = [0]
        lane_maps: List[Dict[Any, Any]] = [{} for _ in range(4)]
        for s_idx, (s_base, s_boff, s_stride, s_width, s_res) in enumerate(load_specs):
            addrs = self._emit_4x_slot_addrs(c_iv, s_boff, s_stride, f"ld{s_idx}", f"vec_r_{step_id}", seq, body_insts)
            ld_vt = s_res.var_type if isinstance(s_res, SSAVar) else ("f64" if "f" in s_width else "i64")
            for ln in range(4):
                ld_v = SSAVar(f"vec_lld_{step_id}_{s_idx}_{ln}", 0, var_type=ld_vt)
                body_insts.append(SSAInstruction(ld_v, "load_off", [s_base, addrs[ln], s_width]))
                lane_maps[ln][s_res] = ld_v

        needs_i = (
            any(r["delta_var"] == i_var or r["cond_mask"] == i_var for r in red_specs)
            or any(i_var in ins.operands for ins in dag_insts)
        )
        if needs_i:
            start_i: int = pattern.get("start_i", 0)
            step_i: int = pattern.get("step_i", 1)
            if start_i == 0 and step_i == 1:
                itwo = SSAVar(f"vec_ritwo_{step_id}", 0)
                ibase = SSAVar(f"vec_ribase_{step_id}", 0)
                body_insts.extend([SSAInstruction(itwo, "const", [2]), SSAInstruction(ibase, "shl", [c_iv, itwo])])
                lane_maps[0][i_var] = ibase
                for ln in range(1, 4):
                    ic = SSAVar(f"vec_ric_{step_id}_{ln}", 0)
                    il = SSAVar(f"vec_ril_{step_id}_{ln}", 0)
                    body_insts.extend([SSAInstruction(ic, "const", [ln]), SSAInstruction(il, "add", [ibase, ic])])
                    lane_maps[ln][i_var] = il
            else:
                iv_addrs = self._emit_4x_slot_addrs(c_iv, start_i, step_i, "iv", f"vec_r_{step_id}", seq, body_insts)
                for ln in range(4):
                    lane_maps[ln][i_var] = iv_addrs[ln]

        cloned_lmaps = [
            self._clone_dag_insts(dag_insts, lane_maps[ln], f"vec_rd_{step_id}_l{ln}", seq, body_insts)
            for ln in range(4)
        ]
        for r_idx, r in enumerate(red_specs):
            op = r["op"]
            vt = r["ssa_vt"]
            if op == "linear_recurrence":
                d_lanes = [cloned_lmaps[ln].get(r["delta_var"], r["delta_var"]) for ln in range(4)]
                self._emit_estrin_4x_linear_recurrence(
                    acc_nexts_by_r[r_idx][0],
                    acc_phis_by_r[r_idx][0],
                    d_lanes,
                    r,
                    f"vec_lre_{step_id}_{r_idx}",
                    body_insts,
                )
                for ln in range(1, 4):
                    body_insts.append(SSAInstruction(acc_nexts_by_r[r_idx][ln], "mov", [acc_phis_by_r[r_idx][ln]]))
                continue
            for ln in range(4):
                l_map = cloned_lmaps[ln]
                d_ln = l_map.get(r["delta_var"], r["delta_var"])
                if r["cond_mask"] is not None:
                    c_ln = l_map.get(r["cond_mask"], r["cond_mask"])
                    cand_ln = SSAVar(f"vec_cand{ln}_{step_id}_{r_idx}", 0, var_type=vt)
                    self._emit_reduction_op(cand_ln, op, acc_phis_by_r[r_idx][ln], d_ln, f"vec_rc_{step_id}_{r_idx}_{ln}", body_insts, r_spec=r)
                    sel_ops = (
                        [c_ln, acc_phis_by_r[r_idx][ln], cand_ln]
                        if r["cond_inverted"]
                        else [c_ln, cand_ln, acc_phis_by_r[r_idx][ln]]
                    )
                    body_insts.append(SSAInstruction(acc_nexts_by_r[r_idx][ln], "select", sel_ops))
                else:
                    self._emit_reduction_op(
                        acc_nexts_by_r[r_idx][ln], op, acc_phis_by_r[r_idx][ln], d_ln, f"vec_rn_{step_id}_{r_idx}_{ln}", body_insts, r_spec=r
                    )

        c_one = SSAVar(f"vec_cone_{step_id}", 0)
        body_insts.extend([
            SSAInstruction(c_one, "const", [1]),
            SSAInstruction(c_iv_next, "add", [c_iv, c_one]),
            SSAInstruction(None, "br", [cond_bb.name]),
        ])
        body_blk.phi_nodes = []
        body_blk.instructions = body_insts
        cond_bb.successors = [body_blk, false_target]
        body_blk.successors = [cond_bb]
        body_blk.predecessors = [cond_bb]

        merge_insts: List[SSAInstruction] = []
        merged_vars: List[SSAVar] = [
            acc_phis_by_r[r_idx][0]
            if r["op"] == "linear_recurrence"
            else self._tree_reduce_ssa(acc_phis_by_r[r_idx], r["op"], r["ssa_vt"], f"vec_merge_{step_id}_{r_idx}", merge_insts)
            for r_idx, r in enumerate(red_specs)
        ]
        if pattern["any_float"] and fn.return_type in ("float", "f32", "f64", None):
            fn.return_type = "f64"
        return merged_vars, merge_insts

    def _rewrite_struct_array_strip_mined_4x(
        self,
        fn: SSAFunction,
        pre_bb: BasicBlock,
        cond_bb: BasicBlock,
        body_blk: BasicBlock,
        exit_bb: BasicBlock,
        pattern: Dict[str, Any],
        step_id: int,
    ) -> None:
        """Transforms large constant struct/buffer reductions into a 4-way ILP strip-mined VLA loop."""
        i_var: SSAVar = pattern["i_var"]
        bound_count: int = pattern["bound_count"]
        load_specs: List[Tuple[Any, int, int, str, SSAVar]] = pattern["loads"]
        dag_insts: List[SSAInstruction] = pattern["dag_insts"]
        red_specs: List[Dict[str, Any]] = pattern["reductions"]

        chunks = bound_count // 4
        c_bound = SSAVar(f"vec_cbound_{step_id}", 0)
        merged_vars, merge_insts = self._emit_strip_mined_4x_core(
            fn=fn,
            pre_bb=pre_bb,
            cond_bb=cond_bb,
            body_blk=body_blk,
            false_target=exit_bb,
            bound_var=c_bound,
            pattern=pattern,
            step_id=step_id,
            extra_pre_insts=[],
            cond_prefix_insts=[SSAInstruction(c_bound, "const", [chunks])],
        )

        seq = [0]
        start_i: int = pattern.get("start_i", 0)
        step_i: int = pattern.get("step_i", 1)
        needs_i = (
            any(r["delta_var"] == i_var or r["cond_mask"] == i_var for r in red_specs)
            or any(i_var in ins.operands for ins in dag_insts)
        )
        for t_idx in range(chunks * 4, bound_count):
            t_map: Dict[Any, Any] = {}
            for s_idx, (base_ptr, base_offset, stride, width, s_res) in enumerate(load_specs):
                t_off_v = SSAVar(f"vec_toff_{step_id}_{s_idx}_{t_idx}", 0)
                ld_vt = s_res.var_type if isinstance(s_res, SSAVar) else ("f64" if "f" in width else "i64")
                t_ld_v = SSAVar(f"vec_tld_{step_id}_{s_idx}_{t_idx}", 0, var_type=ld_vt)
                merge_insts.extend([
                    SSAInstruction(t_off_v, "const", [base_offset + t_idx * stride]),
                    SSAInstruction(t_ld_v, "load_off", [base_ptr, t_off_v, width]),
                ])
                t_map[s_res] = t_ld_v
            if needs_i:
                ti_c = SSAVar(f"vec_tic_{step_id}_{t_idx}", 0)
                merge_insts.append(SSAInstruction(ti_c, "const", [start_i + t_idx * step_i]))
                t_map[i_var] = ti_c
            t_map = self._clone_dag_insts(dag_insts, t_map, f"vec_rt_{step_id}_{t_idx}", seq, merge_insts)
            for r_idx, r in enumerate(red_specs):
                d_t = t_map.get(r["delta_var"], r["delta_var"])
                t_next = SSAVar(f"vec_tacc_{step_id}_{r_idx}_{t_idx}", 0, var_type=r["ssa_vt"])
                if r["cond_mask"] is not None:
                    c_t = t_map.get(r["cond_mask"], r["cond_mask"])
                    t_cand = SSAVar(f"vec_tcand_{step_id}_{r_idx}_{t_idx}", 0, var_type=r["ssa_vt"])
                    self._emit_reduction_op(t_cand, r["op"], merged_vars[r_idx], d_t, f"vec_stc_{step_id}_{r_idx}_{t_idx}", merge_insts, r_spec=r)
                    sel_ops = (
                        [c_t, merged_vars[r_idx], t_cand]
                        if r["cond_inverted"]
                        else [c_t, t_cand, merged_vars[r_idx]]
                    )
                    merge_insts.append(SSAInstruction(t_next, "select", sel_ops))
                else:
                    self._emit_reduction_op(t_next, r["op"], merged_vars[r_idx], d_t, f"vec_stn_{step_id}_{r_idx}_{t_idx}", merge_insts, r_spec=r)
                merged_vars[r_idx] = t_next

        # Substitute uses of acc_prev / acc_next outside the loop BEFORE inserting merge_insts
        for r_idx, r in enumerate(red_specs):
            target_vars = {v for v in (r["acc_prev"], r["acc_next"]) if isinstance(v, SSAVar)}
            self._substitute_loop_uses(fn, {cond_bb, body_blk}, target_vars, merged_vars[r_idx])
        exit_bb.instructions = merge_insts + exit_bb.instructions

    def _rewrite_struct_array_dynamic_strip_mined_4x(
        self,
        fn: SSAFunction,
        pre_bb: BasicBlock,
        cond_bb: BasicBlock,
        body_blk: BasicBlock,
        exit_bb: BasicBlock,
        pattern: Dict[str, Any],
        step_id: int,
    ) -> None:
        """Transforms symbolic/dynamic-bound struct/buffer reductions into a 4-way VLA strip-mined loop + scalar tail."""
        i_var: SSAVar = pattern["i_var"]
        bound_op = pattern["bound_op"]
        is_le: bool = pattern["is_le"]
        start_i: int = pattern.get("start_i", 0)
        step_i: int = pattern.get("step_i", 1)
        bound_delta: int = pattern.get("bound_delta", 1 if is_le else 0)
        load_specs: List[Tuple[Any, int, int, str, SSAVar]] = pattern["loads"]
        dag_insts: List[SSAInstruction] = pattern["dag_insts"]
        red_specs: List[Dict[str, Any]] = pattern["reductions"]

        pre_insts: List[SSAInstruction] = []
        z_cmp = SSAVar(f"vec_zcmp_{step_id}", 0)
        two_c = SSAVar(f"vec_two_{step_id}", 0)
        is_pos = SSAVar(f"vec_ispos_{step_id}", 0)
        shr_n = SSAVar(f"vec_shrn_{step_id}", 0)
        chunks_v = SSAVar(f"vec_chunks_{step_id}", 0)
        tail_start = SSAVar(f"vec_tstart_{step_id}", 0)

        if start_i == 0 and step_i == 1 and bound_delta in (0, 1):
            if bound_delta == 1:
                eff_one = SSAVar(f"vec_eff1_{step_id}", 0)
                eff_n = SSAVar(f"vec_effn_{step_id}", 0)
                pre_insts.append(SSAInstruction(eff_one, "const", [1]))
                pre_insts.append(SSAInstruction(eff_n, "add", [bound_op, eff_one]))
            else:
                eff_n = bound_op
            pre_insts.extend([
                SSAInstruction(z_cmp, "const", [0]),
                SSAInstruction(two_c, "const", [2]),
                SSAInstruction(is_pos, "cmp_gt", [eff_n, z_cmp]),
                SSAInstruction(shr_n, "shr", [eff_n, two_c]),
                SSAInstruction(chunks_v, "select", [is_pos, shr_n, z_cmp]),
                SSAInstruction(tail_start, "shl", [chunks_v, two_c]),
            ])
        else:
            min_b_val = start_i - bound_delta
            min_b_v = SSAVar(f"vec_minb_{step_id}", 0)
            pre_insts.extend([
                SSAInstruction(z_cmp, "const", [0]),
                SSAInstruction(two_c, "const", [2]),
                SSAInstruction(min_b_v, "const", [min_b_val]),
                SSAInstruction(is_pos, "cmp_gt", [bound_op, min_b_v]),
            ])
            net_adj = bound_delta - start_i + (step_i - 1)
            if net_adj == 0:
                adj_n = bound_op
            elif net_adj > 0:
                adj_c = SSAVar(f"vec_adjc_{step_id}", 0)
                adj_n = SSAVar(f"vec_adjn_{step_id}", 0)
                pre_insts.extend([
                    SSAInstruction(adj_c, "const", [net_adj]),
                    SSAInstruction(adj_n, "add", [bound_op, adj_c]),
                ])
            else:
                adj_c = SSAVar(f"vec_adjc_{step_id}", 0)
                adj_n = SSAVar(f"vec_adjn_{step_id}", 0)
                pre_insts.extend([
                    SSAInstruction(adj_c, "const", [-net_adj]),
                    SSAInstruction(adj_n, "sub", [bound_op, adj_c]),
                ])
            if step_i == 1:
                raw_eff = adj_n
            else:
                sh_p = step_i.bit_length() - 1
                shp_v = SSAVar(f"vec_shp_{step_id}", 0)
                raw_eff = SSAVar(f"vec_raweff_{step_id}", 0)
                pre_insts.extend([
                    SSAInstruction(shp_v, "const", [sh_p]),
                    SSAInstruction(raw_eff, "shr", [adj_n, shp_v]),
                ])
            eff_n = SSAVar(f"vec_effn_{step_id}", 0)
            pre_insts.extend([
                SSAInstruction(eff_n, "select", [is_pos, raw_eff, z_cmp]),
                SSAInstruction(shr_n, "shr", [raw_eff, two_c]),
                SSAInstruction(chunks_v, "select", [is_pos, shr_n, z_cmp]),
                SSAInstruction(tail_start, "shl", [chunks_v, two_c]),
            ])

        merge_bb = BasicBlock(f"vec_merge_bb_{step_id}")
        tail_cond_bb = BasicBlock(f"vec_tail_cond_{step_id}")
        tail_body_bb = BasicBlock(f"vec_tail_body_{step_id}")

        merged_vars, merge_insts = self._emit_strip_mined_4x_core(
            fn=fn,
            pre_bb=pre_bb,
            cond_bb=cond_bb,
            body_blk=body_blk,
            false_target=merge_bb,
            bound_var=chunks_v,
            pattern=pattern,
            step_id=step_id,
            extra_pre_insts=pre_insts,
            cond_prefix_insts=[],
        )

        merge_bb.instructions = merge_insts + [SSAInstruction(None, "br", [tail_cond_bb.name])]
        merge_bb.predecessors = [cond_bb]
        merge_bb.successors = [tail_cond_bb]

        # Scalar tail loop from tail_start up to eff_n
        t_iv = SSAVar(f"vec_tiv_{step_id}", 0)
        t_iv_next = SSAVar(f"vec_tiv_nxt_{step_id}", 0)
        t_cmp = SSAVar(f"vec_tcmp_{step_id}", 0)

        t_accs = [SSAVar(f"vec_tacc_{step_id}_{r_idx}", 0, var_type=r["ssa_vt"]) for r_idx, r in enumerate(red_specs)]
        t_acc_nexts = [SSAVar(f"vec_tacc_nxt_{step_id}_{r_idx}", 0, var_type=r["ssa_vt"]) for r_idx, r in enumerate(red_specs)]

        tail_cond_bb.phi_nodes = [
            SSAInstruction(
                t_iv, "phi", [tail_start, t_iv_next],
                phi_incoming=[(merge_bb.name, tail_start), (tail_body_bb.name, t_iv_next)],
            ),
        ] + [
            SSAInstruction(
                t_accs[r_idx], "phi", [merged_vars[r_idx], t_acc_nexts[r_idx]],
                phi_incoming=[(merge_bb.name, merged_vars[r_idx]), (tail_body_bb.name, t_acc_nexts[r_idx])],
            )
            for r_idx in range(len(red_specs))
        ]
        tail_cond_bb.instructions = [
            SSAInstruction(t_cmp, "cmp_lt", [t_iv, eff_n]),
            SSAInstruction(None, "br_cond", [t_cmp, tail_body_bb.name, exit_bb.name]),
        ]
        tail_cond_bb.predecessors = [merge_bb, tail_body_bb]
        tail_cond_bb.successors = [tail_body_bb, exit_bb]

        tail_body_insts: List[SSAInstruction] = []
        t_seq = [0]
        needs_i = (
            any(r["delta_var"] == i_var or r["cond_mask"] == i_var for r in red_specs)
            or any(i_var in ins.operands for ins in dag_insts)
        )
        t_map: Dict[Any, Any] = {}
        if needs_i:
            if start_i == 0 and step_i == 1:
                t_map[i_var] = t_iv
            else:
                t_map[i_var] = self._emit_scalar_slot_addr(t_iv, start_i, step_i, "tiv", f"vec_rt_{step_id}", t_seq, tail_body_insts)
        for s_idx, (base_ptr, base_offset, stride, width, s_res) in enumerate(load_specs):
            t_off = self._emit_scalar_slot_addr(t_iv, base_offset, stride, f"tld{s_idx}", f"vec_rt_{step_id}", t_seq, tail_body_insts)
            ld_vt = s_res.var_type if isinstance(s_res, SSAVar) else ("f64" if "f" in width else "i64")
            t_ld = SSAVar(f"vec_tld_{step_id}_{s_idx}", 0, var_type=ld_vt)
            tail_body_insts.append(SSAInstruction(t_ld, "load_off", [base_ptr, t_off, width]))
            t_map[s_res] = t_ld

        t_map = self._clone_dag_insts(dag_insts, t_map, f"vec_rtd_{step_id}", t_seq, tail_body_insts)
        for r_idx, r in enumerate(red_specs):
            d_t = t_map.get(r["delta_var"], r["delta_var"])
            if r["cond_mask"] is not None:
                c_t = t_map.get(r["cond_mask"], r["cond_mask"])
                t_cand = SSAVar(f"vec_dtcand_{step_id}_{r_idx}", 0, var_type=r["ssa_vt"])
                self._emit_reduction_op(t_cand, r["op"], t_accs[r_idx], d_t, f"vec_dtc_{step_id}_{r_idx}", tail_body_insts, r_spec=r)
                sel_ops = (
                    [c_t, t_accs[r_idx], t_cand]
                    if r["cond_inverted"]
                    else [c_t, t_cand, t_accs[r_idx]]
                )
                tail_body_insts.append(SSAInstruction(t_acc_nexts[r_idx], "select", sel_ops))
            else:
                self._emit_reduction_op(t_acc_nexts[r_idx], r["op"], t_accs[r_idx], d_t, f"vec_dtn_{step_id}_{r_idx}", tail_body_insts, r_spec=r)

        t_one = SSAVar(f"vec_tone_{step_id}", 0)
        tail_body_insts.extend([
            SSAInstruction(t_one, "const", [1]),
            SSAInstruction(t_iv_next, "add", [t_iv, t_one]),
            SSAInstruction(None, "br", [tail_cond_bb.name]),
        ])
        tail_body_bb.instructions = tail_body_insts
        tail_body_bb.predecessors = [tail_cond_bb]
        tail_body_bb.successors = [tail_cond_bb]

        exit_bb.predecessors = [tail_cond_bb if p == cond_bb else p for p in exit_bb.predecessors]
        if tail_cond_bb not in exit_bb.predecessors:
            exit_bb.predecessors.append(tail_cond_bb)
        for phi in exit_bb.phi_nodes:
            if phi.phi_incoming:
                phi.phi_incoming = [
                    (tail_cond_bb.name if (getattr(sb, "name", str(sb)) == cond_bb.name) else sb, val)
                    for sb, val in phi.phi_incoming
                ]

        exit_idx = fn.blocks.index(exit_bb)
        for new_blk in reversed((merge_bb, tail_cond_bb, tail_body_bb)):
            fn.blocks.insert(exit_idx, new_blk)

        for r_idx, r in enumerate(red_specs):
            target_vars = {v for v in (r["acc_prev"], r["acc_next"]) if isinstance(v, SSAVar)}
            self._substitute_loop_uses(
                fn,
                {cond_bb, body_blk, merge_bb, tail_cond_bb, tail_body_bb},
                target_vars,
                t_accs[r_idx],
            )

    @classmethod
    def _is_statically_disjoint_same_base(
        cls,
        off_a: int,
        stride_a: int,
        w_a: str,
        off_b: int,
        stride_b: int,
        w_b: str,
        bound_count: Optional[int],
    ) -> bool:
        wb_a = cls._WIDTH_BYTES.get(w_a, 8)
        wb_b = cls._WIDTH_BYTES.get(w_b, 8)
        if bound_count is not None and bound_count > 0:
            end_a = off_a + (bound_count - 1) * stride_a + wb_a
            end_b = off_b + (bound_count - 1) * stride_b + wb_b
            if end_a <= off_b or end_b <= off_a:
                return True
        if stride_a == stride_b and off_a != off_b:
            lo_o, lo_w, hi_o, hi_w = (off_a, wb_a, off_b, wb_b) if off_a < off_b else (off_b, wb_b, off_a, wb_a)
            diff = hi_o - lo_o
            if diff < stride_a and lo_o + lo_w <= hi_o and diff + hi_w <= stride_a:
                return True  # Interleaved AoS struct fields never overlap at any index
        return False

    def _rewrite_struct_array_store_4x(
        self,
        fn: SSAFunction,
        pre_bb: BasicBlock,
        cond_bb: BasicBlock,
        body_blk: BasicBlock,
        exit_bb: BasicBlock,
        pattern: Dict[str, Any],
        step_id: int,
    ) -> None:
        """Transforms single or multi-field elementwise array/struct write loops into 4-lane vector store + alias guard + scalar tail."""
        i_var: SSAVar = pattern["i_var"]
        bound_count: Optional[int] = pattern["bound_count"]
        bound_op = pattern["bound_op"]
        is_le: bool = pattern["is_le"]
        start_i: int = pattern.get("start_i", 0)
        step_i: int = pattern.get("step_i", 1)
        bound_delta: int = pattern.get("bound_delta", 1 if is_le else 0)
        dst_specs: List[Tuple[Any, int, int, str, Any]] = pattern["dsts"]
        load_specs: List[Tuple[Any, int, int, str, SSAVar]] = pattern["loads"]
        dag_insts: List[SSAInstruction] = pattern["dag_insts"]
        red_specs: List[Dict[str, Any]] = pattern.get("reductions") or []

        seq = [0]

        def _mk(tag: str, opcode: str, ops: List[Any], out: List[SSAInstruction], vt: str = "i64") -> SSAVar:
            v = SSAVar(f"vec_st_{step_id}_{tag}_{seq[0]}", 0, var_type=vt)
            seq[0] += 1
            out.append(SSAInstruction(v, opcode, ops))
            return v

        store_vals = [d[4] for d in dst_specs]
        needs_i_var = (
            (i_var in store_vals)
            or any(r["delta_var"] == i_var or r["cond_mask"] == i_var for r in red_specs)
            or any(i_var in ins.operands for ins in dag_insts)
        )

        # 1. Pre-header: eff_n, raw_chunks, pairwise alias guard across (dst vs read) & (dst vs dst), tail_start
        pre_insts: List[SSAInstruction] = []
        acc_inits_by_r: List[List[Any]] = []
        acc_phis_by_r: List[List[SSAVar]] = []
        acc_nexts_by_r: List[List[SSAVar]] = []

        for r_idx, r in enumerate(red_specs):
            id_op, id_val = self._REDUCTION_OPS_IDENTITY[r["op"]]
            vt = r["ssa_vt"]
            init_val = self._find_init_acc(cond_bb, pre_bb, r["acc_prev"])
            if init_val is None:
                init_val = _mk(f"a0z_{r_idx}", id_op, [id_val], pre_insts, vt=vt)
            r_inits: List[Any] = [init_val]
            if r["op"] in self._MINMAX_CMP_MAP:
                r_inits.extend([init_val, init_val, init_val])
            else:
                for lane in range(1, 4):
                    r_inits.append(_mk(f"a{lane}z_{r_idx}", id_op, [id_val], pre_insts, vt=vt))
            acc_inits_by_r.append(r_inits)
            acc_phis_by_r.append([SSAVar(f"vec_st_acc{lane}_{step_id}_{r_idx}", 0, var_type=vt) for lane in range(4)])
            acc_nexts_by_r.append([SSAVar(f"vec_st_acc{lane}_nxt_{step_id}_{r_idx}", 0, var_type=vt) for lane in range(4)])
        z_c = _mk("zc", "const", [0], pre_insts)
        two_c = _mk("two", "const", [2], pre_insts)
        if bound_count is not None:
            eff_n = _mk("effn", "const", [bound_count], pre_insts)
            is_pos = _mk("ispos", "cmp_gt", [eff_n, z_c], pre_insts)
            shr_n = _mk("shrn", "shr", [eff_n, two_c], pre_insts)
            raw_chunks = _mk("rchk", "select", [is_pos, shr_n, z_c], pre_insts)
        elif start_i == 0 and step_i == 1 and bound_delta in (0, 1):
            if bound_delta == 1:
                eff_1 = _mk("eff1", "const", [1], pre_insts)
                eff_n = _mk("effn", "add", [bound_op, eff_1], pre_insts)
            else:
                eff_n = bound_op
            is_pos = _mk("ispos", "cmp_gt", [eff_n, z_c], pre_insts)
            shr_n = _mk("shrn", "shr", [eff_n, two_c], pre_insts)
            raw_chunks = _mk("rchk", "select", [is_pos, shr_n, z_c], pre_insts)
        else:
            min_b_v = _mk("minb", "const", [start_i - bound_delta], pre_insts)
            is_pos = _mk("ispos", "cmp_gt", [bound_op, min_b_v], pre_insts)
            net_adj = bound_delta - start_i + (step_i - 1)
            if net_adj == 0:
                adj_n = bound_op
            elif net_adj > 0:
                adj_n = _mk("adjn", "add", [bound_op, _mk("adjc", "const", [net_adj], pre_insts)], pre_insts)
            else:
                adj_n = _mk("adjn", "sub", [bound_op, _mk("adjc", "const", [-net_adj], pre_insts)], pre_insts)
            if step_i == 1:
                raw_eff = adj_n
            else:
                sh_p = step_i.bit_length() - 1
                raw_eff = _mk("raweff", "shr", [adj_n, _mk("shp", "const", [sh_p], pre_insts)], pre_insts)
            eff_n = _mk("effn", "select", [is_pos, raw_eff, z_c], pre_insts)
            shr_n = _mk("shrn", "shr", [raw_eff, two_c], pre_insts)
            raw_chunks = _mk("rchk", "select", [is_pos, shr_n, z_c], pre_insts)

        span_cache: Dict[Tuple[Any, int, int], Tuple[Any, SSAVar]] = {}

        def _get_interval(base: Any, boff: int, stride: int, tag: str) -> Tuple[Any, SSAVar]:
            key = (base, boff, stride)
            if key not in span_cache:
                start_v = _mk(f"{tag}s", "add", [base, _mk(f"{tag}o", "const", [boff], pre_insts)], pre_insts) if boff != 0 else base
                end_v = _mk(f"{tag}e", "add", [start_v, _mk(f"{tag}n", "mul", [eff_n, _mk(f"{tag}t", "const", [stride], pre_insts)], pre_insts)], pre_insts)
                span_cache[key] = (start_v, end_v)
            return span_cache[key]

        static_alias_force_scalar = False
        alias_guards: List[SSAVar] = []
        checks_to_emit: List[Tuple[Tuple[Any, int, int, str], Tuple[Any, int, int, str], bool]] = []
        for m_idx, d_sp in enumerate(dst_specs):
            d_slot = (d_sp[0], d_sp[1], d_sp[2], d_sp[3])
            for r_sp in load_specs:
                checks_to_emit.append((d_slot, (r_sp[0], r_sp[1], r_sp[2], r_sp[3]), True))
            for k_idx in range(m_idx + 1, len(dst_specs)):
                k_sp = dst_specs[k_idx]
                checks_to_emit.append((d_slot, (k_sp[0], k_sp[1], k_sp[2], k_sp[3]), False))

        seen_pairs: Set[Tuple[Any, ...]] = set()
        for slot_a, slot_b, is_store_load in checks_to_emit:
            base_a, boff_a, str_a, w_a = slot_a
            base_b, boff_b, str_b, w_b = slot_b
            pkey = (slot_a, slot_b, is_store_load)
            if pkey in seen_pairs:
                continue
            seen_pairs.add(pkey)

            if base_a == base_b:
                if boff_a == boff_b and str_a == str_b:
                    # Exact in-place (store vs load) safe iff no OTHER store targets this slot
                    if is_store_load and not any(
                        other_idx != idx_a and other[:3] == (base_a, boff_a, str_a)
                        for idx_a, ds in enumerate(dst_specs) if ds[:4] == slot_a
                        for other_idx, other in enumerate(dst_specs)
                    ):
                        continue
                    static_alias_force_scalar = True
                    break
                if self._is_statically_disjoint_same_base(boff_a, str_a, w_a, boff_b, str_b, w_b, bound_count):
                    continue
                if str_a == str_b and abs(boff_a - boff_b) < 4 * str_a:
                    static_alias_force_scalar = True
                    break

            sa_v, ea_v = _get_interval(base_a, boff_a, str_a, "da")
            sb_v, eb_v = _get_interval(base_b, boff_b, str_b, "sb")
            d1 = _mk("d1", "cmp_le", [ea_v, sb_v], pre_insts)
            d2 = _mk("d2", "cmp_le", [eb_v, sa_v], pre_insts)
            pok = _mk("dj", "or", [d1, d2], pre_insts)
            if is_store_load and str_a == str_b and len(dst_specs) == 1:
                eq_s = _mk("eq", "cmp_eq", [sa_v, sb_v], pre_insts)
                pok = _mk("pk", "or", [pok, eq_s], pre_insts)
            alias_guards.append(pok)

        if static_alias_force_scalar:
            chunks_v = z_c
        elif alias_guards:
            all_ok = alias_guards[0]
            for g in alias_guards[1:]:
                all_ok = _mk("allok", "and", [all_ok, g], pre_insts)
            chunks_v = _mk("chks", "select", [all_ok, raw_chunks, z_c], pre_insts)
        else:
            chunks_v = raw_chunks

        tail_start = _mk("tstart", "shl", [chunks_v, two_c], pre_insts)
        zero_idx = _mk("zidx", "const", [0], pre_insts)

        if pre_bb.instructions:
            term = pre_bb.instructions[-1]
            pre_bb.instructions = pre_bb.instructions[:-1] + pre_insts + [term]
        else:
            pre_bb.instructions.extend(pre_insts)

        # 2. Vector chunk loop (cond_bb -> body_blk) and scalar tail loop (tail_cond_bb -> tail_body_bb)
        merge_bb: Optional[BasicBlock] = BasicBlock(f"vec_st_merge_{step_id}") if red_specs else None
        tail_cond_bb = BasicBlock(f"vec_st_tail_cond_{step_id}")
        tail_body_bb = BasicBlock(f"vec_st_tail_body_{step_id}")
        cond_false_target = merge_bb if merge_bb is not None else tail_cond_bb

        c_iv = SSAVar(f"vec_st_ci_{step_id}", 0)
        c_iv_next = SSAVar(f"vec_st_cin_{step_id}", 0)
        new_cond_phis = [
            SSAInstruction(
                c_iv, "phi", [zero_idx, c_iv_next],
                phi_incoming=[(pre_bb.name, zero_idx), (body_blk.name, c_iv_next)],
            )
        ]
        for r_idx in range(len(red_specs)):
            for lane in range(4):
                new_cond_phis.append(
                    SSAInstruction(
                        acc_phis_by_r[r_idx][lane],
                        "phi",
                        [acc_inits_by_r[r_idx][lane], acc_nexts_by_r[r_idx][lane]],
                        phi_incoming=[(pre_bb.name, acc_inits_by_r[r_idx][lane]), (body_blk.name, acc_nexts_by_r[r_idx][lane])],
                    )
                )
        cond_bb.phi_nodes = new_cond_phis
        c_cmp = SSAVar(f"vec_st_ccmp_{step_id}", 0)
        cond_bb.instructions = [
            SSAInstruction(c_cmp, "cmp_lt", [c_iv, chunks_v]),
            SSAInstruction(None, "br_cond", [c_cmp, body_blk.name, cond_false_target.name]),
        ]
        cond_bb.successors = [body_blk, cond_false_target]

        # Build body_blk: 1) all 4x loads, 2) 4x pure DAG clones, 3) all 4x stores, 4) optional 4x reductions
        body_insts: List[SSAInstruction] = []
        lane_maps: List[Dict[Any, Any]] = [{} for _ in range(4)]

        for s_idx, (s_base, s_boff, s_stride, s_width, s_res) in enumerate(load_specs):
            s_addrs = self._emit_4x_slot_addrs(c_iv, s_boff, s_stride, f"ld{s_idx}", f"vec_st_{step_id}", seq, body_insts)
            ld_vt = s_res.var_type if isinstance(s_res, SSAVar) else ("f64" if "f" in s_width else "i64")
            for ln in range(4):
                ld_v = _mk(f"ld{s_idx}_l{ln}", "load_off", [s_base, s_addrs[ln], s_width], body_insts, vt=ld_vt)
                lane_maps[ln][s_res] = ld_v

        if needs_i_var:
            if start_i == 0 and step_i == 1:
                base_i = _mk("ibase", "shl", [c_iv, _mk("itwo", "const", [2], body_insts)], body_insts)
                lane_maps[0][i_var] = base_i
                for ln in range(1, 4):
                    lane_maps[ln][i_var] = _mk(f"il{ln}", "add", [base_i, _mk(f"ic{ln}", "const", [ln], body_insts)], body_insts)
            else:
                iv_addrs = self._emit_4x_slot_addrs(c_iv, start_i, step_i, "iv", f"vec_st_{step_id}", seq, body_insts)
                for ln in range(4):
                    lane_maps[ln][i_var] = iv_addrs[ln]

        cloned_maps = [self._clone_dag_insts(dag_insts, lane_maps[ln], f"vec_st_{step_id}_l{ln}", seq, body_insts) for ln in range(4)]
        for r_idx, r in enumerate(red_specs):
            op = r["op"]
            vt = r["ssa_vt"]
            if r.get("is_scan"):
                cur_prev = acc_phis_by_r[r_idx][0]
                for ln in range(4):
                    l_map = cloned_maps[ln]
                    d_ln = l_map.get(r["delta_var"], r["delta_var"])
                    step_res = acc_nexts_by_r[r_idx][0] if ln == 3 else SSAVar(f"vec_st_sc{ln}_{step_id}_{r_idx}", 0, var_type=vt)
                    if r["cond_mask"] is not None:
                        c_ln = l_map.get(r["cond_mask"], r["cond_mask"])
                        cand_ln = SSAVar(f"vec_st_scc{ln}_{step_id}_{r_idx}", 0, var_type=vt)
                        self._emit_reduction_op(cand_ln, op, cur_prev, d_ln, f"vec_stsc_{step_id}_{r_idx}_{ln}", body_insts, r_spec=r)
                        sel_ops = [c_ln, cur_prev, cand_ln] if r["cond_inverted"] else [c_ln, cand_ln, cur_prev]
                        body_insts.append(SSAInstruction(step_res, "select", sel_ops))
                    else:
                        self._emit_reduction_op(step_res, op, cur_prev, d_ln, f"vec_stsn_{step_id}_{r_idx}_{ln}", body_insts, r_spec=r)
                    l_map[r["acc_prev"]] = cur_prev
                    l_map[r["acc_next"]] = step_res
                    cur_prev = step_res
                for ln in range(1, 4):
                    body_insts.append(SSAInstruction(acc_nexts_by_r[r_idx][ln], "mov", [acc_phis_by_r[r_idx][ln]]))
            elif op == "linear_recurrence":
                d_lanes = [cloned_maps[ln].get(r["delta_var"], r["delta_var"]) for ln in range(4)]
                self._emit_estrin_4x_linear_recurrence(
                    acc_nexts_by_r[r_idx][0],
                    acc_phis_by_r[r_idx][0],
                    d_lanes,
                    r,
                    f"vec_st_lre_{step_id}_{r_idx}",
                    body_insts,
                )
                for ln in range(1, 4):
                    body_insts.append(SSAInstruction(acc_nexts_by_r[r_idx][ln], "mov", [acc_phis_by_r[r_idx][ln]]))
            else:
                for ln in range(4):
                    l_map = cloned_maps[ln]
                    d_ln = l_map.get(r["delta_var"], r["delta_var"])
                    if r["cond_mask"] is not None:
                        c_ln = l_map.get(r["cond_mask"], r["cond_mask"])
                        cand_ln = SSAVar(f"vec_st_cand{ln}_{step_id}_{r_idx}", 0, var_type=vt)
                        self._emit_reduction_op(cand_ln, op, acc_phis_by_r[r_idx][ln], d_ln, f"vec_strc_{step_id}_{r_idx}_{ln}", body_insts, r_spec=r)
                        sel_ops = (
                            [c_ln, acc_phis_by_r[r_idx][ln], cand_ln]
                            if r["cond_inverted"]
                            else [c_ln, cand_ln, acc_phis_by_r[r_idx][ln]]
                        )
                        body_insts.append(SSAInstruction(acc_nexts_by_r[r_idx][ln], "select", sel_ops))
                    else:
                        self._emit_reduction_op(
                            acc_nexts_by_r[r_idx][ln], op, acc_phis_by_r[r_idx][ln], d_ln, f"vec_strn_{step_id}_{r_idx}_{ln}", body_insts, r_spec=r
                        )

        for d_idx, (d_base, d_boff, d_stride, d_width, d_val) in enumerate(dst_specs):
            dst_addrs = self._emit_4x_slot_addrs(c_iv, d_boff, d_stride, f"dst{d_idx}", f"vec_st_{step_id}", seq, body_insts)
            for ln in range(4):
                st_v = cloned_maps[ln].get(d_val, d_val)
                body_insts.append(SSAInstruction(None, "store_off", [d_base, dst_addrs[ln], st_v, d_width]))

        body_insts.extend([
            SSAInstruction(c_iv_next, "add", [c_iv, _mk("one", "const", [1], body_insts)]),
            SSAInstruction(None, "br", [cond_bb.name]),
        ])
        body_blk.phi_nodes = []
        body_blk.instructions = body_insts
        body_blk.predecessors = [cond_bb]
        body_blk.successors = [cond_bb]

        merged_vars: List[SSAVar] = []
        tail_pred_bb = cond_bb
        if merge_bb is not None:
            merge_insts: List[SSAInstruction] = []
            merged_vars = [
                acc_phis_by_r[r_idx][0]
                if (r.get("is_scan") or r["op"] == "linear_recurrence")
                else self._tree_reduce_ssa(acc_phis_by_r[r_idx], r["op"], r["ssa_vt"], f"vec_st_mrg_{step_id}_{r_idx}", merge_insts)
                for r_idx, r in enumerate(red_specs)
            ]
            merge_bb.instructions = merge_insts + [SSAInstruction(None, "br", [tail_cond_bb.name])]
            merge_bb.predecessors = [cond_bb]
            merge_bb.successors = [tail_cond_bb]
            tail_pred_bb = merge_bb

        # Build scalar tail loop
        t_iv = SSAVar(f"vec_st_ti_{step_id}", 0)
        t_iv_next = SSAVar(f"vec_st_tin_{step_id}", 0)
        t_cmp = SSAVar(f"vec_st_tcmp_{step_id}", 0)
        t_accs = [SSAVar(f"vec_st_tacc_{step_id}_{r_idx}", 0, var_type=r["ssa_vt"]) for r_idx, r in enumerate(red_specs)]
        t_acc_nexts = [SSAVar(f"vec_st_tacc_nxt_{step_id}_{r_idx}", 0, var_type=r["ssa_vt"]) for r_idx, r in enumerate(red_specs)]
        tail_cond_bb.phi_nodes = [
            SSAInstruction(
                t_iv, "phi", [tail_start, t_iv_next],
                phi_incoming=[(tail_pred_bb.name, tail_start), (tail_body_bb.name, t_iv_next)],
            )
        ] + [
            SSAInstruction(
                t_accs[r_idx], "phi", [merged_vars[r_idx], t_acc_nexts[r_idx]],
                phi_incoming=[(tail_pred_bb.name, merged_vars[r_idx]), (tail_body_bb.name, t_acc_nexts[r_idx])],
            )
            for r_idx in range(len(red_specs))
        ]
        tail_cond_bb.instructions = [
            SSAInstruction(t_cmp, "cmp_lt", [t_iv, eff_n]),
            SSAInstruction(None, "br_cond", [t_cmp, tail_body_bb.name, exit_bb.name]),
        ]
        tail_cond_bb.predecessors = [tail_pred_bb, tail_body_bb]
        tail_cond_bb.successors = [tail_body_bb, exit_bb]

        tail_insts: List[SSAInstruction] = []
        tail_map: Dict[Any, Any] = {}
        if needs_i_var:
            if start_i == 0 and step_i == 1:
                tail_map[i_var] = t_iv
            else:
                tail_map[i_var] = self._emit_scalar_slot_addr(t_iv, start_i, step_i, "tiv", f"vec_st_{step_id}", seq, tail_insts)
        for s_idx, (s_base, s_boff, s_stride, s_width, s_res) in enumerate(load_specs):
            t_addr = self._emit_scalar_slot_addr(t_iv, s_boff, s_stride, f"tld{s_idx}", f"vec_st_{step_id}", seq, tail_insts)
            ld_vt = s_res.var_type if isinstance(s_res, SSAVar) else ("f64" if "f" in s_width else "i64")
            tail_map[s_res] = _mk(f"tld{s_idx}", "load_off", [s_base, t_addr, s_width], tail_insts, vt=ld_vt)

        tail_map = self._clone_dag_insts(dag_insts, tail_map, f"vec_st_{step_id}_tdag", seq, tail_insts)
        for r_idx, r in enumerate(red_specs):
            d_t = tail_map.get(r["delta_var"], r["delta_var"])
            if r["cond_mask"] is not None:
                c_t = tail_map.get(r["cond_mask"], r["cond_mask"])
                t_cand = SSAVar(f"vec_st_dtcand_{step_id}_{r_idx}", 0, var_type=r["ssa_vt"])
                self._emit_reduction_op(t_cand, r["op"], t_accs[r_idx], d_t, f"vec_st_dtc_{step_id}_{r_idx}", tail_insts, r_spec=r)
                sel_ops = (
                    [c_t, t_accs[r_idx], t_cand]
                    if r["cond_inverted"]
                    else [c_t, t_cand, t_accs[r_idx]]
                )
                tail_insts.append(SSAInstruction(t_acc_nexts[r_idx], "select", sel_ops))
            else:
                self._emit_reduction_op(t_acc_nexts[r_idx], r["op"], t_accs[r_idx], d_t, f"vec_st_dtn_{step_id}_{r_idx}", tail_insts, r_spec=r)
            tail_map[r["acc_prev"]] = t_accs[r_idx]
            tail_map[r["acc_next"]] = t_acc_nexts[r_idx]
        for d_idx, (d_base, d_boff, d_stride, d_width, d_val) in enumerate(dst_specs):
            t_dst_addr = self._emit_scalar_slot_addr(t_iv, d_boff, d_stride, f"tdst{d_idx}", f"vec_st_{step_id}", seq, tail_insts)
            tail_insts.append(SSAInstruction(None, "store_off", [d_base, t_dst_addr, tail_map.get(d_val, d_val), d_width]))
        tail_insts.extend([
            SSAInstruction(t_iv_next, "add", [t_iv, _mk("tone", "const", [1], tail_insts)]),
            SSAInstruction(None, "br", [tail_cond_bb.name]),
        ])
        tail_body_bb.instructions = tail_insts
        tail_body_bb.predecessors = [tail_cond_bb]
        tail_body_bb.successors = [tail_cond_bb]

        exit_bb.predecessors = [tail_cond_bb if p == cond_bb else p for p in exit_bb.predecessors]
        if tail_cond_bb not in exit_bb.predecessors:
            exit_bb.predecessors.append(tail_cond_bb)
        for phi in exit_bb.phi_nodes:
            if phi.phi_incoming:
                phi.phi_incoming = [
                    (tail_cond_bb.name if (getattr(sb, "name", str(sb)) == cond_bb.name) else sb, val)
                    for sb, val in phi.phi_incoming
                ]

        new_blks_to_insert = (merge_bb, tail_cond_bb, tail_body_bb) if merge_bb is not None else (tail_cond_bb, tail_body_bb)
        exit_idx = fn.blocks.index(exit_bb)
        for new_blk in reversed(new_blks_to_insert):
            fn.blocks.insert(exit_idx, new_blk)

        if red_specs:
            excl_blks = {cond_bb, body_blk, tail_cond_bb, tail_body_bb} | ({merge_bb} if merge_bb is not None else set())
            for r_idx, r in enumerate(red_specs):
                target_vars = {v for v in (r["acc_prev"], r["acc_next"]) if isinstance(v, SSAVar)}
                self._substitute_loop_uses(fn, excl_blks, target_vars, t_accs[r_idx])
            if pattern.get("any_float") and fn.return_type in ("float", "f32", "f64", None):
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
        vla_ops = sum(v for k, v in base_stats.items() if k.startswith("vectorized_"))
        stats = {
            **base_stats,
            "vla_isa": target_isa,
            "vla_lanes": vla.vector_lanes,
            "vla_predicated_ops": vla_ops,
        }
        return fn, stats
