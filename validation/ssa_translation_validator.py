"""
OmniCompiler Per-Pass SMT Translation Validation Gate
(validation/ssa_translation_validator.py)

Alive2-style symbolic equivalence verifier for Omni-SSA IR optimization passes:
1. SSATranslationValidator:
   - Compiles acyclic (and optionally bounded-unrolled cyclic) multi-block
     `SSAFunction`s into Z3 64-bit `QF_BV` / `QF_ABV` formulas over shared symbolic
     parameter inputs and symbolic memory arrays.
   - Models `phi` nodes, `br_cond` path conditions, `cmp_*`, bitwise, arithmetic,
     `select`, and (when `enable_memory_theory=True`) `alloca`, `load`, `store`
     with separation between non-escaping local `alloca` storage and caller-visible
     external memory.
   - Proves equivalence (`unsat` => `PROVEN_EQUIVALENT` for acyclic CFGs, or
     `PROVEN_BOUNDED_EQUIVALENT` when bounded loop unrolling succeeds and is
     non-vacuous) or extracts an exact counterexample (`sat` => `REFUTED_COUNTEREXAMPLE`).
   - Strictly Fail-Closed on cycles when `max_loop_unroll == 0`, unsupported opcodes
     (`call`), escaping allocas, insufficient unroll bounds, or solver timeouts.
2. VerifiedPassRunner:
   - Snapshots `SSAFunction` before a pass, executes the pass, and validates
     equivalence afterward.
   - Automatically rolls back to the pre-pass snapshot if a counterexample refutes
     semantic equivalence.
"""

from typing import Dict, List, Set, Tuple, Any, Optional, Callable
import z3

from compiler.ssa_ir import SSAFunction, BasicBlock, SSAInstruction, SSAVar
from compiler.ip_sccp_gvn import clone_ssa_function


SUPPORTED_Z3_OPCODES = frozenset({
    "param", "const", "mov",
    "add", "sub", "mul", "sdiv", "srem",
    "shl", "shr", "sar", "lshr", "and", "or", "xor",
    "neg", "not",
    "cmp_eq", "cmp_ne", "cmp_lt", "cmp_le", "cmp_gt", "cmp_ge",
    "select", "phi",
    "br", "br_cond", "ret",
})

SUPPORTED_Z3_MEMORY_OPCODES = frozenset({"alloca", "load", "store"})
SUPPORTED_Z3_METADATA_OPCODES = frozenset({"unroll_meta", "unroll_factor"})


class SSATranslationValidator:
    """
    Translates Omni-SSA functions to Z3 64-bit QF_BV / QF_ABV expressions
    and proves semantic equivalence before and after optimization passes.
    """

    def __init__(
        self,
        enable_memory_theory: bool = False,
        max_loop_unroll: int = 0,
        enable_inductive_loops: bool = False,
        enable_call_congruence: bool = False,
    ):
        self.enable_memory_theory = enable_memory_theory
        self.max_loop_unroll = max(0, int(max_loop_unroll))
        self.enable_inductive_loops = bool(enable_inductive_loops)
        self.enable_call_congruence = bool(enable_call_congruence)

    def _topological_blocks(self, fn: SSAFunction) -> Optional[List[BasicBlock]]:
        """
        Returns reachable blocks in topological order, or None if a cycle exists.
        """
        if not fn.blocks:
            return None
        entry = fn.entry_block or fn.blocks[0]

        reachable: Set[str] = set()
        visiting: Set[str] = set()
        postorder: List[BasicBlock] = []
        has_cycle = False

        def dfs(b: BasicBlock):
            nonlocal has_cycle
            if b.name in visiting:
                has_cycle = True
                return
            if b.name in reachable:
                return
            visiting.add(b.name)
            for s in b.successors:
                dfs(s)
            visiting.remove(b.name)
            reachable.add(b.name)
            postorder.append(b)

        dfs(entry)
        if has_cycle:
            return None
        return list(reversed(postorder))

    def _classify_cfg_dag_and_backedges(
        self, fn: SSAFunction
    ) -> Tuple[List[BasicBlock], Set[Tuple[str, str]]]:
        """
        Performs DFS from `entry` to split edges into a cycle-free DAG (`E \\ E_back`)
        and the DFS back-edge set `E_back`, returning reachable blocks in DFS RPO.
        """
        entry = fn.entry_block or fn.blocks[0]
        visited: Set[str] = set()
        visiting: Set[str] = set()
        postorder: List[BasicBlock] = []
        back_edges: Set[Tuple[str, str]] = set()

        def dfs(b: BasicBlock):
            visited.add(b.name)
            visiting.add(b.name)
            for s in b.successors:
                if s.name in visiting:
                    back_edges.add((b.name, s.name))
                elif s.name not in visited:
                    dfs(s)
            visiting.remove(b.name)
            postorder.append(b)

        dfs(entry)
        return list(reversed(postorder)), back_edges

    def _allowed_opcodes(self) -> frozenset:
        ops = set(SUPPORTED_Z3_OPCODES)
        if self.enable_memory_theory:
            ops |= SUPPORTED_Z3_MEMORY_OPCODES
        if self.max_loop_unroll > 0:
            ops |= SUPPORTED_Z3_METADATA_OPCODES
        if self.enable_call_congruence:
            ops.add("call")
        return frozenset(ops)

    def _eval_call_uf(self, callee: str, arg_exprs: List[z3.BitVecRef]) -> z3.BitVecRef:
        bv64 = z3.BitVecSort(64)
        arity = len(arg_exprs)
        uf_name = f"uf_call_{callee}_{arity}"
        if arity == 0:
            return z3.Const(uf_name, bv64)
        uf = z3.Function(uf_name, *([bv64] * arity), bv64)
        return uf(*arg_exprs)

    def _encode_function_symbolic(
        self,
        fn: SSAFunction,
        sym_params: List[z3.BitVecRef],
        init_ext_mem: Optional[z3.ArrayRef] = None,
    ) -> Dict[str, Any]:
        """
        Symbolically executes an `SSAFunction` (acyclic, or bounded-unrolled if
        `max_loop_unroll > 0`) over `sym_params` and `init_ext_mem`.
        Returns a structured dict containing `ret_expr`, `ext_mem_expr`,
        `terminated_cond`, `bounded`, and `error`.
        """
        if not fn.blocks:
            return {"error": "EMPTY_FUNCTION"}
        if len(fn.params) != len(sym_params):
            return {"error": "PARAM_ARITY_MISMATCH"}

        entry = fn.entry_block or fn.blocks[0]
        ordered_acyclic = self._topological_blocks(fn)
        is_cyclic = ordered_acyclic is None

        if is_cyclic and self.max_loop_unroll <= 0:
            return {"error": "CYCLIC_CFG"}

        allowed_ops = self._allowed_opcodes()
        bv64 = z3.BitVecSort(64)
        base_ext_mem = init_ext_mem if init_ext_mem is not None else z3.Array("ext_mem_init", bv64, bv64)
        base_loc_mem = z3.Array(f"loc_mem_init_{fn.name}", bv64, bv64)

        if not is_cyclic:
            dag_blocks = ordered_acyclic
            back_edges: Set[Tuple[str, str]] = set()
            max_level = 0
        else:
            dag_blocks, back_edges = self._classify_cfg_dag_and_backedges(fn)
            max_level = self.max_loop_unroll

        # Node keys are `(block.name, level)` with `level in 0..max_level`.
        # Forward/cross edges preserve `level`; back-edges advance `level -> level + 1`.
        env_levels: List[Dict[SSAVar, z3.BitVecRef]] = [{} for _ in range(max_level + 1)]
        alloca_bases: Dict[SSAVar, z3.BitVecRef] = {}
        alloca_counter = 0

        block_reach: Dict[Tuple[str, int], z3.BoolRef] = {}
        edge_cond: Dict[Tuple[Tuple[str, int], Tuple[str, int]], z3.BoolRef] = {}
        node_ext_mem_out: Dict[Tuple[str, int], z3.ArrayRef] = {}
        node_loc_mem_out: Dict[Tuple[str, int], z3.ArrayRef] = {}
        ret_cases: List[Tuple[z3.BoolRef, z3.BitVecRef, z3.ArrayRef]] = []

        block_reach[(entry.name, 0)] = z3.BoolVal(True)
        # Predecessors map in the unrolled DAG: node -> list of pred_nodes
        unrolled_preds: Dict[Tuple[str, int], List[Tuple[str, int]]] = {(entry.name, 0): []}

        for lvl in range(max_level + 1):
            for blk in dag_blocks:
                node = (blk.name, lvl)
                if node != (entry.name, 0):
                    preds = unrolled_preds.get(node, [])
                    if not preds:
                        continue  # unreachable at this unroll level
                    incoming_conds = [
                        edge_cond[(pn, node)]
                        for pn in preds
                        if (pn, node) in edge_cond
                    ]
                    if not incoming_conds:
                        continue
                    block_reach[node] = (
                        incoming_conds[0] if len(incoming_conds) == 1 else z3.Or(incoming_conds)
                    )

                b_reach = block_reach[node]

                # Initialize memory states at node entry from active predecessors
                if node == (entry.name, 0):
                    cur_ext_mem = base_ext_mem
                    cur_loc_mem = base_loc_mem
                else:
                    preds = [pn for pn in unrolled_preds.get(node, []) if pn in node_ext_mem_out]
                    if not preds:
                        cur_ext_mem = base_ext_mem
                        cur_loc_mem = base_loc_mem
                    elif len(preds) == 1:
                        cur_ext_mem = node_ext_mem_out[preds[0]]
                        cur_loc_mem = node_loc_mem_out[preds[0]]
                    else:
                        cur_ext_mem = node_ext_mem_out[preds[-1]]
                        cur_loc_mem = node_loc_mem_out[preds[-1]]
                        for pn in reversed(preds[:-1]):
                            ec = edge_cond.get((pn, node), z3.BoolVal(False))
                            cur_ext_mem = z3.If(ec, node_ext_mem_out[pn], cur_ext_mem)
                            cur_loc_mem = z3.If(ec, node_loc_mem_out[pn], cur_loc_mem)

                def eval_op(op: Any, lookup_lvl: int = lvl) -> Optional[z3.BitVecRef]:
                    if isinstance(op, bool):
                        return z3.BitVecVal(int(op), 64)
                    if isinstance(op, int):
                        return z3.BitVecVal(op, 64)
                    if isinstance(op, SSAVar):
                        for search_l in range(lookup_lvl, -1, -1):
                            if op in env_levels[search_l]:
                                return env_levels[search_l][op]
                    return None

                def is_alloca_var(op: Any) -> bool:
                    return isinstance(op, SSAVar) and op in alloca_bases

                # Evaluate Phi nodes
                for phi in blk.phi_nodes:
                    if phi.result is None or not phi.phi_incoming:
                        return {"error": "INVALID_PHI"}
                    active_phi_pairs: List[Tuple[Tuple[str, int], Any]] = []
                    for pred_name, val_op in phi.phi_incoming:
                        if (pred_name, blk.name) in back_edges:
                            if lvl > 0:
                                pred_node = (pred_name, lvl - 1)
                                if (pred_node, node) in edge_cond:
                                    active_phi_pairs.append((pred_node, val_op))
                        else:
                            pred_node = (pred_name, lvl)
                            if (pred_node, node) in edge_cond:
                                active_phi_pairs.append((pred_node, val_op))

                    if not active_phi_pairs:
                        return {"error": f"UNREACHABLE_PHI_{phi.result}"}

                    acc: Optional[z3.BitVecRef] = None
                    for pred_node, val_op in reversed(active_phi_pairs):
                        v_expr = eval_op(val_op, lookup_lvl=pred_node[1])
                        if v_expr is None:
                            return {"error": f"UNRESOLVED_PHI_OP_{val_op}"}
                        if acc is None:
                            acc = v_expr
                        else:
                            ec = edge_cond.get((pred_node, node), z3.BoolVal(False))
                            acc = z3.If(ec, v_expr, acc)
                    if acc is None:
                        return {"error": "EMPTY_PHI"}
                    env_levels[lvl][phi.result] = acc

                # Evaluate instructions
                for inst in blk.instructions:
                    op = inst.opcode
                    if op not in allowed_ops:
                        return {"error": f"UNSUPPORTED_OPCODE_{op}"}

                    if op in SUPPORTED_Z3_METADATA_OPCODES:
                        continue

                    if op == "param":
                        if not inst.operands or inst.result is None:
                            return {"error": "INVALID_PARAM"}
                        raw_p = inst.operands[0]
                        if isinstance(raw_p, int):
                            p_idx = raw_p
                        elif isinstance(raw_p, str) and raw_p in fn.params:
                            p_idx = fn.params.index(raw_p)
                        else:
                            return {"error": f"UNKNOWN_PARAM_{raw_p}"}
                        if p_idx < 0 or p_idx >= len(sym_params):
                            return {"error": "PARAM_INDEX_OOB"}
                        env_levels[lvl][inst.result] = sym_params[p_idx]

                    elif op == "const":
                        if not inst.operands or inst.result is None:
                            return {"error": "INVALID_CONST"}
                        val = inst.operands[0]
                        if not isinstance(val, (int, bool)):
                            return {"error": "NON_INT_CONST"}
                        env_levels[lvl][inst.result] = z3.BitVecVal(int(val), 64)

                    elif op == "mov":
                        if not inst.operands or inst.result is None:
                            return {"error": "INVALID_MOV"}
                        src_op = inst.operands[0]
                        v = eval_op(src_op)
                        if v is None:
                            return {"error": "UNRESOLVED_MOV"}
                        env_levels[lvl][inst.result] = v
                        if is_alloca_var(src_op):
                            alloca_bases[inst.result] = alloca_bases[src_op]

                    elif op == "alloca":
                        if inst.result is None:
                            return {"error": "INVALID_ALLOCA"}
                        base_addr = z3.BitVecVal(0x4000_0000 + alloca_counter * 0x10000, 64)
                        alloca_counter += 1
                        alloca_bases[inst.result] = base_addr
                        env_levels[lvl][inst.result] = base_addr

                    elif op == "load":
                        if inst.result is None or not inst.operands:
                            return {"error": "INVALID_LOAD"}
                        ptr_op = inst.operands[0]
                        ptr_v = eval_op(ptr_op)
                        if ptr_v is None:
                            return {"error": "UNRESOLVED_LOAD_PTR"}
                        if len(inst.operands) >= 2:
                            idx_v = eval_op(inst.operands[1])
                            if idx_v is None:
                                return {"error": "UNRESOLVED_LOAD_IDX"}
                            addr = ptr_v + (idx_v << 3)
                        else:
                            addr = ptr_v
                        if is_alloca_var(ptr_op):
                            env_levels[lvl][inst.result] = z3.Select(cur_loc_mem, addr)
                        else:
                            env_levels[lvl][inst.result] = z3.Select(cur_ext_mem, addr)

                    elif op == "store":
                        if len(inst.operands) < 2:
                            return {"error": "INVALID_STORE"}
                        ptr_op = inst.operands[0]
                        ptr_v = eval_op(ptr_op)
                        if ptr_v is None:
                            return {"error": "UNRESOLVED_STORE_PTR"}
                        if len(inst.operands) >= 3:
                            idx_v = eval_op(inst.operands[1])
                            val_op = inst.operands[2]
                            if idx_v is None:
                                return {"error": "UNRESOLVED_STORE_IDX"}
                            addr = ptr_v + (idx_v << 3)
                        else:
                            val_op = inst.operands[1]
                            addr = ptr_v
                        val_v = eval_op(val_op)
                        if val_v is None:
                            return {"error": "UNRESOLVED_STORE_VAL"}
                        if is_alloca_var(val_op) and not is_alloca_var(ptr_op):
                            return {"error": "ESCAPED_ALLOCA_UNSUPPORTED"}
                        if is_alloca_var(ptr_op):
                            cur_loc_mem = z3.Store(cur_loc_mem, addr, val_v)
                        else:
                            cur_ext_mem = z3.Store(cur_ext_mem, addr, val_v)

                    elif op in ("neg", "not"):
                        if len(inst.operands) != 1 or inst.result is None:
                            return {"error": f"INVALID_{op}"}
                        if is_alloca_var(inst.operands[0]):
                            return {"error": "ESCAPED_ALLOCA_UNSUPPORTED"}
                        v = eval_op(inst.operands[0])
                        if v is None:
                            return {"error": f"UNRESOLVED_{op}"}
                        if op == "neg":
                            env_levels[lvl][inst.result] = -v
                        else:
                            env_levels[lvl][inst.result] = z3.If(v == 0, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))

                    elif op in (
                        "add", "sub", "mul", "sdiv", "srem",
                        "shl", "shr", "sar", "lshr", "and", "or", "xor",
                        "cmp_eq", "cmp_ne", "cmp_lt", "cmp_le", "cmp_gt", "cmp_ge",
                    ):
                        if len(inst.operands) != 2 or inst.result is None:
                            return {"error": f"INVALID_{op}"}
                        if is_alloca_var(inst.operands[0]) or is_alloca_var(inst.operands[1]):
                            return {"error": "ESCAPED_ALLOCA_UNSUPPORTED"}
                        v0 = eval_op(inst.operands[0])
                        v1 = eval_op(inst.operands[1])
                        if v0 is None or v1 is None:
                            return {"error": f"UNRESOLVED_{op}"}

                        if op == "add":
                            res_bv = v0 + v1
                        elif op == "sub":
                            res_bv = v0 - v1
                        elif op == "mul":
                            res_bv = v0 * v1
                        elif op == "sdiv":
                            res_bv = v0 / v1
                        elif op == "srem":
                            res_bv = z3.SRem(v0, v1)
                        elif op == "shl":
                            res_bv = v0 << v1
                        elif op == "shr" or op == "sar":
                            res_bv = v0 >> v1
                        elif op == "lshr":
                            res_bv = z3.LShR(v0, v1)
                        elif op == "and":
                            res_bv = v0 & v1
                        elif op == "or":
                            res_bv = v0 | v1
                        elif op == "xor":
                            res_bv = v0 ^ v1
                        elif op == "cmp_eq":
                            res_bv = z3.If(v0 == v1, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                        elif op == "cmp_ne":
                            res_bv = z3.If(v0 != v1, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                        elif op == "cmp_lt":
                            res_bv = z3.If(v0 < v1, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                        elif op == "cmp_le":
                            res_bv = z3.If(v0 <= v1, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                        elif op == "cmp_gt":
                            res_bv = z3.If(v0 > v1, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                        else:  # cmp_ge
                            res_bv = z3.If(v0 >= v1, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                        env_levels[lvl][inst.result] = res_bv

                    elif op == "select":
                        if len(inst.operands) != 3 or inst.result is None:
                            return {"error": "INVALID_SELECT"}
                        c = eval_op(inst.operands[0])
                        vt = eval_op(inst.operands[1])
                        vf = eval_op(inst.operands[2])
                        if c is None or vt is None or vf is None:
                            return {"error": "UNRESOLVED_SELECT"}
                        env_levels[lvl][inst.result] = z3.If(c != 0, vt, vf)

                    elif op == "call":
                        if not inst.operands:
                            return {"error": "INVALID_CALL"}
                        callee = str(inst.operands[0])
                        if callee.startswith("omni_"):
                            return {"error": f"UNSUPPORTED_IMPURE_CALL_{callee}"}
                        arg_exprs: List[z3.BitVecRef] = []
                        for a in inst.operands[1:]:
                            av = eval_op(a)
                            if av is None:
                                return {"error": f"UNRESOLVED_CALL_ARG_{callee}"}
                            arg_exprs.append(av)
                        if inst.result is not None:
                            env_levels[lvl][inst.result] = self._eval_call_uf(callee, arg_exprs)

                    elif op == "br":
                        if not inst.operands:
                            return {"error": "INVALID_BR"}
                        target = str(inst.operands[0])
                        t_lvl = lvl + 1 if (blk.name, target) in back_edges else lvl
                        if t_lvl <= max_level:
                            dst = (target, t_lvl)
                            prev = edge_cond.get((node, dst))
                            edge_cond[(node, dst)] = b_reach if prev is None else z3.Or(prev, b_reach)
                            unrolled_preds.setdefault(dst, [])
                            if node not in unrolled_preds[dst]:
                                unrolled_preds[dst].append(node)

                    elif op == "br_cond":
                        if len(inst.operands) < 3:
                            return {"error": "INVALID_BR_COND"}
                        c = eval_op(inst.operands[0])
                        if c is None:
                            return {"error": "UNRESOLVED_BR_COND"}
                        t_blk = str(inst.operands[1])
                        f_blk = str(inst.operands[2])
                        c_true = (c != 0)
                        t_cond = z3.And(b_reach, c_true)
                        f_cond = z3.And(b_reach, z3.Not(c_true))

                        t_lvl = lvl + 1 if (blk.name, t_blk) in back_edges else lvl
                        f_lvl = lvl + 1 if (blk.name, f_blk) in back_edges else lvl
                        dst_t = (t_blk, t_lvl)
                        dst_f = (f_blk, f_lvl)

                        if dst_t == dst_f:
                            if t_lvl <= max_level:
                                edge_cond[(node, dst_t)] = b_reach
                                unrolled_preds.setdefault(dst_t, [])
                                if node not in unrolled_preds[dst_t]:
                                    unrolled_preds[dst_t].append(node)
                        else:
                            if t_lvl <= max_level:
                                prev_t = edge_cond.get((node, dst_t))
                                edge_cond[(node, dst_t)] = t_cond if prev_t is None else z3.Or(prev_t, t_cond)
                                unrolled_preds.setdefault(dst_t, [])
                                if node not in unrolled_preds[dst_t]:
                                    unrolled_preds[dst_t].append(node)
                            if f_lvl <= max_level:
                                prev_f = edge_cond.get((node, dst_f))
                                edge_cond[(node, dst_f)] = f_cond if prev_f is None else z3.Or(prev_f, f_cond)
                                unrolled_preds.setdefault(dst_f, [])
                                if node not in unrolled_preds[dst_f]:
                                    unrolled_preds[dst_f].append(node)

                    elif op == "ret":
                        if not inst.operands:
                            ret_cases.append((b_reach, z3.BitVecVal(0, 64), cur_ext_mem))
                        else:
                            if is_alloca_var(inst.operands[0]):
                                return {"error": "ESCAPED_ALLOCA_UNSUPPORTED"}
                            rv = eval_op(inst.operands[0])
                            if rv is None:
                                return {"error": "UNRESOLVED_RET"}
                            ret_cases.append((b_reach, rv, cur_ext_mem))

                node_ext_mem_out[node] = cur_ext_mem
                node_loc_mem_out[node] = cur_loc_mem

        if not ret_cases:
            return {"error": "LOOP_BOUND_EXCEEDED" if is_cyclic else "NO_RETURN_FOUND"}

        comb_ret = ret_cases[-1][1]
        comb_mem = ret_cases[-1][2]
        for r_cond, r_val, r_mem in reversed(ret_cases[:-1]):
            comb_ret = z3.If(r_cond, r_val, comb_ret)
            comb_mem = z3.If(r_cond, r_mem, comb_mem)

        term_cond = ret_cases[0][0] if len(ret_cases) == 1 else z3.Or([rc[0] for rc in ret_cases])

        return {
            "error": None,
            "ret_expr": comb_ret,
            "ext_mem_expr": comb_mem,
            "terminated_cond": term_cond,
            "bounded": is_cyclic,
        }

    def encode_function_to_z3(
        self,
        fn: SSAFunction,
        sym_params: List[z3.BitVecRef],
    ) -> Tuple[Optional[z3.BitVecRef], Optional[str]]:
        """
        Symbolically executes an `SSAFunction` over `sym_params` into a
        single Z3 64-bit BitVecRef representing its return value.
        Returns `(expr, None)` on success or `(None, reason)` if unsupported/cyclic.
        """
        enc = self._encode_function_symbolic(fn, sym_params)
        if enc.get("error"):
            return None, enc["error"]
        return enc["ret_expr"], None

    def _run_dag_segment(
        self,
        fn: SSAFunction,
        blocks: List[BasicBlock],
        sym_params: List[z3.BitVecRef],
        init_env: Dict[SSAVar, z3.BitVecRef],
        init_alloca_bases: Dict[SSAVar, z3.BitVecRef],
        entry_reach: Dict[str, z3.BoolRef],
        entry_edge_conds: Dict[Tuple[str, str], z3.BoolRef],
        entry_ext_mem: Dict[str, z3.ArrayRef],
        entry_loc_mem: Dict[str, z3.ArrayRef],
        default_ext_mem: z3.ArrayRef,
        default_loc_mem: z3.ArrayRef,
        stop_targets: Set[str],
        skip_phi_blocks: Set[str],
        allow_allocas: bool = True,
        allowed_ops: Optional[frozenset] = None,
    ) -> Dict[str, Any]:
        """
        Executes a cycle-free sequence of CFG blocks in topological order,
        returning bindings, stopped boundary edges, return cases, and memory states.
        """
        ops_set = allowed_ops if allowed_ops is not None else self._allowed_opcodes()
        local_env: Dict[SSAVar, z3.BitVecRef] = dict(init_env)
        block_env: Dict[str, Dict[SSAVar, z3.BitVecRef]] = {}
        alloca_bases = dict(init_alloca_bases)
        alloca_counter = len(alloca_bases)

        block_reach: Dict[str, z3.BoolRef] = dict(entry_reach)
        edge_cond: Dict[Tuple[str, str], z3.BoolRef] = dict(entry_edge_conds)
        node_ext_mem_out: Dict[str, z3.ArrayRef] = dict(entry_ext_mem)
        node_loc_mem_out: Dict[str, z3.ArrayRef] = dict(entry_loc_mem)
        preds_map: Dict[str, List[str]] = {b.name: [] for b in blocks}
        for (src_n, dst_n) in entry_edge_conds:
            preds_map.setdefault(dst_n, [])
            if src_n not in preds_map[dst_n]:
                preds_map[dst_n].append(src_n)

        stopped_edges: List[Tuple[str, str, z3.BoolRef]] = []
        ret_cases: List[Tuple[z3.BoolRef, z3.BitVecRef, z3.ArrayRef]] = []
        wrote_ext_mem = False

        for blk in blocks:
            bname = blk.name
            if bname not in block_reach:
                preds = preds_map.get(bname, [])
                incoming = [edge_cond[(pn, bname)] for pn in preds if (pn, bname) in edge_cond]
                if not incoming:
                    continue
                block_reach[bname] = incoming[0] if len(incoming) == 1 else z3.Or(incoming)

            b_reach = block_reach[bname]
            active_preds = [pn for pn in preds_map.get(bname, []) if pn in node_ext_mem_out]
            if not active_preds:
                cur_ext_mem = default_ext_mem
                cur_loc_mem = default_loc_mem
            elif len(active_preds) == 1:
                cur_ext_mem = node_ext_mem_out[active_preds[0]]
                cur_loc_mem = node_loc_mem_out[active_preds[0]]
            else:
                cur_ext_mem = node_ext_mem_out[active_preds[-1]]
                cur_loc_mem = node_loc_mem_out[active_preds[-1]]
                for pn in reversed(active_preds[:-1]):
                    ec = edge_cond.get((pn, bname), z3.BoolVal(False))
                    cur_ext_mem = z3.If(ec, node_ext_mem_out[pn], cur_ext_mem)
                    cur_loc_mem = z3.If(ec, node_loc_mem_out[pn], cur_loc_mem)

            def eval_op(op: Any, specific_block: Optional[str] = None) -> Optional[z3.BitVecRef]:
                if isinstance(op, bool):
                    return z3.BitVecVal(int(op), 64)
                if isinstance(op, int):
                    return z3.BitVecVal(op, 64)
                if isinstance(op, SSAVar):
                    if specific_block and specific_block in block_env and op in block_env[specific_block]:
                        return block_env[specific_block][op]
                    if op in local_env:
                        return local_env[op]
                return None

            def is_alloca_var(op: Any) -> bool:
                return isinstance(op, SSAVar) and op in alloca_bases

            if bname not in skip_phi_blocks:
                for phi in blk.phi_nodes:
                    if phi.result is None or not phi.phi_incoming:
                        return {"error": "INVALID_PHI"}
                    active_pairs = [
                        (pred_n, val_op)
                        for pred_n, val_op in phi.phi_incoming
                        if (pred_n, bname) in edge_cond
                    ]
                    if not active_pairs:
                        return {"error": f"UNREACHABLE_PHI_{phi.result}"}
                    acc: Optional[z3.BitVecRef] = None
                    for pred_n, val_op in reversed(active_pairs):
                        v_expr = eval_op(val_op, specific_block=pred_n)
                        if v_expr is None:
                            return {"error": f"UNRESOLVED_PHI_OP_{val_op}"}
                        if acc is None:
                            acc = v_expr
                        else:
                            ec = edge_cond.get((pred_n, bname), z3.BoolVal(False))
                            acc = z3.If(ec, v_expr, acc)
                    if acc is None:
                        return {"error": "EMPTY_PHI"}
                    local_env[phi.result] = acc

            for inst in blk.instructions:
                op = inst.opcode
                if op not in ops_set:
                    return {"error": f"UNSUPPORTED_OPCODE_{op}"}
                if op in SUPPORTED_Z3_METADATA_OPCODES:
                    continue

                if op == "param":
                    if not inst.operands or inst.result is None:
                        return {"error": "INVALID_PARAM"}
                    raw_p = inst.operands[0]
                    if isinstance(raw_p, int):
                        p_idx = raw_p
                    elif isinstance(raw_p, str) and raw_p in fn.params:
                        p_idx = fn.params.index(raw_p)
                    else:
                        return {"error": f"UNKNOWN_PARAM_{raw_p}"}
                    if p_idx < 0 or p_idx >= len(sym_params):
                        return {"error": "PARAM_INDEX_OOB"}
                    local_env[inst.result] = sym_params[p_idx]

                elif op == "const":
                    if not inst.operands or inst.result is None:
                        return {"error": "INVALID_CONST"}
                    val = inst.operands[0]
                    if not isinstance(val, (int, bool)):
                        return {"error": "NON_INT_CONST"}
                    local_env[inst.result] = z3.BitVecVal(int(val), 64)

                elif op == "mov":
                    if not inst.operands or inst.result is None:
                        return {"error": "INVALID_MOV"}
                    src_op = inst.operands[0]
                    v = eval_op(src_op)
                    if v is None:
                        return {"error": "UNRESOLVED_MOV"}
                    local_env[inst.result] = v
                    if is_alloca_var(src_op):
                        alloca_bases[inst.result] = alloca_bases[src_op]

                elif op == "alloca":
                    if not allow_allocas:
                        return {"error": "ALLOCA_INSIDE_LOOP_UNSUPPORTED"}
                    if inst.result is None:
                        return {"error": "INVALID_ALLOCA"}
                    base_addr = z3.BitVecVal(0x4000_0000 + alloca_counter * 0x10000, 64)
                    alloca_counter += 1
                    alloca_bases[inst.result] = base_addr
                    local_env[inst.result] = base_addr

                elif op == "load":
                    if inst.result is None or not inst.operands:
                        return {"error": "INVALID_LOAD"}
                    ptr_op = inst.operands[0]
                    ptr_v = eval_op(ptr_op)
                    if ptr_v is None:
                        return {"error": "UNRESOLVED_LOAD_PTR"}
                    if len(inst.operands) >= 2:
                        idx_v = eval_op(inst.operands[1])
                        if idx_v is None:
                            return {"error": "UNRESOLVED_LOAD_IDX"}
                        addr = ptr_v + (idx_v << 3)
                    else:
                        addr = ptr_v
                    if is_alloca_var(ptr_op):
                        local_env[inst.result] = z3.Select(cur_loc_mem, addr)
                    else:
                        local_env[inst.result] = z3.Select(cur_ext_mem, addr)

                elif op == "store":
                    if len(inst.operands) < 2:
                        return {"error": "INVALID_STORE"}
                    ptr_op = inst.operands[0]
                    ptr_v = eval_op(ptr_op)
                    if ptr_v is None:
                        return {"error": "UNRESOLVED_STORE_PTR"}
                    if len(inst.operands) >= 3:
                        idx_v = eval_op(inst.operands[1])
                        val_op = inst.operands[2]
                        if idx_v is None:
                            return {"error": "UNRESOLVED_STORE_IDX"}
                        addr = ptr_v + (idx_v << 3)
                    else:
                        val_op = inst.operands[1]
                        addr = ptr_v
                    val_v = eval_op(val_op)
                    if val_v is None:
                        return {"error": "UNRESOLVED_STORE_VAL"}
                    if is_alloca_var(val_op) and not is_alloca_var(ptr_op):
                        return {"error": "ESCAPED_ALLOCA_UNSUPPORTED"}
                    if is_alloca_var(ptr_op):
                        cur_loc_mem = z3.Store(cur_loc_mem, addr, val_v)
                    else:
                        cur_ext_mem = z3.Store(cur_ext_mem, addr, val_v)
                        wrote_ext_mem = True

                elif op in ("neg", "not"):
                    if len(inst.operands) != 1 or inst.result is None:
                        return {"error": f"INVALID_{op}"}
                    if is_alloca_var(inst.operands[0]):
                        return {"error": "ESCAPED_ALLOCA_UNSUPPORTED"}
                    v = eval_op(inst.operands[0])
                    if v is None:
                        return {"error": f"UNRESOLVED_{op}"}
                    local_env[inst.result] = (
                        -v if op == "neg" else z3.If(v == 0, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                    )

                elif op in (
                    "add", "sub", "mul", "sdiv", "srem",
                    "shl", "shr", "sar", "lshr", "and", "or", "xor",
                    "cmp_eq", "cmp_ne", "cmp_lt", "cmp_le", "cmp_gt", "cmp_ge",
                ):
                    if len(inst.operands) != 2 or inst.result is None:
                        return {"error": f"INVALID_{op}"}
                    if is_alloca_var(inst.operands[0]) or is_alloca_var(inst.operands[1]):
                        return {"error": "ESCAPED_ALLOCA_UNSUPPORTED"}
                    v0 = eval_op(inst.operands[0])
                    v1 = eval_op(inst.operands[1])
                    if v0 is None or v1 is None:
                        return {"error": f"UNRESOLVED_{op}"}
                    if op == "add":
                        res_bv = v0 + v1
                    elif op == "sub":
                        res_bv = v0 - v1
                    elif op == "mul":
                        res_bv = v0 * v1
                    elif op == "sdiv":
                        res_bv = v0 / v1
                    elif op == "srem":
                        res_bv = z3.SRem(v0, v1)
                    elif op == "shl":
                        res_bv = v0 << v1
                    elif op in ("shr", "sar"):
                        res_bv = v0 >> v1
                    elif op == "lshr":
                        res_bv = z3.LShR(v0, v1)
                    elif op == "and":
                        res_bv = v0 & v1
                    elif op == "or":
                        res_bv = v0 | v1
                    elif op == "xor":
                        res_bv = v0 ^ v1
                    elif op == "cmp_eq":
                        res_bv = z3.If(v0 == v1, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                    elif op == "cmp_ne":
                        res_bv = z3.If(v0 != v1, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                    elif op == "cmp_lt":
                        res_bv = z3.If(v0 < v1, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                    elif op == "cmp_le":
                        res_bv = z3.If(v0 <= v1, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                    elif op == "cmp_gt":
                        res_bv = z3.If(v0 > v1, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                    else:
                        res_bv = z3.If(v0 >= v1, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                    local_env[inst.result] = res_bv

                elif op == "select":
                    if len(inst.operands) != 3 or inst.result is None:
                        return {"error": "INVALID_SELECT"}
                    c = eval_op(inst.operands[0])
                    vt = eval_op(inst.operands[1])
                    vf = eval_op(inst.operands[2])
                    if c is None or vt is None or vf is None:
                        return {"error": "UNRESOLVED_SELECT"}
                    local_env[inst.result] = z3.If(c != 0, vt, vf)

                elif op == "call":
                    if not inst.operands:
                        return {"error": "INVALID_CALL"}
                    callee = str(inst.operands[0])
                    if callee.startswith("omni_"):
                        return {"error": f"UNSUPPORTED_IMPURE_CALL_{callee}"}
                    arg_exprs: List[z3.BitVecRef] = []
                    for a in inst.operands[1:]:
                        av = eval_op(a)
                        if av is None:
                            return {"error": f"UNRESOLVED_CALL_ARG_{callee}"}
                        arg_exprs.append(av)
                    if inst.result is not None:
                        local_env[inst.result] = self._eval_call_uf(callee, arg_exprs)

                elif op == "br":
                    if not inst.operands:
                        return {"error": "INVALID_BR"}
                    target = str(inst.operands[0])
                    if target in stop_targets:
                        stopped_edges.append((bname, target, b_reach))
                    else:
                        prev = edge_cond.get((bname, target))
                        edge_cond[(bname, target)] = b_reach if prev is None else z3.Or(prev, b_reach)
                        preds_map.setdefault(target, [])
                        if bname not in preds_map[target]:
                            preds_map[target].append(bname)

                elif op == "br_cond":
                    if len(inst.operands) < 3:
                        return {"error": "INVALID_BR_COND"}
                    c = eval_op(inst.operands[0])
                    if c is None:
                        return {"error": "UNRESOLVED_BR_COND"}
                    t_blk = str(inst.operands[1])
                    f_blk = str(inst.operands[2])
                    c_true = (c != 0)
                    t_cond = z3.And(b_reach, c_true)
                    f_cond = z3.And(b_reach, z3.Not(c_true))
                    if t_blk == f_blk:
                        if t_blk in stop_targets:
                            stopped_edges.append((bname, t_blk, b_reach))
                        else:
                            prev = edge_cond.get((bname, t_blk))
                            edge_cond[(bname, t_blk)] = b_reach if prev is None else z3.Or(prev, b_reach)
                            preds_map.setdefault(t_blk, [])
                            if bname not in preds_map[t_blk]:
                                preds_map[t_blk].append(bname)
                    else:
                        for target_blk, cond_e in ((t_blk, t_cond), (f_blk, f_cond)):
                            if target_blk in stop_targets:
                                stopped_edges.append((bname, target_blk, cond_e))
                            else:
                                prev = edge_cond.get((bname, target_blk))
                                edge_cond[(bname, target_blk)] = cond_e if prev is None else z3.Or(prev, cond_e)
                                preds_map.setdefault(target_blk, [])
                                if bname not in preds_map[target_blk]:
                                    preds_map[target_blk].append(bname)

                elif op == "ret":
                    if not inst.operands:
                        ret_cases.append((b_reach, z3.BitVecVal(0, 64), cur_ext_mem))
                    else:
                        if is_alloca_var(inst.operands[0]):
                            return {"error": "ESCAPED_ALLOCA_UNSUPPORTED"}
                        rv = eval_op(inst.operands[0])
                        if rv is None:
                            return {"error": "UNRESOLVED_RET"}
                        ret_cases.append((b_reach, rv, cur_ext_mem))

            node_ext_mem_out[bname] = cur_ext_mem
            node_loc_mem_out[bname] = cur_loc_mem
            block_env[bname] = dict(local_env)

        return {
            "error": None,
            "env": local_env,
            "block_env": block_env,
            "alloca_bases": alloca_bases,
            "edge_cond": edge_cond,
            "ext_mem_out": node_ext_mem_out,
            "loc_mem_out": node_loc_mem_out,
            "stopped_edges": stopped_edges,
            "ret_cases": ret_cases,
            "wrote_ext_mem": wrote_ext_mem,
        }

    @staticmethod
    def _combine_ret_cases(
        ret_cases: List[Tuple[z3.BoolRef, z3.BitVecRef, z3.ArrayRef]],
        fallback_mem: z3.ArrayRef,
    ) -> Tuple[z3.BoolRef, z3.BitVecRef, z3.ArrayRef]:
        if not ret_cases:
            return z3.BoolVal(False), z3.BitVecVal(0, 64), fallback_mem
        comb_ret = ret_cases[-1][1]
        comb_mem = ret_cases[-1][2]
        for r_cond, r_val, r_mem in reversed(ret_cases[:-1]):
            comb_ret = z3.If(r_cond, r_val, comb_ret)
            comb_mem = z3.If(r_cond, r_mem, comb_mem)
        term_cond = ret_cases[0][0] if len(ret_cases) == 1 else z3.Or([rc[0] for rc in ret_cases])
        return term_cond, comb_ret, comb_mem

    def _decompose_single_natural_loop(self, fn: SSAFunction) -> Optional[Dict[str, Any]]:
        if not fn.blocks:
            return None
        entry = fn.entry_block or fn.blocks[0]
        rpo_blocks, back_edges = self._classify_cfg_dag_and_backedges(fn)
        headers = {dst for (_, dst) in back_edges}
        if len(headers) != 1:
            return None
        header_name = next(iter(headers))
        block_map = {b.name: b for b in rpo_blocks}
        if header_name not in block_map:
            return None

        # Natural loop body via reverse DFS from latches stopping at header
        loop_names: Set[str] = {header_name}
        stack = [src for (src, dst) in back_edges if dst == header_name]
        while stack:
            cur = stack.pop()
            if cur in loop_names:
                continue
            loop_names.add(cur)
            cur_blk = block_map.get(cur)
            if cur_blk:
                for p in cur_blk.predecessors:
                    if p.name not in loop_names:
                        stack.append(p.name)

        # Preheader/pre-loop blocks: blocks in RPO strictly preceding header and outside loop_names
        pre_blocks: List[BasicBlock] = []
        loop_blocks: List[BasicBlock] = []
        exit_blocks: List[BasicBlock] = []
        header_idx = next(i for i, b in enumerate(rpo_blocks) if b.name == header_name)
        for idx_b, b in enumerate(rpo_blocks):
            if b.name in loop_names:
                loop_blocks.append(b)
            elif idx_b < header_idx:
                pre_blocks.append(b)
            else:
                exit_blocks.append(b)

        # Verify exit_blocks and pre_blocks have no internal back-edges
        pre_set = {b.name for b in pre_blocks}
        exit_set = {b.name for b in exit_blocks}
        for b in exit_blocks:
            for s in b.successors:
                if s.name in loop_names or (s.name in pre_set):
                    return None
        # Also verify no back-edge inside loop_blocks targets anything other than header_name
        for (src_n, dst_n) in back_edges:
            if dst_n != header_name:
                return None

        return {
            "entry": entry,
            "header": block_map[header_name],
            "pre_blocks": pre_blocks,
            "loop_blocks": loop_blocks,
            "exit_blocks": exit_blocks,
            "loop_names": loop_names,
            "exit_names": exit_set,
        }

    def _build_symbolic_loop_phases(
        self,
        fn: SSAFunction,
        sym_params: List[z3.BitVecRef],
        init_ext_mem: z3.ArrayRef,
        tag: str,
    ) -> Optional[Dict[str, Any]]:
        decomp = self._decompose_single_natural_loop(fn)
        if decomp is None:
            return None

        bv64 = z3.BitVecSort(64)
        header: BasicBlock = decomp["header"]
        pre_blocks: List[BasicBlock] = decomp["pre_blocks"]
        loop_blocks: List[BasicBlock] = decomp["loop_blocks"]
        exit_blocks: List[BasicBlock] = decomp["exit_blocks"]
        loop_names: Set[str] = decomp["loop_names"]
        entry: BasicBlock = decomp["entry"]

        init_loc_mem = z3.Array(f"loc_mem_init_{tag}_{fn.name}", bv64, bv64)
        allowed_ops = set(self._allowed_opcodes()) | SUPPORTED_Z3_METADATA_OPCODES

        # Phase 1: Execute Preheader segment stopping at header
        if pre_blocks:
            pre_res = self._run_dag_segment(
                fn=fn,
                blocks=pre_blocks,
                sym_params=sym_params,
                init_env={},
                init_alloca_bases={},
                entry_reach={entry.name: z3.BoolVal(True)},
                entry_edge_conds={},
                entry_ext_mem={},
                entry_loc_mem={},
                default_ext_mem=init_ext_mem,
                default_loc_mem=init_loc_mem,
                stop_targets={header.name},
                skip_phi_blocks=set(),
                allow_allocas=True,
                allowed_ops=frozenset(allowed_ops),
            )
            if pre_res.get("error"):
                return None
            edges_to_header = [e for e in pre_res["stopped_edges"] if e[1] == header.name]
            if not edges_to_header:
                return None
            enter_cond = (
                edges_to_header[0][2]
                if len(edges_to_header) == 1
                else z3.Or([e[2] for e in edges_to_header])
            )
            pre_edge_map = {}
            for src_n, dst_n, ec in edges_to_header:
                prev = pre_edge_map.get((src_n, dst_n))
                pre_edge_map[(src_n, dst_n)] = ec if prev is None else z3.Or(prev, ec)

            pre_preds = [e[0] for e in edges_to_header]
            pre_ext_mem = pre_res["ext_mem_out"][pre_preds[-1]]
            pre_loc_mem = pre_res["loc_mem_out"][pre_preds[-1]]
            for pn in reversed(pre_preds[:-1]):
                ec = pre_edge_map[(pn, header.name)]
                pre_ext_mem = z3.If(ec, pre_res["ext_mem_out"][pn], pre_ext_mem)
                pre_loc_mem = z3.If(ec, pre_res["loc_mem_out"][pn], pre_loc_mem)

            def eval_pre_val(op: Any, pred_name: str) -> Optional[z3.BitVecRef]:
                if isinstance(op, bool):
                    return z3.BitVecVal(int(op), 64)
                if isinstance(op, int):
                    return z3.BitVecVal(op, 64)
                if isinstance(op, SSAVar):
                    bmap = pre_res["block_env"].get(pred_name, {})
                    if op in bmap:
                        return bmap[op]
                    return pre_res["env"].get(op)
                return None

            init_phi_vals: Dict[Tuple[str, int], z3.BitVecRef] = {}
            for phi in header.phi_nodes:
                if phi.result is None:
                    return None
                acc = None
                pre_pairs = [
                    (pn, v) for pn, v in phi.phi_incoming
                    if (pn, header.name) in pre_edge_map
                ]
                if not pre_pairs:
                    return None
                for pn, v_op in reversed(pre_pairs):
                    ve = eval_pre_val(v_op, pn)
                    if ve is None:
                        return None
                    if acc is None:
                        acc = ve
                    else:
                        acc = z3.If(pre_edge_map[(pn, header.name)], ve, acc)
                init_phi_vals[(phi.result.name, phi.result.version)] = acc

            bypass_term, bypass_ret, bypass_mem = self._combine_ret_cases(
                pre_res["ret_cases"], init_ext_mem
            )
            pre_env = pre_res["env"]
            pre_allocas = pre_res["alloca_bases"]
        else:
            enter_cond = z3.BoolVal(True)
            pre_ext_mem = init_ext_mem
            pre_loc_mem = init_loc_mem
            init_phi_vals = {}
            if header.phi_nodes:
                return None
            bypass_term = z3.BoolVal(False)
            bypass_ret = z3.BitVecVal(0, 64)
            bypass_mem = init_ext_mem
            pre_env = {}
            pre_allocas = {}

        # Phase 2: Symbolic loop header state
        phi_syms: Dict[Tuple[str, int], z3.BitVecRef] = {}
        loop_init_env = dict(pre_env)
        for phi in header.phi_nodes:
            key = (phi.result.name, phi.result.version)
            ps = z3.BitVec(f"ind_{tag}_{phi.result.name}_{phi.result.version}", 64)
            phi_syms[key] = ps
            loop_init_env[phi.result] = ps

        sym_loop_ext_mem = z3.Array(f"ind_{tag}_ext_mem", bv64, bv64)
        sym_loop_loc_mem = z3.Array(f"ind_{tag}_loc_mem", bv64, bv64)

        loop_res = self._run_dag_segment(
            fn=fn,
            blocks=loop_blocks,
            sym_params=sym_params,
            init_env=loop_init_env,
            init_alloca_bases=pre_allocas,
            entry_reach={header.name: z3.BoolVal(True)},
            entry_edge_conds={},
            entry_ext_mem={},
            entry_loc_mem={},
            default_ext_mem=sym_loop_ext_mem,
            default_loc_mem=sym_loop_loc_mem,
            stop_targets={header.name} | decomp["exit_names"],
            skip_phi_blocks={header.name},
            allow_allocas=False,
            allowed_ops=frozenset(allowed_ops),
        )
        if loop_res.get("error"):
            return None

        back_edges_list = [e for e in loop_res["stopped_edges"] if e[1] == header.name]
        exit_edges_list = [e for e in loop_res["stopped_edges"] if e[1] in decomp["exit_names"]]

        if not back_edges_list:
            return None

        back_cond_map: Dict[str, z3.BoolRef] = {}
        for src_n, _, ec in back_edges_list:
            prev = back_cond_map.get(src_n)
            back_cond_map[src_n] = ec if prev is None else z3.Or(prev, ec)

        continue_cond = (
            list(back_cond_map.values())[0]
            if len(back_cond_map) == 1
            else z3.Or(list(back_cond_map.values()))
        )

        def eval_loop_val(op: Any, pred_name: str) -> Optional[z3.BitVecRef]:
            if isinstance(op, bool):
                return z3.BitVecVal(int(op), 64)
            if isinstance(op, int):
                return z3.BitVecVal(op, 64)
            if isinstance(op, SSAVar):
                bmap = loop_res["block_env"].get(pred_name, {})
                if op in bmap:
                    return bmap[op]
                return loop_res["env"].get(op)
            return None

        next_phi_vals: Dict[Tuple[str, int], z3.BitVecRef] = {}
        for phi in header.phi_nodes:
            key = (phi.result.name, phi.result.version)
            back_pairs = [(pn, v) for pn, v in phi.phi_incoming if pn in back_cond_map]
            if not back_pairs:
                return None
            acc = None
            for pn, v_op in reversed(back_pairs):
                ve = eval_loop_val(v_op, pn)
                if ve is None:
                    return None
                if acc is None:
                    acc = ve
                else:
                    acc = z3.If(back_cond_map[pn], ve, acc)
            next_phi_vals[key] = acc

        back_preds = list(back_cond_map.keys())
        next_ext_mem = loop_res["ext_mem_out"][back_preds[-1]]
        next_loc_mem = loop_res["loc_mem_out"][back_preds[-1]]
        for pn in reversed(back_preds[:-1]):
            ec = back_cond_map[pn]
            next_ext_mem = z3.If(ec, loop_res["ext_mem_out"][pn], next_ext_mem)
            next_loc_mem = z3.If(ec, loop_res["loc_mem_out"][pn], next_loc_mem)

        early_term, early_ret, early_mem = self._combine_ret_cases(
            loop_res["ret_cases"], sym_loop_ext_mem
        )

        # Phase 3: Post-loop Exit DAG
        exit_entry_reach: Dict[str, z3.BoolRef] = {}
        exit_edge_conds: Dict[Tuple[str, str], z3.BoolRef] = {}
        exit_preds_ext: Dict[str, z3.ArrayRef] = {}
        exit_preds_loc: Dict[str, z3.ArrayRef] = {}
        leave_conds: List[z3.BoolRef] = []

        for src_n, dst_n, ec in exit_edges_list:
            leave_conds.append(ec)
            prev = exit_edge_conds.get((src_n, dst_n))
            exit_edge_conds[(src_n, dst_n)] = ec if prev is None else z3.Or(prev, ec)
            exit_preds_ext[src_n] = loop_res["ext_mem_out"][src_n]
            exit_preds_loc[src_n] = loop_res["loc_mem_out"][src_n]

        leave_cond = (
            z3.BoolVal(False)
            if not leave_conds
            else (leave_conds[0] if len(leave_conds) == 1 else z3.Or(leave_conds))
        )

        if exit_blocks and exit_edge_conds:
            exit_res = self._run_dag_segment(
                fn=fn,
                blocks=exit_blocks,
                sym_params=sym_params,
                init_env=loop_res["env"],
                init_alloca_bases=pre_allocas,
                entry_reach=exit_entry_reach,
                entry_edge_conds=exit_edge_conds,
                entry_ext_mem=exit_preds_ext,
                entry_loc_mem=exit_preds_loc,
                default_ext_mem=sym_loop_ext_mem,
                default_loc_mem=sym_loop_loc_mem,
                stop_targets=set(),
                skip_phi_blocks=set(),
                allow_allocas=False,
                allowed_ops=frozenset(allowed_ops),
            )
            if exit_res.get("error"):
                return None
            exit_term, exit_ret, exit_mem = self._combine_ret_cases(
                exit_res["ret_cases"], sym_loop_ext_mem
            )
            exit_wrote_ext = bool(exit_res["wrote_ext_mem"])
        else:
            exit_term = z3.BoolVal(False)
            exit_ret = z3.BitVecVal(0, 64)
            exit_mem = sym_loop_ext_mem
            exit_wrote_ext = False

        return {
            "enter_cond": enter_cond,
            "bypass_term": bypass_term,
            "bypass_ret": bypass_ret,
            "bypass_mem": bypass_mem,
            "pre_ext_mem": pre_ext_mem,
            "pre_loc_mem": pre_loc_mem,
            "pre_allocas_count": len(pre_allocas),
            "phi_keys": list(phi_syms.keys()),
            "init_phi_vals": init_phi_vals,
            "phi_syms": phi_syms,
            "sym_ext_mem": sym_loop_ext_mem,
            "sym_loc_mem": sym_loop_loc_mem,
            "continue_cond": continue_cond,
            "next_phi_vals": next_phi_vals,
            "next_ext_mem": next_ext_mem,
            "next_loc_mem": next_loc_mem,
            "early_term": early_term,
            "early_ret": early_ret,
            "early_mem": early_mem,
            "leave_cond": leave_cond,
            "exit_term": exit_term,
            "exit_ret": exit_ret,
            "exit_mem": exit_mem,
            "loop_writes_ext": bool(loop_res["wrote_ext_mem"]),
            "exit_writes_ext": exit_wrote_ext,
        }

    def _decompose_all_natural_loops(self, fn: SSAFunction) -> Optional[Dict[str, Any]]:
        if not fn.blocks:
            return None
        entry = fn.entry_block or fn.blocks[0]
        rpo_blocks, back_edges = self._classify_cfg_dag_and_backedges(fn)
        rpo_idx = {b.name: i for i, b in enumerate(rpo_blocks)}
        headers = sorted({dst for (_, dst) in back_edges if dst in rpo_idx}, key=lambda h: rpo_idx[h])
        if len(headers) < 2:
            return None

        block_map = {b.name: b for b in rpo_blocks}
        loop_names: Dict[str, Set[str]] = {}
        for h in headers:
            names: Set[str] = {h}
            stack = [src for (src, dst) in back_edges if dst == h]
            while stack:
                cur = stack.pop()
                if cur in names:
                    continue
                if cur not in block_map or rpo_idx[cur] < rpo_idx[h]:
                    return None
                names.add(cur)
                cur_blk = block_map[cur]
                for p in cur_blk.predecessors:
                    if p.name not in names:
                        stack.append(p.name)
            loop_names[h] = names

        # Check proper tree nesting: any pair of loops is either disjoint or strictly nested
        for i in range(len(headers)):
            for j in range(i + 1, len(headers)):
                s1 = loop_names[headers[i]]
                s2 = loop_names[headers[j]]
                if not s1.isdisjoint(s2) and not (s1 < s2 or s2 < s1):
                    return None

        return {
            "entry": entry,
            "rpo_blocks": rpo_blocks,
            "rpo_idx": rpo_idx,
            "block_map": block_map,
            "back_edges": back_edges,
            "headers": headers,
            "loop_names": loop_names,
        }

    def _pair_phi_keys(
        self,
        keys_b: List[Tuple[str, int]],
        keys_a: List[Tuple[str, int]],
    ) -> Tuple[List[Tuple[Tuple[str, int], Tuple[str, int]]], List[Tuple[str, int]], List[Tuple[str, int]]]:
        paired: List[Tuple[Tuple[str, int], Tuple[str, int]]] = []
        matched_b: Set[Tuple[str, int]] = set()
        matched_a: Set[Tuple[str, int]] = set()
        for kb in keys_b:
            if kb in keys_a:
                paired.append((kb, kb))
                matched_b.add(kb)
                matched_a.add(kb)
        rem_b = [k for k in keys_b if k not in matched_b]
        rem_a = [k for k in keys_a if k not in matched_a]
        if len(rem_b) == len(rem_a):
            for kb, ka in zip(rem_b, rem_a):
                paired.append((kb, ka))
            rem_b, rem_a = [], []
        return paired, rem_b, rem_a

    def _probe_bounded_counterexample(
        self,
        ssa_before: SSAFunction,
        ssa_after: SSAFunction,
        timeout_ms: int,
    ) -> Dict[str, Any]:
        bounded_probe = SSATranslationValidator(
            enable_memory_theory=self.enable_memory_theory,
            max_loop_unroll=max(self.max_loop_unroll, 12),
            enable_inductive_loops=False,
            enable_call_congruence=self.enable_call_congruence,
        )
        probe_res = bounded_probe.verify_equivalence(ssa_before, ssa_after, timeout_ms=timeout_ms)
        if probe_res["status"] == "REFUTED_COUNTEREXAMPLE":
            return probe_res
        return {
            "proven": False,
            "status": "UNVERIFIED_INDUCTIVE_PROOF_FAILED",
            "counterexample": None,
            "bounded": False,
        }

    @staticmethod
    def _eval_var_in_seg(seg_res: Dict[str, Any], op: Any, pred_name: str) -> Optional[z3.BitVecRef]:
        if isinstance(op, bool):
            return z3.BitVecVal(int(op), 64)
        if isinstance(op, int):
            return z3.BitVecVal(op, 64)
        if isinstance(op, SSAVar):
            bmap = seg_res["block_env"].get(pred_name, {})
            if op in bmap:
                return bmap[op]
            return seg_res["env"].get(op)
        return None

    @staticmethod
    def _extract_edge_group(
        stopped_edges: List[Tuple[str, str, z3.BoolRef]],
        target_names: Set[str],
    ) -> Tuple[Optional[z3.BoolRef], Dict[Tuple[str, str], z3.BoolRef]]:
        matching = [e for e in stopped_edges if e[1] in target_names]
        if not matching:
            return None, {}
        cond = matching[0][2] if len(matching) == 1 else z3.Or([e[2] for e in matching])
        edge_map: Dict[Tuple[str, str], z3.BoolRef] = {}
        for src_n, dst_n, ec in matching:
            prev = edge_map.get((src_n, dst_n))
            edge_map[(src_n, dst_n)] = ec if prev is None else z3.Or(prev, ec)
        return cond, edge_map

    def _collect_header_phi_values(
        self,
        header: BasicBlock,
        edge_map: Dict[Tuple[str, str], z3.BoolRef],
        seg_res: Dict[str, Any],
    ) -> Optional[Dict[Tuple[str, int], z3.BitVecRef]]:
        out: Dict[Tuple[str, int], z3.BitVecRef] = {}
        preds = [src for (src, dst) in edge_map.keys() if dst == header.name]
        for phi in header.phi_nodes:
            if phi.result is None:
                return None
            pairs = [(pn, v) for pn, v in phi.phi_incoming if (pn, header.name) in edge_map]
            if not pairs:
                return None
            acc = None
            for pn, v_op in reversed(pairs):
                ve = self._eval_var_in_seg(seg_res, v_op, pn)
                if ve is None:
                    return None
                acc = ve if acc is None else z3.If(edge_map[(pn, header.name)], ve, acc)
            out[(phi.result.name, phi.result.version)] = acc
        if not preds:
            return None
        return out

    @staticmethod
    def _merge_pred_mem(
        seg_res: Dict[str, Any],
        edge_map: Dict[Tuple[str, str], z3.BoolRef],
        dst_filter: Optional[Set[str]] = None,
    ) -> Tuple[z3.ArrayRef, z3.ArrayRef]:
        edges = [
            (src, ec)
            for (src, dst), ec in edge_map.items()
            if dst_filter is None or dst in dst_filter
        ]
        ext_m = seg_res["ext_mem_out"][edges[-1][0]]
        loc_m = seg_res["loc_mem_out"][edges[-1][0]]
        for src, ec in reversed(edges[:-1]):
            ext_m = z3.If(ec, seg_res["ext_mem_out"][src], ext_m)
            loc_m = z3.If(ec, seg_res["loc_mem_out"][src], loc_m)
        return ext_m, loc_m

    def _verify_nested_two_level_loops(
        self,
        ssa_before: SSAFunction,
        ssa_after: SSAFunction,
        db: Dict[str, Any],
        da: Dict[str, Any],
        sym_params: List[z3.BitVecRef],
        shared_ext_mem: z3.ArrayRef,
        timeout_ms: int,
    ) -> Optional[Dict[str, Any]]:
        hb_out, hb_in = db["headers"][0], db["headers"][1]
        ha_out, ha_in = da["headers"][0], da["headers"][1]
        if not (db["loop_names"][hb_in] < db["loop_names"][hb_out]):
            return None
        if not (da["loop_names"][ha_in] < da["loop_names"][ha_out]):
            return None

        bv64 = z3.BitVecSort(64)
        allowed_ops = frozenset(set(self._allowed_opcodes()) | SUPPORTED_Z3_METADATA_OPCODES)
        init_loc_b = z3.Array(f"loc_nest_init_B_{ssa_before.name}", bv64, bv64)
        init_loc_a = z3.Array(f"loc_nest_init_A_{ssa_after.name}", bv64, bv64)

        def split_nested(d: Dict[str, Any], h_out: str, h_in: str) -> Optional[Dict[str, Any]]:
            rpo = d["rpo_blocks"]
            ridx = d["rpo_idx"]
            outer_set = d["loop_names"][h_out]
            inner_set = d["loop_names"][h_in]
            pre_blocks = [b for b in rpo if ridx[b.name] < ridx[h_out] and b.name not in outer_set]
            exit_blocks = [b for b in rpo if ridx[b.name] > ridx[h_out] and b.name not in outer_set]
            out_prefix = [b for b in rpo if b.name in outer_set and b.name not in inner_set and ridx[b.name] < ridx[h_in]]
            in_blocks = [b for b in rpo if b.name in inner_set]
            out_suffix = [b for b in rpo if b.name in outer_set and b.name not in inner_set and ridx[b.name] > ridx[h_in]]
            exit_names = {b.name for b in exit_blocks}
            # Ensure no backedges jump elsewhere
            for src_n, dst_n in d["back_edges"]:
                if dst_n not in (h_out, h_in):
                    return None
                if dst_n == h_out and src_n not in outer_set:
                    return None
                if dst_n == h_in and src_n not in inner_set:
                    return None
            return {
                "entry": d["entry"],
                "h_out": d["block_map"][h_out],
                "h_in": d["block_map"][h_in],
                "pre_blocks": pre_blocks,
                "out_prefix": out_prefix,
                "in_blocks": in_blocks,
                "out_suffix": out_suffix,
                "exit_blocks": exit_blocks,
                "outer_set": outer_set,
                "inner_set": inner_set,
                "exit_names": exit_names,
                "suffix_and_exit_names": {b.name for b in out_suffix} | exit_names,
            }

        sb = split_nested(db, hb_out, hb_in)
        sa = split_nested(da, ha_out, ha_in)
        if sb is None or sa is None:
            return None

        # 1. Preheader segment -> Outer Header
        def run_pre(fn: SSAFunction, s: Dict[str, Any], init_loc: z3.ArrayRef):
            if not s["pre_blocks"]:
                if s["h_out"].phi_nodes:
                    return None
                return {
                    "enter_cond": z3.BoolVal(True),
                    "bypass_term": z3.BoolVal(False),
                    "bypass_ret": z3.BitVecVal(0, 64),
                    "bypass_mem": shared_ext_mem,
                    "pre_ext_mem": shared_ext_mem,
                    "pre_loc_mem": init_loc,
                    "init_phis": {},
                    "env": {},
                    "allocas": {},
                }
            res = self._run_dag_segment(
                fn=fn, blocks=s["pre_blocks"], sym_params=sym_params,
                init_env={}, init_alloca_bases={},
                entry_reach={s["entry"].name: z3.BoolVal(True)},
                entry_edge_conds={}, entry_ext_mem={}, entry_loc_mem={},
                default_ext_mem=shared_ext_mem, default_loc_mem=init_loc,
                stop_targets={s["h_out"].name}, skip_phi_blocks=set(),
                allow_allocas=True, allowed_ops=allowed_ops,
            )
            if res.get("error"):
                return None
            enter_c, edge_map = self._extract_edge_group(res["stopped_edges"], {s["h_out"].name})
            if enter_c is None:
                return None
            init_phis = self._collect_header_phi_values(s["h_out"], edge_map, res)
            if init_phis is None:
                return None
            pre_ext, pre_loc = self._merge_pred_mem(res, edge_map)
            b_term, b_ret, b_mem = self._combine_ret_cases(res["ret_cases"], shared_ext_mem)
            return {
                "enter_cond": enter_c,
                "bypass_term": b_term,
                "bypass_ret": b_ret,
                "bypass_mem": b_mem,
                "pre_ext_mem": pre_ext,
                "pre_loc_mem": pre_loc,
                "init_phis": init_phis,
                "env": res["env"],
                "allocas": res["alloca_bases"],
            }

        pre_b = run_pre(ssa_before, sb, init_loc_b)
        pre_a = run_pre(ssa_after, sa, init_loc_a)
        if pre_b is None or pre_a is None:
            return None

        out_pairs, out_rem_b, out_rem_a = self._pair_phi_keys(
            list(pre_b["init_phis"].keys()), list(pre_a["init_phis"].keys())
        )

        # Symbolic outer header phis & memory
        sym_out_b = {k: z3.BitVec(f"nest_out_B_{k[0]}_{k[1]}", 64) for k in pre_b["init_phis"]}
        sym_out_a = {k: z3.BitVec(f"nest_out_A_{k[0]}_{k[1]}", 64) for k in pre_a["init_phis"]}
        sym_out_ext_b = z3.Array("nest_out_ext_B", bv64, bv64)
        sym_out_ext_a = z3.Array("nest_out_ext_A", bv64, bv64)
        sym_out_loc_b = z3.Array("nest_out_loc_B", bv64, bv64)
        sym_out_loc_a = z3.Array("nest_out_loc_A", bv64, bv64)

        def make_out_inv(sb_map, sa_map, mb, ma, lb, la) -> z3.BoolRef:
            cl = [mb == ma]
            if len(pre_b["allocas"]) == len(pre_a["allocas"]) and len(pre_b["allocas"]) > 0:
                cl.append(lb == la)
            for kb, ka in out_pairs:
                cl.append(sb_map[kb] == sa_map[ka])
            for kb in out_rem_b:
                cl.append(sb_map[kb] == pre_b["init_phis"][kb])
            for ka in out_rem_a:
                cl.append(sa_map[ka] == pre_a["init_phis"][ka])
            return z3.And(cl)

        # 2. Run Outer Prefix up to Inner Header (and Outer Exit)
        def run_out_prefix(fn: SSAFunction, s: Dict[str, Any], pre: Dict[str, Any], sym_phi: Dict[Tuple[str, int], z3.BitVecRef], sym_ext: z3.ArrayRef, sym_loc: z3.ArrayRef):
            init_env = dict(pre["env"])
            for phi in s["h_out"].phi_nodes:
                init_env[phi.result] = sym_phi[(phi.result.name, phi.result.version)]
            res = self._run_dag_segment(
                fn=fn, blocks=s["out_prefix"], sym_params=sym_params,
                init_env=init_env, init_alloca_bases=pre["allocas"],
                entry_reach={s["h_out"].name: z3.BoolVal(True)},
                entry_edge_conds={}, entry_ext_mem={}, entry_loc_mem={},
                default_ext_mem=sym_ext, default_loc_mem=sym_loc,
                stop_targets={s["h_in"].name} | s["exit_names"],
                skip_phi_blocks={s["h_out"].name},
                allow_allocas=False, allowed_ops=allowed_ops,
            )
            if res.get("error"):
                return None
            return res

        pref_b = run_out_prefix(ssa_before, sb, pre_b, sym_out_b, sym_out_ext_b, sym_out_loc_b)
        pref_a = run_out_prefix(ssa_after, sa, pre_a, sym_out_a, sym_out_ext_a, sym_out_loc_a)
        if pref_b is None or pref_a is None:
            return None

        in_enter_b, in_pre_edges_b = self._extract_edge_group(pref_b["stopped_edges"], {sb["h_in"].name})
        in_enter_a, in_pre_edges_a = self._extract_edge_group(pref_a["stopped_edges"], {sa["h_in"].name})
        if in_enter_b is None or in_enter_a is None:
            return None

        init_in_b = self._collect_header_phi_values(sb["h_in"], in_pre_edges_b, pref_b)
        init_in_a = self._collect_header_phi_values(sa["h_in"], in_pre_edges_a, pref_a)
        if init_in_b is None or init_in_a is None:
            return None

        pre_in_ext_b, pre_in_loc_b = self._merge_pred_mem(pref_b, in_pre_edges_b)
        pre_in_ext_a, pre_in_loc_a = self._merge_pred_mem(pref_a, in_pre_edges_a)

        in_pairs, in_rem_b, in_rem_a = self._pair_phi_keys(list(init_in_b.keys()), list(init_in_a.keys()))

        # 3. Inner Loop Symbolic Step Execution
        sym_in_b = {k: z3.BitVec(f"nest_in_B_{k[0]}_{k[1]}", 64) for k in init_in_b}
        sym_in_a = {k: z3.BitVec(f"nest_in_A_{k[0]}_{k[1]}", 64) for k in init_in_a}
        sym_in_ext_b = z3.Array("nest_in_ext_B", bv64, bv64)
        sym_in_ext_a = z3.Array("nest_in_ext_A", bv64, bv64)
        sym_in_loc_b = z3.Array("nest_in_loc_B", bv64, bv64)
        sym_in_loc_a = z3.Array("nest_in_loc_A", bv64, bv64)

        def run_in_body(fn: SSAFunction, s: Dict[str, Any], pref: Dict[str, Any], pre: Dict[str, Any], sym_in: Dict[Tuple[str, int], z3.BitVecRef], sym_ext: z3.ArrayRef, sym_loc: z3.ArrayRef):
            init_env = dict(pref["env"])
            for phi in s["h_in"].phi_nodes:
                init_env[phi.result] = sym_in[(phi.result.name, phi.result.version)]
            res = self._run_dag_segment(
                fn=fn, blocks=s["in_blocks"], sym_params=sym_params,
                init_env=init_env, init_alloca_bases=pre["allocas"],
                entry_reach={s["h_in"].name: z3.BoolVal(True)},
                entry_edge_conds={}, entry_ext_mem={}, entry_loc_mem={},
                default_ext_mem=sym_ext, default_loc_mem=sym_loc,
                stop_targets={s["h_in"].name} | s["suffix_and_exit_names"],
                skip_phi_blocks={s["h_in"].name},
                allow_allocas=False, allowed_ops=allowed_ops,
            )
            if res.get("error"):
                return None
            return res

        in_body_b = run_in_body(ssa_before, sb, pref_b, pre_b, sym_in_b, sym_in_ext_b, sym_in_loc_b)
        in_body_a = run_in_body(ssa_after, sa, pref_a, pre_a, sym_in_a, sym_in_ext_a, sym_in_loc_a)
        if in_body_b is None or in_body_a is None:
            return None

        in_cont_b, in_back_edges_b = self._extract_edge_group(in_body_b["stopped_edges"], {sb["h_in"].name})
        in_cont_a, in_back_edges_a = self._extract_edge_group(in_body_a["stopped_edges"], {sa["h_in"].name})
        if in_cont_b is None or in_cont_a is None:
            return None

        next_in_b = self._collect_header_phi_values(sb["h_in"], in_back_edges_b, in_body_b)
        next_in_a = self._collect_header_phi_values(sa["h_in"], in_back_edges_a, in_body_a)
        if next_in_b is None or next_in_a is None:
            return None

        next_in_ext_b, next_in_loc_b = self._merge_pred_mem(in_body_b, in_back_edges_b)
        next_in_ext_a, next_in_loc_a = self._merge_pred_mem(in_body_a, in_back_edges_a)
        in_early_tb, in_early_rb, in_early_mb = self._combine_ret_cases(in_body_b["ret_cases"], sym_in_ext_b)
        in_early_ta, in_early_ra, in_early_ma = self._combine_ret_cases(in_body_a["ret_cases"], sym_in_ext_a)

        in_leave_b, in_exit_edges_b = self._extract_edge_group(in_body_b["stopped_edges"], sb["suffix_and_exit_names"])
        in_leave_a, in_exit_edges_a = self._extract_edge_group(in_body_a["stopped_edges"], sa["suffix_and_exit_names"])
        if in_leave_b is None:
            in_leave_b = z3.BoolVal(False)
        if in_leave_a is None:
            in_leave_a = z3.BoolVal(False)

        in_read_only = (not in_body_b["wrote_ext_mem"]) and (not in_body_a["wrote_ext_mem"])

        def make_in_inv(ib, ia, mb, ma, lb, la) -> z3.BoolRef:
            cl = [mb == ma]
            if len(pre_b["allocas"]) == len(pre_a["allocas"]) and len(pre_b["allocas"]) > 0:
                cl.append(lb == la)
            for kb, ka in in_pairs:
                cl.append(ib[kb] == ia[ka])
            for kb in in_rem_b:
                cl.append(ib[kb] == init_in_b[kb])
            for ka in in_rem_a:
                cl.append(ia[ka] == init_in_a[ka])
            if in_read_only:
                cl.append(mb == pre_in_ext_b)
                cl.append(ma == pre_in_ext_a)
            return z3.And(cl)

        # Obligation A: Outer Preheader + Outer Base
        out_base_assume = z3.And(
            pre_b["enter_cond"] == pre_a["enter_cond"],
            z3.Implies(
                z3.Not(pre_b["enter_cond"]),
                z3.And(
                    pre_b["bypass_term"] == pre_a["bypass_term"],
                    z3.Implies(
                        pre_b["bypass_term"],
                        z3.And(
                            pre_b["bypass_ret"] == pre_a["bypass_ret"],
                            pre_b["bypass_mem"] == pre_a["bypass_mem"],
                        ),
                    ),
                ),
            ),
            z3.Implies(
                pre_b["enter_cond"],
                make_out_inv(
                    pre_b["init_phis"], pre_a["init_phis"],
                    pre_b["pre_ext_mem"], pre_a["pre_ext_mem"],
                    pre_b["pre_loc_mem"], pre_a["pre_loc_mem"],
                ),
            ),
        )
        s_base = z3.Solver()
        s_base.set("timeout", timeout_ms)
        s_base.add(z3.Not(out_base_assume))
        if s_base.check() != z3.unsat:
            return self._probe_bounded_counterexample(ssa_before, ssa_after, timeout_ms)

        # Obligation B: Outer Inv => (Inner Entry Lockstep & Inner Base) AND (Outer+Inner Inv => Inner Step)
        outer_rel_assume = make_out_inv(sym_out_b, sym_out_a, sym_out_ext_b, sym_out_ext_a, sym_out_loc_b, sym_out_loc_a)
        in_base_goal = z3.And(
            in_enter_b == in_enter_a,
            z3.Implies(
                in_enter_b,
                make_in_inv(init_in_b, init_in_a, pre_in_ext_b, pre_in_ext_a, pre_in_loc_b, pre_in_loc_a),
            ),
        )
        s_in_base = z3.Solver()
        s_in_base.set("timeout", timeout_ms)
        s_in_base.add(z3.And(outer_rel_assume, z3.Not(in_base_goal)))
        if s_in_base.check() != z3.unsat:
            return self._probe_bounded_counterexample(ssa_before, ssa_after, timeout_ms)

        in_step_assume = z3.And(
            outer_rel_assume,
            in_enter_b,
            make_in_inv(sym_in_b, sym_in_a, sym_in_ext_b, sym_in_ext_a, sym_in_loc_b, sym_in_loc_a),
        )
        in_step_goal = z3.And(
            in_cont_b == in_cont_a,
            in_early_tb == in_early_ta,
            z3.Implies(
                in_early_tb,
                z3.And(in_early_rb == in_early_ra, in_early_mb == in_early_ma),
            ),
            z3.Implies(
                in_cont_b,
                make_in_inv(next_in_b, next_in_a, next_in_ext_b, next_in_ext_a, next_in_loc_b, next_in_loc_a),
            ),
            in_leave_b == in_leave_a,
        )
        s_in_step = z3.Solver()
        s_in_step.set("timeout", timeout_ms)
        s_in_step.add(z3.And(in_step_assume, z3.Not(in_step_goal)))
        if s_in_step.check() != z3.unsat:
            return self._probe_bounded_counterexample(ssa_before, ssa_after, timeout_ms)

        # 4. Inner Loop Proven Equivalent -> Summarize post-inner exit state equally into Outer Suffix!
        shared_post_in_ext = pre_in_ext_b if in_read_only else z3.Array("nest_post_in_ext", bv64, bv64)
        shared_post_in_ext_a = pre_in_ext_a if in_read_only else shared_post_in_ext
        no_loc = (len(pre_b["allocas"]) == 0 and len(pre_a["allocas"]) == 0)
        shared_post_in_loc = pre_in_loc_b if no_loc else z3.Array("nest_post_in_loc", bv64, bv64)
        shared_post_in_loc_a = pre_in_loc_a if no_loc else shared_post_in_loc

        post_in_syms_b: Dict[Tuple[str, int], z3.BitVecRef] = {}
        post_in_syms_a: Dict[Tuple[str, int], z3.BitVecRef] = {}
        for idx_p, (kb, ka) in enumerate(in_pairs):
            sv = z3.BitVec(f"nest_post_in_{idx_p}_{kb[0]}_{kb[1]}", 64)
            post_in_syms_b[kb] = sv
            post_in_syms_a[ka] = sv
        for kb in in_rem_b:
            post_in_syms_b[kb] = init_in_b[kb]
        for ka in in_rem_a:
            post_in_syms_a[ka] = init_in_a[ka]

        def run_out_suffix_and_exit(
            fn: SSAFunction,
            s: Dict[str, Any],
            pre: Dict[str, Any],
            pref: Dict[str, Any],
            post_in_syms: Dict[Tuple[str, int], z3.BitVecRef],
            post_ext: z3.ArrayRef,
            post_loc: z3.ArrayRef,
            in_exit_edges: Dict[Tuple[str, str], z3.BoolRef],
            sym_out_ext: z3.ArrayRef,
            sym_out_loc: z3.ArrayRef,
        ):
            suf_env = dict(pref["env"])
            for phi in s["h_in"].phi_nodes:
                suf_env[phi.result] = post_in_syms[(phi.result.name, phi.result.version)]
            # Collapse inner-exit edges conditioned on `in_enter` (since `leave` happens only when `in` was entered)
            suf_edges = {e: z3.BoolVal(True) for e in in_exit_edges.keys() if e[1] in {b.name for b in s["out_suffix"]}}
            suf_reach: Dict[str, z3.BoolRef] = {}
            suf_ext = {src: post_ext for (src, _) in suf_edges.keys()}
            suf_loc = {src: post_loc for (src, _) in suf_edges.keys()}

            if s["out_suffix"] and suf_edges:
                suf_res = self._run_dag_segment(
                    fn=fn, blocks=s["out_suffix"], sym_params=sym_params,
                    init_env=suf_env, init_alloca_bases=pre["allocas"],
                    entry_reach=suf_reach, entry_edge_conds=suf_edges,
                    entry_ext_mem=suf_ext, entry_loc_mem=suf_loc,
                    default_ext_mem=post_ext, default_loc_mem=post_loc,
                    stop_targets={s["h_out"].name} | s["exit_names"],
                    skip_phi_blocks=set(), allow_allocas=False, allowed_ops=allowed_ops,
                )
                if suf_res.get("error"):
                    return None
                back_c, back_edges_out = self._extract_edge_group(suf_res["stopped_edges"], {s["h_out"].name})
                if back_c is None:
                    return None
                # Actual continue cond of outer loop requires entering inner & completing suffix back to h_out
                actual_back_edges = {k: z3.And(in_enter_b if fn is ssa_before else in_enter_a, v) for k, v in back_edges_out.items()}
                next_out = self._collect_header_phi_values(s["h_out"], actual_back_edges, suf_res)
                if next_out is None:
                    return None
                next_out_ext, next_out_loc = self._merge_pred_mem(suf_res, actual_back_edges)
                early_t, early_r, early_m = self._combine_ret_cases(suf_res["ret_cases"], post_ext)
            else:
                return None

            # Outer exits: combine exit edges from out_prefix & out_suffix
            leave_conds: List[z3.BoolRef] = []
            exit_edge_conds: Dict[Tuple[str, str], z3.BoolRef] = {}
            exit_ext: Dict[str, z3.ArrayRef] = {}
            exit_loc: Dict[str, z3.ArrayRef] = {}
            for src_n, dst_n, ec in pref["stopped_edges"]:
                if dst_n in s["exit_names"]:
                    leave_conds.append(ec)
                    prev = exit_edge_conds.get((src_n, dst_n))
                    exit_edge_conds[(src_n, dst_n)] = ec if prev is None else z3.Or(prev, ec)
                    exit_ext[src_n] = pref["ext_mem_out"][src_n]
                    exit_loc[src_n] = pref["loc_mem_out"][src_n]
            for src_n, dst_n, ec in suf_res["stopped_edges"]:
                if dst_n in s["exit_names"]:
                    c_eff = z3.And(in_enter_b if fn is ssa_before else in_enter_a, ec)
                    leave_conds.append(c_eff)
                    prev = exit_edge_conds.get((src_n, dst_n))
                    exit_edge_conds[(src_n, dst_n)] = c_eff if prev is None else z3.Or(prev, c_eff)
                    exit_ext[src_n] = suf_res["ext_mem_out"][src_n]
                    exit_loc[src_n] = suf_res["loc_mem_out"][src_n]

            leave_c = z3.BoolVal(False) if not leave_conds else (leave_conds[0] if len(leave_conds) == 1 else z3.Or(leave_conds))
            if s["exit_blocks"] and exit_edge_conds:
                exit_env = dict(pref["env"])
                exit_env.update(suf_res["env"])
                ex_res = self._run_dag_segment(
                    fn=fn, blocks=s["exit_blocks"], sym_params=sym_params,
                    init_env=exit_env, init_alloca_bases=pre["allocas"],
                    entry_reach={}, entry_edge_conds=exit_edge_conds,
                    entry_ext_mem=exit_ext, entry_loc_mem=exit_loc,
                    default_ext_mem=sym_out_ext, default_loc_mem=sym_out_loc,
                    stop_targets=set(), skip_phi_blocks=set(),
                    allow_allocas=False, allowed_ops=allowed_ops,
                )
                if ex_res.get("error"):
                    return None
                ex_t, ex_r, ex_m = self._combine_ret_cases(ex_res["ret_cases"], sym_out_ext)
            else:
                ex_t, ex_r, ex_m = z3.BoolVal(False), z3.BitVecVal(0, 64), sym_out_ext

            return {
                "cont": z3.And(in_enter_b if fn is ssa_before else in_enter_a, back_c),
                "next_phis": next_out,
                "next_ext": next_out_ext,
                "next_loc": next_out_loc,
                "early_term": early_t,
                "early_ret": early_r,
                "early_mem": early_m,
                "leave": leave_c,
                "exit_term": ex_t,
                "exit_ret": ex_r,
                "exit_mem": ex_m,
            }

        end_b = run_out_suffix_and_exit(
            ssa_before, sb, pre_b, pref_b, post_in_syms_b,
            shared_post_in_ext, shared_post_in_loc, in_exit_edges_b, sym_out_ext_b, sym_out_loc_b
        )
        end_a = run_out_suffix_and_exit(
            ssa_after, sa, pre_a, pref_a, post_in_syms_a,
            shared_post_in_ext_a, shared_post_in_loc_a, in_exit_edges_a, sym_out_ext_a, sym_out_loc_a
        )
        if end_b is None or end_a is None:
            return None

        out_step_goal = z3.And(
            end_b["cont"] == end_a["cont"],
            end_b["early_term"] == end_a["early_term"],
            z3.Implies(
                end_b["early_term"],
                z3.And(end_b["early_ret"] == end_a["early_ret"], end_b["early_mem"] == end_a["early_mem"]),
            ),
            z3.Implies(
                end_b["cont"],
                make_out_inv(
                    end_b["next_phis"], end_a["next_phis"],
                    end_b["next_ext"], end_a["next_ext"],
                    end_b["next_loc"], end_a["next_loc"],
                ),
            ),
            end_b["leave"] == end_a["leave"],
            z3.Implies(
                end_b["leave"],
                z3.And(
                    end_b["exit_term"] == end_a["exit_term"],
                    z3.Implies(
                        end_b["exit_term"],
                        z3.And(end_b["exit_ret"] == end_a["exit_ret"], end_b["exit_mem"] == end_a["exit_mem"]),
                    ),
                ),
            ),
        )
        s_out_step = z3.Solver()
        s_out_step.set("timeout", timeout_ms)
        s_out_step.add(z3.And(outer_rel_assume, z3.Not(out_step_goal)))
        if s_out_step.check() == z3.unsat:
            return {
                "proven": True,
                "status": "PROVEN_INDUCTIVE_EQUIVALENT",
                "counterexample": None,
                "bounded": False,
            }
        return self._probe_bounded_counterexample(ssa_before, ssa_after, timeout_ms)

    def _verify_sequential_multi_loops(
        self,
        ssa_before: SSAFunction,
        ssa_after: SSAFunction,
        db: Dict[str, Any],
        da: Dict[str, Any],
        sym_params: List[z3.BitVecRef],
        shared_ext_mem: z3.ArrayRef,
        timeout_ms: int,
    ) -> Optional[Dict[str, Any]]:
        hb_list = db["headers"]
        ha_list = da["headers"]
        if len(hb_list) != len(ha_list):
            return None
        for i in range(len(hb_list)):
            for j in range(i + 1, len(hb_list)):
                if not db["loop_names"][hb_list[i]].isdisjoint(db["loop_names"][hb_list[j]]):
                    return None
                if not da["loop_names"][ha_list[i]].isdisjoint(da["loop_names"][ha_list[j]]):
                    return None

        bv64 = z3.BitVecSort(64)
        allowed_ops = frozenset(set(self._allowed_opcodes()) | SUPPORTED_Z3_METADATA_OPCODES)
        init_loc_b = z3.Array(f"loc_seq_init_B_{ssa_before.name}", bv64, bv64)
        init_loc_a = z3.Array(f"loc_seq_init_A_{ssa_after.name}", bv64, bv64)

        cur_reach_b = {db["entry"].name: z3.BoolVal(True)}
        cur_reach_a = {da["entry"].name: z3.BoolVal(True)}
        cur_edges_b: Dict[Tuple[str, str], z3.BoolRef] = {}
        cur_edges_a: Dict[Tuple[str, str], z3.BoolRef] = {}
        cur_edge_ext_b: Dict[str, z3.ArrayRef] = {}
        cur_edge_ext_a: Dict[str, z3.ArrayRef] = {}
        cur_edge_loc_b: Dict[str, z3.ArrayRef] = {}
        cur_edge_loc_a: Dict[str, z3.ArrayRef] = {}
        cur_ext_b, cur_ext_a = shared_ext_mem, shared_ext_mem
        cur_loc_b, cur_loc_a = init_loc_b, init_loc_a
        cur_env_b: Dict[SSAVar, z3.BitVecRef] = {}
        cur_env_a: Dict[SSAVar, z3.BitVecRef] = {}
        cur_alloc_b: Dict[SSAVar, z3.BitVecRef] = {}
        cur_alloc_a: Dict[SSAVar, z3.BitVecRef] = {}
        prev_pos_b = -1
        prev_pos_a = -1
        seen_loops_b: Set[str] = set()
        seen_loops_a: Set[str] = set()

        for idx, (hb, ha) in enumerate(zip(hb_list, ha_list)):
            hb_idx = db["rpo_idx"][hb]
            ha_idx = da["rpo_idx"][ha]
            loop_b_set = db["loop_names"][hb]
            loop_a_set = da["loop_names"][ha]
            pre_blocks_b = [
                b for b in db["rpo_blocks"]
                if prev_pos_b < db["rpo_idx"][b.name] < hb_idx
                and b.name not in loop_b_set
                and b.name not in seen_loops_b
            ]
            pre_blocks_a = [
                b for b in da["rpo_blocks"]
                if prev_pos_a < da["rpo_idx"][b.name] < ha_idx
                and b.name not in loop_a_set
                and b.name not in seen_loops_a
            ]

            # Bridge / preheader up to loop idx header
            pre_res_b = self._run_dag_segment(
                fn=ssa_before, blocks=pre_blocks_b, sym_params=sym_params,
                init_env=cur_env_b, init_alloca_bases=cur_alloc_b,
                entry_reach=cur_reach_b, entry_edge_conds=cur_edges_b,
                entry_ext_mem=cur_edge_ext_b, entry_loc_mem=cur_edge_loc_b,
                default_ext_mem=cur_ext_b, default_loc_mem=cur_loc_b,
                stop_targets={hb}, skip_phi_blocks=set(),
                allow_allocas=(idx == 0), allowed_ops=allowed_ops,
            )
            pre_res_a = self._run_dag_segment(
                fn=ssa_after, blocks=pre_blocks_a, sym_params=sym_params,
                init_env=cur_env_a, init_alloca_bases=cur_alloc_a,
                entry_reach=cur_reach_a, entry_edge_conds=cur_edges_a,
                entry_ext_mem=cur_edge_ext_a, entry_loc_mem=cur_edge_loc_a,
                default_ext_mem=cur_ext_a, default_loc_mem=cur_loc_a,
                stop_targets={ha}, skip_phi_blocks=set(),
                allow_allocas=(idx == 0), allowed_ops=allowed_ops,
            )
            if pre_res_b.get("error") or pre_res_a.get("error"):
                return None

            enter_b, pre_em_b = self._extract_edge_group(pre_res_b["stopped_edges"], {hb})
            enter_a, pre_em_a = self._extract_edge_group(pre_res_a["stopped_edges"], {ha})
            if enter_b is None or enter_a is None:
                return None

            hb_blk = db["block_map"][hb]
            ha_blk = da["block_map"][ha]
            init_phi_b = self._collect_header_phi_values(hb_blk, pre_em_b, pre_res_b)
            init_phi_a = self._collect_header_phi_values(ha_blk, pre_em_a, pre_res_a)
            if init_phi_b is None or init_phi_a is None:
                return None

            pre_ext_b, pre_loc_b = self._merge_pred_mem(pre_res_b, pre_em_b)
            pre_ext_a, pre_loc_a = self._merge_pred_mem(pre_res_a, pre_em_a)
            bt_b, br_b, bm_b = self._combine_ret_cases(pre_res_b["ret_cases"], cur_ext_b)
            bt_a, br_a, bm_a = self._combine_ret_cases(pre_res_a["ret_cases"], cur_ext_a)

            if idx == 0:
                cur_alloc_b = pre_res_b["alloca_bases"]
                cur_alloc_a = pre_res_a["alloca_bases"]

            pairs, rem_b, rem_a = self._pair_phi_keys(list(init_phi_b.keys()), list(init_phi_a.keys()))
            sym_b = {k: z3.BitVec(f"seq_{idx}_B_{k[0]}_{k[1]}", 64) for k in init_phi_b}
            sym_a = {k: z3.BitVec(f"seq_{idx}_A_{k[0]}_{k[1]}", 64) for k in init_phi_a}
            sym_ext_b = z3.Array(f"seq_{idx}_ext_B", bv64, bv64)
            sym_ext_a = z3.Array(f"seq_{idx}_ext_A", bv64, bv64)
            sym_loc_b = z3.Array(f"seq_{idx}_loc_B", bv64, bv64)
            sym_loc_a = z3.Array(f"seq_{idx}_loc_A", bv64, bv64)

            next_start_b = hb_idx
            next_start_a = ha_idx
            seen_loops_b |= loop_b_set
            seen_loops_a |= loop_a_set
            after_b = {
                b.name for b in db["rpo_blocks"]
                if db["rpo_idx"][b.name] > hb_idx and b.name not in seen_loops_b
            }
            after_a = {
                b.name for b in da["rpo_blocks"]
                if da["rpo_idx"][b.name] > ha_idx and b.name not in seen_loops_a
            }

            l_env_b = dict(pre_res_b["env"])
            for phi in hb_blk.phi_nodes:
                l_env_b[phi.result] = sym_b[(phi.result.name, phi.result.version)]
            l_env_a = dict(pre_res_a["env"])
            for phi in ha_blk.phi_nodes:
                l_env_a[phi.result] = sym_a[(phi.result.name, phi.result.version)]

            loop_b_blocks = [b for b in db["rpo_blocks"] if b.name in loop_b_set]
            loop_a_blocks = [b for b in da["rpo_blocks"] if b.name in loop_a_set]
            l_res_b = self._run_dag_segment(
                fn=ssa_before, blocks=loop_b_blocks, sym_params=sym_params,
                init_env=l_env_b, init_alloca_bases=cur_alloc_b,
                entry_reach={hb: z3.BoolVal(True)}, entry_edge_conds={},
                entry_ext_mem={}, entry_loc_mem={},
                default_ext_mem=sym_ext_b, default_loc_mem=sym_loc_b,
                stop_targets={hb} | after_b, skip_phi_blocks={hb},
                allow_allocas=False, allowed_ops=allowed_ops,
            )
            l_res_a = self._run_dag_segment(
                fn=ssa_after, blocks=loop_a_blocks, sym_params=sym_params,
                init_env=l_env_a, init_alloca_bases=cur_alloc_a,
                entry_reach={ha: z3.BoolVal(True)}, entry_edge_conds={},
                entry_ext_mem={}, entry_loc_mem={},
                default_ext_mem=sym_ext_a, default_loc_mem=sym_loc_a,
                stop_targets={ha} | after_a, skip_phi_blocks={ha},
                allow_allocas=False, allowed_ops=allowed_ops,
            )
            if l_res_b.get("error") or l_res_a.get("error"):
                return None

            cont_b, back_b = self._extract_edge_group(l_res_b["stopped_edges"], {hb})
            cont_a, back_a = self._extract_edge_group(l_res_a["stopped_edges"], {ha})
            if cont_b is None or cont_a is None:
                return None
            next_phi_b = self._collect_header_phi_values(hb_blk, back_b, l_res_b)
            next_phi_a = self._collect_header_phi_values(ha_blk, back_a, l_res_a)
            if next_phi_b is None or next_phi_a is None:
                return None

            next_ext_b, next_loc_b = self._merge_pred_mem(l_res_b, back_b)
            next_ext_a, next_loc_a = self._merge_pred_mem(l_res_a, back_a)
            et_b, er_b, em_b = self._combine_ret_cases(l_res_b["ret_cases"], sym_ext_b)
            et_a, er_a, em_a = self._combine_ret_cases(l_res_a["ret_cases"], sym_ext_a)
            leave_b, leave_em_b = self._extract_edge_group(l_res_b["stopped_edges"], after_b)
            leave_a, leave_em_a = self._extract_edge_group(l_res_a["stopped_edges"], after_a)
            if leave_b is None:
                leave_b = z3.BoolVal(False)
            if leave_a is None:
                leave_a = z3.BoolVal(False)

            read_only = (not l_res_b["wrote_ext_mem"]) and (not l_res_a["wrote_ext_mem"])

            def make_inv(mb_map, ma_map, eb, ea, lb, la) -> z3.BoolRef:
                cl = [eb == ea]
                if len(cur_alloc_b) == len(cur_alloc_a) and len(cur_alloc_b) > 0:
                    cl.append(lb == la)
                for kb, ka in pairs:
                    cl.append(mb_map[kb] == ma_map[ka])
                for kb in rem_b:
                    cl.append(mb_map[kb] == init_phi_b[kb])
                for ka in rem_a:
                    cl.append(ma_map[ka] == init_phi_a[ka])
                if read_only:
                    cl.append(eb == pre_ext_b)
                    cl.append(ea == pre_ext_a)
                return z3.And(cl)

            base_goal = z3.And(
                enter_b == enter_a,
                z3.Implies(z3.Not(enter_b), z3.And(bt_b == bt_a, z3.Implies(bt_b, z3.And(br_b == br_a, bm_b == bm_a)))),
                z3.Implies(enter_b, make_inv(init_phi_b, init_phi_a, pre_ext_b, pre_ext_a, pre_loc_b, pre_loc_a)),
            )
            sb_solver = z3.Solver()
            sb_solver.set("timeout", timeout_ms)
            sb_solver.add(z3.Not(base_goal))
            if sb_solver.check() != z3.unsat:
                return self._probe_bounded_counterexample(ssa_before, ssa_after, timeout_ms)

            step_goal = z3.And(
                cont_b == cont_a,
                et_b == et_a,
                z3.Implies(et_b, z3.And(er_b == er_a, em_b == em_a)),
                z3.Implies(cont_b, make_inv(next_phi_b, next_phi_a, next_ext_b, next_ext_a, next_loc_b, next_loc_a)),
                leave_b == leave_a,
            )
            st_solver = z3.Solver()
            st_solver.set("timeout", timeout_ms)
            st_solver.add(z3.And(make_inv(sym_b, sym_a, sym_ext_b, sym_ext_a, sym_loc_b, sym_loc_a), z3.Not(step_goal)))
            if st_solver.check() != z3.unsat:
                return self._probe_bounded_counterexample(ssa_before, ssa_after, timeout_ms)

            # Summarize Loop `idx` output into next segment cleanly
            shared_ext_out = pre_ext_b if read_only else z3.Array(f"seq_{idx}_post_ext", bv64, bv64)
            no_loc = (len(cur_alloc_b) == 0 and len(cur_alloc_a) == 0)
            shared_loc_out = pre_loc_b if no_loc else z3.Array(f"seq_{idx}_post_loc", bv64, bv64)
            cur_ext_b = pre_ext_b if read_only else shared_ext_out
            cur_ext_a = pre_ext_a if read_only else shared_ext_out
            cur_loc_b = pre_loc_b if no_loc else shared_loc_out
            cur_loc_a = pre_loc_a if no_loc else shared_loc_out

            cur_env_b = dict(pre_res_b["env"])
            cur_env_a = dict(pre_res_a["env"])
            for p_idx, (kb, ka) in enumerate(pairs):
                sv = z3.BitVec(f"seq_{idx}_post_{p_idx}_{kb[0]}_{kb[1]}", 64)
                for phi in hb_blk.phi_nodes:
                    if (phi.result.name, phi.result.version) == kb:
                        cur_env_b[phi.result] = sv
                for phi in ha_blk.phi_nodes:
                    if (phi.result.name, phi.result.version) == ka:
                        cur_env_a[phi.result] = sv
            for kb in rem_b:
                for phi in hb_blk.phi_nodes:
                    if (phi.result.name, phi.result.version) == kb:
                        cur_env_b[phi.result] = init_phi_b[kb]
            for ka in rem_a:
                for phi in ha_blk.phi_nodes:
                    if (phi.result.name, phi.result.version) == ka:
                        cur_env_a[phi.result] = init_phi_a[ka]

            cur_reach_b, cur_reach_a = {}, {}
            cur_edges_b = {e: z3.BoolVal(True) for e in leave_em_b.keys()}
            cur_edges_a = {e: z3.BoolVal(True) for e in leave_em_a.keys()}
            if not cur_edges_b or not cur_edges_a:
                return None
            cur_edge_ext_b = {src: cur_ext_b for (src, _) in cur_edges_b.keys()}
            cur_edge_ext_a = {src: cur_ext_a for (src, _) in cur_edges_a.keys()}
            cur_edge_loc_b = {src: cur_loc_b for (src, _) in cur_edges_b.keys()}
            cur_edge_loc_a = {src: cur_loc_a for (src, _) in cur_edges_a.keys()}
            prev_pos_b = next_start_b
            prev_pos_a = next_start_a

        # Final tail segment after last loop
        tail_blocks_b = [
            b for b in db["rpo_blocks"]
            if db["rpo_idx"][b.name] > prev_pos_b and b.name not in seen_loops_b
        ]
        tail_blocks_a = [
            b for b in da["rpo_blocks"]
            if da["rpo_idx"][b.name] > prev_pos_a and b.name not in seen_loops_a
        ]
        tail_res_b = self._run_dag_segment(
            fn=ssa_before, blocks=tail_blocks_b, sym_params=sym_params,
            init_env=cur_env_b, init_alloca_bases=cur_alloc_b,
            entry_reach=cur_reach_b, entry_edge_conds=cur_edges_b,
            entry_ext_mem=cur_edge_ext_b, entry_loc_mem=cur_edge_loc_b,
            default_ext_mem=cur_ext_b, default_loc_mem=cur_loc_b,
            stop_targets=set(), skip_phi_blocks=set(),
            allow_allocas=False, allowed_ops=allowed_ops,
        )
        tail_res_a = self._run_dag_segment(
            fn=ssa_after, blocks=tail_blocks_a, sym_params=sym_params,
            init_env=cur_env_a, init_alloca_bases=cur_alloc_a,
            entry_reach=cur_reach_a, entry_edge_conds=cur_edges_a,
            entry_ext_mem=cur_edge_ext_a, entry_loc_mem=cur_edge_loc_a,
            default_ext_mem=cur_ext_a, default_loc_mem=cur_loc_a,
            stop_targets=set(), skip_phi_blocks=set(),
            allow_allocas=False, allowed_ops=allowed_ops,
        )
        if tail_res_b.get("error") or tail_res_a.get("error"):
            return None

        ft_b, fr_b, fm_b = self._combine_ret_cases(tail_res_b["ret_cases"], cur_ext_b)
        ft_a, fr_a, fm_a = self._combine_ret_cases(tail_res_a["ret_cases"], cur_ext_a)
        fin_solver = z3.Solver()
        fin_solver.set("timeout", timeout_ms)
        fin_solver.add(z3.Not(z3.And(ft_b == ft_a, z3.Implies(ft_b, z3.And(fr_b == fr_a, fm_b == fm_a)))))
        if fin_solver.check() == z3.unsat:
            return {
                "proven": True,
                "status": "PROVEN_INDUCTIVE_EQUIVALENT",
                "counterexample": None,
                "bounded": False,
            }
        return self._probe_bounded_counterexample(ssa_before, ssa_after, timeout_ms)

    def _verify_multi_loop_inductive_equivalence(
        self,
        ssa_before: SSAFunction,
        ssa_after: SSAFunction,
        timeout_ms: int = 2000,
    ) -> Optional[Dict[str, Any]]:
        db = self._decompose_all_natural_loops(ssa_before)
        da = self._decompose_all_natural_loops(ssa_after)
        if db is None or da is None:
            return None
        sym_params = [z3.BitVec(f"p_{i}_{name}", 64) for i, name in enumerate(ssa_before.params)]
        bv64 = z3.BitVecSort(64)
        shared_ext_mem = z3.Array("shared_multi_ext_mem_0", bv64, bv64)

        if len(db["headers"]) == 2 and len(da["headers"]) == 2:
            if db["loop_names"][db["headers"][1]] < db["loop_names"][db["headers"][0]]:
                nested_res = self._verify_nested_two_level_loops(
                    ssa_before, ssa_after, db, da, sym_params, shared_ext_mem, timeout_ms
                )
                if nested_res is not None:
                    return nested_res

        return self._verify_sequential_multi_loops(
            ssa_before, ssa_after, db, da, sym_params, shared_ext_mem, timeout_ms
        )

    def _verify_inductive_loop_equivalence(
        self,
        ssa_before: SSAFunction,
        ssa_after: SSAFunction,
        timeout_ms: int = 2000,
    ) -> Optional[Dict[str, Any]]:
        """
        Proves unbounded semantic equivalence for single-header natural loops
        via 1-inductive relational bisimulation (Preheader Base => Lockstep Guard
        & Body Preservation => Post-Loop Exit Equivalence).
        """
        sym_params = [z3.BitVec(f"p_{i}_{name}", 64) for i, name in enumerate(ssa_before.params)]
        bv64 = z3.BitVecSort(64)
        shared_ext_mem = z3.Array("shared_ind_ext_mem_0", bv64, bv64)

        ph_b = self._build_symbolic_loop_phases(ssa_before, sym_params, shared_ext_mem, "B")
        ph_a = self._build_symbolic_loop_phases(ssa_after, sym_params, shared_ext_mem, "A")
        if ph_b is None or ph_a is None:
            return self._verify_multi_loop_inductive_equivalence(ssa_before, ssa_after, timeout_ms=timeout_ms)

        # Pair header phis by (name, version) first, then positional if bijective
        keys_b = ph_b["phi_keys"]
        keys_a = ph_a["phi_keys"]
        paired_keys: List[Tuple[Tuple[str, int], Tuple[str, int]]] = []
        matched_b: Set[Tuple[str, int]] = set()
        matched_a: Set[Tuple[str, int]] = set()

        for kb in keys_b:
            if kb in keys_a:
                paired_keys.append((kb, kb))
                matched_b.add(kb)
                matched_a.add(kb)

        rem_b = [k for k in keys_b if k not in matched_b]
        rem_a = [k for k in keys_a if k not in matched_a]
        if len(rem_b) == len(rem_a):
            for kb, ka in zip(rem_b, rem_a):
                paired_keys.append((kb, ka))
                matched_b.add(kb)
                matched_a.add(ka)
            rem_b, rem_a = [], []

        def make_rel_inv(
            state_b: Dict[Tuple[str, int], z3.BitVecRef],
            state_a: Dict[Tuple[str, int], z3.BitVecRef],
            mem_b: z3.ArrayRef,
            mem_a: z3.ArrayRef,
            loc_b: z3.ArrayRef,
            loc_a: z3.ArrayRef,
            read_only_mem_inv: bool,
        ) -> z3.BoolRef:
            clauses: List[z3.BoolRef] = [mem_b == mem_a]
            if ph_b["pre_allocas_count"] == ph_a["pre_allocas_count"] and ph_b["pre_allocas_count"] > 0:
                clauses.append(loc_b == loc_a)
            for kb, ka in paired_keys:
                clauses.append(state_b[kb] == state_a[ka])
            # Unpaired phis are invariant to their preheader initializers if constant across loop
            for kb in rem_b:
                clauses.append(state_b[kb] == ph_b["init_phi_vals"][kb])
            for ka in rem_a:
                clauses.append(state_a[ka] == ph_a["init_phi_vals"][ka])
            if read_only_mem_inv:
                clauses.append(mem_b == ph_b["pre_ext_mem"])
                clauses.append(mem_a == ph_a["pre_ext_mem"])
            return z3.And(clauses)

        read_only_loop = (not ph_b["loop_writes_ext"]) and (not ph_a["loop_writes_ext"])

        # Obligation 1: Preheader Bypass + Base Case
        pre_eq = z3.And(
            ph_b["enter_cond"] == ph_a["enter_cond"],
            z3.Implies(
                z3.Not(ph_b["enter_cond"]),
                z3.And(
                    ph_b["bypass_term"] == ph_a["bypass_term"],
                    z3.Implies(
                        ph_b["bypass_term"],
                        z3.And(
                            ph_b["bypass_ret"] == ph_a["bypass_ret"],
                            ph_b["bypass_mem"] == ph_a["bypass_mem"],
                        ),
                    ),
                ),
            ),
        )
        base_inv = make_rel_inv(
            ph_b["init_phi_vals"], ph_a["init_phi_vals"],
            ph_b["pre_ext_mem"], ph_a["pre_ext_mem"],
            ph_b["pre_loc_mem"], ph_a["pre_loc_mem"],
            read_only_mem_inv=read_only_loop,
        )
        base_solver = z3.Solver()
        base_solver.set("timeout", timeout_ms)
        base_solver.add(z3.Not(z3.And(pre_eq, z3.Implies(ph_b["enter_cond"], base_inv))))
        base_chk = base_solver.check()
        if base_chk == z3.sat:
            m = base_solver.model()
            ce = {}
            for i, p_sym in enumerate(sym_params):
                val = m.eval(p_sym, model_completion=True)
                ce[ssa_before.params[i]] = val.as_signed_long() if hasattr(val, "as_signed_long") else str(val)
            return {
                "proven": False,
                "status": "REFUTED_COUNTEREXAMPLE",
                "counterexample": ce,
                "bounded": False,
            }
        if base_chk != z3.unsat:
            return None

        # Obligation 2: Inductive Step + Exit Equivalence
        step_assume = make_rel_inv(
            ph_b["phi_syms"], ph_a["phi_syms"],
            ph_b["sym_ext_mem"], ph_a["sym_ext_mem"],
            ph_b["sym_loc_mem"], ph_a["sym_loc_mem"],
            read_only_mem_inv=read_only_loop,
        )
        next_inv = make_rel_inv(
            ph_b["next_phi_vals"], ph_a["next_phi_vals"],
            ph_b["next_ext_mem"], ph_a["next_ext_mem"],
            ph_b["next_loc_mem"], ph_a["next_loc_mem"],
            read_only_mem_inv=read_only_loop,
        )
        step_goal = z3.And(
            ph_b["continue_cond"] == ph_a["continue_cond"],
            ph_b["early_term"] == ph_a["early_term"],
            z3.Implies(
                ph_b["early_term"],
                z3.And(
                    ph_b["early_ret"] == ph_a["early_ret"],
                    ph_b["early_mem"] == ph_a["early_mem"],
                ),
            ),
            z3.Implies(ph_b["continue_cond"], next_inv),
            ph_b["leave_cond"] == ph_a["leave_cond"],
            z3.Implies(
                ph_b["leave_cond"],
                z3.And(
                    ph_b["exit_term"] == ph_a["exit_term"],
                    z3.Implies(
                        ph_b["exit_term"],
                        z3.And(
                            ph_b["exit_ret"] == ph_a["exit_ret"],
                            ph_b["exit_mem"] == ph_a["exit_mem"],
                        ),
                    ),
                ),
            ),
        )
        step_solver = z3.Solver()
        step_solver.set("timeout", timeout_ms)
        step_solver.add(z3.And(step_assume, z3.Not(step_goal)))
        step_chk = step_solver.check()

        if step_chk == z3.unsat:
            return {
                "proven": True,
                "status": "PROVEN_INDUCTIVE_EQUIVALENT",
                "counterexample": None,
                "bounded": False,
            }

        # Step/Exit failed under arbitrary state: confirm concrete refutation via bounded witness check
        if step_chk == z3.sat:
            return self._probe_bounded_counterexample(ssa_before, ssa_after, timeout_ms)

        return {
            "proven": False,
            "status": "UNVERIFIED_INDUCTIVE_PROOF_FAILED",
            "counterexample": None,
            "bounded": False,
        }

    def verify_equivalence(
        self,
        ssa_before: SSAFunction,
        ssa_after: SSAFunction,
        timeout_ms: int = 2000,
    ) -> Dict[str, Any]:
        """
        Proves semantic equivalence between `ssa_before` and `ssa_after` via Z3 QF_BV / QF_ABV
        (acyclic, bounded unrolling, or unbounded 1-inductive loop bisimulation).
        """
        if len(ssa_before.params) != len(ssa_after.params):
            return {
                "proven": False,
                "status": "REFUTED_ARITY_MISMATCH",
                "counterexample": None,
                "bounded": False,
            }

        sym_params = [z3.BitVec(f"p_{i}_{name}", 64) for i, name in enumerate(ssa_before.params)]
        bv64 = z3.BitVecSort(64)
        shared_ext_mem = z3.Array("shared_ext_mem_0", bv64, bv64)

        enc_before = self._encode_function_symbolic(ssa_before, sym_params, init_ext_mem=shared_ext_mem)
        enc_after = self._encode_function_symbolic(ssa_after, sym_params, init_ext_mem=shared_ext_mem)

        cyclic_errs = {"CYCLIC_CFG", "LOOP_BOUND_EXCEEDED"}
        if (enc_before.get("error") in cyclic_errs or enc_after.get("error") in cyclic_errs) and self.enable_inductive_loops:
            ind_res = self._verify_inductive_loop_equivalence(ssa_before, ssa_after, timeout_ms=timeout_ms)
            if ind_res is not None:
                return ind_res

        if enc_before.get("error"):
            return {
                "proven": False,
                "status": f"UNVERIFIED_{enc_before['error']}",
                "counterexample": None,
                "bounded": False,
            }

        if enc_after.get("error"):
            return {
                "proven": False,
                "status": f"UNVERIFIED_{enc_after['error']}",
                "counterexample": None,
                "bounded": False,
            }

        is_bounded = bool(enc_before["bounded"] or enc_after["bounded"])
        ret_b, mem_b, term_b = enc_before["ret_expr"], enc_before["ext_mem_expr"], enc_before["terminated_cond"]
        ret_a, mem_a, term_a = enc_after["ret_expr"], enc_after["ext_mem_expr"], enc_after["terminated_cond"]

        if is_bounded and self.enable_inductive_loops:
            ind_res = self._verify_inductive_loop_equivalence(ssa_before, ssa_after, timeout_ms=timeout_ms)
            if ind_res is not None:
                if ind_res["proven"] or ind_res["status"] == "REFUTED_COUNTEREXAMPLE":
                    return ind_res

        if is_bounded:
            # First ensure at least one execution actually terminates within the unroll bound
            wit_solver = z3.Solver()
            wit_solver.set("timeout", timeout_ms)
            wit_solver.add(z3.Or(term_b, term_a))
            if wit_solver.check() != z3.sat:
                return {
                    "proven": False,
                    "status": "UNVERIFIED_LOOP_BOUND_EXCEEDED",
                    "counterexample": None,
                    "bounded": True,
                }

        # Exact Z3 AST reflexivity fast-path: identical encoded terms cannot diverge
        if ret_b.eq(ret_a) and mem_b.eq(mem_a) and (not is_bounded or term_b.eq(term_a)):
            return {
                "proven": True,
                "status": "PROVEN_BOUNDED_EQUIVALENT" if is_bounded else "PROVEN_EQUIVALENT",
                "counterexample": None,
                "bounded": is_bounded,
            }

        if is_bounded:
            mismatch_cond = z3.Or(
                term_b != term_a,
                z3.And(term_b, term_a, z3.Or(ret_b != ret_a, mem_b != mem_a)),
            )
        else:
            mismatch_cond = z3.Or(ret_b != ret_a, mem_b != mem_a)

        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        solver.add(mismatch_cond)
        check = solver.check()

        if check == z3.unsat:
            return {
                "proven": True,
                "status": "PROVEN_BOUNDED_EQUIVALENT" if is_bounded else "PROVEN_EQUIVALENT",
                "counterexample": None,
                "bounded": is_bounded,
            }
        elif check == z3.sat:
            model = solver.model()
            ce = {}
            for i, p_sym in enumerate(sym_params):
                pname = ssa_before.params[i]
                val = model.eval(p_sym, model_completion=True)
                ce[pname] = val.as_signed_long() if hasattr(val, "as_signed_long") else str(val)
            return {
                "proven": False,
                "status": "REFUTED_COUNTEREXAMPLE",
                "counterexample": ce,
                "bounded": is_bounded,
            }
        else:
            return {
                "proven": False,
                "status": "UNVERIFIED_TIMEOUT",
                "counterexample": None,
                "bounded": is_bounded,
            }


class VerifiedPassRunner:
    """
    Executes an SSA optimization pass under an SMT Translation Validation gate.
    Automatically rolls back to the pre-pass snapshot if Z3 finds a counterexample.
    """

    def __init__(
        self,
        timeout_ms: int = 2000,
        enable_memory_theory: bool = False,
        max_loop_unroll: int = 0,
        enable_inductive_loops: bool = False,
    ):
        self.validator = SSATranslationValidator(
            enable_memory_theory=enable_memory_theory,
            max_loop_unroll=max_loop_unroll,
            enable_inductive_loops=enable_inductive_loops,
        )
        self.timeout_ms = timeout_ms

    def run_verified_pass(
        self,
        fn: SSAFunction,
        pass_fn: Callable[[SSAFunction], Tuple[SSAFunction, Dict[str, Any]]],
    ) -> Tuple[SSAFunction, Dict[str, Any], Dict[str, Any]]:
        snapshot = clone_ssa_function(fn)
        candidate_fn, pass_stats = pass_fn(fn)
        verdict = self.validator.verify_equivalence(snapshot, candidate_fn, timeout_ms=self.timeout_ms)

        if verdict["status"] == "REFUTED_COUNTEREXAMPLE":
            return snapshot, pass_stats, {
                "verified": False,
                "rolled_back": True,
                "verdict": verdict,
            }

        return candidate_fn, pass_stats, {
            "verified": verdict["proven"],
            "rolled_back": False,
            "verdict": verdict,
        }
