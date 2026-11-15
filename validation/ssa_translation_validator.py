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
    ):
        self.enable_memory_theory = enable_memory_theory
        self.max_loop_unroll = max(0, int(max_loop_unroll))
        self.enable_inductive_loops = bool(enable_inductive_loops)

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
        return frozenset(ops)

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
            return None

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
            bounded_probe = SSATranslationValidator(
                enable_memory_theory=self.enable_memory_theory,
                max_loop_unroll=max(self.max_loop_unroll, 8),
                enable_inductive_loops=False,
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
