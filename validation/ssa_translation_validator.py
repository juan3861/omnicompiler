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
    "shl", "shr", "sar", "and", "or", "xor",
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
    ):
        self.enable_memory_theory = enable_memory_theory
        self.max_loop_unroll = max(0, int(max_loop_unroll))

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
                        "shl", "shr", "sar", "and", "or", "xor",
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
                        elif op == "shr":
                            res_bv = z3.LShR(v0, v1)
                        elif op == "sar":
                            res_bv = v0 >> v1
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

    def verify_equivalence(
        self,
        ssa_before: SSAFunction,
        ssa_after: SSAFunction,
        timeout_ms: int = 2000,
    ) -> Dict[str, Any]:
        """
        Proves semantic equivalence between `ssa_before` and `ssa_after` via Z3 QF_BV / QF_ABV.
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
        if enc_before.get("error"):
            return {
                "proven": False,
                "status": f"UNVERIFIED_{enc_before['error']}",
                "counterexample": None,
                "bounded": False,
            }

        enc_after = self._encode_function_symbolic(ssa_after, sym_params, init_ext_mem=shared_ext_mem)
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
            check = z3.unsat
            solver = None
        else:
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
    ):
        self.validator = SSATranslationValidator(
            enable_memory_theory=enable_memory_theory,
            max_loop_unroll=max_loop_unroll,
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
