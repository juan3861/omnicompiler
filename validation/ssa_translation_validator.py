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

import struct
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

SUPPORTED_Z3_MEMORY_OPCODES = frozenset({"alloca", "load", "store", "load_off", "store_off"})
SUPPORTED_Z3_METADATA_OPCODES = frozenset({"unroll_meta", "unroll_factor"})
SUPPORTED_Z3_FLOAT_OPCODES = frozenset({
    "fconst", "fneg", "fadd", "fsub", "fmul", "fdiv",
    "fcmp_eq", "fcmp_ne", "fcmp_lt", "fcmp_le", "fcmp_gt", "fcmp_ge",
    "sitofp", "fptosi",
})


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
        enable_float_theory: bool = False,
    ):
        self.enable_memory_theory = enable_memory_theory
        self.max_loop_unroll = max(0, int(max_loop_unroll))
        self.enable_inductive_loops = bool(enable_inductive_loops)
        self.enable_call_congruence = bool(enable_call_congruence)
        self.enable_float_theory = bool(enable_float_theory)

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
        if self.enable_float_theory:
            ops |= SUPPORTED_Z3_FLOAT_OPCODES
        return frozenset(ops)

    @staticmethod
    def _load_off_z3(raw_bv: z3.BitVecRef, width: str) -> z3.BitVecRef:
        if width == "i32":
            return z3.SignExt(32, z3.Extract(31, 0, raw_bv))
        if width == "f32":
            f32_val = z3.fpBVToFP(z3.Extract(31, 0, raw_bv), z3.Float32())
            return z3.fpToIEEEBV(z3.fpToFP(z3.RNE(), f32_val, z3.Float64()))
        return raw_bv

    @staticmethod
    def _store_off_z3(val_bv: z3.BitVecRef, width: str) -> z3.BitVecRef:
        if width == "i32":
            return z3.ZeroExt(32, z3.Extract(31, 0, val_bv))
        if width == "f32":
            f64_val = z3.fpBVToFP(val_bv, z3.Float64())
            return z3.ZeroExt(32, z3.fpToIEEEBV(z3.fpToFP(z3.RNE(), f64_val, z3.Float32())))
        return val_bv

    @staticmethod
    def _float_to_bv(val: float) -> z3.BitVecRef:
        bits = struct.unpack("<Q", struct.pack("<d", float(val)))[0]
        return z3.BitVecVal(bits, 64)

    @staticmethod
    def _eval_float_inst(op: str, args: List[z3.BitVecRef]) -> z3.BitVecRef:
        fp64 = z3.Float64()
        rm = z3.RNE()
        if op == "fneg":
            return args[0] ^ z3.BitVecVal(0x8000000000000000, 64)
        if op == "sitofp":
            return z3.fpToIEEEBV(z3.fpSignedToFP(rm, args[0], fp64))
        if op == "fptosi":
            return z3.fpToSBV(z3.RTZ(), z3.fpBVToFP(args[0], fp64), z3.BitVecSort(64))
        f0 = z3.fpBVToFP(args[0], fp64)
        f1 = z3.fpBVToFP(args[1], fp64)
        if op == "fadd":
            return z3.fpToIEEEBV(z3.fpAdd(rm, f0, f1))
        if op == "fsub":
            return z3.fpToIEEEBV(z3.fpSub(rm, f0, f1))
        if op == "fmul":
            return z3.fpToIEEEBV(z3.fpMul(rm, f0, f1))
        if op == "fdiv":
            return z3.fpToIEEEBV(z3.fpDiv(rm, f0, f1))
        if op == "fcmp_eq":
            cond = z3.fpEQ(f0, f1)
        elif op == "fcmp_ne":
            cond = z3.And(z3.Not(z3.fpIsNaN(f0)), z3.Not(z3.fpIsNaN(f1)), z3.Not(z3.fpEQ(f0, f1)))
        elif op == "fcmp_lt":
            cond = z3.fpLT(f0, f1)
        elif op == "fcmp_le":
            cond = z3.fpLEQ(f0, f1)
        elif op == "fcmp_gt":
            cond = z3.fpGT(f0, f1)
        else:  # fcmp_ge
            cond = z3.fpGEQ(f0, f1)
        return z3.If(cond, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))

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
                    if isinstance(op, float):
                        return self._float_to_bv(op)
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
                        if isinstance(val, float) and self.enable_float_theory:
                            env_levels[lvl][inst.result] = self._float_to_bv(val)
                        elif not isinstance(val, (int, bool)):
                            return {"error": "NON_INT_CONST"}
                        else:
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

                    elif op == "load_off":
                        if inst.result is None or len(inst.operands) < 2:
                            return {"error": "INVALID_LOAD_OFF"}
                        ptr_op = inst.operands[0]
                        ptr_v = eval_op(ptr_op)
                        off_v = eval_op(inst.operands[1])
                        width = str(inst.operands[2]) if len(inst.operands) >= 3 else "i64"
                        if ptr_v is None or off_v is None:
                            return {"error": "UNRESOLVED_LOAD_OFF"}
                        addr = ptr_v + off_v
                        raw_v = z3.Select(cur_loc_mem if is_alloca_var(ptr_op) else cur_ext_mem, addr)
                        env_levels[lvl][inst.result] = self._load_off_z3(raw_v, width)

                    elif op == "store_off":
                        if len(inst.operands) < 3:
                            return {"error": "INVALID_STORE_OFF"}
                        ptr_op = inst.operands[0]
                        ptr_v = eval_op(ptr_op)
                        off_v = eval_op(inst.operands[1])
                        val_op = inst.operands[2]
                        width = str(inst.operands[3]) if len(inst.operands) >= 4 else "i64"
                        val_v = eval_op(val_op)
                        if ptr_v is None or off_v is None or val_v is None:
                            return {"error": "UNRESOLVED_STORE_OFF"}
                        if is_alloca_var(val_op) and not is_alloca_var(ptr_op):
                            return {"error": "ESCAPED_ALLOCA_UNSUPPORTED"}
                        addr = ptr_v + off_v
                        w_val = self._store_off_z3(val_v, width)
                        if is_alloca_var(ptr_op):
                            cur_loc_mem = z3.Store(cur_loc_mem, addr, w_val)
                        else:
                            cur_ext_mem = z3.Store(cur_ext_mem, addr, w_val)

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

                    elif op == "fconst":
                        if not inst.operands or inst.result is None:
                            return {"error": "INVALID_FCONST"}
                        env_levels[lvl][inst.result] = self._float_to_bv(float(inst.operands[0]))

                    elif op in SUPPORTED_Z3_FLOAT_OPCODES:
                        if inst.result is None:
                            return {"error": f"INVALID_{op}"}
                        fargs: List[z3.BitVecRef] = []
                        for a in inst.operands:
                            av = eval_op(a)
                            if av is None:
                                return {"error": f"UNRESOLVED_{op}"}
                            fargs.append(av)
                        env_levels[lvl][inst.result] = self._eval_float_inst(op, fargs)

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
                if isinstance(op, float):
                    return self._float_to_bv(op)
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
                    if isinstance(val, float) and self.enable_float_theory:
                        local_env[inst.result] = self._float_to_bv(val)
                    elif not isinstance(val, (int, bool)):
                        return {"error": "NON_INT_CONST"}
                    else:
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

                elif op == "load_off":
                    if inst.result is None or len(inst.operands) < 2:
                        return {"error": "INVALID_LOAD_OFF"}
                    ptr_op = inst.operands[0]
                    ptr_v = eval_op(ptr_op)
                    off_v = eval_op(inst.operands[1])
                    width = str(inst.operands[2]) if len(inst.operands) >= 3 else "i64"
                    if ptr_v is None or off_v is None:
                        return {"error": "UNRESOLVED_LOAD_OFF"}
                    addr = ptr_v + off_v
                    raw_v = z3.Select(cur_loc_mem if is_alloca_var(ptr_op) else cur_ext_mem, addr)
                    local_env[inst.result] = self._load_off_z3(raw_v, width)

                elif op == "store_off":
                    if len(inst.operands) < 3:
                        return {"error": "INVALID_STORE_OFF"}
                    ptr_op = inst.operands[0]
                    ptr_v = eval_op(ptr_op)
                    off_v = eval_op(inst.operands[1])
                    val_op = inst.operands[2]
                    width = str(inst.operands[3]) if len(inst.operands) >= 4 else "i64"
                    val_v = eval_op(val_op)
                    if ptr_v is None or off_v is None or val_v is None:
                        return {"error": "UNRESOLVED_STORE_OFF"}
                    if is_alloca_var(val_op) and not is_alloca_var(ptr_op):
                        return {"error": "ESCAPED_ALLOCA_UNSUPPORTED"}
                    addr = ptr_v + off_v
                    w_val = self._store_off_z3(val_v, width)
                    if is_alloca_var(ptr_op):
                        cur_loc_mem = z3.Store(cur_loc_mem, addr, w_val)
                    else:
                        cur_ext_mem = z3.Store(cur_ext_mem, addr, w_val)
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

                elif op == "fconst":
                    if not inst.operands or inst.result is None:
                        return {"error": "INVALID_FCONST"}
                    local_env[inst.result] = self._float_to_bv(float(inst.operands[0]))

                elif op in SUPPORTED_Z3_FLOAT_OPCODES:
                    if inst.result is None:
                        return {"error": f"INVALID_{op}"}
                    fargs: List[z3.BitVecRef] = []
                    for a in inst.operands:
                        av = eval_op(a)
                        if av is None:
                            return {"error": f"UNRESOLVED_{op}"}
                        fargs.append(av)
                    local_env[inst.result] = self._eval_float_inst(op, fargs)

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
                if isinstance(op, float) and self.enable_float_theory:
                    return self._float_to_bv(op)
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
            if isinstance(op, float) and self.enable_float_theory:
                return self._float_to_bv(op)
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
        for kb in keys_b:
            if kb in matched_b:
                continue
            suffix = f"_var_{kb[0]}_{kb[1]}"
            for ka in keys_a:
                if ka not in matched_a and ka[0].endswith(suffix):
                    paired.append((kb, ka))
                    matched_b.add(kb)
                    matched_a.add(ka)
                    break
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
        unroll_k = max(self.max_loop_unroll, 4 if self.enable_float_theory else 12)
        bounded_probe = SSATranslationValidator(
            enable_memory_theory=self.enable_memory_theory,
            max_loop_unroll=unroll_k,
            enable_inductive_loops=False,
            enable_call_congruence=self.enable_call_congruence,
            enable_float_theory=self.enable_float_theory,
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
        if isinstance(op, float):
            return SSATranslationValidator._float_to_bv(op)
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

    @staticmethod
    def _top_level_headers_in_scope(
        d: Dict[str, Any], scope: Set[str], exclude_headers: Set[str]
    ) -> List[str]:
        cand = [h for h in d["headers"] if h in scope and h not in exclude_headers]
        return [
            h for h in cand
            if not any(h != other and h in d["loop_names"][other] for other in cand)
        ]

    @staticmethod
    def _group_stop_cond(
        edges: List[Tuple[str, str, z3.BoolRef]], targets: Set[str]
    ) -> z3.BoolRef:
        cs = [ec for (_, dst, ec) in edges if dst in targets]
        if not cs:
            return z3.BoolVal(False)
        return cs[0] if len(cs) == 1 else z3.Or(cs)

    def _verify_loop_sequence_in_region(
        self,
        ssa_before: SSAFunction,
        ssa_after: SSAFunction,
        db: Dict[str, Any],
        da: Dict[str, Any],
        sym_params: List[z3.BitVecRef],
        scope_b: Set[str],
        scope_a: Set[str],
        exclude_b: Set[str],
        exclude_a: Set[str],
        start_pos_b: int,
        start_pos_a: int,
        init_reach_b: Dict[str, z3.BoolRef],
        init_reach_a: Dict[str, z3.BoolRef],
        init_edges_b: Dict[Tuple[str, str], z3.BoolRef],
        init_edges_a: Dict[Tuple[str, str], z3.BoolRef],
        init_edge_ext_b: Dict[str, z3.ArrayRef],
        init_edge_ext_a: Dict[str, z3.ArrayRef],
        init_edge_loc_b: Dict[str, z3.ArrayRef],
        init_edge_loc_a: Dict[str, z3.ArrayRef],
        default_ext_b: z3.ArrayRef,
        default_ext_a: z3.ArrayRef,
        default_loc_b: z3.ArrayRef,
        default_loc_a: z3.ArrayRef,
        init_env_b: Dict[SSAVar, z3.BitVecRef],
        init_env_a: Dict[SSAVar, z3.BitVecRef],
        init_alloc_b: Dict[SSAVar, z3.BitVecRef],
        init_alloc_a: Dict[SSAVar, z3.BitVecRef],
        skip_b: Set[str],
        skip_a: Set[str],
        stop_targets_b: Set[str],
        stop_targets_a: Set[str],
        allow_allocas: bool,
        outer_rel_assume: z3.BoolRef,
        parent_exit_targets_b: Set[str],
        parent_exit_targets_a: Set[str],
        timeout_ms: int,
        tag: str,
    ) -> Dict[str, Any]:
        bv64 = z3.BitVecSort(64)
        allowed_ops = frozenset(set(self._allowed_opcodes()) | SUPPORTED_Z3_METADATA_OPCODES)
        top_b = self._top_level_headers_in_scope(db, scope_b, exclude_b)
        top_a = self._top_level_headers_in_scope(da, scope_a, exclude_a)
        if len(top_b) != len(top_a):
            return {"status": "FALLBACK"}

        if not top_b:
            blocks_b = [
                b for b in db["rpo_blocks"]
                if b.name in scope_b and db["rpo_idx"][b.name] >= start_pos_b
            ]
            blocks_a = [
                b for b in da["rpo_blocks"]
                if b.name in scope_a and da["rpo_idx"][b.name] >= start_pos_a
            ]
            if blocks_b:
                res_b = self._run_dag_segment(
                    fn=ssa_before, blocks=blocks_b, sym_params=sym_params,
                    init_env=init_env_b, init_alloca_bases=init_alloc_b,
                    entry_reach=init_reach_b, entry_edge_conds=init_edges_b,
                    entry_ext_mem=init_edge_ext_b, entry_loc_mem=init_edge_loc_b,
                    default_ext_mem=default_ext_b, default_loc_mem=default_loc_b,
                    stop_targets=stop_targets_b, skip_phi_blocks=skip_b,
                    allow_allocas=allow_allocas, allowed_ops=allowed_ops,
                )
            else:
                res_b = {
                    "stopped_edges": [(s, d, ec) for (s, d), ec in init_edges_b.items()],
                    "ret_cases": [],
                    "env": dict(init_env_b),
                    "alloca_bases": dict(init_alloc_b),
                    "ext_mem_out": dict(init_edge_ext_b),
                    "loc_mem_out": dict(init_edge_loc_b),
                    "block_env": {},
                    "wrote_ext_mem": False,
                }
            if blocks_a:
                res_a = self._run_dag_segment(
                    fn=ssa_after, blocks=blocks_a, sym_params=sym_params,
                    init_env=init_env_a, init_alloca_bases=init_alloc_a,
                    entry_reach=init_reach_a, entry_edge_conds=init_edges_a,
                    entry_ext_mem=init_edge_ext_a, entry_loc_mem=init_edge_loc_a,
                    default_ext_mem=default_ext_a, default_loc_mem=default_loc_a,
                    stop_targets=stop_targets_a, skip_phi_blocks=skip_a,
                    allow_allocas=allow_allocas, allowed_ops=allowed_ops,
                )
            else:
                res_a = {
                    "stopped_edges": [(s, d, ec) for (s, d), ec in init_edges_a.items()],
                    "ret_cases": [],
                    "env": dict(init_env_a),
                    "alloca_bases": dict(init_alloc_a),
                    "ext_mem_out": dict(init_edge_ext_a),
                    "loc_mem_out": dict(init_edge_loc_a),
                    "block_env": {},
                    "wrote_ext_mem": False,
                }
            if res_b.get("error") or res_a.get("error"):
                return {"status": "FALLBACK"}
            return {
                "status": "OK",
                "res_b": res_b,
                "res_a": res_a,
                "wrote_ext_mem": bool(res_b["wrote_ext_mem"] or res_a["wrote_ext_mem"]),
            }

        cur_pos_b, cur_pos_a = start_pos_b, start_pos_a
        seen_b: Set[str] = set()
        seen_a: Set[str] = set()
        cur_reach_b, cur_reach_a = dict(init_reach_b), dict(init_reach_a)
        cur_edges_b, cur_edges_a = dict(init_edges_b), dict(init_edges_a)
        cur_edge_ext_b, cur_edge_ext_a = dict(init_edge_ext_b), dict(init_edge_ext_a)
        cur_edge_loc_b, cur_edge_loc_a = dict(init_edge_loc_b), dict(init_edge_loc_a)
        cur_ext_b, cur_ext_a = default_ext_b, default_ext_a
        cur_loc_b, cur_loc_a = default_loc_b, default_loc_a
        cur_env_b, cur_env_a = dict(init_env_b), dict(init_env_a)
        cur_alloc_b, cur_alloc_a = dict(init_alloc_b), dict(init_alloc_a)
        cur_skip_b, cur_skip_a = set(skip_b), set(skip_a)
        cur_allow_allocas = allow_allocas

        accum_stopped_b: List[Tuple[str, str, z3.BoolRef]] = []
        accum_stopped_a: List[Tuple[str, str, z3.BoolRef]] = []
        accum_rets_b: List[Tuple[z3.BoolRef, z3.BitVecRef, z3.ArrayRef]] = []
        accum_rets_a: List[Tuple[z3.BoolRef, z3.BitVecRef, z3.ArrayRef]] = []
        accum_ext_out_b: Dict[str, z3.ArrayRef] = {}
        accum_ext_out_a: Dict[str, z3.ArrayRef] = {}
        accum_loc_out_b: Dict[str, z3.ArrayRef] = {}
        accum_loc_out_a: Dict[str, z3.ArrayRef] = {}
        accum_benv_b: Dict[str, Dict[SSAVar, z3.BitVecRef]] = {}
        accum_benv_a: Dict[str, Dict[SSAVar, z3.BitVecRef]] = {}
        accum_wrote_ext = False

        for idx, (hb, ha) in enumerate(zip(top_b, top_a)):
            hb_idx, ha_idx = db["rpo_idx"][hb], da["rpo_idx"][ha]
            lb_set, la_set = db["loop_names"][hb], da["loop_names"][ha]
            hb_blk, ha_blk = db["block_map"][hb], da["block_map"][ha]

            pre_blocks_b = [
                b for b in db["rpo_blocks"]
                if b.name in scope_b
                and cur_pos_b <= db["rpo_idx"][b.name] < hb_idx
                and b.name not in lb_set
                and b.name not in seen_b
            ]
            pre_blocks_a = [
                b for b in da["rpo_blocks"]
                if b.name in scope_a
                and cur_pos_a <= da["rpo_idx"][b.name] < ha_idx
                and b.name not in la_set
                and b.name not in seen_a
            ]

            def run_pre_seg(fn, blocks, reach, edges, eext, eloc, dext, dloc, env, alloc, skip, allow_al, hname, stops):
                if blocks:
                    r = self._run_dag_segment(
                        fn=fn, blocks=blocks, sym_params=sym_params,
                        init_env=env, init_alloca_bases=alloc,
                        entry_reach=reach, entry_edge_conds=edges,
                        entry_ext_mem=eext, entry_loc_mem=eloc,
                        default_ext_mem=dext, default_loc_mem=dloc,
                        stop_targets={hname} | stops, skip_phi_blocks=skip,
                        allow_allocas=allow_al, allowed_ops=allowed_ops,
                    )
                    if r.get("error"):
                        return None
                    return r
                return {
                    "stopped_edges": [(s, d, ec) for (s, d), ec in edges.items()],
                    "ret_cases": [],
                    "env": dict(env),
                    "alloca_bases": dict(alloc),
                    "ext_mem_out": dict(eext),
                    "loc_mem_out": dict(eloc),
                    "block_env": {},
                    "wrote_ext_mem": False,
                }

            pre_res_b = run_pre_seg(
                ssa_before, pre_blocks_b, cur_reach_b, cur_edges_b, cur_edge_ext_b, cur_edge_loc_b,
                cur_ext_b, cur_loc_b, cur_env_b, cur_alloc_b, cur_skip_b, cur_allow_allocas, hb, stop_targets_b
            )
            pre_res_a = run_pre_seg(
                ssa_after, pre_blocks_a, cur_reach_a, cur_edges_a, cur_edge_ext_a, cur_edge_loc_a,
                cur_ext_a, cur_loc_a, cur_env_a, cur_alloc_a, cur_skip_a, cur_allow_allocas, ha, stop_targets_a
            )
            if pre_res_b is None or pre_res_a is None:
                return {"status": "FALLBACK"}

            if pre_res_b["wrote_ext_mem"] or pre_res_a["wrote_ext_mem"]:
                accum_wrote_ext = True

            for src_n, dst_n, ec in pre_res_b["stopped_edges"]:
                if dst_n in stop_targets_b:
                    accum_stopped_b.append((src_n, dst_n, ec))
                    if src_n in pre_res_b["ext_mem_out"]:
                        accum_ext_out_b[src_n] = pre_res_b["ext_mem_out"][src_n]
                        accum_loc_out_b[src_n] = pre_res_b["loc_mem_out"][src_n]
                    if src_n in pre_res_b["block_env"]:
                        accum_benv_b[src_n] = pre_res_b["block_env"][src_n]
            for src_n, dst_n, ec in pre_res_a["stopped_edges"]:
                if dst_n in stop_targets_a:
                    accum_stopped_a.append((src_n, dst_n, ec))
                    if src_n in pre_res_a["ext_mem_out"]:
                        accum_ext_out_a[src_n] = pre_res_a["ext_mem_out"][src_n]
                        accum_loc_out_a[src_n] = pre_res_a["loc_mem_out"][src_n]
                    if src_n in pre_res_a["block_env"]:
                        accum_benv_a[src_n] = pre_res_a["block_env"][src_n]
            accum_rets_b.extend(pre_res_b["ret_cases"])
            accum_rets_a.extend(pre_res_a["ret_cases"])

            enter_b, pre_em_b = self._extract_edge_group(pre_res_b["stopped_edges"], {hb})
            enter_a, pre_em_a = self._extract_edge_group(pre_res_a["stopped_edges"], {ha})
            if enter_b is None or enter_a is None:
                return {"status": "FALLBACK"}

            init_phi_b = self._collect_header_phi_values(hb_blk, pre_em_b, pre_res_b)
            init_phi_a = self._collect_header_phi_values(ha_blk, pre_em_a, pre_res_a)
            if init_phi_b is None or init_phi_a is None:
                return {"status": "FALLBACK"}

            pre_ext_b, pre_loc_b = self._merge_pred_mem(pre_res_b, pre_em_b)
            pre_ext_a, pre_loc_a = self._merge_pred_mem(pre_res_a, pre_em_a)
            bt_b, br_b, bm_b = self._combine_ret_cases(pre_res_b["ret_cases"], cur_ext_b)
            bt_a, br_a, bm_a = self._combine_ret_cases(pre_res_a["ret_cases"], cur_ext_a)

            if cur_allow_allocas:
                cur_alloc_b = pre_res_b["alloca_bases"]
                cur_alloc_a = pre_res_a["alloca_bases"]

            pairs, rem_b, rem_a = self._pair_phi_keys(list(init_phi_b.keys()), list(init_phi_a.keys()))
            sym_b = {k: z3.BitVec(f"{tag}_L{idx}_B_{k[0]}_{k[1]}", 64) for k in init_phi_b}
            sym_a = {k: z3.BitVec(f"{tag}_L{idx}_A_{k[0]}_{k[1]}", 64) for k in init_phi_a}
            sym_ext_b = z3.Array(f"{tag}_L{idx}_ext_B", bv64, bv64)
            sym_ext_a = z3.Array(f"{tag}_L{idx}_ext_A", bv64, bv64)
            sym_loc_b = z3.Array(f"{tag}_L{idx}_loc_B", bv64, bv64)
            sym_loc_a = z3.Array(f"{tag}_L{idx}_loc_A", bv64, bv64)

            def make_inv(sb_m, sa_m, eb, ea, lb, la, read_only_flag: bool = False) -> z3.BoolRef:
                cl = [eb == ea]
                if len(cur_alloc_b) == len(cur_alloc_a) and len(cur_alloc_b) > 0:
                    cl.append(lb == la)
                for kb, ka in pairs:
                    cl.append(sb_m[kb] == sa_m[ka])
                for kb in rem_b:
                    cl.append(sb_m[kb] == init_phi_b[kb])
                for ka in rem_a:
                    cl.append(sa_m[ka] == init_phi_a[ka])
                if read_only_flag:
                    cl.append(eb == pre_ext_b)
                    cl.append(ea == pre_ext_a)
                return z3.And(cl)

            # Check Base Obligation & preheader lockstep under outer_rel_assume
            pre_stop_eq_clauses: List[z3.BoolRef] = []
            if parent_exit_targets_b or parent_exit_targets_a:
                pb_leave = self._group_stop_cond(pre_res_b["stopped_edges"], parent_exit_targets_b)
                pa_leave = self._group_stop_cond(pre_res_a["stopped_edges"], parent_exit_targets_a)
                pre_stop_eq_clauses.append(pb_leave == pa_leave)
            base_goal = z3.And(
                pre_stop_eq_clauses + [
                    enter_b == enter_a,
                    bt_b == bt_a,
                    z3.Implies(bt_b, z3.And(br_b == br_a, bm_b == bm_a)),
                    z3.Implies(enter_b, make_inv(init_phi_b, init_phi_a, pre_ext_b, pre_ext_a, pre_loc_b, pre_loc_a)),
                ]
            )
            if not (self.enable_float_theory and z3.is_true(z3.simplify(base_goal))):
                sb_solver = z3.Solver()
                sb_solver.set("timeout", min(timeout_ms, 600) if self.enable_float_theory else timeout_ms)
                sb_solver.add(z3.And(outer_rel_assume, z3.Not(base_goal)))
                if sb_solver.check() != z3.unsat:
                    return {"status": "RESULT", "result": self._probe_bounded_counterexample(ssa_before, ssa_after, timeout_ms)}

            exit_targets_b = {
                s.name for n in lb_set for s in db["block_map"][n].successors if s.name not in lb_set
            }
            exit_targets_a = {
                s.name for n in la_set for s in da["block_map"][n].successors if s.name not in la_set
            }

            l_env_b = dict(pre_res_b["env"])
            for phi in hb_blk.phi_nodes:
                l_env_b[phi.result] = sym_b[(phi.result.name, phi.result.version)]
            l_env_a = dict(pre_res_a["env"])
            for phi in ha_blk.phi_nodes:
                l_env_a[phi.result] = sym_a[(phi.result.name, phi.result.version)]

            loop_assume = z3.And(
                outer_rel_assume,
                enter_b,
                make_inv(sym_b, sym_a, sym_ext_b, sym_ext_a, sym_loc_b, sym_loc_a),
            )
            body_ret = self._verify_loop_sequence_in_region(
                ssa_before=ssa_before, ssa_after=ssa_after, db=db, da=da, sym_params=sym_params,
                scope_b=lb_set, scope_a=la_set,
                exclude_b=exclude_b | {hb}, exclude_a=exclude_a | {ha},
                start_pos_b=hb_idx, start_pos_a=ha_idx,
                init_reach_b={hb: z3.BoolVal(True)}, init_reach_a={ha: z3.BoolVal(True)},
                init_edges_b={}, init_edges_a={},
                init_edge_ext_b={}, init_edge_ext_a={},
                init_edge_loc_b={}, init_edge_loc_a={},
                default_ext_b=sym_ext_b, default_ext_a=sym_ext_a,
                default_loc_b=sym_loc_b, default_loc_a=sym_loc_a,
                init_env_b=l_env_b, init_env_a=l_env_a,
                init_alloc_b=cur_alloc_b, init_alloc_a=cur_alloc_a,
                skip_b={hb}, skip_a={ha},
                stop_targets_b={hb} | exit_targets_b, stop_targets_a={ha} | exit_targets_a,
                allow_allocas=False,
                outer_rel_assume=loop_assume,
                parent_exit_targets_b=exit_targets_b,
                parent_exit_targets_a=exit_targets_a,
                timeout_ms=timeout_ms,
                tag=f"{tag}_d{idx}",
            )
            if body_ret["status"] != "OK":
                return body_ret

            l_res_b, l_res_a = body_ret["res_b"], body_ret["res_a"]
            cont_b, back_b = self._extract_edge_group(l_res_b["stopped_edges"], {hb})
            cont_a, back_a = self._extract_edge_group(l_res_a["stopped_edges"], {ha})
            if cont_b is None or cont_a is None:
                return {"status": "FALLBACK"}

            next_phi_b = self._collect_header_phi_values(hb_blk, back_b, l_res_b)
            next_phi_a = self._collect_header_phi_values(ha_blk, back_a, l_res_a)
            if next_phi_b is None or next_phi_a is None:
                return {"status": "FALLBACK"}

            next_ext_b, next_loc_b = self._merge_pred_mem(l_res_b, back_b)
            next_ext_a, next_loc_a = self._merge_pred_mem(l_res_a, back_a)
            et_b, er_b, em_b = self._combine_ret_cases(l_res_b["ret_cases"], sym_ext_b)
            et_a, er_a, em_a = self._combine_ret_cases(l_res_a["ret_cases"], sym_ext_a)
            leave_b, leave_em_b = self._extract_edge_group(l_res_b["stopped_edges"], exit_targets_b)
            leave_a, leave_em_a = self._extract_edge_group(l_res_a["stopped_edges"], exit_targets_a)
            if leave_b is None:
                leave_b, leave_em_b = z3.BoolVal(False), {}
            if leave_a is None:
                leave_a, leave_em_a = z3.BoolVal(False), {}

            read_only = not body_ret["wrote_ext_mem"]
            if not read_only:
                accum_wrote_ext = True

            step_goal = z3.And(
                cont_b == cont_a,
                et_b == et_a,
                z3.Implies(et_b, z3.And(er_b == er_a, em_b == em_a)),
                z3.Implies(cont_b, make_inv(next_phi_b, next_phi_a, next_ext_b, next_ext_a, next_loc_b, next_loc_a, read_only_flag=read_only)),
                leave_b == leave_a,
            )
            step_assume = (
                z3.And(loop_assume, sym_ext_b == pre_ext_b, sym_ext_a == pre_ext_a)
                if read_only
                else loop_assume
            )
            step_proven_fast = False
            if self.enable_float_theory:
                inv_subst = (
                    [(sym_a[ka], sym_b[kb]) for kb, ka in pairs]
                    + [(sym_ext_a, pre_ext_b if read_only else sym_ext_b), (sym_loc_a, sym_loc_b)]
                    + ([(sym_ext_b, pre_ext_b), (pre_ext_a, pre_ext_b)] if read_only else [])
                    + [(sym_b[kb], init_phi_b[kb]) for kb in rem_b]
                    + [(sym_a[ka], init_phi_a[ka]) for ka in rem_a]
                )
                if z3.is_true(z3.simplify(z3.substitute(step_goal, *inv_subst))):
                    step_proven_fast = True
            if not step_proven_fast:
                st_solver = z3.Solver()
                st_solver.set("timeout", min(timeout_ms, 600) if self.enable_float_theory else timeout_ms)
                st_solver.add(z3.And(step_assume, z3.Not(step_goal)))
                if st_solver.check() != z3.unsat:
                    return {"status": "RESULT", "result": self._probe_bounded_counterexample(ssa_before, ssa_after, timeout_ms)}

            # Summarize proven-equivalent loop exit equally for downstream siblings / parent suffix
            shared_ext_out = pre_ext_b if read_only else z3.Array(f"{tag}_L{idx}_post_ext", bv64, bv64)
            no_loc = (len(cur_alloc_b) == 0 and len(cur_alloc_a) == 0)
            shared_loc_out = pre_loc_b if no_loc else z3.Array(f"{tag}_L{idx}_post_loc", bv64, bv64)
            cur_ext_b = pre_ext_b if read_only else shared_ext_out
            cur_ext_a = pre_ext_a if read_only else shared_ext_out
            cur_loc_b = pre_loc_b if no_loc else shared_loc_out
            cur_loc_a = pre_loc_a if no_loc else shared_loc_out

            cur_env_b = dict(pre_res_b["env"])
            cur_env_a = dict(pre_res_a["env"])
            for p_idx, (kb, ka) in enumerate(pairs):
                sv = z3.BitVec(f"{tag}_L{idx}_post_{p_idx}_{kb[0]}_{kb[1]}", 64)
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

            if not leave_em_b or not leave_em_a:
                return {"status": "FALLBACK"}

            cur_reach_b, cur_reach_a = {}, {}
            cur_edges_b = {e: enter_b for e in leave_em_b.keys()}
            cur_edges_a = {e: enter_a for e in leave_em_a.keys()}
            cur_edge_ext_b = {src: cur_ext_b for (src, _) in cur_edges_b.keys()}
            cur_edge_ext_a = {src: cur_ext_a for (src, _) in cur_edges_a.keys()}
            cur_edge_loc_b = {src: cur_loc_b for (src, _) in cur_edges_b.keys()}
            cur_edge_loc_a = {src: cur_loc_a for (src, _) in cur_edges_a.keys()}

            seen_b |= lb_set
            seen_a |= la_set
            cur_pos_b = hb_idx + 1
            cur_pos_a = ha_idx + 1
            cur_skip_b, cur_skip_a = set(), set()
            cur_allow_allocas = False

        # Tail segment after final top-level loop in scope
        tail_blocks_b = [
            b for b in db["rpo_blocks"]
            if b.name in scope_b and b.name not in seen_b and db["rpo_idx"][b.name] >= cur_pos_b
        ]
        tail_blocks_a = [
            b for b in da["rpo_blocks"]
            if b.name in scope_a and b.name not in seen_a and da["rpo_idx"][b.name] >= cur_pos_a
        ]

        if tail_blocks_b:
            t_res_b = self._run_dag_segment(
                fn=ssa_before, blocks=tail_blocks_b, sym_params=sym_params,
                init_env=cur_env_b, init_alloca_bases=cur_alloc_b,
                entry_reach=cur_reach_b, entry_edge_conds=cur_edges_b,
                entry_ext_mem=cur_edge_ext_b, entry_loc_mem=cur_edge_loc_b,
                default_ext_mem=cur_ext_b, default_loc_mem=cur_loc_b,
                stop_targets=stop_targets_b, skip_phi_blocks=cur_skip_b,
                allow_allocas=False, allowed_ops=allowed_ops,
            )
            if t_res_b.get("error"):
                return {"status": "FALLBACK"}
            if t_res_b["wrote_ext_mem"]:
                accum_wrote_ext = True
            accum_stopped_b.extend(t_res_b["stopped_edges"])
            accum_rets_b.extend(t_res_b["ret_cases"])
            accum_ext_out_b.update(t_res_b["ext_mem_out"])
            accum_loc_out_b.update(t_res_b["loc_mem_out"])
            accum_benv_b.update(t_res_b["block_env"])
            tail_env_b = t_res_b["env"]
        else:
            for (src_n, dst_n), ec in cur_edges_b.items():
                accum_stopped_b.append((src_n, dst_n, ec))
            accum_ext_out_b.update(cur_edge_ext_b)
            accum_loc_out_b.update(cur_edge_loc_b)
            tail_env_b = cur_env_b

        if tail_blocks_a:
            t_res_a = self._run_dag_segment(
                fn=ssa_after, blocks=tail_blocks_a, sym_params=sym_params,
                init_env=cur_env_a, init_alloca_bases=cur_alloc_a,
                entry_reach=cur_reach_a, entry_edge_conds=cur_edges_a,
                entry_ext_mem=cur_edge_ext_a, entry_loc_mem=cur_edge_loc_a,
                default_ext_mem=cur_ext_a, default_loc_mem=cur_loc_a,
                stop_targets=stop_targets_a, skip_phi_blocks=cur_skip_a,
                allow_allocas=False, allowed_ops=allowed_ops,
            )
            if t_res_a.get("error"):
                return {"status": "FALLBACK"}
            if t_res_a["wrote_ext_mem"]:
                accum_wrote_ext = True
            accum_stopped_a.extend(t_res_a["stopped_edges"])
            accum_rets_a.extend(t_res_a["ret_cases"])
            accum_ext_out_a.update(t_res_a["ext_mem_out"])
            accum_loc_out_a.update(t_res_a["loc_mem_out"])
            accum_benv_a.update(t_res_a["block_env"])
            tail_env_a = t_res_a["env"]
        else:
            for (src_n, dst_n), ec in cur_edges_a.items():
                accum_stopped_a.append((src_n, dst_n, ec))
            accum_ext_out_a.update(cur_edge_ext_a)
            accum_loc_out_a.update(cur_edge_loc_a)
            tail_env_a = cur_env_a

        return {
            "status": "OK",
            "res_b": {
                "stopped_edges": accum_stopped_b,
                "ret_cases": accum_rets_b,
                "env": tail_env_b,
                "alloca_bases": cur_alloc_b,
                "ext_mem_out": accum_ext_out_b,
                "loc_mem_out": accum_loc_out_b,
                "block_env": accum_benv_b,
                "wrote_ext_mem": accum_wrote_ext,
            },
            "res_a": {
                "stopped_edges": accum_stopped_a,
                "ret_cases": accum_rets_a,
                "env": tail_env_a,
                "alloca_bases": cur_alloc_a,
                "ext_mem_out": accum_ext_out_a,
                "loc_mem_out": accum_loc_out_a,
                "block_env": accum_benv_a,
                "wrote_ext_mem": accum_wrote_ext,
            },
            "wrote_ext_mem": accum_wrote_ext,
        }

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
        init_loc_b = z3.Array(f"loc_tree_init_B_{ssa_before.name}", bv64, bv64)
        init_loc_a = z3.Array(f"loc_tree_init_A_{ssa_after.name}", bv64, bv64)

        root_ret = self._verify_loop_sequence_in_region(
            ssa_before=ssa_before, ssa_after=ssa_after, db=db, da=da, sym_params=sym_params,
            scope_b={b.name for b in db["rpo_blocks"]},
            scope_a={b.name for b in da["rpo_blocks"]},
            exclude_b=set(), exclude_a=set(),
            start_pos_b=0, start_pos_a=0,
            init_reach_b={db["entry"].name: z3.BoolVal(True)},
            init_reach_a={da["entry"].name: z3.BoolVal(True)},
            init_edges_b={}, init_edges_a={},
            init_edge_ext_b={}, init_edge_ext_a={},
            init_edge_loc_b={}, init_edge_loc_a={},
            default_ext_b=shared_ext_mem, default_ext_a=shared_ext_mem,
            default_loc_b=init_loc_b, default_loc_a=init_loc_a,
            init_env_b={}, init_env_a={},
            init_alloc_b={}, init_alloc_a={},
            skip_b=set(), skip_a=set(),
            stop_targets_b=set(), stop_targets_a=set(),
            allow_allocas=True,
            outer_rel_assume=z3.BoolVal(True),
            parent_exit_targets_b=set(),
            parent_exit_targets_a=set(),
            timeout_ms=timeout_ms,
            tag="rt",
        )
        if root_ret["status"] == "RESULT":
            return root_ret["result"]
        if root_ret["status"] != "OK":
            return None

        ft_b, fr_b, fm_b = self._combine_ret_cases(root_ret["res_b"]["ret_cases"], shared_ext_mem)
        ft_a, fr_a, fm_a = self._combine_ret_cases(root_ret["res_a"]["ret_cases"], shared_ext_mem)
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
        paired_keys, rem_b_raw, rem_a_raw = self._pair_phi_keys(keys_b, keys_a)
        rem_b = [k for k in rem_b_raw if ph_b["next_phi_vals"][k].eq(ph_b["phi_syms"][k])]
        rem_a = [k for k in rem_a_raw if ph_a["next_phi_vals"][k].eq(ph_a["phi_syms"][k])]

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
        base_goal_expr = z3.And(pre_eq, z3.Implies(ph_b["enter_cond"], base_inv))
        if self.enable_float_theory and z3.is_true(z3.simplify(base_goal_expr)):
            base_chk = z3.unsat
        else:
            base_solver = z3.Solver()
            base_solver.set("timeout", min(timeout_ms, 600) if self.enable_float_theory else timeout_ms)
            base_solver.add(z3.Not(base_goal_expr))
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
        step_chk = None
        if self.enable_float_theory:
            step_subst = (
                [(ph_a["phi_syms"][ka], ph_b["phi_syms"][kb]) for kb, ka in paired_keys]
                + [
                    (ph_a["sym_ext_mem"], ph_b["pre_ext_mem"] if read_only_loop else ph_b["sym_ext_mem"]),
                    (ph_a["sym_loc_mem"], ph_b["sym_loc_mem"]),
                ]
                + (
                    [
                        (ph_b["sym_ext_mem"], ph_b["pre_ext_mem"]),
                        (ph_a["pre_ext_mem"], ph_b["pre_ext_mem"]),
                    ]
                    if read_only_loop
                    else []
                )
                + [(ph_b["phi_syms"][kb], ph_b["init_phi_vals"][kb]) for kb in rem_b]
                + [(ph_a["phi_syms"][ka], ph_a["init_phi_vals"][ka]) for ka in rem_a]
            )
            if z3.is_true(z3.simplify(z3.substitute(step_goal, *step_subst))):
                step_chk = z3.unsat
        if step_chk is None:
            step_solver = z3.Solver()
            step_solver.set("timeout", min(timeout_ms, 600) if self.enable_float_theory else timeout_ms)
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
        if step_chk == z3.sat or (self.enable_float_theory and step_chk == z3.unknown):
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

        # Exact Z3 AST reflexivity + algebraic simplification fast-path
        if ret_b.eq(ret_a) and mem_b.eq(mem_a) and (not is_bounded or term_b.eq(term_a)):
            return {
                "proven": True,
                "status": "PROVEN_BOUNDED_EQUIVALENT" if is_bounded else "PROVEN_EQUIVALENT",
                "counterexample": None,
                "bounded": is_bounded,
            }

        if self.enable_float_theory and (
            z3.simplify(ret_b).eq(z3.simplify(ret_a))
            and z3.simplify(mem_b).eq(z3.simplify(mem_a))
            and (not is_bounded or z3.simplify(term_b).eq(term_a))
        ):
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

        # Fast sound Z3 QF_FP / QF_ABVFP witness substitution before full 53-bit FP bit-blasting
        if self.enable_float_theory and sym_params:
            pt_before = getattr(ssa_before, "param_types", {}) or {}
            pt_after = getattr(ssa_after, "param_types", {}) or {}
            ptr_params: Set[str] = {
                p for p in ssa_before.params
                if pt_before.get(p) in ("ptr", "ptr_f64") or pt_after.get(p) in ("ptr", "ptr_f64")
            }
            for fn_cand in (ssa_before, ssa_after):
                for blk in fn_cand.blocks:
                    for ins in blk.instructions:
                        if ins.opcode in ("load", "store", "load_off", "store_off") and ins.operands:
                            b_op = ins.operands[0]
                            if isinstance(b_op, SSAVar) and b_op.version == 0 and b_op.name in ssa_before.params:
                                ptr_params.add(b_op.name)
            witness_tuples = [
                (0.1, 0.2, 0.3, 1.0, 2.0, -1.0),
                (1e16, -1e16, 1.0, 2.0, 3.0, 4.0),
                (2.0, 2.0, 3.0, 2.0, 2.0, 2.0),
                (2.5, -1.25, 0.5, -3.0, 1.5, -0.5),
                (0.0, 0.0, 0.0, 0.0, 0.0, 0.0),
                (-2.0, 4.0, -0.25, 0.75, 1.25, -1.5),
            ]
            probe_addrs = [
                z3.BitVecVal(0x10000 + i * 0x1000 + off, 64)
                for i in range(len(sym_params))
                for off in (0, 4, 8, 16)
            ]
            mem_probe_disj = [z3.Select(mem_b, pa) != z3.Select(mem_a, pa) for pa in probe_addrs]
            if is_bounded:
                conc_mismatch = z3.Or(
                    term_b != term_a,
                    z3.And(term_b, term_a, z3.Or(ret_b != ret_a, *mem_probe_disj)),
                )
            else:
                conc_mismatch = z3.Or(ret_b != ret_a, *mem_probe_disj)
            init_mem_k = z3.K(bv64, self._float_to_bv(1.5))
            for wt in witness_tuples:
                subst_pairs = [(shared_ext_mem, init_mem_k)]
                ce_cand = {}
                for idx_p, p_sym in enumerate(sym_params):
                    pname = ssa_before.params[idx_p]
                    raw_v = wt[idx_p % len(wt)]
                    pty_b = pt_before.get(pname, "i64")
                    pty_a = pt_after.get(pname, "i64")
                    if pty_b == "f64" or pty_a == "f64":
                        bv_val = self._float_to_bv(float(raw_v))
                        ce_cand[pname] = float(raw_v)
                    elif pname in ptr_params:
                        ptr_addr = 0x10000 + idx_p * 0x1000
                        bv_val = z3.BitVecVal(ptr_addr, 64)
                        ce_cand[pname] = ptr_addr
                    else:
                        iv = int(raw_v)
                        bv_val = z3.BitVecVal(iv, 64)
                        ce_cand[pname] = iv
                    subst_pairs.append((p_sym, bv_val))
                if z3.is_true(z3.simplify(z3.substitute(conc_mismatch, *subst_pairs))):
                    return {
                        "proven": False,
                        "status": "REFUTED_COUNTEREXAMPLE",
                        "counterexample": ce_cand,
                        "bounded": is_bounded,
                    }

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
        enable_float_theory: bool = False,
    ):
        self.validator = SSATranslationValidator(
            enable_memory_theory=enable_memory_theory,
            max_loop_unroll=max_loop_unroll,
            enable_inductive_loops=enable_inductive_loops,
            enable_float_theory=enable_float_theory,
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
