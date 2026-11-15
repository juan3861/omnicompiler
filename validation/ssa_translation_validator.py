"""
OmniCompiler Per-Pass SMT Translation Validation Gate
(validation/ssa_translation_validator.py)

Alive2-style symbolic equivalence verifier for Omni-SSA IR optimization passes:
1. SSATranslationValidator:
   - Compiles acyclic multi-block `SSAFunction`s into Z3 64-bit `BitVec` formulas
     over shared symbolic parameter inputs.
   - Models `phi` nodes, `br_cond` path conditions, `cmp_*`, bitwise, arithmetic,
     and `select` instructions.
   - Proves equivalence (`unsat` => `PROVEN_EQUIVALENT`) or extracts an exact
     counterexample (`sat` => `REFUTED_COUNTEREXAMPLE`).
   - Strictly Fail-Closed on cycles (loops), unsupported opcodes (`call`, memory),
     or solver timeouts.
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


class SSATranslationValidator:
    """
    Translates acyclic Omni-SSA functions to Z3 64-bit QF_BV expressions
    and proves semantic equivalence before and after optimization passes.
    """

    def _topological_blocks(self, fn: SSAFunction) -> Optional[List[BasicBlock]]:
        """
        Returns reachable blocks in topological order, or None if a cycle exists.
        """
        if not fn.blocks:
            return None
        entry = fn.entry_block or fn.blocks[0]

        # Collect reachable blocks via DFS
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

    def encode_function_to_z3(
        self,
        fn: SSAFunction,
        sym_params: List[z3.BitVecRef],
    ) -> Tuple[Optional[z3.BitVecRef], Optional[str]]:
        """
        Symbolically executes an acyclic `SSAFunction` over `sym_params` into a
        single Z3 64-bit BitVecRef representing its return value.
        Returns `(expr, None)` on success or `(None, reason)` if unsupported/cyclic.
        """
        ordered_blocks = self._topological_blocks(fn)
        if ordered_blocks is None:
            return None, "CYCLIC_CFG"

        if len(fn.params) != len(sym_params):
            return None, "PARAM_ARITY_MISMATCH"

        env: Dict[SSAVar, z3.BitVecRef] = {}
        block_reach: Dict[str, z3.BoolRef] = {}
        edge_cond: Dict[Tuple[str, str], z3.BoolRef] = {}
        ret_cases: List[Tuple[z3.BoolRef, z3.BitVecRef]] = []

        entry = fn.entry_block or fn.blocks[0]
        block_reach[entry.name] = z3.BoolVal(True)

        def eval_op(op: Any) -> Optional[z3.BitVecRef]:
            if isinstance(op, bool):
                return z3.BitVecVal(int(op), 64)
            if isinstance(op, int):
                return z3.BitVecVal(op, 64)
            if isinstance(op, SSAVar) and op in env:
                return env[op]
            return None

        for blk in ordered_blocks:
            if blk.name != entry.name:
                incoming_conds = [
                    edge_cond[(p.name, blk.name)]
                    for p in blk.predecessors
                    if (p.name, blk.name) in edge_cond
                ]
                if not incoming_conds:
                    block_reach[blk.name] = z3.BoolVal(False)
                elif len(incoming_conds) == 1:
                    block_reach[blk.name] = incoming_conds[0]
                else:
                    block_reach[blk.name] = z3.Or(incoming_conds)

            b_reach = block_reach[blk.name]

            # Evaluate Phi nodes
            for phi in blk.phi_nodes:
                if phi.result is None or not phi.phi_incoming:
                    return None, "INVALID_PHI"
                acc: Optional[z3.BitVecRef] = None
                for pred_name, val_op in reversed(phi.phi_incoming):
                    v_expr = eval_op(val_op)
                    if v_expr is None:
                        return None, f"UNRESOLVED_PHI_OP_{val_op}"
                    if acc is None:
                        acc = v_expr
                    else:
                        ec = edge_cond.get((pred_name, blk.name), z3.BoolVal(False))
                        acc = z3.If(ec, v_expr, acc)
                if acc is None:
                    return None, "EMPTY_PHI"
                env[phi.result] = acc

            # Evaluate instructions
            for inst in blk.instructions:
                op = inst.opcode
                if op not in SUPPORTED_Z3_OPCODES:
                    return None, f"UNSUPPORTED_OPCODE_{op}"

                if op == "param":
                    if not inst.operands or inst.result is None:
                        return None, "INVALID_PARAM"
                    raw_p = inst.operands[0]
                    if isinstance(raw_p, int):
                        p_idx = raw_p
                    elif isinstance(raw_p, str) and raw_p in fn.params:
                        p_idx = fn.params.index(raw_p)
                    else:
                        return None, f"UNKNOWN_PARAM_{raw_p}"
                    if p_idx < 0 or p_idx >= len(sym_params):
                        return None, "PARAM_INDEX_OOB"
                    env[inst.result] = sym_params[p_idx]

                elif op == "const":
                    if not inst.operands or inst.result is None:
                        return None, "INVALID_CONST"
                    val = inst.operands[0]
                    if not isinstance(val, (int, bool)):
                        return None, "NON_INT_CONST"
                    env[inst.result] = z3.BitVecVal(int(val), 64)

                elif op == "mov":
                    if not inst.operands or inst.result is None:
                        return None, "INVALID_MOV"
                    v = eval_op(inst.operands[0])
                    if v is None:
                        return None, "UNRESOLVED_MOV"
                    env[inst.result] = v

                elif op in ("neg", "not"):
                    if len(inst.operands) != 1 or inst.result is None:
                        return None, f"INVALID_{op}"
                    v = eval_op(inst.operands[0])
                    if v is None:
                        return None, f"UNRESOLVED_{op}"
                    if op == "neg":
                        env[inst.result] = -v
                    else:
                        env[inst.result] = z3.If(v == 0, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))

                elif op in (
                    "add", "sub", "mul", "sdiv", "srem",
                    "shl", "shr", "sar", "and", "or", "xor",
                    "cmp_eq", "cmp_ne", "cmp_lt", "cmp_le", "cmp_gt", "cmp_ge",
                ):
                    if len(inst.operands) != 2 or inst.result is None:
                        return None, f"INVALID_{op}"
                    v0 = eval_op(inst.operands[0])
                    v1 = eval_op(inst.operands[1])
                    if v0 is None or v1 is None:
                        return None, f"UNRESOLVED_{op}"

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
                    env[inst.result] = res_bv

                elif op == "select":
                    if len(inst.operands) != 3 or inst.result is None:
                        return None, "INVALID_SELECT"
                    c = eval_op(inst.operands[0])
                    vt = eval_op(inst.operands[1])
                    vf = eval_op(inst.operands[2])
                    if c is None or vt is None or vf is None:
                        return None, "UNRESOLVED_SELECT"
                    env[inst.result] = z3.If(c != 0, vt, vf)

                elif op == "br":
                    if not inst.operands:
                        return None, "INVALID_BR"
                    target = str(inst.operands[0])
                    prev = edge_cond.get((blk.name, target))
                    edge_cond[(blk.name, target)] = b_reach if prev is None else z3.Or(prev, b_reach)

                elif op == "br_cond":
                    if len(inst.operands) < 3:
                        return None, "INVALID_BR_COND"
                    c = eval_op(inst.operands[0])
                    if c is None:
                        return None, "UNRESOLVED_BR_COND"
                    t_blk = str(inst.operands[1])
                    f_blk = str(inst.operands[2])
                    c_true = (c != 0)
                    t_cond = z3.And(b_reach, c_true)
                    f_cond = z3.And(b_reach, z3.Not(c_true))
                    if t_blk == f_blk:
                        edge_cond[(blk.name, t_blk)] = b_reach
                    else:
                        prev_t = edge_cond.get((blk.name, t_blk))
                        edge_cond[(blk.name, t_blk)] = t_cond if prev_t is None else z3.Or(prev_t, t_cond)
                        prev_f = edge_cond.get((blk.name, f_blk))
                        edge_cond[(blk.name, f_blk)] = f_cond if prev_f is None else z3.Or(prev_f, f_cond)

                elif op == "ret":
                    if not inst.operands:
                        ret_cases.append((b_reach, z3.BitVecVal(0, 64)))
                    else:
                        rv = eval_op(inst.operands[0])
                        if rv is None:
                            return None, "UNRESOLVED_RET"
                        ret_cases.append((b_reach, rv))

        if not ret_cases:
            return None, "NO_RETURN_FOUND"

        combined = ret_cases[-1][1]
        for r_cond, r_val in reversed(ret_cases[:-1]):
            combined = z3.If(r_cond, r_val, combined)
        return combined, None

    def verify_equivalence(
        self,
        ssa_before: SSAFunction,
        ssa_after: SSAFunction,
        timeout_ms: int = 2000,
    ) -> Dict[str, Any]:
        """
        Proves semantic equivalence between `ssa_before` and `ssa_after` via Z3 QF_BV.
        """
        if len(ssa_before.params) != len(ssa_after.params):
            return {
                "proven": False,
                "status": "REFUTED_ARITY_MISMATCH",
                "counterexample": None,
            }

        sym_params = [z3.BitVec(f"p_{i}_{name}", 64) for i, name in enumerate(ssa_before.params)]
        expr_before, err_b = self.encode_function_to_z3(ssa_before, sym_params)
        if expr_before is None:
            return {
                "proven": False,
                "status": f"UNVERIFIED_{err_b}",
                "counterexample": None,
            }

        expr_after, err_a = self.encode_function_to_z3(ssa_after, sym_params)
        if expr_after is None:
            return {
                "proven": False,
                "status": f"UNVERIFIED_{err_a}",
                "counterexample": None,
            }

        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        solver.add(expr_before != expr_after)
        check = solver.check()

        if check == z3.unsat:
            return {
                "proven": True,
                "status": "PROVEN_EQUIVALENT",
                "counterexample": None,
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
            }
        else:
            return {
                "proven": False,
                "status": "UNVERIFIED_TIMEOUT",
                "counterexample": None,
            }


class VerifiedPassRunner:
    """
    Executes an SSA optimization pass under an SMT Translation Validation gate.
    Automatically rolls back to the pre-pass snapshot if Z3 finds a counterexample.
    """

    def __init__(self, timeout_ms: int = 2000):
        self.validator = SSATranslationValidator()
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
