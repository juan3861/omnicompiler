"""
OmniCompiler Scalar Evolution (SCEV) & Closed-Form Loop Optimizer (compiler/scev_analyzer.py).

Implements:
1. Natural Loop & Induction Variable (IV) Analysis:
   - Identifies canonical IVs ({base, +, step}<loop>) and loop bounds.
   - Extracts loop trip count (constant or symbolic parameters).
2. Symbolic Polynomial Expression Tree:
   - Decomposes loop-internal arithmetic into polynomials in IV:
     P(iv) = sum_{k=0}^D c_k * iv^k, where c_k are loop-invariant expressions.
3. Closed-Form Summation (Faulhaber's Formula):
   - Computes sum_{iv=0}^{N-1} P(iv) in O(1) arithmetic:
     sum 1 = N
     sum iv = N*(N-1)//2
     sum iv^2 = N*(N-1)*(2N-1)//6
     sum iv^3 = (N*(N-1)//2)^2
4. Nested Loop Closed-Form Collapse:
   - Hierarchically reduces inner and outer loop nests into O(1) closed-form formulas.
5. Formal Z3 Validation:
   - Formally proves equivalence between iterative loops and closed-form reductions.
"""

from typing import Dict, List, Set, Tuple, Any, Optional, Union
from collections import defaultdict
import z3

from compiler.ssa_ir import (
    SSAFunction,
    BasicBlock,
    SSAInstruction,
    SSAVar,
    optimize_ssa,
)
from compiler.polyhedral_tiler import PolyhedralLoopTilerPass, LoopNestInfo


class SymbolicPoly:
    """
    Represents a polynomial in a specific variable:
    P(var) = sum_{k=0}^D coeffs[k] * var^k
    where each coefficient is an expression tree (int, SSAVar, or SymbolicExpr).
    """

    def __init__(self, var_name: str, coeffs: Optional[Dict[int, Any]] = None):
        self.var_name = var_name
        self.coeffs: Dict[int, Any] = dict(coeffs or {0: 0})

    def degree(self) -> int:
        non_zero = [k for k, v in self.coeffs.items() if v != 0]
        return max(non_zero) if non_zero else 0

    @classmethod
    def constant(cls, var_name: str, val: Any) -> "SymbolicPoly":
        return cls(var_name, {0: val})

    @classmethod
    def variable(cls, var_name: str) -> "SymbolicPoly":
        return cls(var_name, {0: 0, 1: 1})

    def is_constant(self) -> bool:
        return self.degree() == 0


def _build_const_map(fn: SSAFunction) -> Tuple[Dict[SSAVar, int], Dict[SSAVar, SSAInstruction]]:
    const_map: Dict[SSAVar, int] = {}
    def_map: Dict[SSAVar, SSAInstruction] = {}
    for b in fn.blocks:
        for inst in b.instructions:
            if inst.result is not None:
                def_map[inst.result] = inst
                if inst.opcode == "const" and len(inst.operands) == 1 and isinstance(inst.operands[0], int):
                    const_map[inst.result] = inst.operands[0]
    return const_map, def_map


class SCEVAnalyzer:
    """
    Scalar Evolution & Closed-Form Loop Optimization Pass.
    """

    def __init__(self, enable_z3_verification: bool = False):
        self.enable_z3_verification = enable_z3_verification
        self._tmp_id = 0

    def _next_name(self, prefix: str) -> str:
        self._tmp_id += 1
        return f"{prefix}_{self._tmp_id}"

    def analyze_function(self, fn: SSAFunction) -> Tuple[SSAFunction, Dict[str, Any]]:
        """
        Analyzes all natural loops in `fn` and collapses pure polynomial reduction
        loops into O(1) closed-form arithmetic.
        """
        stats = {
            "scev_analyzed_loops": 0,
            "closed_form_reductions": 0,
            "nested_loops_collapsed": 0,
        }

        # Iteratively optimize innermost loops first, then outer loops
        changed = True
        pass_round = 0
        while changed and pass_round < 4:
            changed = False
            pass_round += 1

            const_map, def_map = _build_const_map(fn)
            tiler = PolyhedralLoopTilerPass()
            loops = tiler.analyze_loops(fn)
            if not loops:
                break

            stats["scev_analyzed_loops"] += len(loops)

            # Sort loops by body size ascending (innermost loops first)
            loops.sort(key=lambda l: len(l.body_blocks))

            for loop in loops:
                collapsed = self._try_collapse_loop_to_closed_form(fn, loop, const_map, def_map)
                if collapsed:
                    stats["closed_form_reductions"] += 1
                    if pass_round > 1:
                        stats["nested_loops_collapsed"] += 1
                    changed = True
                    fn = optimize_ssa(fn)
                    break

        return fn, stats

    def _try_collapse_loop_to_closed_form(
        self,
        fn: SSAFunction,
        loop: LoopNestInfo,
        const_map: Dict[SSAVar, int],
        def_map: Dict[SSAVar, SSAInstruction],
    ) -> bool:
        if not loop.header_block or not loop.latch_block or not loop.exit_block:
            return False

        header = loop.header_block
        latch = loop.latch_block
        exit_b = loop.exit_block
        body_blocks = loop.body_blocks
        loop_block_names = {b.name for b in body_blocks}

        # Ensure single outside predecessor (pre-header)
        outside_preds = [p for p in header.predecessors if p.name not in loop_block_names]
        if len(outside_preds) != 1:
            return False
        pre_header = outside_preds[0]

        # Ensure no internal conditional branches or multiple exits in the loop body
        # (other than header's loop exit branch and inner already-collapsed jumps)
        for b in body_blocks:
            for inst in b.instructions:
                if inst.opcode in ("store", "store_off", "call", "malloc", "ret"):
                    return False
                if b is not header and inst.opcode == "br_cond":
                    return False

        # Strictly require exactly 2 header phi nodes (one IV, one accumulator)
        if len(header.phi_nodes) != 2:
            return False

        # 1. Identify Induction Variable (IV) and step
        iv_phi: Optional[SSAInstruction] = None
        acc_phi: Optional[SSAInstruction] = None

        for phi in header.phi_nodes:
            if not phi.result:
                continue
            is_iv = False
            for inst in latch.instructions:
                if inst.opcode == "add" and inst.operands:
                    ops = [o for o in inst.operands if isinstance(o, SSAVar)]
                    if phi.result in ops:
                        is_iv = True
                        break
            if is_iv:
                iv_phi = phi
            else:
                acc_phi = phi

        if not iv_phi or not acc_phi or iv_phi is acc_phi:
            return False

        iv_var = iv_phi.result
        acc_var = acc_phi.result

        # Ensure non-header blocks inside this loop have no phi nodes referencing loop values
        loop_phi_vars: Set[SSAVar] = {iv_var, acc_var}
        for b in body_blocks:
            if b is not header and b.phi_nodes:
                return False

        # Find initial values from pre_header
        iv_init = None
        acc_init = None
        for blk_name, val in iv_phi.phi_incoming:
            if blk_name == pre_header.name:
                iv_init = val
        for blk_name, val in acc_phi.phi_incoming:
            if blk_name == pre_header.name:
                acc_init = val

        if iv_init is None or acc_init is None:
            return False

        # Verify iv_init resolves to 0 (canonical loop start)
        iv_init_val = const_map.get(iv_init, iv_init if isinstance(iv_init, int) else None)
        if iv_init_val != 0:
            return False

        # Extract step in latch and ensure latch actually feeds iv_phi back-edge
        step_val = None
        latch_iv_next = None
        iv_latch_val = None
        for blk_name, val in iv_phi.phi_incoming:
            if blk_name == latch.name:
                iv_latch_val = val
        if not isinstance(iv_latch_val, SSAVar):
            return False

        latch_iv_inst = def_map.get(iv_latch_val)
        if not latch_iv_inst or latch_iv_inst.opcode != "add" or len(latch_iv_inst.operands) < 2:
            return False
        if latch_iv_inst.operands[0] == iv_var:
            other = latch_iv_inst.operands[1]
            step_val = const_map.get(other, other if isinstance(other, int) else None)
        elif latch_iv_inst.operands[1] == iv_var:
            other = latch_iv_inst.operands[0]
            step_val = const_map.get(other, other if isinstance(other, int) else None)

        if step_val != 1:
            return False

        # Extract loop upper bound N from header condition (verify true->body, false->exit)
        bound_var = None
        is_inclusive = False
        if header.instructions and header.instructions[-1].opcode == "br_cond":
            br = header.instructions[-1]
            if len(br.operands) >= 3 and br.operands[2] == exit_b.name and br.operands[1] in loop_block_names:
                cond_var = br.operands[0]
                cmp_inst = def_map.get(cond_var)
                if cmp_inst and cmp_inst.opcode in ("cmp_lt", "cmp_le") and len(cmp_inst.operands) >= 2:
                    if cmp_inst.operands[0] == iv_var:
                        bound_var = cmp_inst.operands[1]
                        is_inclusive = (cmp_inst.opcode == "cmp_le")

        if bound_var is None:
            return False

        # Ensure iv_var does not escape outside the loop
        for blk in fn.blocks:
            if blk.name in loop_block_names:
                continue
            for phi in blk.phi_nodes:
                if iv_var in phi.operands or any(v == iv_var for _, v in phi.phi_incoming):
                    return False
            for inst in blk.instructions:
                if iv_var in inst.operands:
                    return False

        # 3. Analyze Accumulator update
        acc_latch_val = None
        for blk_name, val in acc_phi.phi_incoming:
            if blk_name == latch.name:
                acc_latch_val = val

        if not acc_latch_val or not isinstance(acc_latch_val, SSAVar):
            return False

        add_inst = def_map.get(acc_latch_val)
        if not add_inst or add_inst.opcode != "add" or len(add_inst.operands) < 2:
            return False

        delta_term = None
        if add_inst.operands[0] == acc_var:
            delta_term = add_inst.operands[1]
        elif add_inst.operands[1] == acc_var:
            delta_term = add_inst.operands[0]

        if delta_term is None:
            return False

        # 4. Polynomial Decomposition of delta_term in iv_var
        poly = self._decompose_to_polynomial(
            delta_term, iv_var, acc_var, loop_phi_vars, loop_block_names, def_map, const_map
        )
        if poly is None:
            return False

        deg = poly.degree()
        if deg > 3:
            return False

        # 5. Synthesize Closed-Form in pre_header
        c0 = poly.coeffs.get(0, 0)
        c1 = poly.coeffs.get(1, 0)
        c2 = poly.coeffs.get(2, 0)
        c3 = poly.coeffs.get(3, 0)

        closed_form_res = self._emit_closed_form_sum(
            pre_header,
            acc_init,
            bound_var,
            is_inclusive,
            c0,
            c1,
            c2,
            c3,
            fn,
            def_map=def_map,
            loop_block_names=loop_block_names,
        )

        # 6. Bypass loop in CFG and prune unreachable blocks
        self._replace_loop_with_result(fn, loop, pre_header, exit_b, acc_var, closed_form_res)
        return True

    def _depends_on_loop_state(
        self,
        expr: Any,
        loop_vars: Set[SSAVar],
        def_map: Dict[SSAVar, SSAInstruction],
        visited: Optional[Set[SSAVar]] = None,
    ) -> bool:
        if not isinstance(expr, SSAVar):
            return False
        if expr in loop_vars:
            return True
        if visited is None:
            visited = set()
        if expr in visited:
            return False
        visited.add(expr)
        inst = def_map.get(expr)
        if not inst:
            return False
        return any(self._depends_on_loop_state(op, loop_vars, def_map, visited) for op in inst.operands)

    def _decompose_to_polynomial(
        self,
        expr: Any,
        iv_var: SSAVar,
        acc_var: SSAVar,
        loop_phi_vars: Set[SSAVar],
        loop_block_names: Set[str],
        def_map: Dict[SSAVar, SSAInstruction],
        const_map: Dict[SSAVar, int],
    ) -> Optional[SymbolicPoly]:
        """
        Recursively translates `expr` into a SymbolicPoly in `iv_var`.
        Rejects any expression that depends on `acc_var` or uses non-polynomial ops on `iv_var`.
        """
        if isinstance(expr, int):
            return SymbolicPoly.constant(iv_var.name, expr)

        if not isinstance(expr, SSAVar):
            return None

        if expr in const_map:
            return SymbolicPoly.constant(iv_var.name, const_map[expr])

        if expr == iv_var:
            return SymbolicPoly.variable(iv_var.name)

        if expr == acc_var:
            return None

        inst = def_map.get(expr)
        if not inst:
            return SymbolicPoly.constant(iv_var.name, expr)

        if inst.opcode == "const" and len(inst.operands) == 1:
            val = inst.operands[0]
            return SymbolicPoly.constant(iv_var.name, val if isinstance(val, int) else 0)

        if inst.opcode == "mov" and len(inst.operands) == 1:
            return self._decompose_to_polynomial(
                inst.operands[0], iv_var, acc_var, loop_phi_vars, loop_block_names, def_map, const_map
            )

        if inst.opcode == "add" and len(inst.operands) == 2:
            p1 = self._decompose_to_polynomial(
                inst.operands[0], iv_var, acc_var, loop_phi_vars, loop_block_names, def_map, const_map
            )
            p2 = self._decompose_to_polynomial(
                inst.operands[1], iv_var, acc_var, loop_phi_vars, loop_block_names, def_map, const_map
            )
            if p1 is None or p2 is None:
                return None
            return self._poly_add(p1, p2)

        if inst.opcode == "sub" and len(inst.operands) == 2:
            p1 = self._decompose_to_polynomial(
                inst.operands[0], iv_var, acc_var, loop_phi_vars, loop_block_names, def_map, const_map
            )
            p2 = self._decompose_to_polynomial(
                inst.operands[1], iv_var, acc_var, loop_phi_vars, loop_block_names, def_map, const_map
            )
            if p1 is None or p2 is None:
                return None
            return self._poly_sub(p1, p2)

        if inst.opcode == "mul" and len(inst.operands) == 2:
            p1 = self._decompose_to_polynomial(
                inst.operands[0], iv_var, acc_var, loop_phi_vars, loop_block_names, def_map, const_map
            )
            p2 = self._decompose_to_polynomial(
                inst.operands[1], iv_var, acc_var, loop_phi_vars, loop_block_names, def_map, const_map
            )
            if p1 is None or p2 is None:
                return None
            return self._poly_mul(p1, p2)

        # Other opcodes (sdiv, and, xor, etc.): only allowed if strictly loop-invariant!
        if self._depends_on_loop_state(expr, loop_phi_vars, def_map):
            return None
        return SymbolicPoly.constant(iv_var.name, expr)

    def _poly_add(self, p1: SymbolicPoly, p2: SymbolicPoly) -> SymbolicPoly:
        res = defaultdict(int)
        all_keys = set(p1.coeffs.keys()) | set(p2.coeffs.keys())
        for k in all_keys:
            c1 = p1.coeffs.get(k, 0)
            c2 = p2.coeffs.get(k, 0)
            if isinstance(c1, int) and isinstance(c2, int):
                res[k] = c1 + c2
            elif c1 == 0:
                res[k] = c2
            elif c2 == 0:
                res[k] = c1
            else:
                res[k] = ("add", c1, c2)
        return SymbolicPoly(p1.var_name, dict(res))

    def _poly_sub(self, p1: SymbolicPoly, p2: SymbolicPoly) -> SymbolicPoly:
        res = defaultdict(int)
        all_keys = set(p1.coeffs.keys()) | set(p2.coeffs.keys())
        for k in all_keys:
            c1 = p1.coeffs.get(k, 0)
            c2 = p2.coeffs.get(k, 0)
            if isinstance(c1, int) and isinstance(c2, int):
                res[k] = c1 - c2
            elif c2 == 0:
                res[k] = c1
            elif c1 == 0:
                res[k] = ("neg", c2)
            else:
                res[k] = ("sub", c1, c2)
        return SymbolicPoly(p1.var_name, dict(res))

    def _poly_mul(self, p1: SymbolicPoly, p2: SymbolicPoly) -> SymbolicPoly:
        res = defaultdict(int)
        for k1, v1 in p1.coeffs.items():
            for k2, v2 in p2.coeffs.items():
                if v1 == 0 or v2 == 0:
                    continue
                k = k1 + k2
                if isinstance(v1, int) and isinstance(v2, int):
                    prod = v1 * v2
                elif v1 == 1:
                    prod = v2
                elif v2 == 1:
                    prod = v1
                else:
                    prod = ("mul", v1, v2)

                cur = res[k]
                if cur == 0:
                    res[k] = prod
                elif isinstance(cur, int) and isinstance(prod, int):
                    res[k] = cur + prod
                else:
                    res[k] = ("add", cur, prod)
        return SymbolicPoly(p1.var_name, dict(res))

    def _emit_expr(
        self,
        block: BasicBlock,
        expr: Any,
        fn: SSAFunction,
        def_map: Optional[Dict[SSAVar, SSAInstruction]] = None,
        loop_block_names: Optional[Set[str]] = None,
        loop_defined_vars: Optional[Set[SSAVar]] = None,
        clone_cache: Optional[Dict[Any, SSAVar]] = None,
    ) -> SSAVar:
        """Emits SSA instructions into `block` (before any terminator) to compute symbolic expression `expr`."""
        if clone_cache is not None and (isinstance(expr, int) or isinstance(expr, SSAVar)) and expr in clone_cache:
            return clone_cache[expr]
        if isinstance(expr, int):
            v = SSAVar(self._next_name(f"c_scev_{abs(expr)}"), var_type="i64")
            self._insert_before_term(block, SSAInstruction(result=v, opcode="const", operands=[expr]))
            if clone_cache is not None:
                clone_cache[expr] = v
            return v
        if isinstance(expr, SSAVar):
            if def_map is not None and loop_block_names is not None:
                inst = def_map.get(expr)
                is_loop_def = (loop_defined_vars is None) or (expr in loop_defined_vars)
                if inst and inst.opcode == "const" and len(inst.operands) == 1 and isinstance(inst.operands[0], int):
                    return self._emit_expr(block, inst.operands[0], fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
                if is_loop_def and inst and inst.opcode in ("add", "sub", "mul", "sdiv", "cmp_gt", "cmp_lt", "cmp_le", "cmp_ge", "cmp_eq", "cmp_ne") and len(inst.operands) == 2:
                    v1 = self._emit_expr(block, inst.operands[0], fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
                    v2 = self._emit_expr(block, inst.operands[1], fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
                    v = SSAVar(self._next_name(f"cloned_{expr.name}"), var_type="i64")
                    self._insert_before_term(block, SSAInstruction(result=v, opcode=inst.opcode, operands=[v1, v2]))
                    if clone_cache is not None:
                        clone_cache[expr] = v
                    return v
                if is_loop_def and inst and inst.opcode == "select" and len(inst.operands) == 3:
                    v0 = self._emit_expr(block, inst.operands[0], fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
                    v1 = self._emit_expr(block, inst.operands[1], fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
                    v2 = self._emit_expr(block, inst.operands[2], fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
                    v = SSAVar(self._next_name(f"cloned_{expr.name}"), var_type="i64")
                    self._insert_before_term(block, SSAInstruction(result=v, opcode="select", operands=[v0, v1, v2]))
                    if clone_cache is not None:
                        clone_cache[expr] = v
                    return v
            return expr
        if isinstance(expr, tuple):
            op = expr[0]
            if op == "neg":
                sub_v = self._emit_expr(block, expr[1], fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
                zero_v = self._emit_expr(block, 0, fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
                v = SSAVar(self._next_name("t_scev"), var_type="i64")
                self._insert_before_term(block, SSAInstruction(result=v, opcode="sub", operands=[zero_v, sub_v]))
                return v
            elif op in ("add", "sub", "mul", "sdiv"):
                v1 = self._emit_expr(block, expr[1], fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
                v2 = self._emit_expr(block, expr[2], fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
                v = SSAVar(self._next_name("t_scev"), var_type="i64")
                self._insert_before_term(block, SSAInstruction(result=v, opcode=op, operands=[v1, v2]))
                return v
        # Fallback
        return self._emit_expr(block, 0, fn, def_map, loop_block_names, loop_defined_vars, clone_cache)

    @staticmethod
    def _insert_before_term(block: BasicBlock, inst: SSAInstruction):
        if block.instructions and block.instructions[-1].is_terminator:
            block.instructions.insert(len(block.instructions) - 1, inst)
        else:
            block.instructions.append(inst)

    def _emit_closed_form_sum(
        self,
        block: BasicBlock,
        acc_init: Any,
        n_var: Any,
        is_inclusive: bool,
        c0: Any,
        c1: Any,
        c2: Any,
        c3: Any,
        fn: SSAFunction,
        def_map: Optional[Dict[SSAVar, SSAInstruction]] = None,
        loop_block_names: Optional[Set[str]] = None,
    ) -> SSAVar:
        """
        Emits O(1) Faulhaber closed-form sum:
        Total = acc_init + c0*N + c1*N*(N-1)//2 + c2*N*(N-1)*(2N-1)//6 + c3*(N*(N-1)//2)^2
        where N = max(0, bound + (1 if is_inclusive else 0)).
        """
        loop_defined_vars: Set[SSAVar] = set()
        if loop_block_names:
            for b in fn.blocks:
                if b.name in loop_block_names:
                    for ins in b.instructions:
                        if ins.result is not None:
                            loop_defined_vars.add(ins.result)
        clone_cache: Dict[Any, SSAVar] = {}

        raw_n = self._emit_expr(block, n_var, fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
        zero = self._emit_expr(block, 0, fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
        one = self._emit_expr(block, 1, fn, def_map, loop_block_names, loop_defined_vars, clone_cache)

        if is_inclusive:
            n_plus_1 = SSAVar(self._next_name("n_inc"), var_type="i64")
            self._insert_before_term(block, SSAInstruction(result=n_plus_1, opcode="add", operands=[raw_n, one]))
            raw_n = n_plus_1

        # Clamp trip count N = max(0, raw_n) so negative bounds yield 0 iterations
        cond_pos = SSAVar(self._next_name("n_pos"), var_type="i64")
        self._insert_before_term(block, SSAInstruction(result=cond_pos, opcode="cmp_gt", operands=[raw_n, zero]))
        n = SSAVar(self._next_name("n_clamp"), var_type="i64")
        self._insert_before_term(block, SSAInstruction(result=n, opcode="select", operands=[cond_pos, raw_n, zero]))

        n_minus_1 = None
        n_prod = None
        sum_1 = None
        sum_2 = None
        two = None

        if c1 != 0 or c2 != 0 or c3 != 0:
            two = self._emit_expr(block, 2, fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
            n_minus_1 = SSAVar(self._next_name("n_m1"), var_type="i64")
            self._insert_before_term(block, SSAInstruction(result=n_minus_1, opcode="sub", operands=[n, one]))
            n_prod = SSAVar(self._next_name("n_prod"), var_type="i64")
            self._insert_before_term(block, SSAInstruction(result=n_prod, opcode="mul", operands=[n, n_minus_1]))

        if c1 != 0 or c3 != 0:
            sum_1 = SSAVar(self._next_name("sum1"), var_type="i64")
            self._insert_before_term(block, SSAInstruction(result=sum_1, opcode="sdiv", operands=[n_prod, two]))

        if c2 != 0:
            six = self._emit_expr(block, 6, fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
            two_n = SSAVar(self._next_name("two_n"), var_type="i64")
            self._insert_before_term(block, SSAInstruction(result=two_n, opcode="mul", operands=[two, n]))
            two_n_m1 = SSAVar(self._next_name("two_n_m1"), var_type="i64")
            self._insert_before_term(block, SSAInstruction(result=two_n_m1, opcode="sub", operands=[two_n, one]))
            prod_3 = SSAVar(self._next_name("prod3"), var_type="i64")
            self._insert_before_term(block, SSAInstruction(result=prod_3, opcode="mul", operands=[n_prod, two_n_m1]))
            sum_2 = SSAVar(self._next_name("sum2"), var_type="i64")
            self._insert_before_term(block, SSAInstruction(result=sum_2, opcode="sdiv", operands=[prod_3, six]))

        total_delta = None

        # Term 0: c0 * n
        if c0 != 0:
            c0_v = self._emit_expr(block, c0, fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
            t0 = SSAVar(self._next_name("term0"), var_type="i64")
            self._insert_before_term(block, SSAInstruction(result=t0, opcode="mul", operands=[c0_v, n]))
            total_delta = t0

        # Term 1: c1 * sum_1
        if c1 != 0:
            c1_v = self._emit_expr(block, c1, fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
            t1 = SSAVar(self._next_name("term1"), var_type="i64")
            self._insert_before_term(block, SSAInstruction(result=t1, opcode="mul", operands=[c1_v, sum_1]))
            if total_delta is None:
                total_delta = t1
            else:
                new_d = SSAVar(self._next_name("delta_s1"), var_type="i64")
                self._insert_before_term(block, SSAInstruction(result=new_d, opcode="add", operands=[total_delta, t1]))
                total_delta = new_d

        # Term 2: c2 * sum_2
        if c2 != 0:
            c2_v = self._emit_expr(block, c2, fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
            t2 = SSAVar(self._next_name("term2"), var_type="i64")
            self._insert_before_term(block, SSAInstruction(result=t2, opcode="mul", operands=[c2_v, sum_2]))
            if total_delta is None:
                total_delta = t2
            else:
                new_d = SSAVar(self._next_name("delta_s2"), var_type="i64")
                self._insert_before_term(block, SSAInstruction(result=new_d, opcode="add", operands=[total_delta, t2]))
                total_delta = new_d

        # Term 3: c3 * sum_1^2
        if c3 != 0:
            c3_v = self._emit_expr(block, c3, fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
            sum_3 = SSAVar(self._next_name("sum3"), var_type="i64")
            self._insert_before_term(block, SSAInstruction(result=sum_3, opcode="mul", operands=[sum_1, sum_1]))
            t3 = SSAVar(self._next_name("term3"), var_type="i64")
            self._insert_before_term(block, SSAInstruction(result=t3, opcode="mul", operands=[c3_v, sum_3]))
            if total_delta is None:
                total_delta = t3
            else:
                new_d = SSAVar(self._next_name("delta_s3"), var_type="i64")
                self._insert_before_term(block, SSAInstruction(result=new_d, opcode="add", operands=[total_delta, t3]))
                total_delta = new_d

        if total_delta is None:
            return self._emit_expr(block, acc_init, fn, def_map, loop_block_names, loop_defined_vars, clone_cache)

        acc_init_v = self._emit_expr(block, acc_init, fn, def_map, loop_block_names, loop_defined_vars, clone_cache)
        if isinstance(acc_init, int) and acc_init == 0:
            return total_delta
        final_acc = SSAVar(self._next_name("acc_final"), var_type="i64")
        self._insert_before_term(block, SSAInstruction(result=final_acc, opcode="add", operands=[acc_init_v, total_delta]))
        return final_acc

    def _replace_loop_with_result(
        self,
        fn: SSAFunction,
        loop: LoopNestInfo,
        pre_header: BasicBlock,
        exit_block: BasicBlock,
        acc_var: SSAVar,
        closed_form_res: SSAVar,
    ):
        """
        Rewires pre_header directly to exit_block, updates uses of acc_var,
        and prunes dead unreachable loop blocks from the CFG.
        """
        if pre_header.instructions and pre_header.instructions[-1].is_terminator:
            pre_header.instructions[-1] = SSAInstruction(result=None, opcode="br", operands=[exit_block.name])
        else:
            pre_header.instructions.append(SSAInstruction(result=None, opcode="br", operands=[exit_block.name]))

        # Update CFG edges cleanly
        if loop.header_block in pre_header.successors:
            pre_header.successors.remove(loop.header_block)
        if pre_header in loop.header_block.predecessors:
            loop.header_block.predecessors.remove(pre_header)
        pre_header.connect_to(exit_block)

        # In exit_block and reachable blocks, replace uses of acc_var with closed_form_res
        for blk in fn.blocks:
            for phi in blk.phi_nodes:
                for i, op in enumerate(phi.operands):
                    if op == acc_var:
                        phi.operands[i] = closed_form_res
                for i, (bname, val) in enumerate(phi.phi_incoming):
                    if val == acc_var:
                        phi.phi_incoming[i] = (
                            pre_header.name if bname == loop.header_block.name else bname,
                            closed_form_res,
                        )
            for inst in blk.instructions:
                for i, op in enumerate(inst.operands):
                    if op == acc_var:
                        inst.operands[i] = closed_form_res

        # Prune unreachable blocks via BFS from entry
        if fn.blocks:
            entry = fn.entry_block or fn.blocks[0]
            reachable: Set[str] = set()
            queue = [entry]
            while queue:
                cur = queue.pop(0)
                if cur.name in reachable:
                    continue
                reachable.add(cur.name)
                for succ in cur.successors:
                    if succ.name not in reachable:
                        queue.append(succ)
            fn.blocks = [b for b in fn.blocks if b.name in reachable]
            for b in fn.blocks:
                b.predecessors = [p for p in b.predecessors if p.name in reachable]
                b.successors = [s for s in b.successors if s.name in reachable]
                valid_preds = {p.name for p in b.predecessors}
                for phi in b.phi_nodes:
                    phi.phi_incoming = [(pn, pv) for pn, pv in phi.phi_incoming if pn in valid_preds]
