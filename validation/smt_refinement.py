"""
Alive2 & cvc5-Inspired SMT Refinement & Translation Validation Engine (Fail-Closed QF_BV)
Transplanted from AliveToolkit/alive2 & cvc5/cvc5 for bit-exact semantic preservation.
Features:
  - Recursive Symbolic AST & SSA-to-Z3 BitVector Compiler (32-bit & 64-bit QF_BV)
  - Strictly FAIL-CLOSED: Unsupported constructs, impure calls, or solver timeouts NEVER
    return proven=True; they return proven=False with UNVERIFIED status
  - Handles arbitrary variable sets, arithmetic, bitwise, shifts, comparisons, booleans,
    ternary conditionals, and exact Python floor-div/mod vs C/LLVM two's-complement semantics
  - Automated counterexample extraction when transformation deviates by even 1 bit
"""

import ast
from typing import Dict, Any, List, Optional, Set, Tuple
try:
    import z3
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False


class UnsupportedSmtConstructError(ValueError):
    """Raised when an expression contains side effects or constructs outside decidable QF_BV."""
    pass


# Canonical symbolic shorthand aliases supported by CLI & legacy suites
SYMBOLIC_ALIASES: Dict[str, str] = {
    "mul16": "x * 16",
    "shl4": "x << 4",
    "mul8": "x * 8",
    "shl3": "x << 3",
    "add0": "x + 0",
    "sub0": "x - 0",
    "mul1": "x * 1",
    "nop": "x",
}


def _collect_variable_names(node: ast.AST) -> Set[str]:
    names: Set[str] = set()
    allowed_calls = {"bool", "abs", "min", "max", "int"}
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            if sub.id not in allowed_calls and sub.id not in ("True", "False"):
                names.add(sub.id)
    return names


class SymbolicAstToZ3Compiler:
    """
    Compiles arbitrary pure Python/C arithmetic, bitwise, boolean, and conditional ASTs
    into exact Z3 BitVector expressions, tracking precondition guards (e.g. non-zero divisors,
    in-range shift counts) for sound translation validation.
    """

    def __init__(self, env: Dict[str, Any], bit_width: int = 32, python_floor_semantics: bool = True):
        self.env = env
        self.bit_width = bit_width
        self.python_floor_semantics = python_floor_semantics
        self.definedness_guards: List[Any] = []

    def _to_bv(self, val: Any) -> Any:
        if z3.is_bv(val):
            return val
        if z3.is_bool(val):
            return z3.If(val, z3.BitVecVal(1, self.bit_width), z3.BitVecVal(0, self.bit_width))
        raise UnsupportedSmtConstructError(f"Cannot coerce Z3 sort {type(val)} to BitVec")

    def _to_bool(self, val: Any) -> Any:
        if z3.is_bool(val):
            return val
        if z3.is_bv(val):
            return val != z3.BitVecVal(0, self.bit_width)
        raise UnsupportedSmtConstructError(f"Cannot coerce Z3 sort {type(val)} to Bool")

    def compile(self, node: ast.AST) -> Any:
        W = self.bit_width
        zero = z3.BitVecVal(0, W)
        one = z3.BitVecVal(1, W)

        if isinstance(node, ast.Expression):
            return self.compile(node.body)

        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                return one if node.value else zero
            if isinstance(node.value, int):
                return z3.BitVecVal(node.value, W)
            raise UnsupportedSmtConstructError(f"Unsupported constant literal type: {type(node.value).__name__}")

        if isinstance(node, ast.Name):
            if node.id == "True":
                return one
            if node.id == "False":
                return zero
            if node.id not in self.env:
                self.env[node.id] = z3.BitVec(node.id, W)
            return self.env[node.id]

        if isinstance(node, ast.UnaryOp):
            operand = self.compile(node.operand)
            if isinstance(node.op, ast.USub):
                return -self._to_bv(operand)
            if isinstance(node.op, ast.UAdd):
                return self._to_bv(operand)
            if isinstance(node.op, ast.Invert):
                return ~self._to_bv(operand)
            if isinstance(node.op, ast.Not):
                return z3.If(z3.Not(self._to_bool(operand)), one, zero)
            raise UnsupportedSmtConstructError(f"Unsupported unary op: {type(node.op).__name__}")

        if isinstance(node, ast.BinOp):
            left = self._to_bv(self.compile(node.left))
            right = self._to_bv(self.compile(node.right))

            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.BitAnd):
                return left & right
            if isinstance(node.op, ast.BitOr):
                return left | right
            if isinstance(node.op, ast.BitXor):
                return left ^ right
            if isinstance(node.op, ast.LShift):
                self.definedness_guards.append(z3.And(right >= zero, right < z3.BitVecVal(W, W)))
                return left << right
            if isinstance(node.op, ast.RShift):
                self.definedness_guards.append(z3.And(right >= zero, right < z3.BitVecVal(W, W)))
                return left >> right  # Signed arithmetic right shift (matches Python int >>)
            if isinstance(node.op, ast.FloorDiv):
                int_min = z3.BitVecVal(-(1 << (W - 1)), W)
                neg_one = z3.BitVecVal(-1, W)
                self.definedness_guards.append(right != zero)
                self.definedness_guards.append(z3.Not(z3.And(left == int_min, right == neg_one)))
                # Z3 '/' on BitVec is signed two's-complement truncating toward zero (C sdiv);
                # Python '//' floors toward -infinity when signs differ and remainder != 0.
                q_trunc = left / right
                r_trunc = z3.SRem(left, right)
                if not self.python_floor_semantics:
                    return q_trunc
                signs_differ = (left < zero) != (right < zero)
                needs_adj = z3.And(signs_differ, r_trunc != zero)
                return z3.If(needs_adj, q_trunc - one, q_trunc)
            if isinstance(node.op, ast.Mod):
                int_min = z3.BitVecVal(-(1 << (W - 1)), W)
                neg_one = z3.BitVecVal(-1, W)
                self.definedness_guards.append(right != zero)
                self.definedness_guards.append(z3.Not(z3.And(left == int_min, right == neg_one)))
                r_trunc = z3.SRem(left, right)
                if not self.python_floor_semantics:
                    return r_trunc
                signs_differ = (left < zero) != (right < zero)
                needs_adj = z3.And(signs_differ, r_trunc != zero)
                return z3.If(needs_adj, r_trunc + right, r_trunc)

            raise UnsupportedSmtConstructError(f"Unsupported binary op: {type(node.op).__name__}")

        if isinstance(node, ast.Compare):
            curr = self._to_bv(self.compile(node.left))
            conds = []
            for op, comp_node in zip(node.ops, node.comparators):
                rhs = self._to_bv(self.compile(comp_node))
                if isinstance(op, ast.Eq):
                    conds.append(curr == rhs)
                elif isinstance(op, ast.NotEq):
                    conds.append(curr != rhs)
                elif isinstance(op, ast.Lt):
                    conds.append(curr < rhs)
                elif isinstance(op, ast.LtE):
                    conds.append(curr <= rhs)
                elif isinstance(op, ast.Gt):
                    conds.append(curr > rhs)
                elif isinstance(op, ast.GtE):
                    conds.append(curr >= rhs)
                else:
                    raise UnsupportedSmtConstructError(f"Unsupported comparison op: {type(op).__name__}")
                curr = rhs
            combined = conds[0] if len(conds) == 1 else z3.And(*conds)
            return z3.If(combined, one, zero)

        if isinstance(node, ast.BoolOp):
            vals = [self._to_bool(self.compile(v)) for v in node.values]
            if isinstance(node.op, ast.And):
                return z3.If(z3.And(*vals), one, zero)
            if isinstance(node.op, ast.Or):
                return z3.If(z3.Or(*vals), one, zero)
            raise UnsupportedSmtConstructError(f"Unsupported BoolOp: {type(node.op).__name__}")

        if isinstance(node, ast.IfExp):
            cond = self._to_bool(self.compile(node.test))
            body = self._to_bv(self.compile(node.body))
            orelse = self._to_bv(self.compile(node.orelse))
            return z3.If(cond, body, orelse)

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and not node.keywords:
            fn = node.func.id
            if fn == "int" and len(node.args) == 1:
                arg0 = node.args[0]
                if isinstance(arg0, ast.BinOp) and isinstance(arg0.op, ast.Div):
                    # Explicit C/LLVM signed truncating division toward zero: `int(a / b)` -> `sdiv(a, b)`
                    lhs = self._to_bv(self.compile(arg0.left))
                    rhs = self._to_bv(self.compile(arg0.right))
                    int_min = z3.BitVecVal(-(1 << (W - 1)), W)
                    neg_one = z3.BitVecVal(-1, W)
                    self.definedness_guards.append(rhs != zero)
                    self.definedness_guards.append(z3.Not(z3.And(lhs == int_min, rhs == neg_one)))
                    return lhs / rhs
                return self._to_bv(self.compile(arg0))
            if fn == "bool" and len(node.args) == 1:
                v = self.compile(node.args[0])
                return z3.If(self._to_bool(v), one, zero)
            if fn == "abs" and len(node.args) == 1:
                v = self._to_bv(self.compile(node.args[0]))
                return z3.If(v < zero, -v, v)
            if fn == "min" and len(node.args) == 2:
                a = self._to_bv(self.compile(node.args[0]))
                b = self._to_bv(self.compile(node.args[1]))
                return z3.If(a <= b, a, b)
            if fn == "max" and len(node.args) == 2:
                a = self._to_bv(self.compile(node.args[0]))
                b = self._to_bv(self.compile(node.args[1]))
                return z3.If(a >= b, a, b)

        raise UnsupportedSmtConstructError(f"Unsupported or impure AST construct: {type(node).__name__}")


class SmtRefinementVerifier:
    """
    Formal Translation Validation checking bit-exact equivalence between source and optimized
    expressions/capsules. Strictly Fail-Closed: never approves unverified or divergent code.
    """

    def __init__(self, timeout_ms: int = 2000, bit_width: int = 32):
        self.has_z3 = _HAS_Z3
        self.timeout_ms = timeout_ms
        self.bit_width = bit_width

    def verify_arithmetic_refinement(
        self,
        expr_src: str,
        expr_tgt: str,
        bit_width: Optional[int] = None,
        python_floor_semantics: bool = True
    ) -> Dict[str, Any]:
        """
        Proves forall inputs in BV_{bit_width}:
            Defined(src) => (Defined(tgt) and expr_src == expr_tgt)
        using Z3 QF_BV logic.
        """
        if bit_width is None:
            bit_width = self.bit_width
        src_norm = SYMBOLIC_ALIASES.get(expr_src.strip(), expr_src.strip())
        tgt_norm = SYMBOLIC_ALIASES.get(expr_tgt.strip(), expr_tgt.strip())

        if not self.has_z3:
            is_identical = (src_norm == tgt_norm)
            return {
                "proven": is_identical,
                "solver": "fail_closed_without_z3",
                "counterexamples": [] if is_identical else ["Z3_SOLVER_MISSING"],
                "refinement_status": "EXACT_AST_IDENTITY" if is_identical else "UNVERIFIED_NO_SOLVER",
                "fail_closed": not is_identical,
                "bits_verified": bit_width
            }

        try:
            tree_src = ast.parse(src_norm, mode="eval")
            tree_tgt = ast.parse(tgt_norm, mode="eval")
        except SyntaxError as syn_err:
            return {
                "proven": False,
                "solver": "Z3Prover/QF_BV",
                "counterexamples": [f"SYNTAX_ERROR: {syn_err}"],
                "refinement_status": "INVALID_SYNTAX_FAIL_CLOSED",
                "fail_closed": True,
                "bits_verified": bit_width
            }

        all_vars = sorted(_collect_variable_names(tree_src) | _collect_variable_names(tree_tgt))
        if not all_vars:
            all_vars = ["x"]

        env = {name: z3.BitVec(name, bit_width) for name in all_vars}

        try:
            comp_src = SymbolicAstToZ3Compiler(env, bit_width=bit_width, python_floor_semantics=python_floor_semantics)
            comp_tgt = SymbolicAstToZ3Compiler(env, bit_width=bit_width, python_floor_semantics=python_floor_semantics)

            val_src = comp_src._to_bv(comp_src.compile(tree_src))
            val_tgt = comp_tgt._to_bv(comp_tgt.compile(tree_tgt))

            src_defined = z3.And(*comp_src.definedness_guards) if comp_src.definedness_guards else z3.BoolVal(True)
            tgt_defined = z3.And(*comp_tgt.definedness_guards) if comp_tgt.definedness_guards else z3.BoolVal(True)

            # Alive2 Refinement Theorem:
            # Whenever Source is well-defined (no UB), Target MUST ALSO be well-defined AND produce the exact same bits!
            violation = z3.And(
                src_defined,
                z3.Or(z3.Not(tgt_defined), val_src != val_tgt)
            )

            solver = z3.SolverFor("QF_BV")
            solver.set("timeout", self.timeout_ms)
            solver.add(violation)
            res = solver.check()

            if res == z3.unsat:
                return {
                    "proven": True,
                    "solver": "Z3Prover/QF_BV",
                    "counterexamples": [],
                    "refinement_status": "EXACT_BIT_REFINEMENT",
                    "fail_closed": False,
                    "bits_verified": bit_width,
                    "variables_verified": all_vars
                }
            elif res == z3.sat:
                model = solver.model()
                cx = {str(d): str(model[d]) for d in model.decls()}
                return {
                    "proven": False,
                    "solver": "Z3Prover/QF_BV",
                    "counterexamples": [cx],
                    "refinement_status": "SEMANTIC_DIVERGENCE_DETECTED",
                    "fail_closed": False,
                    "bits_verified": bit_width
                }
            else:
                return {
                    "proven": False,
                    "solver": "Z3Prover/QF_BV",
                    "counterexamples": ["SOLVER_UNKNOWN_OR_TIMEOUT"],
                    "refinement_status": "UNVERIFIED_SOLVER_TIMEOUT_FAIL_CLOSED",
                    "fail_closed": True,
                    "bits_verified": bit_width
                }
        except UnsupportedSmtConstructError as unsup_err:
            return {
                "proven": False,
                "solver": "Z3Prover/QF_BV",
                "counterexamples": [str(unsup_err)],
                "refinement_status": "UNVERIFIED_UNSUPPORTED_CONSTRUCT_FAIL_CLOSED",
                "fail_closed": True,
                "bits_verified": bit_width
            }
        except Exception as err:
            return {
                "proven": False,
                "solver": "Z3Prover/QF_BV",
                "counterexamples": [str(err)],
                "refinement_status": "UNVERIFIED_INTERNAL_ERROR_FAIL_CLOSED",
                "fail_closed": True,
                "bits_verified": bit_width
            }
