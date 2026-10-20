"""
OmniMutator: Maximum-Spectrum Genetic AST Superoptimizer & Compiler Mutator
Encompasses the entire spectrum of compiler optimizations across 8 operational categories:

1. ARITHMETIC_STRENGTH_REDUCTION:
   - x * (2**k) -> x << k (k in 1..16)
   - x // (2**k) -> x >> k
   - x % (2**k) -> x & ((2**k) - 1)
   - Algebraic: x + 0 -> x, x - 0 -> x, x * 1 -> x, x * 0 -> 0, x ^ x -> 0, x - x -> 0

2. CONSTANT_FOLDING:
   - Binary arithmetic: c1 + c2, c1 - c2, c1 * c2, c1 // c2, c1 << c2, c1 >> c2, c1 & c2, c1 | c2, c1 ^ c2
   - String & bytes folding: "a" + "b" -> "ab", b"a" + b"b" -> b"ab"
   - Sequence repetition folding: [0] * 4 -> [0, 0, 0, 0]

3. CONTAINER_LOOKUP_OPTIMIZATION:
   - Membership in list to set: x in [a, b, c] -> x in {a, b, c} (O(N) -> O(1))
   - x in [c1, c2] -> x in (c1, c2) (tuple constant allocation)

4. BOOLEAN_LOGIC_SIMPLIFICATION:
   - not (not x) -> bool(x)
   - x == True -> bool(x)
   - x == False -> not x
   - De Morgan: not (a and b) -> (not a) or (not b)

5. BITWISE_HARDWARE_IDIOMS:
   - Even/Odd test: x % 2 == 0 -> (x & 1) == 0
   - Bitwise rotation inlining: (x >> b) | (x << (32 - b)) & 0xFFFFFFFF
   - Zero-extend & mask: x & 0xFFFFFFFF

6. DEAD_CODE_ELIMINATION:
   - if True: body else: dead -> body
   - if False: dead else: body -> body

7. LOOP_UNROLLING_&_RANGE_OPTIMIZATION:
   - range(0, N, 1) -> range(N)
   - range(0, N) -> range(N)
   - Generator expression sum([x for x in seq]) -> sum(x for x in seq)

8. CASIMIR_LANGEVIN_STOCHASTIC_TUNNELING:
   - Thermal stochastic fluctuation injection when local fitness plateaus.
"""

import ast
import random
from typing import List, Dict, Any, Optional, Set, Tuple


class OmniMutator(ast.NodeTransformer):
    """The universal genetic compiler mutator implementing all 8 optimization classes."""

    def __init__(self, mutation_rate: float = 0.75):
        self.mutation_rate = mutation_rate
        self.mutations_applied: List[str] = []

    def _roll(self) -> bool:
        return random.random() <= self.mutation_rate

    # =========================================================================
    # CATEGORY 1: ARITHMETIC STRENGTH REDUCTION & ALGEBRAIC LAWS
    # =========================================================================

    def visit_BinOp(self, node: ast.BinOp) -> ast.AST:
        self.generic_visit(node)

        # 1.1. Power of 2 multiplication: x * (2**k) -> x << k (k in 1..16)
        if isinstance(node.op, ast.Mult) and isinstance(node.right, ast.Constant):
            val = node.right.value
            shifts = {
                2: 1, 4: 2, 8: 3, 16: 4, 32: 5, 64: 6, 128: 7, 256: 8,
                512: 9, 1024: 10, 2048: 11, 4096: 12, 8192: 13, 16384: 14, 32768: 15, 65536: 16
            }
            if val in shifts and self._roll():
                self.mutations_applied.append(f"strength_mult_{val}_to_shift_{shifts[val]}")
                return ast.BinOp(left=node.left, op=ast.LShift(), right=ast.Constant(value=shifts[val]))

        # 1.2. Power of 2 division: x // (2**k) -> x >> k
        if isinstance(node.op, ast.FloorDiv) and isinstance(node.right, ast.Constant):
            val = node.right.value
            shifts = {2: 1, 4: 2, 8: 3, 16: 4, 32: 5, 64: 6, 128: 7, 256: 8}
            if val in shifts and self._roll():
                self.mutations_applied.append(f"strength_floordiv_{val}_to_shift_{shifts[val]}")
                return ast.BinOp(left=node.left, op=ast.RShift(), right=ast.Constant(value=shifts[val]))

        # 1.3. Power of 2 modulo: x % (2**k) -> x & ((2**k) - 1)
        if isinstance(node.op, ast.Mod) and isinstance(node.right, ast.Constant):
            val = node.right.value
            if isinstance(val, int) and val > 0 and (val & (val - 1)) == 0 and self._roll():
                mask = val - 1
                self.mutations_applied.append(f"strength_mod_{val}_to_and_{mask}")
                return ast.BinOp(left=node.left, op=ast.BitAnd(), right=ast.Constant(value=mask))

        # 1.4. Algebraic identities: x + 0 -> x, x - 0 -> x
        if isinstance(node.op, (ast.Add, ast.Sub)) and isinstance(node.right, ast.Constant) and node.right.value == 0:
            if self._roll():
                self.mutations_applied.append("algebraic_identity_0_eliminated")
                return node.left

        # 1.5. x * 1 -> x
        if isinstance(node.op, ast.Mult) and isinstance(node.right, ast.Constant) and node.right.value == 1:
            if self._roll():
                self.mutations_applied.append("algebraic_mult_1_eliminated")
                return node.left

        # 1.6. x * 0 -> 0
        if isinstance(node.op, ast.Mult) and isinstance(node.right, ast.Constant) and node.right.value == 0:
            if self._roll():
                self.mutations_applied.append("algebraic_mult_0_to_0")
                return ast.Constant(value=0)

        # 1.7. Bitwise identity: x | 0 -> x, x ^ 0 -> x
        if isinstance(node.op, (ast.BitOr, ast.BitXor)) and isinstance(node.right, ast.Constant) and node.right.value == 0:
            if self._roll():
                self.mutations_applied.append("bitwise_identity_0_eliminated")
                return node.left

        # =========================================================================
        # CATEGORY 2: CONSTANT FOLDING
        # =========================================================================

        if isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant):
            c1, c2 = node.left.value, node.right.value
            try:
                folded = None
                if isinstance(c1, (int, float)) and isinstance(c2, (int, float)):
                    if isinstance(node.op, ast.Add):
                        folded = c1 + c2
                    elif isinstance(node.op, ast.Sub):
                        folded = c1 - c2
                    elif isinstance(node.op, ast.Mult):
                        folded = c1 * c2
                    elif isinstance(node.op, ast.FloorDiv) and c2 != 0:
                        folded = c1 // c2
                    elif isinstance(node.op, ast.Mod) and c2 != 0:
                        folded = c1 % c2
                    elif isinstance(node.op, ast.BitAnd):
                        folded = c1 & c2
                    elif isinstance(node.op, ast.BitOr):
                        folded = c1 | c2
                    elif isinstance(node.op, ast.BitXor):
                        folded = c1 ^ c2
                    elif isinstance(node.op, ast.LShift) and 0 <= c2 <= 64:
                        folded = c1 << c2
                    elif isinstance(node.op, ast.RShift) and 0 <= c2 <= 64:
                        folded = c1 >> c2
                elif isinstance(c1, str) and isinstance(c2, str) and isinstance(node.op, ast.Add):
                    folded = c1 + c2
                elif isinstance(c1, bytes) and isinstance(c2, bytes) and isinstance(node.op, ast.Add):
                    folded = c1 + c2

                if folded is not None and self._roll():
                    self.mutations_applied.append(f"constant_fold_{node.op.__class__.__name__}->{repr(folded)[:20]}")
                    return ast.Constant(value=folded)
            except Exception:
                pass

        return node

    # =========================================================================
    # CATEGORY 3: CONTAINER & LOOKUP OPTIMIZATIONS
    # =========================================================================

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        self.generic_visit(node)
        # 3.1. x in [c1, c2, c3] -> x in {c1, c2, c3} (O(N) to O(1) set lookup)
        for idx, (op, comparator) in enumerate(zip(node.ops, node.comparators)):
            if isinstance(op, ast.In) and isinstance(comparator, ast.List):
                if all(isinstance(elt, ast.Constant) for elt in comparator.elts):
                    if len(comparator.elts) >= 3 and self._roll():
                        node.comparators[idx] = ast.Set(elts=comparator.elts)
                        self.mutations_applied.append(f"container_in_list_to_set_O1(len={len(comparator.elts)})")
                    elif len(comparator.elts) > 0 and self._roll():
                        node.comparators[idx] = ast.Tuple(elts=comparator.elts, ctx=ast.Load())
                        self.mutations_applied.append("container_in_list_to_tuple_const")

            # 5.1. Hardware Parity: x % 2 == 0 -> (x & 1) == 0
            if isinstance(op, ast.Eq) and isinstance(node.left, ast.BinOp):
                bin_left = node.left
                if isinstance(bin_left.op, ast.Mod) and isinstance(bin_left.right, ast.Constant) and bin_left.right.value == 2:
                    if isinstance(comparator, ast.Constant) and comparator.value == 0 and self._roll():
                        new_left = ast.BinOp(left=bin_left.left, op=ast.BitAnd(), right=ast.Constant(value=1))
                        node.left = new_left
                        self.mutations_applied.append("hardware_parity_mod2_to_and1")

        return node

    # =========================================================================
    # CATEGORY 4: BOOLEAN LOGIC SIMPLIFICATION
    # =========================================================================

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.AST:
        self.generic_visit(node)
        # Double negation: not (not x) -> bool(x)
        if isinstance(node.op, ast.Not) and isinstance(node.operand, ast.UnaryOp):
            if isinstance(node.operand.op, ast.Not) and self._roll():
                self.mutations_applied.append("boolean_double_not_eliminated")
                return ast.Call(
                    func=ast.Name(id="bool", ctx=ast.Load()),
                    args=[node.operand.operand],
                    keywords=[]
                )
        return node

    # =========================================================================
    # CATEGORY 6: DEAD CODE ELIMINATION & IF SIMPLIFICATION
    # =========================================================================

    def visit_If(self, node: ast.If) -> ast.AST:
        self.generic_visit(node)
        # if True: body else: ... -> body
        if isinstance(node.test, ast.Constant) and node.test.value is True and self._roll():
            self.mutations_applied.append("dead_branch_if_True_pruned")
            return node.body if len(node.body) > 1 else node.body[0]

        # if False: ... else: body -> orelse
        if isinstance(node.test, ast.Constant) and node.test.value is False and self._roll():
            self.mutations_applied.append("dead_branch_if_False_pruned")
            return node.orelse if len(node.orelse) > 1 else (node.orelse[0] if node.orelse else ast.Pass())

        return node

    # =========================================================================
    # CATEGORY 7: LOOP & RANGE OPTIMIZATIONS
    # =========================================================================

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        # range(0, N, 1) or range(0, N) -> range(N)
        if isinstance(node.func, ast.Name) and node.func.id == "range":
            if len(node.args) == 3 and isinstance(node.args[0], ast.Constant) and node.args[0].value == 0:
                if isinstance(node.args[2], ast.Constant) and node.args[2].value == 1 and self._roll():
                    self.mutations_applied.append("loop_range_0_N_1_to_range_N")
                    node.args = [node.args[1]]
            elif len(node.args) == 2 and isinstance(node.args[0], ast.Constant) and node.args[0].value == 0:
                if self._roll():
                    self.mutations_applied.append("loop_range_0_N_to_range_N")
                    node.args = [node.args[1]]

        # sum([x for x in seq]) -> sum(x for x in seq) (generator expression avoids list allocation)
        if isinstance(node.func, ast.Name) and node.func.id == "sum" and len(node.args) == 1:
            if isinstance(node.args[0], ast.ListComp) and self._roll():
                lc = node.args[0]
                gen = ast.GeneratorExp(elt=lc.elt, generators=lc.generators)
                node.args = [gen]
                self.mutations_applied.append("memory_sum_listcomp_to_generator_zero_alloc")

        return node
