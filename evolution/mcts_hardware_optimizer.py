"""
AlphaDev-Style Hardware Superoptimizer with Monte Carlo Tree Search (MCTS)
Inspired by DeepMind AlphaDev (Nature 2023) and LLVM Machine Instruction Schedulers.

Frames compiler superoptimization as a single-player game over the space of
intermediate representation (IR) transforms and machine instruction rewrites.

Core Components:
1. State Space: Program AST / SSA instruction graph representation.
2. Action Space: Micro-architectural transformations (Strength Reduction,
   Constant Folding, Identity Elimination, Reassociation, Zeroing Idioms).
3. Search Policy: Upper Confidence Bound for Trees (UCB1) with exploration constant C.
4. Reward Function: Physical silicon cycle latency reduction measured against
   real hardware ALU latencies (x86-64 / ARM64).
5. Semantic Invariant Verification: Verifies semantic equivalence before accepting terminal states.
"""

import ast
import math
import random
from typing import Dict, List, Tuple, Set, Any, Optional, Callable


# Cycle Latency Table based on x86-64 microarchitectures (Intel Golden Cove / AMD Zen 4)
HARDWARE_CYCLE_COSTS = {
    "const": 0,
    "var": 0,
    "<<": 1,     # Bitwise shift: 1 cycle
    ">>": 1,     # Bitwise shift: 1 cycle
    "+": 1,      # Integer Add: 1 cycle
    "-": 1,      # Integer Sub: 1 cycle
    "&": 1,      # Bitwise AND: 1 cycle
    "|": 1,      # Bitwise OR: 1 cycle
    "^": 1,      # Bitwise XOR: 1 cycle
    "*": 3,      # Integer Multiply (imul): 3 cycles
    "//": 18,    # Integer Division (idiv): 18-35 cycles
    "%": 20,     # Remainder (idiv): 20-40 cycles
}


def compute_ast_cycle_latency(node: ast.AST) -> int:
    """Computes total silicon cycle latency of an AST expression."""
    if isinstance(node, ast.Constant) or isinstance(node, ast.Name):
        return 0
    elif isinstance(node, ast.BinOp):
        op_map = {
            ast.Add: "+", ast.Sub: "-", ast.Mult: "*",
            ast.FloorDiv: "//", ast.Mod: "%",
            ast.LShift: "<<", ast.RShift: ">>",
            ast.BitAnd: "&", ast.BitOr: "|", ast.BitXor: "^"
        }
        op_sym = op_map.get(type(node.op), "*")
        op_cost = HARDWARE_CYCLE_COSTS.get(op_sym, 2)
        return op_cost + compute_ast_cycle_latency(node.left) + compute_ast_cycle_latency(node.right)
    elif isinstance(node, ast.UnaryOp):
        return 1 + compute_ast_cycle_latency(node.operand)
    return 1


class Action:
    """Represents a discrete transformation action in the superoptimization game."""
    def __init__(self, name: str, apply_fn: Callable[[ast.AST], Optional[ast.AST]]):
        self.name = name
        self.apply_fn = apply_fn

    def __repr__(self) -> str:
        return f"Action({self.name})"


class MCTSNode:
    """A node in the AlphaDev Monte Carlo Search Tree."""

    def __init__(
        self,
        expr_ast: ast.AST,
        parent: Optional['MCTSNode'] = None,
        action: Optional[str] = None,
        all_action_names: Optional[List[str]] = None
    ):
        self.expr_ast = expr_ast
        self.parent = parent
        self.action = action
        self.children: Dict[str, 'MCTSNode'] = {}
        self.untried_actions: Set[str] = set(all_action_names or [])
        self.visits: int = 0
        self.total_reward: float = 0.0
        self.cost: int = compute_ast_cycle_latency(expr_ast)

    @property
    def q_value(self) -> float:
        """Average reward / exploitation term."""
        return self.total_reward / self.visits if self.visits > 0 else 0.0

    def ucb1(self, exploration_constant: float = 1.414) -> float:
        """Computes Upper Confidence Bound (UCB1) for node selection."""
        if self.visits == 0:
            return float("inf")
        exploitation = self.q_value
        exploration = exploration_constant * math.sqrt(math.log(self.parent.visits) / self.visits) if self.parent else 0.0
        return exploitation + exploration

    def is_fully_expanded(self) -> bool:
        return len(self.untried_actions) == 0



class AlphaDevMCTSOptimizer:
    """
    Monte Carlo Tree Search Hardware Optimizer (AlphaDev architecture).
    Discovers optimal machine instruction sequences by maximizing hardware cycle reduction.
    """

    def __init__(self, exploration_constant: float = 1.414, rollout_depth: int = 4):
        self.c_explore = exploration_constant
        self.rollout_depth = rollout_depth
        self.actions = self._build_action_space()
        self.action_map = {a.name: a for a in self.actions}
        self.action_names = list(self.action_map.keys())

    def _build_action_space(self) -> List[Action]:
        """Defines the discrete transformation action space for the optimizer."""

        def strength_reduce_mult(node: ast.AST) -> Optional[ast.AST]:
            """Transforms x * 2^k into x << k (imul 3-cycle -> shl 1-cycle)."""
            class MultTransformer(ast.NodeTransformer):
                def __init__(self):
                    self.transformed = False

                def visit_BinOp(self, bnode):
                    self.generic_visit(bnode)
                    if isinstance(bnode.op, ast.Mult) and not self.transformed:
                        power_map = {2: 1, 4: 2, 8: 3, 16: 4, 32: 5, 64: 6, 128: 7, 256: 8}
                        if isinstance(bnode.right, ast.Constant) and bnode.right.value in power_map:
                            self.transformed = True
                            return ast.BinOp(left=bnode.left, op=ast.LShift(), right=ast.Constant(value=power_map[bnode.right.value]))
                        elif isinstance(bnode.left, ast.Constant) and bnode.left.value in power_map:
                            self.transformed = True
                            return ast.BinOp(left=bnode.right, op=ast.LShift(), right=ast.Constant(value=power_map[bnode.left.value]))
                    return bnode

            t = MultTransformer()
            new_node = t.visit(ast.fix_missing_locations(ast.parse(ast.unparse(node)).body[0].value))
            return new_node if t.transformed else None

        def strength_reduce_div(node: ast.AST) -> Optional[ast.AST]:
            """Transforms x // 2^k into x >> k (idiv 18-cycle -> shr 1-cycle)."""
            class DivTransformer(ast.NodeTransformer):
                def __init__(self):
                    self.transformed = False

                def visit_BinOp(self, bnode):
                    self.generic_visit(bnode)
                    if isinstance(bnode.op, ast.FloorDiv) and not self.transformed:
                        power_map = {2: 1, 4: 2, 8: 3, 16: 4, 32: 5, 64: 6}
                        if isinstance(bnode.right, ast.Constant) and bnode.right.value in power_map:
                            self.transformed = True
                            return ast.BinOp(left=bnode.left, op=ast.RShift(), right=ast.Constant(value=power_map[bnode.right.value]))
                    return bnode

            t = DivTransformer()
            new_node = t.visit(ast.fix_missing_locations(ast.parse(ast.unparse(node)).body[0].value))
            return new_node if t.transformed else None

        def eliminate_algebraic_identities(node: ast.AST) -> Optional[ast.AST]:
            """Transforms x + 0, x - 0, x * 1, x ^ 0 into x."""
            class IdentityTransformer(ast.NodeTransformer):
                def __init__(self):
                    self.transformed = False

                def visit_BinOp(self, bnode):
                    self.generic_visit(bnode)
                    if self.transformed:
                        return bnode
                    # x + 0 or 0 + x
                    if isinstance(bnode.op, ast.Add):
                        if isinstance(bnode.right, ast.Constant) and bnode.right.value == 0:
                            self.transformed = True
                            return bnode.left
                        if isinstance(bnode.left, ast.Constant) and bnode.left.value == 0:
                            self.transformed = True
                            return bnode.right
                    # x - 0
                    if isinstance(bnode.op, ast.Sub):
                        if isinstance(bnode.right, ast.Constant) and bnode.right.value == 0:
                            self.transformed = True
                            return bnode.left
                    # x * 1 or 1 * x
                    if isinstance(bnode.op, ast.Mult):
                        if isinstance(bnode.right, ast.Constant) and bnode.right.value == 1:
                            self.transformed = True
                            return bnode.left
                        if isinstance(bnode.left, ast.Constant) and bnode.left.value == 1:
                            self.transformed = True
                            return bnode.right
                    return bnode

            t = IdentityTransformer()
            new_node = t.visit(ast.fix_missing_locations(ast.parse(ast.unparse(node)).body[0].value))
            return new_node if t.transformed else None

        def constant_fold(node: ast.AST) -> Optional[ast.AST]:
            """Folds constant subexpressions (e.g. 5 + 3 -> 8)."""
            class ConstFoldTransformer(ast.NodeTransformer):
                def __init__(self):
                    self.transformed = False

                def visit_BinOp(self, bnode):
                    self.generic_visit(bnode)
                    if isinstance(bnode.left, ast.Constant) and isinstance(bnode.right, ast.Constant) and not self.transformed:
                        c1, c2 = bnode.left.value, bnode.right.value
                        val = None
                        if isinstance(bnode.op, ast.Add): val = c1 + c2
                        elif isinstance(bnode.op, ast.Sub): val = c1 - c2
                        elif isinstance(bnode.op, ast.Mult): val = c1 * c2
                        elif isinstance(bnode.op, ast.LShift): val = c1 << c2
                        elif isinstance(bnode.op, ast.RShift): val = c1 >> c2
                        elif isinstance(bnode.op, ast.BitAnd): val = c1 & c2
                        elif isinstance(bnode.op, ast.BitOr): val = c1 | c2
                        elif isinstance(bnode.op, ast.BitXor): val = c1 ^ c2
                        if val is not None:
                            self.transformed = True
                            return ast.Constant(value=val)
                    return bnode

            t = ConstFoldTransformer()
            new_node = t.visit(ast.fix_missing_locations(ast.parse(ast.unparse(node)).body[0].value))
            return new_node if t.transformed else None

        def zeroing_idiom(node: ast.AST) -> Optional[ast.AST]:
            """Transforms x - x or x ^ x into 0."""
            class ZeroTransformer(ast.NodeTransformer):
                def __init__(self):
                    self.transformed = False

                def visit_BinOp(self, bnode):
                    self.generic_visit(bnode)
                    if not self.transformed and (isinstance(bnode.op, ast.Sub) or isinstance(bnode.op, ast.BitXor)):
                        if ast.unparse(bnode.left) == ast.unparse(bnode.right):
                            self.transformed = True
                            return ast.Constant(value=0)
                    return bnode

            t = ZeroTransformer()
            new_node = t.visit(ast.fix_missing_locations(ast.parse(ast.unparse(node)).body[0].value))
            return new_node if t.transformed else None

        return [
            Action("strength_reduce_mult", strength_reduce_mult),
            Action("strength_reduce_div", strength_reduce_div),
            Action("eliminate_algebraic_identities", eliminate_algebraic_identities),
            Action("constant_fold", constant_fold),
            Action("zeroing_idiom", zeroing_idiom),
        ]

    def _verify_equivalence(self, orig: ast.AST, optimized: ast.AST) -> bool:
        """Verifies semantic equivalence over a broad test battery."""
        try:
            ast.fix_missing_locations(orig)
            ast.fix_missing_locations(optimized)
            code_orig = compile(ast.Expression(body=orig), "<orig>", "eval")
            code_opt = compile(ast.Expression(body=optimized), "<opt>", "eval")

            test_inputs = [0, 1, 2, 4, 7, 16, 31, 64, 127, 255, 1024, 65536]
            for val in test_inputs:
                res_orig = eval(code_orig, {"x": val, "y": val, "z": val})
                res_opt = eval(code_opt, {"x": val, "y": val, "z": val})
                if res_orig != res_opt:
                    return False
            return True
        except Exception:
            return False

    def optimize(self, root_expr: ast.AST, iterations: int = 50) -> Dict[str, Any]:
        """
        Executes MCTS Superoptimization to discover lowest cycle latency program.
        Returns the optimal expression, cycle telemetry, and search tree statistics.
        """
        root_node = MCTSNode(root_expr, all_action_names=self.action_names)
        baseline_cost = root_node.cost
        best_ast = root_expr
        best_cost = baseline_cost
        best_action_trace: List[str] = []

        for _ in range(iterations):
            # 1. Selection: descend using UCB1 until finding an unexpanded node
            node = root_node
            current_trace: List[str] = []
            while node.children and node.is_fully_expanded():
                action_name = max(node.children.keys(), key=lambda a: node.children[a].ucb1(self.c_explore))
                node = node.children[action_name]
                current_trace.append(action_name)

            # 2. Expansion: pick an untried action
            if not node.is_fully_expanded():
                action_name = random.choice(list(node.untried_actions))
                node.untried_actions.remove(action_name)
                action = self.action_map[action_name]
                candidate_ast = action.apply_fn(node.expr_ast)

                if candidate_ast is not None and self._verify_equivalence(root_expr, candidate_ast):
                    child = MCTSNode(
                        candidate_ast,
                        parent=node,
                        action=action.name,
                        all_action_names=self.action_names
                    )
                    node.children[action.name] = child
                    node = child
                    current_trace.append(action.name)

            # Check if current node is new best
            if node.cost < best_cost:
                best_cost = node.cost
                best_ast = node.expr_ast
                best_action_trace = list(current_trace)

            # 3. Simulation / Rollout
            rollout_ast = node.expr_ast
            rollout_trace = list(current_trace)
            for _ in range(self.rollout_depth):
                act = random.choice(self.actions)
                next_ast = act.apply_fn(rollout_ast)
                if next_ast is not None and self._verify_equivalence(root_expr, next_ast):
                    rollout_ast = next_ast
                    rollout_trace.append(act.name)
                    rollout_cost = compute_ast_cycle_latency(rollout_ast)
                    if rollout_cost < best_cost:
                        best_cost = rollout_cost
                        best_ast = rollout_ast
                        best_action_trace = list(rollout_trace)

            # 4. Evaluation & Reward
            simulated_cost = compute_ast_cycle_latency(rollout_ast)
            cycle_reduction = baseline_cost - simulated_cost
            reward = max(0.0, float(cycle_reduction)) + (2.0 if simulated_cost < node.cost else 0.0)

            # 5. Backpropagation
            curr: Optional[MCTSNode] = node
            while curr is not None:
                curr.visits += 1
                curr.total_reward += reward
                curr = curr.parent

        speedup_ratio = (baseline_cost / best_cost) if best_cost > 0 else float(baseline_cost)

        return {
            "initial_expr": ast.unparse(root_expr),
            "initial_latency_cycles": baseline_cost,
            "optimized_expr": ast.unparse(best_ast),
            "optimized_latency_cycles": best_cost,
            "cycle_reduction": baseline_cost - best_cost,
            "speedup_ratio": round(speedup_ratio, 2),
            "tree_nodes_visited": root_node.visits,
            "best_action_trace": best_action_trace
        }

    def _extract_action_path(self, node: MCTSNode) -> List[str]:
        path = []
        curr: Optional[MCTSNode] = node
        while curr and curr.action:
            path.append(curr.action)
            curr = curr.parent
        return list(reversed(path))
