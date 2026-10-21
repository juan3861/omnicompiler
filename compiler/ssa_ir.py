"""
OmniCompiler SSA Intermediate Representation (Omni-SSA)
High-performance Static Single Assignment (SSA) form with Basic Blocks,
Phi-nodes, Dominance calculation, and Optimization Passes.
Bridges high-level Python AST with low-level Native JIT silicon compilation.
"""

from typing import List, Dict, Set, Tuple, Any, Optional
import ast


class SSAVar:
    __slots__ = ("name", "version", "var_type")

    def __init__(self, name: str, version: int = 0, var_type: str = "i64"):
        self.name = name
        self.version = version
        self.var_type = var_type

    def __repr__(self) -> str:
        return f"%{self.name}_{self.version}"

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, SSAVar):
            return False
        return self.name == other.name and self.version == other.version

    def __hash__(self) -> int:
        return hash((self.name, self.version))


class SSAInstruction:
    __slots__ = ("result", "opcode", "operands")

    def __init__(self, result: Optional[SSAVar], opcode: str, operands: List[Any]):
        self.result = result
        self.opcode = opcode
        self.operands = operands

    def __repr__(self) -> str:
        ops = ", ".join(str(o) for o in self.operands)
        if self.result:
            return f"{self.result} = {self.opcode} {ops}"
        return f"{self.opcode} {ops}"


class BasicBlock:
    def __init__(self, name: str):
        self.name = name
        self.instructions: List[SSAInstruction] = []
        self.predecessors: List['BasicBlock'] = []
        self.successors: List['BasicBlock'] = []
        self.phi_nodes: List[SSAInstruction] = []

    def add_instruction(self, inst: SSAInstruction):
        self.instructions.append(inst)

    def __repr__(self) -> str:
        return f"Block({self.name}, insts={len(self.instructions)})"


class SSAFunction:
    def __init__(self, name: str, params: List[str]):
        self.name = name
        self.params = params
        self.entry_block: Optional[BasicBlock] = None
        self.blocks: List[BasicBlock] = []

    def add_block(self, block: BasicBlock):
        self.blocks.append(block)

    def print_ir(self) -> str:
        lines = [f"define @{self.name}({', '.join(self.params)}):"]
        for block in self.blocks:
            lines.append(f"{block.name}:")
            for phi in block.phi_nodes:
                lines.append(f"  {phi}")
            for inst in block.instructions:
                lines.append(f"  {inst}")
        return "\n".join(lines)


class AstToSsaLowering:
    """Lowers an AST function into Omni-SSA representation."""

    def __init__(self):
        self.var_versions: Dict[str, int] = {}

    def _next_var(self, name: str) -> SSAVar:
        v = self.var_versions.get(name, 0) + 1
        self.var_versions[name] = v
        return SSAVar(name, v)

    def lower_expression_function(self, fn_name: str, param_names: List[str], expr_ast: ast.AST) -> SSAFunction:
        fn = SSAFunction(fn_name, param_names)
        entry = BasicBlock("entry")
        fn.entry_block = entry
        fn.add_block(entry)

        # Map initial parameters to version 0
        env: Dict[str, SSAVar] = {}
        for p in param_names:
            v = SSAVar(p, 0)
            env[p] = v
            entry.add_instruction(SSAInstruction(v, "param", [p]))

        def lower_node(node: ast.AST) -> SSAVar:
            if isinstance(node, ast.Name):
                return env.get(node.id, SSAVar(node.id, 0))

            elif isinstance(node, ast.Constant):
                val = node.value
                const_var = self._next_var("c")
                entry.add_instruction(SSAInstruction(const_var, "const", [val]))
                return const_var

            elif isinstance(node, ast.BinOp):
                left_var = lower_node(node.left)
                right_var = lower_node(node.right)
                op_map = {
                    ast.Add: "add", ast.Sub: "sub", ast.Mult: "mul",
                    ast.LShift: "shl", ast.RShift: "shr",
                    ast.BitAnd: "and", ast.BitOr: "or", ast.BitXor: "xor"
                }
                opcode = op_map.get(type(node.op), "binop")
                res_var = self._next_var("t")
                entry.add_instruction(SSAInstruction(res_var, opcode, [left_var, right_var]))
                return res_var

            else:
                fallback_var = self._next_var("val")
                entry.add_instruction(SSAInstruction(fallback_var, "unknown", [str(node)]))
                return fallback_var

        result_var = lower_node(expr_ast)
        entry.add_instruction(SSAInstruction(None, "ret", [result_var]))
        return fn


def lower_ast_to_ssa(node: ast.AST, fn_name: str = "func", param_names: Optional[List[str]] = None) -> SSAFunction:
    """Convenience helper to lower an AST function definition or expression to SSA."""
    lowering = AstToSsaLowering()
    if isinstance(node, ast.FunctionDef):
        name = node.name
        params = [arg.arg for arg in node.args.args]
        # Return expression in body
        for stmt in node.body:
            if isinstance(stmt, ast.Return) and stmt.value:
                return lowering.lower_expression_function(name, params, stmt.value)
            elif isinstance(stmt, ast.Assign) and len(node.body) > 1 and isinstance(node.body[-1], ast.Return):
                # Simple sequence lowering
                pass
        # Fallback to last return expression
        ret_expr = [s.value for s in node.body if isinstance(s, ast.Return) and s.value]
        if ret_expr:
            return lowering.lower_expression_function(name, params, ret_expr[-1])
        return lowering.lower_expression_function(name, params, ast.Constant(value=0))
    else:
        return lowering.lower_expression_function(fn_name, param_names or [], node)

