"""
OmniCompiler SSA Intermediate Representation (Omni-SSA)
Turing-Complete Multi-Block Static Single Assignment (SSA) IR featuring:
1. Braun et al. (2013) On-The-Fly Multi-Block CFG & Minimal Phi-Node Construction
   (`if/elif/else`, `while`, `for ... in range(...)`, `break`, `continue`, tuple swaps).
2. Rich Instruction Set: Arithmetic, Bitwise, Comparisons (`cmp_*`), `select`,
   Direct/Recursive/External `call`, Memory `load`/`store`/`alloca`, SIMD `vadd`/`vmul`,
   `br` & `br_cond` terminators, and `ret`.
3. Cooper-Harvey-Kennedy Iterative Dominator Tree & Dominance Frontier Calculation.
4. Multi-Pass SSA Optimizer: Trivial Phi Elimination, Constant Folding & Propagation,
   Algebraic Identity Strength Reduction, and Dead Code Elimination (DCE).
"""

from typing import List, Dict, Set, Tuple, Any, Optional
import ast


TERMINATOR_OPCODES = frozenset({"ret", "br", "br_cond"})
SIDE_EFFECT_OPCODES = frozenset({"ret", "br", "br_cond", "store", "call", "param"})


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
    __slots__ = ("result", "opcode", "operands", "phi_incoming", "source_line")

    def __init__(
        self,
        result: Optional[SSAVar],
        opcode: str,
        operands: List[Any],
        phi_incoming: Optional[List[Tuple[str, Any]]] = None,
        source_line: int = 0,
    ):
        self.result = result
        self.opcode = opcode
        self.operands = operands
        # For 'phi' instructions: list of (pred_block_name, SSAVar_or_const)
        self.phi_incoming: List[Tuple[str, Any]] = phi_incoming if phi_incoming is not None else []
        self.source_line = source_line

    @property
    def is_terminator(self) -> bool:
        return self.opcode in TERMINATOR_OPCODES

    def __repr__(self) -> str:
        if self.opcode == "phi" and self.phi_incoming:
            inc = ", ".join(f"[{val}, %{blk}]" for blk, val in self.phi_incoming)
            return f"{self.result} = phi {inc}"
        ops = ", ".join(str(o) for o in self.operands)
        if self.result:
            return f"{self.result} = {self.opcode} {ops}"
        return f"{self.opcode} {ops}"


class BasicBlock:
    def __init__(self, name: str):
        self.name = name
        self.instructions: List[SSAInstruction] = []
        self.predecessors: List["BasicBlock"] = []
        self.successors: List["BasicBlock"] = []
        self.phi_nodes: List[SSAInstruction] = []
        self.loop_depth: int = 0

    def add_instruction(self, inst: SSAInstruction):
        self.instructions.append(inst)

    @property
    def is_terminated(self) -> bool:
        return bool(self.instructions) and self.instructions[-1].is_terminator

    def connect_to(self, target: "BasicBlock"):
        if target not in self.successors:
            self.successors.append(target)
        if self not in target.predecessors:
            target.predecessors.append(self)

    def __repr__(self) -> str:
        return f"Block({self.name}, phis={len(self.phi_nodes)}, insts={len(self.instructions)})"


class SSAFunction:
    def __init__(self, name: str, params: List[str], param_types: Optional[Dict[str, str]] = None):
        self.name = name
        self.params = params
        self.param_types: Dict[str, str] = param_types or {p: "i64" for p in params}
        self.entry_block: Optional[BasicBlock] = None
        self.blocks: List[BasicBlock] = []
        self.source_file: str = "<module>"

    def add_block(self, block: BasicBlock):
        if self.entry_block is None:
            self.entry_block = block
        self.blocks.append(block)

    def get_block(self, name: str) -> Optional[BasicBlock]:
        for b in self.blocks:
            if b.name == name:
                return b
        return None

    def compute_dominators(self) -> Dict[str, Optional[str]]:
        """
        Cooper-Harvey-Kennedy iterative immediate dominator algorithm.
        Returns mapping {block_name: immediate_dominator_block_name_or_None}.
        """
        if not self.blocks:
            return {}
        entry = self.entry_block or self.blocks[0]

        # Compute Reverse Post-Order (RPO) over reachable CFG
        visited: Set[str] = set()
        postorder: List[BasicBlock] = []
        block_map: Dict[str, BasicBlock] = {b.name: b for b in self.blocks}

        def dfs(b: BasicBlock):
            visited.add(b.name)
            for succ in b.successors:
                if succ.name in block_map and succ.name not in visited:
                    dfs(succ)
            postorder.append(b)

        dfs(entry)
        rpo = list(reversed(postorder))
        rpo_idx: Dict[str, int] = {b.name: i for i, b in enumerate(rpo)}

        doms: Dict[str, Optional[str]] = {b.name: None for b in rpo}
        doms[entry.name] = entry.name

        def intersect(b1: str, b2: str) -> str:
            finger1, finger2 = b1, b2
            while finger1 != finger2:
                while rpo_idx[finger1] > rpo_idx[finger2]:
                    finger1 = doms[finger1]  # type: ignore[assignment]
                while rpo_idx[finger2] > rpo_idx[finger1]:
                    finger2 = doms[finger2]  # type: ignore[assignment]
            return finger1

        changed = True
        while changed:
            changed = False
            for b in rpo:
                if b.name == entry.name:
                    continue
                processed_preds = [
                    p.name for p in b.predecessors
                    if p.name in doms and doms[p.name] is not None
                ]
                if not processed_preds:
                    continue
                new_idom = processed_preds[0]
                for p_name in processed_preds[1:]:
                    new_idom = intersect(p_name, new_idom)
                if doms[b.name] != new_idom:
                    doms[b.name] = new_idom
                    changed = True

        doms[entry.name] = None
        return doms

    def compute_dominance_frontiers(self) -> Dict[str, Set[str]]:
        """Computes dominance frontiers DF[b] for each reachable basic block."""
        doms = self.compute_dominators()
        df: Dict[str, Set[str]] = {b.name: set() for b in self.blocks}
        for b in self.blocks:
            if len(b.predecessors) >= 2 and b.name in doms:
                idom_b = doms[b.name]
                for p in b.predecessors:
                    runner: Optional[str] = p.name
                    while runner is not None and runner != idom_b:
                        if runner in df:
                            df[runner].add(b.name)
                        runner = doms.get(runner)
        return df

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
    """
    Lowers Python AST expressions and multi-block functions into Omni-SSA IR
    using Braun et al. (2013) on-the-fly SSA construction with minimal Phi placement.
    """

    BINOP_MAP = {
        ast.Add: "add",
        ast.Sub: "sub",
        ast.Mult: "mul",
        ast.FloorDiv: "sdiv",
        ast.Div: "sdiv",
        ast.Mod: "srem",
        ast.LShift: "shl",
        ast.RShift: "shr",
        ast.BitAnd: "and",
        ast.BitOr: "or",
        ast.BitXor: "xor",
    }

    CMP_MAP = {
        ast.Eq: "cmp_eq",
        ast.NotEq: "cmp_ne",
        ast.Lt: "cmp_lt",
        ast.LtE: "cmp_le",
        ast.Gt: "cmp_gt",
        ast.GtE: "cmp_ge",
        ast.Is: "cmp_eq",
        ast.IsNot: "cmp_ne",
    }

    def __init__(self):
        self.var_versions: Dict[str, int] = {}
        self._block_counter: int = 0
        # Braun SSA bookkeeping
        self._current_def: Dict[str, Dict[str, SSAVar]] = {}
        self._sealed_blocks: Set[str] = set()
        self._incomplete_phis: Dict[str, Dict[str, SSAInstruction]] = {}
        self._block_by_name: Dict[str, BasicBlock] = {}
        # Loop stack: (continue_target_block, break_target_block)
        self._loop_stack: List[Tuple[BasicBlock, BasicBlock]] = []
        self._loop_depth: int = 0
        self._fn: Optional[SSAFunction] = None
        self._cur_block: Optional[BasicBlock] = None

    def _next_var(self, name: str, var_type: str = "i64") -> SSAVar:
        v = self.var_versions.get(name, 0) + 1
        self.var_versions[name] = v
        return SSAVar(name, v, var_type=var_type)

    def _new_block(self, prefix: str, seal: bool = False) -> BasicBlock:
        self._block_counter += 1
        name = prefix if prefix == "entry" and self._block_counter == 1 else f"{prefix}_{self._block_counter}"
        bb = BasicBlock(name)
        bb.loop_depth = self._loop_depth
        self._block_by_name[name] = bb
        if self._fn is not None:
            self._fn.add_block(bb)
        if seal:
            self._sealed_blocks.add(name)
        return bb

    # ------------------------------------------------------------------
    # Legacy single-expression lowering (100% preserved for compatibility)
    # ------------------------------------------------------------------
    def lower_expression_function(self, fn_name: str, param_names: List[str], expr_ast: ast.AST) -> SSAFunction:
        fn = SSAFunction(fn_name, param_names)
        entry = BasicBlock("entry")
        fn.entry_block = entry
        fn.add_block(entry)

        env: Dict[str, SSAVar] = {}
        for p in param_names:
            v = SSAVar(p, 0)
            env[p] = v
            entry.add_instruction(SSAInstruction(v, "param", [p], source_line=getattr(expr_ast, "lineno", 0)))

        def lower_node(node: ast.AST) -> SSAVar:
            line = getattr(node, "lineno", 0)
            if isinstance(node, ast.Name):
                return env.get(node.id, SSAVar(node.id, 0))

            elif isinstance(node, ast.Constant):
                val = int(node.value) if isinstance(node.value, bool) else node.value
                const_var = self._next_var("c")
                entry.add_instruction(SSAInstruction(const_var, "const", [val], source_line=line))
                return const_var

            elif isinstance(node, ast.UnaryOp):
                operand_var = lower_node(node.operand)
                if isinstance(node.op, ast.UAdd):
                    return operand_var
                elif isinstance(node.op, ast.USub):
                    zero = self._next_var("c")
                    entry.add_instruction(SSAInstruction(zero, "const", [0], source_line=line))
                    res = self._next_var("t")
                    entry.add_instruction(SSAInstruction(res, "sub", [zero, operand_var], source_line=line))
                    return res
                elif isinstance(node.op, ast.Invert):
                    neg1 = self._next_var("c")
                    entry.add_instruction(SSAInstruction(neg1, "const", [-1], source_line=line))
                    res = self._next_var("t")
                    entry.add_instruction(SSAInstruction(res, "xor", [operand_var, neg1], source_line=line))
                    return res
                elif isinstance(node.op, ast.Not):
                    zero = self._next_var("c")
                    entry.add_instruction(SSAInstruction(zero, "const", [0], source_line=line))
                    res = self._next_var("t")
                    entry.add_instruction(SSAInstruction(res, "cmp_eq", [operand_var, zero], source_line=line))
                    return res

            elif isinstance(node, ast.BinOp):
                left_var = lower_node(node.left)
                right_var = lower_node(node.right)
                opcode = self.BINOP_MAP.get(type(node.op), "binop")
                res_var = self._next_var("t")
                entry.add_instruction(SSAInstruction(res_var, opcode, [left_var, right_var], source_line=line))
                return res_var

            elif isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
                left_var = lower_node(node.left)
                right_var = lower_node(node.comparators[0])
                opcode = self.CMP_MAP.get(type(node.ops[0]), "cmp_eq")
                res_var = self._next_var("t")
                entry.add_instruction(SSAInstruction(res_var, opcode, [left_var, right_var], source_line=line))
                return res_var

            elif isinstance(node, ast.IfExp):
                cond_var = lower_node(node.test)
                true_var = lower_node(node.body)
                false_var = lower_node(node.orelse)
                res_var = self._next_var("sel")
                entry.add_instruction(SSAInstruction(res_var, "select", [cond_var, true_var, false_var], source_line=line))
                return res_var

            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                arg_vars = [lower_node(a) for a in node.args]
                res_var = self._next_var("call")
                entry.add_instruction(SSAInstruction(res_var, "call", [node.func.id] + arg_vars, source_line=line))
                return res_var

            elif isinstance(node, ast.Subscript):
                base_var = lower_node(node.value)
                idx_var = lower_node(node.slice)
                is_raw_pointer = (
                    isinstance(node.value, ast.Name)
                    and (
                        node.value.id in param_names
                        or node.value.id.endswith("_ptr")
                        or node.value.id.endswith("_buf")
                        or node.value.id.startswith("buf")
                        or node.value.id.startswith("sim_")
                    )
                )
                res_var = self._next_var("ld")
                if is_raw_pointer:
                    entry.add_instruction(SSAInstruction(res_var, "load", [base_var, idx_var], source_line=line))
                else:
                    entry.add_instruction(SSAInstruction(res_var, "call", ["omni_item_get", base_var, idx_var], source_line=line))
                return res_var

            fallback_var = self._next_var("val")
            entry.add_instruction(SSAInstruction(fallback_var, "unknown", [str(node)], source_line=line))
            return fallback_var

        result_var = lower_node(expr_ast)
        entry.add_instruction(SSAInstruction(None, "ret", [result_var], source_line=getattr(expr_ast, "lineno", 0)))
        return fn

    # ------------------------------------------------------------------
    # Braun et al. (2013) Multi-Block SSA Construction
    # ------------------------------------------------------------------
    def _write_variable(self, var_name: str, block: BasicBlock, value: SSAVar):
        self._current_def.setdefault(var_name, {})[block.name] = value

    def _read_variable(self, var_name: str, block: BasicBlock) -> SSAVar:
        defs = self._current_def.get(var_name, {})
        if block.name in defs:
            return defs[block.name]
        return self._read_variable_recursive(var_name, block)

    def _read_variable_recursive(self, var_name: str, block: BasicBlock) -> SSAVar:
        if block.name not in self._sealed_blocks:
            # Incomplete CFG (e.g., loop header before back-edge): place operandless Phi
            phi_res = self._next_var(var_name)
            phi_inst = SSAInstruction(phi_res, "phi", [], phi_incoming=[])
            block.phi_nodes.append(phi_inst)
            self._incomplete_phis.setdefault(block.name, {})[var_name] = phi_inst
            val = phi_res
        elif len(block.predecessors) == 0:
            # Uninitialized variable at entry -> default to 0
            zero_var = self._next_var("zero")
            insert_idx = 0
            while insert_idx < len(block.instructions) and block.instructions[insert_idx].opcode == "param":
                insert_idx += 1
            block.instructions.insert(insert_idx, SSAInstruction(zero_var, "const", [0]))
            val = zero_var
        elif len(block.predecessors) == 1:
            val = self._read_variable(var_name, block.predecessors[0])
        else:
            # Break potential cycles with Phi node, then populate operands
            phi_res = self._next_var(var_name)
            phi_inst = SSAInstruction(phi_res, "phi", [], phi_incoming=[])
            block.phi_nodes.append(phi_inst)
            self._write_variable(var_name, block, phi_res)
            val = self._add_phi_operands(var_name, block, phi_inst)

        self._write_variable(var_name, block, val)
        return val

    def _add_phi_operands(self, var_name: str, block: BasicBlock, phi_inst: SSAInstruction) -> SSAVar:
        incoming: List[Tuple[str, Any]] = []
        operands: List[Any] = []
        for pred in block.predecessors:
            pred_val = self._read_variable(var_name, pred)
            incoming.append((pred.name, pred_val))
            operands.append(pred_val)
        phi_inst.phi_incoming = incoming
        phi_inst.operands = operands
        return self._try_remove_trivial_phi(block, phi_inst)

    def _try_remove_trivial_phi(self, block: BasicBlock, phi_inst: SSAInstruction) -> SSAVar:
        assert phi_inst.result is not None
        same: Optional[SSAVar] = None
        for op in phi_inst.operands:
            if op == same or op == phi_inst.result:
                continue
            if same is not None:
                return phi_inst.result  # Non-trivial Phi merging >= 2 distinct values
            same = op

        if same is None:
            same = self._next_var("undef")
            block.instructions.insert(0, SSAInstruction(same, "const", [0]))

        # Remove trivial phi and replace all uses of phi_inst.result with `same`
        old_var = phi_inst.result
        if phi_inst in block.phi_nodes:
            block.phi_nodes.remove(phi_inst)

        self._replace_all_uses(old_var, same)
        for v_defs in self._current_def.values():
            for blk_name, cur_v in list(v_defs.items()):
                if cur_v == old_var:
                    v_defs[blk_name] = same
        return same

    def _replace_all_uses(self, old_var: SSAVar, new_var: SSAVar):
        if self._fn is None:
            return
        affected_phis: List[Tuple[BasicBlock, SSAInstruction]] = []
        for b in self._fn.blocks:
            for phi in list(b.phi_nodes):
                changed = False
                for i, op in enumerate(phi.operands):
                    if op == old_var:
                        phi.operands[i] = new_var
                        changed = True
                for i, (p_blk, p_val) in enumerate(phi.phi_incoming):
                    if p_val == old_var:
                        phi.phi_incoming[i] = (p_blk, new_var)
                        changed = True
                if changed and phi.result != old_var:
                    affected_phis.append((b, phi))
            for inst in b.instructions:
                for i, op in enumerate(inst.operands):
                    if op == old_var:
                        inst.operands[i] = new_var

        for b, phi in affected_phis:
            if phi in b.phi_nodes:
                self._try_remove_trivial_phi(b, phi)

    def _seal_block(self, block: BasicBlock):
        if block.name in self._sealed_blocks:
            return
        inc = self._incomplete_phis.pop(block.name, {})
        for var_name, phi_inst in inc.items():
            self._add_phi_operands(var_name, block, phi_inst)
        self._sealed_blocks.add(block.name)

    def _emit(self, result: Optional[SSAVar], opcode: str, operands: List[Any], line: int = 0) -> Optional[SSAVar]:
        assert self._cur_block is not None
        if self._cur_block.is_terminated:
            return result
        self._cur_block.add_instruction(SSAInstruction(result, opcode, operands, source_line=line))
        return result

    def _emit_const(self, val: int, line: int = 0) -> SSAVar:
        v = self._next_var("c")
        self._emit(v, "const", [int(val)], line=line)
        return v

    # ------------------------------------------------------------------
    # Full Function & Statement/Expression Lowering
    # ------------------------------------------------------------------
    def lower_function_def(self, func_def: ast.FunctionDef) -> SSAFunction:
        # Fast path for pure single-statement `return <expr>` without control-flow
        body_stmts = [
            s for s in func_def.body
            if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str))
        ]
        params = [arg.arg for arg in func_def.args.args]
        if (
            len(body_stmts) == 1
            and isinstance(body_stmts[0], ast.Return)
            and body_stmts[0].value is not None
            and not any(isinstance(n, (ast.BoolOp,)) for n in ast.walk(body_stmts[0].value))
        ):
            return self.lower_expression_function(func_def.name, params, body_stmts[0].value)

        param_types: Dict[str, str] = {}
        for arg in func_def.args.args:
            ann = arg.annotation
            if isinstance(ann, ast.Name) and ann.id in ("ptr", "pointer", "bytes", "list"):
                param_types[arg.arg] = "ptr"
            else:
                param_types[arg.arg] = "i64"

        fn = SSAFunction(func_def.name, params, param_types=param_types)
        self._fn = fn
        self._block_counter = 0
        self._current_def.clear()
        self._sealed_blocks.clear()
        self._incomplete_phis.clear()
        self._block_by_name.clear()
        self._loop_stack.clear()
        self._loop_depth = 0

        entry = self._new_block("entry", seal=True)
        self._cur_block = entry

        for p in params:
            v = SSAVar(p, 0, var_type=param_types.get(p, "i64"))
            self._emit(v, "param", [p], line=getattr(func_def, "lineno", 0))
            self._write_variable(p, entry, v)

        self._lower_stmt_list(body_stmts)

        # Ensure fallthrough block ends with `ret 0`
        if self._cur_block is not None and not self._cur_block.is_terminated:
            z = self._emit_const(0, line=getattr(func_def, "lineno", 0))
            self._emit(None, "ret", [z], line=getattr(func_def, "lineno", 0))

        # Seal any remaining unsealed blocks defensively and prune unreachable empty blocks
        for b in list(fn.blocks):
            self._seal_block(b)

        self._prune_unreachable_blocks(fn)
        return fn

    def _prune_unreachable_blocks(self, fn: SSAFunction):
        if not fn.blocks:
            return
        entry = fn.entry_block or fn.blocks[0]
        reachable: Set[str] = set()

        def visit(b: BasicBlock):
            if b.name in reachable:
                return
            reachable.add(b.name)
            for s in b.successors:
                visit(s)

        visit(entry)
        fn.blocks = [b for b in fn.blocks if b.name in reachable]
        for b in fn.blocks:
            b.predecessors = [p for p in b.predecessors if p.name in reachable]
            b.successors = [s for s in b.successors if s.name in reachable]

    def _lower_stmt_list(self, stmts: List[ast.stmt]):
        for stmt in stmts:
            if self._cur_block is None or self._cur_block.is_terminated:
                break
            self._lower_stmt(stmt)

    def _lower_stmt(self, stmt: ast.stmt):
        assert self._cur_block is not None
        line = getattr(stmt, "lineno", 0)

        if isinstance(stmt, ast.Return):
            if stmt.value is not None:
                val = self._lower_expr(stmt.value)
            else:
                val = self._emit_const(0, line=line)
            self._emit(None, "ret", [val], line=line)

        elif isinstance(stmt, ast.Assign):
            if len(stmt.targets) == 1:
                target = stmt.targets[0]
                # Tuple unpacking / parallel assignment: `a, b = b, a + b`
                if isinstance(target, (ast.Tuple, ast.List)) and isinstance(stmt.value, (ast.Tuple, ast.List)):
                    rhs_vals = [self._lower_expr(elt) for elt in stmt.value.elts]
                    for lhs_elt, rhs_val in zip(target.elts, rhs_vals):
                        self._assign_target(lhs_elt, rhs_val, line=line)
                    return

            val = self._lower_expr(stmt.value)
            for target in stmt.targets:
                self._assign_target(target, val, line=line)

        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                val = self._lower_expr(stmt.value)
                self._assign_target(stmt.target, val, line=line)

        elif isinstance(stmt, ast.AugAssign):
            if isinstance(stmt.target, ast.Name):
                cur_val = self._read_variable(stmt.target.id, self._cur_block)
                rhs_val = self._lower_expr(stmt.value)
                opcode = self.BINOP_MAP.get(type(stmt.op), "add")
                res = self._next_var(stmt.target.id)
                self._emit(res, opcode, [cur_val, rhs_val], line=line)
                self._write_variable(stmt.target.id, self._cur_block, res)
            elif isinstance(stmt.target, ast.Subscript):
                base_var = self._lower_expr(stmt.target.value)
                idx_var = self._lower_expr(stmt.target.slice)
                loaded = self._next_var("ld")
                self._emit(loaded, "call", ["omni_item_get", base_var, idx_var], line=line)
                rhs_val = self._lower_expr(stmt.value)
                opcode = self.BINOP_MAP.get(type(stmt.op), "add")
                res = self._next_var("st_val")
                self._emit(res, opcode, [loaded, rhs_val], line=line)
                self._emit(None, "call", ["omni_item_set", base_var, idx_var, res], line=line)

        elif isinstance(stmt, ast.If):
            cond_var = self._lower_expr(stmt.test)
            pred_bb = self._cur_block
            then_bb = self._new_block("if_then", seal=False)
            has_else = len(stmt.orelse) > 0
            else_bb = self._new_block("if_else", seal=False) if has_else else None
            merge_bb = self._new_block("if_merge", seal=False)

            if else_bb is not None:
                pred_bb.connect_to(then_bb)
                pred_bb.connect_to(else_bb)
                self._emit(None, "br_cond", [cond_var, then_bb.name, else_bb.name], line=line)
            else:
                pred_bb.connect_to(then_bb)
                pred_bb.connect_to(merge_bb)
                self._emit(None, "br_cond", [cond_var, then_bb.name, merge_bb.name], line=line)

            self._seal_block(then_bb)
            self._cur_block = then_bb
            self._lower_stmt_list(stmt.body)
            then_end = self._cur_block
            if then_end is not None and not then_end.is_terminated:
                then_end.connect_to(merge_bb)
                self._emit(None, "br", [merge_bb.name], line=line)

            if else_bb is not None:
                self._seal_block(else_bb)
                self._cur_block = else_bb
                self._lower_stmt_list(stmt.orelse)
                else_end = self._cur_block
                if else_end is not None and not else_end.is_terminated:
                    else_end.connect_to(merge_bb)
                    self._emit(None, "br", [merge_bb.name], line=line)

            self._seal_block(merge_bb)
            if len(merge_bb.predecessors) == 0:
                # Both branches returned / broke / continued
                self._cur_block = None
            else:
                self._cur_block = merge_bb

        elif isinstance(stmt, ast.While):
            pre_bb = self._cur_block
            self._loop_depth += 1
            cond_bb = self._new_block("while_cond", seal=False)  # Unsealed until body back-edges finish!
            body_bb = self._new_block("while_body", seal=False)
            self._loop_depth -= 1
            exit_bb = self._new_block("while_exit", seal=False)

            pre_bb.connect_to(cond_bb)
            self._emit(None, "br", [cond_bb.name], line=line)

            self._cur_block = cond_bb
            cond_var = self._lower_expr(stmt.test)
            cond_end = self._cur_block
            assert cond_end is not None
            cond_end.connect_to(body_bb)
            cond_end.connect_to(exit_bb)
            self._emit(None, "br_cond", [cond_var, body_bb.name, exit_bb.name], line=line)

            self._seal_block(body_bb)
            self._loop_depth += 1
            self._loop_stack.append((cond_bb, exit_bb))
            self._cur_block = body_bb
            self._lower_stmt_list(stmt.body)
            self._loop_stack.pop()
            self._loop_depth -= 1

            body_end = self._cur_block
            if body_end is not None and not body_end.is_terminated:
                body_end.connect_to(cond_bb)
                self._emit(None, "br", [cond_bb.name], line=line)

            # All predecessors of cond_bb and exit_bb are now known
            self._seal_block(cond_bb)
            self._seal_block(exit_bb)
            self._cur_block = exit_bb

        elif isinstance(stmt, ast.For):
            # Supports `for i in range(stop)` / `range(start, stop)` / `range(start, stop, step)`
            if (
                isinstance(stmt.target, ast.Name)
                and isinstance(stmt.iter, ast.Call)
                and isinstance(stmt.iter.func, ast.Name)
                and stmt.iter.func.id == "range"
                and 1 <= len(stmt.iter.args) <= 3
            ):
                r_args = stmt.iter.args
                if len(r_args) == 1:
                    start_var = self._emit_const(0, line=line)
                    stop_var = self._lower_expr(r_args[0])
                    step_var = self._emit_const(1, line=line)
                    neg_step = False
                elif len(r_args) == 2:
                    start_var = self._lower_expr(r_args[0])
                    stop_var = self._lower_expr(r_args[1])
                    step_var = self._emit_const(1, line=line)
                    neg_step = False
                else:
                    start_var = self._lower_expr(r_args[0])
                    stop_var = self._lower_expr(r_args[1])
                    step_var = self._lower_expr(r_args[2])
                    neg_step = (
                        isinstance(r_args[2], ast.UnaryOp)
                        and isinstance(r_args[2].op, ast.USub)
                    ) or (
                        isinstance(r_args[2], ast.Constant)
                        and isinstance(r_args[2].value, int)
                        and r_args[2].value < 0
                    )

                loop_var_name = stmt.target.id
                self._write_variable(loop_var_name, self._cur_block, start_var)

                pre_bb = self._cur_block
                self._loop_depth += 1
                cond_bb = self._new_block("for_cond", seal=False)
                body_bb = self._new_block("for_body", seal=False)
                latch_bb = self._new_block("for_latch", seal=False)
                self._loop_depth -= 1
                exit_bb = self._new_block("for_exit", seal=False)

                pre_bb.connect_to(cond_bb)
                self._emit(None, "br", [cond_bb.name], line=line)

                self._cur_block = cond_bb
                cur_iv = self._read_variable(loop_var_name, cond_bb)
                cmp_op = "cmp_gt" if neg_step else "cmp_lt"
                cond_var = self._next_var("for_cmp")
                self._emit(cond_var, cmp_op, [cur_iv, stop_var], line=line)
                cond_bb.connect_to(body_bb)
                cond_bb.connect_to(exit_bb)
                self._emit(None, "br_cond", [cond_var, body_bb.name, exit_bb.name], line=line)

                self._seal_block(body_bb)
                self._loop_depth += 1
                self._loop_stack.append((latch_bb, exit_bb))
                self._cur_block = body_bb
                self._lower_stmt_list(stmt.body)
                self._loop_stack.pop()
                self._loop_depth -= 1

                body_end = self._cur_block
                if body_end is not None and not body_end.is_terminated:
                    body_end.connect_to(latch_bb)
                    self._emit(None, "br", [latch_bb.name], line=line)

                self._seal_block(latch_bb)
                if len(latch_bb.predecessors) > 0:
                    self._cur_block = latch_bb
                    latch_iv = self._read_variable(loop_var_name, latch_bb)
                    next_iv = self._next_var(loop_var_name)
                    self._emit(next_iv, "add", [latch_iv, step_var], line=line)
                    self._write_variable(loop_var_name, latch_bb, next_iv)
                    latch_bb.connect_to(cond_bb)
                    self._emit(None, "br", [cond_bb.name], line=line)

                self._seal_block(cond_bb)
                self._seal_block(exit_bb)
                self._cur_block = exit_bb

            elif isinstance(stmt.target, ast.Name):
                # Generic collection loop: `for item in <iterable>:`
                coll_v = self._lower_expr(stmt.iter)
                len_v = self._next_var("coll_len")
                self._emit(len_v, "call", ["omni_item_len", coll_v], line=line)
                iv_name = f"_iter_idx_{self._block_counter}"
                iv_start = self._emit_const(0, line=line)
                iv_step = self._emit_const(1, line=line)
                self._write_variable(iv_name, self._cur_block, iv_start)

                pre_bb = self._cur_block
                self._loop_depth += 1
                cond_bb = self._new_block("for_cond", seal=False)
                body_bb = self._new_block("for_body", seal=False)
                latch_bb = self._new_block("for_latch", seal=False)
                self._loop_depth -= 1
                exit_bb = self._new_block("for_exit", seal=False)

                pre_bb.connect_to(cond_bb)
                self._emit(None, "br", [cond_bb.name], line=line)

                self._cur_block = cond_bb
                cur_iv = self._read_variable(iv_name, cond_bb)
                cond_var = self._next_var("for_cmp")
                self._emit(cond_var, "cmp_lt", [cur_iv, len_v], line=line)
                cond_bb.connect_to(body_bb)
                cond_bb.connect_to(exit_bb)
                self._emit(None, "br_cond", [cond_var, body_bb.name, exit_bb.name], line=line)

                self._seal_block(body_bb)
                self._loop_depth += 1
                self._loop_stack.append((latch_bb, exit_bb))
                self._cur_block = body_bb

                # Fetch element from collection and bind to loop target
                item_v = self._next_var("coll_item")
                self._emit(item_v, "call", ["omni_item_get", coll_v, cur_iv], line=line)
                self._write_variable(stmt.target.id, body_bb, item_v)

                self._lower_stmt_list(stmt.body)
                self._loop_stack.pop()
                self._loop_depth -= 1

                body_end = self._cur_block
                if body_end is not None and not body_end.is_terminated:
                    body_end.connect_to(latch_bb)
                    self._emit(None, "br", [latch_bb.name], line=line)

                self._seal_block(latch_bb)
                if len(latch_bb.predecessors) > 0:
                    self._cur_block = latch_bb
                    latch_iv = self._read_variable(iv_name, latch_bb)
                    next_iv = self._next_var(iv_name)
                    self._emit(next_iv, "add", [latch_iv, iv_step], line=line)
                    self._write_variable(iv_name, latch_bb, next_iv)
                    latch_bb.connect_to(cond_bb)
                    self._emit(None, "br", [cond_bb.name], line=line)

                self._seal_block(cond_bb)
                self._seal_block(exit_bb)
                self._cur_block = exit_bb

        elif isinstance(stmt, ast.Break):
            if self._loop_stack:
                _, break_bb = self._loop_stack[-1]
                self._cur_block.connect_to(break_bb)
                self._emit(None, "br", [break_bb.name], line=line)

        elif isinstance(stmt, ast.Continue):
            if self._loop_stack:
                cont_bb, _ = self._loop_stack[-1]
                self._cur_block.connect_to(cont_bb)
                self._emit(None, "br", [cont_bb.name], line=line)

        elif isinstance(stmt, ast.Expr):
            if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                return  # Ignore docstring
            if (
                isinstance(stmt.value, ast.Call)
                and isinstance(stmt.value.func, ast.Attribute)
                and stmt.value.func.attr == "append"
                and isinstance(stmt.value.func.value, ast.Name)
            ):
                var_name = stmt.value.func.value.id
                new_ptr = self._lower_expr(stmt.value)
                self._write_variable(var_name, self._cur_block, new_ptr)
                return
            self._lower_expr(stmt.value)

        elif isinstance(stmt, ast.Pass):
            return

    def _assign_target(self, target: ast.AST, val: SSAVar, line: int = 0):
        assert self._cur_block is not None
        if isinstance(target, ast.Name):
            self._write_variable(target.id, self._cur_block, val)
        elif isinstance(target, ast.Subscript):
            base_var = self._lower_expr(target.value)
            idx_var = self._lower_expr(target.slice)
            is_raw_pointer = (
                isinstance(target.value, ast.Name)
                and (
                    (self._fn is not None and target.value.id in self._fn.params)
                    or target.value.id.endswith("_ptr")
                    or target.value.id.endswith("_buf")
                    or target.value.id.startswith("buf")
                    or target.value.id.startswith("sim_")
                )
            )
            if is_raw_pointer:
                self._emit(None, "store", [base_var, idx_var, val], line=line)
            else:
                self._emit(None, "call", ["omni_item_set", base_var, idx_var, val], line=line)

    def _lower_expr(self, node: ast.AST) -> SSAVar:
        assert self._cur_block is not None
        line = getattr(node, "lineno", 0)

        if isinstance(node, ast.Name):
            return self._read_variable(node.id, self._cur_block)

        elif isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                return self._emit_const(1 if node.value else 0, line=line)
            elif isinstance(node.value, int):
                return self._emit_const(node.value, line=line)
            return self._emit_const(0, line=line)

        elif isinstance(node, ast.UnaryOp):
            op_var = self._lower_expr(node.operand)
            if isinstance(node.op, ast.UAdd):
                return op_var
            elif isinstance(node.op, ast.USub):
                zero = self._emit_const(0, line=line)
                res = self._next_var("neg")
                self._emit(res, "sub", [zero, op_var], line=line)
                return res
            elif isinstance(node.op, ast.Invert):
                neg1 = self._emit_const(-1, line=line)
                res = self._next_var("inv")
                self._emit(res, "xor", [op_var, neg1], line=line)
                return res
            elif isinstance(node.op, ast.Not):
                zero = self._emit_const(0, line=line)
                res = self._next_var("not")
                self._emit(res, "cmp_eq", [op_var, zero], line=line)
                return res

        elif isinstance(node, ast.BinOp):
            left_var = self._lower_expr(node.left)
            right_var = self._lower_expr(node.right)
            opcode = self.BINOP_MAP.get(type(node.op), "add")
            res = self._next_var("t")
            self._emit(res, opcode, [left_var, right_var], line=line)
            return res

        elif isinstance(node, ast.Compare):
            left_var = self._lower_expr(node.left)
            acc: Optional[SSAVar] = None
            for op, comp in zip(node.ops, node.comparators):
                right_var = self._lower_expr(comp)
                cmp_opcode = self.CMP_MAP.get(type(op), "cmp_eq")
                cmp_res = self._next_var("cmp")
                self._emit(cmp_res, cmp_opcode, [left_var, right_var], line=line)
                if acc is None:
                    acc = cmp_res
                else:
                    merged = self._next_var("cmp_and")
                    self._emit(merged, "and", [acc, cmp_res], line=line)
                    acc = merged
                left_var = right_var
            return acc if acc is not None else self._emit_const(1, line=line)

        elif isinstance(node, ast.BoolOp):
            zero = self._emit_const(0, line=line)
            vals = []
            for v_node in node.values:
                raw_v = self._lower_expr(v_node)
                as_bool = self._next_var("bool")
                self._emit(as_bool, "cmp_ne", [raw_v, zero], line=line)
                vals.append(as_bool)
            acc = vals[0]
            op_code = "and" if isinstance(node.op, ast.And) else "or"
            for nxt in vals[1:]:
                merged = self._next_var("logic")
                self._emit(merged, op_code, [acc, nxt], line=line)
                acc = merged
            return acc

        elif isinstance(node, ast.IfExp):
            cond_var = self._lower_expr(node.test)
            true_var = self._lower_expr(node.body)
            false_var = self._lower_expr(node.orelse)
            res = self._next_var("sel")
            self._emit(res, "select", [cond_var, true_var, false_var], line=line)
            return res

        elif isinstance(node, ast.List):
            init_cap = self._emit_const(max(4, len(node.elts)), line=line)
            list_ptr = self._next_var("list_ptr")
            self._emit(list_ptr, "call", ["omni_list_new", init_cap], line=line)
            for i, elt in enumerate(node.elts):
                elt_v = self._lower_expr(elt)
                idx_v = self._emit_const(i, line=line)
                self._emit(None, "call", ["omni_list_set", list_ptr, idx_v, elt_v], line=line)
            return list_ptr

        elif isinstance(node, ast.Dict):
            init_cap = self._emit_const(max(16, len(node.keys) * 2), line=line)
            dict_ptr = self._next_var("dict_ptr")
            self._emit(dict_ptr, "call", ["omni_dict_new", init_cap], line=line)
            for k_node, v_node in zip(node.keys, node.values):
                if k_node is not None:
                    k_v = self._lower_expr(k_node)
                    v_v = self._lower_expr(v_node)
                    self._emit(None, "call", ["omni_dict_set", dict_ptr, k_v, v_v], line=line)
            return dict_ptr

        elif isinstance(node, ast.Subscript):
            base_var = self._lower_expr(node.value)
            idx_var = self._lower_expr(node.slice)
            is_raw_pointer = (
                isinstance(node.value, ast.Name)
                and (
                    (self._fn is not None and node.value.id in self._fn.params)
                    or node.value.id.endswith("_ptr")
                    or node.value.id.endswith("_buf")
                    or node.value.id.startswith("buf")
                    or node.value.id.startswith("sim_")
                )
            )
            res = self._next_var("ld")
            if is_raw_pointer:
                self._emit(res, "load", [base_var, idx_var], line=line)
            else:
                self._emit(res, "call", ["omni_item_get", base_var, idx_var], line=line)
            return res

        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                fname = node.func.id
                if fname == "len" and len(node.args) == 1:
                    arg_v = self._lower_expr(node.args[0])
                    res = self._next_var("len")
                    self._emit(res, "call", ["omni_item_len", arg_v], line=line)
                    return res
                elif fname == "abs" and len(node.args) == 1:
                    x = self._lower_expr(node.args[0])
                    z = self._emit_const(0, line=line)
                    is_neg = self._next_var("is_neg")
                    self._emit(is_neg, "cmp_lt", [x, z], line=line)
                    neg_x = self._next_var("neg_x")
                    self._emit(neg_x, "sub", [z, x], line=line)
                    res = self._next_var("abs")
                    self._emit(res, "select", [is_neg, neg_x, x], line=line)
                    return res
                elif fname == "min" and len(node.args) == 2:
                    a = self._lower_expr(node.args[0])
                    b = self._lower_expr(node.args[1])
                    cond = self._next_var("lt")
                    self._emit(cond, "cmp_lt", [a, b], line=line)
                    res = self._next_var("min")
                    self._emit(res, "select", [cond, a, b], line=line)
                    return res
                elif fname == "max" and len(node.args) == 2:
                    a = self._lower_expr(node.args[0])
                    b = self._lower_expr(node.args[1])
                    cond = self._next_var("gt")
                    self._emit(cond, "cmp_gt", [a, b], line=line)
                    res = self._next_var("max")
                    self._emit(res, "select", [cond, a, b], line=line)
                    return res
                elif fname == "int" and len(node.args) == 1:
                    return self._lower_expr(node.args[0])
                else:
                    arg_vars = [self._lower_expr(a) for a in node.args]
                    res = self._next_var("call")
                    self._emit(res, "call", [fname] + arg_vars, line=line)
                    return res
            elif isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                if attr == "append" and len(node.args) == 1:
                    obj_v = self._lower_expr(node.func.value)
                    val_v = self._lower_expr(node.args[0])
                    res = self._next_var("appended_list")
                    self._emit(res, "call", ["omni_list_append", obj_v, val_v], line=line)
                    return res
                elif attr == "get" and 1 <= len(node.args) <= 2:
                    obj_v = self._lower_expr(node.func.value)
                    key_v = self._lower_expr(node.args[0])
                    res = self._next_var("get_val")
                    self._emit(res, "call", ["omni_dict_get", obj_v, key_v], line=line)
                    return res

        return self._emit_const(0, line=line)


# ==============================================================================
# SSA Optimization Pipeline (Constant Propagation/Folding + Strength Reduction + DCE)
# ==============================================================================

def _eval_const_binop(opcode: str, a: int, b: int) -> Optional[int]:
    mask64 = 0xFFFFFFFFFFFFFFFF
    # Interpret as signed 64-bit integers
    def to_s64(x: int) -> int:
        x &= mask64
        return x - (1 << 64) if x >= (1 << 63) else x

    sa, sb = to_s64(a), to_s64(b)
    if opcode == "add":
        return to_s64(sa + sb)
    elif opcode == "sub":
        return to_s64(sa - sb)
    elif opcode == "mul":
        return to_s64(sa * sb)
    elif opcode == "sdiv":
        if sb == 0 or (sa == -(1 << 63) and sb == -1):
            return None
        q = abs(sa) // abs(sb)
        return -q if (sa < 0) ^ (sb < 0) else q
    elif opcode == "srem":
        if sb == 0 or (sa == -(1 << 63) and sb == -1):
            return None
        r = abs(sa) % abs(sb)
        return -r if sa < 0 else r
    elif opcode == "shl":
        if 0 <= sb < 64:
            return to_s64(sa << sb)
        return None
    elif opcode == "shr":
        if 0 <= sb < 64:
            return sa >> sb
        return None
    elif opcode == "and":
        return to_s64(sa & sb)
    elif opcode == "or":
        return to_s64(sa | sb)
    elif opcode == "xor":
        return to_s64(sa ^ sb)
    elif opcode == "cmp_eq":
        return 1 if sa == sb else 0
    elif opcode == "cmp_ne":
        return 1 if sa != sb else 0
    elif opcode == "cmp_lt":
        return 1 if sa < sb else 0
    elif opcode == "cmp_le":
        return 1 if sa <= sb else 0
    elif opcode == "cmp_gt":
        return 1 if sa > sb else 0
    elif opcode == "cmp_ge":
        return 1 if sa >= sb else 0
    return None


def optimize_ssa(fn: SSAFunction) -> SSAFunction:
    """
    Runs multi-pass SSA optimization:
    1. Constant Folding & Constant Propagation across Phi & ALU instructions.
    2. Algebraic Strength Reduction (x * 2^k -> x << k, x + 0 -> x, x * 1 -> x).
    3. Dead Code Elimination (DCE) for unused pure instructions.
    """
    changed = True
    max_iters = 8
    iters = 0

    while changed and iters < max_iters:
        changed = False
        iters += 1
        const_map: Dict[SSAVar, int] = {}
        copy_map: Dict[SSAVar, SSAVar] = {}

        def resolve(op: Any) -> Any:
            while isinstance(op, SSAVar) and op in copy_map:
                op = copy_map[op]
            return op

        # Pass A: Constant propagation + algebraic simplification
        for block in fn.blocks:
            for phi in list(block.phi_nodes):
                for i, op in enumerate(phi.operands):
                    r = resolve(op)
                    if r != op:
                        phi.operands[i] = r
                        changed = True
                for i, (blk, op) in enumerate(phi.phi_incoming):
                    r = resolve(op)
                    if r != op:
                        phi.phi_incoming[i] = (blk, r)
                        changed = True

                # Check if all Phi inputs have identical constant value
                if phi.result and phi.operands:
                    vals = [const_map.get(op) if isinstance(op, SSAVar) else (op if isinstance(op, int) else None) for op in phi.operands]
                    if vals[0] is not None and all(v == vals[0] for v in vals):
                        const_map[phi.result] = vals[0]  # type: ignore[assignment]

            for inst in block.instructions:
                for i, op in enumerate(inst.operands):
                    r = resolve(op)
                    if r != op:
                        inst.operands[i] = r
                        changed = True

                if inst.opcode == "const" and inst.result and len(inst.operands) == 1 and isinstance(inst.operands[0], int):
                    const_map[inst.result] = inst.operands[0]
                    continue

                if inst.result and len(inst.operands) == 2 and inst.opcode in (
                    "add", "sub", "mul", "sdiv", "srem", "shl", "shr", "and", "or", "xor",
                    "cmp_eq", "cmp_ne", "cmp_lt", "cmp_le", "cmp_gt", "cmp_ge",
                ):
                    o0, o1 = inst.operands[0], inst.operands[1]
                    c0 = const_map.get(o0) if isinstance(o0, SSAVar) else (o0 if isinstance(o0, int) else None)
                    c1 = const_map.get(o1) if isinstance(o1, SSAVar) else (o1 if isinstance(o1, int) else None)

                    if c0 is not None and c1 is not None:
                        folded = _eval_const_binop(inst.opcode, c0, c1)
                        if folded is not None:
                            inst.opcode = "const"
                            inst.operands = [folded]
                            const_map[inst.result] = folded
                            changed = True
                            continue

                    # Algebraic identities & strength reduction
                    if inst.opcode == "add":
                        if c1 == 0 and isinstance(o0, SSAVar):
                            copy_map[inst.result] = o0
                            changed = True
                        elif c0 == 0 and isinstance(o1, SSAVar):
                            copy_map[inst.result] = o1
                            changed = True
                    elif inst.opcode == "sub" and c1 == 0 and isinstance(o0, SSAVar):
                        copy_map[inst.result] = o0
                        changed = True
                    elif inst.opcode == "mul":
                        if c1 == 1 and isinstance(o0, SSAVar):
                            copy_map[inst.result] = o0
                            changed = True
                        elif c0 == 1 and isinstance(o1, SSAVar):
                            copy_map[inst.result] = o1
                            changed = True
                        elif c1 is not None and c1 > 1 and (c1 & (c1 - 1)) == 0:
                            shift = c1.bit_length() - 1
                            shift_var = SSAVar(f"sh_{inst.result.name}_{inst.result.version}", 0)
                            inst.opcode = "shl"
                            inst.operands = [o0, shift]
                            changed = True

        # Apply any final copy_map resolutions
        if copy_map:
            for block in fn.blocks:
                for phi in block.phi_nodes:
                    phi.operands = [resolve(op) for op in phi.operands]
                    phi.phi_incoming = [(blk, resolve(op)) for blk, op in phi.phi_incoming]
                for inst in block.instructions:
                    inst.operands = [resolve(op) for op in inst.operands]

        # Pass B: Dead Code Elimination (DCE)
        used_vars: Set[SSAVar] = set()
        for block in fn.blocks:
            for phi in block.phi_nodes:
                for op in phi.operands:
                    if isinstance(op, SSAVar):
                        used_vars.add(op)
            for inst in block.instructions:
                for op in inst.operands:
                    if isinstance(op, SSAVar):
                        used_vars.add(op)

        for block in fn.blocks:
            new_phis = []
            for phi in block.phi_nodes:
                if phi.result is None or phi.result in used_vars:
                    new_phis.append(phi)
                else:
                    changed = True
            block.phi_nodes = new_phis

            new_insts = []
            for inst in block.instructions:
                if inst.opcode in SIDE_EFFECT_OPCODES or inst.result is None or inst.result in used_vars:
                    new_insts.append(inst)
                else:
                    changed = True
            block.instructions = new_insts

    return fn


def lower_ast_to_ssa(
    node: ast.AST,
    fn_name: str = "func",
    param_names: Optional[List[str]] = None,
    optimize: bool = False,
) -> SSAFunction:
    """Lowers an AST FunctionDef, Module (first FunctionDef), or expression into Omni-SSA."""
    lowering = AstToSsaLowering()
    if isinstance(node, ast.Module):
        for stmt in node.body:
            if isinstance(stmt, ast.FunctionDef):
                fn = lowering.lower_function_def(stmt)
                return optimize_ssa(fn) if optimize else fn
    if isinstance(node, ast.FunctionDef):
        fn = lowering.lower_function_def(node)
        return optimize_ssa(fn) if optimize else fn
    fn = lowering.lower_expression_function(fn_name, param_names or [], node)
    return optimize_ssa(fn) if optimize else fn


def lower_source_to_ssa(source_code: str, fn_name: Optional[str] = None, optimize: bool = True) -> SSAFunction:
    """Parses Python source code and lowers the target function (or expression) into Omni-SSA."""
    tree = ast.parse(source_code)
    lowering = AstToSsaLowering()
    for stmt in tree.body:
        if isinstance(stmt, ast.FunctionDef):
            if fn_name is None or stmt.name == fn_name:
                fn = lowering.lower_function_def(stmt)
                return optimize_ssa(fn) if optimize else fn
    if len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
        fn = lowering.lower_expression_function(fn_name or "expr_fn", [], tree.body[0].value)
        return optimize_ssa(fn) if optimize else fn
    raise ValueError(f"No FunctionDef matching '{fn_name}' found in source.")
