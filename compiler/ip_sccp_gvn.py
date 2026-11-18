"""
OmniCompiler Inter-Procedural SCCP, Global Value Numbering (GVN) & Call-Site Specialization
(compiler/ip_sccp_gvn.py)

Implements:
1. GlobalValueNumberingPass (GVN):
   - Dominator-Tree Scoped Hash Table over SSA IR.
   - Commutative canonicalization (add, mul, and, or, xor, cmp_eq, cmp_ne).
   - Eliminates redundant pure computations across dominated blocks.
2. SCCPPass (Wegman & Zadeck Sparse Conditional Constant Propagation):
   - 3-level lattice (TOP, CONSTANT(val), BOTTOM) with reachable-edge tracking.
   - Folds constant `br_cond` terminators into unconditional `br`.
   - Prunes unreachable CFG blocks and updates Phi incoming edges atomically.
3. InterProceduralSCCPPass & CallSiteSpecializer:
   - Propagates constant arguments across call sites.
   - Clones & specializes target functions (`fn__spec_<sig>`), binds constants,
     folds dead branches, and rewrites call sites.
   - Propagates pure constant-return functions across callers.
"""

from typing import Dict, List, Set, Tuple, Any, Optional
import copy

from compiler.ssa_ir import (
    SSAFunction,
    BasicBlock,
    SSAInstruction,
    SSAVar,
    SIDE_EFFECT_OPCODES,
    optimize_ssa,
    _eval_const_binop,
)


GVN_PURE_OPCODES = frozenset({
    "add", "sub", "mul", "sdiv", "srem",
    "shl", "shr", "sar", "and", "or", "xor",
    "neg", "not",
    "cmp_eq", "cmp_ne", "cmp_lt", "cmp_le", "cmp_gt", "cmp_ge",
    "fconst", "fneg", "fadd", "fsub", "fmul", "fdiv",
    "fcmp_eq", "fcmp_ne", "fcmp_lt", "fcmp_le", "fcmp_gt", "fcmp_ge",
    "sitofp", "fptosi",
})

COMMUTATIVE_OPCODES = frozenset({
    "add", "mul", "and", "or", "xor", "cmp_eq", "cmp_ne",
    "fadd", "fmul", "fcmp_eq", "fcmp_ne",
})


def clone_ssa_function(fn: SSAFunction, new_name: Optional[str] = None) -> SSAFunction:
    """Deep-clones an SSAFunction with fresh BasicBlocks, instructions, and CFG edges."""
    cloned = SSAFunction(
        name=new_name or fn.name,
        params=list(fn.params),
        param_types=dict(fn.param_types),
        return_type=getattr(fn, "return_type", "i64"),
    )
    cloned.source_file = fn.source_file
    cloned.luts = dict(getattr(fn, "luts", {}) or {})
    cloned.cstrs = dict(getattr(fn, "cstrs", {}) or {})

    block_map: Dict[str, BasicBlock] = {}
    for b in fn.blocks:
        nb = BasicBlock(b.name)
        nb.loop_depth = b.loop_depth
        for phi in b.phi_nodes:
            nb.phi_nodes.append(
                SSAInstruction(
                    result=SSAVar(phi.result.name, phi.result.version, phi.result.var_type) if phi.result else None,
                    opcode=phi.opcode,
                    operands=[
                        SSAVar(o.name, o.version, o.var_type) if isinstance(o, SSAVar) else o
                        for o in phi.operands
                    ],
                    phi_incoming=[
                        (blk, SSAVar(v.name, v.version, v.var_type) if isinstance(v, SSAVar) else v)
                        for blk, v in phi.phi_incoming
                    ],
                    source_line=phi.source_line,
                )
            )
        for inst in b.instructions:
            nb.instructions.append(
                SSAInstruction(
                    result=SSAVar(inst.result.name, inst.result.version, inst.result.var_type) if inst.result else None,
                    opcode=inst.opcode,
                    operands=[
                        SSAVar(o.name, o.version, o.var_type) if isinstance(o, SSAVar) else o
                        for o in inst.operands
                    ],
                    phi_incoming=list(inst.phi_incoming),
                    source_line=inst.source_line,
                )
            )
        block_map[nb.name] = nb
        cloned.add_block(nb)

    if fn.entry_block and fn.entry_block.name in block_map:
        cloned.entry_block = block_map[fn.entry_block.name]

    for b in fn.blocks:
        nb = block_map[b.name]
        nb.predecessors = [block_map[p.name] for p in b.predecessors if p.name in block_map]
        nb.successors = [block_map[s.name] for s in b.successors if s.name in block_map]

    return cloned


class GlobalValueNumberingPass:
    """
    Dominator-Tree Scoped Global Value Numbering (GVN) over Omni-SSA IR.
    Eliminates redundant pure expressions within and across dominated basic blocks.
    """

    def run_on_function(self, fn: SSAFunction) -> Tuple[SSAFunction, Dict[str, Any]]:
        if not fn.blocks:
            return fn, {"gvn_eliminated_exprs": 0}

        entry = fn.entry_block or fn.blocks[0]
        idom = fn.compute_dominators()
        dom_children: Dict[str, List[str]] = {b.name: [] for b in fn.blocks}
        for b in fn.blocks:
            parent = idom.get(b.name)
            if parent is not None and parent != b.name and parent in dom_children:
                dom_children[parent].append(b.name)

        block_by_name = {b.name: b for b in fn.blocks}
        scopes: List[Dict[Tuple[Any, ...], SSAVar]] = []
        var_rep: Dict[SSAVar, SSAVar] = {}
        eliminated = 0

        def resolve(op: Any) -> Any:
            while isinstance(op, SSAVar) and op in var_rep:
                op = var_rep[op]
            return op

        def canon_operand(op: Any) -> Tuple[str, Any]:
            r = resolve(op)
            if isinstance(r, SSAVar):
                return ("var", r.name, r.version)
            if isinstance(r, bool):
                return ("int", int(r))
            if isinstance(r, int):
                return ("int", r)
            return ("other", str(r))

        def lookup_expr(key: Tuple[Any, ...]) -> Optional[SSAVar]:
            for scope in reversed(scopes):
                if key in scope:
                    return scope[key]
            return None

        def visit_block(bname: str):
            nonlocal eliminated
            block = block_by_name.get(bname)
            if block is None:
                return

            scopes.append({})

            for phi in block.phi_nodes:
                phi.operands = [resolve(o) for o in phi.operands]
                phi.phi_incoming = [(blk, resolve(v)) for blk, v in phi.phi_incoming]

            kept_insts: List[SSAInstruction] = []
            for inst in block.instructions:
                inst.operands = [resolve(o) for o in inst.operands]

                if inst.opcode in GVN_PURE_OPCODES and inst.result is not None:
                    c_ops = [canon_operand(o) for o in inst.operands]
                    if inst.opcode in COMMUTATIVE_OPCODES and len(c_ops) == 2:
                        c_ops = sorted(c_ops)
                    expr_key = (inst.opcode, tuple(c_ops))

                    existing = lookup_expr(expr_key)
                    if existing is not None:
                        var_rep[inst.result] = existing
                        eliminated += 1
                        continue
                    else:
                        scopes[-1][expr_key] = inst.result

                kept_insts.append(inst)

            block.instructions = kept_insts

            for child_name in dom_children.get(bname, []):
                visit_block(child_name)

            scopes.pop()

        visit_block(entry.name)

        # Resolve any back-edge / non-dominator-order phi references
        if var_rep:
            for block in fn.blocks:
                for phi in block.phi_nodes:
                    phi.operands = [resolve(o) for o in phi.operands]
                    phi.phi_incoming = [(blk, resolve(v)) for blk, v in phi.phi_incoming]
                for inst in block.instructions:
                    inst.operands = [resolve(o) for o in inst.operands]

        return fn, {"gvn_eliminated_exprs": eliminated}


class _LatticeSentinel:
    def __init__(self, name: str):
        self.name = name

    def __repr__(self) -> str:
        return self.name


_TOP = _LatticeSentinel("TOP")
_BOTTOM = _LatticeSentinel("BOTTOM")


class SCCPPass:
    """
    Sparse Conditional Constant Propagation (Wegman & Zadeck 1991).
    Propagates constants through SSA & Phi nodes while folding constant `br_cond`
    branches and pruning unreachable blocks.
    """

    def run_on_function(self, fn: SSAFunction) -> Tuple[SSAFunction, Dict[str, Any]]:
        if not fn.blocks:
            return fn, {"sccp_folded_constants": 0, "sccp_folded_branches": 0, "sccp_pruned_blocks": 0}

        entry = fn.entry_block or fn.blocks[0]
        block_by_name = {b.name: b for b in fn.blocks}

        lattice: Dict[SSAVar, Any] = {}
        executable_blocks: Set[str] = {entry.name}
        executable_edges: Set[Tuple[str, str]] = set()
        cfg_worklist: List[str] = [entry.name]
        ssa_worklist: List[SSAVar] = []

        # Build def -> uses index for fast SSA worklist propagation
        uses_of: Dict[SSAVar, List[Tuple[str, SSAInstruction]]] = {}
        for b in fn.blocks:
            for phi in b.phi_nodes:
                for _, v in phi.phi_incoming:
                    if isinstance(v, SSAVar):
                        uses_of.setdefault(v, []).append((b.name, phi))
            for inst in b.instructions:
                for o in inst.operands:
                    if isinstance(o, SSAVar):
                        uses_of.setdefault(o, []).append((b.name, inst))

        def get_val(op: Any) -> Any:
            if isinstance(op, bool):
                return int(op)
            if isinstance(op, int):
                return op
            if isinstance(op, SSAVar):
                return lattice.get(op, _TOP)
            return _BOTTOM

        def meet(a: Any, b: Any) -> Any:
            if a is _TOP:
                return b
            if b is _TOP:
                return a
            if a is _BOTTOM or b is _BOTTOM:
                return _BOTTOM
            if a == b:
                return a
            return _BOTTOM

        def update_lattice(var: Optional[SSAVar], new_val: Any):
            if var is None:
                return
            old_val = lattice.get(var, _TOP)
            if new_val != old_val:
                lattice[var] = new_val
                ssa_worklist.append(var)

        def eval_phi(bname: str, phi: SSAInstruction):
            acc = _TOP
            for pred_name, val in phi.phi_incoming:
                if (pred_name, bname) in executable_edges:
                    acc = meet(acc, get_val(val))
            update_lattice(phi.result, acc)

        def eval_inst(bname: str, inst: SSAInstruction):
            op = inst.opcode
            if op == "const" and inst.operands:
                v = inst.operands[0]
                update_lattice(inst.result, int(v) if isinstance(v, (int, bool)) else _BOTTOM)
            elif op == "mov" and inst.operands:
                update_lattice(inst.result, get_val(inst.operands[0]))
            elif op == "param":
                update_lattice(inst.result, _BOTTOM)
            elif op in ("neg", "not") and len(inst.operands) == 1:
                v = get_val(inst.operands[0])
                if isinstance(v, int):
                    update_lattice(inst.result, -v if op == "neg" else (1 if v == 0 else 0))
                elif v is _BOTTOM:
                    update_lattice(inst.result, _BOTTOM)
            elif op in (
                "add", "sub", "mul", "sdiv", "srem",
                "shl", "shr", "sar", "and", "or", "xor",
                "cmp_eq", "cmp_ne", "cmp_lt", "cmp_le", "cmp_gt", "cmp_ge",
            ) and len(inst.operands) == 2:
                v0 = get_val(inst.operands[0])
                v1 = get_val(inst.operands[1])
                if isinstance(v0, int) and isinstance(v1, int):
                    folded = _eval_const_binop(op, v0, v1)
                    update_lattice(inst.result, folded if folded is not None else _BOTTOM)
                elif v0 is _BOTTOM or v1 is _BOTTOM:
                    # Handle annihilators like x * 0 == 0
                    if op == "mul" and (v0 == 0 or v1 == 0):
                        update_lattice(inst.result, 0)
                    elif op == "and" and (v0 == 0 or v1 == 0):
                        update_lattice(inst.result, 0)
                    else:
                        update_lattice(inst.result, _BOTTOM)
            elif op == "br" and inst.operands:
                target = str(inst.operands[0])
                if (bname, target) not in executable_edges:
                    executable_edges.add((bname, target))
                    if target not in executable_blocks:
                        executable_blocks.add(target)
                        cfg_worklist.append(target)
                    else:
                        # Re-evaluate phis in target because new edge became executable
                        tb = block_by_name.get(target)
                        if tb:
                            for p in tb.phi_nodes:
                                eval_phi(target, p)
            elif op == "br_cond" and len(inst.operands) >= 3:
                cond_v = get_val(inst.operands[0])
                t_blk = str(inst.operands[1])
                f_blk = str(inst.operands[2])
                targets = []
                if isinstance(cond_v, int):
                    targets.append(t_blk if cond_v != 0 else f_blk)
                elif cond_v is _BOTTOM:
                    targets.extend([t_blk, f_blk])
                for target in targets:
                    if (bname, target) not in executable_edges:
                        executable_edges.add((bname, target))
                        if target not in executable_blocks:
                            executable_blocks.add(target)
                            cfg_worklist.append(target)
                        else:
                            tb = block_by_name.get(target)
                            if tb:
                                for p in tb.phi_nodes:
                                    eval_phi(target, p)
            elif inst.result is not None:
                update_lattice(inst.result, _BOTTOM)

        # Fixpoint iteration
        while cfg_worklist or ssa_worklist:
            while cfg_worklist:
                bname = cfg_worklist.pop(0)
                blk = block_by_name.get(bname)
                if blk is None:
                    continue
                for phi in blk.phi_nodes:
                    eval_phi(bname, phi)
                for inst in blk.instructions:
                    eval_inst(bname, inst)

            while ssa_worklist:
                var = ssa_worklist.pop(0)
                for user_blk, user_inst in uses_of.get(var, []):
                    if user_blk in executable_blocks:
                        if user_inst.opcode == "phi":
                            eval_phi(user_blk, user_inst)
                        else:
                            eval_inst(user_blk, user_inst)

        # Rewrite constants & fold branches
        folded_constants = 0
        folded_branches = 0

        for b in fn.blocks:
            if b.name not in executable_blocks:
                continue

            # Replace constant Phis
            remaining_phis: List[SSAInstruction] = []
            prepended_consts: List[SSAInstruction] = []
            for phi in b.phi_nodes:
                if phi.result and isinstance(lattice.get(phi.result), int):
                    cval = lattice[phi.result]
                    prepended_consts.append(SSAInstruction(phi.result, "const", [cval], source_line=phi.source_line))
                    folded_constants += 1
                else:
                    # Prune unreachable incoming edges from phi
                    phi.phi_incoming = [
                        (pred, val) for pred, val in phi.phi_incoming
                        if (pred, b.name) in executable_edges
                    ]
                    phi.operands = [val for _, val in phi.phi_incoming]
                    remaining_phis.append(phi)
            b.phi_nodes = remaining_phis
            if prepended_consts:
                b.instructions = prepended_consts + b.instructions

            # Rewrite constant instructions & fold br_cond
            for inst in b.instructions:
                if inst.opcode == "br_cond" and len(inst.operands) >= 3:
                    cond_v = get_val(inst.operands[0])
                    if isinstance(cond_v, int):
                        taken = str(inst.operands[1]) if cond_v != 0 else str(inst.operands[2])
                        inst.opcode = "br"
                        inst.operands = [taken]
                        folded_branches += 1
                elif inst.result is not None and inst.opcode != "const" and inst.opcode not in SIDE_EFFECT_OPCODES:
                    val = lattice.get(inst.result)
                    if isinstance(val, int):
                        inst.opcode = "const"
                        inst.operands = [val]
                        folded_constants += 1

        # Prune unreachable blocks and update CFG edges
        original_block_count = len(fn.blocks)
        fn.blocks = [b for b in fn.blocks if b.name in executable_blocks]
        pruned_blocks = original_block_count - len(fn.blocks)

        surviving_map = {b.name: b for b in fn.blocks}
        for b in fn.blocks:
            b.successors = [
                s for s in b.successors
                if s.name in surviving_map and (b.name, s.name) in executable_edges
            ]
            b.predecessors = [
                p for p in b.predecessors
                if p.name in surviving_map and (p.name, b.name) in executable_edges
            ]

        fn = optimize_ssa(fn)
        return fn, {
            "sccp_folded_constants": folded_constants,
            "sccp_folded_branches": folded_branches,
            "sccp_pruned_blocks": pruned_blocks,
        }


class InterProceduralSCCPPass:
    """
    Inter-Procedural SCCP & Call-Site Function Specializer.
    Propagates constant arguments across call sites, creates specialized function
    clones (`fn__spec_<args>`), and propagates constant return values from pure functions.
    """

    def __init__(self, max_specializations: int = 16):
        self.max_specializations = max_specializations

    def _collect_const_map(self, fn: SSAFunction) -> Dict[SSAVar, int]:
        consts: Dict[SSAVar, int] = {}
        for b in fn.blocks:
            for inst in b.instructions:
                if inst.opcode == "const" and inst.result is not None and inst.operands:
                    val = inst.operands[0]
                    if isinstance(val, (int, bool)):
                        consts[inst.result] = int(val)
        return consts

    def _is_pure_constant_return(self, fn: SSAFunction) -> Optional[int]:
        """If `fn` has no side effects and all `ret` instructions return the same int constant, return it."""
        const_map = self._collect_const_map(fn)
        ret_vals: List[int] = []
        for b in fn.blocks:
            for inst in b.instructions:
                if inst.opcode in ("store", "call"):
                    return None
                if inst.opcode == "ret":
                    if not inst.operands:
                        return None
                    op = inst.operands[0]
                    if isinstance(op, int):
                        ret_vals.append(op)
                    elif isinstance(op, SSAVar) and op in const_map:
                        ret_vals.append(const_map[op])
                    else:
                        return None
        if ret_vals and all(v == ret_vals[0] for v in ret_vals):
            return ret_vals[0]
        return None

    def optimize_program(
        self,
        functions: Dict[str, SSAFunction],
    ) -> Tuple[Dict[str, SSAFunction], Dict[str, Any]]:
        """
        Runs intra-procedural SCCP + GVN, call-site specialization, and pure constant
        return propagation across `functions`.
        """
        sccp = SCCPPass()
        gvn = GlobalValueNumberingPass()

        total_gvn = 0
        total_branches = 0
        total_consts = 0
        specialized_count = 0
        ip_const_returns = 0

        # Step 1: Initial SCCP + GVN on all functions
        for fname in list(functions.keys()):
            fn, s_stats = sccp.run_on_function(functions[fname])
            fn, g_stats = gvn.run_on_function(fn)
            functions[fname] = fn
            total_branches += s_stats["sccp_folded_branches"]
            total_consts += s_stats["sccp_folded_constants"]
            total_gvn += g_stats["gvn_eliminated_exprs"]

        # Step 2: Call-Site Function Specialization
        # Inspect call sites for constant arguments
        existing_specs: Dict[Tuple[str, Tuple[Optional[int], ...]], str] = {}

        for caller_name in list(functions.keys()):
            caller_fn = functions[caller_name]
            const_map = self._collect_const_map(caller_fn)

            for b in caller_fn.blocks:
                for inst in b.instructions:
                    if inst.opcode != "call" or not inst.operands:
                        continue
                    callee_name = str(inst.operands[0])
                    if callee_name not in functions:
                        continue
                    if callee_name == caller_name:
                        continue  # avoid recursive self-specialization blowup

                    callee_fn = functions[callee_name]
                    call_args = inst.operands[1:]
                    if len(call_args) != len(callee_fn.params):
                        continue

                    # Resolve constant arguments
                    arg_consts: List[Optional[int]] = []
                    for a in call_args:
                        if isinstance(a, (int, bool)):
                            arg_consts.append(int(a))
                        elif isinstance(a, SSAVar) and a in const_map:
                            arg_consts.append(const_map[a])
                        else:
                            arg_consts.append(None)

                    if not any(c is not None for c in arg_consts):
                        continue

                    spec_key = (callee_name, tuple(arg_consts))
                    if spec_key in existing_specs:
                        spec_name = existing_specs[spec_key]
                    else:
                        if specialized_count >= self.max_specializations:
                            continue
                        sig_parts = [
                            f"a{idx}_{val}" for idx, val in enumerate(arg_consts) if val is not None
                        ]
                        spec_name = f"{callee_name}__spec_{'_'.join(sig_parts)}"
                        spec_fn = clone_ssa_function(callee_fn, new_name=spec_name)

                        # Bind constant parameters inside spec_fn and compact remaining param indices
                        new_params: List[str] = []
                        new_param_types: Dict[str, str] = {}
                        old_to_new_idx: Dict[int, int] = {}
                        for idx, pname in enumerate(callee_fn.params):
                            if arg_consts[idx] is None:
                                old_to_new_idx[idx] = len(new_params)
                                new_params.append(pname)
                                new_param_types[pname] = callee_fn.param_types.get(pname, "i64")
                        spec_fn.params = new_params
                        spec_fn.param_types = new_param_types

                        for sb in spec_fn.blocks:
                            for sinst in sb.instructions:
                                if sinst.opcode == "param" and sinst.operands:
                                    raw_param = sinst.operands[0]
                                    if isinstance(raw_param, int):
                                        p_idx = raw_param
                                    elif isinstance(raw_param, str) and raw_param in callee_fn.params:
                                        p_idx = callee_fn.params.index(raw_param)
                                    else:
                                        continue
                                    if p_idx < len(arg_consts) and arg_consts[p_idx] is not None:
                                        sinst.opcode = "const"
                                        sinst.operands = [arg_consts[p_idx]]
                                    elif isinstance(raw_param, int) and p_idx in old_to_new_idx:
                                        sinst.operands = [old_to_new_idx[p_idx]]

                        # Optimize specialized clone with SCCP + GVN
                        spec_fn, s_stats = sccp.run_on_function(spec_fn)
                        spec_fn, g_stats = gvn.run_on_function(spec_fn)
                        total_branches += s_stats["sccp_folded_branches"]
                        total_consts += s_stats["sccp_folded_constants"]
                        total_gvn += g_stats["gvn_eliminated_exprs"]

                        functions[spec_name] = spec_fn
                        existing_specs[spec_key] = spec_name
                        specialized_count += 1

                    # Rewrite call instruction to invoke specialized target with non-constant args
                    non_const_args = [
                        a for a, c in zip(call_args, arg_consts) if c is None
                    ]
                    inst.operands = [spec_name] + non_const_args

        # Step 3: Inter-Procedural Constant Return Propagation
        pure_const_returns: Dict[str, int] = {}
        for fname, fn in functions.items():
            cret = self._is_pure_constant_return(fn)
            if cret is not None:
                pure_const_returns[fname] = cret

        if pure_const_returns:
            for fname, fn in functions.items():
                changed = False
                for b in fn.blocks:
                    for inst in b.instructions:
                        if inst.opcode == "call" and inst.operands:
                            callee_name = str(inst.operands[0])
                            if callee_name in pure_const_returns and inst.result is not None:
                                inst.opcode = "const"
                                inst.operands = [pure_const_returns[callee_name]]
                                ip_const_returns += 1
                                changed = True
                if changed:
                    fn, s_stats = sccp.run_on_function(fn)
                    fn, g_stats = gvn.run_on_function(fn)
                    functions[fname] = fn
                    total_branches += s_stats["sccp_folded_branches"]
                    total_consts += s_stats["sccp_folded_constants"]
                    total_gvn += g_stats["gvn_eliminated_exprs"]

        return functions, {
            "gvn_eliminated_exprs": total_gvn,
            "sccp_folded_branches": total_branches,
            "sccp_folded_constants": total_consts,
            "specialized_functions": specialized_count,
            "ip_constant_returns_propagated": ip_const_returns,
        }
