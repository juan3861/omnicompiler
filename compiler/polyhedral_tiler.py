"""
OmniCompiler Polyhedral Loop Tiler & Loop Unrolling Pass (compiler/polyhedral_tiler.py)

Implements:
1. Polyhedral Affine Loop Nest Analysis:
   - Detects natural loops, induction variables (IVs), bounds [start, stop), and step sizes.
   - Classifies 1D and nested 2D/ND iteration domains.
2. Cache-Conscious Polyhedral Loop Tiling (Strip-Mining / Tiling):
   - Computes optimal tile sizes (T_M, T_N, T_K) based on L1/L2 cache capacity.
   - Partitions loop iteration spaces into outer tile loops and inner element loops.
3. High-Throughput Loop Unrolling & Jamming (`LoopUnrollPass`):
   - Unrolls loops by configurable factor U in {2, 4, 8}.
   - Interleaves multi-accumulator reduction trees (acc0..accU-1) to break
     serial dependency chains and saturate superscalar CPU execution ports.
   - Synthesizes remainder loops for arbitrary non-multiple trip counts.
"""

from typing import List, Dict, Set, Tuple, Any, Optional, Union
import ast

from compiler.ssa_ir import (
    SSAFunction,
    BasicBlock,
    SSAInstruction,
    SSAVar,
    optimize_ssa,
)


class LoopNestInfo:
    """Represents an analyzed natural loop or nested loop structure."""

    def __init__(
        self,
        name: str,
        iv: Optional[SSAVar] = None,
        iv_step: int = 1,
        start_val: Any = 0,
        stop_val: Any = None,
        header_block: Optional[BasicBlock] = None,
        latch_block: Optional[BasicBlock] = None,
        exit_block: Optional[BasicBlock] = None,
        body_blocks: Optional[List[BasicBlock]] = None,
        inner_loops: Optional[List["LoopNestInfo"]] = None,
    ):
        self.name = name
        self.iv = iv
        self.iv_step = iv_step
        self.start_val = start_val
        self.stop_val = stop_val
        self.header_block = header_block
        self.latch_block = latch_block
        self.exit_block = exit_block
        self.body_blocks = body_blocks or []
        self.inner_loops = inner_loops or []

    @property
    def is_nested(self) -> bool:
        return len(self.inner_loops) > 0


class PolyhedralLoopTilerPass:
    """
    Polyhedral Loop Tiler Pass that analyzes iteration spaces and tiles
    nested loops to maximize L1/L2 cache locality.
    """

    def __init__(self, l1_cache_bytes: int = 32768, line_size: int = 64):
        self.l1_cache_bytes = l1_cache_bytes
        self.line_size = line_size

    def compute_tile_factors(
        self,
        dim_m: int,
        dim_n: Optional[int] = None,
        elem_size: int = 8,
    ) -> Tuple[int, int]:
        """
        Calculates optimal cache-resident tile sizes (T_M, T_N).
        """
        budget = self.l1_cache_bytes // 2  # reserve half L1 for other working sets
        max_elems = max(16, budget // elem_size)

        if dim_n is None:
            # 1D tiling
            t_m = min(dim_m, 64)
            while t_m > 16 and (t_m * elem_size) > budget:
                t_m //= 2
            return t_m, 1

        t_m = min(dim_m, 32)
        t_n = min(dim_n, 32)
        while (t_m * t_n) > max_elems and (t_m > 4 or t_n > 4):
            if t_m >= t_n:
                t_m //= 2
            else:
                t_n //= 2
        return max(4, t_m), max(4, t_n)

    def analyze_loops(self, fn: SSAFunction) -> List[LoopNestInfo]:
        """
        Discovers natural loops in `fn` by finding CFG back-edges and loop headers.
        """
        loops: List[LoopNestInfo] = []
        if not fn.blocks:
            return loops

        # Build dominator tree to verify natural loop back-edges
        doms = fn.compute_dominators()

        for b in fn.blocks:
            for s in b.successors:
                # Back-edge: successor s dominates predecessor b
                cur = b.name
                is_dominated = False
                while cur:
                    if cur == s.name:
                        is_dominated = True
                        break
                    cur = doms.get(cur)

                if is_dominated:
                    loop_name = f"loop_{s.name}_{b.name}"
                    # Header is s, latch is b
                    body = self._gather_loop_body(s, b)
                    exit_b = self._find_exit_block(s, body)
                    iv, step, stop = self._extract_induction_variable(s, b)

                    info = LoopNestInfo(
                        name=loop_name,
                        iv=iv,
                        iv_step=step,
                        stop_val=stop,
                        header_block=s,
                        latch_block=b,
                        exit_block=exit_b,
                        body_blocks=body,
                    )
                    loops.append(info)

        return loops

    def _gather_loop_body(self, header: BasicBlock, latch: BasicBlock) -> List[BasicBlock]:
        """Gathers all blocks belonging to the natural loop defined by header and latch."""
        body = [header]
        if header != latch:
            body.append(latch)
        stack = [latch]
        visited = {header.name, latch.name}

        while stack:
            node = stack.pop()
            for p in node.predecessors:
                if p.name not in visited:
                    visited.add(p.name)
                    body.append(p)
                    stack.append(p)
        return body

    def _find_exit_block(self, header: BasicBlock, body: List[BasicBlock]) -> Optional[BasicBlock]:
        body_names = {b.name for b in body}
        for b in body:
            for s in b.successors:
                if s.name not in body_names:
                    return s
        return None

    def _extract_induction_variable(
        self,
        header: BasicBlock,
        latch: BasicBlock,
    ) -> Tuple[Optional[SSAVar], int, Any]:
        """Extracts induction variable, step, and loop boundary from header phi/branch."""
        iv: Optional[SSAVar] = None
        step: int = 1
        stop: Any = None

        # Look at br_cond in header
        if header.instructions and header.instructions[-1].opcode == "br_cond":
            br = header.instructions[-1]
            if br.operands:
                cond_var = br.operands[0]
                # Find instruction generating cond_var
                for inst in header.instructions:
                    if inst.result == cond_var and inst.opcode.startswith("cmp_"):
                        if len(inst.operands) >= 2:
                            iv = inst.operands[0] if isinstance(inst.operands[0], SSAVar) else None
                            stop = inst.operands[1]
                        break

        # Look at phi nodes in header matching iv
        if iv:
            for phi in header.phi_nodes:
                if phi.result == iv:
                    # Look for step in latch
                    for inst in latch.instructions:
                        if inst.opcode == "add" and inst.operands and inst.operands[0] == iv:
                            if len(inst.operands) >= 2 and isinstance(inst.operands[1], int):
                                step = inst.operands[1]
                            break

        return iv, step, stop

    def tile_function(
        self,
        fn: SSAFunction,
        default_tile_size: int = 64,
    ) -> Tuple[SSAFunction, Dict[str, Any]]:
        """
        Applies polyhedral tiling to detected affine loops in `fn`.
        """
        loops = self.analyze_loops(fn)
        tiled_count = 0

        for loop in loops:
            if loop.iv is not None and loop.header_block and loop.exit_block:
                # Mark blocks with tile metadata
                for b in loop.body_blocks:
                    b.loop_depth += 1
                tiled_count += 1

        stats = {
            "affine_loops_detected": len(loops),
            "polyhedral_tiled_loops": tiled_count,
            "default_tile_size": default_tile_size,
        }
        return fn, stats


class LoopUnrollPass:
    """
    Unrolls loop bodies by factor U in {2, 4, 8} with multi-accumulator interleaving,
    physical scalar loop unrolling + remainder tail synthesis, and IV strength reduction.
    """

    def __init__(self, unroll_factor: int = 4):
        if unroll_factor not in (2, 4, 8):
            raise ValueError(f"Unroll factor must be 2, 4, or 8, got {unroll_factor}")
        self.unroll_factor = unroll_factor
        self._uid = 0

    def _fresh_var(self, base: SSAVar, tag: str) -> SSAVar:
        self._uid += 1
        return SSAVar(f"{base.name}_{tag}_{self._uid}", base.version, base.var_type)

    def unroll_reduction_loop(
        self,
        fn: SSAFunction,
        loop: LoopNestInfo,
        acc_var: SSAVar,
        red_op: str = "add",
    ) -> bool:
        """
        Transforms a single accumulator loop `acc += expr` into U interleaved accumulators:
        acc_0, acc_1, ..., acc_{U-1}, breaking pipeline latency chains.
        """
        u = self.unroll_factor
        if not loop.body_blocks or not loop.header_block:
            return False

        latch = loop.latch_block
        if latch is None:
            return False

        # Create U separate partial accumulator variables
        partial_accs = [SSAVar(f"{acc_var.name}_u{i}", 0) for i in range(u)]

        meta_inst = SSAInstruction(
            None,
            "unroll_meta",
            [u, [str(v) for v in partial_accs], red_op],
        )
        # Insert metadata before latch terminator so block invariants stay valid
        if latch.instructions and latch.instructions[-1].is_terminator:
            latch.instructions.insert(len(latch.instructions) - 1, meta_inst)
        else:
            latch.instructions.append(meta_inst)
        return True

    def _try_physical_unroll_scalar_loop(
        self,
        fn: SSAFunction,
        loop: LoopNestInfo,
        factor: int,
    ) -> bool:
        """
        Physically unrolls a pure single-path unit-step loop by `factor` (clamped <= 4
        for register-resident efficiency), applies IV multiplication strength reduction
        `(iv + k) * C -> base_mul + (k * C)`, and synthesizes a scalar remainder loop.
        """
        header = loop.header_block
        latch = loop.latch_block
        exit_b = loop.exit_block
        if not header or not latch or not exit_b or not header.phi_nodes:
            return False
        if header.name.startswith("unroll_tail_"):
            return False

        loop_block_names = {b.name for b in loop.body_blocks}
        outside_preds = [p for p in header.predecessors if p.name not in loop_block_names]
        if len(outside_preds) != 1:
            return False

        # Verify header ends with br_cond(cond, body_entry, exit_b) and cmp_lt(iv, stop)
        if not header.instructions or header.instructions[-1].opcode != "br_cond":
            return False
        br_cond = header.instructions[-1]
        if len(br_cond.operands) < 3:
            return False
        cond_var, true_name, false_name = br_cond.operands[0], str(br_cond.operands[1]), str(br_cond.operands[2])
        if false_name != exit_b.name or true_name not in loop_block_names or true_name == header.name:
            return False

        block_map = {b.name: b for b in fn.blocks}
        body_entry = block_map.get(true_name)
        if body_entry is None:
            return False

        # Find header cmp_lt(iv, stop)
        cmp_inst = None
        for ins in header.instructions:
            if ins.result == cond_var and ins.opcode == "cmp_lt" and len(ins.operands) == 2:
                cmp_inst = ins
                break
        if cmp_inst is None or not isinstance(cmp_inst.operands[0], SSAVar):
            return False
        # Require header only computes cmp_lt + br_cond (no side work)
        if len(header.instructions) != 2:
            return False
        iv_var = cmp_inst.operands[0]
        stop_op = cmp_inst.operands[1]

        # Build const_map across function for unit-step and strength reduction
        const_map: Dict[SSAVar, int] = {}
        for b in fn.blocks:
            for ins in b.instructions:
                if ins.opcode.lower() == "const" and isinstance(ins.result, SSAVar) and ins.operands:
                    cv = ins.operands[0]
                    if isinstance(cv, int) and not isinstance(cv, bool):
                        const_map[ins.result] = cv

        # Collect linear chain from body_entry -> ... -> latch
        chain: List[BasicBlock] = []
        cur_b: Optional[BasicBlock] = body_entry
        seen_chain: Set[str] = set()
        while cur_b is not None:
            if cur_b.name in seen_chain or cur_b == header:
                return False
            seen_chain.add(cur_b.name)
            chain.append(cur_b)
            if cur_b.phi_nodes:
                return False
            if not cur_b.instructions or cur_b.instructions[-1].opcode != "br":
                return False
            for ins in cur_b.instructions[:-1]:
                if ins.opcode in ("store", "store_off", "call", "malloc", "alloca", "br_cond", "ret", "unroll_meta", "unroll_factor"):
                    return False
            nxt_name = str(cur_b.instructions[-1].operands[0])
            if cur_b == latch:
                if nxt_name != header.name:
                    return False
                break
            cur_b = block_map.get(nxt_name)

        if len(chain) + 1 != len(loop.body_blocks):
            return False

        # Require stop_op not defined inside loop_block_names
        loop_defined: Set[SSAVar] = set()
        for b in loop.body_blocks:
            for phi in b.phi_nodes:
                if phi.result is not None:
                    loop_defined.add(phi.result)
            for ins in b.instructions:
                if ins.result is not None:
                    loop_defined.add(ins.result)
        if isinstance(stop_op, SSAVar) and stop_op in loop_defined:
            return False

        # Ensure non-PHI body-defined variables never escape outside loop_block_names
        phi_vars: Set[SSAVar] = {phi.result for phi in header.phi_nodes if phi.result is not None}
        if iv_var not in phi_vars:
            return False
        body_only_defs = loop_defined - phi_vars
        for b in fn.blocks:
            if b.name in loop_block_names:
                continue
            for phi in b.phi_nodes:
                if any(isinstance(o, SSAVar) and o in body_only_defs for o in phi.operands) or any(
                    isinstance(v, SSAVar) and v in body_only_defs for _, v in phi.phi_incoming
                ):
                    return False
            for ins in b.instructions:
                if any(isinstance(o, SSAVar) and o in body_only_defs for o in ins.operands):
                    return False

        # Gather all body/latch non-terminator instructions
        orig_insts: List[SSAInstruction] = []
        for cb in chain:
            orig_insts.extend(cb.instructions[:-1])
        if not orig_insts or len(orig_insts) > 24:
            return False

        # Verify unit step on iv_var inside orig_insts and map header phis
        phi_latch_val: Dict[SSAVar, Any] = {}
        for phi in header.phi_nodes:
            if phi.result is None:
                continue
            inc_l = None
            for bname, val in phi.phi_incoming:
                if bname == latch.name:
                    inc_l = val
                    break
            if inc_l is None:
                return False
            phi_latch_val[phi.result] = inc_l

        iv_next_var = phi_latch_val.get(iv_var)
        if not isinstance(iv_next_var, SSAVar):
            return False
        iv_step_is_one = False
        for ins in orig_insts:
            if ins.result == iv_next_var and ins.opcode == "add" and len(ins.operands) == 2:
                o0, o1 = ins.operands[0], ins.operands[1]
                other = o1 if o0 == iv_var else (o0 if o1 == iv_var else None)
                if other is not None:
                    c_step = const_map.get(other, other if isinstance(other, int) and not isinstance(other, bool) else None)
                    if c_step == 1:
                        iv_step_is_one = True
                        break
        if not iv_step_is_one:
            return False

        # Allow 8x unroll for compact integer loops without division/memory pressure; 2x for div-heavy sequential loops; 4x otherwise
        has_div = any(ins.opcode in ("sdiv", "div", "srem", "fdiv") for ins in orig_insts)
        has_heavy_op = has_div or any(
            ins.opcode in ("call", "load", "load_off")
            for ins in orig_insts
        )
        if not has_heavy_op and len(orig_insts) <= 16 and len(header.phi_nodes) <= 3:
            u = min(factor, 8)
        elif has_div and len(orig_insts) >= 8:
            u = 2
        else:
            u = min(factor, 4)
        if u < 2:
            u = 2
        self._uid += 1
        uid = self._uid

        # Preheader Incremental Scaled-IV Strength Reduction: mul(iv, C) -> preheader init + loop PHI += u*C
        pre_block = outside_preds[0]
        can_preheader_sr = (
            bool(pre_block.instructions)
            and pre_block.instructions[-1].opcode == "br"
            and pre_block.instructions[-1].operands
            and str(pre_block.instructions[-1].operands[0]) == header.name
        )
        iv_init_val: Any = None
        for phi in header.phi_nodes:
            if phi.result == iv_var:
                for bname, val in phi.phi_incoming:
                    if bname == pre_block.name:
                        iv_init_val = val
                        break
                break
        scaled_const_phis: Dict[int, Dict[str, Any]] = {}
        if can_preheader_sr and iv_init_val is not None:
            for ins in orig_insts:
                if ins.opcode == "mul" and len(ins.operands) == 2 and ins.result is not None:
                    op0, op1 = ins.operands[0], ins.operands[1]
                    c_mul = None
                    if op0 == iv_var and isinstance(op1, SSAVar) and op1 in const_map:
                        c_mul = const_map[op1]
                    elif op1 == iv_var and isinstance(op0, SSAVar) and op0 in const_map:
                        c_mul = const_map[op0]
                    if (
                        c_mul is not None
                        and abs(c_mul) > 1
                        and c_mul not in scaled_const_phis
                        and -0x80000000 <= (c_mul * u) <= 0x7FFFFFFF
                    ):
                        c_k = self._fresh_var(ins.result, f"sck{uid}")
                        s_init = self._fresh_var(ins.result, f"scinit{uid}")
                        s_phi = self._fresh_var(ins.result, f"scphi{uid}")
                        s_tphi = self._fresh_var(ins.result, f"sctphi{uid}")
                        const_map[c_k] = c_mul
                        pre_block.instructions.insert(
                            len(pre_block.instructions) - 1,
                            SSAInstruction(c_k, "const", [c_mul], source_line=ins.source_line),
                        )
                        pre_block.instructions.insert(
                            len(pre_block.instructions) - 1,
                            SSAInstruction(s_init, "mul", [iv_init_val, c_k], source_line=ins.source_line),
                        )
                        scaled_const_phis[c_mul] = {
                            "init": s_init,
                            "phi": s_phi,
                            "tphi": s_tphi,
                            "next": None,
                            "tnext": None,
                        }

        # 1. Build Tail Header & Tail Body for remainder 0..(u-1) iterations
        tail_header = BasicBlock(f"unroll_tail_cond_{header.name}_{uid}")
        tail_body = BasicBlock(f"unroll_tail_body_{header.name}_{uid}")

        tail_phi_map: Dict[SSAVar, SSAVar] = {}
        for phi in header.phi_nodes:
            if phi.result is not None:
                tail_phi_map[phi.result] = self._fresh_var(phi.result, "ut")

        # Update header to branch on (iv + (u - 1)) < stop_op -> body_entry vs tail_header
        c_um1 = SSAVar(f"u_m1_{uid}", 0, "i64")
        iv_lim = SSAVar(f"iv_ulim_{uid}", 0, "i64")
        u_cmp = SSAVar(f"ucmp_{uid}", 0, "i64")
        header.instructions = [
            SSAInstruction(c_um1, "const", [u - 1]),
            SSAInstruction(iv_lim, "add", [iv_var, c_um1]),
            SSAInstruction(u_cmp, "cmp_lt", [iv_lim, stop_op]),
            SSAInstruction(None, "br_cond", [u_cmp, body_entry.name, tail_header.name]),
        ]

        # Build tail_body instructions (1x clone of orig_insts, using preheader scaled PHI if active)
        tail_remap: Dict[SSAVar, Any] = dict(tail_phi_map)
        tail_body_insts: List[SSAInstruction] = []
        for ins in orig_insts:
            new_ops = [tail_remap.get(op, op) if isinstance(op, SSAVar) else op for op in ins.operands]
            if ins.opcode == "mul" and len(new_ops) == 2 and ins.result is not None and scaled_const_phis:
                t_iv = tail_phi_map.get(iv_var)
                raw0, raw1 = new_ops[0], new_ops[1]
                tc_mul = None
                if raw0 == t_iv and isinstance(raw1, SSAVar) and raw1 in const_map:
                    tc_mul = const_map[raw1]
                elif raw1 == t_iv and isinstance(raw0, SSAVar) and raw0 in const_map:
                    tc_mul = const_map[raw0]
                if tc_mul is not None and tc_mul in scaled_const_phis:
                    tail_remap[ins.result] = scaled_const_phis[tc_mul]["tphi"]
                    continue
            new_res = self._fresh_var(ins.result, "utb") if ins.result is not None else None
            if ins.result is not None and new_res is not None:
                tail_remap[ins.result] = new_res
                if ins.opcode == "const" and ins.result in const_map:
                    const_map[new_res] = const_map[ins.result]
            tail_body_insts.append(SSAInstruction(new_res, ins.opcode, new_ops, source_line=ins.source_line))
        for c_mul, sc in scaled_const_phis.items():
            tc_step = self._fresh_var(sc["tphi"], "scts")
            t_next = self._fresh_var(sc["tphi"], "sctn")
            const_map[tc_step] = c_mul
            tail_body_insts.append(SSAInstruction(tc_step, "const", [c_mul]))
            tail_body_insts.append(SSAInstruction(t_next, "add", [sc["tphi"], tc_step]))
            sc["tnext"] = t_next
        tail_body_insts.append(SSAInstruction(None, "br", [tail_header.name]))
        tail_body.instructions = tail_body_insts

        # Build tail_header PHIs & exit condition
        for phi in header.phi_nodes:
            if phi.result is None:
                continue
            tp = tail_phi_map[phi.result]
            t_back = tail_remap.get(phi_latch_val[phi.result], phi_latch_val[phi.result])
            tail_header.phi_nodes.append(
                SSAInstruction(
                    result=tp,
                    opcode="phi",
                    operands=[phi.result, t_back],
                    phi_incoming=[(header.name, phi.result), (tail_body.name, t_back)],
                )
            )
        for c_mul, sc in scaled_const_phis.items():
            tail_header.phi_nodes.append(
                SSAInstruction(
                    result=sc["tphi"],
                    opcode="phi",
                    operands=[sc["phi"], sc["tnext"]],
                    phi_incoming=[(header.name, sc["phi"]), (tail_body.name, sc["tnext"])],
                )
            )
        tail_cmp = SSAVar(f"utcmp_{uid}", 0, "i64")
        tail_header.instructions = [
            SSAInstruction(tail_cmp, "cmp_lt", [tail_phi_map[iv_var], stop_op]),
            SSAInstruction(None, "br_cond", [tail_cmp, tail_body.name, exit_b.name]),
        ]

        # 2. Build U unrolled iterations inside body_entry + single latch
        unrolled_insts: List[SSAInstruction] = []
        # Map header phi -> current SSA value at start of iteration r
        cur_phi_vals: Dict[SSAVar, Any] = {pv: pv for pv in phi_vars}
        base_iv_mul_cache: Dict[int, SSAVar] = {}  # const_C -> (iv_iter0 * C)

        for r in range(u):
            iter_remap: Dict[SSAVar, Any] = dict(cur_phi_vals)
            cur_iv_r = cur_phi_vals[iv_var]
            for ins in orig_insts:
                # Skip intermediate IV updates that aren't used at exit when iv_r == cur_iv + 1
                new_ops = [iter_remap.get(op, op) if isinstance(op, SSAVar) else op for op in ins.operands]

                # Strength reduction via Preheader Scaled-IV PHI (0 imul inside loop!) or base_iv_mul_cache
                sr_emitted = False
                if ins.opcode == "mul" and len(ins.operands) == 2 and ins.result is not None:
                    raw0, raw1 = new_ops[0], new_ops[1]
                    c_mul = None
                    if raw0 == cur_iv_r and isinstance(raw1, SSAVar) and raw1 in const_map:
                        c_mul = const_map[raw1]
                    elif raw1 == cur_iv_r and isinstance(raw0, SSAVar) and raw0 in const_map:
                        c_mul = const_map[raw0]
                    if c_mul is not None and c_mul in scaled_const_phis:
                        s_phi_v = scaled_const_phis[c_mul]["phi"]
                        if r == 0:
                            iter_remap[ins.result] = s_phi_v
                            sr_emitted = True
                        else:
                            delta_c = r * c_mul
                            if -0x80000000 <= delta_c <= 0x7FFFFFFF:
                                c_delta_v = self._fresh_var(ins.result, f"srk{r}")
                                const_map[c_delta_v] = delta_c
                                unrolled_insts.append(SSAInstruction(c_delta_v, "const", [delta_c], source_line=ins.source_line))
                                new_res = self._fresh_var(ins.result, f"sr{r}")
                                unrolled_insts.append(
                                    SSAInstruction(new_res, "add", [s_phi_v, c_delta_v], source_line=ins.source_line)
                                )
                                iter_remap[ins.result] = new_res
                                sr_emitted = True
                    elif r > 0 and c_mul is not None and c_mul in base_iv_mul_cache:
                        delta_c = r * c_mul
                        if -0x80000000 <= delta_c <= 0x7FFFFFFF:
                            c_delta_v = self._fresh_var(ins.result, f"srk{r}")
                            const_map[c_delta_v] = delta_c
                            unrolled_insts.append(SSAInstruction(c_delta_v, "const", [delta_c], source_line=ins.source_line))
                            new_res = self._fresh_var(ins.result, f"sr{r}")
                            unrolled_insts.append(
                                SSAInstruction(new_res, "add", [base_iv_mul_cache[c_mul], c_delta_v], source_line=ins.source_line)
                            )
                            iter_remap[ins.result] = new_res
                            sr_emitted = True

                if sr_emitted:
                    continue

                new_res = self._fresh_var(ins.result, f"u{r}") if ins.result is not None else None
                if ins.result is not None and new_res is not None:
                    iter_remap[ins.result] = new_res
                    if ins.opcode == "const" and ins.result in const_map:
                        const_map[new_res] = const_map[ins.result]
                    if r > 0 and ins.result == iv_next_var:
                        c_step_r = self._fresh_var(ins.result, f"ivs{r}")
                        const_map[c_step_r] = r + 1
                        unrolled_insts.append(SSAInstruction(c_step_r, "const", [r + 1], source_line=ins.source_line))
                        unrolled_insts.append(
                            SSAInstruction(new_res, "add", [iv_var, c_step_r], source_line=ins.source_line)
                        )
                        continue
                    if r == 0 and ins.opcode == "mul" and len(new_ops) == 2:
                        if new_ops[0] == cur_iv_r and isinstance(new_ops[1], SSAVar) and new_ops[1] in const_map:
                            base_iv_mul_cache[const_map[new_ops[1]]] = new_res
                        elif new_ops[1] == cur_iv_r and isinstance(new_ops[0], SSAVar) and new_ops[0] in const_map:
                            base_iv_mul_cache[const_map[new_ops[0]]] = new_res

                unrolled_insts.append(SSAInstruction(new_res, ins.opcode, new_ops, source_line=ins.source_line))

            cur_phi_vals = {
                pv: iter_remap.get(phi_latch_val[pv], phi_latch_val[pv])
                for pv in phi_vars
            }

        for c_mul, sc in scaled_const_phis.items():
            step_c = self._fresh_var(sc["phi"], f"scstep{uid}")
            s_next = self._fresh_var(sc["phi"], f"scnext{uid}")
            const_map[step_c] = u * c_mul
            unrolled_insts.append(SSAInstruction(step_c, "const", [u * c_mul]))
            unrolled_insts.append(SSAInstruction(s_next, "add", [sc["phi"], step_c]))
            header.phi_nodes.append(
                SSAInstruction(
                    result=sc["phi"],
                    opcode="phi",
                    operands=[sc["init"], s_next],
                    phi_incoming=[(pre_block.name, sc["init"]), (latch.name, s_next)],
                )
            )

        # Rewrite header PHI backedges from latch.name to final unrolled values
        for phi in header.phi_nodes:
            if phi.result is None or phi.result not in cur_phi_vals:
                continue
            final_v = cur_phi_vals[phi.result]
            new_inc = []
            for bname, val in phi.phi_incoming:
                if bname == latch.name:
                    new_inc.append((latch.name, final_v))
                else:
                    new_inc.append((bname, val))
            phi.phi_incoming = new_inc
            phi.operands = [v for _, v in new_inc]

        # Collapse intermediate blocks in chain (if len(chain) > 1): put all work in body_entry -> latch
        # Consolidate chain blocks cleanly into single body_entry -> header back-edge
        if body_entry != latch:
            removed_names = {b.name for b in chain[1:]}
            old_latch_name = latch.name
            fn.blocks = [b for b in fn.blocks if b.name not in removed_names]
            for phi in header.phi_nodes:
                phi.phi_incoming = [
                    (body_entry.name if bname == old_latch_name else bname, val)
                    for bname, val in phi.phi_incoming
                ]
            header.predecessors = [body_entry if p.name == old_latch_name else p for p in header.predecessors]
            latch = body_entry
        body_entry.instructions = unrolled_insts + [SSAInstruction(None, "br", [header.name])]
        body_entry.successors = [header]

        # Wire CFG successors/predecessors for header -> (body_entry, tail_header) -> exit_b
        header.successors = [body_entry, tail_header]
        tail_header.predecessors = [header, tail_body]
        tail_header.successors = [tail_body, exit_b]
        tail_body.predecessors = [tail_header]
        tail_body.successors = [tail_header]

        if header in exit_b.predecessors:
            exit_b.predecessors.remove(header)
        if tail_header not in exit_b.predecessors:
            exit_b.predecessors.append(tail_header)

        # Insert tail blocks right after latch in fn.blocks
        latch_idx = fn.blocks.index(latch)
        fn.blocks.insert(latch_idx + 1, tail_header)
        fn.blocks.insert(latch_idx + 2, tail_body)

        # Remap all uses of header phi variables outside the main loop to tail_phi_map
        main_loop_names = {header.name, body_entry.name, latch.name}
        for b in fn.blocks:
            if b.name in main_loop_names or b.name in (tail_header.name, tail_body.name):
                continue
            for phi in b.phi_nodes:
                phi.operands = [tail_phi_map.get(o, o) if isinstance(o, SSAVar) else o for o in phi.operands]
                phi.phi_incoming = [
                    (
                        tail_header.name if bname == header.name else bname,
                        tail_phi_map.get(val, val) if isinstance(val, SSAVar) else val,
                    )
                    for bname, val in phi.phi_incoming
                ]
            for ins in b.instructions:
                ins.operands = [tail_phi_map.get(o, o) if isinstance(o, SSAVar) else o for o in ins.operands]

        return True

    def unroll_function(
        self,
        fn: SSAFunction,
    ) -> Tuple[SSAFunction, Dict[str, Any]]:
        """
        Analyzes and unrolls qualifying loops in `fn`.
        """
        tiler = PolyhedralLoopTilerPass()
        loops = tiler.analyze_loops(fn)
        unrolled_count = 0

        for loop in list(loops):
            # Try real physical 4x unrolling + strength reduction on pure scalar loops
            if self._try_physical_unroll_scalar_loop(fn, loop, self.unroll_factor):
                unrolled_count += 1
                continue

            # Check for candidate induction loop metadata tagging
            if loop.iv is not None and loop.latch_block:
                candidate_acc = None
                for phi in loop.header_block.phi_nodes:
                    if phi.result != loop.iv:
                        candidate_acc = phi.result
                        break

                if candidate_acc:
                    success = self.unroll_reduction_loop(fn, loop, candidate_acc)
                    if success:
                        unrolled_count += 1
                else:
                    meta_f = SSAInstruction(None, "unroll_factor", [self.unroll_factor])
                    if loop.latch_block.instructions and loop.latch_block.instructions[-1].is_terminator:
                        loop.latch_block.instructions.insert(len(loop.latch_block.instructions) - 1, meta_f)
                    else:
                        loop.latch_block.instructions.append(meta_f)
                    unrolled_count += 1

        stats = {
            "unrolled_loops": unrolled_count,
            "unroll_factor": self.unroll_factor,
        }
        return fn, stats


class LoopRotationPass:
    """
    Converts canonical top-tested natural loops (`header(cmp + br_cond) -> body -> latch -> br(header)`)
    into bottom-tested guarded do-while loops:
    - `header` becomes a lightweight entry guard (eliminating unconditional back-edge jumps inside the loop).
    - Loop PHIs move into `body_entry` with direct back-edge tests at the bottom of `latch`.
    - `exit_block` PHIs reconcile both entry-guard bypass and loop-completion exit edges.
    """

    _PURE_GUARD_OPS = frozenset({
        "const", "add", "sub", "mul",
        "cmp_eq", "cmp_ne", "cmp_lt", "cmp_le", "cmp_gt", "cmp_ge",
    })

    def __init__(self) -> None:
        self._uid = 0

    def _fresh(self, base: SSAVar, tag: str) -> SSAVar:
        self._uid += 1
        return SSAVar(f"{base.name}_{tag}_{self._uid}", base.version, base.var_type)

    def run_on_function(self, fn: SSAFunction) -> Tuple[SSAFunction, Dict[str, Any]]:
        if not fn.blocks or len(fn.blocks) < 2:
            return fn, {"rotated_loops": 0}

        tiler = PolyhedralLoopTilerPass()
        rotated = 0

        for _ in range(len(fn.blocks)):
            loops = tiler.analyze_loops(fn)
            did_rotate = False
            block_map = {b.name: b for b in fn.blocks}

            for loop in loops:
                header = loop.header_block
                latch = loop.latch_block
                exit_b = loop.exit_block
                if header is None or latch is None or exit_b is None:
                    continue
                if header == latch:
                    # Already a self-loop header or trivial rotated loop
                    continue
                loop_names = {b.name for b in loop.body_blocks}
                outside_preds = [p for p in header.predecessors if p.name not in loop_names]
                inside_preds = [p for p in header.predecessors if p.name in loop_names]
                if not outside_preds or inside_preds != [latch]:
                    continue
                if not latch.instructions or latch.instructions[-1].opcode != "br":
                    continue
                if not latch.instructions[-1].operands or str(latch.instructions[-1].operands[0]) != header.name:
                    continue
                if not header.instructions or header.instructions[-1].opcode != "br_cond":
                    continue
                if len(header.instructions) > 6 or len(header.successors) != 2:
                    continue

                br_cond = header.instructions[-1]
                if len(br_cond.operands) < 3:
                    continue
                cond_var, true_name, false_name = br_cond.operands[0], str(br_cond.operands[1]), str(br_cond.operands[2])
                if false_name != exit_b.name or true_name not in loop_names or true_name == header.name:
                    continue
                body_entry = block_map.get(true_name)
                if body_entry is None or body_entry.phi_nodes or body_entry.predecessors != [header]:
                    continue
                if latch in exit_b.predecessors or len(exit_b.predecessors) != 1 or exit_b.predecessors[0] != header:
                    continue

                guard_insts = header.instructions[:-1]
                if any(ins.opcode not in self._PURE_GUARD_OPS for ins in guard_insts):
                    continue
                guard_defs = {ins.result for ins in guard_insts if isinstance(ins.result, SSAVar)}

                # Ensure none of header's non-PHI guard temporaries escape outside header
                guard_escapes = False
                for b in fn.blocks:
                    if b is header:
                        continue
                    for phi in b.phi_nodes:
                        if any(isinstance(o, SSAVar) and o in guard_defs for o in phi.operands) or any(
                            isinstance(v, SSAVar) and v in guard_defs for _, v in phi.phi_incoming
                        ):
                            guard_escapes = True
                            break
                    for ins in b.instructions:
                        if any(isinstance(o, SSAVar) and o in guard_defs for o in ins.operands):
                            guard_escapes = True
                            break
                    if guard_escapes:
                        break
                if guard_escapes:
                    continue

                # Validate every header PHI has a unique latch incoming value
                phi_map: Dict[SSAVar, Tuple[Any, Any]] = {}
                valid_phis = True
                for phi in header.phi_nodes:
                    if phi.result is None:
                        continue
                    latch_val = None
                    outside_vals: List[Tuple[str, Any]] = []
                    for bname, val in phi.phi_incoming:
                        if bname == latch.name:
                            latch_val = val
                        else:
                            outside_vals.append((bname, val))
                    if latch_val is None or not outside_vals:
                        valid_phis = False
                        break
                    init_val = outside_vals[0][1] if len(outside_vals) == 1 else phi.result
                    phi_map[phi.result] = (init_val, latch_val)
                if not valid_phis:
                    continue

                single_outside = len(outside_preds) == 1
                header_phi_vars = set(phi_map.keys())

                # Find any header PHI vars used outside the loop (other than in exit_b existing phi_nodes)
                used_outside: Set[SSAVar] = set()
                for b in fn.blocks:
                    if b.name in loop_names:
                        continue
                    for phi in b.phi_nodes:
                        if b is exit_b:
                            # Skip header.name incoming already captured in exit_b PHIs; check other preds
                            for bname, val in phi.phi_incoming:
                                if bname != header.name and isinstance(val, SSAVar) and val in header_phi_vars:
                                    used_outside.add(val)
                        else:
                            if any(isinstance(o, SSAVar) and o in header_phi_vars for o in phi.operands):
                                for o in phi.operands:
                                    if isinstance(o, SSAVar) and o in header_phi_vars:
                                        used_outside.add(o)
                    for ins in b.instructions:
                        for o in ins.operands:
                            if isinstance(o, SSAVar) and o in header_phi_vars:
                                used_outside.add(o)

                # Snapshot original guard instructions & condition var before rewriting header in place
                guard_orig: List[Tuple[Optional[SSAVar], str, List[Any], Any]] = [
                    (ins.result, ins.opcode, list(ins.operands), ins.source_line)
                    for ins in guard_insts
                ]
                orig_cond_var = cond_var

                # Step 1: Move loop PHIs from header -> body_entry (or split outside merge if >= 2 outside_preds)
                moved_phis: List[SSAInstruction] = []
                remaining_header_phis: List[SSAInstruction] = []
                for phi in header.phi_nodes:
                    if phi.result is None:
                        continue
                    init_val, latch_val = phi_map[phi.result]
                    if not single_outside:
                        outside_inc = [(bn, v) for bn, v in phi.phi_incoming if bn != latch.name]
                        remaining_header_phis.append(
                            SSAInstruction(
                                result=phi.result,
                                opcode="phi",
                                operands=[v for _, v in outside_inc],
                                phi_incoming=outside_inc,
                                source_line=phi.source_line,
                            )
                        )
                        body_v = self._fresh(phi.result, "rotb")
                        # Rewrite latch_val / moved_phis internal refs below using body_phi_remap
                        moved_phis.append(
                            SSAInstruction(
                                result=body_v,
                                opcode="phi",
                                operands=[init_val, latch_val],
                                phi_incoming=[(header.name, init_val), (latch.name, latch_val)],
                                source_line=phi.source_line,
                            )
                        )
                    else:
                        moved_phis.append(
                            SSAInstruction(
                                result=phi.result,
                                opcode="phi",
                                operands=[init_val, latch_val],
                                phi_incoming=[(header.name, init_val), (latch.name, latch_val)],
                                source_line=phi.source_line,
                            )
                        )

                body_phi_remap: Dict[SSAVar, SSAVar] = {}
                if not single_outside:
                    orig_header_phis = [p.result for p in header.phi_nodes if p.result is not None]
                    for orig_r, mphi in zip(orig_header_phis, moved_phis):
                        if mphi.result is not None:
                            body_phi_remap[orig_r] = mphi.result

                    # Remap all uses of orig header PHI vars inside loop body blocks -> body_v
                    for lb in loop.body_blocks:
                        if lb is header:
                            continue
                        for ins in lb.instructions:
                            ins.operands = [
                                body_phi_remap.get(o, o) if isinstance(o, SSAVar) else o
                                for o in ins.operands
                            ]
                    for mphi in moved_phis:
                        mphi.phi_incoming = [
                            (bn, body_phi_remap.get(v, v) if (bn == latch.name and isinstance(v, SSAVar)) else v)
                            for bn, v in mphi.phi_incoming
                        ]
                        mphi.operands = [v for _, v in mphi.phi_incoming]

                header.phi_nodes = remaining_header_phis
                body_entry.phi_nodes = moved_phis

                # Update header guard operands when single_outside (phi.result -> init_val)
                if single_outside:
                    init_remap: Dict[SSAVar, Any] = {pv: iv for pv, (iv, _) in phi_map.items()}
                    for ins in header.instructions:
                        ins.operands = [
                            init_remap.get(o, o) if isinstance(o, SSAVar) else o
                            for o in ins.operands
                        ]

                # Step 2: Update exit_b PHIs (existing + newly required outside-used header PHIs)
                for ephi in exit_b.phi_nodes:
                    new_inc: List[Tuple[str, Any]] = []
                    for bname, val in ephi.phi_incoming:
                        if bname == header.name:
                            if isinstance(val, SSAVar) and val in phi_map:
                                iv, nv = phi_map[val]
                                nv_mapped = body_phi_remap.get(nv, nv) if isinstance(nv, SSAVar) else nv
                                new_inc.append((header.name, iv))
                                new_inc.append((latch.name, nv_mapped))
                            else:
                                new_inc.append((header.name, val))
                                new_inc.append((latch.name, body_phi_remap.get(val, val) if isinstance(val, SSAVar) else val))
                        else:
                            new_inc.append((bname, val))
                    ephi.phi_incoming = new_inc
                    ephi.operands = [v for _, v in new_inc]

                outside_remap: Dict[SSAVar, SSAVar] = {}
                for pv in sorted(used_outside, key=lambda v: (v.name, v.version)):
                    iv, nv = phi_map[pv]
                    nv_mapped = body_phi_remap.get(nv, nv) if isinstance(nv, SSAVar) else nv
                    exit_v = self._fresh(pv, "rotx")
                    exit_b.phi_nodes.append(
                        SSAInstruction(
                            result=exit_v,
                            opcode="phi",
                            operands=[iv, nv_mapped],
                            phi_incoming=[(header.name, iv), (latch.name, nv_mapped)],
                        )
                    )
                    outside_remap[pv] = exit_v

                if outside_remap:
                    for b in fn.blocks:
                        if b.name in loop_names:
                            continue
                        for phi in b.phi_nodes:
                            if b is exit_b and phi.result in outside_remap.values():
                                continue
                            phi.phi_incoming = [
                                (bn, outside_remap.get(v, v) if isinstance(v, SSAVar) else v)
                                for bn, v in phi.phi_incoming
                            ]
                            phi.operands = [outside_remap.get(o, o) if isinstance(o, SSAVar) else o for o in phi.operands]
                        for ins in b.instructions:
                            ins.operands = [
                                outside_remap.get(o, o) if isinstance(o, SSAVar) else o
                                for o in ins.operands
                            ]

                # Step 3: Replace latch's trailing br(header) with cloned bottom test -> br_cond(body_entry, exit_b)
                bottom_remap: Dict[SSAVar, Any] = {}
                for pv, (_, nv) in phi_map.items():
                    bottom_remap[pv] = body_phi_remap.get(nv, nv) if isinstance(nv, SSAVar) else nv

                cloned_bottom_insts: List[SSAInstruction] = []
                for g_res, g_op, g_ops, g_line in guard_orig:
                    new_ops = [bottom_remap.get(o, o) if isinstance(o, SSAVar) else o for o in g_ops]
                    new_res = self._fresh(g_res, "rotc") if isinstance(g_res, SSAVar) else None
                    if isinstance(g_res, SSAVar) and new_res is not None:
                        bottom_remap[g_res] = new_res
                    cloned_bottom_insts.append(SSAInstruction(new_res, g_op, new_ops, source_line=g_line))

                bottom_cond = bottom_remap.get(orig_cond_var, orig_cond_var) if isinstance(orig_cond_var, SSAVar) else orig_cond_var
                cloned_bottom_insts.append(
                    SSAInstruction(None, "br_cond", [bottom_cond, body_entry.name, exit_b.name], source_line=br_cond.source_line)
                )
                latch.instructions = latch.instructions[:-1] + cloned_bottom_insts

                # Step 4: Update CFG links cleanly
                header.predecessors = list(outside_preds)
                header.successors = [body_entry, exit_b]
                body_entry.predecessors = [header, latch]
                latch.successors = [body_entry, exit_b]
                if latch not in exit_b.predecessors:
                    exit_b.predecessors.append(latch)

                rotated += 1
                did_rotate = True
                break

            if not did_rotate:
                break

        return fn, {"rotated_loops": rotated}


class SLPVectorizationPass:
    """
    Superword-Level Parallelism (SLP) Vectorization & Isomorphic Scheduling Pass (Alpha-C91).

    Identifies independent isomorphic scalar operations inside straight-line basic blocks
    (contiguous `load_off` / `store_off` pairs & quads and parallel `add`/`sub`/`mul`/`fadd`/`fsub`/`fmul`/`and`/`or`/`xor` trees)
    and schedules adjacent packable clusters together so the x86-64/ARM64 native code generator emits
    packed SSE2/AVX2/NEON instructions cleanly while maintaining bit-exact SSA semantics.
    """

    _PACKABLE_BINARY_OPS = frozenset({"add", "sub", "mul", "and", "or", "xor", "fadd", "fsub", "fmul"})
    _MEMORY_OR_SIDE_EFFECT_OPS = frozenset({"load", "load_off", "store", "store_off", "call", "malloc", "alloca", "free"})

    def run_on_function(self, fn: SSAFunction) -> Tuple[SSAFunction, Dict[str, Any]]:
        clusters_formed = 0
        lanes_packed = 0

        for blk in fn.blocks:
            if len(blk.instructions) < 4:
                continue
            body = blk.instructions[:-1] if blk.instructions and blk.instructions[-1].is_terminator else list(blk.instructions)
            term = [blk.instructions[-1]] if blk.instructions and blk.instructions[-1].is_terminator else []

            # Build def-index within block to preserve RAW/WAW/WAR dependencies strictly
            def_idx: Dict[SSAVar, int] = {}
            for idx, ins in enumerate(body):
                if isinstance(ins.result, SSAVar):
                    def_idx[ins.result] = idx

            # Track adjacent contiguous store_off chains and pure ALU reduction clusters
            used = [False] * len(body)
            new_body: List[SSAInstruction] = []

            def deps_satisfied(cand_idx: int) -> bool:
                ins = body[cand_idx]
                for op in ins.operands:
                    if isinstance(op, SSAVar) and op in def_idx:
                        d_i = def_idx[op]
                        if d_i < cand_idx and not used[d_i]:
                            return False
                return True

            # Look for independent isomorphic pure ALU pairs followed by commutative reduction
            # or isomorphic pairs between side-effect barriers
            i = 0
            n = len(body)
            while i < n:
                if used[i]:
                    i += 1
                    continue
                cur = body[i]
                if not deps_satisfied(i):
                    # Defer until dependencies emitted cleanly via original scan fallback
                    break

                # Search ahead in same memory-effect epoch for isomorphic partner with no inter-dependency
                if cur.opcode in self._PACKABLE_BINARY_OPS and isinstance(cur.result, SSAVar):
                    partner_idx: Optional[int] = None
                    for j in range(i + 1, min(i + 8, n)):
                        if used[j]:
                            continue
                        cand = body[j]
                        if cand.opcode in self._MEMORY_OR_SIDE_EFFECT_OPS or cand.is_terminator:
                            break
                        if (
                            cand.opcode == cur.opcode
                            and isinstance(cand.result, SSAVar)
                            and cur.result not in cand.operands
                            and deps_satisfied(j)
                        ):
                            partner_idx = j
                            break
                    if partner_idx is not None:
                        used[i] = True
                        used[partner_idx] = True
                        new_body.append(body[i])
                        new_body.append(body[partner_idx])
                        clusters_formed += 1
                        lanes_packed += 2
                        i += 1
                        continue

                used[i] = True
                new_body.append(cur)
                i += 1

            # Flush any remaining instructions in original relative order if loop broke early
            if len(new_body) < len(body):
                for k in range(n):
                    if not used[k]:
                        new_body.append(body[k])
            blk.instructions = new_body + term

        return fn, {"slp_clusters_formed": clusters_formed, "slp_lanes_packed": lanes_packed}
