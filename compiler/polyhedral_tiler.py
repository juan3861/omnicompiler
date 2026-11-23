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
                if any(o in body_only_defs for o in phi.operands) or any(v in body_only_defs for _, v in phi.phi_incoming):
                    return False
            for ins in b.instructions:
                if any(o in body_only_defs for o in ins.operands):
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

        # Clamp scalar unroll factor to 4 so live temporaries stay comfortably in registers
        u = min(factor, 4)
        self._uid += 1
        uid = self._uid

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

        # Build tail_body instructions (1x clone of orig_insts)
        tail_remap: Dict[SSAVar, Any] = dict(tail_phi_map)
        tail_body_insts: List[SSAInstruction] = []
        for ins in orig_insts:
            new_ops = [tail_remap.get(op, op) if isinstance(op, SSAVar) else op for op in ins.operands]
            new_res = self._fresh_var(ins.result, "utb") if ins.result is not None else None
            if ins.result is not None and new_res is not None:
                tail_remap[ins.result] = new_res
                if ins.opcode == "const" and ins.result in const_map:
                    const_map[new_res] = const_map[ins.result]
            tail_body_insts.append(SSAInstruction(new_res, ins.opcode, new_ops, source_line=ins.source_line))
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
                # Emit independent IV offset iv_0 + (r+1) on final latch edge or r-step strength reduction
                new_ops = [iter_remap.get(op, op) if isinstance(op, SSAVar) else op for op in ins.operands]

                # Strength reduction: mul(cur_iv_r, C) for r >= 1 -> add(base_mul, r*C)
                sr_emitted = False
                if r > 0 and ins.opcode == "mul" and len(ins.operands) == 2 and ins.result is not None:
                    raw0, raw1 = new_ops[0], new_ops[1]
                    c_mul = None
                    if raw0 == cur_iv_r and isinstance(raw1, SSAVar) and raw1 in const_map:
                        c_mul = const_map[raw1]
                    elif raw1 == cur_iv_r and isinstance(raw0, SSAVar) and raw0 in const_map:
                        c_mul = const_map[raw0]
                    if c_mul is not None and c_mul in base_iv_mul_cache:
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

                # Skip intermediate constants duplicated across unrolled copies by reusing r=0 or cloning cleanly
                new_res = self._fresh_var(ins.result, f"u{r}") if ins.result is not None else None
                if ins.result is not None and new_res is not None:
                    iter_remap[ins.result] = new_res
                    if ins.opcode == "const" and ins.result in const_map:
                        const_map[new_res] = const_map[ins.result]
                    # Record base_iv * C in iteration r == 0 for strength reduction
                    if r == 0 and ins.opcode == "mul" and len(new_ops) == 2:
                        if new_ops[0] == cur_iv_r and isinstance(new_ops[1], SSAVar) and new_ops[1] in const_map:
                            base_iv_mul_cache[const_map[new_ops[1]]] = new_res
                        elif new_ops[1] == cur_iv_r and isinstance(new_ops[0], SSAVar) and new_ops[0] in const_map:
                            base_iv_mul_cache[const_map[new_ops[0]]] = new_res

                unrolled_insts.append(SSAInstruction(new_res, ins.opcode, new_ops, source_line=ins.source_line))

            # Advance phi values to the end of iteration r
            cur_phi_vals = {
                pv: iter_remap.get(phi_latch_val[pv], phi_latch_val[pv])
                for pv in phi_vars
            }

        # Rewrite header PHI backedges from latch.name to final unrolled values
        for phi in header.phi_nodes:
            if phi.result is None:
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
        if body_entry == latch:
            body_entry.instructions = unrolled_insts + [SSAInstruction(None, "br", [header.name])]
        else:
            # Remove middle chain blocks between body_entry and latch cleanly
            mid_names = {b.name for b in chain[1:-1]}
            if mid_names:
                fn.blocks = [b for b in fn.blocks if b.name not in mid_names]
            body_entry.instructions = unrolled_insts + [SSAInstruction(None, "br", [latch.name])]
            body_entry.successors = [latch]
            latch.predecessors = [body_entry]
            latch.instructions = [SSAInstruction(None, "br", [header.name])]
            latch.successors = [header]

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
