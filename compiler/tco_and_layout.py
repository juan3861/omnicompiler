"""
OmniCompiler Tail-Call Optimization (TCO), Hot/Cold Block Layout & Peephole Machine Optimizer
(compiler/tco_and_layout.py)

Implements:
1. TailCallOptimizationPass:
   - Detects self-tail-recursive calls (`res = call fn(args); ret res`) in SSA IR.
   - Splits `entry` after `param` instructions into `entry -> tco_header`.
   - Synthesizes loop-header Phi nodes for each parameter and converts tail calls
     into unconditional `br tco_header`, turning O(N) stack recursion into O(1) iteration.
2. BlockLayoutPass:
   - Orders CFG basic blocks by loop-depth and optional PGO execution counts,
     keeping `entry` first and placing hot loop headers/bodies contiguously for
     fallthrough branch elimination and I-cache locality.
3. PeepholeMachineOptimizer:
   - Scans emitted x86-64 machine code for redundant zero-displacement jumps
     (`E9 00 00 00 00`) and redundant register self-moves (`mov rax, rax`, etc.),
     returning optimized bytes when no external relocations are shifted.
"""

from typing import Dict, List, Set, Tuple, Any, Optional

from compiler.ssa_ir import (
    SSAFunction,
    BasicBlock,
    SSAInstruction,
    SSAVar,
    optimize_ssa,
)


class TailCallOptimizationPass:
    """
    Converts self-tail-recursive SSA calls into O(1) stack-frame loops.
    """

    def _find_tail_recursive_blocks(self, fn: SSAFunction) -> List[Tuple[BasicBlock, SSAInstruction, SSAInstruction]]:
        matches: List[Tuple[BasicBlock, SSAInstruction, SSAInstruction]] = []
        for b in fn.blocks:
            if len(b.instructions) < 2:
                continue
            call_inst = b.instructions[-2]
            ret_inst = b.instructions[-1]
            if call_inst.opcode != "call" or ret_inst.opcode != "ret":
                continue
            if not call_inst.operands or str(call_inst.operands[0]) != fn.name:
                continue
            call_args = call_inst.operands[1:]
            if len(call_args) != len(fn.params):
                continue
            # Check tail position: ret returns call_inst.result (or ret has no operands)
            if call_inst.result is not None:
                if not ret_inst.operands or ret_inst.operands[0] != call_inst.result:
                    continue
            matches.append((b, call_inst, ret_inst))
        return matches

    def run_on_function(self, fn: SSAFunction) -> Tuple[SSAFunction, Dict[str, Any]]:
        if not fn.blocks:
            return fn, {"tco_converted_calls": 0}

        matches = self._find_tail_recursive_blocks(fn)
        if not matches:
            return fn, {"tco_converted_calls": 0}

        entry = fn.entry_block or fn.blocks[0]

        # Separate `param` instructions at the start of `entry`
        param_insts: List[SSAInstruction] = []
        other_entry_insts: List[SSAInstruction] = []
        for inst in entry.instructions:
            if inst.opcode == "param" and not other_entry_insts:
                param_insts.append(inst)
            else:
                other_entry_insts.append(inst)

        if len(param_insts) != len(fn.params):
            # Ensure we have a 1-to-1 mapping of param instructions to fn.params
            param_vars: List[Optional[SSAVar]] = [None] * len(fn.params)
            for inst in param_insts:
                if inst.operands and inst.result is not None:
                    raw = inst.operands[0]
                    if isinstance(raw, int) and 0 <= raw < len(fn.params):
                        param_vars[raw] = inst.result
                    elif isinstance(raw, str) and raw in fn.params:
                        param_vars[fn.params.index(raw)] = inst.result
            if any(v is None for v in param_vars):
                return fn, {"tco_converted_calls": 0}
            orig_param_vars: List[SSAVar] = [v for v in param_vars if v is not None]
        else:
            orig_param_vars = [inst.result for inst in param_insts if inst.result is not None]
            if len(orig_param_vars) != len(fn.params):
                return fn, {"tco_converted_calls": 0}

        # Create tco_header block
        header_name = "tco_header"
        existing_names = {b.name for b in fn.blocks}
        idx = 0
        while header_name in existing_names:
            idx += 1
            header_name = f"tco_header_{idx}"

        tco_header = BasicBlock(header_name)
        tco_header.instructions = other_entry_insts
        tco_header.phi_nodes = list(entry.phi_nodes)
        tco_header.loop_depth = entry.loop_depth + 1
        entry.phi_nodes = []

        # Redirect successors of entry to become successors of tco_header
        tco_header.successors = list(entry.successors)
        for succ in tco_header.successors:
            succ.predecessors = [tco_header if p == entry else p for p in succ.predecessors]
            for phi in succ.phi_nodes:
                phi.phi_incoming = [
                    (header_name if blk == entry.name else blk, val)
                    for blk, val in phi.phi_incoming
                ]

        # Connect entry -> tco_header
        entry.instructions = param_insts + [SSAInstruction(None, "br", [header_name])]
        entry.successors = [tco_header]
        tco_header.predecessors = [entry]

        # Insert tco_header right after entry
        entry_idx = fn.blocks.index(entry)
        fn.blocks.insert(entry_idx + 1, tco_header)

        # Create Phi variables for each parameter in tco_header
        param_phi_map: Dict[SSAVar, SSAVar] = {}
        phi_vars: List[SSAVar] = []
        for p_var in orig_param_vars:
            phi_v = SSAVar(f"{p_var.name}_tco", p_var.version + 100, p_var.var_type)
            param_phi_map[p_var] = phi_v
            phi_vars.append(phi_v)

        # Rewrite all uses of orig_param_vars across all blocks (except entry)
        def remap_op(op: Any) -> Any:
            if isinstance(op, SSAVar) and op in param_phi_map:
                return param_phi_map[op]
            return op

        for b in fn.blocks:
            if b == entry:
                continue
            for phi in b.phi_nodes:
                phi.operands = [remap_op(o) for o in phi.operands]
                phi.phi_incoming = [(blk, remap_op(v)) for blk, v in phi.phi_incoming]
            for inst in b.instructions:
                inst.operands = [remap_op(o) for o in inst.operands]

        # Build Phi incoming lists and convert tail call+ret blocks into `br tco_header`
        incoming_per_param: List[List[Tuple[str, Any]]] = [
            [(entry.name, p_var)] for p_var in orig_param_vars
        ]

        converted = 0
        for tail_blk, call_inst, ret_inst in matches:
            call_args = call_inst.operands[1:]
            for i, arg in enumerate(call_args):
                incoming_per_param[i].append((tail_blk.name, arg))

            # Replace `call` + `ret` with `br tco_header`
            tail_blk.instructions = tail_blk.instructions[:-2] + [
                SSAInstruction(None, "br", [header_name], source_line=call_inst.source_line)
            ]
            if tco_header not in tail_blk.successors:
                tail_blk.successors.append(tco_header)
            if tail_blk not in tco_header.predecessors:
                tco_header.predecessors.append(tail_blk)
            converted += 1

        # Add synthesized Phi nodes to tco_header
        for i, phi_v in enumerate(phi_vars):
            inc = incoming_per_param[i]
            tco_header.phi_nodes.append(
                SSAInstruction(
                    result=phi_v,
                    opcode="phi",
                    operands=[v for _, v in inc],
                    phi_incoming=inc,
                )
            )

        fn = optimize_ssa(fn)
        return fn, {"tco_converted_calls": converted}


class BlockLayoutPass:
    """
    Hot/Cold Basic-Block Layout Pass.
    Reorders CFG blocks (preserving `entry` at index 0) to maximize fallthrough
    paths and group hot loop blocks contiguously for I-cache efficiency.
    """

    def run_on_function(
        self,
        fn: SSAFunction,
        pgo_counts: Optional[Dict[str, int]] = None,
    ) -> Tuple[SSAFunction, Dict[str, Any]]:
        if len(fn.blocks) <= 2:
            return fn, {"reordered_blocks": 0}

        entry = fn.entry_block or fn.blocks[0]
        pgo = pgo_counts or {}

        def block_score(b: BasicBlock) -> Tuple[int, int, int]:
            has_ret = 1 if (b.instructions and b.instructions[-1].opcode == "ret") else 0
            hotness = pgo.get(b.name, 0) + (10 ** min(b.loop_depth, 4))
            # Higher hotness first, non-return (continuation/loop) blocks before cold exits
            return (-hotness, has_ret, fn.blocks.index(b))

        others = [b for b in fn.blocks if b != entry]
        sorted_others = sorted(others, key=block_score)
        new_order = [entry] + sorted_others

        reordered = sum(1 for a, b in zip(fn.blocks, new_order) if a != b)
        fn.blocks = new_order
        return fn, {"reordered_blocks": reordered}


class PeepholeMachineOptimizer:
    """
    Machine-Code Peephole Optimizer for x86-64.
    Detects and eliminates redundant zero-displacement unconditional jumps (`E9 00 00 00 00`)
    and redundant 64-bit self-moves (`48 89 C0`, `48 89 C9`, `48 89 D2`, etc.).
    """

    REDUNDANT_SELF_MOVES = (
        b"\x48\x89\xc0",  # mov rax, rax
        b"\x48\x89\xc9",  # mov rcx, rcx
        b"\x48\x89\xd2",  # mov rdx, rdx
        b"\x48\x89\xdb",  # mov rbx, rbx
        b"\x48\x89\xf6",  # mov rsi, rsi
        b"\x48\x89\xff",  # mov rdi, rdi
    )

    ZERO_JMP_REL32 = b"\xe9\x00\x00\x00\x00"

    def optimize_bytes(
        self,
        code: bytes,
        has_relocations: bool = False,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Optimizes standalone x86-64 byte sequences.
        When `has_relocations` is True, replaces redundant patterns in-place with
        shorter/NOP-free safe metadata or skips byte-shifting to preserve relocation offsets.
        """
        if has_relocations or not code:
            return code, {"peephole_bytes_saved": 0, "eliminated_fallthrough_jmps": 0}

        # Only strip trailing/isolated zero-offset jumps when there are no internal rel32 jumps
        # that could have their displacement shifted.
        if b"\xe9" in code.replace(self.ZERO_JMP_REL32, b"") or b"\x0f" in code or b"\xeb" in code:
            # Has internal conditional/relative branches: do not shift offsets
            return code, {"peephole_bytes_saved": 0, "eliminated_fallthrough_jmps": 0}

        orig_len = len(code)
        opt = code
        eliminated_jmps = opt.count(self.ZERO_JMP_REL32)
        if eliminated_jmps:
            opt = opt.replace(self.ZERO_JMP_REL32, b"")

        for smov in self.REDUNDANT_SELF_MOVES:
            opt = opt.replace(smov, b"")

        saved = orig_len - len(opt)
        return opt, {
            "peephole_bytes_saved": saved,
            "eliminated_fallthrough_jmps": eliminated_jmps,
        }
