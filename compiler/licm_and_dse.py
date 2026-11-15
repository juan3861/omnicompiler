"""
OmniCompiler Loop-Invariant Code Motion (LICM), Alias Analysis & Dead Store Elimination (DSE)
(compiler/licm_and_dse.py)

Implements:
1. AliasAnalysis:
   - Classifies memory locations `(base_ptr, index)` into `NO_ALIAS`, `MAY_ALIAS`, `MUST_ALIAS`.
   - Distinguishes distinct `alloca` stack frames, `alloca` vs external `param`,
     and distinct constant offsets/indices.
2. LICMPass (Loop-Invariant Code Motion):
   - Detects natural loops via dominator back-edges.
   - Identifies pure loop-invariant instructions whose operands are constants or defined
     strictly outside the loop (or by other hoisted loop-invariant instructions).
   - Hoists invariant instructions into the loop pre-header in topological order.
3. DSEPass (Dead Store Elimination & Store-to-Load Forwarding):
   - Store-to-Load Forwarding: forwards stored values directly to subsequent loads
     (`load` -> `mov`) when no aliasing store or call intervenes.
   - Dead Store Elimination: eliminates overwritten `MUST_ALIAS` stores before any
     intervening read/call, and eliminates dead stores to non-escaping local `alloca`s
     before function `ret`.
"""

from typing import Dict, List, Set, Tuple, Any, Optional

from compiler.ssa_ir import (
    SSAFunction,
    BasicBlock,
    SSAInstruction,
    SSAVar,
    SIDE_EFFECT_OPCODES,
    optimize_ssa,
)
from compiler.polyhedral_tiler import PolyhedralLoopTilerPass


class AliasResult:
    NO_ALIAS = "NO_ALIAS"
    MAY_ALIAS = "MAY_ALIAS"
    MUST_ALIAS = "MUST_ALIAS"


LICM_SAFE_PURE_OPCODES = frozenset({
    "add", "sub", "mul", "shl", "shr", "sar",
    "and", "or", "xor", "neg", "not",
    "cmp_eq", "cmp_ne", "cmp_lt", "cmp_le", "cmp_gt", "cmp_ge",
    "const", "mov",
})


class AliasAnalysis:
    """
    SSA Pointer & Memory Location Alias Analyzer.
    Tracks `alloca` origins, `param` origins, and constant indices.
    """

    def __init__(self, fn: SSAFunction):
        self.fn = fn
        self.allocas: Set[SSAVar] = set()
        self.params: Set[SSAVar] = set()
        self.const_vals: Dict[SSAVar, int] = {}
        self._analyze_origins()

    def _analyze_origins(self):
        for b in self.fn.blocks:
            for inst in b.instructions:
                if inst.result is None:
                    continue
                if inst.opcode == "alloca":
                    self.allocas.add(inst.result)
                elif inst.opcode == "param":
                    self.params.add(inst.result)
                elif inst.opcode == "const" and inst.operands:
                    v = inst.operands[0]
                    if isinstance(v, (int, bool)):
                        self.const_vals[inst.result] = int(v)

    def _resolve_const(self, val: Any) -> Optional[int]:
        if isinstance(val, bool):
            return int(val)
        if isinstance(val, int):
            return val
        if isinstance(val, SSAVar) and val in self.const_vals:
            return self.const_vals[val]
        return None

    def alias(
        self,
        ptr_a: Any,
        idx_a: Any,
        ptr_b: Any,
        idx_b: Any,
    ) -> str:
        """
        Determines alias relationship between `(ptr_a, idx_a)` and `(ptr_b, idx_b)`.
        """
        ca = self._resolve_const(idx_a)
        cb = self._resolve_const(idx_b)

        # Identical base pointer
        if ptr_a == ptr_b:
            if idx_a == idx_b:
                return AliasResult.MUST_ALIAS
            if ca is not None and cb is not None:
                return AliasResult.MUST_ALIAS if ca == cb else AliasResult.NO_ALIAS
            return AliasResult.MAY_ALIAS

        # Distinct stack allocations never alias each other
        if ptr_a in self.allocas and ptr_b in self.allocas:
            return AliasResult.NO_ALIAS

        # Non-escaping local alloca vs incoming function parameter
        if (ptr_a in self.allocas and ptr_b in self.params) or (
            ptr_b in self.allocas and ptr_a in self.params
        ):
            return AliasResult.NO_ALIAS

        return AliasResult.MAY_ALIAS


class LICMPass:
    """
    Loop-Invariant Code Motion (LICM) Pass.
    Hoists pure loop-invariant computations out of natural loops into the pre-header.
    """

    def run_on_function(self, fn: SSAFunction) -> Tuple[SSAFunction, Dict[str, Any]]:
        if not fn.blocks:
            return fn, {"licm_hoisted_insts": 0}

        tiler = PolyhedralLoopTilerPass()
        loops = tiler.analyze_loops(fn)
        if not loops:
            return fn, {"licm_hoisted_insts": 0}

        # Map each SSAVar -> defining block name
        def_block: Dict[SSAVar, str] = {}
        for b in fn.blocks:
            for phi in b.phi_nodes:
                if phi.result is not None:
                    def_block[phi.result] = b.name
            for inst in b.instructions:
                if inst.result is not None:
                    def_block[inst.result] = b.name

        total_hoisted = 0

        for loop in loops:
            if not loop.header_block or not loop.body_blocks:
                continue

            loop_block_names = {b.name for b in loop.body_blocks}
            # Identify unique outside predecessor (pre-header)
            outside_preds = [
                p for p in loop.header_block.predecessors
                if p.name not in loop_block_names
            ]
            if len(outside_preds) != 1:
                continue
            preheader = outside_preds[0]

            # Iteratively discover loop-invariant instructions
            invariant_vars: Set[SSAVar] = set()
            hoist_list: List[Tuple[BasicBlock, SSAInstruction]] = []
            hoist_set: Set[int] = set()

            changed = True
            while changed:
                changed = False
                for blk in loop.body_blocks:
                    for inst in blk.instructions:
                        if id(inst) in hoist_set:
                            continue
                        if inst.opcode not in LICM_SAFE_PURE_OPCODES or inst.result is None:
                            continue

                        # Check if all operands are invariant (constant or defined outside loop or invariant)
                        all_inv = True
                        for op in inst.operands:
                            if isinstance(op, (int, bool, str)):
                                continue
                            if isinstance(op, SSAVar):
                                db = def_block.get(op)
                                if db is not None and db in loop_block_names and op not in invariant_vars:
                                    all_inv = False
                                    break
                            else:
                                all_inv = False
                                break

                        if all_inv:
                            invariant_vars.add(inst.result)
                            hoist_list.append((blk, inst))
                            hoist_set.add(id(inst))
                            changed = True

            if not hoist_list:
                continue

            # Remove hoisted instructions from loop blocks and insert into preheader before terminator
            hoisted_insts: List[SSAInstruction] = []
            for blk, inst in hoist_list:
                if inst in blk.instructions:
                    blk.instructions.remove(inst)
                    hoisted_insts.append(inst)
                    def_block[inst.result] = preheader.name  # type: ignore[index]
                    total_hoisted += 1

            if hoisted_insts:
                if preheader.instructions and preheader.instructions[-1].is_terminator:
                    term = preheader.instructions.pop()
                    preheader.instructions.extend(hoisted_insts)
                    preheader.instructions.append(term)
                else:
                    preheader.instructions.extend(hoisted_insts)

        return fn, {"licm_hoisted_insts": total_hoisted}


class DSEPass:
    """
    Dead Store Elimination (DSE) & Store-to-Load Forwarding Pass guided by AliasAnalysis.
    """

    def run_on_function(self, fn: SSAFunction) -> Tuple[SSAFunction, Dict[str, Any]]:
        if not fn.blocks:
            return fn, {"dse_eliminated_stores": 0, "forwarded_loads": 0}

        aa = AliasAnalysis(fn)
        eliminated_stores = 0
        forwarded_loads = 0

        # Track whether an alloca is ever passed to a `call` or returned (escaped)
        escaped_allocas: Set[SSAVar] = set()
        for b in fn.blocks:
            for inst in b.instructions:
                if inst.opcode in ("call", "ret"):
                    for op in inst.operands:
                        if isinstance(op, SSAVar) and op in aa.allocas:
                            escaped_allocas.add(op)

        for b in fn.blocks:
            # Active stores in block: list of (ptr, idx, val, store_inst, is_dead_candidate)
            active_stores: List[Tuple[Any, Any, Any, SSAInstruction]] = []
            dead_store_ids: Set[int] = set()
            new_insts: List[SSAInstruction] = []

            for inst in b.instructions:
                if inst.opcode == "store" and len(inst.operands) >= 3:
                    ptr, idx, val = inst.operands[0], inst.operands[1], inst.operands[2]

                    # Any prior MUST_ALIAS store not yet read is overwritten -> DEAD STORE!
                    surviving_stores: List[Tuple[Any, Any, Any, SSAInstruction]] = []
                    for s_ptr, s_idx, s_val, s_inst in active_stores:
                        rel = aa.alias(s_ptr, s_idx, ptr, idx)
                        if rel == AliasResult.MUST_ALIAS:
                            dead_store_ids.add(id(s_inst))
                            eliminated_stores += 1
                        elif rel == AliasResult.NO_ALIAS:
                            surviving_stores.append((s_ptr, s_idx, s_val, s_inst))
                        else:
                            # MAY_ALIAS: conservatively drop from active tracking without killing
                            pass

                    surviving_stores.append((ptr, idx, val, inst))
                    active_stores = surviving_stores
                    new_insts.append(inst)

                elif inst.opcode == "load" and len(inst.operands) >= 2 and inst.result is not None:
                    ptr, idx = inst.operands[0], inst.operands[1]

                    # Check if we can forward a stored value directly!
                    forwarded_val = None
                    for s_ptr, s_idx, s_val, _s_inst in reversed(active_stores):
                        rel = aa.alias(s_ptr, s_idx, ptr, idx)
                        if rel == AliasResult.MUST_ALIAS:
                            forwarded_val = s_val
                            break
                        elif rel == AliasResult.MAY_ALIAS:
                            break  # conservative stop

                    if forwarded_val is not None:
                        fwd_inst = SSAInstruction(
                            inst.result,
                            "mov",
                            [forwarded_val],
                            source_line=inst.source_line,
                        )
                        new_insts.append(fwd_inst)
                        forwarded_loads += 1
                    else:
                        # Load reads any MAY_ALIAS/MUST_ALIAS active store -> no longer dead if overwritten later
                        active_stores = [
                            (sp, si, sv, si_inst)
                            for sp, si, sv, si_inst in active_stores
                            if aa.alias(sp, si, ptr, idx) == AliasResult.NO_ALIAS
                        ]
                        new_insts.append(inst)

                elif inst.opcode == "call":
                    # Calls may read/write any escaped/param memory; preserve non-escaped allocas only
                    active_stores = [
                        (sp, si, sv, si_inst)
                        for sp, si, sv, si_inst in active_stores
                        if isinstance(sp, SSAVar) and sp in aa.allocas and sp not in escaped_allocas
                    ]
                    new_insts.append(inst)

                elif inst.opcode == "ret":
                    # At function exit, any unread store to a non-escaped local alloca is DEAD!
                    for sp, _si, _sv, si_inst in active_stores:
                        if isinstance(sp, SSAVar) and sp in aa.allocas and sp not in escaped_allocas:
                            dead_store_ids.add(id(si_inst))
                            eliminated_stores += 1
                    active_stores.clear()
                    new_insts.append(inst)

                else:
                    new_insts.append(inst)

            if dead_store_ids:
                b.instructions = [i for i in new_insts if id(i) not in dead_store_ids]
            else:
                b.instructions = new_insts

        if forwarded_loads > 0:
            fn = optimize_ssa(fn)

        return fn, {
            "dse_eliminated_stores": eliminated_stores,
            "forwarded_loads": forwarded_loads,
        }
