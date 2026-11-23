"""
Industrial Register Allocation Suite:
1. Chaitin-Briggs + Biased Coalescing Graph Coloring Allocator (CompCert / LLVM style):
   - Exact inter-block backward fixed-point CFG liveness analysis with SSA Phi-edge semantics.
   - Loop-nesting-depth weighted spill heuristics (10^loop_depth / degree).
   - Biased Coloring register coalescing across `mov` and `phi` edges without increasing chromatic pressure.
2. Poletto-Sarkar O(N log N) Linear Scan Register Allocator (`LinearScanAllocator`)
   for ultra-low-latency JIT compilation.
"""

from typing import Dict, List, Set, Tuple, Optional, Any
import heapq
from compiler.ssa_ir import SSAFunction, BasicBlock, SSAInstruction, SSAVar


# Available General-Purpose x86-64 Physical Registers
PHYSICAL_REGISTERS = [
    "rax", "rcx", "rdx", "rbx", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
]

# Windows x64 ABI Caller-Saved (Volatile) vs Callee-Saved (Non-Volatile) Registers
WIN64_CALLER_SAVED = ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"]
WIN64_CALLEE_SAVED = ["rbx", "rsi", "rdi", "r12", "r13", "r14", "r15"]

# System V AMD64 ABI Caller-Saved vs Callee-Saved Registers
SYSV64_CALLER_SAVED = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]
SYSV64_CALLEE_SAVED = ["rbx", "r12", "r13", "r14", "r15"]

# ARM64 AAPCS64 Caller-Saved vs Callee-Saved General-Purpose Registers
ARM64_CALLER_SAVED = [f"x{i}" for i in range(0, 15)]
ARM64_CALLEE_SAVED = [f"x{i}" for i in range(19, 29)]

# ARM64 Allocatable Caller/Callee General-Purpose Registers
ARM64_PHYSICAL_REGISTERS = ARM64_CALLER_SAVED + ARM64_CALLEE_SAVED


class LiveRange:
    def __init__(self, var: SSAVar):
        self.var = var
        self.definitions: Set[int] = set()  # global linearized instruction indices
        self.uses: Set[int] = set()
        self.start: int = 10**9
        self.end: int = -1
        self.spill_cost: float = 0.0
        self.crosses_call: bool = False

    def record_def(self, pos: int, weight: float = 1.0):
        self.definitions.add(pos)
        if pos < self.start:
            self.start = pos
        if pos > self.end:
            self.end = pos
        self.spill_cost += weight

    def record_use(self, pos: int, weight: float = 1.0):
        self.uses.add(pos)
        if pos < self.start:
            self.start = pos
        if pos > self.end:
            self.end = pos
        self.spill_cost += weight

    def expand_span(self, lo: int, hi: int):
        if lo < self.start:
            self.start = lo
        if hi > self.end:
            self.end = hi

    def __repr__(self) -> str:
        return f"LiveRange({self.var}, [{self.start}, {self.end}], cost={self.spill_cost:.1f})"


class InterferenceGraph:
    """Undirected interference graph + move/phi affinity edges for biased coalescing."""

    def __init__(self):
        self.nodes: Set[SSAVar] = set()
        self.adj: Dict[SSAVar, Set[SSAVar]] = {}
        self.move_affinity: Dict[SSAVar, Set[SSAVar]] = {}

    def add_node(self, var: SSAVar):
        self.nodes.add(var)
        if var not in self.adj:
            self.adj[var] = set()
        if var not in self.move_affinity:
            self.move_affinity[var] = set()

    def add_interference(self, u: SSAVar, v: SSAVar):
        if u != v:
            self.add_node(u)
            self.add_node(v)
            self.adj[u].add(v)
            self.adj[v].add(u)

    def add_affinity(self, u: SSAVar, v: SSAVar):
        if u != v:
            self.add_node(u)
            self.add_node(v)
            self.move_affinity[u].add(v)
            self.move_affinity[v].add(u)

    def interferes(self, u: SSAVar, v: SSAVar) -> bool:
        return v in self.adj.get(u, set())

    def degree(self, node: SSAVar) -> int:
        return len(self.adj.get(node, set()))


class ChaitinBriggsAllocator:
    """
    Inter-block CFG Chaitin-Briggs Graph Coloring Register Allocator with
    SSA Phi-aware fixed-point liveness and Biased Coalescing.
    """

    def __init__(self, k_registers: Optional[List[str]] = None):
        self.registers = list(k_registers) if k_registers is not None else list(PHYSICAL_REGISTERS)
        self.k = len(self.registers)

    def compute_liveness(
        self, fn: SSAFunction
    ) -> Tuple[InterferenceGraph, Dict[SSAVar, LiveRange]]:
        """
        Performs exact backward dataflow liveness across multi-block CFGs with SSA Phi nodes
        and constructs the interference graph.
        """
        igraph = InterferenceGraph()
        ranges: Dict[SSAVar, LiveRange] = {}

        def ensure_var(v: SSAVar) -> LiveRange:
            igraph.add_node(v)
            if v not in ranges:
                ranges[v] = LiveRange(v)
            return ranges[v]

        # Assign linearized global positions to every block & instruction
        block_span: Dict[str, Tuple[int, int]] = {}
        phi_defs: Dict[str, Set[SSAVar]] = {}
        phi_uses_from_pred: Dict[Tuple[str, str], Set[SSAVar]] = {}
        block_use: Dict[str, Set[SSAVar]] = {}
        block_def: Dict[str, Set[SSAVar]] = {}

        pos = 0
        for block in fn.blocks:
            b_start = pos
            weight = float(10 ** min(block.loop_depth, 4))
            p_defs: Set[SSAVar] = set()

            for phi in block.phi_nodes:
                if phi.result is not None:
                    p_defs.add(phi.result)
                    ensure_var(phi.result).record_def(pos, weight)
                if phi.phi_incoming:
                    for pred_name, op in phi.phi_incoming:
                        if isinstance(op, SSAVar):
                            ensure_var(op).record_use(pos, weight)
                            phi_uses_from_pred.setdefault((block.name, pred_name), set()).add(op)
                            if phi.result is not None:
                                igraph.add_affinity(phi.result, op)
                else:
                    for op in phi.operands:
                        if isinstance(op, SSAVar):
                            ensure_var(op).record_use(pos, weight)
                            for pred in block.predecessors:
                                phi_uses_from_pred.setdefault((block.name, pred.name), set()).add(op)
                            if phi.result is not None:
                                igraph.add_affinity(phi.result, op)
            phi_defs[block.name] = p_defs
            pos += 1

            uses: Set[SSAVar] = set()
            defs: Set[SSAVar] = set(p_defs)

            for inst in block.instructions:
                for op in inst.operands:
                    if isinstance(op, SSAVar):
                        ensure_var(op).record_use(pos, weight)
                        if op not in defs:
                            uses.add(op)
                if inst.result is not None:
                    ensure_var(inst.result).record_def(pos, weight)
                    defs.add(inst.result)
                    if inst.opcode == "mov" and len(inst.operands) == 1 and isinstance(inst.operands[0], SSAVar):
                        igraph.add_affinity(inst.result, inst.operands[0])
                pos += 1

            block_use[block.name] = uses
            block_def[block.name] = defs
            block_span[block.name] = (b_start, max(b_start, pos - 1))

        # Fixed-point backward dataflow equations:
        #   LiveOut[B] = U_{S in succ(B)} ( (LiveIn[S] \ PhiDefs[S]) U PhiUses(S, from B) )
        #   LiveIn[B]  = Use[B] U (LiveOut[B] \ Def[B]) U PhiDefs[B]
        live_in: Dict[str, Set[SSAVar]] = {b.name: set() for b in fn.blocks}
        live_out: Dict[str, Set[SSAVar]] = {b.name: set() for b in fn.blocks}

        changed = True
        while changed:
            changed = False
            for block in reversed(fn.blocks):
                bname = block.name
                new_out: Set[SSAVar] = set()
                for succ in block.successors:
                    sname = succ.name
                    succ_non_phi_in = live_in.get(sname, set()) - phi_defs.get(sname, set())
                    succ_phi_use = phi_uses_from_pred.get((sname, bname), set())
                    new_out |= succ_non_phi_in | succ_phi_use

                new_in = (
                    block_use[bname]
                    | (new_out - block_def[bname])
                    | phi_defs[bname]
                )

                if new_out != live_out[bname] or new_in != live_in[bname]:
                    live_out[bname] = new_out
                    live_in[bname] = new_in
                    changed = True

        # Expand LiveRange intervals for any variable live across a full basic block
        for block in fn.blocks:
            b_lo, b_hi = block_span[block.name]
            for v in live_in[block.name]:
                ranges[v].expand_span(b_lo, b_lo)
            for v in live_out[block.name]:
                ranges[v].expand_span(b_hi, b_hi)
            for v in live_in[block.name] & live_out[block.name]:
                ranges[v].expand_span(b_lo, b_hi)

        # Exact instruction-level backward sweep per block to build InterferenceGraph
        live_across_call: Set[SSAVar] = set()
        for block in fn.blocks:
            bname = block.name
            live: Set[SSAVar] = set(live_out[bname])

            for inst in reversed(block.instructions):
                is_copy = (
                    inst.opcode == "mov"
                    and len(inst.operands) == 1
                    and isinstance(inst.operands[0], SSAVar)
                )
                copy_src = inst.operands[0] if is_copy else None

                # Any variable live right after a call (except the call's own return value)
                # must survive across the call boundary (requires callee-saved register or spill).
                if inst.opcode == "call":
                    for v in live:
                        if v != inst.result:
                            live_across_call.add(v)
                            ranges[v].crosses_call = True

                if inst.result is not None:
                    for v in live:
                        if v != inst.result and v != copy_src:
                            igraph.add_interference(inst.result, v)
                    live.discard(inst.result)

                for op in inst.operands:
                    if isinstance(op, SSAVar):
                        live.add(op)

            # Phi definitions at top of block are simultaneously defined
            p_list = [phi.result for phi in block.phi_nodes if phi.result is not None]
            for i, p1 in enumerate(p_list):
                for p2 in p_list[i + 1:]:
                    igraph.add_interference(p1, p2)
                for v in live:
                    if v not in phi_defs[bname]:
                        igraph.add_interference(p1, v)

        self._last_live_in = live_in
        self._last_live_out = live_out
        self._last_live_across_call = live_across_call
        return igraph, ranges

    def allocate(self, fn: SSAFunction) -> Dict[str, Any]:
        """
        Runs Chaitin-Briggs Graph Coloring with Loop-Weighted Spill Heuristics
        and Biased Register Coalescing.
        """
        self._last_live_in = {}
        self._last_live_out = {}
        self._last_live_across_call = set()
        igraph, ranges = self.compute_liveness(fn)

        adj_copy = {u: set(neighbors) for u, neighbors in igraph.adj.items()}
        nodes_to_process = set(igraph.nodes)
        select_stack: List[Tuple[SSAVar, bool]] = []
        potential_spills: Set[SSAVar] = set()

        # Step 1: Kempe Simplification + Optimistic Briggs Spill Push
        while nodes_to_process:
            low_degree_node = None
            # Deterministic ordering by variable name/version
            for node in sorted(nodes_to_process, key=lambda v: (v.name, v.version)):
                if len(adj_copy[node]) < self.k:
                    low_degree_node = node
                    break

            if low_degree_node is not None:
                nodes_to_process.remove(low_degree_node)
                select_stack.append((low_degree_node, False))
                for neighbor in adj_copy[low_degree_node]:
                    if neighbor in adj_copy:
                        adj_copy[neighbor].discard(low_degree_node)
            else:
                # Optimistic Briggs Spill: push lowest spill_cost / degree onto stack anyway
                # so it still gets a chance at coloring in Step 2!
                spill_candidate = min(
                    nodes_to_process,
                    key=lambda n: (
                        ranges[n].spill_cost / max(1, len(adj_copy[n])),
                        n.name,
                        n.version,
                    ),
                )
                nodes_to_process.remove(spill_candidate)
                potential_spills.add(spill_candidate)
                select_stack.append((spill_candidate, True))
                for neighbor in adj_copy[spill_candidate]:
                    if neighbor in adj_copy:
                        adj_copy[neighbor].discard(spill_candidate)

        # Step 2: Biased Coloring (Pop from stack, prefer affinity partner's color if free)
        color_map: Dict[SSAVar, str] = {}
        actual_spills: Set[SSAVar] = set()
        coalesced_moves = 0

        while select_stack:
            node, _was_potential = select_stack.pop()
            used_colors = {
                color_map[nbr]
                for nbr in igraph.adj.get(node, set())
                if nbr in color_map
            }

            assigned_color = None
            # Biased coalescing: check if any move/phi partner already has an available color
            for partner in sorted(igraph.move_affinity.get(node, set()), key=lambda v: (v.name, v.version)):
                if partner in color_map and color_map[partner] not in used_colors:
                    assigned_color = color_map[partner]
                    coalesced_moves += 1
                    break

            if assigned_color is None:
                for reg in self.registers:
                    if reg not in used_colors:
                        assigned_color = reg
                        break

            if assigned_color is not None:
                color_map[node] = assigned_color
            else:
                actual_spills.add(node)

        spill_slots: Dict[SSAVar, int] = {}
        for idx, spilled in enumerate(sorted(actual_spills, key=lambda v: (v.name, v.version))):
            spill_slots[spilled] = -8 * (idx + 1)

        return {
            "success": len(actual_spills) == 0,
            "total_vars": len(igraph.nodes),
            "allocated_colors": {str(var): reg for var, reg in color_map.items()},
            "color_map": color_map,
            "spills_count": len(actual_spills),
            "spill_slots": {str(var): slot for var, slot in spill_slots.items()},
            "spill_slot_vars": spill_slots,
            "coalesced_moves": coalesced_moves,
            "k_registers": self.k,
            "live_across_call": sorted(str(v) for v in self._last_live_across_call),
            "live_in": {k: [str(v) for v in vs] for k, vs in self._last_live_in.items()},
            "live_out": {k: [str(v) for v in vs] for k, vs in self._last_live_out.items()},
        }


class IteratedRegisterCoalescingAllocator:
    """
    George & Appel (1996) Iterated Register Coalescing (IRC) Graph Coloring Allocator
    with ABI Caller-Saved vs. Callee-Saved Register Partitioning across Call Boundaries.

    Phases:
      1. Build: Exact CFG backward liveness, InterferenceGraph, MoveWorklists, and `live_across_call`.
      2. Simplify: Remove low-degree (< K) non-move-related nodes onto SelectStack.
      3. Coalesce: Conservatively merge move-related pairs (u, v) satisfying Briggs or George criterion.
      4. Freeze: Give up coalescing on a low-degree move-related node when Simplify & Coalesce stall.
      5. SelectSpill: Optimistically push loop-depth-weighted lowest `spill_cost / degree` high-degree node.
      6. AssignColors: Partition physical registers by ABI call-preservation (`callee_saved` for
         variables live across calls; `caller_saved` for short-lived temporaries).
    """

    def __init__(
        self,
        k_registers: Optional[List[str]] = None,
        abi: str = "win64",
        caller_saved: Optional[List[str]] = None,
        callee_saved: Optional[List[str]] = None,
    ):
        self.abi = abi.lower()
        if self.abi in ("arm64", "aarch64"):
            default_regs = ARM64_PHYSICAL_REGISTERS
            default_caller = ARM64_CALLER_SAVED
            default_callee = ARM64_CALLEE_SAVED
        elif self.abi in ("sysv64", "sysv", "linux", "macos"):
            default_regs = PHYSICAL_REGISTERS
            default_caller = SYSV64_CALLER_SAVED
            default_callee = SYSV64_CALLEE_SAVED
        else:
            default_regs = PHYSICAL_REGISTERS
            default_caller = WIN64_CALLER_SAVED
            default_callee = WIN64_CALLEE_SAVED

        self.registers = list(k_registers) if k_registers is not None else list(default_regs)
        self.k = len(self.registers)

        if caller_saved is not None and callee_saved is not None:
            self.caller_saved = [r for r in caller_saved if r in self.registers]
            self.callee_saved = [r for r in callee_saved if r in self.registers]
        else:
            self.caller_saved = [r for r in default_caller if r in self.registers]
            self.callee_saved = [r for r in default_callee if r in self.registers]
            # Any custom test registers (e.g. ["r0", "r1", "r2"]) not in standard ABI tables:
            # partition first half as caller-saved and second half as callee-saved if neither matched
            unclassified = [
                r for r in self.registers
                if r not in self.caller_saved and r not in self.callee_saved
            ]
            if unclassified:
                if not self.caller_saved and not self.callee_saved:
                    mid = max(1, len(unclassified) // 2)
                    self.caller_saved = unclassified[:mid]
                    self.callee_saved = unclassified[mid:]
                else:
                    self.caller_saved.extend(unclassified)

    @staticmethod
    def briggs_criterion(
        u: SSAVar,
        v: SSAVar,
        adj: Dict[SSAVar, Set[SSAVar]],
        k: int,
    ) -> bool:
        """
        Briggs Conservative Coalescing Criterion:
        Nodes u and v can be coalesced if the resulting combined node uv will have
        fewer than K neighbors of significant degree (degree >= K).
        """
        combined_neighbors = (adj.get(u, set()) | adj.get(v, set())) - {u, v}
        significant_count = 0
        for n in combined_neighbors:
            n_adj = adj.get(n, set())
            # If n was adjacent to BOTH u and v, merging u and v reduces n's degree by 1
            effective_deg = len(n_adj) - (1 if (u in n_adj and v in n_adj) else 0)
            if effective_deg >= k:
                significant_count += 1
        return significant_count < k

    @staticmethod
    def george_criterion(
        u: SSAVar,
        v: SSAVar,
        adj: Dict[SSAVar, Set[SSAVar]],
        k: int,
    ) -> bool:
        """
        George Conservative Coalescing Criterion:
        Nodes u and v can be coalesced if for every neighbor t of v, either t already
        interferes with u or t has insignificant degree (degree < K).
        """
        u_neighbors = adj.get(u, set())
        for t in adj.get(v, set()):
            if t == u:
                continue
            if t not in u_neighbors and len(adj.get(t, set())) >= k:
                return False
        return True

    def allocate(self, fn: SSAFunction, ignore_vars: Optional[Set[SSAVar]] = None) -> Dict[str, Any]:
        cb = ChaitinBriggsAllocator(self.registers)
        igraph, ranges = cb.compute_liveness(fn)
        if ignore_vars:
            for iv in ignore_vars:
                igraph.nodes.discard(iv)
                igraph.adj.pop(iv, None)
                igraph.move_affinity.pop(iv, None)
                ranges.pop(iv, None)
            for nbrs in igraph.adj.values():
                nbrs.difference_update(ignore_vars)
            for affs in igraph.move_affinity.values():
                affs.difference_update(ignore_vars)
        live_across_call: Set[SSAVar] = set(cb._last_live_across_call) - (ignore_vars or set())

        # Active interference adjacency map (mutated during Simplify/Coalesce)
        adj: Dict[SSAVar, Set[SSAVar]] = {u: set(nbrs) for u, nbrs in igraph.adj.items()}
        # Complete interference adjacency map (retains edges for AssignColors)
        full_adj: Dict[SSAVar, Set[SSAVar]] = {u: set(nbrs) for u, nbrs in igraph.adj.items()}

        # Canonicalize move pairs (u, v) with deterministic ordering
        def canon_move(a: SSAVar, b: SSAVar) -> Tuple[SSAVar, SSAVar]:
            return (a, b) if (a.name, a.version) <= (b.name, b.version) else (b, a)

        move_list: Dict[SSAVar, Set[Tuple[SSAVar, SSAVar]]] = {u: set() for u in igraph.nodes}
        worklist_moves: Set[Tuple[SSAVar, SSAVar]] = set()

        for u, partners in igraph.move_affinity.items():
            for v in partners:
                if u != v:
                    m = canon_move(u, v)
                    worklist_moves.add(m)
                    move_list[u].add(m)
                    move_list[v].add(m)

        active_moves: Set[Tuple[SSAVar, SSAVar]] = set()
        coalesced_moves: List[Tuple[SSAVar, SSAVar]] = []
        constrained_moves: List[Tuple[SSAVar, SSAVar]] = []
        frozen_moves: List[Tuple[SSAVar, SSAVar]] = []

        simplify_worklist: Set[SSAVar] = set()
        freeze_worklist: Set[SSAVar] = set()
        spill_worklist: Set[SSAVar] = set()

        coalesced_nodes: Set[SSAVar] = set()
        select_stack: List[SSAVar] = []
        select_stack_set: Set[SSAVar] = set()
        alias: Dict[SSAVar, SSAVar] = {u: u for u in igraph.nodes}

        def get_alias(n: SSAVar) -> SSAVar:
            curr = n
            while curr in coalesced_nodes and alias.get(curr, curr) != curr:
                curr = alias[curr]
            return curr

        def node_moves(n: SSAVar) -> Set[Tuple[SSAVar, SSAVar]]:
            return move_list.get(n, set()) & (active_moves | worklist_moves)

        def move_related(n: SSAVar) -> bool:
            return len(node_moves(n)) > 0

        def adjacent(n: SSAVar) -> Set[SSAVar]:
            return adj.get(n, set()) - (select_stack_set | coalesced_nodes)

        def degree(n: SSAVar) -> int:
            return len(adjacent(n))

        # MakeWorklist
        for n in igraph.nodes:
            if degree(n) >= self.k:
                spill_worklist.add(n)
            elif move_related(n):
                freeze_worklist.add(n)
            else:
                simplify_worklist.add(n)

        def enable_moves(nodes: Set[SSAVar]):
            for n in nodes:
                for m in list(node_moves(n)):
                    if m in active_moves:
                        active_moves.remove(m)
                        worklist_moves.add(m)

        def decrement_degree(m: SSAVar):
            # Called right after removing a neighbor of m
            if m in spill_worklist and degree(m) < self.k:
                spill_worklist.remove(m)
                enable_moves({m} | adjacent(m))
                if move_related(m):
                    freeze_worklist.add(m)
                else:
                    simplify_worklist.add(m)

        def add_work_list(u: SSAVar):
            if u not in coalesced_nodes and u not in select_stack_set:
                if degree(u) < self.k and not move_related(u):
                    freeze_worklist.discard(u)
                    simplify_worklist.add(u)

        def freeze_moves(u: SSAVar):
            for m in list(node_moves(u)):
                x, y = m
                if get_alias(y) == get_alias(u):
                    v = get_alias(x)
                else:
                    v = get_alias(y)
                active_moves.discard(m)
                worklist_moves.discard(m)
                frozen_moves.append(m)
                if v in freeze_worklist and not move_related(v) and degree(v) < self.k:
                    freeze_worklist.remove(v)
                    simplify_worklist.add(v)

        def combine(u: SSAVar, v: SSAVar):
            if v in freeze_worklist:
                freeze_worklist.remove(v)
            else:
                spill_worklist.discard(v)
            coalesced_nodes.add(v)
            alias[v] = u
            move_list[u] |= move_list.get(v, set())
            enable_moves({v})

            if v in live_across_call:
                live_across_call.add(u)
                ranges[u].crosses_call = True
            ranges[u].spill_cost += ranges[v].spill_cost

            for t in list(adjacent(v)):
                adj[u].add(t)
                adj[t].add(u)
                full_adj[u].add(t)
                full_adj[t].add(u)
                adj[t].discard(v)
                decrement_degree(t)
            adj[v].clear()

            if degree(u) >= self.k and u in freeze_worklist:
                freeze_worklist.remove(u)
                spill_worklist.add(u)

        # Main George & Appel Iterated Loop
        while simplify_worklist or worklist_moves or freeze_worklist or spill_worklist:
            if simplify_worklist:
                n = min(simplify_worklist, key=lambda v: (v.name, v.version))
                simplify_worklist.remove(n)
                select_stack.append(n)
                select_stack_set.add(n)
                nbrs = list(adjacent(n))
                for m in nbrs:
                    adj[m].discard(n)
                    decrement_degree(m)
                adj[n].clear()

            elif worklist_moves:
                m = min(worklist_moves, key=lambda pair: (pair[0].name, pair[0].version, pair[1].name, pair[1].version))
                worklist_moves.remove(m)
                x = get_alias(m[0])
                y = get_alias(m[1])
                u, v = (x, y) if (x.name, x.version) <= (y.name, y.version) else (y, x)

                if u == v:
                    coalesced_moves.append(m)
                    add_work_list(u)
                elif v in adj.get(u, set()) or v in full_adj.get(u, set()):
                    constrained_moves.append(m)
                    add_work_list(u)
                    add_work_list(v)
                elif (
                    self.briggs_criterion(u, v, adj, self.k)
                    or self.george_criterion(u, v, adj, self.k)
                    or self.george_criterion(v, u, adj, self.k)
                ):
                    coalesced_moves.append(m)
                    combine(u, v)
                    add_work_list(u)
                else:
                    active_moves.add(m)

            elif freeze_worklist:
                u = min(freeze_worklist, key=lambda v: (v.name, v.version))
                freeze_worklist.remove(u)
                simplify_worklist.add(u)
                freeze_moves(u)

            elif spill_worklist:
                m = min(
                    spill_worklist,
                    key=lambda n: (
                        ranges[n].spill_cost / max(1, degree(n)),
                        n.name,
                        n.version,
                    ),
                )
                spill_worklist.remove(m)
                simplify_worklist.add(m)
                freeze_moves(m)

        # Step 6: AssignColors with ABI Caller-Saved vs. Callee-Saved Partitioning
        color_map: Dict[SSAVar, str] = {}
        spilled_nodes: Set[SSAVar] = set()

        while select_stack:
            n = select_stack.pop()
            select_stack_set.discard(n)
            used_colors = {
                color_map[get_alias(w)]
                for w in full_adj.get(n, set())
                if get_alias(w) in color_map
            }

            # Partition preference:
            # Variables live across calls prefer callee-saved (non-volatile) registers;
            # Variables NOT live across calls prefer caller-saved (volatile) registers.
            if n in live_across_call:
                preferred_order = self.callee_saved + [r for r in self.caller_saved if r not in self.callee_saved]
            else:
                preferred_order = self.caller_saved + [r for r in self.callee_saved if r not in self.caller_saved]

            assigned_color = None
            for reg in preferred_order:
                if reg not in used_colors:
                    assigned_color = reg
                    break

            if assigned_color is not None:
                color_map[n] = assigned_color
            else:
                spilled_nodes.add(n)

        # Propagate colors (or spills) to coalesced nodes
        for n in sorted(coalesced_nodes, key=lambda v: (v.name, v.version)):
            rep = get_alias(n)
            if rep in color_map:
                color_map[n] = color_map[rep]
            else:
                spilled_nodes.add(n)

        spill_slots: Dict[SSAVar, int] = {}
        for idx, spilled in enumerate(sorted(spilled_nodes, key=lambda v: (v.name, v.version))):
            spill_slots[spilled] = -8 * (idx + 1)

        used_regs = set(color_map.values())
        callee_saved_used = [r for r in self.callee_saved if r in used_regs]
        caller_saved_used = [r for r in self.caller_saved if r in used_regs]

        return {
            "success": len(spilled_nodes) == 0,
            "allocator": "GeorgeAppelIRC",
            "abi": self.abi,
            "total_vars": len(igraph.nodes),
            "allocated_colors": {str(var): reg for var, reg in color_map.items()},
            "color_map": color_map,
            "spills_count": len(spilled_nodes),
            "spill_slots": {str(var): slot for var, slot in spill_slots.items()},
            "spill_slot_vars": spill_slots,
            "coalesced_moves": len(coalesced_moves),
            "coalesced_pairs": [(str(u), str(v)) for u, v in coalesced_moves],
            "coalesced_into": {str(v): str(get_alias(v)) for v in coalesced_nodes},
            "constrained_moves": len(constrained_moves),
            "frozen_moves": len(frozen_moves),
            "live_across_call": sorted(str(v) for v in live_across_call),
            "callee_saved_used": callee_saved_used,
            "caller_saved_used": caller_saved_used,
            "k_registers": self.k,
            "live_in": {k: [str(v) for v in vs] for k, vs in cb._last_live_in.items()},
            "live_out": {k: [str(v) for v in vs] for k, vs in cb._last_live_out.items()},
        }


IRCAllocator = IteratedRegisterCoalescingAllocator


class LinearScanAllocator:
    """
    Poletto & Sarkar O(N log N) Linear Scan Register Allocator for fast JIT lowering.
    """

    def __init__(self, k_registers: Optional[List[str]] = None):
        self.registers = list(k_registers) if k_registers is not None else list(PHYSICAL_REGISTERS)
        self.k = len(self.registers)

    def allocate(self, fn: SSAFunction) -> Dict[str, Any]:
        cb = ChaitinBriggsAllocator(self.registers)
        _, ranges = cb.compute_liveness(fn)

        intervals = sorted(ranges.values(), key=lambda r: (r.start, r.end, r.var.name, r.var.version))
        # Min-heap of active intervals keyed by (end_point, reg_idx, var_name, var_version, LiveRange)
        active: List[Tuple[int, int, str, int, LiveRange]] = []
        free_reg_indices = list(range(self.k))
        heapq.heapify(free_reg_indices)

        color_map: Dict[SSAVar, str] = {}
        spilled_vars: List[SSAVar] = []

        for current in intervals:
            # Expire old intervals whose end < current.start
            while active and active[0][0] < current.start:
                _end, freed_idx, _vn, _vv, _rng = heapq.heappop(active)
                heapq.heappush(free_reg_indices, freed_idx)

            if not free_reg_indices:
                # Spill the interval with the furthest end point
                furthest = max(active, key=lambda item: item[0])
                if furthest[0] > current.end:
                    active.remove(furthest)
                    heapq.heapify(active)
                    stolen_idx = furthest[1]
                    spilled_var = furthest[4].var
                    color_map.pop(spilled_var, None)
                    spilled_vars.append(spilled_var)
                    color_map[current.var] = self.registers[stolen_idx]
                    heapq.heappush(active, (current.end, stolen_idx, current.var.name, current.var.version, current))
                else:
                    spilled_vars.append(current.var)
            else:
                reg_idx = heapq.heappop(free_reg_indices)
                color_map[current.var] = self.registers[reg_idx]
                heapq.heappush(active, (current.end, reg_idx, current.var.name, current.var.version, current))

        spill_slots = {v: -8 * (i + 1) for i, v in enumerate(spilled_vars)}
        return {
            "success": len(spilled_vars) == 0,
            "allocator": "PolettoSarkarLinearScan",
            "total_vars": len(ranges),
            "allocated_colors": {str(v): r for v, r in color_map.items()},
            "color_map": color_map,
            "spills_count": len(spilled_vars),
            "spill_slots": {str(v): s for v, s in spill_slots.items()},
            "spill_slot_vars": spill_slots,
            "k_registers": self.k,
        }
