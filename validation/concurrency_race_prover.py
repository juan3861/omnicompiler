"""
Alpha-C99: Z3 SMT Happens-Before Concurrency Data-Race & Deadlock Prover (`validation/concurrency_race_prover.py`).

Uses Microsoft Z3 (`z3.Solver`) to mathematically prove or refute with exact counterexamples:
1. Shared-memory data races (conflicting non-atomic reads/writes lacking a transitive Lamport Happens-Before path or common mutex discipline).
2. Lock-order inversion deadlocks (cyclic acquisition graph in Z3 integer rank ordering).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    z3 = None
    Z3_AVAILABLE = False


@dataclass
class MemoryEvent:
    event_id: str
    thread_id: str
    location: str
    is_write: bool
    is_atomic: bool = False
    locks_held: Tuple[str, ...] = ()
    hb_after: Tuple[str, ...] = ()  # explicit prior event_ids (program order / fork / join / unlock->lock)


@dataclass
class ConcurrencyProofReport:
    race_free_proven: bool
    deadlock_free_proven: bool
    detected_races: List[Dict[str, Any]] = field(default_factory=list)
    deadlock_cycles: List[List[str]] = field(default_factory=list)
    solver_engine: str = "z3_smt"


class ConcurrencyRaceProver:
    """
    Formal Z3 SMT verifier for concurrent event traces & multi-threaded lock graphs.
    """

    def verify(
        self,
        events: Sequence[MemoryEvent],
        lock_acquisitions: Optional[Sequence[Tuple[str, Sequence[str]]]] = None,
    ) -> ConcurrencyProofReport:
        if not Z3_AVAILABLE:
            raise RuntimeError("z3-solver is required for ConcurrencyRaceProver")

        ev_list = list(events)
        ev_by_id = {e.event_id: e for e in ev_list}

        # 1. Happens-Before SMT Clock Solver:
        # Collect transitive closure of program-order (sequence per thread_id) + explicit hb_after edges.
        preds: Dict[str, set] = {e.event_id: set(e.hb_after) for e in ev_list}
        last_by_thread: Dict[str, str] = {}
        for e in ev_list:
            if e.thread_id in last_by_thread:
                preds[e.event_id].add(last_by_thread[e.thread_id])
            last_by_thread[e.thread_id] = e.event_id

        # Check Happens-Before feasibility and transitive ordering via Z3 Int timestamps `ts[id]`
        # Plus pairwise reachability probe: `e1 -hb-> e2` holds iff adding `(ts[e1] >= ts[e2])` makes HB UNSAT.
        base_constraints = []
        ts_vars = {e.event_id: z3.Int(f"ts_{idx}") for idx, e in enumerate(ev_list)}
        for idx, e in enumerate(ev_list):
            base_constraints.append(ts_vars[e.event_id] >= 0)
            for p_id in preds[e.event_id]:
                if p_id in ts_vars:
                    base_constraints.append(ts_vars[p_id] < ts_vars[e.event_id])

        def _hb_ordered(a_id: str, b_id: str) -> bool:
            s = z3.Solver()
            s.add(base_constraints)
            # Can a_id happen AT OR AFTER b_id? If UNSAT, a_id MUST precede b_id in every HB schedule.
            s.add(ts_vars[a_id] >= ts_vars[b_id])
            return s.check() == z3.unsat

        races: List[Dict[str, Any]] = []
        n = len(ev_list)
        for i in range(n):
            e1 = ev_list[i]
            if e1.is_atomic:
                continue
            for j in range(i + 1, n):
                e2 = ev_list[j]
                if e2.is_atomic:
                    continue
                if e1.thread_id == e2.thread_id or e1.location != e2.location:
                    continue
                if not (e1.is_write or e2.is_write):
                    continue
                if set(e1.locks_held) & set(e2.locks_held):
                    continue
                # Ask Z3 whether an interleaving exists where neither HB(e1, e2) nor HB(e2, e1) holds
                if not (_hb_ordered(e1.event_id, e2.event_id) or _hb_ordered(e2.event_id, e1.event_id)):
                    s_wit = z3.Solver()
                    s_wit.add(base_constraints)
                    # Witness simultaneous logical execution slot if possible, or arbitrary witness order
                    s_wit.add(ts_vars[e1.event_id] == ts_vars[e2.event_id])
                    if s_wit.check() == z3.sat:
                        m = s_wit.model()
                        witness = {e1.event_id: m[ts_vars[e1.event_id]].as_long(), e2.event_id: m[ts_vars[e2.event_id]].as_long()}
                    else:
                        witness = {}
                    races.append({
                        "event_a": e1.event_id,
                        "event_b": e2.event_id,
                        "thread_a": e1.thread_id,
                        "thread_b": e2.thread_id,
                        "location": e1.location,
                        "witness_timestamps": witness,
                    })

        # 2. Z3 Lock-Order Rank Consistency Solver (Deadlock Freedom Proof)
        deadlocks: List[List[str]] = []
        lock_rank_solver = z3.Solver()
        all_locks: List[str] = []
        edges: List[Tuple[str, str, str]] = []  # (thread_id, outer_lock, inner_lock)

        for seq_idx, (tid, stack) in enumerate(lock_acquisitions or []):
            for lk in stack:
                if lk not in all_locks:
                    all_locks.append(lk)
            for k in range(len(stack) - 1):
                edges.append((str(tid), stack[k], stack[k + 1]))

        lock_ranks = {lk: z3.Int(f"rank_{lk}") for lk in all_locks}
        for _, l1, l2 in edges:
            lock_rank_solver.add(lock_ranks[l1] < lock_ranks[l2])

        deadlock_free = True
        if edges and lock_rank_solver.check() == z3.unsat:
            deadlock_free = False
            # Extract minimal cycle from lock edges for diagnostic counterexample
            adj: Dict[str, List[str]] = {}
            for _, u, v in edges:
                adj.setdefault(u, []).append(v)
            visited: set = set()
            stack_path: List[str] = []

            def _dfs(node: str) -> Optional[List[str]]:
                visited.add(node)
                stack_path.append(node)
                for nxt in adj.get(node, []):
                    if nxt in stack_path:
                        idx_c = stack_path.index(nxt)
                        return stack_path[idx_c:] + [nxt]
                    if nxt not in visited:
                        res_c = _dfs(nxt)
                        if res_c:
                            return res_c
                stack_path.pop()
                return None

            for start_l in all_locks:
                cyc = _dfs(start_l)
                if cyc:
                    deadlocks.append(cyc)
                    break

        return ConcurrencyProofReport(
            race_free_proven=(len(races) == 0),
            deadlock_free_proven=deadlock_free,
            detected_races=races,
            deadlock_cycles=deadlocks,
            solver_engine="z3_smt",
        )
