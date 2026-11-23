"""
Profile-Guided Optimization (PGO) Profiler & Hot/Cold Optimizer (Alpha-C91).

Executes lightweight deterministic SSA trace sampling to measure basic-block execution
frequencies, branch bias, and loop trip counts, driving:
1. Dynamic unroll-factor calibration (4x vs 8x for compact hot loops without division/calls).
2. `BlockLayoutPass` hot-fallthrough / cold-exit basic-block ordering.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from compiler.ssa_ir import BasicBlock, SSAFunction, SSAVar
from compiler.tco_and_layout import BlockLayoutPass


@dataclass
class PGOProfile:
    function_name: str
    block_counts: Dict[str, int] = field(default_factory=dict)
    edge_counts: Dict[Tuple[str, str], int] = field(default_factory=dict)
    loop_trip_estimates: Dict[str, int] = field(default_factory=dict)
    recommended_unroll: int = 4
    total_steps_sampled: int = 0


def _to_i64(x: int) -> int:
    u = int(x) & 0xFFFFFFFFFFFFFFFF
    return u - (1 << 64) if u >= (1 << 63) else u


class ProfileGuidedOptimizer:
    """
    Collects deterministic execution counts over Omni-SSA CFGs and applies
    profile-guided hot/cold block layout and unrolling hints.
    """

    def __init__(self, max_trace_steps: int = 4096):
        self.max_trace_steps = max_trace_steps

    def collect_ssa_profile(
        self,
        fn: SSAFunction,
        sample_inputs: Optional[List[Tuple[int, ...]]] = None,
    ) -> PGOProfile:
        prof = PGOProfile(function_name=fn.name)
        if not fn.blocks:
            return prof

        inputs = sample_inputs or [
            tuple(64 if i == 0 else (3 if i == 1 else i + 1) for i in range(len(fn.params)))
        ]
        blk_map = {b.name: b for b in fn.blocks}
        entry = fn.entry_block or fn.blocks[0]

        for vec in inputs:
            env: Dict[SSAVar, int] = {}
            for i, p_name in enumerate(fn.params):
                if i < len(vec):
                    env[SSAVar(p_name, 0)] = int(vec[i])

            def eval_v(op: Any) -> Optional[int]:
                if isinstance(op, bool):
                    return int(op)
                if isinstance(op, int):
                    return int(op)
                if isinstance(op, SSAVar):
                    return env.get(op, 0)
                return None

            cur_blk: Optional[BasicBlock] = entry
            prev_name: Optional[str] = None
            steps = 0
            while cur_blk is not None and steps < self.max_trace_steps:
                steps += 1
                prof.block_counts[cur_blk.name] = prof.block_counts.get(cur_blk.name, 0) + 1
                if prev_name is not None:
                    ekey = (prev_name, cur_blk.name)
                    prof.edge_counts[ekey] = prof.edge_counts.get(ekey, 0) + 1

                if prev_name is not None:
                    phi_updates: List[Tuple[SSAVar, int]] = []
                    for phi in cur_blk.phi_nodes:
                        if phi.result is None:
                            continue
                        val = None
                        for b_n, v_op in phi.phi_incoming:
                            if b_n == prev_name:
                                val = eval_v(v_op)
                                break
                        if val is None and phi.operands:
                            val = eval_v(phi.operands[0])
                        phi_updates.append((phi.result, int(val or 0)))
                    for p_var, p_val in phi_updates:
                        env[p_var] = p_val

                next_blk: Optional[BasicBlock] = None
                aborted = False
                for inst in cur_blk.instructions:
                    op = inst.opcode
                    if op == "param":
                        if inst.result is not None and inst.operands:
                            raw_p = inst.operands[0]
                            idx = raw_p if isinstance(raw_p, int) else (fn.params.index(raw_p) if raw_p in fn.params else 0)
                            if idx < len(vec):
                                env[inst.result] = int(vec[idx])
                    elif op == "const" and inst.result is not None:
                        val = inst.operands[0]
                        if isinstance(val, (int, bool)):
                            env[inst.result] = int(val)
                        else:
                            aborted = True
                            break
                    elif op == "mov" and inst.result is not None:
                        v = eval_v(inst.operands[0])
                        env[inst.result] = 0 if v is None else v
                    elif op in ("neg", "not") and inst.result is not None:
                        v = eval_v(inst.operands[0]) or 0
                        env[inst.result] = _to_i64(-v if op == "neg" else ~v)
                    elif op in (
                        "add", "sub", "mul", "sdiv", "div", "srem",
                        "shl", "shr", "sar", "lshr", "and", "or", "xor",
                        "cmp_eq", "cmp_ne", "cmp_lt", "cmp_le", "cmp_gt", "cmp_ge",
                    ) and inst.result is not None:
                        a = eval_v(inst.operands[0]) or 0
                        b = eval_v(inst.operands[1]) or 0
                        if op == "add":
                            r = _to_i64(a + b)
                        elif op == "sub":
                            r = _to_i64(a - b)
                        elif op == "mul":
                            r = _to_i64(a * b)
                        elif op in ("sdiv", "div"):
                            if b == 0:
                                aborted = True
                                break
                            q = abs(a) // abs(b)
                            r = -q if (a < 0) ^ (b < 0) else q
                        elif op == "srem":
                            if b == 0:
                                aborted = True
                                break
                            q = abs(a) // abs(b)
                            sq = -q if (a < 0) ^ (b < 0) else q
                            r = _to_i64(a - sq * b)
                        elif op == "shl":
                            r = _to_i64(a << (b & 63))
                        elif op in ("shr", "sar"):
                            r = _to_i64(a >> (b & 63))
                        elif op == "lshr":
                            r = _to_i64((a & 0xFFFFFFFFFFFFFFFF) >> (b & 63))
                        elif op == "and":
                            r = _to_i64(a & b)
                        elif op == "or":
                            r = _to_i64(a | b)
                        elif op == "xor":
                            r = _to_i64(a ^ b)
                        else:
                            cmps = {
                                "cmp_eq": a == b, "cmp_ne": a != b,
                                "cmp_lt": a < b, "cmp_le": a <= b,
                                "cmp_gt": a > b, "cmp_ge": a >= b,
                            }
                            r = int(cmps[op])
                        env[inst.result] = r
                    elif op == "select" and inst.result is not None:
                        c = eval_v(inst.operands[0]) or 0
                        vt = eval_v(inst.operands[1]) or 0
                        vf = eval_v(inst.operands[2]) or 0
                        env[inst.result] = vt if c != 0 else vf
                    elif op == "br":
                        next_blk = blk_map.get(str(inst.operands[0]))
                    elif op == "br_cond":
                        c = eval_v(inst.operands[0]) or 0
                        tgt = str(inst.operands[1]) if c != 0 else str(inst.operands[2])
                        next_blk = blk_map.get(tgt)
                    elif op == "ret":
                        next_blk = None
                        break
                    else:
                        # Memory/float/call opcodes: stop trace cleanly without inventing counts
                        aborted = True
                        break
                prof.total_steps_sampled += 1
                if aborted or next_blk is None:
                    break
                prev_name = cur_blk.name
                cur_blk = next_blk

        # Fallback structural weights for any unvisited blocks
        for b in fn.blocks:
            if b.name not in prof.block_counts:
                prof.block_counts[b.name] = max(1, 16 * (max(1, b.loop_depth) if b.loop_depth > 0 else 1))
            if b.loop_depth > 0:
                prof.loop_trip_estimates[b.name] = prof.block_counts[b.name]

        max_trip = max(prof.loop_trip_estimates.values(), default=0)
        has_div_or_mem = any(
            ins.opcode in ("sdiv", "div", "srem", "load", "store", "load_off", "store_off", "call")
            for b in fn.blocks
            for ins in b.instructions
        )
        prof.recommended_unroll = 8 if (max_trip >= 32 and not has_div_or_mem) else 4
        return prof

    def optimize_with_profile(
        self,
        fn: SSAFunction,
        profile: Optional[PGOProfile] = None,
        sample_inputs: Optional[List[Tuple[int, ...]]] = None,
    ) -> Tuple[SSAFunction, Dict[str, Any]]:
        prof = profile or self.collect_ssa_profile(fn, sample_inputs=sample_inputs)
        laid_fn, layout_stats = BlockLayoutPass().run_on_function(fn, pgo_counts=prof.block_counts)
        return laid_fn, {
            "pgo_reordered_blocks": layout_stats.get("reordered_blocks", 0),
            "pgo_steps_sampled": prof.total_steps_sampled,
            "pgo_recommended_unroll": prof.recommended_unroll,
            "hot_blocks": sorted(prof.block_counts.items(), key=lambda kv: -kv[1])[:4],
        }
