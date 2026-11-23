"""
Async / Await Coroutine State Machine Lowering to Zero-Allocation Omni-SSA (Alpha-C90).

Lowers Python `async def` functions with arbitrary `await expr` suspension points
into a resumable stackless state-machine `SSAFunction`:
  int64_t poll_<name>(int64_t* frame, int64_t resume_val)

Frame layout (64-bit slots):
  frame[0] (offset 0)  : state_id (`0` = initial entry, `1..K` = await point k, `-1` = completed)
  frame[1] (offset 8)  : yield_or_result (input awaited token when poll returns 0, or final return value when poll returns 1)
  frame[2..]           : persisted parameters and locals live across suspension boundaries

Returns:
  0 -> suspended at next await point (await token stored in frame[1])
  1 -> coroutine completed (final return value stored in frame[1])
"""

import ast
import ctypes
from typing import Any, Dict, List, Optional, Tuple

from compiler.ssa_ir import BasicBlock, SSAFunction, SSAInstruction, SSAVar


class _MiniExprSSAEmitter:
    """Emits scalar integer AST expressions within a block backed by frame slots."""

    def __init__(self, frame_ptr: SSAVar, slot_map: Dict[str, int]):
        self.frame_ptr = frame_ptr
        self.slot_map = slot_map
        self.ver: Dict[str, int] = {}

    def fresh(self, prefix: str = "t") -> SSAVar:
        v = self.ver.get(prefix, 0) + 1
        self.ver[prefix] = v
        return SSAVar(prefix, v)

    def ensure_slot(self, name: str) -> int:
        if name not in self.slot_map:
            self.slot_map[name] = len(self.slot_map) * 8
        return self.slot_map[name]

    def load_var(self, blk: BasicBlock, name: str) -> SSAVar:
        off = self.ensure_slot(name)
        v = self.fresh(name)
        blk.add_instruction(SSAInstruction(v, "load_off", [self.frame_ptr, off, "i64"]))
        return v

    def store_var(self, blk: BasicBlock, name: str, val: Any) -> None:
        off = self.ensure_slot(name)
        blk.add_instruction(SSAInstruction(None, "store_off", [self.frame_ptr, off, val, "i64"]))

    def emit_expr(self, blk: BasicBlock, node: ast.AST) -> SSAVar:
        if isinstance(node, ast.Constant):
            v = self.fresh("c")
            blk.add_instruction(SSAInstruction(v, "const", [int(node.value)]))
            return v
        if isinstance(node, ast.Name):
            return self.load_var(blk, node.id)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            opv = self.emit_expr(blk, node.operand)
            v = self.fresh("neg")
            blk.add_instruction(SSAInstruction(v, "neg", [opv]))
            return v
        if isinstance(node, ast.BinOp):
            lhs = self.emit_expr(blk, node.left)
            rhs = self.emit_expr(blk, node.right)
            op_map = {
                ast.Add: "add", ast.Sub: "sub", ast.Mult: "mul",
                ast.FloorDiv: "sdiv", ast.Mod: "srem",
                ast.BitAnd: "and", ast.BitOr: "or", ast.BitXor: "xor",
                ast.LShift: "shl", ast.RShift: "sar",
            }
            sop = op_map.get(type(node.op))
            if sop is None:
                raise ValueError(f"Unsupported async expr op: {type(node.op).__name__}")
            v = self.fresh(sop)
            blk.add_instruction(SSAInstruction(v, sop, [lhs, rhs]))
            return v
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
            lhs = self.emit_expr(blk, node.left)
            rhs = self.emit_expr(blk, node.comparators[0])
            cmp_map = {
                ast.Eq: "cmp_eq", ast.NotEq: "cmp_ne",
                ast.Lt: "cmp_lt", ast.LtE: "cmp_le",
                ast.Gt: "cmp_gt", ast.GtE: "cmp_ge",
            }
            cop = cmp_map[type(node.ops[0])]
            v = self.fresh(cop)
            blk.add_instruction(SSAInstruction(v, cop, [lhs, rhs]))
            return v
        if isinstance(node, ast.IfExp):
            cond = self.emit_expr(blk, node.test)
            vt = self.emit_expr(blk, node.body)
            vf = self.emit_expr(blk, node.orelse)
            v = self.fresh("sel")
            blk.add_instruction(SSAInstruction(v, "select", [cond, vt, vf]))
            return v
        raise ValueError(f"Unsupported AST expression in async lowering: {ast.dump(node)}")


class AsyncCoroutineLowerer:
    """
    Transforms `async def` AST functions into deterministic resumable state-machine
    `SSAFunction` polling kernels compatible with `X64CodeGenerator`, `Arm64CodeGenerator`,
    and `Riscv64CodeGenerator`.
    """

    def lower_async_function(self, fn_def: ast.AsyncFunctionDef) -> Dict[str, Any]:
        if not isinstance(fn_def, ast.AsyncFunctionDef):
            raise TypeError("Expected ast.AsyncFunctionDef")

        param_names = [a.arg for a in fn_def.args.args]
        frame_ptr = SSAVar("frame", 0, var_type="ptr")
        resume_val = SSAVar("resume_val", 0, var_type="i64")

        # Reserve slots 0 (__state__) and 1 (__io__) first, then parameter slots
        slot_map: Dict[str, int] = {"__state__": 0, "__io__": 8}
        for pn in param_names:
            slot_map[pn] = len(slot_map) * 8

        emitter = _MiniExprSSAEmitter(frame_ptr, slot_map)

        entry = BasicBlock("entry")
        entry.add_instruction(SSAInstruction(frame_ptr, "param", [0]))
        entry.add_instruction(SSAInstruction(resume_val, "param", [1]))

        # Partition linear statements / simple if-statements into state segments separated by `await`
        # Supports:
        #   - x = await expr
        #   - await expr
        #   - x = expr
        #   - if cond: ... (non-await single-step or straight-line)
        #   - return expr
        state_blocks: List[BasicBlock] = []
        done_block = BasicBlock("coro_done")
        c_done = emitter.fresh("c_done")
        done_block.add_instruction(SSAInstruction(c_done, "const", [1]))
        done_block.add_instruction(SSAInstruction(None, "ret", [c_done]))

        def new_state_blk(sid: int) -> BasicBlock:
            b = BasicBlock(f"coro_state_{sid}")
            state_blocks.append(b)
            return b

        cur_sid = 0
        cur_blk = new_state_blk(cur_sid)
        suspend_points: List[Dict[str, Any]] = []
        lbl_ctr = 0

        def lower_stmt_seq(stmts: List[ast.stmt], blk: BasicBlock) -> Tuple[BasicBlock, bool]:
            nonlocal cur_sid, lbl_ctr
            for st in stmts:
                if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                    target_name = st.targets[0].id
                    if isinstance(st.value, ast.Await):
                        # Emit awaited token expr -> frame[__io__], set frame[__state__] = cur_sid + 1, return 0
                        tok = emitter.emit_expr(blk, st.value.value)
                        emitter.store_var(blk, "__io__", tok)
                        next_sid = cur_sid + 1
                        emitter.store_var(blk, "__state__", next_sid)
                        suspend_points.append({"state_id": next_sid, "target_var": target_name})
                        c0 = emitter.fresh("c_susp")
                        blk.add_instruction(SSAInstruction(c0, "const", [0]))
                        blk.add_instruction(SSAInstruction(None, "ret", [c0]))

                        # Next state block stores `resume_val` into `target_var`
                        cur_sid = next_sid
                        blk = new_state_blk(cur_sid)
                        emitter.store_var(blk, target_name, resume_val)
                    else:
                        rv = emitter.emit_expr(blk, st.value)
                        emitter.store_var(blk, target_name, rv)
                elif isinstance(st, ast.Expr) and isinstance(st.value, ast.Await):
                    tok = emitter.emit_expr(blk, st.value.value)
                    emitter.store_var(blk, "__io__", tok)
                    next_sid = cur_sid + 1
                    emitter.store_var(blk, "__state__", next_sid)
                    suspend_points.append({"state_id": next_sid, "target_var": None})
                    c0 = emitter.fresh("c_susp")
                    blk.add_instruction(SSAInstruction(c0, "const", [0]))
                    blk.add_instruction(SSAInstruction(None, "ret", [c0]))
                    cur_sid = next_sid
                    blk = new_state_blk(cur_sid)
                elif isinstance(st, ast.Return):
                    rv = emitter.emit_expr(blk, st.value) if st.value is not None else emitter.fresh("c0")
                    if st.value is None:
                        blk.add_instruction(SSAInstruction(rv, "const", [0]))
                    emitter.store_var(blk, "__io__", rv)
                    emitter.store_var(blk, "__state__", -1)
                    blk.add_instruction(SSAInstruction(None, "br", [done_block.name]))
                    if done_block not in blk.successors:
                        blk.successors.append(done_block)
                    if blk not in done_block.predecessors:
                        done_block.predecessors.append(blk)
                    return blk, True
                elif isinstance(st, ast.If):
                    # Handle structured non-await if/else within current state segment cleanly
                    lbl_ctr += 1
                    cid_tag = lbl_ctr
                    t_blk = BasicBlock(f"coro_if_t_{cid_tag}")
                    f_blk = BasicBlock(f"coro_if_f_{cid_tag}")
                    m_blk = BasicBlock(f"coro_if_m_{cid_tag}")
                    cond_v = emitter.emit_expr(blk, st.test)
                    blk.add_instruction(SSAInstruction(None, "br_cond", [cond_v, t_blk.name, f_blk.name]))
                    for succ in (t_blk, f_blk):
                        blk.successors.append(succ)
                        succ.predecessors.append(blk)

                    state_blocks.append(t_blk)
                    end_t, term_t = lower_stmt_seq(st.body, t_blk)
                    if not term_t:
                        end_t.add_instruction(SSAInstruction(None, "br", [m_blk.name]))
                        end_t.successors.append(m_blk)
                        m_blk.predecessors.append(end_t)

                    state_blocks.append(f_blk)
                    end_f, term_f = lower_stmt_seq(st.orelse, f_blk)
                    if not term_f:
                        end_f.add_instruction(SSAInstruction(None, "br", [m_blk.name]))
                        end_f.successors.append(m_blk)
                        m_blk.predecessors.append(end_f)

                    if term_t and term_f:
                        return end_t, True
                    state_blocks.append(m_blk)
                    blk = m_blk
                else:
                    raise ValueError(f"Unsupported statement in async coroutine lowering: {ast.dump(st)}")
            return blk, False

        end_blk, terminated = lower_stmt_seq(list(fn_def.body), cur_blk)
        if not terminated:
            c0 = emitter.fresh("c_ret0")
            end_blk.add_instruction(SSAInstruction(c0, "const", [0]))
            emitter.store_var(end_blk, "__io__", c0)
            emitter.store_var(end_blk, "__state__", -1)
            end_blk.add_instruction(SSAInstruction(None, "br", [done_block.name]))
            end_blk.successors.append(done_block)
            done_block.predecessors.append(end_blk)

        # Build entry dispatcher switching on frame[__state__]
        cur_state_v = emitter.load_var(entry, "__state__")
        dispatch_blocks: List[BasicBlock] = []
        head_blk = entry
        state_entry_blks = [b for b in state_blocks if b.name.startswith("coro_state_")]
        for idx_s, s_blk in enumerate(state_entry_blks):
            s_num = int(s_blk.name.rsplit("_", 1)[1])
            cmp_s = emitter.fresh(f"is_s{s_num}")
            head_blk.add_instruction(SSAInstruction(cmp_s, "cmp_eq", [cur_state_v, s_num]))
            next_disp = BasicBlock(f"disp_{idx_s + 1}") if idx_s + 1 < len(state_entry_blks) else done_block
            head_blk.add_instruction(SSAInstruction(None, "br_cond", [cmp_s, s_blk.name, next_disp.name]))
            head_blk.successors.extend([s_blk, next_disp])
            s_blk.predecessors.append(head_blk)
            next_disp.predecessors.append(head_blk)
            if next_disp is not done_block:
                dispatch_blocks.append(next_disp)
            head_blk = next_disp

        poll_fn = SSAFunction(
            name=f"poll_{fn_def.name}",
            params=["frame", "resume_val"],
            param_types={"frame": "ptr", "resume_val": "i64"},
            return_type="i64",
        )
        poll_fn.blocks = [entry] + dispatch_blocks + state_blocks + [done_block]
        poll_fn.entry_block = entry
        return {
            "poll_fn": poll_fn,
            "param_names": param_names,
            "frame_slots": slot_map,
            "frame_size_bytes": len(slot_map) * 8,
            "suspend_points": suspend_points,
        }


def drive_compiled_coroutine(
    poll_callable,
    frame_slots: Dict[str, int],
    init_args: Dict[str, int],
    await_handler,
    max_steps: int = 32,
) -> int:
    """
    Executes a compiled coroutine polling machine (`int64(frame_ptr, resume_val)`)
    to completion inside an explicit `ctypes.c_int64` frame array.
    """
    n_slots = max(2, len(frame_slots))
    frame = (ctypes.c_int64 * n_slots)()
    frame[0] = 0  # initial state
    frame[1] = 0
    for pname, val in init_args.items():
        if pname in frame_slots:
            frame[frame_slots[pname] // 8] = int(val)
    frame_addr = ctypes.addressof(frame)

    resume_arg = 0
    for _ in range(max_steps):
        done_flag = int(poll_callable(frame_addr, resume_arg))
        if done_flag == 1:
            return int(frame[1])
        await_token = int(frame[1])
        resume_arg = int(await_handler(await_token))
    raise RuntimeError("Coroutine exceeded max suspension steps without completing")
