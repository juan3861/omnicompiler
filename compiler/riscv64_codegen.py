"""
RISC-V 64 (RV64IM LP64) Native Machine Code Generator (Alpha-C88).

Translates Omni-SSA Functions (`param`, `const`, `mov`, `add`, `sub`, `mul`, `smulh`,
`umulh`, `sdiv`, `srem`, `shl`, `shr`, `sar`, `lshr`, `and`, `or`, `xor`, `neg`, `not`,
`cmp_*`, `select`, `phi`, `alloca`, `load`, `store`, `load_off`, `store_off`, `br`,
`br_cond`, `ret`) directly into little-endian 32-bit RISC-V RV64IM machine words.
"""

import struct
from typing import Any, Dict, List, Optional, Tuple
from compiler.ssa_ir import BasicBlock, SSAFunction, SSAInstruction, SSAVar
from compiler.native_codegen import CompiledFunctionArtifact


_RV_REG = {
    "zero": 0, "x0": 0, "ra": 1, "sp": 2, "gp": 3, "tp": 4,
    "t0": 5, "t1": 6, "t2": 7, "s0": 8, "fp": 8, "s1": 9,
    "a0": 10, "a1": 11, "a2": 12, "a3": 13, "a4": 14, "a5": 15, "a6": 16, "a7": 17,
    "s2": 18, "s3": 19, "s4": 20, "s5": 21, "s6": 22, "s7": 23,
    "t3": 28, "t4": 29, "t5": 30, "t6": 31,
}
_PARAM_REGS = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]


def _rv_i(imm12: int, rs1: str, f3: int, rd: str, opcode: int) -> bytes:
    w = ((imm12 & 0xFFF) << 20) | (_RV_REG[rs1] << 15) | ((f3 & 7) << 12) | (_RV_REG[rd] << 7) | (opcode & 0x7F)
    return struct.pack("<I", w)


def _rv_r(f7: int, rs2: str, rs1: str, f3: int, rd: str, opcode: int = 0x33) -> bytes:
    w = ((f7 & 0x7F) << 25) | (_RV_REG[rs2] << 20) | (_RV_REG[rs1] << 15) | ((f3 & 7) << 12) | (_RV_REG[rd] << 7) | (opcode & 0x7F)
    return struct.pack("<I", w)


def _rv_u(imm20: int, rd: str, opcode: int = 0x37) -> bytes:
    w = ((imm20 & 0xFFFFF) << 12) | (_RV_REG[rd] << 7) | (opcode & 0x7F)
    return struct.pack("<I", w)


def _rv_s(simm12: int, rs2: str, rs1: str, f3: int = 3) -> bytes:
    imm = simm12 & 0xFFF
    w = (((imm >> 5) & 0x7F) << 25) | (_RV_REG[rs2] << 20) | (_RV_REG[rs1] << 15) | ((f3 & 7) << 12) | ((imm & 0x1F) << 7) | 0x23
    return struct.pack("<I", w)


def _rv_b(simm13: int, rs2: str, rs1: str, f3: int) -> bytes:
    imm = simm13 & 0x1FFF
    b12 = (imm >> 12) & 1
    b11 = (imm >> 11) & 1
    b10_5 = (imm >> 5) & 0x3F
    b4_1 = (imm >> 1) & 0xF
    w = (b12 << 31) | (b10_5 << 25) | (_RV_REG[rs2] << 20) | (_RV_REG[rs1] << 15) | ((f3 & 7) << 12) | (b4_1 << 8) | (b11 << 7) | 0x63
    return struct.pack("<I", w)


def _rv_j(simm21: int, rd: str = "zero") -> bytes:
    imm = simm21 & 0x1FFFFF
    b20 = (imm >> 20) & 1
    b10_1 = (imm >> 1) & 0x3FF
    b11 = (imm >> 11) & 1
    b19_12 = (imm >> 12) & 0xFF
    w = (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12) | (_RV_REG[rd] << 7) | 0x6F
    return struct.pack("<I", w)


def _rv_li(rd: str, imm64: int) -> bytes:
    """Emits exact 64-bit signed constant load into `rd`."""
    sval = imm64 & 0xFFFFFFFFFFFFFFFF
    if sval >= (1 << 63):
        sval -= (1 << 64)
    if -2048 <= sval <= 2047:
        return _rv_i(sval, "zero", 0, rd, 0x13)
    if -(1 << 31) <= sval < (1 << 31):
        hi = ((sval + 0x800) >> 12) & 0xFFFFF
        lo = sval - ((((hi << 12) ^ 0x80000000) - 0x80000000))
        out = bytearray(_rv_u(hi, rd, 0x37))
        if lo != 0:
            out.extend(_rv_i(lo, rd, 0, rd, 0x13))
        return bytes(out)

    # Arbitrary 64-bit signed value: chunk into signed top bits + 11-bit unsigned slices (< 2048)
    uval = imm64 & 0xFFFFFFFFFFFFFFFF
    chunks: List[int] = []
    tmp = sval
    while not (-2048 <= tmp <= 2047):
        chunks.append(tmp & 0x7FF)
        tmp >>= 11
    out = bytearray(_rv_i(tmp, "zero", 0, rd, 0x13))
    for ch in reversed(chunks):
        out.extend(_rv_i(11, rd, 1, rd, 0x13))  # SLLI rd, rd, 11
        if ch:
            out.extend(_rv_i(ch, rd, 6, rd, 0x13))  # ORI rd, rd, ch
    return bytes(out)


class _RV64LabelBuffer:
    def __init__(self):
        self.code = bytearray()
        self.labels: Dict[str, int] = {}
        self.fixups: List[Tuple[str, int, str, Any]] = []  # (kind, pos, label, extra)
        self.relocations: List[Tuple[int, str]] = []

    def emit(self, raw: bytes):
        self.code.extend(raw)

    def mark(self, name: str):
        self.labels[name] = len(self.code)

    def j(self, label: str):
        self.fixups.append(("j", len(self.code), label, None))
        self.code.extend(_rv_j(0, "zero"))

    def bnez(self, rs1: str, label: str):
        # Emit inverse short BEQ +4 over JAL so branch range is +/-1MB unconditionally
        self.code.extend(_rv_b(8, "zero", rs1, 0))  # BEQ rs1, zero, +8 (skip JAL)
        self.fixups.append(("j", len(self.code), label, None))
        self.code.extend(_rv_j(0, "zero"))

    def beqz(self, rs1: str, label: str):
        self.code.extend(_rv_b(8, "zero", rs1, 1))  # BNE rs1, zero, +8 (skip JAL)
        self.fixups.append(("j", len(self.code), label, None))
        self.code.extend(_rv_j(0, "zero"))

    def finalize(self) -> bytes:
        for kind, pos, label, _ in self.fixups:
            if label not in self.labels:
                raise ValueError(f"Unresolved RISC-V label: {label}")
            disp = self.labels[label] - pos
            if kind == "j":
                self.code[pos:pos + 4] = _rv_j(disp, "zero")
        return bytes(self.code)


class Riscv64CodeGenerator:
    """Compiles Omni-SSA functions to LP64 RISC-V 64-bit (RV64IM) machine code."""

    def __init__(self, target_os: str = "linux"):
        self.target_os = target_os.lower()
        self.abi = "lp64"

    def compile_function(self, fn: SSAFunction) -> CompiledFunctionArtifact:
        if not fn.blocks:
            ret_bytes = _rv_i(0, "zero", 0, "a0", 0x13) + struct.pack("<I", 0x00008067)
            return CompiledFunctionArtifact(
                name=fn.name, arch="riscv64", abi=self.abi, code_bytes=ret_bytes,
                relocations=[], stack_frame_size=0, saved_nonvolatile_regs=[], code_end_offset=len(ret_bytes),
            )

        # Assign stack slots relative to sp (kept within 12-bit +/-2047 immediate range when small,
        # fallback using t6 offset for larger frames)
        slot_offsets: Dict[SSAVar, int] = {}
        next_off = 0

        def ensure_slot(v: SSAVar) -> int:
            nonlocal next_off
            if v not in slot_offsets:
                slot_offsets[v] = next_off
                next_off += 8
            return slot_offsets[v]

        alloca_offsets: Dict[SSAVar, int] = {}
        for blk in fn.blocks:
            for phi in blk.phi_nodes:
                if phi.result:
                    ensure_slot(phi.result)
            for inst in blk.instructions:
                if inst.opcode == "alloca" and inst.result is not None:
                    sz = 64
                    if inst.operands and isinstance(inst.operands[0], int) and inst.operands[0] > 0:
                        sz = ((inst.operands[0] + 7) // 8) * 8
                    alloca_offsets[inst.result] = next_off
                    next_off += sz
                    ensure_slot(inst.result)
                elif inst.result is not None:
                    ensure_slot(inst.result)

        for i, pname in enumerate(fn.params):
            ensure_slot(SSAVar(pname, 0))

        # Reserve top 16 bytes for saved ra, s0
        raw_frame = next_off + 16
        frame_size = ((raw_frame + 15) // 16) * 16
        ra_off = frame_size - 8
        s0_off = frame_size - 16

        buf = _RV64LabelBuffer()
        # Prologue: sp -= frame_size; save ra, s0
        if frame_size <= 2040:
            buf.emit(_rv_i(-frame_size, "sp", 0, "sp", 0x13))
        else:
            buf.emit(_rv_li("t6", -frame_size))
            buf.emit(_rv_r(0x00, "t6", "sp", 0, "sp"))
        buf.emit(_rv_s(ra_off, "ra", "sp") if ra_off <= 2040 else _rv_li("t6", ra_off) + _rv_r(0, "t6", "sp", 0, "t6") + _rv_s(0, "ra", "t6"))
        buf.emit(_rv_s(s0_off, "s0", "sp") if s0_off <= 2040 else _rv_li("t6", s0_off) + _rv_r(0, "t6", "sp", 0, "t6") + _rv_s(0, "s0", "t6"))

        def emit_store_slot(src_reg: str, var: SSAVar):
            off = slot_offsets[var]
            if off <= 2040:
                buf.emit(_rv_s(off, src_reg, "sp"))
            else:
                buf.emit(_rv_li("t6", off))
                buf.emit(_rv_r(0, "t6", "sp", 0, "t6"))
                buf.emit(_rv_s(0, src_reg, "t6"))

        def emit_load_slot(dst_reg: str, var: SSAVar):
            off = slot_offsets[var]
            if off <= 2040:
                buf.emit(_rv_i(off, "sp", 3, dst_reg, 0x03))
            else:
                buf.emit(_rv_li("t6", off))
                buf.emit(_rv_r(0, "t6", "sp", 0, "t6"))
                buf.emit(_rv_i(0, "t6", 3, dst_reg, 0x03))

        def load_op(opnd: Any, dst_reg: str):
            if isinstance(opnd, bool):
                buf.emit(_rv_i(int(opnd), "zero", 0, dst_reg, 0x13))
            elif isinstance(opnd, int):
                buf.emit(_rv_li(dst_reg, opnd))
            elif isinstance(opnd, SSAVar):
                emit_load_slot(dst_reg, opnd)
            else:
                buf.emit(_rv_i(0, "zero", 0, dst_reg, 0x13))

        for i, pname in enumerate(fn.params):
            if i < len(_PARAM_REGS):
                emit_store_slot(_PARAM_REGS[i], SSAVar(pname, 0))

        block_map = {b.name: b for b in fn.blocks}
        edge_ctr = 0

        def emit_phi_copies(pred_name: str, succ_bb: BasicBlock):
            tmps = []
            for phi in succ_bb.phi_nodes:
                if phi.result is None:
                    continue
                val = next((v for p, v in phi.phi_incoming if p == pred_name), None)
                if val is not None:
                    load_op(val, "t0")
                    tmps.append((phi.result, val))
                    buf.emit(_rv_r(0, "zero", "t0", 0, "t1"))  # single-cycle? wait load+store sequentially if aliased:
            if len(succ_bb.phi_nodes) == 1:
                for phi in succ_bb.phi_nodes:
                    val = next((v for p, v in phi.phi_incoming if p == pred_name), None)
                    if val is not None and phi.result:
                        load_op(val, "t0")
                        emit_store_slot("t0", phi.result)
                return
            # Sequential temp copy through staged temp registers/stack slots:
            # First copy all incoming values into staging list slots or compute sequentially if acyclic
            staged: List[Tuple[SSAVar, int]] = []
            # Wait: safe parallel copy via extra scratch regs t2..t5 / fallback direct on sp
            pairs = []
            for phi in succ_bb.phi_nodes:
                if phi.result is None:
                    continue
                val = next((v for p, v in phi.phi_incoming if p == pred_name), None)
                if val is not None:
                    pairs.append((phi.result, val))
            # Stage all incoming values into t3..t6 when <=4, else read-all-before-write via temp on stack
            if len(pairs) <= 4:
                tregs = ["t2", "t3", "t4", "t5"]
                for (res_v, src_v), tr in zip(pairs, tregs):
                    load_op(src_v, tr)
                for (res_v, _), tr in zip(pairs, tregs):
                    emit_store_slot(tr, res_v)
            else:
                # General parallel copy using negative frame scratch above ra? No, use fresh staging via sequential read + frame adjust
                extra = ((len(pairs) * 8 + 15) // 16) * 16
                for idx_p, (_, src_v) in enumerate(pairs):
                    if isinstance(src_v, SSAVar):
                        off = slot_offsets[src_v] + extra
                        if off <= 2040:
                            pass
                # Simpler: adjust sp only after computing old offset addresses or stage via alternating t0/t1? Actually sequential with dependency ordering or extra stack:
                buf.emit(_rv_i(-extra, "sp", 0, "sp", 0x13))
                for idx_p, (_, src_v) in enumerate(pairs):
                    if isinstance(src_v, SSAVar):
                        old_off = slot_offsets[src_v] + extra
                        if old_off <= 2040:
                            buf.emit(_rv_i(old_off, "sp", 3, "t0", 0x03))
                        else:
                            buf.emit(_rv_li("t6", old_off))
                            buf.emit(_rv_r(0, "t6", "sp", 0, "t6"))
                            buf.emit(_rv_i(0, "t6", 3, "t0", 0x03))
                    else:
                        load_op(src_v, "t0")
                    buf.emit(_rv_s(idx_p * 8, "t0", "sp"))
                for idx_p, (res_v, _) in enumerate(pairs):
                    buf.emit(_rv_i(idx_p * 8, "sp", 3, "t0", 0x03))
                    new_off = slot_offsets[res_v] + extra
                    if new_off <= 2040:
                        buf.emit(_rv_s(new_off, "t0", "sp"))
                    else:
                        buf.emit(_rv_li("t6", new_off))
                        buf.emit(_rv_r(0, "t6", "sp", 0, "t6"))
                        buf.emit(_rv_s(0, "t0", "t6"))
                buf.emit(_rv_i(extra, "sp", 0, "sp", 0x13))

        trampolines: List[Tuple[str, str, BasicBlock]] = []

        for idx_b, blk in enumerate(fn.blocks):
            buf.mark(f".L_bb_{blk.name}")
            next_bb_name = fn.blocks[idx_b + 1].name if idx_b + 1 < len(fn.blocks) else None
            for inst in blk.instructions:
                op = inst.opcode
                if op == "param":
                    idx_p = inst.operands[0] if inst.operands else 0
                    if isinstance(idx_p, str) and idx_p in fn.params:
                        idx_p = fn.params.index(idx_p)
                    if isinstance(idx_p, int) and idx_p < len(_PARAM_REGS) and inst.result is not None:
                        emit_store_slot(_PARAM_REGS[idx_p], inst.result)
                elif op == "const" and inst.result is not None:
                    load_op(inst.operands[0], "t0")
                    emit_store_slot("t0", inst.result)
                elif op == "mov" and inst.result is not None:
                    load_op(inst.operands[0], "t0")
                    emit_store_slot("t0", inst.result)
                elif op == "neg" and inst.result is not None:
                    load_op(inst.operands[0], "t0")
                    buf.emit(_rv_r(0x20, "t0", "zero", 0, "t0"))
                    emit_store_slot("t0", inst.result)
                elif op == "not" and inst.result is not None:
                    load_op(inst.operands[0], "t0")
                    buf.emit(_rv_i(-1, "t0", 4, "t0", 0x13))  # XORI t0, t0, -1
                    emit_store_slot("t0", inst.result)
                elif op in ("add", "sub", "mul", "smulh", "umulh", "sdiv", "srem", "shl", "shr", "sar", "lshr", "and", "or", "xor"):
                    load_op(inst.operands[0], "t0")
                    load_op(inst.operands[1], "t1")
                    r_map = {
                        "add": (0x00, 0), "sub": (0x20, 0),
                        "shl": (0x00, 1), "lshr": (0x00, 5), "shr": (0x20, 5), "sar": (0x20, 5),
                        "xor": (0x00, 4), "or": (0x00, 6), "and": (0x00, 7),
                        "mul": (0x01, 0), "smulh": (0x01, 1), "umulh": (0x01, 3),
                        "sdiv": (0x01, 4), "srem": (0x01, 6),
                    }
                    f7, f3 = r_map[op]
                    buf.emit(_rv_r(f7, "t1", "t0", f3, "t0"))
                    if inst.result is not None:
                        emit_store_slot("t0", inst.result)
                elif op in ("cmp_eq", "cmp_ne", "cmp_lt", "cmp_le", "cmp_gt", "cmp_ge") and inst.result is not None:
                    load_op(inst.operands[0], "t0")
                    load_op(inst.operands[1], "t1")
                    if op == "cmp_eq":
                        buf.emit(_rv_r(0x20, "t1", "t0", 0, "t0"))     # SUB t0, t0, t1
                        buf.emit(_rv_i(1, "t0", 3, "t0", 0x13))        # SLTIU t0, t0, 1
                    elif op == "cmp_ne":
                        buf.emit(_rv_r(0x20, "t1", "t0", 0, "t0"))     # SUB
                        buf.emit(_rv_r(0x00, "t0", "zero", 3, "t0"))   # SLTU t0, zero, t0
                    elif op == "cmp_lt":
                        buf.emit(_rv_r(0x00, "t1", "t0", 2, "t0"))     # SLT t0, t0, t1
                    elif op == "cmp_gt":
                        buf.emit(_rv_r(0x00, "t0", "t1", 2, "t0"))     # SLT t0, t1, t0
                    elif op == "cmp_le":
                        buf.emit(_rv_r(0x00, "t0", "t1", 2, "t0"))     # SLT t0, t1, t0 (t0 > t1)
                        buf.emit(_rv_i(1, "t0", 4, "t0", 0x13))        # XORI t0, t0, 1
                    elif op == "cmp_ge":
                        buf.emit(_rv_r(0x00, "t1", "t0", 2, "t0"))     # SLT t0, t0, t1 (t0 < t1)
                        buf.emit(_rv_i(1, "t0", 4, "t0", 0x13))        # XORI t0, t0, 1
                    emit_store_slot("t0", inst.result)
                elif op == "select" and inst.result is not None:
                    edge_ctr += 1
                    lbl_f = f".L_sel_f_{edge_ctr}"
                    lbl_d = f".L_sel_d_{edge_ctr}"
                    load_op(inst.operands[0], "t0")
                    buf.beqz("t0", lbl_f)
                    load_op(inst.operands[1], "t1")
                    buf.j(lbl_d)
                    buf.mark(lbl_f)
                    load_op(inst.operands[2], "t1")
                    buf.mark(lbl_d)
                    emit_store_slot("t1", inst.result)
                elif op == "alloca" and inst.result is not None:
                    a_off = alloca_offsets[inst.result]
                    if a_off <= 2040:
                        buf.emit(_rv_i(a_off, "sp", 0, "t0", 0x13))
                    else:
                        buf.emit(_rv_li("t6", a_off))
                        buf.emit(_rv_r(0, "t6", "sp", 0, "t0"))
                    emit_store_slot("t0", inst.result)
                elif op == "load" and inst.result is not None:
                    load_op(inst.operands[0], "t0")
                    buf.emit(_rv_i(0, "t0", 3, "t0", 0x03))
                    emit_store_slot("t0", inst.result)
                elif op == "store":
                    load_op(inst.operands[0], "t0")
                    load_op(inst.operands[1], "t1")
                    buf.emit(_rv_s(0, "t1", "t0"))
                elif op == "load_off" and inst.result is not None:
                    load_op(inst.operands[0], "t0")
                    load_op(inst.operands[1], "t1")
                    buf.emit(_rv_r(0, "t1", "t0", 0, "t0"))
                    buf.emit(_rv_i(0, "t0", 3, "t0", 0x03))
                    emit_store_slot("t0", inst.result)
                elif op == "store_off":
                    load_op(inst.operands[0], "t0")
                    load_op(inst.operands[1], "t1")
                    buf.emit(_rv_r(0, "t1", "t0", 0, "t0"))
                    load_op(inst.operands[2], "t2")
                    buf.emit(_rv_s(0, "t2", "t0"))
                elif op == "br":
                    succ_n = str(inst.operands[0])
                    succ_bb = block_map.get(succ_n)
                    if succ_bb and succ_bb.phi_nodes:
                        emit_phi_copies(blk.name, succ_bb)
                    if next_bb_name != succ_n:
                        buf.j(f".L_bb_{succ_n}")
                elif op == "br_cond":
                    cond_op, t_n, f_n = inst.operands[0], str(inst.operands[1]), str(inst.operands[2])
                    load_op(cond_op, "t0")
                    t_bb, f_bb = block_map.get(t_n), block_map.get(f_n)
                    if t_bb and t_bb.phi_nodes:
                        edge_ctr += 1
                        t_lbl = f".L_tramp_{edge_ctr}_{blk.name}_{t_n}"
                        trampolines.append((t_lbl, blk.name, t_bb))
                    else:
                        t_lbl = f".L_bb_{t_n}"
                    buf.bnez("t0", t_lbl)
                    if f_bb and f_bb.phi_nodes:
                        emit_phi_copies(blk.name, f_bb)
                    if next_bb_name != f_n:
                        buf.j(f".L_bb_{f_n}")
                elif op == "ret":
                    if inst.operands:
                        load_op(inst.operands[0], "a0")
                    else:
                        buf.emit(_rv_i(0, "zero", 0, "a0", 0x13))
                    buf.j(".L_epilogue")

        for t_lbl, pred_n, succ_bb in trampolines:
            buf.mark(t_lbl)
            emit_phi_copies(pred_n, succ_bb)
            buf.j(f".L_bb_{succ_bb.name}")

        buf.mark(".L_epilogue")
        buf.emit(_rv_i(ra_off, "sp", 3, "ra", 0x03) if ra_off <= 2040 else _rv_li("t6", ra_off) + _rv_r(0, "t6", "sp", 0, "t6") + _rv_i(0, "t6", 3, "ra", 0x03))
        buf.emit(_rv_i(s0_off, "sp", 3, "s0", 0x03) if s0_off <= 2040 else _rv_li("t6", s0_off) + _rv_r(0, "t6", "sp", 0, "t6") + _rv_i(0, "t6", 3, "s0", 0x03))
        if frame_size <= 2040:
            buf.emit(_rv_i(frame_size, "sp", 0, "sp", 0x13))
        else:
            buf.emit(_rv_li("t6", frame_size))
            buf.emit(_rv_r(0, "t6", "sp", 0, "sp"))
        buf.emit(struct.pack("<I", 0x00008067))  # JALR zero, 0(ra)

        raw_code = buf.finalize()
        return CompiledFunctionArtifact(
            name=fn.name,
            arch="riscv64",
            abi=self.abi,
            code_bytes=raw_code,
            relocations=[],
            stack_frame_size=frame_size,
            saved_nonvolatile_regs=["ra", "s0"],
            code_end_offset=len(raw_code),
        )
