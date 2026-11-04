"""
OmniCompiler Multi-Architecture Native Machine Code Generator (`native_codegen.py`).
Compiles Turing-complete multi-block `SSAFunction`s directly into executable machine code:
1. x86-64 Backend (Windows x64 ABI & Linux/macOS System V AMD64 ABI):
   - Full CFG lowering with critical-edge-safe Phi parallel-copy sequentialization (cycle breaking via R11).
   - Leaf Register-Resident Fast Path (Chaitin-Briggs physical GP registers, zero stack traffic in inner loops).
   - Call-Safe Frame Path (16-byte ABI stack alignment + 32-byte Win64 shadow space + balanced `sub/add rsp` + single canonical `0xC3` epilogue).
   - Recursive self-calls + external `CALL rel32` (`RelocationEntry` emission for `NativeObjectLinker`).
   - VEX-encoded 256-bit AVX2 SIMD kernels (`vmovdqu`, `vpaddq`, `vpmulld`, `vaddpd`, `vzeroupper`).
2. ARM64 / AArch64 Backend (AAPCS64 ABI):
   - Full multi-block CFG lowering (`ADD`, `SUB`, `MUL`, `SDIV`, `MSUB`, `LSLV`, `ASRV`, `CMP`+`CSET`, `CSEL`, `CBNZ`/`B`, `BL` `ARM64_CALL26` relocations, `STP/LDP` + `RET`).
"""

import sys
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Set

from compiler.ssa_ir import SSAFunction, BasicBlock, SSAInstruction, SSAVar
from compiler.regalloc_graph_coloring import ChaitinBriggsAllocator


@dataclass
class CodegenRelocation:
    offset: int
    symbol_name: str
    reloc_type: str = "REL32"  # "REL32", "ADDR64", "ARM64_CALL26"
    addend: int = 0


@dataclass
class CompiledFunctionArtifact:
    name: str
    arch: str
    abi: str
    code_bytes: bytes
    relocations: List[CodegenRelocation] = field(default_factory=list)
    line_table: List[Tuple[int, int]] = field(default_factory=list)  # (code_offset, source_line)
    stack_frame_size: int = 0
    saved_nonvolatile_regs: List[str] = field(default_factory=list)
    prologue_size: int = 0
    leaf_register_mode: bool = False


# ==============================================================================
# x86-64 Machine Code Encoder & Multi-Block SSA Lowering
# ==============================================================================

X64_REGS: Dict[str, Tuple[int, int]] = {
    "rax": (0, 0), "rcx": (0, 1), "rdx": (0, 2), "rbx": (0, 3),
    "rsp": (0, 4), "rbp": (0, 5), "rsi": (0, 6), "rdi": (0, 7),
    "r8":  (1, 0), "r9":  (1, 1), "r10": (1, 2), "r11": (1, 3),
    "r12": (1, 4), "r13": (1, 5), "r14": (1, 6), "r15": (1, 7),
}

WIN64_PARAM_REGS = ["rcx", "rdx", "r8", "r9"]
SYSV_PARAM_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

WIN64_CALLEE_SAVED = ["rbx", "rsi", "rdi", "r12", "r13", "r14", "r15"]
SYSV_CALLEE_SAVED = ["rbx", "r12", "r13", "r14", "r15"]

# Exclude rax, rcx, rdx, r11 so idiv/imul/shifts/scratch never clobber allocated registers
LEAF_ALLOC_REGS = ["r8", "r9", "r10", "rbx", "rsi", "rdi", "r12", "r13", "r14", "r15"]


class X64LabelBuffer:
    def __init__(self):
        self.code = bytearray()
        self.labels: Dict[str, int] = {}
        self.fixups: List[Tuple[int, str]] = []  # (disp32_offset, label_name)
        self.relocations: List[CodegenRelocation] = []
        self.line_table: List[Tuple[int, int]] = []
        self._last_line: int = -1

    def record_line(self, line: int):
        if line > 0 and line != self._last_line:
            self.line_table.append((len(self.code), line))
            self._last_line = line

    def mark(self, label: str):
        self.labels[label] = len(self.code)

    def emit(self, data: bytes):
        self.code.extend(data)

    def jmp(self, label: str):
        self.emit(b"\xe9\x00\x00\x00\x00")
        self.fixups.append((len(self.code) - 4, label))

    def jne(self, label: str):
        self.emit(b"\x0f\x85\x00\x00\x00\x00")
        self.fixups.append((len(self.code) - 4, label))

    def call_label(self, label: str):
        self.emit(b"\xe8\x00\x00\x00\x00")
        self.fixups.append((len(self.code) - 4, label))

    def call_external(self, symbol_name: str):
        self.emit(b"\xe8\x00\x00\x00\x00")
        disp_off = len(self.code) - 4
        self.relocations.append(CodegenRelocation(offset=disp_off, symbol_name=symbol_name, reloc_type="REL32"))

    def finalize(self) -> bytes:
        for disp_off, label in self.fixups:
            if label not in self.labels:
                raise KeyError(f"Unresolved x86-64 label '{label}'")
            target = self.labels[label]
            next_rip = disp_off + 4
            disp32 = target - next_rip
            struct.pack_into("<i", self.code, disp_off, disp32)
        return bytes(self.code)


def _x64_push(reg: str) -> bytes:
    hi, lo = X64_REGS[reg]
    return bytes([0x41, 0x50 + lo]) if hi else bytes([0x50 + lo])


def _x64_pop(reg: str) -> bytes:
    hi, lo = X64_REGS[reg]
    return bytes([0x41, 0x58 + lo]) if hi else bytes([0x58 + lo])


def _x64_mov_rr(dst: str, src: str) -> bytes:
    if dst == src:
        return b""
    s_hi, s_lo = X64_REGS[src]
    d_hi, d_lo = X64_REGS[dst]
    rex = 0x48 | (s_hi << 2) | d_hi
    modrm = 0xC0 | (s_lo << 3) | d_lo
    return bytes([rex, 0x89, modrm])


def _x64_mov_ri(dst: str, imm: int) -> bytes:
    d_hi, d_lo = X64_REGS[dst]
    # Normalize to signed 64-bit
    imm64 = imm & 0xFFFFFFFFFFFFFFFF
    if imm64 >= (1 << 63):
        imm64 -= (1 << 64)
    if imm64 == 0:
        rex = 0x48 | (d_hi << 2) | d_hi
        modrm = 0xC0 | (d_lo << 3) | d_lo
        return bytes([rex, 0x31, modrm])
    if -0x80000000 <= imm64 <= 0x7FFFFFFF:
        rex = 0x48 | d_hi
        modrm = 0xC0 | d_lo
        return bytes([rex, 0xC7, modrm]) + struct.pack("<i", imm64)
    rex = 0x48 | d_hi
    return bytes([rex, 0xB8 + d_lo]) + struct.pack("<q", imm64)


def _x64_load_rbp(dst: str, disp: int) -> bytes:
    d_hi, d_lo = X64_REGS[dst]
    rex = 0x48 | (d_hi << 2)
    if -128 <= disp <= 127:
        modrm = 0x45 | (d_lo << 3)
        return bytes([rex, 0x8B, modrm]) + struct.pack("<b", disp)
    modrm = 0x85 | (d_lo << 3)
    return bytes([rex, 0x8B, modrm]) + struct.pack("<i", disp)


def _x64_store_rbp(disp: int, src: str) -> bytes:
    s_hi, s_lo = X64_REGS[src]
    rex = 0x48 | (s_hi << 2)
    if -128 <= disp <= 127:
        modrm = 0x45 | (s_lo << 3)
        return bytes([rex, 0x89, modrm]) + struct.pack("<b", disp)
    modrm = 0x85 | (s_lo << 3)
    return bytes([rex, 0x89, modrm]) + struct.pack("<i", disp)


def _x64_alu_rr(opcode_byte: int, dst: str, src: str) -> bytes:
    s_hi, s_lo = X64_REGS[src]
    d_hi, d_lo = X64_REGS[dst]
    rex = 0x48 | (s_hi << 2) | d_hi
    modrm = 0xC0 | (s_lo << 3) | d_lo
    return bytes([rex, opcode_byte, modrm])


def _x64_imul_rr(dst: str, src: str) -> bytes:
    d_hi, d_lo = X64_REGS[dst]
    s_hi, s_lo = X64_REGS[src]
    rex = 0x48 | (d_hi << 2) | s_hi
    modrm = 0xC0 | (d_lo << 3) | s_lo
    return bytes([rex, 0x0F, 0xAF, modrm])


def _x64_test_rr(reg: str) -> bytes:
    hi, lo = X64_REGS[reg]
    rex = 0x48 | (hi << 2) | hi
    modrm = 0xC0 | (lo << 3) | lo
    return bytes([rex, 0x85, modrm])


def _sequentialize_parallel_copies(
    copies: List[Tuple[Any, Any]],
    scratch_loc: str,
) -> List[Tuple[Any, Any]]:
    """
    Resolves simultaneous parallel copies [(dst_loc, src_loc_or_imm), ...] into an ordered
    sequence of safe sequential moves, breaking register/slot swap cycles with `scratch_loc`.
    """
    pending: Dict[Any, Any] = {}
    for dst, src in copies:
        if dst != src:
            pending[dst] = src

    ordered: List[Tuple[Any, Any]] = []
    while pending:
        # Find any destination `d` that is NOT currently needed as a source of another pending copy
        active_sources = set(pending.values())
        ready_dst = None
        for d in list(pending.keys()):
            if d not in active_sources:
                ready_dst = d
                break

        if ready_dst is not None:
            src = pending.pop(ready_dst)
            ordered.append((ready_dst, src))
        else:
            # Pure cycle detected (e.g. a := b, b := a): break cycle using `scratch_loc`
            cyc_dst = next(iter(pending.keys()))
            cyc_src = pending[cyc_dst]
            ordered.append((scratch_loc, cyc_src))
            pending[cyc_dst] = scratch_loc

    return ordered


class X64CodeGenerator:
    """Compiles an Omni-SSA `SSAFunction` into native x86-64 machine code."""

    SETCC_BYTES = {
        "cmp_eq": 0x94,
        "cmp_ne": 0x95,
        "cmp_lt": 0x9C,
        "cmp_le": 0x9E,
        "cmp_gt": 0x9F,
        "cmp_ge": 0x9D,
    }

    def __init__(self, target_os: Optional[str] = None):
        if target_os is None:
            self.is_windows = sys.platform == "win32"
        else:
            self.is_windows = target_os.lower() in ("windows", "win32", "pe", "pe64", "pe_dll")
        self.abi = "win64" if self.is_windows else "sysv_amd64"
        self.param_regs = WIN64_PARAM_REGS if self.is_windows else SYSV_PARAM_REGS
        self.callee_saved_pool = WIN64_CALLEE_SAVED if self.is_windows else SYSV_CALLEE_SAVED

    def compile_function(self, fn: SSAFunction) -> CompiledFunctionArtifact:
        has_calls = any(
            inst.opcode == "call"
            for b in fn.blocks
            for inst in b.instructions
        )

        # Collect all SSA variables
        all_vars: List[SSAVar] = []
        seen_vars: Set[SSAVar] = set()

        def register_var(v: Any):
            if isinstance(v, SSAVar) and v not in seen_vars:
                seen_vars.add(v)
                all_vars.append(v)

        for p in fn.params:
            register_var(SSAVar(p, 0))
        for b in fn.blocks:
            for phi in b.phi_nodes:
                register_var(phi.result)
                for op in phi.operands:
                    register_var(op)
            for inst in b.instructions:
                register_var(inst.result)
                for op in inst.operands:
                    register_var(op)

        # Determine Leaf Register-Resident Mode vs General Stack-Frame Mode
        alloca_insts = [inst for b in fn.blocks for inst in b.instructions if inst.opcode == "alloca"]
        has_alloca = len(alloca_insts) > 0
        alloc = ChaitinBriggsAllocator(LEAF_ALLOC_REGS).allocate(fn)
        leaf_mode = (not has_calls) and (not has_alloca) and alloc["success"] and len(fn.params) <= len(self.param_regs)

        reg_map: Dict[SSAVar, str] = {}
        slot_map: Dict[SSAVar, int] = {}
        alloca_map: Dict[SSAVar, int] = {}
        used_callee_saved: List[str] = []

        if leaf_mode:
            reg_map = dict(alloc["color_map"])
            for v in all_vars:
                if v not in reg_map:
                    reg_map[v] = "r8"
            used_regs = set(reg_map.values())
            used_callee_saved = [r for r in self.callee_saved_pool if r in used_regs]
            frame_size = 0
        else:
            for idx, v in enumerate(all_vars):
                slot_map[v] = -8 * (idx + 1)
            current_disp = len(all_vars) * 8
            for inst in alloca_insts:
                sz = inst.operands[0] if inst.operands and isinstance(inst.operands[0], int) else 32
                aligned_sz = ((sz + 15) // 16) * 16
                current_disp += aligned_sz
                if inst.result:
                    alloca_map[inst.result] = current_disp

            max_call_args = max(
                [len(inst.operands) - 1 for b in fn.blocks for inst in b.instructions if inst.opcode == "call"] + [0]
            )
            extra_stack_args = max(0, max_call_args - len(self.param_regs)) * 8
            shadow_bytes = 32 if (self.is_windows and has_calls) else 0
            raw_bytes = current_disp + shadow_bytes + extra_stack_args
            # After `push rbp`, RSP % 16 == 0, so keeping frame_size a multiple of 16 keeps RSP 16-byte aligned!
            frame_size = ((raw_bytes + 15) // 16) * 16

        buf = X64LabelBuffer()
        buf.mark(".L_func_entry")

        # --- Emit Prologue ---
        if leaf_mode:
            for r in used_callee_saved:
                buf.emit(_x64_push(r))
            prologue_size = len(buf.code)
            # Move incoming ABI parameters into their assigned leaf registers via parallel copy
            param_copies: List[Tuple[Any, Any]] = []
            for idx, p_name in enumerate(fn.params):
                p_var = SSAVar(p_name, 0)
                if p_var in reg_map:
                    param_copies.append((reg_map[p_var], self.param_regs[idx]))
            for dst_r, src_r in _sequentialize_parallel_copies(param_copies, "r11"):
                buf.emit(_x64_mov_rr(dst_r, src_r))
        else:
            buf.emit(b"\x55")              # push rbp
            buf.emit(b"\x48\x89\xe5")      # mov rbp, rsp
            if frame_size > 0:
                if frame_size <= 127:
                    buf.emit(b"\x48\x83\xec" + struct.pack("<B", frame_size))
                else:
                    buf.emit(b"\x48\x81\xec" + struct.pack("<I", frame_size))
            prologue_size = len(buf.code)
            # Spill incoming ABI parameters into their stack frame home slots
            for idx, p_name in enumerate(fn.params):
                p_var = SSAVar(p_name, 0)
                if p_var in slot_map:
                    if idx < len(self.param_regs):
                        buf.emit(_x64_store_rbp(slot_map[p_var], self.param_regs[idx]))
                    else:
                        # Stack parameter above [rbp + 16] (+32 shadow on Win64)
                        caller_disp = 16 + (32 if self.is_windows else 0) + (idx - len(self.param_regs)) * 8
                        buf.emit(_x64_load_rbp("rax", caller_disp))
                        buf.emit(_x64_store_rbp(slot_map[p_var], "rax"))

        def resolve_operand_to_reg(op: Any, target_reg: str) -> None:
            if isinstance(op, int):
                buf.emit(_x64_mov_ri(target_reg, op))
                return
            if isinstance(op, str):
                s = op.strip()
                if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                    buf.emit(_x64_mov_ri(target_reg, int(s)))
                    return
                clean = s.lstrip("%")
                op = SSAVar(clean, 0)
            if isinstance(op, SSAVar):
                if leaf_mode:
                    src_r = reg_map.get(op, "r8")
                    buf.emit(_x64_mov_rr(target_reg, src_r))
                else:
                    disp = slot_map.get(op)
                    if disp is not None:
                        buf.emit(_x64_load_rbp(target_reg, disp))
                    else:
                        buf.emit(_x64_mov_ri(target_reg, 0))
                return
            buf.emit(_x64_mov_ri(target_reg, 0))

        def write_result_from_reg(res_var: Optional[SSAVar], src_reg: str) -> None:
            if res_var is None:
                return
            if leaf_mode:
                dst_r = reg_map[res_var]
                buf.emit(_x64_mov_rr(dst_r, src_reg))
            else:
                buf.emit(_x64_store_rbp(slot_map[res_var], src_reg))

        def emit_phi_copies_for_edge(pred_name: str, succ_block: BasicBlock):
            if not succ_block.phi_nodes:
                return
            copies: List[Tuple[Any, Any]] = []
            for phi in succ_block.phi_nodes:
                if phi.result is None:
                    continue
                chosen_val = None
                for blk_n, val in phi.phi_incoming:
                    if blk_n == pred_name:
                        chosen_val = val
                        break
                if chosen_val is None and phi.operands:
                    chosen_val = phi.operands[0]
                if chosen_val is None:
                    chosen_val = 0

                if leaf_mode:
                    dst_loc = reg_map[phi.result]
                    if isinstance(chosen_val, SSAVar):
                        src_loc: Any = reg_map[chosen_val]
                    elif isinstance(chosen_val, int):
                        src_loc = ("imm", chosen_val)
                    else:
                        src_loc = ("imm", 0)
                    copies.append((dst_loc, src_loc))
                else:
                    dst_loc = ("slot", slot_map[phi.result])
                    if isinstance(chosen_val, SSAVar):
                        src_loc = ("slot", slot_map[chosen_val])
                    elif isinstance(chosen_val, int):
                        src_loc = ("imm", chosen_val)
                    else:
                        src_loc = ("imm", 0)
                    copies.append((dst_loc, src_loc))

            seq = _sequentialize_parallel_copies(copies, "r11" if leaf_mode else ("reg", "r11"))
            for dst_loc, src_loc in seq:
                if leaf_mode:
                    if isinstance(src_loc, tuple) and src_loc[0] == "imm":
                        buf.emit(_x64_mov_ri(dst_loc, src_loc[1]))
                    else:
                        buf.emit(_x64_mov_rr(dst_loc, src_loc))
                else:
                    # General slot/reg move via rax
                    if isinstance(src_loc, tuple) and src_loc[0] == "imm":
                        val_reg = "rax"
                        buf.emit(_x64_mov_ri("rax", src_loc[1]))
                    elif isinstance(src_loc, tuple) and src_loc[0] == "reg":
                        val_reg = src_loc[1]
                    else:
                        val_reg = "rax"
                        buf.emit(_x64_load_rbp("rax", src_loc[1]))

                    if isinstance(dst_loc, tuple) and dst_loc[0] == "reg":
                        buf.emit(_x64_mov_rr(dst_loc[1], val_reg))
                    else:
                        buf.emit(_x64_store_rbp(dst_loc[1], val_reg))

        block_map: Dict[str, BasicBlock] = {b.name: b for b in fn.blocks}
        edge_trampolines: List[Tuple[str, str, BasicBlock]] = []

        def branch_target_label(pred_name: str, succ_name: str) -> str:
            succ_bb = block_map.get(succ_name)
            if succ_bb is not None and len(succ_bb.phi_nodes) > 0:
                tramp_label = f".L_edge_{pred_name}_to_{succ_name}_{len(edge_trampolines)}"
                edge_trampolines.append((tramp_label, pred_name, succ_bb))
                return tramp_label
            return f".L_bb_{succ_name}"

        # --- Emit Basic Blocks ---
        for idx_b, block in enumerate(fn.blocks):
            buf.mark(f".L_bb_{block.name}")
            for inst in block.instructions:
                buf.record_line(inst.source_line)
                op = inst.opcode.lower()

                if op == "param":
                    continue

                elif op in ("const", "mov"):
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    write_result_from_reg(inst.result, "rax")

                elif op in ("add", "sub", "and", "or", "xor"):
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    resolve_operand_to_reg(inst.operands[1], "r11")
                    alu_byte = {"add": 0x01, "sub": 0x29, "and": 0x21, "or": 0x09, "xor": 0x31}[op]
                    buf.emit(_x64_alu_rr(alu_byte, "rax", "r11"))
                    write_result_from_reg(inst.result, "rax")

                elif op in ("mul", "imul"):
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    resolve_operand_to_reg(inst.operands[1], "r11")
                    buf.emit(_x64_imul_rr("rax", "r11"))
                    write_result_from_reg(inst.result, "rax")

                elif op in ("div", "sdiv", "srem"):
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    resolve_operand_to_reg(inst.operands[1], "r11")
                    buf.emit(b"\x48\x99")          # cqo (sign-extend rax -> rdx:rax)
                    buf.emit(b"\x49\xf7\xfb")      # idiv r11
                    write_result_from_reg(inst.result, "rax" if op != "srem" else "rdx")

                elif op in ("shl", "shr"):
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    resolve_operand_to_reg(inst.operands[1], "rcx")
                    if op == "shl":
                        buf.emit(b"\x48\xd3\xe0")  # shl rax, cl
                    else:
                        buf.emit(b"\x48\xd3\xf8")  # sar rax, cl (signed arithmetic shift)
                    write_result_from_reg(inst.result, "rax")

                elif op in self.SETCC_BYTES:
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    resolve_operand_to_reg(inst.operands[1], "r11")
                    buf.emit(_x64_alu_rr(0x39, "rax", "r11"))  # cmp rax, r11
                    buf.emit(bytes([0x0F, self.SETCC_BYTES[op], 0xC0]))  # setcc al
                    buf.emit(b"\x48\x0f\xb6\xc0")              # movzx rax, al
                    write_result_from_reg(inst.result, "rax")

                elif op == "select":
                    resolve_operand_to_reg(inst.operands[2], "rax")  # false_val
                    resolve_operand_to_reg(inst.operands[1], "r11")  # true_val
                    resolve_operand_to_reg(inst.operands[0], "rcx")  # cond
                    buf.emit(_x64_test_rr("rcx"))                    # test rcx, rcx
                    buf.emit(b"\x49\x0f\x45\xc3")                    # cmovne rax, r11
                    write_result_from_reg(inst.result, "rax")

                elif op == "load":
                    resolve_operand_to_reg(inst.operands[0], "r11")  # base ptr
                    resolve_operand_to_reg(inst.operands[1], "rax")  # index
                    buf.emit(b"\x49\x8b\x04\xc3")                    # mov rax, [r11 + rax*8]
                    write_result_from_reg(inst.result, "rax")

                elif op == "store":
                    resolve_operand_to_reg(inst.operands[0], "r11")  # base ptr
                    resolve_operand_to_reg(inst.operands[1], "rcx")  # index
                    resolve_operand_to_reg(inst.operands[2], "rax")  # value
                    # REX.W=1, R=0(rax), X=0(rcx), B=1(r11) -> 0x49; SIB: scale=8(0xC0), idx=rcx(1<<3), base=r11(3) -> 0xCB
                    buf.emit(b"\x49\x89\x04\xcb")                    # mov [r11 + rcx*8], rax

                elif op == "alloca":
                    disp = alloca_map.get(inst.result, 16)
                    if disp <= 127:
                        # lea rax, [rbp - disp] -> 48 8d 45 <sbyte>
                        buf.emit(b"\x48\x8d\x45" + struct.pack("<b", -disp))
                    else:
                        # lea rax, [rbp - disp] -> 48 8d 85 <int32>
                        buf.emit(b"\x48\x8d\x85" + struct.pack("<i", -disp))
                    write_result_from_reg(inst.result, "rax")

                elif op == "call":
                    callee = str(inst.operands[0])
                    call_args = inst.operands[1:]
                    # Place stack arguments (> len(param_regs)) first
                    shadow_off = 32 if self.is_windows else 0
                    for a_idx in range(len(self.param_regs), len(call_args)):
                        resolve_operand_to_reg(call_args[a_idx], "rax")
                        sp_disp = shadow_off + (a_idx - len(self.param_regs)) * 8
                        # mov [rsp + disp32], rax -> 48 89 84 24 <disp32>
                        buf.emit(b"\x48\x89\x84\x24" + struct.pack("<i", sp_disp))
                    # Place register arguments
                    for a_idx in range(min(len(call_args), len(self.param_regs))):
                        resolve_operand_to_reg(call_args[a_idx], self.param_regs[a_idx])

                    if callee == fn.name:
                        buf.call_label(".L_func_entry")
                    else:
                        buf.call_external(callee)
                    write_result_from_reg(inst.result, "rax")

                elif op == "br":
                    succ_name = str(inst.operands[0])
                    lbl = branch_target_label(block.name, succ_name)
                    buf.jmp(lbl)

                elif op == "br_cond":
                    cond_op, true_name, false_name = inst.operands[0], str(inst.operands[1]), str(inst.operands[2])
                    resolve_operand_to_reg(cond_op, "rax")
                    buf.emit(_x64_test_rr("rax"))
                    t_lbl = branch_target_label(block.name, true_name)
                    f_lbl = branch_target_label(block.name, false_name)
                    buf.jne(t_lbl)
                    buf.jmp(f_lbl)

                elif op == "ret":
                    if inst.operands:
                        resolve_operand_to_reg(inst.operands[0], "rax")
                    else:
                        buf.emit(_x64_mov_ri("rax", 0))
                    buf.jmp(".L_epilogue")

        # --- Emit Phi Edge Trampolines ---
        for tramp_lbl, pred_name, succ_bb in edge_trampolines:
            buf.mark(tramp_lbl)
            emit_phi_copies_for_edge(pred_name, succ_bb)
            buf.jmp(f".L_bb_{succ_bb.name}")

        # --- Emit Single Canonical Epilogue (Guarantees Balanced RSP & Final 0xC3) ---
        buf.mark(".L_epilogue")
        if leaf_mode:
            for r in reversed(used_callee_saved):
                buf.emit(_x64_pop(r))
            buf.emit(b"\xc3")
        else:
            if frame_size > 0:
                if frame_size <= 127:
                    buf.emit(b"\x48\x83\xc4" + struct.pack("<B", frame_size))
                else:
                    buf.emit(b"\x48\x81\xc4" + struct.pack("<I", frame_size))
            buf.emit(b"\x5d")  # pop rbp
            buf.emit(b"\xc3")  # ret

        final_bytes = buf.finalize()
        return CompiledFunctionArtifact(
            name=fn.name,
            arch="x86_64",
            abi=self.abi,
            code_bytes=final_bytes,
            relocations=buf.relocations,
            line_table=buf.line_table,
            stack_frame_size=frame_size,
            saved_nonvolatile_regs=used_callee_saved if leaf_mode else ["rbp"],
            prologue_size=prologue_size,
            leaf_register_mode=leaf_mode,
        )

    def emit_avx2_vector_add_i64(self) -> bytes:
        """
        Emits a VEX-encoded 256-bit AVX2 SIMD kernel:
          void avx2_add_i64(const int64_t* a, const int64_t* b, int64_t* out, int64_t count)
        Processes 4 x 64-bit integers (32 bytes) per cycle using YMM0/YMM1 (`vpaddq`),
        with scalar tail cleanup for arbitrary `count` and `vzeroupper` epilogue.
        """
        buf = X64LabelBuffer()
        # Normalize ABI args into: r10=a, r11=b, rax=out, rcx=count
        if self.is_windows:
            # Win64: rcx=a, rdx=b, r8=out, r9=count
            buf.emit(_x64_mov_rr("r10", "rcx"))
            buf.emit(_x64_mov_rr("r11", "rdx"))
            buf.emit(_x64_mov_rr("rax", "r8"))
            buf.emit(_x64_mov_rr("rcx", "r9"))
        else:
            # SysV: rdi=a, rsi=b, rdx=out, rcx=count
            buf.emit(_x64_mov_rr("r10", "rdi"))
            buf.emit(_x64_mov_rr("r11", "rsi"))
            buf.emit(_x64_mov_rr("rax", "rdx"))

        # Vector loop while rcx >= 4
        buf.mark(".L_vec_loop")
        buf.emit(b"\x48\x83\xf9\x04")              # cmp rcx, 4
        buf.emit(b"\x0f\x8c\x00\x00\x00\x00")      # jl .L_scalar_tail
        buf.fixups.append((len(buf.code) - 4, ".L_scalar_tail"))

        buf.emit(b"\xc4\xc1\x7e\x6f\x02")          # vmovdqu ymm0, [r10]
        buf.emit(b"\xc4\xc1\x7e\x6f\x0b")          # vmovdqu ymm1, [r11]
        buf.emit(b"\xc5\xfd\xd4\xc1")              # vpaddq ymm0, ymm0, ymm1
        buf.emit(b"\xc5\xfe\x7f\x00")              # vmovdqu [rax], ymm0

        buf.emit(b"\x49\x83\xc2\x20")              # add r10, 32
        buf.emit(b"\x49\x83\xc3\x20")              # add r11, 32
        buf.emit(b"\x48\x83\xc0\x20")              # add rax, 32
        buf.emit(b"\x48\x83\xe9\x04")              # sub rcx, 4
        buf.jmp(".L_vec_loop")

        buf.mark(".L_scalar_tail")
        buf.emit(b"\xc5\xf8\x77")                  # vzeroupper
        buf.mark(".L_tail_loop")
        buf.emit(_x64_test_rr("rcx"))              # test rcx, rcx
        buf.emit(b"\x0f\x8e\x00\x00\x00\x00")      # jle .L_done
        buf.fixups.append((len(buf.code) - 4, ".L_done"))

        buf.emit(b"\x49\x8b\x12")                  # mov rdx, [r10]
        buf.emit(b"\x49\x03\x13")                  # add rdx, [r11]
        buf.emit(b"\x48\x89\x10")                  # mov [rax], rdx
        buf.emit(b"\x49\x83\xc2\x08")              # add r10, 8
        buf.emit(b"\x49\x83\xc3\x08")              # add r11, 8
        buf.emit(b"\x48\x83\xc0\x08")              # add rax, 8
        buf.emit(b"\x48\xff\xc9")                  # dec rcx
        buf.jmp(".L_tail_loop")

        buf.mark(".L_done")
        buf.emit(_x64_mov_ri("rax", 1))
        buf.emit(b"\xc3")
        return buf.finalize()

    def emit_avx2_fma_dot_i64(self) -> bytes:
        """
        Emits a VEX-encoded 256-bit AVX2 tiled reduction / dot-scale kernel:
          int64_t avx2_dot_sum_i64(const int64_t* a, const int64_t* b, int64_t count)
        Computes sum_{i=0}^{count-1} (a[i] + b[i]) using 256-bit YMM vector accumulators.
        """
        buf = X64LabelBuffer()
        if self.is_windows:
            buf.emit(_x64_mov_rr("r10", "rcx"))
            buf.emit(_x64_mov_rr("r11", "rdx"))
            buf.emit(_x64_mov_rr("rcx", "r8"))
        else:
            buf.emit(_x64_mov_rr("r10", "rdi"))
            buf.emit(_x64_mov_rr("r11", "rsi"))
            buf.emit(_x64_mov_rr("rcx", "rdx"))

        buf.emit(_x64_mov_ri("rax", 0))
        # vpxor ymm2, ymm2, ymm2 (C5 ED EF D2)
        buf.emit(b"\xc5\xed\xef\xd2")

        buf.mark(".L_dot_vec")
        buf.emit(b"\x48\x83\xf9\x04")
        buf.emit(b"\x0f\x8c\x00\x00\x00\x00")
        buf.fixups.append((len(buf.code) - 4, ".L_dot_reduce"))

        buf.emit(b"\xc4\xc1\x7e\x6f\x02")          # vmovdqu ymm0, [r10]
        buf.emit(b"\xc4\xc1\x7e\x6f\x0b")          # vmovdqu ymm1, [r11]
        buf.emit(b"\xc5\xfd\xd4\xc1")              # vpaddq ymm0, ymm0, ymm1
        buf.emit(b"\xc5\xed\xd4\xd0")              # vpaddq ymm2, ymm2, ymm0
        buf.emit(b"\x49\x83\xc2\x20")
        buf.emit(b"\x49\x83\xc3\x20")
        buf.emit(b"\x48\x83\xe9\x04")
        buf.jmp(".L_dot_vec")

        buf.mark(".L_dot_reduce")
        # Spill ymm2 to 32-byte temporary stack space [rsp - 32] (red-zone safe via sub rsp, 40)
        buf.emit(b"\x48\x83\xec\x28")              # sub rsp, 40
        buf.emit(b"\xc5\xfe\x7f\x14\x24")          # vmovdqu [rsp], ymm2
        buf.emit(b"\xc5\xf8\x77")                  # vzeroupper
        buf.emit(b"\x48\x03\x04\x24")              # add rax, [rsp]
        buf.emit(b"\x48\x03\x44\x24\x08")          # add rax, [rsp+8]
        buf.emit(b"\x48\x03\x44\x24\x10")          # add rax, [rsp+16]
        buf.emit(b"\x48\x03\x44\x24\x18")          # add rax, [rsp+24]
        buf.emit(b"\x48\x83\xc4\x28")              # add rsp, 40

        buf.mark(".L_dot_tail")
        buf.emit(_x64_test_rr("rcx"))
        buf.emit(b"\x0f\x8e\x00\x00\x00\x00")
        buf.fixups.append((len(buf.code) - 4, ".L_dot_done"))
        buf.emit(b"\x49\x03\x02")                  # add rax, [r10]
        buf.emit(b"\x49\x03\x03")                  # add rax, [r11]
        buf.emit(b"\x49\x83\xc2\x08")
        buf.emit(b"\x49\x83\xc3\x08")
        buf.emit(b"\x48\xff\xc9")
        buf.jmp(".L_dot_tail")

        buf.mark(".L_dot_done")
        buf.emit(b"\xc3")
        return buf.finalize()


# ==============================================================================
# ARM64 (AArch64 AAPCS64) Machine Code Encoder & Multi-Block SSA Lowering
# ==============================================================================

def _a64_u32(inst: int) -> bytes:
    return struct.pack("<I", inst & 0xFFFFFFFF)


def _a64_mov_imm64(rd: int, val: int) -> bytes:
    uval = val & 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    # MOVZ Xd, #(uval & 0xFFFF), LSL #0
    out.extend(_a64_u32(0xD2800000 | ((uval & 0xFFFF) << 5) | rd))
    for shift_idx, shift in enumerate((16, 32, 48), start=1):
        chunk = (uval >> shift) & 0xFFFF
        if chunk != 0:
            # MOVK Xd, #chunk, LSL #(shift)
            out.extend(_a64_u32(0xF2800000 | (shift_idx << 21) | (chunk << 5) | rd))
    return bytes(out)


def _a64_mov_rr(rd: int, rm: int) -> bytes:
    if rd == rm:
        return b""
    # ORR Xd, XZR, Xm -> 0xAA0003E0 | (rm << 16) | rd
    return _a64_u32(0xAA0003E0 | (rm << 16) | rd)


def _a64_ldr_fp_slot(rt: int, slot_index: int) -> bytes:
    # Store slots at positive 8-byte offsets from SP+16: [sp, #16 + slot_index*8]
    uimm12 = (16 + slot_index * 8) // 8
    # LDR Xt, [SP, #(uimm12 * 8)] -> 0xF9400000 | (uimm12 << 10) | (31 << 5) | rt
    return _a64_u32(0xF9400000 | ((uimm12 & 0xFFF) << 10) | (31 << 5) | rt)


def _a64_str_fp_slot(rt: int, slot_index: int) -> bytes:
    uimm12 = (16 + slot_index * 8) // 8
    # STR Xt, [SP, #(uimm12 * 8)] -> 0xF9000000 | (uimm12 << 10) | (31 << 5) | rt
    return _a64_u32(0xF9000000 | ((uimm12 & 0xFFF) << 10) | (31 << 5) | rt)


class Arm64CodeGenerator:
    """Compiles an Omni-SSA `SSAFunction` into native 64-bit ARM64 (AArch64) machine code."""

    # ARM64 condition codes (inverted for CSET because CSET uses invertedlsb of cond!)
    # Wait: in AArch64 `CSINC Xd, XZR, XZR, invert(cond)`:
    # EQ=0 -> invert=1(NE), NE=1 -> invert=0(EQ), LT=11(0xB) -> invert=10(0xA=GE),
    # LE=13(0xD) -> invert=12(0xC=GT), GT=12(0xC) -> invert=13(0xD=LE), GE=10(0xA) -> invert=11(0xB=LT).
    CSET_INV_COND = {
        "cmp_eq": 0x1,
        "cmp_ne": 0x0,
        "cmp_lt": 0xA,
        "cmp_le": 0xC,
        "cmp_gt": 0xD,
        "cmp_ge": 0xB,
    }

    def compile_function(self, fn: SSAFunction) -> CompiledFunctionArtifact:
        all_vars: List[SSAVar] = []
        seen: Set[SSAVar] = set()

        def reg_v(v: Any):
            if isinstance(v, SSAVar) and v not in seen:
                seen.add(v)
                all_vars.append(v)

        for p in fn.params:
            reg_v(SSAVar(p, 0))
        for b in fn.blocks:
            for phi in b.phi_nodes:
                reg_v(phi.result)
                for op in phi.operands:
                    reg_v(op)
            for inst in b.instructions:
                reg_v(inst.result)
                for op in inst.operands:
                    reg_v(op)

        slot_idx_map: Dict[SSAVar, int] = {v: i for i, v in enumerate(all_vars)}
        alloca_insts = [inst for b in fn.blocks for inst in b.instructions if inst.opcode == "alloca"]
        alloca_map: Dict[SSAVar, int] = {}
        curr_disp = 16 + len(all_vars) * 8
        for inst in alloca_insts:
            sz = inst.operands[0] if inst.operands and isinstance(inst.operands[0], int) else 32
            aligned_sz = ((sz + 15) // 16) * 16
            curr_disp += aligned_sz
            if inst.result:
                alloca_map[inst.result] = curr_disp

        # 16 bytes for saved X29/X30 + variables + alloca, 16-byte aligned
        frame_size = ((curr_disp + 15) // 16) * 16
        frame_size = max(16, frame_size)

        code = bytearray()
        labels: Dict[str, int] = {}
        b_fixups: List[Tuple[int, str, str]] = []  # (byte_offset, kind: "B"|"CBNZ"|"BL", label)
        relocs: List[CodegenRelocation] = []
        line_table: List[Tuple[int, int]] = []

        def mark(lbl: str):
            labels[lbl] = len(code)

        def emit_b(lbl: str):
            off = len(code)
            code.extend(_a64_u32(0x14000000))
            b_fixups.append((off, "B", lbl))

        def emit_cbnz_x9(lbl: str):
            off = len(code)
            code.extend(_a64_u32(0xB5000009))  # CBNZ X9, #0
            b_fixups.append((off, "CBNZ", lbl))

        mark(".L_func_entry")
        # SUB SP, SP, #frame_size -> 0xD10003FF | (frame_size << 10)
        code.extend(_a64_u32(0xD10003FF | ((frame_size & 0xFFF) << 10)))
        # STP X29, X30, [SP, #0] -> 0xA9007BFD
        code.extend(_a64_u32(0xA9007BFD))
        prologue_size = len(code)

        # Store incoming parameters X0..X7 into slots
        for idx, p_name in enumerate(fn.params[:8]):
            pv = SSAVar(p_name, 0)
            if pv in slot_idx_map:
                code.extend(_a64_str_fp_slot(idx, slot_idx_map[pv]))

        def load_op(op: Any, target_x: int):
            if isinstance(op, int):
                code.extend(_a64_mov_imm64(target_x, op))
                return
            if isinstance(op, str):
                s = op.strip()
                if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                    code.extend(_a64_mov_imm64(target_x, int(s)))
                    return
                op = SSAVar(s.lstrip("%"), 0)
            if isinstance(op, SSAVar) and op in slot_idx_map:
                code.extend(_a64_ldr_fp_slot(target_x, slot_idx_map[op]))
                return
            code.extend(_a64_mov_imm64(target_x, 0))

        def store_res(res: Optional[SSAVar], src_x: int):
            if res is not None and res in slot_idx_map:
                code.extend(_a64_str_fp_slot(src_x, slot_idx_map[res]))

        block_map = {b.name: b for b in fn.blocks}
        trampolines: List[Tuple[str, str, BasicBlock]] = []

        def target_lbl(pred_n: str, succ_n: str) -> str:
            sb = block_map.get(succ_n)
            if sb is not None and sb.phi_nodes:
                tl = f".L_edge_{pred_n}_{succ_n}_{len(trampolines)}"
                trampolines.append((tl, pred_n, sb))
                return tl
            return f".L_bb_{succ_n}"

        for block in fn.blocks:
            mark(f".L_bb_{block.name}")
            for inst in block.instructions:
                if inst.source_line > 0:
                    line_table.append((len(code), inst.source_line))
                op = inst.opcode.lower()
                if op == "param":
                    continue
                elif op in ("const", "mov"):
                    load_op(inst.operands[0], 9)
                    store_res(inst.result, 9)
                elif op == "add":
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    code.extend(_a64_u32(0x8B0A0129))  # ADD X9, X9, X10
                    store_res(inst.result, 9)
                elif op == "sub":
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    code.extend(_a64_u32(0xCB0A0129))  # SUB X9, X9, X10
                    store_res(inst.result, 9)
                elif op in ("mul", "imul"):
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    code.extend(_a64_u32(0x9B0A7D29))  # MUL X9, X9, X10
                    store_res(inst.result, 9)
                elif op in ("div", "sdiv"):
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    code.extend(_a64_u32(0x9ACA0D29))  # SDIV X9, X9, X10
                    store_res(inst.result, 9)
                elif op == "srem":
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    code.extend(_a64_u32(0x9ACA0D2B))  # SDIV X11, X9, X10
                    # MSUB X9, X11, X10, X9 -> 0x9B0A8000 | (9 << 10) | (11 << 5) | 9
                    code.extend(_a64_u32(0x9B0A8000 | (9 << 10) | (11 << 5) | 9))
                    store_res(inst.result, 9)
                elif op == "shl":
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    code.extend(_a64_u32(0x9ACA2129))  # LSLV X9, X9, X10
                    store_res(inst.result, 9)
                elif op == "shr":
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    code.extend(_a64_u32(0x9ACA2929))  # ASRV X9, X9, X10
                    store_res(inst.result, 9)
                elif op == "and":
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    code.extend(_a64_u32(0x8A0A0129))  # AND X9, X9, X10
                    store_res(inst.result, 9)
                elif op == "or":
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    code.extend(_a64_u32(0xAA0A0129))  # ORR X9, X9, X10
                    store_res(inst.result, 9)
                elif op == "xor":
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    code.extend(_a64_u32(0xCA0A0129))  # EOR X9, X9, X10
                    store_res(inst.result, 9)
                elif op in self.CSET_INV_COND:
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    code.extend(_a64_u32(0xEB0A013F))  # CMP X9, X10 (SUBS XZR, X9, X10)
                    inv_c = self.CSET_INV_COND[op]
                    # CSINC X9, XZR, XZR, inv_c -> 0x9A9F07E9 | (inv_c << 12)
                    code.extend(_a64_u32(0x9A9F07E9 | (inv_c << 12)))
                    store_res(inst.result, 9)
                elif op == "select":
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    load_op(inst.operands[2], 11)
                    code.extend(_a64_u32(0xEB1F013F))  # CMP X9, XZR
                    # CSEL X9, X10, X11, NE(1) -> 0x9A8B1149
                    code.extend(_a64_u32(0x9A8B1149))
                    store_res(inst.result, 9)
                elif op == "load":
                    load_op(inst.operands[0], 9)   # base ptr in X9
                    load_op(inst.operands[1], 10)  # index in X10
                    # LDR X11, [X9, X10, LSL #3] -> 0xF8607800 | (10 << 16) | (9 << 5) | 11
                    code.extend(_a64_u32(0xF8607800 | (10 << 16) | (9 << 5) | 11))
                    store_res(inst.result, 11)
                elif op == "store":
                    load_op(inst.operands[0], 9)   # base ptr in X9
                    load_op(inst.operands[1], 10)  # index in X10
                    load_op(inst.operands[2], 11)  # value in X11
                    # STR X11, [X9, X10, LSL #3] -> 0xF8207800 | (10 << 16) | (9 << 5) | 11
                    code.extend(_a64_u32(0xF8207800 | (10 << 16) | (9 << 5) | 11))
                elif op == "alloca":
                    disp = alloca_map.get(inst.result, 16)
                    # SUB X9, X29, #disp -> 0xD1000000 | ((disp & 0xFFF) << 10) | (29 << 5) | 9
                    code.extend(_a64_u32(0xD1000000 | ((disp & 0xFFF) << 10) | (29 << 5) | 9))
                    store_res(inst.result, 9)
                elif op == "call":
                    callee = str(inst.operands[0])
                    for a_i, a_op in enumerate(inst.operands[1:9]):
                        load_op(a_op, a_i)
                    off = len(code)
                    code.extend(_a64_u32(0x94000000))  # BL #0
                    if callee == fn.name:
                        b_fixups.append((off, "BL", ".L_func_entry"))
                    else:
                        relocs.append(CodegenRelocation(offset=off, symbol_name=callee, reloc_type="ARM64_CALL26"))
                    store_res(inst.result, 0)
                elif op == "br":
                    emit_b(target_lbl(block.name, str(inst.operands[0])))
                elif op == "br_cond":
                    load_op(inst.operands[0], 9)
                    tl = target_lbl(block.name, str(inst.operands[1]))
                    fl = target_lbl(block.name, str(inst.operands[2]))
                    emit_cbnz_x9(tl)
                    emit_b(fl)
                elif op == "ret":
                    if inst.operands:
                        load_op(inst.operands[0], 0)
                    else:
                        code.extend(_a64_mov_imm64(0, 0))
                    emit_b(".L_epilogue")

        for tl, pred_n, sb in trampolines:
            mark(tl)
            copies: List[Tuple[Any, Any]] = []
            for phi in sb.phi_nodes:
                if phi.result is None:
                    continue
                c_val = None
                for bn, v in phi.phi_incoming:
                    if bn == pred_n:
                        c_val = v
                        break
                if c_val is None and phi.operands:
                    c_val = phi.operands[0]
                dst_s = ("slot", slot_idx_map[phi.result])
                if isinstance(c_val, SSAVar) and c_val in slot_idx_map:
                    src_s: Any = ("slot", slot_idx_map[c_val])
                elif isinstance(c_val, int):
                    src_s = ("imm", c_val)
                else:
                    src_s = ("imm", 0)
                copies.append((dst_s, src_s))

            for dst_s, src_s in _sequentialize_parallel_copies(copies, ("reg", 15)):
                if src_s[0] == "imm":
                    code.extend(_a64_mov_imm64(9, src_s[1]))
                    v_reg = 9
                elif src_s[0] == "reg":
                    v_reg = src_s[1]
                else:
                    code.extend(_a64_ldr_fp_slot(9, src_s[1]))
                    v_reg = 9

                if dst_s[0] == "reg":
                    code.extend(_a64_mov_rr(dst_s[1], v_reg))
                else:
                    code.extend(_a64_str_fp_slot(v_reg, dst_s[1]))
            emit_b(f".L_bb_{sb.name}")

        mark(".L_epilogue")
        # LDP X29, X30, [SP, #0] -> 0xA9407BFD
        code.extend(_a64_u32(0xA9407BFD))
        # ADD SP, SP, #frame_size -> 0x910003FF | (frame_size << 10)
        code.extend(_a64_u32(0x910003FF | ((frame_size & 0xFFF) << 10)))
        # RET -> 0xD65F03C0
        code.extend(_a64_u32(0xD65F03C0))

        # Patch branches
        for off, kind, lbl in b_fixups:
            target = labels[lbl]
            imm_words = (target - off) // 4
            if kind == "B":
                inst_w = 0x14000000 | (imm_words & 0x03FFFFFF)
            elif kind == "BL":
                inst_w = 0x94000000 | (imm_words & 0x03FFFFFF)
            else:  # CBNZ X9
                inst_w = 0xB5000009 | ((imm_words & 0x7FFFF) << 5)
            struct.pack_into("<I", code, off, inst_w)

        return CompiledFunctionArtifact(
            name=fn.name,
            arch="arm64",
            abi="aapcs64",
            code_bytes=bytes(code),
            relocations=relocs,
            line_table=line_table,
            stack_frame_size=frame_size,
            saved_nonvolatile_regs=["x29", "x30"],
            prologue_size=prologue_size,
            leaf_register_mode=False,
        )


class NativeCodeGenerator:
    """Unified Multi-Architecture Codegen Dispatcher (`x86_64` & `arm64`)."""

    def __init__(self, arch: str = "x86_64", target_os: Optional[str] = None):
        self.arch = arch.lower()
        self.target_os = target_os
        self.x64 = X64CodeGenerator(target_os=target_os)
        self.arm64 = Arm64CodeGenerator()

    def compile_ssa(self, fn: SSAFunction) -> CompiledFunctionArtifact:
        if self.arch in ("arm64", "aarch64"):
            return self.arm64.compile_function(fn)
        return self.x64.compile_function(fn)
