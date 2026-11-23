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

import heapq
import sys
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Set

from compiler.ssa_ir import SSAFunction, BasicBlock, SSAInstruction, SSAVar, analyze_ssa_constant_offsets, is_contiguous_stride
from compiler.regalloc_graph_coloring import ChaitinBriggsAllocator, IteratedRegisterCoalescingAllocator


def _schedule_basic_block_instructions(
    instructions: List[SSAInstruction],
    var_use_counts: Optional[Dict[SSAVar, int]] = None,
) -> List[SSAInstruction]:
    """
    Local Critical-Path DAG List Scheduler for SSA basic blocks.
    Reorders pure arithmetic windows between memory/control-flow barriers to expose
    instruction-level parallelism (hiding multi-cycle `mul`/`sdiv` latencies) while
    strictly preserving RAW dependencies and single-use `cmp_* + br_cond` fusion pairs.
    """
    if len(instructions) < 4:
        return instructions

    _PURE_SCHED_OPS = frozenset({
        "const", "fconst", "mov",
        "add", "sub", "mul", "imul", "div", "sdiv", "srem",
        "and", "or", "xor", "shl", "shr", "sar", "neg", "not",
        "fadd", "fsub", "fmul", "fdiv", "fneg", "sitofp", "fptosi",
        "cmp_eq", "cmp_ne", "cmp_lt", "cmp_le", "cmp_gt", "cmp_ge",
    })
    _LATENCY_TABLE = {
        "div": 6, "sdiv": 6, "srem": 6, "fdiv": 6,
        "mul": 3, "imul": 3, "fmul": 3, "fadd": 3, "fsub": 3,
    }

    out: List[SSAInstruction] = []
    n = len(instructions)
    i = 0
    while i < n:
        ins = instructions[i]
        op = ins.opcode.lower()
        # Leave terminators, memory/call ops, metadata, and pinned cmp+br_cond anchors as barriers
        is_fused_cmp = (
            op.startswith("cmp_")
            and i + 1 < n
            and instructions[i + 1].opcode.lower() == "br_cond"
            and isinstance(ins.result, SSAVar)
            and (var_use_counts is None or var_use_counts.get(ins.result, 0) == 1)
        )
        if op not in _PURE_SCHED_OPS or is_fused_cmp:
            out.append(ins)
            i += 1
            continue

        # Collect maximal pure arithmetic window
        j = i
        while j < n:
            op_j = instructions[j].opcode.lower()
            is_fused_j = (
                op_j.startswith("cmp_")
                and j + 1 < n
                and instructions[j + 1].opcode.lower() == "br_cond"
                and isinstance(instructions[j].result, SSAVar)
                and (var_use_counts is None or var_use_counts.get(instructions[j].result, 0) == 1)
            )
            if op_j not in _PURE_SCHED_OPS or is_fused_j:
                break
            j += 1

        win = instructions[i:j]
        i = j
        # Skip reordering if < 3 instructions or if window has no multi-cycle ops or matches packed tree pattern
        has_multi_cycle = any(w.opcode.lower() in _LATENCY_TABLE for w in win)
        if len(win) < 3 or not has_multi_cycle:
            out.extend(win)
            continue

        # Build local RAW DAG
        wlen = len(win)
        local_def: Dict[SSAVar, int] = {}
        preds: List[Set[int]] = [set() for _ in range(wlen)]
        succs: List[List[int]] = [[] for _ in range(wlen)]
        for idx_w, w_ins in enumerate(win):
            for op_item in w_ins.operands:
                if isinstance(op_item, SSAVar) and op_item in local_def:
                    p_idx = local_def[op_item]
                    if p_idx not in preds[idx_w]:
                        preds[idx_w].add(p_idx)
                        succs[p_idx].append(idx_w)
            if isinstance(w_ins.result, SSAVar):
                local_def[w_ins.result] = idx_w

        # Compute critical path latency bottom-up
        cp = [0] * wlen
        for idx_w in range(wlen - 1, -1, -1):
            lat = _LATENCY_TABLE.get(win[idx_w].opcode.lower(), 1)
            cp[idx_w] = lat + (max(cp[s] for s in succs[idx_w]) if succs[idx_w] else 0)

        in_deg = [len(preds[k]) for k in range(wlen)]
        ready = [(-cp[k], k) for k in range(wlen) if in_deg[k] == 0]
        heapq.heapify(ready)
        scheduled: List[SSAInstruction] = []
        while ready:
            _, cur = heapq.heappop(ready)
            scheduled.append(win[cur])
            for s in succs[cur]:
                in_deg[s] -= 1
                if in_deg[s] == 0:
                    heapq.heappush(ready, (-cp[s], s))
        if len(scheduled) == wlen:
            out.extend(scheduled)
        else:
            out.extend(win)
    return out


# ---------------------------------------------------------------------------
# Hacker's Delight / Granlund-Montgomery Magic Multiplier for Fast Division
# ---------------------------------------------------------------------------
def compute_magic_signed_64(d: int) -> Tuple[int, int]:
    """Compute Granlund-Montgomery/Hacker's Delight magic multiplier and shift for 64-bit signed division."""
    assert d != 0 and abs(d) != 1
    two63 = 1 << 63
    ad = abs(d)
    t = two63 + (1 if d < 0 else 0)
    anc = t - 1 - (t % ad)
    p = 63
    q1 = two63 // anc
    r1 = two63 - q1 * anc
    q2 = two63 // ad
    r2 = two63 - q2 * ad
    while True:
        p += 1
        q1 = 2 * q1
        r1 = 2 * r1
        if r1 >= anc:
            q1 += 1
            r1 -= anc
        q2 = 2 * q2
        r2 = 2 * r2
        if r2 >= ad:
            q2 += 1
            r2 -= ad
        delta = ad - r2
        if not (q1 < delta or (q1 == delta and r1 == 0)):
            break
    mag = q2 + 1
    if d < 0:
        mag = -mag
    shift = p - 64
    return mag, shift


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
    coalesced_moves: int = 0
    live_across_call_count: int = 0
    code_end_offset: int = 0


_LUT_PACK_SPEC: Dict[str, Tuple[str, int, int]] = {
    "i8": ("b", 1, 0), "u8": ("B", 1, 0),
    "i16": ("h", 2, 1), "u16": ("H", 2, 1),
    "i32": ("i", 4, 2), "u32": ("I", 4, 2), "f32": ("f", 4, 2),
    "i64": ("q", 8, 3), "u64": ("Q", 8, 3), "f64": ("d", 8, 3),
}


def _pack_lut_bytes(width: str, vals: Tuple[Any, ...]) -> bytes:
    fmt, _, _ = _LUT_PACK_SPEC.get(width, ("q", 8, 3))
    coerced = [float(v) if fmt in ("f", "d") else int(v) for v in vals]
    return struct.pack(f"<{len(coerced)}{fmt}", *coerced)


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

    def jcc(self, jcc_opcode2: int, label: str):
        self.emit(bytes([0x0F, jcc_opcode2, 0x00, 0x00, 0x00, 0x00]))
        self.fixups.append((len(self.code) - 4, label))

    def call_label(self, label: str):
        self.emit(b"\xe8\x00\x00\x00\x00")
        self.fixups.append((len(self.code) - 4, label))

    def lea_r11_label(self, label: str):
        # lea r11, [rip + disp32] -> 4C 8D 1D <disp32>
        self.emit(b"\x4c\x8d\x1d\x00\x00\x00\x00")
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


def _x64_mov_ri(dst: str, imm: int, preserve_flags: bool = False) -> bytes:
    d_hi, d_lo = X64_REGS[dst]
    # Normalize to signed 64-bit
    imm64 = imm & 0xFFFFFFFFFFFFFFFF
    if imm64 >= (1 << 63):
        imm64 -= (1 << 64)
    if imm64 == 0 and not preserve_flags:
        rex = 0x48 | (d_hi << 2) | d_hi
        modrm = 0xC0 | (d_lo << 3) | d_lo
        return bytes([rex, 0x31, modrm])
    if -0x80000000 <= imm64 <= 0x7FFFFFFF:
        rex = 0x48 | d_hi
        modrm = 0xC0 | d_lo
        return bytes([rex, 0xC7, modrm]) + struct.pack("<i", imm64)
    rex = 0x48 | d_hi
    return bytes([rex, 0xB8 + d_lo]) + struct.pack("<q", imm64)


def _x64_lea_add_imm(dst: str, base: str, disp: int) -> bytes:
    d_hi, d_lo = X64_REGS[dst]
    b_hi, b_lo = X64_REGS[base]
    rex = 0x48 | (d_hi << 2) | b_hi
    if -128 <= disp <= 127:
        if b_lo == 4:
            return bytes([rex, 0x8D, 0x44 | (d_lo << 3), 0x24]) + struct.pack("<b", disp)
        return bytes([rex, 0x8D, 0x40 | (d_lo << 3) | b_lo]) + struct.pack("<b", disp)
    if b_lo == 4:
        return bytes([rex, 0x8D, 0x84 | (d_lo << 3), 0x24]) + struct.pack("<i", disp)
    return bytes([rex, 0x8D, 0x80 | (d_lo << 3) | b_lo]) + struct.pack("<i", disp)


def _x64_lea_add_rr(dst: str, base: str, idx: str) -> bytes:
    d_hi, d_lo = X64_REGS[dst]
    b_hi, b_lo = X64_REGS[base]
    i_hi, i_lo = X64_REGS[idx]
    rex = 0x48 | (d_hi << 2) | (i_hi << 1) | b_hi
    sib = (i_lo << 3) | b_lo
    if b_lo == 5:
        return bytes([rex, 0x8D, 0x44 | (d_lo << 3), sib, 0x00])
    return bytes([rex, 0x8D, 0x04 | (d_lo << 3), sib])


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


def _x64_alu_ri32(ext_reg: int, dst: str, imm: int) -> bytes:
    """Emit add(0)/or(1)/and(4)/sub(5)/xor(6)/cmp(7) dst, imm8/imm32."""
    d_hi, d_lo = X64_REGS[dst]
    rex = 0x48 | d_hi
    modrm = 0xC0 | (ext_reg << 3) | d_lo
    if -128 <= imm <= 127:
        return bytes([rex, 0x83, modrm]) + struct.pack("<b", imm)
    return bytes([rex, 0x81, modrm]) + struct.pack("<i", imm)


def _x64_imul_rr(dst: str, src: str) -> bytes:
    d_hi, d_lo = X64_REGS[dst]
    s_hi, s_lo = X64_REGS[src]
    rex = 0x48 | (d_hi << 2) | s_hi
    modrm = 0xC0 | (d_lo << 3) | s_lo
    return bytes([rex, 0x0F, 0xAF, modrm])


def _x64_imul_rri32(dst: str, src: str, imm: int) -> bytes:
    """Emit 3-operand imul dst, src, imm8/imm32."""
    d_hi, d_lo = X64_REGS[dst]
    s_hi, s_lo = X64_REGS[src]
    rex = 0x48 | (d_hi << 2) | s_hi
    modrm = 0xC0 | (d_lo << 3) | s_lo
    if -128 <= imm <= 127:
        return bytes([rex, 0x6B, modrm]) + struct.pack("<b", imm)
    return bytes([rex, 0x69, modrm]) + struct.pack("<i", imm)


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


FLOAT_OPCODES = frozenset({
    "fconst", "fneg", "fadd", "fsub", "fmul", "fdiv",
    "fcmp_eq", "fcmp_ne", "fcmp_lt", "fcmp_le", "fcmp_gt", "fcmp_ge",
    "sitofp", "fptosi",
})


def _f64_bits(val: float) -> int:
    return struct.unpack("<q", struct.pack("<d", float(val)))[0]


def _x64_movq_xmm_r64(xmm_idx: int, reg: str) -> bytes:
    r_hi, r_lo = X64_REGS[reg]
    rex = 0x48 | ((1 if xmm_idx >= 8 else 0) << 2) | r_hi
    modrm = 0xC0 | ((xmm_idx & 7) << 3) | r_lo
    return bytes([0x66, rex, 0x0F, 0x6E, modrm])


def _x64_movq_r64_xmm(reg: str, xmm_idx: int) -> bytes:
    r_hi, r_lo = X64_REGS[reg]
    rex = 0x48 | ((1 if xmm_idx >= 8 else 0) << 2) | r_hi
    modrm = 0xC0 | ((xmm_idx & 7) << 3) | r_lo
    return bytes([0x66, rex, 0x0F, 0x7E, modrm])


def _x64_sse_sd(op_byte: int, dst_xmm: int = 0, src_xmm: int = 1) -> bytes:
    modrm = 0xC0 | ((dst_xmm & 7) << 3) | (src_xmm & 7)
    return bytes([0xF2, 0x0F, op_byte, modrm])


def _x64_ucomisd(xmm_a: int = 0, xmm_b: int = 1) -> bytes:
    modrm = 0xC0 | ((xmm_a & 7) << 3) | (xmm_b & 7)
    return bytes([0x66, 0x0F, 0x2E, modrm])


_HOST_SIMD_FEATURES_CACHE: Optional[Dict[str, Any]] = None


def detect_host_simd_features() -> Dict[str, Any]:
    """
    Executes hardware CPUID (leaves 1 and 7,0) + XGETBV(0) in W^X JIT memory on x86-64
    (Win64 or SysV AMD64) to detect exact silicon + OS-enabled AVX/AVX2/FMA/AVX-512 support.
    """
    global _HOST_SIMD_FEATURES_CACHE
    if _HOST_SIMD_FEATURES_CACHE is not None:
        return dict(_HOST_SIMD_FEATURES_CACHE)

    import platform
    mach = platform.machine().lower()
    if mach in ("aarch64", "arm64"):
        feats = {
            "arch": "arm64",
            "sse2": False, "sse4_1": False, "avx": False, "avx2": False,
            "fma": True, "avx512f": False, "avx512dq": False, "avx512bw": False,
            "avx512vl": False, "osxsave": False, "os_avx": False, "os_avx512": False,
            "neon": True, "recommended_tier": "NEON_128",
        }
        _HOST_SIMD_FEATURES_CACHE = feats
        return dict(feats)

    feats = {
        "arch": "x86_64",
        "sse2": True, "sse4_1": False, "avx": False, "avx2": False,
        "fma": False, "avx512f": False, "avx512dq": False, "avx512bw": False,
        "avx512vl": False, "osxsave": False, "os_avx": False, "os_avx512": False,
        "neon": False, "recommended_tier": "SSE2_128",
    }
    try:
        import ctypes
        from compiler.native_jit import NativeJitMemory

        # Win64 arg0=rcx, SysV arg0=rdi -> mov r8, rcx (49 89 c8) vs mov r8, rdi (49 89 f8)
        arg_mov = b"\x49\x89\xc8" if sys.platform == "win32" else b"\x49\x89\xf8"
        code = (
            b"\x53"                     # push rbx
            + arg_mov                   # mov r8, <arg0>
            + b"\xb8\x01\x00\x00\x00"   # mov eax, 1
            b"\x31\xc9"                 # xor ecx, ecx
            b"\x0f\xa2"                 # cpuid
            b"\x41\x89\x08"             # mov [r8], ecx
            b"\xb8\x07\x00\x00\x00"     # mov eax, 7
            b"\x31\xc9"                 # xor ecx, ecx
            b"\x0f\xa2"                 # cpuid
            b"\x41\x89\x58\x08"         # mov [r8+8], ebx
            b"\x41\x8b\x00"             # mov eax, [r8]
            b"\xa9\x00\x00\x00\x08"     # test eax, 1<<27 (OSXSAVE)
            b"\x74\x09"                 # jz skip_xgetbv
            b"\x31\xc9"                 # xor ecx, ecx
            b"\x0f\x01\xd0"             # xgetbv
            b"\x41\x89\x40\x04"         # mov [r8+4], eax
            b"\xeb\x08"                 # jmp done
            b"\x41\xc7\x40\x04\x00\x00\x00\x00"  # mov dword ptr [r8+4], 0
            b"\x5b"                     # pop rbx
            b"\xc3"                     # ret
        )
        mem = NativeJitMemory(4096)
        try:
            mem.write_code(code)
            out = (ctypes.c_uint32 * 4)()
            ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint32))(mem.ptr)(out)
        finally:
            mem.free()

        ecx1, xcr0, ebx7 = int(out[0]), int(out[1]), int(out[2])
        sse4_1 = bool(ecx1 & (1 << 19))
        osxsave = bool(ecx1 & (1 << 27))
        avx_hw = bool(ecx1 & (1 << 28))
        os_avx = osxsave and avx_hw and ((xcr0 & 0x6) == 0x6)
        os_avx512 = os_avx and ((xcr0 & 0xE0) == 0xE0)
        avx2 = os_avx and bool(ebx7 & (1 << 5))
        fma = os_avx and bool(ecx1 & (1 << 12))
        avx512f = os_avx512 and bool(ebx7 & (1 << 16))
        avx512dq = os_avx512 and bool(ebx7 & (1 << 17))
        avx512bw = os_avx512 and bool(ebx7 & (1 << 30))
        avx512vl = os_avx512 and bool(ebx7 & (1 << 31))

        tier = (
            "AVX512_512" if avx512f
            else ("AVX2_FMA" if (avx2 and fma)
                  else ("AVX2_256" if avx2
                        else ("AVX_256" if os_avx
                              else ("SSE4_128" if sse4_1 else "SSE2_128"))))
        )
        feats.update({
            "sse4_1": sse4_1, "avx": os_avx, "osxsave": osxsave,
            "os_avx": os_avx, "os_avx512": os_avx512,
            "avx2": avx2, "fma": fma,
            "avx512f": avx512f, "avx512dq": avx512dq,
            "avx512bw": avx512bw, "avx512vl": avx512vl,
            "recommended_tier": tier,
        })
    except Exception:
        pass
    _HOST_SIMD_FEATURES_CACHE = feats
    return dict(feats)


def _host_supports_avx2() -> bool:
    return bool(detect_host_simd_features().get("avx2", False))


def _match_contiguous_fma_sources(
    vals: List[Any],
    blk_def_map: Dict[SSAVar, SSAInstruction],
    expected_width: str,
    fn_add_const: Dict[Any, Tuple[Any, int]],
    elem_bytes: int,
) -> Optional[Tuple[SSAInstruction, SSAInstruction, SSAInstruction]]:
    """Matches `a[i] * b[i] + c[i]` (or `c[i] + a[i] * b[i]`) across `len(vals)` contiguous lanes."""
    inss = [blk_def_map.get(v) if isinstance(v, SSAVar) else None for v in vals]
    if not all(x is not None and x.opcode.lower() == "fadd" and len(x.operands) == 2 for x in inss):
        return None
    mul_l = [blk_def_map.get(x.operands[0]) if isinstance(x.operands[0], SSAVar) else None for x in inss]  # type: ignore[union-attr]
    mul_r = [blk_def_map.get(x.operands[1]) if isinstance(x.operands[1], SSAVar) else None for x in inss]  # type: ignore[union-attr]
    if all(m is not None and m.opcode.lower() == "fmul" and len(m.operands) == 2 for m in mul_l):
        muls, add_ops = mul_l, [x.operands[1] for x in inss]  # type: ignore[union-attr]
    elif all(m is not None and m.opcode.lower() == "fmul" and len(m.operands) == 2 for m in mul_r):
        muls, add_ops = mul_r, [x.operands[0] for x in inss]  # type: ignore[union-attr]
    else:
        return None
    lda = [blk_def_map.get(m.operands[0]) if isinstance(m.operands[0], SSAVar) else None for m in muls]  # type: ignore[union-attr]
    ldb = [blk_def_map.get(m.operands[1]) if isinstance(m.operands[1], SSAVar) else None for m in muls]  # type: ignore[union-attr]
    ldc = [blk_def_map.get(c) if isinstance(c, SSAVar) else None for c in add_ops]
    for grp in (lda, ldb, ldc):
        if not all(x is not None and x.opcode.lower() == "load_off" and len(x.operands) >= 3 and str(x.operands[2]) == expected_width for x in grp):
            return None
        if len({x.operands[0] for x in grp}) != 1:  # type: ignore[union-attr]
            return None
        if not is_contiguous_stride(fn_add_const, [x.operands[1] for x in grp], elem_bytes):  # type: ignore[union-attr]
            return None
    return lda[0], ldb[0], ldc[0]  # type: ignore[return-value]


def _match_contiguous_binary_alu_sources(
    vals: List[Any],
    blk_def_map: Dict[SSAVar, SSAInstruction],
    op_table: Dict[str, bytes],
    allowed_widths: Tuple[str, ...],
    fn_add_const: Dict[Any, Tuple[Any, int]],
    elem_bytes: int,
) -> Optional[Tuple[str, SSAInstruction, SSAInstruction]]:
    """Matches uniform binary ALU (`add`/`sub`/`mul`/bitwise/`f*`) fed by two contiguous load streams."""
    inss = [blk_def_map.get(v) if isinstance(v, SSAVar) else None for v in vals]
    if not all(x is not None and len(x.operands) == 2 for x in inss):
        return None
    ops_set = {x.opcode.lower() for x in inss}  # type: ignore[union-attr]
    if len(ops_set) != 1:
        return None
    op_name = next(iter(ops_set))
    if op_name not in op_table:
        return None
    lda = [blk_def_map.get(x.operands[0]) if isinstance(x.operands[0], SSAVar) else None for x in inss]  # type: ignore[union-attr]
    ldb = [blk_def_map.get(x.operands[1]) if isinstance(x.operands[1], SSAVar) else None for x in inss]  # type: ignore[union-attr]
    for grp in (lda, ldb):
        if not all(x is not None and x.opcode.lower() == "load_off" and len(x.operands) >= 3 and str(x.operands[2]) in allowed_widths for x in grp):
            return None
        if len({str(x.operands[2]) for x in grp}) != 1 or len({x.operands[0] for x in grp}) != 1:  # type: ignore[union-attr]
            return None
        if not is_contiguous_stride(fn_add_const, [x.operands[1] for x in grp], elem_bytes):  # type: ignore[union-attr]
            return None
    return op_name, lda[0], ldb[0]  # type: ignore[return-value]


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

    def __init__(
        self,
        target_os: Optional[str] = None,
        enable_avx2: Optional[bool] = None,
        enable_fma: Optional[bool] = None,
        enable_avx512: Optional[bool] = None,
        enable_avx512dq: Optional[bool] = None,
    ):
        if target_os is None:
            self.is_windows = sys.platform == "win32"
        else:
            self.is_windows = target_os.lower() in ("windows", "win32", "pe", "pe64", "pe_dll")
        self.abi = "win64" if self.is_windows else "sysv_amd64"
        self.param_regs = WIN64_PARAM_REGS if self.is_windows else SYSV_PARAM_REGS
        self.callee_saved_pool = WIN64_CALLEE_SAVED if self.is_windows else SYSV_CALLEE_SAVED
        self.host_simd = detect_host_simd_features()
        self.enable_avx2 = bool(self.host_simd.get("avx2", False)) if enable_avx2 is None else bool(enable_avx2)
        self.enable_fma = (bool(self.host_simd.get("fma", False)) if enable_fma is None else bool(enable_fma)) and self.enable_avx2
        self.enable_avx512 = (bool(self.host_simd.get("avx512f", False)) if enable_avx512 is None else bool(enable_avx512)) and self.enable_avx2
        self.enable_avx512dq = (bool(self.host_simd.get("avx512dq", False)) if enable_avx512dq is None else bool(enable_avx512dq)) and self.enable_avx512

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

        # Map constant integers for fast reciprocal division & immediate ALU folding
        const_int_map: Dict[SSAVar, int] = {}
        var_use_counts: Dict[SSAVar, int] = {}
        for b in fn.blocks:
            for phi in b.phi_nodes:
                for op_item in phi.operands:
                    if isinstance(op_item, SSAVar):
                        var_use_counts[op_item] = var_use_counts.get(op_item, 0) + 1
                for _, pv in phi.phi_incoming:
                    if isinstance(pv, SSAVar):
                        var_use_counts[pv] = var_use_counts.get(pv, 0) + 1
            for inst in b.instructions:
                for op_item in inst.operands:
                    if isinstance(op_item, SSAVar):
                        var_use_counts[op_item] = var_use_counts.get(op_item, 0) + 1
                if inst.opcode.lower() == "const" and isinstance(inst.result, SSAVar):
                    if inst.operands:
                        c_val = inst.operands[0]
                        if isinstance(c_val, int) and not isinstance(c_val, bool):
                            const_int_map[inst.result] = c_val
                        elif isinstance(c_val, str) and (c_val.isdigit() or (c_val.startswith("-") and c_val[1:].isdigit())):
                            const_int_map[inst.result] = int(c_val)

        # Pre-allocation Critical-Path DAG Scheduling (preserves liveness invariants!)
        orig_block_insts = [(b, b.instructions) for b in fn.blocks]
        for b, orig_ins in orig_block_insts:
            b.instructions = _schedule_basic_block_instructions(orig_ins, var_use_counts)

        # Determine Leaf Register-Resident Mode vs General Stack-Frame Mode via George & Appel IRC
        alloca_insts = [inst for b in fn.blocks for inst in b.instructions if inst.opcode == "alloca"]
        has_alloca = len(alloca_insts) > 0
        has_f64 = (
            getattr(fn, "return_type", "i64") == "f64"
            or any(t == "f64" for t in fn.param_types.values())
            or any(
                inst.opcode in FLOAT_OPCODES or (inst.result is not None and inst.result.var_type == "f64")
                for b in fn.blocks
                for inst in b.instructions
            )
        )
        has_mem_off = any(
            ins.opcode.lower() in ("load_off", "store_off")
            for b in fn.blocks
            for ins in b.instructions
        )
        reg_eligible = (
            (not has_calls)
            and (not has_alloca)
            and (not has_f64)
            and len(fn.params) <= len(self.param_regs)
        )

        # Identify imm32-foldable constants before register allocation so they don't consume registers
        _FOLDABLE_IMM_OPS = frozenset({
            "add", "sub", "and", "or", "xor", "mul", "imul",
            "div", "sdiv", "srem", *self.SETCC_BYTES.keys(),
        })
        inlined_consts: Set[SSAVar] = set()
        if reg_eligible and (not has_mem_off) and const_int_map:
            candidates = {
                v for v, cval in const_int_map.items()
                if -0x80000000 <= cval <= 0x7FFFFFFF
            }
            for b in fn.blocks:
                for phi in b.phi_nodes:
                    for op_item in phi.operands:
                        candidates.discard(op_item)
                    for _, pv in phi.phi_incoming:
                        candidates.discard(pv)
                for ins in b.instructions:
                    iop = ins.opcode.lower()
                    for idx_o, op_item in enumerate(ins.operands):
                        if not isinstance(op_item, SSAVar) or op_item not in candidates:
                            continue
                        if iop not in _FOLDABLE_IMM_OPS or idx_o != 1:
                            candidates.discard(op_item)
            inlined_consts = candidates

        alloc = IteratedRegisterCoalescingAllocator(
            LEAF_ALLOC_REGS,
            abi="win64" if self.is_windows else "sysv64",
        ).allocate(fn, ignore_vars=inlined_consts if reg_eligible else None)

        reg_map: Dict[SSAVar, str] = {}
        slot_map: Dict[SSAVar, int] = {}
        alloca_map: Dict[SSAVar, int] = {}
        used_callee_saved: List[str] = []

        if reg_eligible and (alloc["success"] or not has_mem_off):
            reg_map = dict(alloc["color_map"])
            spilled_vars = [
                v for v in all_vars
                if v not in reg_map and v not in inlined_consts
            ]
            # Wait: only enter leaf_mode / pure_leaf_mode if colored; any uncolored go to slot_map!
            leaf_mode = True
            pure_leaf_mode = (len(spilled_vars) == 0)
            used_regs = set(reg_map.values())
            used_callee_saved = [r for r in self.callee_saved_pool if r in used_regs]
            if pure_leaf_mode:
                frame_size = 0
            else:
                for idx, v in enumerate(spilled_vars):
                    slot_map[v] = -8 * (idx + 1)
                frame_size = ((len(spilled_vars) * 8 + 15) // 16) * 16
        else:
            leaf_mode = False
            pure_leaf_mode = False
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
        if pure_leaf_mode:
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
        elif leaf_mode:
            # Hybrid Register + Spill Mode: rbp frame for spilled_vars + callee-saved pushes + reg params
            buf.emit(b"\x55")              # push rbp
            buf.emit(b"\x48\x89\xe5")      # mov rbp, rsp
            if frame_size > 0:
                if frame_size <= 127:
                    buf.emit(b"\x48\x83\xec" + struct.pack("<B", frame_size))
                else:
                    buf.emit(b"\x48\x81\xec" + struct.pack("<I", frame_size))
            for r in used_callee_saved:
                buf.emit(_x64_push(r))
            prologue_size = len(buf.code)
            param_copies_h: List[Tuple[Any, Any]] = []
            for idx, p_name in enumerate(fn.params):
                p_var = SSAVar(p_name, 0)
                if p_var in reg_map:
                    param_copies_h.append((("reg", reg_map[p_var]), ("reg", self.param_regs[idx])))
                elif p_var in slot_map:
                    param_copies_h.append((("slot", slot_map[p_var]), ("reg", self.param_regs[idx])))
            for dst_loc, src_loc in _sequentialize_parallel_copies(param_copies_h, ("reg", "r11")):
                if dst_loc[0] == "reg":
                    buf.emit(_x64_mov_rr(dst_loc[1], src_loc[1]))
                else:
                    buf.emit(_x64_store_rbp(dst_loc[1], src_loc[1]))
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
            sysv_int_idx = 0
            sysv_fp_idx = 0
            sysv_stack_idx = 0
            for idx, p_name in enumerate(fn.params):
                p_var = SSAVar(p_name, 0)
                if p_var not in slot_map:
                    continue
                is_fp = fn.param_types.get(p_name) == "f64"
                if self.is_windows:
                    if idx < len(self.param_regs):
                        if is_fp:
                            buf.emit(_x64_movq_r64_xmm("rax", idx))
                            buf.emit(_x64_store_rbp(slot_map[p_var], "rax"))
                        else:
                            buf.emit(_x64_store_rbp(slot_map[p_var], self.param_regs[idx]))
                    else:
                        caller_disp = 16 + 32 + (idx - len(self.param_regs)) * 8
                        buf.emit(_x64_load_rbp("rax", caller_disp))
                        buf.emit(_x64_store_rbp(slot_map[p_var], "rax"))
                else:
                    if is_fp:
                        if sysv_fp_idx < 8:
                            buf.emit(_x64_movq_r64_xmm("rax", sysv_fp_idx))
                            buf.emit(_x64_store_rbp(slot_map[p_var], "rax"))
                            sysv_fp_idx += 1
                        else:
                            caller_disp = 16 + sysv_stack_idx * 8
                            sysv_stack_idx += 1
                            buf.emit(_x64_load_rbp("rax", caller_disp))
                            buf.emit(_x64_store_rbp(slot_map[p_var], "rax"))
                    else:
                        if sysv_int_idx < len(SYSV_PARAM_REGS):
                            buf.emit(_x64_store_rbp(slot_map[p_var], SYSV_PARAM_REGS[sysv_int_idx]))
                            sysv_int_idx += 1
                        else:
                            caller_disp = 16 + sysv_stack_idx * 8
                            sysv_stack_idx += 1
                            buf.emit(_x64_load_rbp("rax", caller_disp))
                            buf.emit(_x64_store_rbp(slot_map[p_var], "rax"))

        def resolve_operand_to_reg(op: Any, target_reg: str) -> None:
            if isinstance(op, float):
                buf.emit(_x64_mov_ri(target_reg, _f64_bits(op)))
                return
            if isinstance(op, bool):
                buf.emit(_x64_mov_ri(target_reg, int(op)))
                return
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
                if op in inlined_consts and op in const_int_map:
                    buf.emit(_x64_mov_ri(target_reg, const_int_map[op]))
                    return
                if leaf_mode:
                    if op in reg_map:
                        buf.emit(_x64_mov_rr(target_reg, reg_map[op]))
                        return
                    disp = slot_map.get(op)
                    if disp is not None:
                        buf.emit(_x64_load_rbp(target_reg, disp))
                        return
                    buf.emit(_x64_mov_rr(target_reg, "r8"))
                else:
                    disp = slot_map.get(op)
                    if disp is not None:
                        buf.emit(_x64_load_rbp(target_reg, disp))
                    else:
                        buf.emit(_x64_mov_ri(target_reg, 0))
                return
            buf.emit(_x64_mov_ri(target_reg, 0))

        def _get_imm32(op: Any) -> Optional[int]:
            v = None
            if isinstance(op, int) and not isinstance(op, bool):
                v = op
            elif isinstance(op, str):
                s = op.strip()
                if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                    v = int(s)
            elif isinstance(op, SSAVar) and op in const_int_map:
                v = const_int_map[op]
            if v is not None and -0x80000000 <= v <= 0x7FFFFFFF:
                return v
            return None

        def write_result_from_reg(res_var: Optional[SSAVar], src_reg: str) -> None:
            if res_var is None:
                return
            if leaf_mode:
                if res_var in reg_map:
                    buf.emit(_x64_mov_rr(reg_map[res_var], src_reg))
                elif res_var in slot_map:
                    buf.emit(_x64_store_rbp(slot_map[res_var], src_reg))
            else:
                buf.emit(_x64_store_rbp(slot_map[res_var], src_reg))

        def _build_phi_copy_seq(pred_name: str, succ_block: BasicBlock) -> Tuple[List[Tuple[Any, Any]], Set[Any]]:
            if not succ_block.phi_nodes:
                return [], set()
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

                if pure_leaf_mode:
                    dst_loc = reg_map[phi.result]
                    if isinstance(chosen_val, SSAVar):
                        src_loc: Any = reg_map[chosen_val]
                    elif isinstance(chosen_val, float):
                        src_loc = ("imm", _f64_bits(chosen_val))
                    elif isinstance(chosen_val, int):
                        src_loc = ("imm", chosen_val)
                    else:
                        src_loc = ("imm", 0)
                    copies.append((dst_loc, src_loc))
                elif leaf_mode:
                    dst_loc = ("reg", reg_map[phi.result]) if phi.result in reg_map else ("slot", slot_map[phi.result])
                    if isinstance(chosen_val, SSAVar):
                        if chosen_val in reg_map:
                            src_loc = ("reg", reg_map[chosen_val])
                        elif chosen_val in slot_map:
                            src_loc = ("slot", slot_map[chosen_val])
                        else:
                            src_loc = ("imm", const_int_map.get(chosen_val, 0))
                    elif isinstance(chosen_val, float):
                        src_loc = ("imm", _f64_bits(chosen_val))
                    elif isinstance(chosen_val, int):
                        src_loc = ("imm", chosen_val)
                    else:
                        src_loc = ("imm", 0)
                    copies.append((dst_loc, src_loc))
                else:
                    dst_loc = ("slot", slot_map[phi.result])
                    if isinstance(chosen_val, SSAVar):
                        src_loc = ("slot", slot_map[chosen_val])
                    elif isinstance(chosen_val, float):
                        src_loc = ("imm", _f64_bits(chosen_val))
                    elif isinstance(chosen_val, int):
                        src_loc = ("imm", chosen_val)
                    else:
                        src_loc = ("imm", 0)
                    copies.append((dst_loc, src_loc))

            seq = _sequentialize_parallel_copies(copies, "r11" if pure_leaf_mode else ("reg", "r11"))
            written: Set[Any] = set()
            for dst_loc, src_loc in seq:
                if dst_loc == src_loc:
                    continue
                if pure_leaf_mode:
                    written.add(("reg", dst_loc))
                else:
                    written.add(dst_loc)
                    if (
                        (isinstance(src_loc, tuple) and src_loc[0] in ("imm", "slot"))
                    ):
                        written.add(("reg", "rax"))
            return seq, written

        def emit_phi_copies_for_edge(pred_name: str, succ_block: BasicBlock, preserve_flags: bool = False):
            if not succ_block.phi_nodes:
                return
            seq, _ = _build_phi_copy_seq(pred_name, succ_block)
            for dst_loc, src_loc in seq:
                if pure_leaf_mode:
                    if isinstance(src_loc, tuple) and src_loc[0] == "imm":
                        buf.emit(_x64_mov_ri(dst_loc, src_loc[1], preserve_flags=preserve_flags))
                    else:
                        buf.emit(_x64_mov_rr(dst_loc, src_loc))
                else:
                    if isinstance(src_loc, tuple) and src_loc[0] == "imm":
                        val_reg = "rax"
                        buf.emit(_x64_mov_ri("rax", src_loc[1], preserve_flags=preserve_flags))
                    elif isinstance(src_loc, tuple) and src_loc[0] == "reg":
                        val_reg = src_loc[1]
                    else:
                        val_reg = "rax"
                        buf.emit(_x64_load_rbp("rax", src_loc[1]))

                    if isinstance(dst_loc, tuple) and dst_loc[0] == "reg":
                        buf.emit(_x64_mov_rr(dst_loc[1], val_reg))
                    else:
                        buf.emit(_x64_store_rbp(dst_loc[1], val_reg))

        def _var_loc(v: Any) -> Optional[Tuple[str, Any]]:
            if not isinstance(v, SSAVar) or v in inlined_consts:
                return None
            if pure_leaf_mode:
                return ("reg", reg_map[v]) if v in reg_map else None
            if leaf_mode:
                if v in reg_map:
                    return ("reg", reg_map[v])
                if v in slot_map:
                    return ("slot", slot_map[v])
                return None
            return ("slot", slot_map[v]) if v in slot_map else None

        def _self_loop_pre_jcc_safe(blk: BasicBlock, false_bb: Optional[BasicBlock]) -> bool:
            _, written = _build_phi_copy_seq(blk.name, blk)
            if not written:
                return True
            if ("reg", "rax") in written or ("reg", "r11") in written:
                return False
            phi_res_vars = {p.result for p in blk.phi_nodes if p.result is not None}
            if false_bb is not None:
                for fp in false_bb.phi_nodes:
                    for bn, val in fp.phi_incoming:
                        if bn == blk.name:
                            loc = _var_loc(val)
                            if loc in written or (isinstance(val, SSAVar) and val in phi_res_vars):
                                return False
            for other_b in fn.blocks:
                if other_b is blk:
                    continue
                for op_p in other_b.phi_nodes:
                    for bn, val in op_p.phi_incoming:
                        if other_b is false_bb and bn == blk.name:
                            continue
                        if isinstance(val, SSAVar):
                            if val in phi_res_vars or _var_loc(val) in written:
                                return False
                for ins_o in other_b.instructions:
                    for operand in ins_o.operands:
                        if isinstance(operand, SSAVar):
                            if operand in phi_res_vars or _var_loc(operand) in written:
                                return False
            return True

        block_map: Dict[str, BasicBlock] = {b.name: b for b in fn.blocks}
        edge_trampolines: List[Tuple[str, str, BasicBlock]] = []

        def branch_target_label(pred_name: str, succ_name: str) -> str:
            succ_bb = block_map.get(succ_name)
            if succ_bb is not None and len(succ_bb.phi_nodes) > 0:
                tramp_label = f".L_edge_{pred_name}_to_{succ_name}_{len(edge_trampolines)}"
                edge_trampolines.append((tramp_label, pred_name, succ_bb))
                return tramp_label
            return f".L_bb_{succ_name}"

        _SSE2_PACKED_ALU_OPS: Dict[str, bytes] = {
            "add": b"\x66\x0f\xd4\xc1",   # paddq xmm0, xmm1
            "sub": b"\x66\x0f\xfb\xc1",   # psubq xmm0, xmm1
            "and": b"\x66\x0f\xdb\xc1",   # pand xmm0, xmm1
            "or":  b"\x66\x0f\xeb\xc1",   # por xmm0, xmm1
            "xor": b"\x66\x0f\xef\xc1",   # pxor xmm0, xmm1
            "fadd": b"\x66\x0f\x58\xc1",  # addpd xmm0, xmm1
            "fsub": b"\x66\x0f\x5c\xc1",  # subpd xmm0, xmm1
            "fmul": b"\x66\x0f\x59\xc1",  # mulpd xmm0, xmm1
        }
        _SSE2_PACKED_32B_ALU_OPS: Dict[str, bytes] = {
            "add": b"\x66\x0f\xfe\xc1",   # paddd xmm0, xmm1
            "sub": b"\x66\x0f\xfa\xc1",   # psubd xmm0, xmm1
            "mul": b"\x66\x0f\x38\x40\xc1",   # pmulld xmm0, xmm1
            "imul": b"\x66\x0f\x38\x40\xc1",  # pmulld xmm0, xmm1
            "and": b"\x66\x0f\xdb\xc1",   # pand xmm0, xmm1
            "or":  b"\x66\x0f\xeb\xc1",   # por xmm0, xmm1
            "xor": b"\x66\x0f\xef\xc1",   # pxor xmm0, xmm1
            "fadd": b"\x0f\x58\xc1",      # addps xmm0, xmm1
            "fsub": b"\x0f\x5c\xc1",      # subps xmm0, xmm1
            "fmul": b"\x0f\x59\xc1",      # mulps xmm0, xmm1
        }
        _AVX2_PACKED_64B_ALU_OPS: Dict[str, bytes] = {
            "add":  b"\xc5\xfd\xd4\xc1",  # vpaddq ymm0, ymm0, ymm1
            "sub":  b"\xc5\xfd\xfb\xc1",  # vpsubq ymm0, ymm0, ymm1
            "and":  b"\xc5\xfd\xdb\xc1",  # vpand ymm0, ymm0, ymm1
            "or":   b"\xc5\xfd\xeb\xc1",  # vpor ymm0, ymm0, ymm1
            "xor":  b"\xc5\xfd\xef\xc1",  # vpxor ymm0, ymm0, ymm1
            "fadd": b"\xc5\xfd\x58\xc1",  # vaddpd ymm0, ymm0, ymm1
            "fsub": b"\xc5\xfd\x5c\xc1",  # vsubpd ymm0, ymm0, ymm1
            "fmul": b"\xc5\xfd\x59\xc1",  # vmulpd ymm0, ymm0, ymm1
        }
        _AVX512_PACKED_64B_ALU_OPS: Dict[str, bytes] = {
            "add":  b"\x62\xf1\xfd\x48\xd4\xc1",  # vpaddq zmm0, zmm0, zmm1
            "sub":  b"\x62\xf1\xfd\x48\xfb\xc1",  # vpsubq zmm0, zmm0, zmm1
            "and":  b"\x62\xf1\xfd\x48\xdb\xc1",  # vpandq zmm0, zmm0, zmm1
            "or":   b"\x62\xf1\xfd\x48\xeb\xc1",  # vporq  zmm0, zmm0, zmm1
            "xor":  b"\x62\xf1\xfd\x48\xef\xc1",  # vpxorq zmm0, zmm0, zmm1
            "fadd": b"\x62\xf1\xfd\x48\x58\xc1",  # vaddpd zmm0, zmm0, zmm1
            "fsub": b"\x62\xf1\xfd\x48\x5c\xc1",  # vsubpd zmm0, zmm0, zmm1
            "fmul": b"\x62\xf1\xfd\x48\x59\xc1",  # vmulpd zmm0, zmm0, zmm1
        }
        if self.enable_avx512dq:
            _AVX512_PACKED_64B_ALU_OPS["mul"] = b"\x62\xf2\xfd\x48\x40\xc1"   # vpmullq zmm0, zmm0, zmm1
            _AVX512_PACKED_64B_ALU_OPS["imul"] = b"\x62\xf2\xfd\x48\x40\xc1"  # vpmullq zmm0, zmm0, zmm1
        _AVX2_PACKED_32B_ALU_OPS: Dict[str, bytes] = {
            "add":  b"\xc5\xfd\xfe\xc1",      # vpaddd ymm0, ymm0, ymm1
            "sub":  b"\xc5\xfd\xfa\xc1",      # vpsubd ymm0, ymm0, ymm1
            "mul":  b"\xc4\xe2\x7d\x40\xc1",  # vpmulld ymm0, ymm0, ymm1
            "imul": b"\xc4\xe2\x7d\x40\xc1",  # vpmulld ymm0, ymm0, ymm1
            "and":  b"\xc5\xfd\xdb\xc1",      # vpand ymm0, ymm0, ymm1
            "or":   b"\xc5\xfd\xeb\xc1",      # vpor ymm0, ymm0, ymm1
            "xor":  b"\xc5\xfd\xef\xc1",      # vpxor ymm0, ymm0, ymm1
            "fadd": b"\xc5\xfc\x58\xc1",      # vaddps ymm0, ymm0, ymm1
            "fsub": b"\xc5\xfc\x5c\xc1",      # vsubps ymm0, ymm0, ymm1
            "fmul": b"\xc5\xfc\x59\xc1",      # vmulps ymm0, ymm0, ymm1
        }
        used_avx2_ymm = False
        fn_add_const = analyze_ssa_constant_offsets(fn)

        # --- Emit Basic Blocks ---
        for idx_b, block in enumerate(fn.blocks):
            buf.mark(f".L_bb_{block.name}")
            block_insts = block.instructions
            blk_def_map: Dict[SSAVar, SSAInstruction] = {
                b_ins.result: b_ins
                for b_ins in block_insts
                if isinstance(b_ins.result, SSAVar)
            }

            def _are_contiguous_8b_offsets(off0: Any, off1: Any) -> bool:
                return is_contiguous_stride(fn_add_const, [off0, off1], 8)

            def _are_contiguous_8b_quad(off0: Any, off1: Any, off2: Any, off3: Any) -> bool:
                return is_contiguous_stride(fn_add_const, [off0, off1, off2, off3], 8)

            def _are_contiguous_4b_quad(off0: Any, off1: Any, off2: Any, off3: Any) -> bool:
                return is_contiguous_stride(fn_add_const, [off0, off1, off2, off3], 4)

            def _are_contiguous_4b_oct(offs: List[Any]) -> bool:
                return is_contiguous_stride(fn_add_const, offs, 4)

            inst_idx = 0
            while inst_idx < len(block_insts):
                inst = block_insts[inst_idx]
                inst_idx += 1
                buf.record_line(inst.source_line)
                op = inst.opcode.lower()

                if op == "param":
                    continue

                elif op in ("const", "fconst", "mov"):
                    if op == "const" and isinstance(inst.result, SSAVar) and inst.result in inlined_consts:
                        continue
                    if leaf_mode and isinstance(inst.result, SSAVar) and inst.result in reg_map:
                        resolve_operand_to_reg(inst.operands[0], reg_map[inst.result])
                    else:
                        resolve_operand_to_reg(inst.operands[0], "rax")
                        write_result_from_reg(inst.result, "rax")

                elif op in ("add", "sub", "and", "or", "xor"):
                    if op in ("add", "and", "or", "xor") and inst_idx + 1 < len(block_insts):
                        ins_hi = block_insts[inst_idx]
                        ins_top = block_insts[inst_idx + 1]
                        if (
                            ins_hi.opcode.lower() == op
                            and ins_top.opcode.lower() == op
                            and isinstance(inst.result, SSAVar)
                            and isinstance(ins_hi.result, SSAVar)
                            and inst.result != ins_hi.result
                            and inst.result not in ins_hi.operands
                            and len(inst.operands) == 2
                            and len(ins_hi.operands) == 2
                            and len(ins_top.operands) == 2
                            and set(ins_top.operands) == {inst.result, ins_hi.result}
                        ):
                            resolve_operand_to_reg(inst.operands[0], "rax")
                            buf.emit(_x64_movq_xmm_r64(0, "rax"))
                            resolve_operand_to_reg(ins_hi.operands[0], "rax")
                            buf.emit(_x64_movq_xmm_r64(1, "rax"))
                            buf.emit(b"\x66\x0f\x6c\xc1")            # punpcklqdq xmm0, xmm1
                            resolve_operand_to_reg(inst.operands[1], "rax")
                            buf.emit(_x64_movq_xmm_r64(1, "rax"))
                            resolve_operand_to_reg(ins_hi.operands[1], "rax")
                            buf.emit(_x64_movq_xmm_r64(2, "rax"))
                            buf.emit(b"\x66\x0f\x6c\xca")            # punpcklqdq xmm1, xmm2
                            buf.emit(_SSE2_PACKED_ALU_OPS[op])       # paddq/pand/por/pxor xmm0, xmm1
                            buf.emit(_x64_movq_r64_xmm("rax", 0))
                            write_result_from_reg(inst.result, "rax")
                            buf.emit(b"\x66\x0f\x70\xc8\x4e")        # pshufd xmm1, xmm0, 0x4E
                            buf.emit(_x64_movq_r64_xmm("rax", 1))
                            write_result_from_reg(ins_hi.result, "rax")
                            buf.emit(_SSE2_PACKED_ALU_OPS[op])       # horizontal collapse xmm0, xmm1
                            buf.emit(_x64_movq_r64_xmm("rax", 0))
                            write_result_from_reg(ins_top.result, "rax")
                            buf.record_line(ins_top.source_line)
                            inst_idx += 2
                            continue

                    alu_byte = {"add": 0x01, "sub": 0x29, "and": 0x21, "or": 0x09, "xor": 0x31}[op]
                    alu_ext = {"add": 0, "or": 1, "and": 4, "sub": 5, "xor": 6}[op]
                    if leaf_mode and isinstance(inst.result, SSAVar) and inst.result in reg_map:
                        dst_r = reg_map[inst.result]
                        op0, op1 = inst.operands[0], inst.operands[1]
                        c_imm1 = _get_imm32(op1)
                        c_imm0 = _get_imm32(op0) if op != "sub" else None
                        if c_imm1 is None and c_imm0 is not None:
                            op0, op1, c_imm1 = op1, op0, c_imm0
                        if c_imm1 is not None and isinstance(op0, SSAVar) and op0 in reg_map and op0 not in inlined_consts:
                            r0 = reg_map[op0]
                            if op == "add" and dst_r != r0:
                                buf.emit(_x64_lea_add_imm(dst_r, r0, c_imm1))
                            else:
                                buf.emit(_x64_mov_rr(dst_r, r0))
                                buf.emit(_x64_alu_ri32(alu_ext, dst_r, c_imm1))
                            continue
                        if (
                            isinstance(op0, SSAVar) and op0 in reg_map and op0 not in inlined_consts
                            and isinstance(op1, SSAVar) and op1 in reg_map and op1 not in inlined_consts
                        ):
                            r0, r1 = reg_map[op0], reg_map[op1]
                            if dst_r != r1:
                                if op == "add" and dst_r != r0 and r1 not in ("rsp", "r12"):
                                    buf.emit(_x64_lea_add_rr(dst_r, r0, r1))
                                else:
                                    buf.emit(_x64_mov_rr(dst_r, r0))
                                    buf.emit(_x64_alu_rr(alu_byte, dst_r, r1))
                                continue
                            elif op != "sub":
                                # dst_r == r1 and op is commutative: op dst_r, r0!
                                buf.emit(_x64_alu_rr(alu_byte, dst_r, r0))
                                continue
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    resolve_operand_to_reg(inst.operands[1], "r11")
                    buf.emit(_x64_alu_rr(alu_byte, "rax", "r11"))
                    write_result_from_reg(inst.result, "rax")

                elif op in ("mul", "imul"):
                    if leaf_mode and isinstance(inst.result, SSAVar) and inst.result in reg_map:
                        dst_r = reg_map[inst.result]
                        op0, op1 = inst.operands[0], inst.operands[1]
                        c_imm1 = _get_imm32(op1)
                        c_imm0 = _get_imm32(op0)
                        if c_imm1 is None and c_imm0 is not None:
                            op0, op1, c_imm1 = op1, op0, c_imm0
                        if c_imm1 is not None and isinstance(op0, SSAVar) and op0 in reg_map and op0 not in inlined_consts:
                            buf.emit(_x64_imul_rri32(dst_r, reg_map[op0], c_imm1))
                            continue
                        if (
                            isinstance(op0, SSAVar) and op0 in reg_map and op0 not in inlined_consts
                            and isinstance(op1, SSAVar) and op1 in reg_map and op1 not in inlined_consts
                        ):
                            r0, r1 = reg_map[op0], reg_map[op1]
                            if dst_r != r1:
                                buf.emit(_x64_mov_rr(dst_r, r0))
                                buf.emit(_x64_imul_rr(dst_r, r1))
                                continue
                            else:
                                buf.emit(_x64_imul_rr(dst_r, r0))
                                continue
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    resolve_operand_to_reg(inst.operands[1], "r11")
                    buf.emit(_x64_imul_rr("rax", "r11"))
                    write_result_from_reg(inst.result, "rax")

                elif op in ("div", "sdiv", "srem"):
                    def _get_const_int(operand: Any) -> Optional[int]:
                        if isinstance(operand, int) and not isinstance(operand, bool):
                            return operand
                        if isinstance(operand, str):
                            s = operand.strip()
                            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                                return int(s)
                        if isinstance(operand, SSAVar):
                            return const_int_map.get(operand)
                        return None

                    c_div = _get_const_int(inst.operands[1]) if len(inst.operands) > 1 else None
                    if c_div is not None and c_div != 0:
                        if c_div == 1:
                            resolve_operand_to_reg(inst.operands[0], "rax")
                            if op == "srem":
                                buf.emit(b"\x48\x31\xc0")  # xor rax, rax
                            write_result_from_reg(inst.result, "rax")
                        elif c_div == -1:
                            resolve_operand_to_reg(inst.operands[0], "rax")
                            if op == "srem":
                                buf.emit(b"\x48\x31\xc0")  # xor rax, rax
                            else:
                                buf.emit(b"\x48\xf7\xd8")  # neg rax
                            write_result_from_reg(inst.result, "rax")
                        elif c_div > 1 and (c_div & (c_div - 1)) == 0:
                            # Fast Power of 2 Division (2, 4, 8, 16, ...)
                            k = c_div.bit_length() - 1
                            resolve_operand_to_reg(inst.operands[0], "rax")
                            if k == 1:
                                if op in ("div", "sdiv"):
                                    buf.emit(b"\x48\x99")              # cqo (rdx = sign(rax))
                                    buf.emit(b"\x48\x29\xd0")          # sub rax, rdx
                                    buf.emit(b"\x48\xd1\xf8")          # sar rax, 1
                                    write_result_from_reg(inst.result, "rax")
                                else:
                                    buf.emit(b"\x48\x89\xc2")          # mov rdx, rax
                                    buf.emit(b"\x48\x89\xc1")          # mov rcx, rax
                                    buf.emit(b"\x48\xc1\xe9\x3f")      # shr rcx, 63
                                    buf.emit(_x64_alu_rr(0x01, "rax", "rcx")) # add rax, rcx
                                    buf.emit(b"\x48\xd1\xf8")          # sar rax, 1 (rax = q)
                                    buf.emit(b"\x48\xd1\xe0")          # shl rax, 1 (rax = q * 2)
                                    buf.emit(_x64_alu_rr(0x29, "rdx", "rax")) # sub rdx, rax (rdx = x - q*2)
                                    buf.emit(_x64_mov_rr("rax", "rdx"))       # mov rax, rdx
                                    write_result_from_reg(inst.result, "rax")
                            else:
                                if op in ("div", "sdiv"):
                                    buf.emit(b"\x48\x89\xc1")          # mov rcx, rax
                                    buf.emit(b"\x48\xc1\xf9\x3f")      # sar rcx, 63
                                    buf.emit(bytes([0x48, 0xc1, 0xe9, 64 - k])) # shr rcx, 64 - k
                                    buf.emit(_x64_alu_rr(0x01, "rax", "rcx"))   # add rax, rcx
                                    buf.emit(bytes([0x48, 0xc1, 0xf8, k]))       # sar rax, k
                                    write_result_from_reg(inst.result, "rax")
                                else:
                                    buf.emit(b"\x48\x89\xc2")          # mov rdx, rax
                                    buf.emit(b"\x48\x89\xc1")          # mov rcx, rax
                                    buf.emit(b"\x48\xc1\xf9\x3f")      # sar rcx, 63
                                    buf.emit(bytes([0x48, 0xc1, 0xe9, 64 - k])) # shr rcx, 64 - k
                                    buf.emit(_x64_alu_rr(0x01, "rax", "rcx"))   # add rax, rcx
                                    buf.emit(bytes([0x48, 0xc1, 0xf8, k]))       # sar rax, k
                                    buf.emit(bytes([0x48, 0xc1, 0xe0, k]))       # shl rax, k
                                    buf.emit(_x64_alu_rr(0x29, "rdx", "rax"))   # sub rdx, rax
                                    buf.emit(_x64_mov_rr("rax", "rdx"))         # mov rax, rdx
                                    write_result_from_reg(inst.result, "rax")
                        elif c_div > 0:
                            # Fast Granlund-Montgomery Reciprocal Division
                            M_u, s = compute_magic_signed_64(c_div)
                            M_signed = M_u if M_u < (1 << 63) else M_u - (1 << 64)
                            resolve_operand_to_reg(inst.operands[0], "rax")
                            buf.emit(_x64_mov_rr("rcx", "rax"))         # save original x in rcx
                            buf.emit(_x64_mov_ri("r11", M_signed))
                            buf.emit(b"\x49\xf7\xeb")                   # imul r11 -> rdx:rax
                            if M_u >= (1 << 63):
                                buf.emit(_x64_alu_rr(0x01, "rdx", "rcx")) # add rdx, rcx
                            if s > 0:
                                if s == 1:
                                    buf.emit(b"\x48\xd1\xfa")           # sar rdx, 1
                                else:
                                    buf.emit(bytes([0x48, 0xc1, 0xfa, s])) # sar rdx, s
                            buf.emit(_x64_mov_rr("rax", "rcx"))         # copy original x to rax
                            buf.emit(b"\x48\xc1\xe8\x3f")               # shr rax, 63
                            buf.emit(_x64_alu_rr(0x01, "rdx", "rax"))   # add rdx, rax (rdx is quotient q)
                            if op == "srem":
                                buf.emit(_x64_mov_ri("r11", c_div))
                                buf.emit(_x64_imul_rr("rdx", "r11"))      # rdx = q * c_div
                                buf.emit(_x64_alu_rr(0x29, "rcx", "rdx")) # sub rcx, rdx (rcx = x - q*D)
                                buf.emit(_x64_mov_rr("rax", "rcx"))
                                write_result_from_reg(inst.result, "rax")
                            else:
                                buf.emit(_x64_mov_rr("rax", "rdx"))
                                write_result_from_reg(inst.result, "rax")
                        else:
                            # Dynamic / Negative Divisor Fallback
                            resolve_operand_to_reg(inst.operands[0], "rax")
                            resolve_operand_to_reg(inst.operands[1], "r11")
                            buf.emit(b"\x48\x99")          # cqo (sign-extend rax -> rdx:rax)
                            buf.emit(b"\x49\xf7\xfb")      # idiv r11
                            write_result_from_reg(inst.result, "rax" if op != "srem" else "rdx")
                    else:
                        # Dynamic Divisor Fallback
                        resolve_operand_to_reg(inst.operands[0], "rax")
                        resolve_operand_to_reg(inst.operands[1], "r11")
                        buf.emit(b"\x48\x99")          # cqo (sign-extend rax -> rdx:rax)
                        buf.emit(b"\x49\xf7\xfb")      # idiv r11
                        write_result_from_reg(inst.result, "rax" if op != "srem" else "rdx")

                elif op == "neg":
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    buf.emit(b"\x48\xf7\xd8")  # neg rax
                    write_result_from_reg(inst.result, "rax")

                elif op == "not":
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    buf.emit(_x64_test_rr("rax"))
                    buf.emit(b"\x0f\x94\xc0")      # sete al
                    buf.emit(b"\x48\x0f\xb6\xc0")  # movzx rax, al
                    write_result_from_reg(inst.result, "rax")

                elif op in ("shl", "shr", "sar"):
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    resolve_operand_to_reg(inst.operands[1], "rcx")
                    if op == "shl":
                        buf.emit(b"\x48\xd3\xe0")  # shl rax, cl
                    else:
                        buf.emit(b"\x48\xd3\xf8")  # sar rax, cl (signed arithmetic shift)
                    write_result_from_reg(inst.result, "rax")

                elif op in self.SETCC_BYTES:
                    op0, op1 = inst.operands[0], inst.operands[1]
                    def _emit_cmp(lhs: Any, rhs: Any) -> None:
                        c_imm1 = _get_imm32(rhs)
                        if (
                            leaf_mode
                            and isinstance(lhs, SSAVar) and lhs in reg_map and lhs not in inlined_consts
                        ):
                            if c_imm1 is not None:
                                buf.emit(_x64_alu_ri32(7, reg_map[lhs], c_imm1))
                                return
                            if isinstance(rhs, SSAVar) and rhs in reg_map and rhs not in inlined_consts:
                                buf.emit(_x64_alu_rr(0x39, reg_map[lhs], reg_map[rhs]))
                                return
                        resolve_operand_to_reg(lhs, "rax")
                        if c_imm1 is not None:
                            buf.emit(_x64_alu_ri32(7, "rax", c_imm1))
                        else:
                            resolve_operand_to_reg(rhs, "r11")
                            buf.emit(_x64_alu_rr(0x39, "rax", "r11"))

                    # Macro-op fusion: single-use cmp_* immediately followed by br_cond
                    fused_br = (
                        block_insts[inst_idx]
                        if (
                            inst_idx < len(block_insts)
                            and block_insts[inst_idx].opcode.lower() == "br_cond"
                            and isinstance(inst.result, SSAVar)
                            and block_insts[inst_idx].operands
                            and block_insts[inst_idx].operands[0] == inst.result
                            and var_use_counts.get(inst.result, 0) == 1
                        )
                        else None
                    )
                    if fused_br is not None:
                        inst_idx += 1
                        buf.record_line(fused_br.source_line)
                        _emit_cmp(op0, op1)
                        true_name, false_name = str(fused_br.operands[1]), str(fused_br.operands[2])
                        next_blk_name = fn.blocks[idx_b + 1].name if (idx_b + 1 < len(fn.blocks)) else None
                        true_bb = block_map.get(true_name)
                        false_bb = block_map.get(false_name)
                        if true_name == block.name and (true_bb is None or _self_loop_pre_jcc_safe(block, false_bb)):
                            if true_bb is not None and len(true_bb.phi_nodes) > 0:
                                emit_phi_copies_for_edge(block.name, true_bb, preserve_flags=True)
                            buf.jcc(self.SETCC_BYTES[op] - 0x10, f".L_bb_{true_name}")
                            if false_bb is not None and len(false_bb.phi_nodes) > 0:
                                emit_phi_copies_for_edge(block.name, false_bb)
                            if next_blk_name != false_name:
                                buf.jmp(f".L_bb_{false_name}")
                        elif true_name == block.name and true_bb is not None and len(true_bb.phi_nodes) > 0:
                            inv_jcc = (self.SETCC_BYTES[op] ^ 0x01) - 0x10
                            f_lbl = branch_target_label(block.name, false_name)
                            buf.jcc(inv_jcc, f_lbl)
                            emit_phi_copies_for_edge(block.name, true_bb, preserve_flags=False)
                            buf.jmp(f".L_bb_{true_name}")
                        elif true_name == next_blk_name and (true_bb is None or not true_bb.phi_nodes):
                            inv_jcc = (self.SETCC_BYTES[op] ^ 0x01) - 0x10
                            f_lbl = branch_target_label(block.name, false_name)
                            buf.jcc(inv_jcc, f_lbl)
                        else:
                            t_lbl = branch_target_label(block.name, true_name)
                            buf.jcc(self.SETCC_BYTES[op] - 0x10, t_lbl)
                            if false_bb is not None and len(false_bb.phi_nodes) > 0:
                                emit_phi_copies_for_edge(block.name, false_bb)
                            if next_blk_name != false_name:
                                buf.jmp(f".L_bb_{false_name}")
                    else:
                        _emit_cmp(op0, op1)
                        buf.emit(bytes([0x0F, self.SETCC_BYTES[op], 0xC0]))  # setcc al
                        buf.emit(b"\x48\x0f\xb6\xc0")              # movzx rax, al
                        write_result_from_reg(inst.result, "rax")

                elif op in ("fadd", "fsub", "fmul", "fdiv"):
                    if op == "fadd" and inst_idx + 1 < len(block_insts):
                        ins_hi = block_insts[inst_idx]
                        ins_top = block_insts[inst_idx + 1]
                        if (
                            ins_hi.opcode.lower() == "fadd"
                            and ins_top.opcode.lower() == "fadd"
                            and isinstance(inst.result, SSAVar)
                            and isinstance(ins_hi.result, SSAVar)
                            and inst.result != ins_hi.result
                            and inst.result not in ins_hi.operands
                            and len(inst.operands) == 2
                            and len(ins_hi.operands) == 2
                            and len(ins_top.operands) == 2
                            and set(ins_top.operands) == {inst.result, ins_hi.result}
                        ):
                            resolve_operand_to_reg(inst.operands[0], "rax")
                            buf.emit(_x64_movq_xmm_r64(0, "rax"))
                            resolve_operand_to_reg(ins_hi.operands[0], "rax")
                            buf.emit(_x64_movq_xmm_r64(1, "rax"))
                            buf.emit(b"\x66\x0f\x6c\xc1")            # punpcklqdq xmm0, xmm1
                            resolve_operand_to_reg(inst.operands[1], "rax")
                            buf.emit(_x64_movq_xmm_r64(1, "rax"))
                            resolve_operand_to_reg(ins_hi.operands[1], "rax")
                            buf.emit(_x64_movq_xmm_r64(2, "rax"))
                            buf.emit(b"\x66\x0f\x6c\xca")            # punpcklqdq xmm1, xmm2
                            buf.emit(b"\x66\x0f\x58\xc1")            # addpd xmm0, xmm1
                            buf.emit(_x64_movq_r64_xmm("rax", 0))
                            write_result_from_reg(inst.result, "rax")
                            buf.emit(b"\x66\x0f\x70\xc8\x4e")        # pshufd xmm1, xmm0, 0x4E
                            buf.emit(_x64_movq_r64_xmm("rax", 1))
                            write_result_from_reg(ins_hi.result, "rax")
                            buf.emit(b"\x66\x0f\x58\xc1")            # addpd xmm0, xmm1 (horizontal collapse)
                            buf.emit(_x64_movq_r64_xmm("rax", 0))
                            write_result_from_reg(ins_top.result, "rax")
                            buf.record_line(ins_top.source_line)
                            inst_idx += 2
                            continue
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    resolve_operand_to_reg(inst.operands[1], "r11")
                    buf.emit(_x64_movq_xmm_r64(0, "rax"))
                    buf.emit(_x64_movq_xmm_r64(1, "r11"))
                    sse_op = {"fadd": 0x58, "fsub": 0x5C, "fmul": 0x59, "fdiv": 0x5E}[op]
                    buf.emit(_x64_sse_sd(sse_op, 0, 1))
                    buf.emit(_x64_movq_r64_xmm("rax", 0))
                    write_result_from_reg(inst.result, "rax")

                elif op == "fneg":
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    buf.emit(_x64_mov_ri("r11", -0x8000000000000000))
                    buf.emit(_x64_alu_rr(0x31, "rax", "r11"))
                    write_result_from_reg(inst.result, "rax")

                elif op == "sitofp":
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    buf.emit(b"\xf2\x48\x0f\x2a\xc0")  # cvtsi2sd xmm0, rax
                    buf.emit(_x64_movq_r64_xmm("rax", 0))
                    write_result_from_reg(inst.result, "rax")

                elif op == "fptosi":
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    buf.emit(_x64_movq_xmm_r64(0, "rax"))
                    buf.emit(b"\xf2\x48\x0f\x2c\xc0")  # cvttsd2si rax, xmm0
                    write_result_from_reg(inst.result, "rax")

                elif op in ("fcmp_eq", "fcmp_ne", "fcmp_lt", "fcmp_le", "fcmp_gt", "fcmp_ge"):
                    resolve_operand_to_reg(inst.operands[0], "rax")
                    resolve_operand_to_reg(inst.operands[1], "r11")
                    buf.emit(_x64_movq_xmm_r64(0, "rax"))
                    buf.emit(_x64_movq_xmm_r64(1, "r11"))
                    if op in ("fcmp_lt", "fcmp_le"):
                        buf.emit(_x64_ucomisd(1, 0))
                        buf.emit(bytes([0x0F, 0x97 if op == "fcmp_lt" else 0x93, 0xC0]))
                    elif op in ("fcmp_gt", "fcmp_ge"):
                        buf.emit(_x64_ucomisd(0, 1))
                        buf.emit(bytes([0x0F, 0x97 if op == "fcmp_gt" else 0x93, 0xC0]))
                    elif op == "fcmp_eq":
                        buf.emit(_x64_ucomisd(0, 1))
                        buf.emit(b"\x0f\x94\xc0")
                        buf.emit(b"\x0f\x9b\xc1")
                        buf.emit(b"\x20\xc8")
                    else:
                        buf.emit(_x64_ucomisd(0, 1))
                        buf.emit(b"\x0f\x95\xc0")
                        buf.emit(b"\x0f\x9b\xc1")
                        buf.emit(b"\x20\xc8")
                    buf.emit(b"\x48\x0f\xb6\xc0")
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

                elif op == "load_off":
                    resolve_operand_to_reg(inst.operands[0], "r11")  # base ptr
                    resolve_operand_to_reg(inst.operands[1], "rcx")  # byte offset
                    width = str(inst.operands[2]) if len(inst.operands) >= 3 else "i64"
                    buf.emit(b"\x49\x01\xcb")                        # add r11, rcx
                    if width == "i8":
                        buf.emit(b"\x49\x0f\xbe\x03")                # movsx rax, byte ptr [r11]
                    elif width == "u8":
                        buf.emit(b"\x41\x0f\xb6\x03")                # movzx eax, byte ptr [r11]
                    elif width == "i16":
                        buf.emit(b"\x49\x0f\xbf\x03")                # movsx rax, word ptr [r11]
                    elif width == "u16":
                        buf.emit(b"\x41\x0f\xb7\x03")                # movzx eax, word ptr [r11]
                    elif width == "i32":
                        buf.emit(b"\x49\x63\x03")                    # movsxd rax, dword ptr [r11]
                    elif width == "u32":
                        buf.emit(b"\x41\x8b\x03")                    # mov eax, dword ptr [r11]
                    elif width == "f32":
                        buf.emit(b"\xf3\x41\x0f\x5a\x03")            # cvtss2sd xmm0, dword ptr [r11]
                        buf.emit(_x64_movq_r64_xmm("rax", 0))
                    else:
                        buf.emit(b"\x49\x8b\x03")                    # mov rax, qword ptr [r11]
                    write_result_from_reg(inst.result, "rax")

                elif op == "lut_load":
                    lut_name = str(inst.operands[0])
                    width = str(inst.operands[1])
                    idx_op = inst.operands[2]
                    buf.lea_r11_label(f".L_ro_{lut_name}")
                    resolve_operand_to_reg(idx_op, "rcx")
                    _, _, sh = _LUT_PACK_SPEC.get(width, ("q", 8, 3))
                    if sh > 0:
                        buf.emit(b"\x48\xc1\xe1" + struct.pack("<B", sh))  # shl rcx, sh
                    buf.emit(b"\x49\x01\xcb")                              # add r11, rcx
                    if width == "i8":
                        buf.emit(b"\x49\x0f\xbe\x03")
                    elif width == "u8":
                        buf.emit(b"\x41\x0f\xb6\x03")
                    elif width == "i16":
                        buf.emit(b"\x49\x0f\xbf\x03")
                    elif width == "u16":
                        buf.emit(b"\x41\x0f\xb7\x03")
                    elif width == "i32":
                        buf.emit(b"\x49\x63\x03")
                    elif width == "u32":
                        buf.emit(b"\x41\x8b\x03")
                    elif width == "f32":
                        buf.emit(b"\xf3\x41\x0f\x5a\x03")
                        buf.emit(_x64_movq_r64_xmm("rax", 0))
                    else:
                        buf.emit(b"\x49\x8b\x03")
                    write_result_from_reg(inst.result, "rax")

                elif op == "cstr_addr":
                    c_name = str(inst.operands[0])
                    buf.lea_r11_label(f".L_cstr_{c_name}")
                    write_result_from_reg(inst.result, "r11")

                elif op == "store_off":
                    width = str(inst.operands[3]) if len(inst.operands) >= 4 else "i64"
                    def _emit_addr_r11_rcx(base_op: Any, off_op: Any) -> None:
                        resolve_operand_to_reg(base_op, "r11")
                        resolve_operand_to_reg(off_op, "rcx")
                        buf.emit(b"\x49\x01\xcb")  # add r11, rcx

                    # 512-bit AVX-512 EVEX path for 8 contiguous 64-bit stores
                    if self.enable_avx512 and width in ("i64", "u64", "f64") and inst_idx + 6 < len(block_insts):
                        oct64_sts = [inst] + [block_insts[inst_idx + k_s] for k_s in range(7)]
                        if (
                            all(s.opcode.lower() == "store_off" and len(s.operands) >= 4 and str(s.operands[3]) == width and s.operands[0] == inst.operands[0] for s in oct64_sts[1:])
                            and is_contiguous_stride(fn_add_const, [s.operands[1] for s in oct64_sts], 8)
                        ):
                            vals_z = [s.operands[2] for s in oct64_sts]
                            z_fma = (
                                _match_contiguous_fma_sources(vals_z, blk_def_map, "f64", fn_add_const, 8)
                                if (self.enable_fma and width == "f64")
                                else None
                            )
                            if z_fma is not None:
                                lda0, ldb0, ldc0 = z_fma
                                _emit_addr_r11_rcx(lda0.operands[0], lda0.operands[1])
                                buf.emit(b"\x62\xd1\xfe\x48\x6f\x03")    # vmovdqu64 zmm0, [r11]
                                _emit_addr_r11_rcx(ldb0.operands[0], ldb0.operands[1])
                                buf.emit(b"\x62\xd1\xfe\x48\x6f\x0b")    # vmovdqu64 zmm1, [r11]
                                _emit_addr_r11_rcx(ldc0.operands[0], ldc0.operands[1])
                                buf.emit(b"\x62\xd1\xfe\x48\x6f\x13")    # vmovdqu64 zmm2, [r11]
                                buf.emit(b"\x62\xf2\xf5\x48\xa8\xc2")    # vfmadd213pd zmm0, zmm1, zmm2
                                _emit_addr_r11_rcx(inst.operands[0], inst.operands[1])
                                buf.emit(b"\x62\xd1\xfe\x48\x7f\x03")    # vmovdqu64 [r11], zmm0
                                used_avx2_ymm = True
                                buf.record_line(oct64_sts[-1].source_line)
                                inst_idx += 7
                                continue
                            z_bin = _match_contiguous_binary_alu_sources(
                                vals_z, blk_def_map, _AVX512_PACKED_64B_ALU_OPS, ("i64", "u64", "f64"), fn_add_const, 8
                            )
                            if z_bin is not None:
                                op_z, lda0, ldb0 = z_bin
                                _emit_addr_r11_rcx(lda0.operands[0], lda0.operands[1])
                                buf.emit(b"\x62\xd1\xfe\x48\x6f\x03")    # vmovdqu64 zmm0, [r11]
                                _emit_addr_r11_rcx(ldb0.operands[0], ldb0.operands[1])
                                buf.emit(b"\x62\xd1\xfe\x48\x6f\x0b")    # vmovdqu64 zmm1, [r11]
                                buf.emit(_AVX512_PACKED_64B_ALU_OPS[op_z])
                                _emit_addr_r11_rcx(inst.operands[0], inst.operands[1])
                                buf.emit(b"\x62\xd1\xfe\x48\x7f\x03")    # vmovdqu64 [r11], zmm0
                                used_avx2_ymm = True
                                buf.record_line(oct64_sts[-1].source_line)
                                inst_idx += 7
                                continue

                    if self.enable_avx2 and width in ("i64", "u64", "f64") and inst_idx + 2 < len(block_insts):
                        st1 = block_insts[inst_idx]
                        st2 = block_insts[inst_idx + 1]
                        st3 = block_insts[inst_idx + 2]
                        if (
                            st1.opcode.lower() == "store_off" and len(st1.operands) >= 4 and str(st1.operands[3]) == width
                            and st2.opcode.lower() == "store_off" and len(st2.operands) >= 4 and str(st2.operands[3]) == width
                            and st3.opcode.lower() == "store_off" and len(st3.operands) >= 4 and str(st3.operands[3]) == width
                            and st1.operands[0] == inst.operands[0] == st2.operands[0] == st3.operands[0]
                            and _are_contiguous_8b_quad(inst.operands[1], st1.operands[1], st2.operands[1], st3.operands[1])
                        ):
                            vals_q = [inst.operands[2], st1.operands[2], st2.operands[2], st3.operands[2]]
                            y_fma = (
                                _match_contiguous_fma_sources(vals_q, blk_def_map, "f64", fn_add_const, 8)
                                if (self.enable_fma and width == "f64")
                                else None
                            )
                            if y_fma is not None:
                                lda0, ldb0, ldc0 = y_fma
                                _emit_addr_r11_rcx(lda0.operands[0], lda0.operands[1])
                                buf.emit(b"\xc4\xc1\x7e\x6f\x03")    # vmovdqu ymm0, [r11]
                                _emit_addr_r11_rcx(ldb0.operands[0], ldb0.operands[1])
                                buf.emit(b"\xc4\xc1\x7e\x6f\x0b")    # vmovdqu ymm1, [r11]
                                _emit_addr_r11_rcx(ldc0.operands[0], ldc0.operands[1])
                                buf.emit(b"\xc4\xc1\x7e\x6f\x13")    # vmovdqu ymm2, [r11]
                                buf.emit(b"\xc4\xe2\xf5\xa8\xc2")    # vfmadd213pd ymm0, ymm1, ymm2
                                _emit_addr_r11_rcx(inst.operands[0], inst.operands[1])
                                buf.emit(b"\xc4\xc1\x7e\x7f\x03")    # vmovdqu [r11], ymm0
                                used_avx2_ymm = True
                                buf.record_line(st3.source_line)
                                inst_idx += 3
                                continue

                            y_bin = _match_contiguous_binary_alu_sources(
                                vals_q, blk_def_map, _AVX2_PACKED_64B_ALU_OPS, ("i64", "u64", "f64"), fn_add_const, 8
                            )
                            if y_bin is not None:
                                op_y, lda0, ldb0 = y_bin
                                _emit_addr_r11_rcx(lda0.operands[0], lda0.operands[1])
                                buf.emit(b"\xc4\xc1\x7e\x6f\x03")    # vmovdqu ymm0, ymmword ptr [r11]
                                _emit_addr_r11_rcx(ldb0.operands[0], ldb0.operands[1])
                                buf.emit(b"\xc4\xc1\x7e\x6f\x0b")    # vmovdqu ymm1, ymmword ptr [r11]
                                buf.emit(_AVX2_PACKED_64B_ALU_OPS[op_y])
                                _emit_addr_r11_rcx(inst.operands[0], inst.operands[1])
                                buf.emit(b"\xc4\xc1\x7e\x7f\x03")    # vmovdqu ymmword ptr [r11], ymm0
                                used_avx2_ymm = True
                                buf.record_line(st3.source_line)
                                inst_idx += 3
                                continue

                            # General 256-bit AVX2 pack-and-store for 4 contiguous 64-bit stores
                            resolve_operand_to_reg(vals_q[0], "rax")
                            buf.emit(b"\xc4\xe1\xf9\x6e\xc0")            # vmovq xmm0, rax
                            resolve_operand_to_reg(vals_q[1], "r11")
                            buf.emit(b"\xc4\xc3\xf9\x22\xc3\x01")        # vpinsrq xmm0, xmm0, r11, 1
                            resolve_operand_to_reg(vals_q[2], "rax")
                            buf.emit(b"\xc4\xe1\xf9\x6e\xc8")            # vmovq xmm1, rax
                            resolve_operand_to_reg(vals_q[3], "r11")
                            buf.emit(b"\xc4\xc3\xf1\x22\xcb\x01")        # vpinsrq xmm1, xmm1, r11, 1
                            buf.emit(b"\xc4\xe3\x7d\x18\xc1\x01")        # vinserti128 ymm0, ymm0, xmm1, 1
                            _emit_addr_r11_rcx(inst.operands[0], inst.operands[1])
                            buf.emit(b"\xc4\xc1\x7e\x7f\x03")            # vmovdqu ymmword ptr [r11], ymm0
                            used_avx2_ymm = True
                            buf.record_line(st3.source_line)
                            inst_idx += 3
                            continue

                    if width in ("i64", "u64", "f64") and inst_idx < len(block_insts):
                        nxt_st = block_insts[inst_idx]
                        nxt_w = str(nxt_st.operands[3]) if (nxt_st.opcode.lower() == "store_off" and len(nxt_st.operands) >= 4) else ""
                        if (
                            nxt_st.opcode.lower() == "store_off"
                            and nxt_w == width
                            and nxt_st.operands[0] == inst.operands[0]
                            and _are_contiguous_8b_offsets(inst.operands[1], nxt_st.operands[1])
                        ):
                            val0, val1 = inst.operands[2], nxt_st.operands[2]
                            ins0 = blk_def_map.get(val0) if isinstance(val0, SSAVar) else None
                            ins1 = blk_def_map.get(val1) if isinstance(val1, SSAVar) else None
                            emitted_full_simd = False
                            if (
                                ins0 is not None
                                and ins1 is not None
                                and ins0.opcode.lower() == ins1.opcode.lower()
                                and ins0.opcode.lower() in _SSE2_PACKED_ALU_OPS
                                and len(ins0.operands) == 2
                                and len(ins1.operands) == 2
                            ):
                                a0, b0 = ins0.operands[0], ins0.operands[1]
                                a1, b1 = ins1.operands[0], ins1.operands[1]
                                ld_a0 = blk_def_map.get(a0) if isinstance(a0, SSAVar) else None
                                ld_a1 = blk_def_map.get(a1) if isinstance(a1, SSAVar) else None
                                ld_b0 = blk_def_map.get(b0) if isinstance(b0, SSAVar) else None
                                ld_b1 = blk_def_map.get(b1) if isinstance(b1, SSAVar) else None
                                if (
                                    ld_a0 is not None and ld_a1 is not None and ld_b0 is not None and ld_b1 is not None
                                    and ld_a0.opcode.lower() == "load_off" and ld_a1.opcode.lower() == "load_off"
                                    and ld_b0.opcode.lower() == "load_off" and ld_b1.opcode.lower() == "load_off"
                                    and str(ld_a0.operands[2]) in ("i64", "u64", "f64")
                                    and str(ld_a0.operands[2]) == str(ld_a1.operands[2])
                                    and str(ld_b0.operands[2]) in ("i64", "u64", "f64")
                                    and str(ld_b0.operands[2]) == str(ld_b1.operands[2])
                                    and ld_a0.operands[0] == ld_a1.operands[0]
                                    and ld_b0.operands[0] == ld_b1.operands[0]
                                    and _are_contiguous_8b_offsets(ld_a0.operands[1], ld_a1.operands[1])
                                    and _are_contiguous_8b_offsets(ld_b0.operands[1], ld_b1.operands[1])
                                ):
                                    resolve_operand_to_reg(ld_a0.operands[0], "r11")
                                    resolve_operand_to_reg(ld_a0.operands[1], "rcx")
                                    buf.emit(b"\x49\x01\xcb")            # add r11, rcx
                                    buf.emit(b"\xf3\x41\x0f\x6f\x03")    # movdqu xmm0, xmmword ptr [r11]
                                    resolve_operand_to_reg(ld_b0.operands[0], "r11")
                                    resolve_operand_to_reg(ld_b0.operands[1], "rcx")
                                    buf.emit(b"\x49\x01\xcb")            # add r11, rcx
                                    buf.emit(b"\xf3\x41\x0f\x6f\x0b")    # movdqu xmm1, xmmword ptr [r11]
                                    buf.emit(_SSE2_PACKED_ALU_OPS[ins0.opcode.lower()])
                                    resolve_operand_to_reg(inst.operands[0], "r11")
                                    resolve_operand_to_reg(inst.operands[1], "rcx")
                                    buf.emit(b"\x49\x01\xcb")            # add r11, rcx
                                    buf.emit(b"\xf3\x41\x0f\x7f\x03")    # movdqu xmmword ptr [r11], xmm0
                                    emitted_full_simd = True

                            if not emitted_full_simd:
                                resolve_operand_to_reg(val0, "rax")
                                buf.emit(_x64_movq_xmm_r64(0, "rax"))
                                resolve_operand_to_reg(val1, "rax")
                                buf.emit(_x64_movq_xmm_r64(1, "rax"))
                                buf.emit(b"\x66\x0f\x6c\xc1")            # punpcklqdq xmm0, xmm1
                                resolve_operand_to_reg(inst.operands[0], "r11")
                                resolve_operand_to_reg(inst.operands[1], "rcx")
                                buf.emit(b"\x49\x01\xcb")                # add r11, rcx
                                buf.emit(b"\xf3\x41\x0f\x7f\x03")        # movdqu xmmword ptr [r11], xmm0

                            buf.record_line(nxt_st.source_line)
                            inst_idx += 1
                            continue

                    if self.enable_avx2 and width in ("i32", "u32", "f32") and inst_idx + 6 < len(block_insts):
                        oct_sts = [inst] + [block_insts[inst_idx + k_s] for k_s in range(7)]
                        if (
                            all(s.opcode.lower() == "store_off" and len(s.operands) >= 4 and str(s.operands[3]) == width and s.operands[0] == inst.operands[0] for s in oct_sts[1:])
                            and _are_contiguous_4b_oct([s.operands[1] for s in oct_sts])
                        ):
                            vals_o = [s.operands[2] for s in oct_sts]
                            inss_o = [blk_def_map.get(v) if isinstance(v, SSAVar) else None for v in vals_o]
                            if self.enable_fma and width == "f32" and all(
                                x is not None and x.opcode.lower() == "fadd" and len(x.operands) == 2 for x in inss_o
                            ):
                                mul_l = [blk_def_map.get(x.operands[0]) if isinstance(x.operands[0], SSAVar) else None for x in inss_o]
                                mul_r = [blk_def_map.get(x.operands[1]) if isinstance(x.operands[1], SSAVar) else None for x in inss_o]
                                if all(m is not None and m.opcode.lower() == "fmul" and len(m.operands) == 2 for m in mul_l):
                                    muls_8, add_8 = mul_l, [x.operands[1] for x in inss_o]
                                elif all(m is not None and m.opcode.lower() == "fmul" and len(m.operands) == 2 for m in mul_r):
                                    muls_8, add_8 = mul_r, [x.operands[0] for x in inss_o]
                                else:
                                    muls_8, add_8 = [], []
                                if muls_8:
                                    lda_8 = [blk_def_map.get(m.operands[0]) if isinstance(m.operands[0], SSAVar) else None for m in muls_8]
                                    ldb_8 = [blk_def_map.get(m.operands[1]) if isinstance(m.operands[1], SSAVar) else None for m in muls_8]
                                    ldc_8 = [blk_def_map.get(c) if isinstance(c, SSAVar) else None for c in add_8]
                                    if (
                                        all(la is not None and la.opcode.lower() == "load_off" and str(la.operands[2]) == "f32" and la.operands[0] == lda_8[0].operands[0] for la in lda_8)
                                        and all(lb is not None and lb.opcode.lower() == "load_off" and str(lb.operands[2]) == "f32" and lb.operands[0] == ldb_8[0].operands[0] for lb in ldb_8)
                                        and all(lc is not None and lc.opcode.lower() == "load_off" and str(lc.operands[2]) == "f32" and lc.operands[0] == ldc_8[0].operands[0] for lc in ldc_8)
                                        and _are_contiguous_4b_oct([la.operands[1] for la in lda_8])
                                        and _are_contiguous_4b_oct([lb.operands[1] for lb in ldb_8])
                                        and _are_contiguous_4b_oct([lc.operands[1] for lc in ldc_8])
                                    ):
                                        resolve_operand_to_reg(lda_8[0].operands[0], "r11")
                                        resolve_operand_to_reg(lda_8[0].operands[1], "rcx")
                                        buf.emit(b"\x49\x01\xcb")
                                        buf.emit(b"\xc4\xc1\x7e\x6f\x03")    # vmovdqu ymm0, [r11]
                                        resolve_operand_to_reg(ldb_8[0].operands[0], "r11")
                                        resolve_operand_to_reg(ldb_8[0].operands[1], "rcx")
                                        buf.emit(b"\x49\x01\xcb")
                                        buf.emit(b"\xc4\xc1\x7e\x6f\x0b")    # vmovdqu ymm1, [r11]
                                        resolve_operand_to_reg(ldc_8[0].operands[0], "r11")
                                        resolve_operand_to_reg(ldc_8[0].operands[1], "rcx")
                                        buf.emit(b"\x49\x01\xcb")
                                        buf.emit(b"\xc4\xc1\x7e\x6f\x13")    # vmovdqu ymm2, [r11]
                                        buf.emit(b"\xc4\xe2\x75\xa8\xc2")    # vfmadd213ps ymm0, ymm1, ymm2
                                        resolve_operand_to_reg(inst.operands[0], "r11")
                                        resolve_operand_to_reg(inst.operands[1], "rcx")
                                        buf.emit(b"\x49\x01\xcb")
                                        buf.emit(b"\xc4\xc1\x7e\x7f\x03")    # vmovdqu [r11], ymm0
                                        used_avx2_ymm = True
                                        buf.record_line(oct_sts[-1].source_line)
                                        inst_idx += 7
                                        continue

                            if all(
                                x is not None
                                and x.opcode.lower() == inss_o[0].opcode.lower()
                                and x.opcode.lower() in _AVX2_PACKED_32B_ALU_OPS
                                and len(x.operands) == 2
                                for x in inss_o
                            ):
                                op_8x = inss_o[0].opcode.lower()
                                is_f32_op = op_8x.startswith("f")
                                if (width == "f32" and is_f32_op) or (width in ("i32", "u32") and not is_f32_op):
                                    lds_a = [blk_def_map.get(x.operands[0]) if isinstance(x.operands[0], SSAVar) else None for x in inss_o]
                                    lds_b = [blk_def_map.get(x.operands[1]) if isinstance(x.operands[1], SSAVar) else None for x in inss_o]
                                    if (
                                        all(la is not None and la.opcode.lower() == "load_off" and str(la.operands[2]) == width and la.operands[0] == lds_a[0].operands[0] for la in lds_a)
                                        and all(lb is not None and lb.opcode.lower() == "load_off" and str(lb.operands[2]) == width and lb.operands[0] == lds_b[0].operands[0] for lb in lds_b)
                                        and _are_contiguous_4b_oct([la.operands[1] for la in lds_a])
                                        and _are_contiguous_4b_oct([lb.operands[1] for lb in lds_b])
                                    ):
                                        resolve_operand_to_reg(lds_a[0].operands[0], "r11")
                                        resolve_operand_to_reg(lds_a[0].operands[1], "rcx")
                                        buf.emit(b"\x49\x01\xcb")            # add r11, rcx
                                        buf.emit(b"\xc4\xc1\x7e\x6f\x03")    # vmovdqu ymm0, ymmword ptr [r11]
                                        resolve_operand_to_reg(lds_b[0].operands[0], "r11")
                                        resolve_operand_to_reg(lds_b[0].operands[1], "rcx")
                                        buf.emit(b"\x49\x01\xcb")            # add r11, rcx
                                        buf.emit(b"\xc4\xc1\x7e\x6f\x0b")    # vmovdqu ymm1, ymmword ptr [r11]
                                        buf.emit(_AVX2_PACKED_32B_ALU_OPS[op_8x])
                                        resolve_operand_to_reg(inst.operands[0], "r11")
                                        resolve_operand_to_reg(inst.operands[1], "rcx")
                                        buf.emit(b"\x49\x01\xcb")            # add r11, rcx
                                        buf.emit(b"\xc4\xc1\x7e\x7f\x03")    # vmovdqu ymmword ptr [r11], ymm0
                                        used_avx2_ymm = True
                                        buf.record_line(oct_sts[-1].source_line)
                                        inst_idx += 7
                                        continue

                            # General 256-bit AVX2 pack-and-store for 8 contiguous 32-bit stores
                            for half_idx, v_chunk in enumerate((vals_o[:4], vals_o[4:])):
                                resolve_operand_to_reg(v_chunk[0], "rax")
                                if width == "f32":
                                    buf.emit(_x64_movq_xmm_r64(half_idx, "rax"))
                                    buf.emit(b"\xf2\x0f\x5a\xc0" if half_idx == 0 else b"\xf2\x0f\x5a\xc9")
                                else:
                                    buf.emit(b"\xc5\xf9\x6e\xc0" if half_idx == 0 else b"\xc5\xf9\x6e\xc8")
                                for sub_ln in range(1, 4):
                                    resolve_operand_to_reg(v_chunk[sub_ln], "rax")
                                    if width == "f32":
                                        buf.emit(_x64_movq_xmm_r64(2, "rax"))
                                        buf.emit(b"\xf2\x0f\x5a\xd2")        # cvtsd2ss xmm2, xmm2
                                        buf.emit(b"\xc4\xc1\x79\x7e\xd3")    # vmovd r11d, xmm2
                                    else:
                                        buf.emit(b"\x49\x89\xc3")            # mov r11, rax
                                    if half_idx == 0:
                                        buf.emit(bytes([0xC4, 0xC3, 0x79, 0x22, 0xC3, sub_ln]))
                                    else:
                                        buf.emit(bytes([0xC4, 0xC3, 0x71, 0x22, 0xCB, sub_ln]))
                            buf.emit(b"\xc4\xe3\x7d\x18\xc1\x01")            # vinserti128 ymm0, ymm0, xmm1, 1
                            resolve_operand_to_reg(inst.operands[0], "r11")
                            resolve_operand_to_reg(inst.operands[1], "rcx")
                            buf.emit(b"\x49\x01\xcb")                        # add r11, rcx
                            buf.emit(b"\xc4\xc1\x7e\x7f\x03")                # vmovdqu ymmword ptr [r11], ymm0
                            used_avx2_ymm = True
                            buf.record_line(oct_sts[-1].source_line)
                            inst_idx += 7
                            continue

                    if width in ("i32", "u32", "f32") and inst_idx + 2 < len(block_insts):
                        st1 = block_insts[inst_idx]
                        st2 = block_insts[inst_idx + 1]
                        st3 = block_insts[inst_idx + 2]
                        if (
                            st1.opcode.lower() == "store_off" and len(st1.operands) >= 4 and str(st1.operands[3]) == width
                            and st2.opcode.lower() == "store_off" and len(st2.operands) >= 4 and str(st2.operands[3]) == width
                            and st3.opcode.lower() == "store_off" and len(st3.operands) >= 4 and str(st3.operands[3]) == width
                            and st1.operands[0] == inst.operands[0] == st2.operands[0] == st3.operands[0]
                            and _are_contiguous_4b_quad(inst.operands[1], st1.operands[1], st2.operands[1], st3.operands[1])
                        ):
                            vals_q = [inst.operands[2], st1.operands[2], st2.operands[2], st3.operands[2]]
                            inss_q = [blk_def_map.get(v) if isinstance(v, SSAVar) else None for v in vals_q]
                            emitted_4x_simd = False
                            if all(
                                x is not None
                                and x.opcode.lower() == inss_q[0].opcode.lower()
                                and x.opcode.lower() in _SSE2_PACKED_32B_ALU_OPS
                                and len(x.operands) == 2
                                for x in inss_q
                            ):
                                op_4x = inss_q[0].opcode.lower()
                                is_f32_op = op_4x.startswith("f")
                                if (width == "f32" and is_f32_op) or (width in ("i32", "u32") and not is_f32_op):
                                    lds_a = [blk_def_map.get(x.operands[0]) if isinstance(x.operands[0], SSAVar) else None for x in inss_q]
                                    lds_b = [blk_def_map.get(x.operands[1]) if isinstance(x.operands[1], SSAVar) else None for x in inss_q]
                                    if (
                                        all(la is not None and la.opcode.lower() == "load_off" and str(la.operands[2]) == width and la.operands[0] == lds_a[0].operands[0] for la in lds_a)
                                        and all(lb is not None and lb.opcode.lower() == "load_off" and str(lb.operands[2]) == width and lb.operands[0] == lds_b[0].operands[0] for lb in lds_b)
                                        and _are_contiguous_4b_quad(lds_a[0].operands[1], lds_a[1].operands[1], lds_a[2].operands[1], lds_a[3].operands[1])
                                        and _are_contiguous_4b_quad(lds_b[0].operands[1], lds_b[1].operands[1], lds_b[2].operands[1], lds_b[3].operands[1])
                                    ):
                                        resolve_operand_to_reg(lds_a[0].operands[0], "r11")
                                        resolve_operand_to_reg(lds_a[0].operands[1], "rcx")
                                        buf.emit(b"\x49\x01\xcb")            # add r11, rcx
                                        buf.emit(b"\xf3\x41\x0f\x6f\x03")    # movdqu xmm0, xmmword ptr [r11]
                                        resolve_operand_to_reg(lds_b[0].operands[0], "r11")
                                        resolve_operand_to_reg(lds_b[0].operands[1], "rcx")
                                        buf.emit(b"\x49\x01\xcb")            # add r11, rcx
                                        buf.emit(b"\xf3\x41\x0f\x6f\x0b")    # movdqu xmm1, xmmword ptr [r11]
                                        buf.emit(_SSE2_PACKED_32B_ALU_OPS[op_4x])
                                        resolve_operand_to_reg(inst.operands[0], "r11")
                                        resolve_operand_to_reg(inst.operands[1], "rcx")
                                        buf.emit(b"\x49\x01\xcb")            # add r11, rcx
                                        buf.emit(b"\xf3\x41\x0f\x7f\x03")    # movdqu xmmword ptr [r11], xmm0
                                        emitted_4x_simd = True

                            if not emitted_4x_simd:
                                resolve_operand_to_reg(vals_q[0], "rax")
                                buf.emit(_x64_movq_xmm_r64(0, "rax"))
                                if width == "f32":
                                    buf.emit(b"\xf2\x0f\x5a\xc0")            # cvtsd2ss xmm0, xmm0
                                resolve_operand_to_reg(vals_q[1], "rax")
                                buf.emit(_x64_movq_xmm_r64(1, "rax"))
                                if width == "f32":
                                    buf.emit(b"\xf2\x0f\x5a\xc9")            # cvtsd2ss xmm1, xmm1
                                buf.emit(b"\x66\x0f\x62\xc1")                # punpckldq xmm0, xmm1
                                resolve_operand_to_reg(vals_q[2], "rax")
                                buf.emit(_x64_movq_xmm_r64(1, "rax"))
                                if width == "f32":
                                    buf.emit(b"\xf2\x0f\x5a\xc9")            # cvtsd2ss xmm1, xmm1
                                resolve_operand_to_reg(vals_q[3], "rax")
                                buf.emit(_x64_movq_xmm_r64(2, "rax"))
                                if width == "f32":
                                    buf.emit(b"\xf2\x0f\x5a\xd2")            # cvtsd2ss xmm2, xmm2
                                buf.emit(b"\x66\x0f\x62\xca")                # punpckldq xmm1, xmm2
                                buf.emit(b"\x66\x0f\x6c\xc1")                # punpcklqdq xmm0, xmm1
                                resolve_operand_to_reg(inst.operands[0], "r11")
                                resolve_operand_to_reg(inst.operands[1], "rcx")
                                buf.emit(b"\x49\x01\xcb")                    # add r11, rcx
                                buf.emit(b"\xf3\x41\x0f\x7f\x03")            # movdqu xmmword ptr [r11], xmm0

                            buf.record_line(st3.source_line)
                            inst_idx += 3
                            continue

                    resolve_operand_to_reg(inst.operands[0], "r11")  # base ptr
                    resolve_operand_to_reg(inst.operands[1], "rcx")  # byte offset
                    resolve_operand_to_reg(inst.operands[2], "rax")  # value
                    buf.emit(b"\x49\x01\xcb")                        # add r11, rcx
                    if width in ("i8", "u8"):
                        buf.emit(b"\x41\x88\x03")                    # mov byte ptr [r11], al
                    elif width in ("i16", "u16"):
                        buf.emit(b"\x66\x41\x89\x03")                # mov word ptr [r11], ax
                    elif width in ("i32", "u32"):
                        buf.emit(b"\x41\x89\x03")                    # mov dword ptr [r11], eax
                    elif width == "f32":
                        buf.emit(_x64_movq_xmm_r64(0, "rax"))
                        buf.emit(b"\xf2\x0f\x5a\xc0")                # cvtsd2ss xmm0, xmm0
                        buf.emit(b"\xf3\x41\x0f\x11\x03")            # movss dword ptr [r11], xmm0
                    else:
                        buf.emit(b"\x49\x89\x03")                    # mov qword ptr [r11], rax

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
                    shadow_off = 32 if self.is_windows else 0
                    if self.is_windows:
                        for a_idx in range(len(self.param_regs), len(call_args)):
                            resolve_operand_to_reg(call_args[a_idx], "rax")
                            sp_disp = shadow_off + (a_idx - len(self.param_regs)) * 8
                            buf.emit(b"\x48\x89\x84\x24" + struct.pack("<i", sp_disp))
                        for a_idx in range(min(len(call_args), len(self.param_regs))):
                            ca = call_args[a_idx]
                            is_fp_arg = isinstance(ca, float) or (isinstance(ca, SSAVar) and ca.var_type == "f64")
                            if is_fp_arg:
                                # Mirror FP arg in both integer param reg and XMM reg per Win64 varargs ABI
                                resolve_operand_to_reg(ca, self.param_regs[a_idx])
                                buf.emit(_x64_movq_xmm_r64(a_idx, self.param_regs[a_idx]))
                            else:
                                resolve_operand_to_reg(ca, self.param_regs[a_idx])
                    else:
                        c_int, c_fp, c_stk = 0, 0, 0
                        reg_ops: List[Tuple[str, Any, bool, int]] = []
                        for ca in call_args:
                            is_fp_arg = isinstance(ca, float) or (isinstance(ca, SSAVar) and ca.var_type == "f64")
                            if is_fp_arg:
                                if c_fp < 8:
                                    reg_ops.append(("fp", ca, True, c_fp))
                                    c_fp += 1
                                else:
                                    resolve_operand_to_reg(ca, "rax")
                                    buf.emit(b"\x48\x89\x84\x24" + struct.pack("<i", c_stk * 8))
                                    c_stk += 1
                            else:
                                if c_int < len(SYSV_PARAM_REGS):
                                    reg_ops.append(("int", ca, False, c_int))
                                    c_int += 1
                                else:
                                    resolve_operand_to_reg(ca, "rax")
                                    buf.emit(b"\x48\x89\x84\x24" + struct.pack("<i", c_stk * 8))
                                    c_stk += 1
                        for kind, ca, _, r_idx in reg_ops:
                            if kind == "fp":
                                resolve_operand_to_reg(ca, "rax")
                                buf.emit(_x64_movq_xmm_r64(r_idx, "rax"))
                            else:
                                resolve_operand_to_reg(ca, SYSV_PARAM_REGS[r_idx])
                        # SysV AMD64 variadic ABI requires %al = number of vector registers used
                        buf.emit(_x64_mov_ri("rax", min(8, c_fp)))

                    if callee == fn.name:
                        buf.call_label(".L_func_entry")
                    else:
                        buf.call_external(callee)
                    if inst.result is not None and inst.result.var_type == "f64":
                        buf.emit(_x64_movq_r64_xmm("rax", 0))
                    write_result_from_reg(inst.result, "rax")

                elif op == "br":
                    succ_name = str(inst.operands[0])
                    succ_bb = block_map.get(succ_name)
                    if succ_bb is not None and len(succ_bb.phi_nodes) > 0:
                        emit_phi_copies_for_edge(block.name, succ_bb)
                    is_fallthrough = (idx_b + 1 < len(fn.blocks) and fn.blocks[idx_b + 1].name == succ_name)
                    if not is_fallthrough:
                        buf.jmp(f".L_bb_{succ_name}")

                elif op == "br_cond":
                    cond_op, true_name, false_name = inst.operands[0], str(inst.operands[1]), str(inst.operands[2])
                    if leaf_mode and isinstance(cond_op, SSAVar) and cond_op in reg_map and cond_op not in inlined_consts:
                        buf.emit(_x64_test_rr(reg_map[cond_op]))
                    else:
                        resolve_operand_to_reg(cond_op, "rax")
                        buf.emit(_x64_test_rr("rax"))
                    next_blk_name = fn.blocks[idx_b + 1].name if (idx_b + 1 < len(fn.blocks)) else None
                    true_bb = block_map.get(true_name)
                    if true_name == next_blk_name and (true_bb is None or not true_bb.phi_nodes):
                        f_lbl = branch_target_label(block.name, false_name)
                        buf.jcc(0x84, f_lbl)  # je false_name, fallthrough true_name
                    else:
                        t_lbl = branch_target_label(block.name, true_name)
                        buf.jne(t_lbl)
                        false_bb = block_map.get(false_name)
                        if false_bb is not None and len(false_bb.phi_nodes) > 0:
                            emit_phi_copies_for_edge(block.name, false_bb)
                        if next_blk_name != false_name:
                            buf.jmp(f".L_bb_{false_name}")

                elif op == "ret":
                    if inst.operands:
                        rv = inst.operands[0]
                        resolve_operand_to_reg(rv, "rax")
                        is_fp_ret = getattr(fn, "return_type", "i64") == "f64" or isinstance(rv, float) or (isinstance(rv, SSAVar) and rv.var_type == "f64")
                        if is_fp_ret:
                            buf.emit(_x64_movq_xmm_r64(0, "rax"))
                    else:
                        buf.emit(_x64_mov_ri("rax", 0))
                        if getattr(fn, "return_type", "i64") == "f64":
                            buf.emit(_x64_movq_xmm_r64(0, "rax"))
                    buf.jmp(".L_epilogue")

        # --- Emit Phi Edge Trampolines ---
        for tramp_lbl, pred_name, succ_bb in edge_trampolines:
            buf.mark(tramp_lbl)
            emit_phi_copies_for_edge(pred_name, succ_bb)
            buf.jmp(f".L_bb_{succ_bb.name}")

        # --- Emit Single Canonical Epilogue (Guarantees Balanced RSP & Final 0xC3) ---
        buf.mark(".L_epilogue")
        if used_avx2_ymm:
            buf.emit(b"\xc5\xf8\x77")  # vzeroupper
        if pure_leaf_mode:
            for r in reversed(used_callee_saved):
                buf.emit(_x64_pop(r))
            buf.emit(b"\xc3")
        elif leaf_mode:
            for r in reversed(used_callee_saved):
                buf.emit(_x64_pop(r))
            if frame_size > 0:
                if frame_size <= 127:
                    buf.emit(b"\x48\x83\xc4" + struct.pack("<B", frame_size))
                else:
                    buf.emit(b"\x48\x81\xc4" + struct.pack("<I", frame_size))
            buf.emit(b"\x5d")  # pop rbp
            buf.emit(b"\xc3")  # ret
        else:
            if frame_size > 0:
                if frame_size <= 127:
                    buf.emit(b"\x48\x83\xc4" + struct.pack("<B", frame_size))
                else:
                    buf.emit(b"\x48\x81\xc4" + struct.pack("<I", frame_size))
            buf.emit(b"\x5d")  # pop rbp
            buf.emit(b"\xc3")  # ret

        code_end_off = len(buf.code)
        luts_map = getattr(fn, "luts", {}) or {}
        cstrs_map = getattr(fn, "cstrs", {}) or {}
        if luts_map or cstrs_map:
            pad_rem = (-len(buf.code)) & 7
            if pad_rem:
                buf.emit(b"\x90" * pad_rem)
            for l_name, (l_wt, l_vals) in sorted(luts_map.items()):
                buf.mark(f".L_ro_{l_name}")
                buf.emit(_pack_lut_bytes(l_wt, l_vals))
            for c_name, c_bytes in sorted(cstrs_map.items()):
                buf.mark(f".L_cstr_{c_name}")
                buf.emit(c_bytes)

        final_bytes = buf.finalize()
        for b, orig_ins in orig_block_insts:
            b.instructions = orig_ins
        return CompiledFunctionArtifact(
            name=fn.name,
            arch="x86_64",
            abi=self.abi,
            code_bytes=final_bytes,
            relocations=buf.relocations,
            line_table=buf.line_table,
            stack_frame_size=frame_size,
            saved_nonvolatile_regs=used_callee_saved if pure_leaf_mode else (["rbp"] + used_callee_saved if leaf_mode else ["rbp"]),
            prologue_size=prologue_size,
            leaf_register_mode=pure_leaf_mode or leaf_mode,
            coalesced_moves=alloc.get("coalesced_moves", 0),
            live_across_call_count=len(alloc.get("live_across_call", [])),
            code_end_offset=code_end_off,
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

    def emit_avx2_vector_add_f64(self) -> bytes:
        """
        Emits a VEX-encoded 256-bit AVX2 IEEE-754 double-precision SIMD kernel:
          int64_t avx2_add_f64(const double* a, const double* b, double* out, int64_t count)
        Processes 4 x 64-bit IEEE-754 doubles (32 bytes) per cycle using YMM0/YMM1 (`vaddpd`),
        with SSE2 scalar `addsd` tail cleanup and `vzeroupper` epilogue.
        """
        buf = X64LabelBuffer()
        if self.is_windows:
            buf.emit(_x64_mov_rr("r10", "rcx"))
            buf.emit(_x64_mov_rr("r11", "rdx"))
            buf.emit(_x64_mov_rr("rax", "r8"))
            buf.emit(_x64_mov_rr("rcx", "r9"))
        else:
            buf.emit(_x64_mov_rr("r10", "rdi"))
            buf.emit(_x64_mov_rr("r11", "rsi"))
            buf.emit(_x64_mov_rr("rax", "rdx"))

        buf.mark(".L_vec_loop_f64")
        buf.emit(b"\x48\x83\xf9\x04")              # cmp rcx, 4
        buf.emit(b"\x0f\x8c\x00\x00\x00\x00")      # jl .L_scalar_tail_f64
        buf.fixups.append((len(buf.code) - 4, ".L_scalar_tail_f64"))

        buf.emit(b"\xc4\xc1\x7d\x10\x02")          # vmovupd ymm0, [r10]
        buf.emit(b"\xc4\xc1\x7d\x10\x0b")          # vmovupd ymm1, [r11]
        buf.emit(b"\xc5\xfd\x58\xc1")              # vaddpd ymm0, ymm0, ymm1
        buf.emit(b"\xc5\xfd\x11\x00")              # vmovupd [rax], ymm0

        buf.emit(b"\x49\x83\xc2\x20")              # add r10, 32
        buf.emit(b"\x49\x83\xc3\x20")              # add r11, 32
        buf.emit(b"\x48\x83\xc0\x20")              # add rax, 32
        buf.emit(b"\x48\x83\xe9\x04")              # sub rcx, 4
        buf.jmp(".L_vec_loop_f64")

        buf.mark(".L_scalar_tail_f64")
        buf.emit(b"\xc5\xf8\x77")                  # vzeroupper
        buf.mark(".L_tail_loop_f64")
        buf.emit(_x64_test_rr("rcx"))              # test rcx, rcx
        buf.emit(b"\x0f\x8e\x00\x00\x00\x00")      # jle .L_done_f64
        buf.fixups.append((len(buf.code) - 4, ".L_done_f64"))

        buf.emit(b"\xf2\x41\x0f\x10\x02")          # movsd xmm0, [r10]
        buf.emit(b"\xf2\x41\x0f\x58\x03")          # addsd xmm0, [r11]
        buf.emit(b"\xf2\x0f\x11\x00")              # movsd [rax], xmm0
        buf.emit(b"\x49\x83\xc2\x08")              # add r10, 8
        buf.emit(b"\x49\x83\xc3\x08")              # add r11, 8
        buf.emit(b"\x48\x83\xc0\x08")              # add rax, 8
        buf.emit(b"\x48\xff\xc9")                  # dec rcx
        buf.jmp(".L_tail_loop_f64")

        buf.mark(".L_done_f64")
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

    def _emit_5arg_setup(self, buf: "X64LabelBuffer") -> None:
        """Normalizes 5 pointer/count args into volatile regs: r10=a, r11=b, r8=c, r9=out, rax=count."""
        if self.is_windows:
            buf.emit(b"\x48\x8b\x44\x24\x28")  # mov rax, qword ptr [rsp + 0x28]
            buf.emit(_x64_mov_rr("r10", "rcx"))
            buf.emit(_x64_mov_rr("r11", "rdx"))
        else:
            buf.emit(_x64_mov_rr("rax", "r8"))
            buf.emit(_x64_mov_rr("r10", "rdi"))
            buf.emit(_x64_mov_rr("r11", "rsi"))
            buf.emit(_x64_mov_rr("r8", "rdx"))
            buf.emit(_x64_mov_rr("r9", "rcx"))

    def emit_avx2_fma_pd(self) -> bytes:
        """
        Emits hardware VEX 256-bit AVX2+FMA kernel:
          int64_t avx2_fma_pd(const double* a, const double* b, const double* c, double* out, int64_t count)
        Computes out[i] = a[i] * b[i] + c[i] using `vfmadd213pd` (4 lanes) + `vfmadd213sd` tail.
        """
        buf = X64LabelBuffer()
        self._emit_5arg_setup(buf)

        buf.mark(".L_fma256_vec")
        buf.emit(b"\x48\x83\xf8\x04")              # cmp rax, 4
        buf.emit(b"\x0f\x8c\x00\x00\x00\x00")      # jl .L_fma256_tail
        buf.fixups.append((len(buf.code) - 4, ".L_fma256_tail"))

        buf.emit(b"\xc4\xc1\x7d\x10\x02")          # vmovupd ymm0, ymmword ptr [r10]
        buf.emit(b"\xc4\xc1\x7d\x10\x0b")          # vmovupd ymm1, ymmword ptr [r11]
        buf.emit(b"\xc4\xc1\x7d\x10\x10")          # vmovupd ymm2, ymmword ptr [r8]
        buf.emit(b"\xc4\xe2\xf5\xa8\xc2")          # vfmadd213pd ymm0, ymm1, ymm2
        buf.emit(b"\xc4\xc1\x7d\x11\x01")          # vmovupd ymmword ptr [r9], ymm0
        buf.emit(b"\x49\x83\xc2\x20")              # add r10, 32
        buf.emit(b"\x49\x83\xc3\x20")              # add r11, 32
        buf.emit(b"\x49\x83\xc0\x20")              # add r8, 32
        buf.emit(b"\x49\x83\xc1\x20")              # add r9, 32
        buf.emit(b"\x48\x83\xe8\x04")              # sub rax, 4
        buf.jmp(".L_fma256_vec")

        buf.mark(".L_fma256_tail")
        buf.emit(b"\xc5\xf8\x77")                  # vzeroupper

        buf.mark(".L_fma256_scalar")
        buf.emit(_x64_test_rr("rax"))              # test rax, rax
        buf.emit(b"\x0f\x8e\x00\x00\x00\x00")
        buf.fixups.append((len(buf.code) - 4, ".L_fma256_done"))

        buf.emit(b"\xc4\xc1\x7b\x10\x02")          # vmovsd xmm0, qword ptr [r10]
        buf.emit(b"\xc4\xc1\x7b\x10\x0b")          # vmovsd xmm1, qword ptr [r11]
        buf.emit(b"\xc4\xc1\x7b\x10\x10")          # vmovsd xmm2, qword ptr [r8]
        buf.emit(b"\xc4\xe2\xf1\xa9\xc2")          # vfmadd213sd xmm0, xmm1, xmm2
        buf.emit(b"\xc4\xc1\x7b\x11\x01")          # vmovsd qword ptr [r9], xmm0
        buf.emit(b"\x49\x83\xc2\x08")              # add r10, 8
        buf.emit(b"\x49\x83\xc3\x08")              # add r11, 8
        buf.emit(b"\x49\x83\xc0\x08")              # add r8, 8
        buf.emit(b"\x49\x83\xc1\x08")              # add r9, 8
        buf.emit(b"\x48\xff\xc8")                  # dec rax
        buf.jmp(".L_fma256_scalar")

        buf.mark(".L_fma256_done")
        buf.emit(_x64_mov_ri("rax", 1))
        buf.emit(b"\xc3")
        return buf.finalize()

    def emit_avx512_evex_vec_add_i64(self) -> bytes:
        """
        Emits EVEX-encoded 512-bit AVX-512F kernel (8x i64 per vector instruction):
          int64_t avx512_vec_add_i64(const int64_t* a, const int64_t* b, int64_t* out, int64_t count)
        """
        buf = X64LabelBuffer()
        if self.is_windows:
            buf.emit(_x64_mov_rr("r10", "rcx"))
            buf.emit(_x64_mov_rr("r11", "rdx"))
            buf.emit(_x64_mov_rr("rax", "r9"))
            # out = r8, so mirror via r9 = r8
            buf.emit(_x64_mov_rr("r9", "r8"))
        else:
            buf.emit(_x64_mov_rr("r10", "rdi"))
            buf.emit(_x64_mov_rr("r11", "rsi"))
            buf.emit(_x64_mov_rr("r9", "rdx"))
            buf.emit(_x64_mov_rr("rax", "rcx"))

        buf.mark(".L_zmm_vec")
        buf.emit(b"\x48\x83\xf8\x08")              # cmp rax, 8
        buf.emit(b"\x0f\x8c\x00\x00\x00\x00")
        buf.fixups.append((len(buf.code) - 4, ".L_zmm_vzero"))

        buf.emit(b"\x62\xd1\xfe\x48\x6f\x02")      # vmovdqu64 zmm0, zmmword ptr [r10]
        buf.emit(b"\x62\xd1\xfe\x48\x6f\x0b")      # vmovdqu64 zmm1, zmmword ptr [r11]
        buf.emit(b"\x62\xf1\xfd\x48\xd4\xc1")      # vpaddq zmm0, zmm0, zmm1
        buf.emit(b"\x62\xd1\xfe\x48\x7f\x01")      # vmovdqu64 zmmword ptr [r9], zmm0
        buf.emit(b"\x49\x83\xc2\x40")              # add r10, 64
        buf.emit(b"\x49\x83\xc3\x40")              # add r11, 64
        buf.emit(b"\x49\x83\xc1\x40")              # add r9, 64
        buf.emit(b"\x48\x83\xe8\x08")              # sub rax, 8
        buf.jmp(".L_zmm_vec")

        buf.mark(".L_zmm_vzero")
        buf.emit(b"\xc5\xf8\x77")                  # vzeroupper

        buf.mark(".L_zmm_tail")
        buf.emit(_x64_test_rr("rax"))
        buf.emit(b"\x0f\x8e\x00\x00\x00\x00")
        buf.fixups.append((len(buf.code) - 4, ".L_zmm_done"))

        buf.emit(b"\x49\x8b\x0a")                  # mov rcx, [r10]
        buf.emit(b"\x49\x03\x0b")                  # add rcx, [r11]
        buf.emit(b"\x49\x89\x09")                  # mov [r9], rcx
        buf.emit(b"\x49\x83\xc2\x08")              # add r10, 8
        buf.emit(b"\x49\x83\xc3\x08")              # add r11, 8
        buf.emit(b"\x49\x83\xc1\x08")              # add r9, 8
        buf.emit(b"\x48\xff\xc8")                  # dec rax
        buf.jmp(".L_zmm_tail")

        buf.mark(".L_zmm_done")
        buf.emit(_x64_mov_ri("rax", 1))
        buf.emit(b"\xc3")
        return buf.finalize()

    def emit_avx512_evex_fma_pd(self) -> bytes:
        """
        Emits EVEX-encoded 512-bit AVX-512F Fused Multiply-Add kernel (8x f64 per instruction):
          int64_t avx512_fma_pd(const double* a, const double* b, const double* c, double* out, int64_t count)
        """
        buf = X64LabelBuffer()
        self._emit_5arg_setup(buf)

        buf.mark(".L_zfma_vec")
        buf.emit(b"\x48\x83\xf8\x08")              # cmp rax, 8
        buf.emit(b"\x0f\x8c\x00\x00\x00\x00")
        buf.fixups.append((len(buf.code) - 4, ".L_zfma_vzero"))

        buf.emit(b"\x62\xd1\xfd\x48\x10\x02")      # vmovupd zmm0, zmmword ptr [r10]
        buf.emit(b"\x62\xd1\xfd\x48\x10\x0b")      # vmovupd zmm1, zmmword ptr [r11]
        buf.emit(b"\x62\xd1\xfd\x48\x10\x10")      # vmovupd zmm2, zmmword ptr [r8]
        buf.emit(b"\x62\xf2\xf5\x48\xa8\xc2")      # vfmadd213pd zmm0, zmm1, zmm2
        buf.emit(b"\x62\xd1\xfd\x48\x11\x01")      # vmovupd zmmword ptr [r9], zmm0
        buf.emit(b"\x49\x83\xc2\x40")
        buf.emit(b"\x49\x83\xc3\x40")
        buf.emit(b"\x49\x83\xc0\x40")
        buf.emit(b"\x49\x83\xc1\x40")
        buf.emit(b"\x48\x83\xe8\x08")
        buf.jmp(".L_zfma_vec")

        buf.mark(".L_zfma_vzero")
        buf.emit(b"\xc5\xf8\x77")

        buf.mark(".L_zfma_tail")
        buf.emit(_x64_test_rr("rax"))
        buf.emit(b"\x0f\x8e\x00\x00\x00\x00")
        buf.fixups.append((len(buf.code) - 4, ".L_zfma_done"))

        buf.emit(b"\xc4\xc1\x7b\x10\x02")          # vmovsd xmm0, qword ptr [r10]
        buf.emit(b"\xc4\xc1\x7b\x10\x0b")          # vmovsd xmm1, qword ptr [r11]
        buf.emit(b"\xc4\xc1\x7b\x10\x10")          # vmovsd xmm2, qword ptr [r8]
        buf.emit(b"\xc4\xe2\xf1\xa9\xc2")          # vfmadd213sd xmm0, xmm1, xmm2
        buf.emit(b"\xc4\xc1\x7b\x11\x01")          # vmovsd qword ptr [r9], xmm0
        buf.emit(b"\x49\x83\xc2\x08")
        buf.emit(b"\x49\x83\xc3\x08")
        buf.emit(b"\x49\x83\xc0\x08")
        buf.emit(b"\x49\x83\xc1\x08")
        buf.emit(b"\x48\xff\xc8")
        buf.jmp(".L_zfma_tail")

        buf.mark(".L_zfma_done")
        buf.emit(_x64_mov_ri("rax", 1))
        buf.emit(b"\xc3")
        return buf.finalize()

    def emit_avx2_fma_dot_pd(self) -> bytes:
        """
        Emits 256-bit AVX2+FMA horizontal dot-product reduction kernel:
          double avx2_fma_dot_pd(const double* a, const double* b, int64_t count)
        Accumulates sum_{i=0}^{count-1} a[i]*b[i] via `vfmadd231pd ymm2, ymm0, ymm1` + horizontal collapse.
        """
        buf = X64LabelBuffer()
        if self.is_windows:
            buf.emit(_x64_mov_rr("r10", "rcx"))
            buf.emit(_x64_mov_rr("r11", "rdx"))
            buf.emit(_x64_mov_rr("rax", "r8"))
        else:
            buf.emit(_x64_mov_rr("r10", "rdi"))
            buf.emit(_x64_mov_rr("r11", "rsi"))
            buf.emit(_x64_mov_rr("rax", "rdx"))

        buf.emit(b"\xc5\xed\x57\xd2")              # vxorpd ymm2, ymm2, ymm2

        buf.mark(".L_dotf_vec")
        buf.emit(b"\x48\x83\xf8\x04")              # cmp rax, 4
        buf.emit(b"\x0f\x8c\x00\x00\x00\x00")
        buf.fixups.append((len(buf.code) - 4, ".L_dotf_reduce"))

        buf.emit(b"\xc4\xc1\x7d\x10\x02")          # vmovupd ymm0, [r10]
        buf.emit(b"\xc4\xc1\x7d\x10\x0b")          # vmovupd ymm1, [r11]
        buf.emit(b"\xc4\xe2\xfd\xb8\xd1")          # vfmadd231pd ymm2, ymm0, ymm1
        buf.emit(b"\x49\x83\xc2\x20")              # add r10, 32
        buf.emit(b"\x49\x83\xc3\x20")              # add r11, 32
        buf.emit(b"\x48\x83\xe8\x04")              # sub rax, 4
        buf.jmp(".L_dotf_vec")

        buf.mark(".L_dotf_reduce")
        buf.emit(b"\xc4\xe3\x7d\x19\xd0\x00")      # vextractf128 xmm0, ymm2, 0
        buf.emit(b"\xc4\xe3\x7d\x19\xd1\x01")      # vextractf128 xmm1, ymm2, 1
        buf.emit(b"\xc5\xf9\x58\xc1")              # vaddpd xmm0, xmm0, xmm1
        buf.emit(b"\xc5\xf9\x7c\xc0")              # vhaddpd xmm0, xmm0, xmm0
        buf.emit(b"\xc5\xf8\x77")                  # vzeroupper

        buf.mark(".L_dotf_tail")
        buf.emit(_x64_test_rr("rax"))
        buf.emit(b"\x0f\x8e\x00\x00\x00\x00")
        buf.fixups.append((len(buf.code) - 4, ".L_dotf_done"))

        buf.emit(b"\xc4\xc1\x7b\x10\x0a")          # vmovsd xmm1, [r10]
        buf.emit(b"\xc4\xc1\x7b\x10\x1b")          # vmovsd xmm3, [r11]
        buf.emit(b"\xc4\xe2\xf1\xb9\xc3")          # vfmadd231sd xmm0, xmm1, xmm3
        buf.emit(b"\x49\x83\xc2\x08")
        buf.emit(b"\x49\x83\xc3\x08")
        buf.emit(b"\x48\xff\xc8")
        buf.jmp(".L_dotf_tail")

        buf.mark(".L_dotf_done")
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
        const_int_map_arm: Dict[SSAVar, int] = {}
        for b in fn.blocks:
            for inst in b.instructions:
                if inst.opcode.lower() == "const" and isinstance(inst.result, SSAVar) and inst.operands:
                    cv = inst.operands[0]
                    if isinstance(cv, int) and not isinstance(cv, bool):
                        const_int_map_arm[inst.result] = cv
                    elif isinstance(cv, str) and (cv.isdigit() or (cv.startswith("-") and cv[1:].isdigit())):
                        const_int_map_arm[inst.result] = int(cv)

        def _arm_const_int(op: Any) -> Optional[int]:
            if isinstance(op, int) and not isinstance(op, bool):
                return op
            if isinstance(op, str):
                s = op.strip()
                if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                    return int(s)
            if isinstance(op, SSAVar):
                return const_int_map_arm.get(op)
            return None
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
        if frame_size > 0xFFF:
            code.extend(_a64_u32(0xD14003FF | (((frame_size >> 12) & 0xFFF) << 10)))
        if (frame_size & 0xFFF) or frame_size <= 0xFFF:
            code.extend(_a64_u32(0xD10003FF | ((frame_size & 0xFFF) << 10)))
        # STP X29, X30, [SP, #0] -> 0xA9007BFD
        code.extend(_a64_u32(0xA9007BFD))
        prologue_size = len(code)

        # Store incoming parameters X0..X7 / D0..D7 into slots (AAPCS64)
        a64_int_idx = 0
        a64_fp_idx = 0
        for p_name in fn.params:
            pv = SSAVar(p_name, 0)
            if pv not in slot_idx_map:
                continue
            if fn.param_types.get(p_name) == "f64":
                if a64_fp_idx < 8:
                    # FMOV X9, D{a64_fp_idx} -> 0x9E660009 | (a64_fp_idx << 5)
                    code.extend(_a64_u32(0x9E660009 | (a64_fp_idx << 5)))
                    code.extend(_a64_str_fp_slot(9, slot_idx_map[pv]))
                    a64_fp_idx += 1
            else:
                if a64_int_idx < 8:
                    code.extend(_a64_str_fp_slot(a64_int_idx, slot_idx_map[pv]))
                    a64_int_idx += 1

        def load_op(op: Any, target_x: int):
            if isinstance(op, float):
                code.extend(_a64_mov_imm64(target_x, _f64_bits(op)))
                return
            if isinstance(op, bool):
                code.extend(_a64_mov_imm64(target_x, int(op)))
                return
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

        _NEON_64B_ALU_OPS: Dict[str, int] = {
            "add": 0x4EE18400,   # ADD V0.2D, V0.2D, V1.2D
            "sub": 0x6EE18400,   # SUB V0.2D, V0.2D, V1.2D
            "and": 0x4E211C00,   # AND V0.16B, V0.16B, V1.16B
            "or":  0x4EA11C00,   # ORR V0.16B, V0.16B, V1.16B
            "xor": 0x6E211C00,   # EOR V0.16B, V0.16B, V1.16B
            "fadd": 0x4E61D400,  # FADD V0.2D, V0.2D, V1.2D
            "fsub": 0x4EE1D400,  # FSUB V0.2D, V0.2D, V1.2D
            "fmul": 0x6E61DC00,  # FMUL V0.2D, V0.2D, V1.2D
        }
        _NEON_32B_ALU_OPS: Dict[str, int] = {
            "add": 0x4EA18400,   # ADD V0.4S, V0.4S, V1.4S
            "sub": 0x6EA18400,   # SUB V0.4S, V0.4S, V1.4S
            "mul": 0x4EA19C00,   # MUL V0.4S, V0.4S, V1.4S
            "imul": 0x4EA19C00,  # MUL V0.4S, V0.4S, V1.4S
            "and": 0x4E211C00,   # AND V0.16B, V0.16B, V1.16B
            "or":  0x4EA11C00,   # ORR V0.16B, V0.16B, V1.16B
            "xor": 0x6E211C00,   # EOR V0.16B, V0.16B, V1.16B
            "fadd": 0x4E21D400,  # FADD V0.4S, V0.4S, V1.4S
            "fsub": 0x4EA1D400,  # FSUB V0.4S, V0.4S, V1.4S
            "fmul": 0x6E21DC00,  # FMUL V0.4S, V0.4S, V1.4S
        }

        fn_add_const_arm = analyze_ssa_constant_offsets(fn)

        for block in fn.blocks:
            mark(f".L_bb_{block.name}")
            blk_def_map: Dict[SSAVar, SSAInstruction] = {
                b_ins.result: b_ins
                for b_ins in block.instructions
                if isinstance(b_ins.result, SSAVar)
            }

            def _are_contiguous_8b_offsets(off0: Any, off1: Any) -> bool:
                return is_contiguous_stride(fn_add_const_arm, [off0, off1], 8)

            def _are_contiguous_8b_quad(off0: Any, off1: Any, off2: Any, off3: Any) -> bool:
                return is_contiguous_stride(fn_add_const_arm, [off0, off1, off2, off3], 8)

            def _are_contiguous_4b_quad(off0: Any, off1: Any, off2: Any, off3: Any) -> bool:
                return is_contiguous_stride(fn_add_const_arm, [off0, off1, off2, off3], 4)

            def _are_contiguous_4b_oct(offs: List[Any]) -> bool:
                return is_contiguous_stride(fn_add_const_arm, offs, 4)

            inst_idx = 0
            while inst_idx < len(block.instructions):
                inst = block.instructions[inst_idx]
                inst_idx += 1
                if inst.source_line > 0:
                    line_table.append((len(code), inst.source_line))
                op = inst.opcode.lower()
                if op == "param":
                    continue
                elif op in ("const", "fconst", "mov"):
                    load_op(inst.operands[0], 9)
                    store_res(inst.result, 9)
                elif op == "add":
                    if inst_idx + 1 < len(block.instructions):
                        ins_hi = block.instructions[inst_idx]
                        ins_top = block.instructions[inst_idx + 1]
                        if (
                            ins_hi.opcode.lower() == "add"
                            and ins_top.opcode.lower() == "add"
                            and isinstance(inst.result, SSAVar)
                            and isinstance(ins_hi.result, SSAVar)
                            and inst.result != ins_hi.result
                            and inst.result not in ins_hi.operands
                            and len(inst.operands) == 2
                            and len(ins_hi.operands) == 2
                            and len(ins_top.operands) == 2
                            and set(ins_top.operands) == {inst.result, ins_hi.result}
                        ):
                            load_op(inst.operands[0], 11)
                            code.extend(_a64_u32(0x9E670160))  # FMOV D0, X11
                            load_op(ins_hi.operands[0], 11)
                            code.extend(_a64_u32(0x4E181D60))  # INS V0.D[1], X11
                            load_op(inst.operands[1], 11)
                            code.extend(_a64_u32(0x9E670161))  # FMOV D1, X11
                            load_op(ins_hi.operands[1], 11)
                            code.extend(_a64_u32(0x4E181D61))  # INS V1.D[1], X11
                            code.extend(_a64_u32(0x4EE18400))  # ADD V0.2D, V0.2D, V1.2D
                            code.extend(_a64_u32(0x9E660009))  # FMOV X9, D0
                            store_res(inst.result, 9)
                            code.extend(_a64_u32(0x4E183C09))  # UMOV X9, V0.D[1]
                            store_res(ins_hi.result, 9)
                            code.extend(_a64_u32(0x5EF1B800))  # ADDP D0, V0.2D
                            code.extend(_a64_u32(0x9E660009))  # FMOV X9, D0
                            store_res(ins_top.result, 9)
                            inst_idx += 2
                            continue
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
                elif op in ("div", "sdiv", "srem"):
                    c_div = _arm_const_int(inst.operands[1]) if len(inst.operands) > 1 else None
                    if c_div is not None and c_div > 1 and (c_div & (c_div - 1)) == 0 and c_div < (1 << 62):
                        k = c_div.bit_length() - 1
                        load_op(inst.operands[0], 9)
                        code.extend(_a64_u32(0x9340FC00 | (63 << 16) | (9 << 5) | 10))          # ASR X10, X9, #63
                        code.extend(_a64_u32(0xD340FC00 | ((64 - k) << 16) | (10 << 5) | 10))   # LSR X10, X10, #(64-k)
                        code.extend(_a64_u32(0x8B0A012B))                                       # ADD X11, X9, X10
                        code.extend(_a64_u32(0x9340FC00 | (k << 16) | (11 << 5) | 11))          # ASR X11, X11, #k
                        if op == "srem":
                            code.extend(_a64_u32(0xD3400000 | ((64 - k) << 16) | ((63 - k) << 10) | (11 << 5) | 10)) # LSL X10, X11, #k
                            code.extend(_a64_u32(0xCB0A0129))                                   # SUB X9, X9, X10
                            store_res(inst.result, 9)
                        else:
                            store_res(inst.result, 11)
                    elif c_div is not None and c_div > 1:
                        M_u, s = compute_magic_signed_64(c_div)
                        M_signed = M_u if M_u < (1 << 63) else M_u - (1 << 64)
                        load_op(inst.operands[0], 9)
                        code.extend(_a64_mov_imm64(10, M_signed))
                        code.extend(_a64_u32(0x9B407C00 | (10 << 16) | (9 << 5) | 11))          # SMULH X11, X9, X10
                        if M_u >= (1 << 63):
                            code.extend(_a64_u32(0x8B000000 | (9 << 16) | (11 << 5) | 11))      # ADD X11, X11, X9
                        if s > 0:
                            code.extend(_a64_u32(0x9340FC00 | (s << 16) | (11 << 5) | 11))      # ASR X11, X11, #s
                        code.extend(_a64_u32(0xD340FC00 | (63 << 16) | (9 << 5) | 12))          # LSR X12, X9, #63
                        code.extend(_a64_u32(0x8B000000 | (12 << 16) | (11 << 5) | 11))         # ADD X11, X11, X12
                        if op == "srem":
                            code.extend(_a64_mov_imm64(10, c_div))
                            code.extend(_a64_u32(0x9B0A8000 | (9 << 10) | (11 << 5) | 9))       # MSUB X9, X11, X10, X9
                            store_res(inst.result, 9)
                        else:
                            store_res(inst.result, 11)
                    else:
                        load_op(inst.operands[0], 9)
                        load_op(inst.operands[1], 10)
                        if op == "srem":
                            code.extend(_a64_u32(0x9ACA0D2B))  # SDIV X11, X9, X10
                            code.extend(_a64_u32(0x9B0A8000 | (9 << 10) | (11 << 5) | 9))
                        else:
                            code.extend(_a64_u32(0x9ACA0D29))  # SDIV X9, X9, X10
                        store_res(inst.result, 9)
                elif op == "shl":
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    code.extend(_a64_u32(0x9ACA2129))  # LSLV X9, X9, X10
                    store_res(inst.result, 9)
                elif op == "neg":
                    load_op(inst.operands[0], 9)
                    code.extend(_a64_u32(0xCB0903E9))  # SUB X9, XZR, X9
                    store_res(inst.result, 9)
                elif op == "not":
                    load_op(inst.operands[0], 9)
                    code.extend(_a64_u32(0xEB1F013F))  # CMP X9, XZR
                    code.extend(_a64_u32(0x9A9F17E9))  # CSET X9, EQ (CSINC X9, XZR, XZR, NE)
                    store_res(inst.result, 9)
                elif op in ("shr", "sar"):
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
                elif op in ("fadd", "fsub", "fmul", "fdiv"):
                    if op == "fadd" and inst_idx + 1 < len(block.instructions):
                        ins_hi = block.instructions[inst_idx]
                        ins_top = block.instructions[inst_idx + 1]
                        if (
                            ins_hi.opcode.lower() == "fadd"
                            and ins_top.opcode.lower() == "fadd"
                            and isinstance(inst.result, SSAVar)
                            and isinstance(ins_hi.result, SSAVar)
                            and inst.result != ins_hi.result
                            and inst.result not in ins_hi.operands
                            and len(inst.operands) == 2
                            and len(ins_hi.operands) == 2
                            and len(ins_top.operands) == 2
                            and set(ins_top.operands) == {inst.result, ins_hi.result}
                        ):
                            load_op(inst.operands[0], 11)
                            code.extend(_a64_u32(0x9E670160))  # FMOV D0, X11
                            load_op(ins_hi.operands[0], 11)
                            code.extend(_a64_u32(0x4E181D60))  # INS V0.D[1], X11
                            load_op(inst.operands[1], 11)
                            code.extend(_a64_u32(0x9E670161))  # FMOV D1, X11
                            load_op(ins_hi.operands[1], 11)
                            code.extend(_a64_u32(0x4E181D61))  # INS V1.D[1], X11
                            code.extend(_a64_u32(0x4E61D400))  # FADD V0.2D, V0.2D, V1.2D
                            code.extend(_a64_u32(0x9E660009))  # FMOV X9, D0
                            store_res(inst.result, 9)
                            code.extend(_a64_u32(0x4E183C09))  # UMOV X9, V0.D[1]
                            store_res(ins_hi.result, 9)
                            code.extend(_a64_u32(0x7E70D400))  # FADDP D0, V0.2D
                            code.extend(_a64_u32(0x9E660009))  # FMOV X9, D0
                            store_res(ins_top.result, 9)
                            inst_idx += 2
                            continue
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    code.extend(_a64_u32(0x9E670120))  # FMOV D0, X9
                    code.extend(_a64_u32(0x9E670141))  # FMOV D1, X10
                    vfp_op = {"fadd": 0x1E612800, "fsub": 0x1E613800, "fmul": 0x1E610800, "fdiv": 0x1E611800}[op]
                    code.extend(_a64_u32(vfp_op))
                    code.extend(_a64_u32(0x9E660009))  # FMOV X9, D0
                    store_res(inst.result, 9)
                elif op == "fneg":
                    load_op(inst.operands[0], 9)
                    code.extend(_a64_u32(0x9E670120))  # FMOV D0, X9
                    code.extend(_a64_u32(0x1E614000))  # FNEG D0, D0
                    code.extend(_a64_u32(0x9E660009))  # FMOV X9, D0
                    store_res(inst.result, 9)
                elif op == "sitofp":
                    load_op(inst.operands[0], 9)
                    code.extend(_a64_u32(0x9E620120))  # SCVTF D0, X9
                    code.extend(_a64_u32(0x9E660009))  # FMOV X9, D0
                    store_res(inst.result, 9)
                elif op == "fptosi":
                    load_op(inst.operands[0], 9)
                    code.extend(_a64_u32(0x9E670120))  # FMOV D0, X9
                    code.extend(_a64_u32(0x9E780009))  # FCVTZS X9, D0
                    store_res(inst.result, 9)
                elif op in ("fcmp_eq", "fcmp_ne", "fcmp_lt", "fcmp_le", "fcmp_gt", "fcmp_ge"):
                    load_op(inst.operands[0], 9)
                    load_op(inst.operands[1], 10)
                    code.extend(_a64_u32(0x9E670120))  # FMOV D0, X9
                    code.extend(_a64_u32(0x9E670141))  # FMOV D1, X10
                    code.extend(_a64_u32(0x1E612000))  # FCMP D0, D1
                    if op == "fcmp_ne":
                        code.extend(_a64_u32(0x9A9F07E9 | (0 << 12)))   # CSET X9, NE (inv=EQ)
                        code.extend(_a64_u32(0x9A9F07EA | (6 << 12)))   # CSET X10, VC (inv=VS)
                        code.extend(_a64_u32(0x8A0A0129))                # AND X9, X9, X10
                    else:
                        inv_fc = {"fcmp_eq": 1, "fcmp_lt": 5, "fcmp_le": 8, "fcmp_gt": 13, "fcmp_ge": 11}[op]
                        code.extend(_a64_u32(0x9A9F07E9 | (inv_fc << 12)))
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
                elif op == "load_off":
                    load_op(inst.operands[0], 9)   # base ptr in X9
                    load_op(inst.operands[1], 10)  # byte offset in X10
                    width = str(inst.operands[2]) if len(inst.operands) >= 3 else "i64"
                    code.extend(_a64_u32(0x8B0A0129))  # ADD X9, X9, X10
                    if width == "i8":
                        code.extend(_a64_u32(0x3980012B))  # LDRSB X11, [X9]
                    elif width == "u8":
                        code.extend(_a64_u32(0x3940012B))  # LDRB W11, [X9]
                    elif width == "i16":
                        code.extend(_a64_u32(0x7980012B))  # LDRSH X11, [X9]
                    elif width == "u16":
                        code.extend(_a64_u32(0x7940012B))  # LDRH W11, [X9]
                    elif width == "i32":
                        code.extend(_a64_u32(0xB980012B))  # LDRSW X11, [X9]
                    elif width == "u32":
                        code.extend(_a64_u32(0xB940012B))  # LDR W11, [X9]
                    elif width == "f32":
                        code.extend(_a64_u32(0xBD400120))  # LDR S0, [X9]
                        code.extend(_a64_u32(0x1E22C000))  # FCVT D0, S0
                        code.extend(_a64_u32(0x9E66000B))  # FMOV X11, D0
                    else:
                        code.extend(_a64_u32(0xF940012B))  # LDR X11, [X9]
                    store_res(inst.result, 11)
                elif op == "lut_load":
                    lut_name = str(inst.operands[0])
                    width = str(inst.operands[1])
                    idx_op = inst.operands[2]
                    b_fixups.append((len(code), "ADR", f".L_ro_{lut_name}"))
                    code.extend(_a64_u32(0x10000009))  # ADR X9, #0 (patched)
                    load_op(idx_op, 10)
                    _, _, sh = _LUT_PACK_SPEC.get(width, ("q", 8, 3))
                    code.extend(_a64_u32(0x8B0A0129 | ((sh & 63) << 10)))  # ADD X9, X9, X10, LSL #sh
                    if width == "i8":
                        code.extend(_a64_u32(0x3980012B))
                    elif width == "u8":
                        code.extend(_a64_u32(0x3940012B))
                    elif width == "i16":
                        code.extend(_a64_u32(0x7980012B))
                    elif width == "u16":
                        code.extend(_a64_u32(0x7940012B))
                    elif width == "i32":
                        code.extend(_a64_u32(0xB980012B))
                    elif width == "u32":
                        code.extend(_a64_u32(0xB940012B))
                    elif width == "f32":
                        code.extend(_a64_u32(0xBD400120))
                        code.extend(_a64_u32(0x1E22C000))
                        code.extend(_a64_u32(0x9E66000B))
                    else:
                        code.extend(_a64_u32(0xF940012B))
                    store_res(inst.result, 11)
                elif op == "cstr_addr":
                    c_name = str(inst.operands[0])
                    b_fixups.append((len(code), "ADR", f".L_cstr_{c_name}"))
                    code.extend(_a64_u32(0x10000009))  # ADR X9, #0 (patched)
                    store_res(inst.result, 9)
                elif op == "store_off":
                    width = str(inst.operands[3]) if len(inst.operands) >= 4 else "i64"
                    if width in ("i64", "u64", "f64") and inst_idx < len(block.instructions):
                        nxt_st = block.instructions[inst_idx]
                        nxt_w = str(nxt_st.operands[3]) if (nxt_st.opcode.lower() == "store_off" and len(nxt_st.operands) >= 4) else ""
                        if (
                            nxt_st.opcode.lower() == "store_off"
                            and nxt_w == width
                            and nxt_st.operands[0] == inst.operands[0]
                            and _are_contiguous_8b_offsets(inst.operands[1], nxt_st.operands[1])
                        ):
                            val0, val1 = inst.operands[2], nxt_st.operands[2]
                            ins0 = blk_def_map.get(val0) if isinstance(val0, SSAVar) else None
                            ins1 = blk_def_map.get(val1) if isinstance(val1, SSAVar) else None
                            emitted_neon_2x = False
                            if (
                                ins0 is not None and ins1 is not None
                                and ins0.opcode.lower() == ins1.opcode.lower()
                                and ins0.opcode.lower() in _NEON_64B_ALU_OPS
                                and len(ins0.operands) == 2 and len(ins1.operands) == 2
                            ):
                                op_2x = ins0.opcode.lower()
                                is_f_op = op_2x.startswith("f")
                                if (width == "f64" and is_f_op) or (width in ("i64", "u64") and not is_f_op):
                                    ld_a0 = blk_def_map.get(ins0.operands[0]) if isinstance(ins0.operands[0], SSAVar) else None
                                    ld_a1 = blk_def_map.get(ins1.operands[0]) if isinstance(ins1.operands[0], SSAVar) else None
                                    ld_b0 = blk_def_map.get(ins0.operands[1]) if isinstance(ins0.operands[1], SSAVar) else None
                                    ld_b1 = blk_def_map.get(ins1.operands[1]) if isinstance(ins1.operands[1], SSAVar) else None
                                    if (
                                        ld_a0 is not None and ld_a1 is not None and ld_b0 is not None and ld_b1 is not None
                                        and ld_a0.opcode.lower() == "load_off" and ld_a1.opcode.lower() == "load_off"
                                        and ld_b0.opcode.lower() == "load_off" and ld_b1.opcode.lower() == "load_off"
                                        and str(ld_a0.operands[2]) == width == str(ld_a1.operands[2])
                                        and str(ld_b0.operands[2]) == width == str(ld_b1.operands[2])
                                        and ld_a0.operands[0] == ld_a1.operands[0]
                                        and ld_b0.operands[0] == ld_b1.operands[0]
                                        and _are_contiguous_8b_offsets(ld_a0.operands[1], ld_a1.operands[1])
                                        and _are_contiguous_8b_offsets(ld_b0.operands[1], ld_b1.operands[1])
                                    ):
                                        load_op(ld_a0.operands[0], 9)
                                        load_op(ld_a0.operands[1], 10)
                                        code.extend(_a64_u32(0x8B0A0129))                # ADD X9, X9, X10
                                        code.extend(_a64_u32(0x3DC00120))                # LDR Q0, [X9]
                                        load_op(ld_b0.operands[0], 9)
                                        load_op(ld_b0.operands[1], 10)
                                        code.extend(_a64_u32(0x8B0A0129))                # ADD X9, X9, X10
                                        code.extend(_a64_u32(0x3DC00121))                # LDR Q1, [X9]
                                        code.extend(_a64_u32(_NEON_64B_ALU_OPS[op_2x]))  # V0.2D = V0.2D op V1.2D
                                        load_op(inst.operands[0], 9)
                                        load_op(inst.operands[1], 10)
                                        code.extend(_a64_u32(0x8B0A0129))                # ADD X9, X9, X10
                                        code.extend(_a64_u32(0x3D800120))                # STR Q0, [X9]
                                        emitted_neon_2x = True
                            if not emitted_neon_2x:
                                load_op(val0, 11)
                                code.extend(_a64_u32(0x9E670160))                        # FMOV D0, X11
                                load_op(val1, 11)
                                code.extend(_a64_u32(0x4E181D60))                        # INS V0.D[1], X11
                                load_op(inst.operands[0], 9)
                                load_op(inst.operands[1], 10)
                                code.extend(_a64_u32(0x8B0A0129))                        # ADD X9, X9, X10
                                code.extend(_a64_u32(0x3D800120))                        # STR Q0, [X9]
                            inst_idx += 1
                            continue

                    if width in ("i32", "u32", "f32") and inst_idx + 2 < len(block.instructions):
                        st1 = block.instructions[inst_idx]
                        st2 = block.instructions[inst_idx + 1]
                        st3 = block.instructions[inst_idx + 2]
                        if (
                            st1.opcode.lower() == "store_off" and len(st1.operands) >= 4 and str(st1.operands[3]) == width
                            and st2.opcode.lower() == "store_off" and len(st2.operands) >= 4 and str(st2.operands[3]) == width
                            and st3.opcode.lower() == "store_off" and len(st3.operands) >= 4 and str(st3.operands[3]) == width
                            and st1.operands[0] == inst.operands[0] == st2.operands[0] == st3.operands[0]
                            and _are_contiguous_4b_quad(inst.operands[1], st1.operands[1], st2.operands[1], st3.operands[1])
                        ):
                            vals_q = [inst.operands[2], st1.operands[2], st2.operands[2], st3.operands[2]]
                            inss_q = [blk_def_map.get(v) if isinstance(v, SSAVar) else None for v in vals_q]
                            emitted_neon_4x = False
                            if all(
                                x is not None
                                and x.opcode.lower() == inss_q[0].opcode.lower()
                                and x.opcode.lower() in _NEON_32B_ALU_OPS
                                and len(x.operands) == 2
                                for x in inss_q
                            ):
                                op_4x = inss_q[0].opcode.lower()
                                is_f32_op = op_4x.startswith("f")
                                if (width == "f32" and is_f32_op) or (width in ("i32", "u32") and not is_f32_op):
                                    lds_a = [blk_def_map.get(x.operands[0]) if isinstance(x.operands[0], SSAVar) else None for x in inss_q]
                                    lds_b = [blk_def_map.get(x.operands[1]) if isinstance(x.operands[1], SSAVar) else None for x in inss_q]
                                    if (
                                        all(la is not None and la.opcode.lower() == "load_off" and str(la.operands[2]) == width and la.operands[0] == lds_a[0].operands[0] for la in lds_a)
                                        and all(lb is not None and lb.opcode.lower() == "load_off" and str(lb.operands[2]) == width and lb.operands[0] == lds_b[0].operands[0] for lb in lds_b)
                                        and _are_contiguous_4b_quad(lds_a[0].operands[1], lds_a[1].operands[1], lds_a[2].operands[1], lds_a[3].operands[1])
                                        and _are_contiguous_4b_quad(lds_b[0].operands[1], lds_b[1].operands[1], lds_b[2].operands[1], lds_b[3].operands[1])
                                    ):
                                        load_op(lds_a[0].operands[0], 9)
                                        load_op(lds_a[0].operands[1], 10)
                                        code.extend(_a64_u32(0x8B0A0129))                # ADD X9, X9, X10
                                        code.extend(_a64_u32(0x3DC00120))                # LDR Q0, [X9]
                                        load_op(lds_b[0].operands[0], 9)
                                        load_op(lds_b[0].operands[1], 10)
                                        code.extend(_a64_u32(0x8B0A0129))                # ADD X9, X9, X10
                                        code.extend(_a64_u32(0x3DC00121))                # LDR Q1, [X9]
                                        code.extend(_a64_u32(_NEON_32B_ALU_OPS[op_4x]))  # V0.4S = V0.4S op V1.4S
                                        load_op(inst.operands[0], 9)
                                        load_op(inst.operands[1], 10)
                                        code.extend(_a64_u32(0x8B0A0129))                # ADD X9, X9, X10
                                        code.extend(_a64_u32(0x3D800120))                # STR Q0, [X9]
                                        emitted_neon_4x = True
                            if not emitted_neon_4x:
                                for ln_k in range(4):
                                    load_op(vals_q[ln_k], 11)
                                    if width == "f32":
                                        code.extend(_a64_u32(0x9E670161))                # FMOV D1, X11
                                        code.extend(_a64_u32(0x1E624021))                # FCVT S1, D1
                                        code.extend(_a64_u32(0x1E26002B))                # FMOV W11, S1
                                    imm5_s = (ln_k << 3) | 0x4
                                    code.extend(_a64_u32(0x4E001C00 | (imm5_s << 16) | (11 << 5) | 0))  # INS V0.S[ln_k], W11
                                load_op(inst.operands[0], 9)
                                load_op(inst.operands[1], 10)
                                code.extend(_a64_u32(0x8B0A0129))                        # ADD X9, X9, X10
                                code.extend(_a64_u32(0x3D800120))                        # STR Q0, [X9]
                            inst_idx += 3
                            continue

                    load_op(inst.operands[0], 9)   # base ptr in X9
                    load_op(inst.operands[1], 10)  # byte offset in X10
                    load_op(inst.operands[2], 11)  # value in X11
                    code.extend(_a64_u32(0x8B0A0129))  # ADD X9, X9, X10
                    if width in ("i8", "u8"):
                        code.extend(_a64_u32(0x3900012B))  # STRB W11, [X9]
                    elif width in ("i16", "u16"):
                        code.extend(_a64_u32(0x7900012B))  # STRH W11, [X9]
                    elif width in ("i32", "u32"):
                        code.extend(_a64_u32(0xB900012B))  # STR W11, [X9]
                    elif width == "f32":
                        code.extend(_a64_u32(0x9E670160))  # FMOV D0, X11
                        code.extend(_a64_u32(0x1E624000))  # FCVT S0, D0
                        code.extend(_a64_u32(0xBD000120))  # STR S0, [X9]
                    else:
                        code.extend(_a64_u32(0xF900012B))  # STR X11, [X9]
                elif op == "alloca":
                    disp = alloca_map.get(inst.result, 16)
                    # SUB X9, X29, #disp -> 0xD1000000 | ((disp & 0xFFF) << 10) | (29 << 5) | 9
                    code.extend(_a64_u32(0xD1000000 | ((disp & 0xFFF) << 10) | (29 << 5) | 9))
                    store_res(inst.result, 9)
                elif op == "call":
                    callee = str(inst.operands[0])
                    c_int_a, c_fp_a = 0, 0
                    for a_op in inst.operands[1:]:
                        is_fp_a = isinstance(a_op, float) or (isinstance(a_op, SSAVar) and a_op.var_type == "f64")
                        if is_fp_a and c_fp_a < 8:
                            load_op(a_op, 9)
                            code.extend(_a64_u32(0x9E670120 | c_fp_a))  # FMOV D{c_fp_a}, X9
                            c_fp_a += 1
                        elif not is_fp_a and c_int_a < 8:
                            load_op(a_op, c_int_a)
                            c_int_a += 1
                    off = len(code)
                    code.extend(_a64_u32(0x94000000))  # BL #0
                    if callee == fn.name:
                        b_fixups.append((off, "BL", ".L_func_entry"))
                    else:
                        relocs.append(CodegenRelocation(offset=off, symbol_name=callee, reloc_type="ARM64_CALL26"))
                    if inst.result is not None and inst.result.var_type == "f64":
                        code.extend(_a64_u32(0x9E660000))  # FMOV X0, D0
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
                        rv = inst.operands[0]
                        load_op(rv, 0)
                        if getattr(fn, "return_type", "i64") == "f64" or isinstance(rv, float) or (isinstance(rv, SSAVar) and rv.var_type == "f64"):
                            code.extend(_a64_u32(0x9E670000))  # FMOV D0, X0
                    else:
                        code.extend(_a64_mov_imm64(0, 0))
                        if getattr(fn, "return_type", "i64") == "f64":
                            code.extend(_a64_u32(0x9E670000))
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
                elif isinstance(c_val, float):
                    src_s = ("imm", _f64_bits(c_val))
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
        if frame_size > 0xFFF:
            code.extend(_a64_u32(0x914003FF | (((frame_size >> 12) & 0xFFF) << 10)))
        if (frame_size & 0xFFF) or frame_size <= 0xFFF:
            code.extend(_a64_u32(0x910003FF | ((frame_size & 0xFFF) << 10)))
        # RET -> 0xD65F03C0
        code.extend(_a64_u32(0xD65F03C0))
        a64_code_end = len(code)

        luts_map = getattr(fn, "luts", {}) or {}
        cstrs_map = getattr(fn, "cstrs", {}) or {}
        if luts_map or cstrs_map:
            if len(code) % 8 != 0:
                code.extend(_a64_u32(0xD503201F))
            for l_name, (l_wt, l_vals) in sorted(luts_map.items()):
                mark(f".L_ro_{l_name}")
                packed = _pack_lut_bytes(l_wt, l_vals)
                rem4 = (-len(packed)) & 3
                code.extend(packed + b"\x00" * rem4)
            for c_name, c_bytes in sorted(cstrs_map.items()):
                mark(f".L_cstr_{c_name}")
                rem4 = (-len(c_bytes)) & 3
                code.extend(c_bytes + b"\x00" * rem4)

        # Patch branches
        for off, kind, lbl in b_fixups:
            target = labels[lbl]
            if kind == "ADR":
                delta_b = target - off
                immlo = delta_b & 0x3
                immhi = (delta_b >> 2) & 0x7FFFF
                inst_w = 0x10000009 | (immlo << 29) | (immhi << 5)
            else:
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
            code_end_offset=a64_code_end,
        )

    def emit_neon_vector_add_f64(self) -> bytes:
        """
        Emits a 128-bit ARMv8-A NEON ASIMD IEEE-754 double-precision vector kernel:
          int64_t neon_add_f64(const double* a, const double* b, double* out, int64_t count)
        Processes 2 x 64-bit IEEE-754 doubles (16 bytes) per cycle using V0.2D/V1.2D (`FADD V0.2D, V0.2D, V1.2D`),
        with scalar VFP `FADD D0, D0, D1` tail cleanup.
        """
        words = [
            # .L_vec_loop (word 0):
            0xF100087F,  # 0: CMP X3, #2
            0x540000EB,  # 1: B.LT .L_tail (+7 words -> word 8)
            0x3CC10400,  # 2: LDR Q0, [X0], #16
            0x3CC10421,  # 3: LDR Q1, [X1], #16
            0x4E61D400,  # 4: FADD V0.2D, V0.2D, V1.2D
            0x3C810440,  # 5: STR Q0, [X2], #16
            0xD1000863,  # 6: SUB X3, X3, #2
            0x17FFFFF9,  # 7: B .L_vec_loop (-7 words -> word 0)
            # .L_tail (word 8):
            0xF100007F,  # 8: CMP X3, #0
            0x540000ED,  # 9: B.LE .L_done (+7 words -> word 16)
            0xFC408400,  # 10: LDR D0, [X0], #8
            0xFC408421,  # 11: LDR D1, [X1], #8
            0x1E612800,  # 12: FADD D0, D0, D1
            0xFC008440,  # 13: STR D0, [X2], #8
            0xD1000463,  # 14: SUB X3, X3, #1
            0x17FFFFF9,  # 15: B .L_tail (-7 words -> word 8)
            # .L_done (word 16):
            0xD2800020,  # 16: MOVZ X0, #1
            0xD65F03C0,  # 17: RET
        ]
        return b"".join(_a64_u32(w) for w in words)


class NativeCodeGenerator:
    """Unified Multi-Architecture Codegen Dispatcher (`x86_64`, `arm64`, `riscv64`)."""

    def __init__(
        self,
        arch: str = "x86_64",
        target_os: Optional[str] = None,
        enable_avx512: Optional[bool] = None,
    ):
        self.arch = arch.lower()
        self.target_os = target_os
        self.x64 = X64CodeGenerator(target_os=target_os, enable_avx512=enable_avx512)
        self.arm64 = Arm64CodeGenerator()
        self._riscv64 = None

    def compile_ssa(self, fn: SSAFunction) -> CompiledFunctionArtifact:
        if self.arch in ("arm64", "aarch64"):
            return self.arm64.compile_function(fn)
        if self.arch in ("riscv64", "rv64", "riscv"):
            if self._riscv64 is None:
                from compiler.riscv64_codegen import Riscv64CodeGenerator
                self._riscv64 = Riscv64CodeGenerator(target_os=self.target_os or "linux")
            return self._riscv64.compile_function(fn)
        return self.x64.compile_function(fn)
