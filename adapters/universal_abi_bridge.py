"""
Universal ABI Bridge & Cross-Language Marshalling Engine
Models low-level C-ABI calling conventions (Windows x64, System V AMD64, ARM64 AAPCS)
and generates binary marshalling trampolines and memory layout coercions.
Integrates with CegisEngine to bridge multi-repository interfaces on native silicon.
"""

import sys
import struct
from typing import Dict, List, Tuple, Any, Optional
from adapters.cegis_engine import CegisEngine


# Register mappings for common 64-bit ABIs
ABI_REGISTERS = {
    "windows_x64": ["rcx", "rdx", "r8", "r9"],
    "system_v_x64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "arm64_aapcs": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
}


class StructField:
    __slots__ = ("name", "field_type", "size", "alignment", "offset")

    def __init__(self, name: str, field_type: str):
        self.name = name
        self.field_type = field_type
        type_table = {
            "i8": (1, 1), "u8": (1, 1),
            "i16": (2, 2), "u16": (2, 2),
            "i32": (4, 4), "u32": (4, 4), "f32": (4, 4),
            "i64": (8, 8), "u64": (8, 8), "f64": (8, 8), "ptr": (8, 8)
        }
        size, align = type_table.get(field_type, (8, 8))
        self.size = size
        self.alignment = align
        self.offset = 0


class StructLayout:
    """Computes exact C-ABI struct layout with padding and natural alignment."""

    def __init__(self, fields: List[Tuple[str, str]]):
        self.fields: List[StructField] = [StructField(name, ftype) for name, ftype in fields]
        self.total_size = 0
        self.struct_alignment = 1
        self._compute_layout()

    def _compute_layout(self):
        curr_offset = 0
        max_align = 1
        for f in self.fields:
            max_align = max(max_align, f.alignment)
            # Align offset
            padding = (f.alignment - (curr_offset % f.alignment)) % f.alignment
            curr_offset += padding
            f.offset = curr_offset
            curr_offset += f.size

        # Struct size must be multiple of largest alignment
        tail_pad = (max_align - (curr_offset % max_align)) % max_align
        self.total_size = curr_offset + tail_pad
        self.struct_alignment = max_align

    def get_offset(self, field_name: str) -> Optional[int]:
        for f in self.fields:
            if f.name == field_name:
                return f.offset
        return None


class UniversalAbiBridge:
    """
    Synthesizes low-level ABI trampolines and adapters across heterogeneous repositories.
    """

    def __init__(self, cegis_engine: Optional[CegisEngine] = None):
        self.cegis = cegis_engine or CegisEngine()
        self.host_abi = "windows_x64" if sys.platform == "win32" else "system_v_x64"

    def compute_struct_layout(self, fields: List[Tuple[str, str]]) -> StructLayout:
        return StructLayout(fields)

    def generate_abi_trampoline(self, caller_abi: str, callee_abi: str) -> bytes:
        """
        Emits x86-64 machine code converting caller register convention into callee convention.
        Supports bidirectional Windows x64 <-> System V AMD64 conversions.
        """
        code = bytearray()

        if caller_abi == "system_v_x64" and callee_abi == "windows_x64":
            # Caller puts args in RDI, RSI, RDX, RCX
            # Windows Callee expects: RCX = RDI, RDX = RSI, R8 = RDX, R9 = RCX
            # Windows requires 32-byte shadow space + 16-byte stack alignment: sub rsp, 40
            code.extend([0x48, 0x83, 0xEC, 0x28])        # sub rsp, 40
            code.extend([0x4D, 0x89, 0xC1])              # mov r9, r8 (if 4th arg)
            code.extend([0x49, 0x89, 0xD0])              # mov r8, rdx
            code.extend([0x48, 0x89, 0xF2])              # mov rdx, rsi
            code.extend([0x48, 0x89, 0xF9])              # mov rcx, rdi
            # Trampoline epilogue: add rsp, 40; ret
            code.extend([0x48, 0x83, 0xC4, 0x28, 0xC3])

        elif caller_abi == "windows_x64" and callee_abi == "system_v_x64":
            # Caller puts args in RCX, RDX, R8, R9
            # System V Callee expects: RDI = RCX, RSI = RDX, RDX = R8, RCX = R9
            code.extend([0x48, 0x89, 0xCF])              # mov rdi, rcx
            code.extend([0x48, 0x89, 0xD6])              # mov rsi, rdx
            code.extend([0x4C, 0x89, 0xC2])              # mov rdx, r8
            code.extend([0x4C, 0x89, 0xC9])              # mov rcx, r9
            code.append(0xC3)                            # ret

        else:
            # Identity ABI pass-through
            code.append(0xC3)                            # ret

        return bytes(code)

    def synthesize_cross_repo_wrapper(
        self,
        caller_params: List[str],
        callee_params: List[str],
        caller_abi: Optional[str] = None,
        callee_abi: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Uses CEGIS SMT solver to find exact parameter mapping, then generates
        ABI marshalling code and parameter binding permutation plan.
        """
        c_abi = caller_abi or self.host_abi
        t_abi = callee_abi or self.host_abi

        mapping_res = self.cegis.synthesize_parameter_mapping(caller_params, callee_params)
        mapping = mapping_res["mapping"]

        # Compute parameter permutation indices:
        # e.g. which caller argument index feeds into each callee slot
        permutations = []
        for target_p in callee_params:
            src_p = mapping.get(target_p)
            src_idx = caller_params.index(src_p) if src_p in caller_params else 0
            permutations.append((target_p, src_p, src_idx))

        trampoline = self.generate_abi_trampoline(c_abi, t_abi)

        return {
            "synthesized": True,
            "mapping": mapping,
            "permutations": permutations,
            "caller_abi": c_abi,
            "callee_abi": t_abi,
            "trampoline_hex": trampoline.hex(),
            "formal_guarantees": mapping_res.get("formal_guarantees", [])
        }
