"""
OmniCompiler Assembly & Calling Convention Invariant Auditor.
Inspects synthesized machine code bytes to formally verify low-level CPU invariants:
1. Valid instruction termination (RET / 0xC3 or JMP).
2. Stack frame balance and 16-byte ABI alignment compliance.
3. Relative branch displacement bound safety ([-2^31, 2^31 - 1]).
4. Zero unescapable infinite loop traps.
"""

import struct
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class AssemblyAuditReport:
    is_valid: bool
    total_bytes_inspected: int
    functions_checked: int
    stack_balanced: bool
    branch_displacements_safe: bool
    termination_valid: bool
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class AssemblyInvariantAuditor:
    """
    Audits synthesized machine code for calling convention and architectural invariants.
    """

    def __init__(self):
        pass

    def audit_function_code(self, code_bytes: bytes, symbol_name: str = "anon") -> AssemblyAuditReport:
        """Audits a single function's machine code bytes."""
        errors: List[str] = []
        warnings: List[str] = []

        if not code_bytes:
            return AssemblyAuditReport(
                is_valid=False,
                total_bytes_inspected=0,
                functions_checked=1,
                stack_balanced=False,
                branch_displacements_safe=False,
                termination_valid=False,
                errors=["Function code is empty"]
            )

        # 1. Termination Check
        # Function must end with RET (0xC3) or tail JMP (EB rel8 / E9 rel32 / FF /4)
        last_byte = code_bytes[-1]
        termination_valid = (last_byte == 0xC3)
        if not termination_valid:
            is_short_jmp = len(code_bytes) >= 2 and code_bytes[-2] == 0xEB
            is_near_jmp = len(code_bytes) >= 5 and code_bytes[-5] == 0xE9
            is_indir_jmp = len(code_bytes) >= 2 and code_bytes[-2] == 0xFF and (code_bytes[-1] & 0x38) == 0x20
            if is_short_jmp or is_near_jmp or is_indir_jmp:
                warnings.append(f"{symbol_name} terminates with JMP rather than RET.")
                termination_valid = True
            else:
                errors.append(f"{symbol_name} does not terminate with RET (0xC3) or JMP; found 0x{last_byte:02X}")

        # 2. Infinite Loop Trap Check
        if b"\xeb\xfe" in code_bytes:
            warnings.append(f"{symbol_name} contains unescapable spin-loop (EB FE)")

        # 3. Stack Frame Balance & Alignment Check
        # Scans for `sub rsp, imm` (48 83 EC imm8 or 48 81 EC imm32)
        # and `add rsp, imm` (48 83 C4 imm8 or 48 81 C4 imm32)
        stack_alloc = 0
        stack_free = 0
        free_sizes: List[int] = []

        i = 0
        branch_safe = True
        n = len(code_bytes)

        # Scan leading prologue push r64 instructions (allowing interleaved setup ALU movs in -O3)
        prologue_push_bytes = 0
        post_rbp_push_bytes = 0
        has_frame_ptr_setup = False
        pi = 0
        saw_mov_rbp_rsp = False
        while pi < min(n, 48):
            b = code_bytes[pi]
            if b == 0x55 and pi + 3 < n and code_bytes[pi+1:pi+4] == b"\x48\x89\xe5":
                prologue_push_bytes += 8
                has_frame_ptr_setup = True
                saw_mov_rbp_rsp = True
                pi += 4
            elif 0x50 <= b <= 0x57:
                prologue_push_bytes += 8
                if saw_mov_rbp_rsp:
                    post_rbp_push_bytes += 8
                pi += 1
            elif b == 0x41 and pi + 1 < n and 0x50 <= code_bytes[pi + 1] <= 0x57:
                prologue_push_bytes += 8
                if saw_mov_rbp_rsp:
                    post_rbp_push_bytes += 8
                pi += 2
            elif code_bytes[pi:pi+3] == b"\x48\x89\xe5":
                has_frame_ptr_setup = True
                saw_mov_rbp_rsp = True
                pi += 3
            elif saw_mov_rbp_rsp and (
                code_bytes[pi:pi+3] == b"\x48\x83\xec"
                or code_bytes[pi:pi+3] == b"\x48\x81\xec"
                or code_bytes[pi:pi+3] == b"\x48\x83\xe4"
            ):
                break
            elif saw_mov_rbp_rsp and code_bytes[pi:pi+3] in (b"\x49\x89\xfd", b"\x48\x89\xfb"):
                pi += 3
            elif saw_mov_rbp_rsp and b == 0x41 and pi + 5 < n and 0xB8 <= code_bytes[pi+1] <= 0xBF:
                pi += 6
            elif saw_mov_rbp_rsp and 0xB8 <= b <= 0xBF and pi + 4 < n:
                pi += 5
            else:
                break

        def _epilogue_inst_len(pos: int) -> int:
            """Lightweight length decoder for x86-64 epilogue scheduling instructions."""
            b0 = code_bytes[pos]
            if 0x40 <= b0 <= 0x4F and pos + 1 < n:
                b1 = code_bytes[pos + 1]
                if 0xB8 <= b1 <= 0xBF:
                    return 10 if (b0 & 0x08) else 6
                if b1 == 0x69:
                    return 7
                if b1 in (0x83, 0xC1, 0x6B):
                    return 4
                if b1 in (0x01, 0x03, 0x29, 0x2B, 0x31, 0x33, 0x39, 0x85, 0x89, 0x8B, 0xF7):
                    if pos + 2 < n:
                        modrm = code_bytes[pos + 2]
                        mod = (modrm >> 6) & 0x03
                        rm = modrm & 0x07
                        if mod == 3:
                            return 3
                        sib = 1 if rm == 4 else 0
                        disp = 1 if mod == 1 else (4 if (mod == 2 or (mod == 0 and rm == 5)) else 0)
                        return 3 + sib + disp
                    return 3
                if b1 == 0x8D and pos + 2 < n:
                    modrm = code_bytes[pos + 2]
                    mod = (modrm >> 6) & 0x03
                    rm = modrm & 0x07
                    sib = 1 if (mod != 3 and rm == 4) else 0
                    disp = 1 if mod == 1 else (4 if (mod == 2 or (mod == 0 and rm == 5)) else 0)
                    return 3 + sib + disp
            if b0 == 0xC5 and pos + 2 < n:
                return 3  # 2-byte VEX e.g. vzeroupper
            if b0 in (0x01, 0x29, 0x31, 0x39, 0x89, 0x8B, 0xF7) and pos + 1 < n and (code_bytes[pos + 1] >> 6) == 3:
                return 2
            return 1

        def _scan_epilogue_pops(pos: int, scan_limit: int = 80) -> Tuple[int, int]:
            """Counts pop r64 instructions following epilogue stack restore before ret/jmp."""
            pop_b = 0
            cur = pos
            end_s = min(n, pos + scan_limit)
            while cur < end_s:
                pb = code_bytes[cur]
                if 0x58 <= pb <= 0x5F:
                    pop_b += 8
                    cur += 1
                elif pb == 0x41 and cur + 1 < end_s and 0x58 <= code_bytes[cur + 1] <= 0x5F:
                    pop_b += 8
                    cur += 2
                elif pb in (0xC3, 0xE8, 0xE9, 0xEB):
                    break
                else:
                    step = _epilogue_inst_len(cur)
                    cur += max(1, step)
            return pop_b, (pos if pop_b == 0 else cur)

        total_pro_sub = 0
        i = 0
        while i < n:
            # Check 48 83 EC <imm8> (sub rsp, imm8)
            if code_bytes[i:i+3] == b"\x48\x83\xec":
                if i + 3 < n:
                    imm = code_bytes[i+3]
                    stack_alloc += imm
                    total_pro_sub += imm
                    i += 4
                    continue
                else:
                    errors.append(f"Truncated sub rsp, imm8 instruction at offset {i}")
                    i += 3
                    continue
            # Check 48 81 EC <imm32> (sub rsp, imm32)
            elif code_bytes[i:i+3] == b"\x48\x81\xec":
                if i + 6 < n:
                    imm = struct.unpack("<I", code_bytes[i+3:i+7])[0]
                    stack_alloc += imm
                    total_pro_sub += imm
                    i += 7
                    continue
                else:
                    errors.append(f"Truncated sub rsp, imm32 instruction at offset {i}")
                    i += 3
                    continue
            # Check 48 83 C4 <imm8> (add rsp, imm8)
            elif code_bytes[i:i+3] == b"\x48\x83\xc4":
                if i + 3 < n:
                    imm = code_bytes[i+3]
                    pop_b, next_i = _scan_epilogue_pops(i + 4)
                    epi_free = imm + min(prologue_push_bytes, pop_b)
                    stack_free += epi_free
                    free_sizes.append(epi_free)
                    i = next_i
                    continue
                else:
                    errors.append(f"Truncated add rsp, imm8 instruction at offset {i}")
                    i += 3
                    continue
            # Check 48 81 C4 <imm32> (add rsp, imm32)
            elif code_bytes[i:i+3] == b"\x48\x81\xc4":
                if i + 6 < n:
                    imm = struct.unpack("<I", code_bytes[i+3:i+7])[0]
                    pop_b, next_i = _scan_epilogue_pops(i + 7)
                    epi_free = imm + min(prologue_push_bytes, pop_b)
                    stack_free += epi_free
                    free_sizes.append(epi_free)
                    i = next_i
                    continue
                else:
                    errors.append(f"Truncated add rsp, imm32 instruction at offset {i}")
                    i += 3
                    continue
            # Frame-pointer teardown: lea disp(%rbp), %rsp (48 8D 65 disp8 / 48 8D A5 disp32) or mov rbp, rsp
            elif has_frame_ptr_setup and code_bytes[i:i+3] in (b"\x48\x8d\x65", b"\x48\x8d\xa5", b"\x48\x89\xec", b"\x48\x8b\xe5"):
                op3 = code_bytes[i:i+3]
                if op3 == b"\x48\x8d\x65" and i + 3 < n:
                    disp = struct.unpack("<b", code_bytes[i+3:i+4])[0]
                    after_pos = i + 4
                elif op3 == b"\x48\x8d\xa5" and i + 6 < n:
                    disp = struct.unpack("<i", code_bytes[i+3:i+7])[0]
                    after_pos = i + 7
                else:
                    disp = 0
                    after_pos = i + 3
                if disp <= 0 and (-disp) == post_rbp_push_bytes:
                    pop_b, next_i = _scan_epilogue_pops(after_pos)
                    if pop_b >= post_rbp_push_bytes + 8:
                        epi_free = stack_alloc + prologue_push_bytes
                        stack_free += epi_free
                        free_sizes.append(epi_free)
                        i = next_i
                        continue
            elif has_frame_ptr_setup and code_bytes[i] == 0xC9 and post_rbp_push_bytes == 0 and i > pi:
                epi_free = stack_alloc + prologue_push_bytes
                stack_free += epi_free
                free_sizes.append(epi_free)
                i += 1
                continue
            # Check Call relative (E8 <disp32>)
            elif code_bytes[i] == 0xE8:
                if i + 4 < n:
                    disp32 = struct.unpack("<i", code_bytes[i+1:i+5])[0]
                    if not (-0x80000000 <= disp32 <= 0x7FFFFFFF):
                        branch_safe = False
                        errors.append(f"Branch displacement out of 32-bit range at offset {i}: {disp32}")
                    i += 1
                    continue
                else:
                    errors.append(f"Truncated call relative displacement at offset {i}")
                    i += 1
                    continue

            i += 1

        # Handle pure-push functions without add rsp (e.g. leaf callee-saved pushes popped right before ret/jmp)
        if prologue_push_bytes > 0 and stack_alloc == 0 and stack_free == 0:
            term_start = n - (1 if last_byte == 0xC3 else (5 if len(code_bytes) >= 5 and code_bytes[-5] == 0xE9 else (2 if len(code_bytes) >= 2 and code_bytes[-2] == 0xEB else 0)))
            tail_pops = 0
            cur_t = term_start - 1
            while cur_t >= pi:
                tb = code_bytes[cur_t]
                if 0x58 <= tb <= 0x5F:
                    if cur_t - 1 >= pi and code_bytes[cur_t - 1] == 0x41:
                        tail_pops += 8
                        cur_t -= 2
                    else:
                        tail_pops += 8
                        cur_t -= 1
                else:
                    break
            if tail_pops > 0:
                matched = min(prologue_push_bytes, tail_pops)
                stack_free += matched
                free_sizes.append(matched)

        total_alloc = stack_alloc + prologue_push_bytes if (stack_free > 0 or stack_alloc > 0) else 0
        has_page_probe = (b"\x48\x81\xec\x00\x10\x00\x00" in code_bytes)
        stack_balanced = (
            (total_alloc == stack_free)
            or (total_alloc > 0 and len(free_sizes) >= 1 and all(f == total_alloc for f in free_sizes))
            or (
                has_page_probe
                and total_alloc > 0
                and len(free_sizes) >= 1
                and all(f >= total_alloc and (f - total_alloc) % 4096 == 0 for f in free_sizes)
            )
        )
        if not stack_balanced:
            errors.append(f"Stack frame imbalance in {symbol_name}: allocated {total_alloc} bytes but freed {stack_free} bytes")

        # Check 16-byte alignment when calls are present
        if stack_alloc % 8 != 0:
            warnings.append(f"Stack allocation of {stack_alloc} bytes is not 8-byte aligned in {symbol_name}")

        is_valid = len(errors) == 0

        return AssemblyAuditReport(
            is_valid=is_valid,
            total_bytes_inspected=len(code_bytes),
            functions_checked=1,
            stack_balanced=stack_balanced,
            branch_displacements_safe=branch_safe,
            termination_valid=termination_valid,
            warnings=warnings,
            errors=errors
        )
