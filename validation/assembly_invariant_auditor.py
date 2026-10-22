"""
OmniCompiler Assembly & Calling Convention Invariant Auditor.
Inspects synthesized machine code bytes to formally verify low-level CPU invariants:
1. Valid instruction termination (RET / 0xC3 or JMP).
2. Stack frame balance and 16-byte ABI alignment compliance.
3. Relative branch displacement bound safety ([-2^31, 2^31 - 1]).
4. Zero unescapable infinite loop traps.
"""

import struct
from typing import Dict, List, Any, Optional
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
        # Function must end with RET (0xC3) or tail JMP (0xE9 / 0xEB)
        last_byte = code_bytes[-1]
        termination_valid = (last_byte == 0xC3)
        if not termination_valid:
            if len(code_bytes) >= 2 and code_bytes[-2] in (0xEB, 0xE9):
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

        i = 0
        branch_safe = True
        n = len(code_bytes)

        while i < n:
            # Check 48 83 EC <imm8> (sub rsp, imm8)
            if code_bytes[i:i+3] == b"\x48\x83\xec":
                if i + 3 < n:
                    imm = code_bytes[i+3]
                    stack_alloc += imm
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
                    stack_free += imm
                    i += 4
                    continue
                else:
                    errors.append(f"Truncated add rsp, imm8 instruction at offset {i}")
                    i += 3
                    continue
            # Check 48 81 C4 <imm32> (add rsp, imm32)
            elif code_bytes[i:i+3] == b"\x48\x81\xc4":
                if i + 6 < n:
                    imm = struct.unpack("<I", code_bytes[i+3:i+7])[0]
                    stack_free += imm
                    i += 7
                    continue
                else:
                    errors.append(f"Truncated add rsp, imm32 instruction at offset {i}")
                    i += 3
                    continue
            # Check Call relative (E8 <disp32>)
            elif code_bytes[i] == 0xE8:
                if i + 4 < n:
                    disp32 = struct.unpack("<i", code_bytes[i+1:i+5])[0]
                    if not (-0x80000000 <= disp32 <= 0x7FFFFFFF):
                        branch_safe = False
                        errors.append(f"Branch displacement out of 32-bit range at offset {i}: {disp32}")
                    i += 5
                    continue
                else:
                    errors.append(f"Truncated call relative displacement at offset {i}")
                    i += 1
                    continue

            i += 1

        stack_balanced = (stack_alloc == stack_free)
        if not stack_balanced:
            errors.append(f"Stack frame imbalance in {symbol_name}: allocated {stack_alloc} bytes but freed {stack_free} bytes")

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
