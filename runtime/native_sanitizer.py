"""
Alpha-C99: Freestanding Native Sanitizer Trap Runtime (`runtime/native_sanitizer.py`).

Provides zero-dependency hardware-enforced machine code traps (`__omni_sanitizer_trap`)
for x86-64 (`ud2; ret`) and ARM64 (`brk #1; ret`) emitted directly into native PE64 / ELF64 / Mach-O
binaries when ASan (`bounds` / `null`) or UBSan (`div-by-zero` / `shift` / `overflow`) checks trip.
"""

from __future__ import annotations

import struct
from typing import Dict

SANITIZER_KIND_DIV_ZERO = 1
SANITIZER_KIND_UB_SHIFT = 2
SANITIZER_KIND_STACK_OOB = 3
SANITIZER_KIND_HEAP_OOB = 4
SANITIZER_KIND_NULL_DEREF = 5
SANITIZER_KIND_SIGNED_OVERFLOW = 6

SANITIZER_KIND_NAMES: Dict[int, str] = {
    SANITIZER_KIND_DIV_ZERO: "UBSAN_INTEGER_DIVIDE_BY_ZERO",
    SANITIZER_KIND_UB_SHIFT: "UBSAN_SHIFT_OUT_OF_BOUNDS",
    SANITIZER_KIND_STACK_OOB: "ASAN_STACK_BUFFER_OVERFLOW",
    SANITIZER_KIND_HEAP_OOB: "ASAN_HEAP_BUFFER_OVERFLOW",
    SANITIZER_KIND_NULL_DEREF: "ASAN_NULL_POINTER_DEREFERENCE",
    SANITIZER_KIND_SIGNED_OVERFLOW: "UBSAN_SIGNED_INTEGER_OVERFLOW",
}

NATIVE_SANITIZER_SYMBOL_NAMES = frozenset({"__omni_sanitizer_trap"})


def get_sanitizer_kernels(target_os: str = "linux", arch: str = "x86_64") -> Dict[str, bytes]:
    """
    Returns freestanding machine-code implementations of `__omni_sanitizer_trap(kind, line, val)`.
    Executes an immediate deterministic hardware trap (`ud2` on x86-64 -> SIGILL / 0xC000001D,
    `brk #1` on ARM64 -> SIGTRAP) followed by `ret` so assembly termination invariants hold.
    """
    if arch.lower() in ("arm64", "aarch64"):
        # brk #1 ; ret
        trap_arm64 = struct.pack("<II", 0xD4200020, 0xD65F03C0)
        return {"__omni_sanitizer_trap": trap_arm64}
    # x86-64: ud2 (0F 0B) ; ret (C3)
    return {"__omni_sanitizer_trap": b"\x0f\x0b\xc3"}
