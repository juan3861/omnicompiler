"""
Freestanding Hardware Atomics & Multi-Thread Synchronization Kernels (x86-64 & ARM64).
Provides zero-dependency machine-code primitives (`LOCK XADD`, `LOCK CMPXCHG`,
`PAUSE` spinlocks on x86-64; LL/SC `LDAXR`/`STLXR` on ARM64) for compiled binaries.
"""

from typing import Dict
import struct

NATIVE_ATOMIC_KERNELS_WIN64: Dict[str, bytes] = {
    # int64_t omni_atomic_add_i64(int64_t* ptr [rcx], int64_t delta [rdx]) -> old_val [rax]
    "omni_atomic_add_i64": bytes.fromhex("4889d0f0480fc101c3"),
    # int64_t omni_atomic_cas_i64(int64_t* ptr [rcx], int64_t expected [rdx], int64_t desired [r8]) -> old_val [rax]
    "omni_atomic_cas_i64": bytes.fromhex("4889d0f04c0fb101c3"),
    # int64_t omni_spinlock_acquire(int64_t* lock_ptr [rcx]) -> 0
    "omni_spinlock_acquire": bytes.fromhex("31c0ba01000000f0480fb1117404f390ebee31c0c3"),
    # int64_t omni_spinlock_release(int64_t* lock_ptr [rcx]) -> 0
    "omni_spinlock_release": bytes.fromhex("48c7010000000031c0c3"),
}

NATIVE_ATOMIC_KERNELS_SYSV: Dict[str, bytes] = {
    # int64_t omni_atomic_add_i64(int64_t* ptr [rdi], int64_t delta [rsi]) -> old_val [rax]
    "omni_atomic_add_i64": bytes.fromhex("4889f0f0480fc107c3"),
    # int64_t omni_atomic_cas_i64(int64_t* ptr [rdi], int64_t expected [rsi], int64_t desired [rdx]) -> old_val [rax]
    "omni_atomic_cas_i64": bytes.fromhex("4889f0f0480fb117c3"),
    # int64_t omni_spinlock_acquire(int64_t* lock_ptr [rdi]) -> 0
    "omni_spinlock_acquire": bytes.fromhex("31c0ba01000000f0480fb1177404f390ebee31c0c3"),
    # int64_t omni_spinlock_release(int64_t* lock_ptr [rdi]) -> 0
    "omni_spinlock_release": bytes.fromhex("48c7070000000031c0c3"),
}

# ARM64 LL/SC freestanding atomic kernels (works on ARMv8.0+ without LSE requirement):
# omni_atomic_add_i64(x0=ptr, x1=delta):
#   loop: ldaxr x2, [x0]; add x3, x2, x1; stlxr w4, x3, [x0]; cbnz w4, loop; mov x0, x2; ret
NATIVE_ATOMIC_KERNELS_ARM64: Dict[str, bytes] = {
    "omni_atomic_add_i64": struct.pack(
        "<6I",
        0xC85FFC02,  # ldaxr x2, [x0]
        0x8B010043,  # add x3, x2, x1
        0xC804FC03,  # stlxr w4, x3, [x0]
        0x35FFFFA4,  # cbnz w4, -12
        0xAA0203E0,  # mov x0, x2
        0xD65F03C0,  # ret
    ),
    # omni_atomic_cas_i64(x0=ptr, x1=expected, x2=desired):
    #   loop: ldaxr x3, [x0]; cmp x3, x1; b.ne fail; stlxr w4, x2, [x0]; cbnz w4, loop
    #   fail: clrex; mov x0, x3; ret
    "omni_atomic_cas_i64": struct.pack(
        "<8I",
        0xC85FFC03,  # ldaxr x3, [x0]
        0xEB01007F,  # cmp x3, x1
        0x54000061,  # b.ne +12 (skip stlxr+cbnz -> fail)
        0xC804FC02,  # stlxr w4, x2, [x0]
        0x35FFFF84,  # cbnz w4, -16
        0xD5033F5F,  # clrex
        0xAA0303E0,  # mov x0, x3
        0xD65F03C0,  # ret
    ),
    # omni_spinlock_acquire(x0=lock_ptr):
    #   mov x1, #1; loop: ldaxr x2, [x0]; cbnz x2, wait; stlxr w3, x1, [x0]; cbnz w3, loop; mov x0, #0; ret
    #   wait: yield; b loop
    "omni_spinlock_acquire": struct.pack(
        "<9I",
        0xD2800021,  # mov x1, #1
        0xC85FFC02,  # ldaxr x2, [x0]
        0xB5000082,  # cbnz x2, +16 (wait)
        0xC803FC01,  # stlxr w3, x1, [x0]
        0x35FFFFA3,  # cbnz w3, -12
        0xD2800000,  # mov x0, #0
        0xD65F03C0,  # ret
        0xD503203F,  # yield
        0x17FFFFFA,  # b -24 (loop)
    ),
    # omni_spinlock_release(x0=lock_ptr):
    #   stlr xzr, [x0]; mov x0, #0; ret
    "omni_spinlock_release": struct.pack(
        "<3I",
        0xC89FFC1F,  # stlr xzr, [x0]
        0xD2800000,  # mov x0, #0
        0xD65F03C0,  # ret
    ),
}

NATIVE_ATOMIC_SYMBOL_NAMES = frozenset(NATIVE_ATOMIC_KERNELS_WIN64.keys())


def get_atomic_kernels(target_os: str = "windows", arch: str = "x86_64") -> Dict[str, bytes]:
    if arch.lower() in ("arm64", "aarch64"):
        return dict(NATIVE_ATOMIC_KERNELS_ARM64)
    if target_os.lower() == "windows":
        return dict(NATIVE_ATOMIC_KERNELS_WIN64)
    return dict(NATIVE_ATOMIC_KERNELS_SYSV)
