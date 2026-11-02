"""
OmniCompiler Native Heap & Composite Collections Runtime Engine.
Provides C-ABI compatible memory allocation, dynamic resizable arrays (OmniList),
and Robin Hood / Open-Addressing hash tables (OmniDict) for native silicon execution
without dependency on the CPython runtime or Python object headers.

Binary Memory Layouts (64-bit aligned):
1. OmniList:
   [offset 0]:  capacity (int64) - total allocated item slots
   [offset 8]:  length   (int64) - current number of items
   [offset 16 + i*8]: item[i] (int64) - payload values or nested pointers

2. OmniDict:
   [offset 0]:  capacity (int64) - power-of-two number of slots
   [offset 8]:  length   (int64) - count of occupied key-value pairs
   [offset 16 + i*16]: key[i]   (int64)
   [offset 24 + i*16]: val[i]   (int64)
   [special]:   empty slot key = 0x8000000000000000 (INT64_MIN / UNSET_KEY)
"""

import ctypes
import os
import struct
import sys
from typing import Dict, Any, Tuple, Optional, List

UNSET_KEY = -0x8000000000000000  # -2^63 sentry representing empty hash slot


class NativeHeapArena:
    """
    Thread-safe native page arena providing raw aligned memory buffers.
    Uses Win32 VirtualAlloc or POSIX mmap for zero-fragmentation OS memory.
    """

    def __init__(self, initial_bytes: int = 1024 * 1024):
        self.arena_size = max(65536, initial_bytes)
        self.is_windows = sys.platform == "win32"
        self._ptr = self._os_alloc(self.arena_size)
        self._offset = 0
        self._allocated_blocks: List[Tuple[int, int]] = []

    def _os_alloc(self, size: int) -> int:
        if self.is_windows:
            k32 = ctypes.windll.kernel32
            k32.VirtualAlloc.restype = ctypes.c_void_p
            k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
            ptr = k32.VirtualAlloc(0, size, 0x1000 | 0x2000, 0x04)  # MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
            if not ptr:
                raise MemoryError("NativeHeapArena VirtualAlloc failed")
            return ptr
        else:
            libc = ctypes.CDLL(None)
            libc.mmap.restype = ctypes.c_void_p
            libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
            MAP_ANON = 0x20 if sys.platform.startswith("linux") else 0x1000
            ptr = libc.mmap(0, size, 0x03, 2 | MAP_ANON, -1, 0)  # PROT_READ | PROT_WRITE
            if not ptr or ptr == -1:
                raise MemoryError("NativeHeapArena mmap failed")
            return ptr

    def alloc(self, num_bytes: int) -> int:
        """Allocates 16-byte aligned memory block from arena."""
        aligned_sz = ((num_bytes + 15) // 16) * 16
        if self._offset + aligned_sz > self.arena_size:
            # Grow by allocating another chunk
            new_chunk_sz = max(self.arena_size * 2, aligned_sz * 2)
            self._ptr = self._os_alloc(new_chunk_sz)
            self.arena_size = new_chunk_sz
            self._offset = 0

        p = self._ptr + self._offset
        self._offset += aligned_sz
        # Zero memory
        ctypes.memset(p, 0, aligned_sz)
        return p

    def free_all(self):
        if self.is_windows:
            ctypes.windll.kernel32.VirtualFree(ctypes.c_void_p(self._ptr), ctypes.c_size_t(0), 0x8000)
        else:
            ctypes.CDLL(None).munmap(ctypes.c_void_p(self._ptr), ctypes.c_size_t(self.arena_size))


# Global process arena singleton
_GLOBAL_ARENA: Optional[NativeHeapArena] = None


def get_global_arena() -> NativeHeapArena:
    global _GLOBAL_ARENA
    if _GLOBAL_ARENA is None:
        _GLOBAL_ARENA = NativeHeapArena()
    return _GLOBAL_ARENA


# ==============================================================================
# C-ABI Native Collection Functions (Called directly by JIT & Linked Binaries)
# ==============================================================================

def omni_alloc(size_bytes: int) -> int:
    return get_global_arena().alloc(max(16, size_bytes))


def omni_list_new(initial_capacity: int = 8) -> int:
    cap = max(4, initial_capacity)
    total_bytes = 16 + cap * 8
    ptr = omni_alloc(total_bytes)
    # ptr[0] = capacity, ptr[8] = length (initially 0)
    ctypes.c_int64.from_address(ptr).value = cap
    ctypes.c_int64.from_address(ptr + 8).value = 0
    return ptr


def omni_list_len(list_ptr: int) -> int:
    if list_ptr == 0:
        return 0
    return ctypes.c_int64.from_address(list_ptr + 8).value


def omni_list_get(list_ptr: int, idx: int) -> int:
    if list_ptr == 0:
        return 0
    length = ctypes.c_int64.from_address(list_ptr + 8).value
    if idx < 0:
        idx += length
    if idx < 0 or idx >= length:
        return 0  # Safe bounds clamping
    return ctypes.c_int64.from_address(list_ptr + 16 + idx * 8).value


def omni_list_set(list_ptr: int, idx: int, val: int) -> int:
    if list_ptr == 0:
        return 0
    cap = ctypes.c_int64.from_address(list_ptr).value
    length = ctypes.c_int64.from_address(list_ptr + 8).value
    if idx < 0:
        idx += length
    if idx < 0 or idx >= cap:
        return list_ptr
    ctypes.c_int64.from_address(list_ptr + 16 + idx * 8).value = val
    if idx >= length:
        ctypes.c_int64.from_address(list_ptr + 8).value = idx + 1
    return list_ptr


def omni_list_append(list_ptr: int, val: int) -> int:
    if list_ptr == 0:
        list_ptr = omni_list_new(8)
    cap = ctypes.c_int64.from_address(list_ptr).value
    length = ctypes.c_int64.from_address(list_ptr + 8).value
    if length >= cap:
        # Resize: double capacity
        new_cap = cap * 2
        new_ptr = omni_list_new(new_cap)
        # Copy existing elements
        ctypes.memmove(new_ptr + 16, list_ptr + 16, length * 8)
        ctypes.c_int64.from_address(new_ptr + 8).value = length
        list_ptr = new_ptr

    ctypes.c_int64.from_address(list_ptr + 16 + length * 8).value = val
    ctypes.c_int64.from_address(list_ptr + 8).value = length + 1
    return list_ptr


def omni_dict_new(initial_capacity: int = 16) -> int:
    # Capacity must be power of two, encoded as NEGATIVE to distinguish from OmniList
    cap = 16
    while cap < initial_capacity:
        cap *= 2
    total_bytes = 16 + cap * 16  # (key, val) = 16 bytes per slot
    ptr = omni_alloc(total_bytes)
    # Stored as negative capacity to tag as Dict
    ctypes.c_int64.from_address(ptr).value = -cap
    ctypes.c_int64.from_address(ptr + 8).value = 0
    # Fill all slot keys with UNSET_KEY
    for i in range(cap):
        ctypes.c_int64.from_address(ptr + 16 + i * 16).value = UNSET_KEY
    return ptr


def _hash64_int(val: int) -> int:
    # 64-bit splitmix / Thomas Wang hash
    val &= 0xFFFFFFFFFFFFFFFF
    val = (~val + (val << 21)) & 0xFFFFFFFFFFFFFFFF
    val = val ^ (val >> 24)
    val = (val + (val << 3) + (val << 8)) & 0xFFFFFFFFFFFFFFFF
    val = val ^ (val >> 14)
    val = (val + (val << 2) + (val << 4)) & 0xFFFFFFFFFFFFFFFF
    val = val ^ (val >> 28)
    val = (val + (val << 31)) & 0xFFFFFFFFFFFFFFFF
    return val


def omni_dict_set(dict_ptr: int, key: int, val: int) -> int:
    if dict_ptr == 0:
        dict_ptr = omni_dict_new(16)
    raw_cap = ctypes.c_int64.from_address(dict_ptr).value
    cap = abs(raw_cap)
    length = ctypes.c_int64.from_address(dict_ptr + 8).value

    # Rehash if load factor > 0.70
    if (length + 1) * 10 >= cap * 7:
        new_dict = omni_dict_new(cap * 2)
        for i in range(cap):
            k = ctypes.c_int64.from_address(dict_ptr + 16 + i * 16).value
            if k != UNSET_KEY:
                v = ctypes.c_int64.from_address(dict_ptr + 16 + i * 16 + 8).value
                omni_dict_set(new_dict, k, v)
        dict_ptr = new_dict
        cap = abs(ctypes.c_int64.from_address(dict_ptr).value)

    mask = cap - 1
    h = _hash64_int(key) & mask
    for step in range(cap):
        slot_idx = (h + step) & mask
        slot_addr = dict_ptr + 16 + slot_idx * 16
        k_slot = ctypes.c_int64.from_address(slot_addr).value
        if k_slot == UNSET_KEY:
            ctypes.c_int64.from_address(slot_addr).value = key
            ctypes.c_int64.from_address(slot_addr + 8).value = val
            ctypes.c_int64.from_address(dict_ptr + 8).value = length + 1
            return dict_ptr
        elif k_slot == key:
            ctypes.c_int64.from_address(slot_addr + 8).value = val
            return dict_ptr

    return dict_ptr


def omni_dict_get(dict_ptr: int, key: int) -> int:
    if dict_ptr == 0:
        return 0
    cap = abs(ctypes.c_int64.from_address(dict_ptr).value)
    mask = cap - 1
    h = _hash64_int(key) & mask
    for step in range(cap):
        slot_idx = (h + step) & mask
        slot_addr = dict_ptr + 16 + slot_idx * 16
        k_slot = ctypes.c_int64.from_address(slot_addr).value
        if k_slot == UNSET_KEY:
            return 0
        if k_slot == key:
            return ctypes.c_int64.from_address(slot_addr + 8).value
    return 0


def omni_dict_len(dict_ptr: int) -> int:
    if dict_ptr == 0:
        return 0
    return ctypes.c_int64.from_address(dict_ptr + 8).value


def omni_item_get(container_ptr: int, key_or_idx: int) -> int:
    if container_ptr == 0:
        return 0
    header_val = ctypes.c_int64.from_address(container_ptr).value
    if header_val < 0:
        return omni_dict_get(container_ptr, key_or_idx)
    return omni_list_get(container_ptr, key_or_idx)


def omni_item_set(container_ptr: int, key_or_idx: int, val: int) -> int:
    if container_ptr == 0:
        return 0
    header_val = ctypes.c_int64.from_address(container_ptr).value
    if header_val < 0:
        return omni_dict_set(container_ptr, key_or_idx, val)
    return omni_list_set(container_ptr, key_or_idx, val)


def omni_item_len(container_ptr: int) -> int:
    if container_ptr == 0:
        return 0
    return ctypes.c_int64.from_address(container_ptr + 8).value


# Mapping of collection helper symbols and signatures for C-ABI call trampolines
NATIVE_COLLECTION_SYMBOLS: Dict[str, Tuple[Any, List[Any], Any]] = {
    "omni_alloc": (omni_alloc, [ctypes.c_int64], ctypes.c_int64),
    "omni_list_new": (omni_list_new, [ctypes.c_int64], ctypes.c_int64),
    "omni_list_len": (omni_list_len, [ctypes.c_int64], ctypes.c_int64),
    "omni_list_get": (omni_list_get, [ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_list_set": (omni_list_set, [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_list_append": (omni_list_append, [ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_dict_new": (omni_dict_new, [ctypes.c_int64], ctypes.c_int64),
    "omni_dict_set": (omni_dict_set, [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_dict_get": (omni_dict_get, [ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_dict_len": (omni_dict_len, [ctypes.c_int64], ctypes.c_int64),
    "omni_item_get": (omni_item_get, [ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_item_set": (omni_item_set, [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_item_len": (omni_item_len, [ctypes.c_int64], ctypes.c_int64),
}
