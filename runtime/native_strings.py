"""
OmniCompiler Native Strings & Zero-Copy Slicing Engine (native_strings.py).
Provides high-performance, C-ABI compliant string operations for compiled silicon execution
with Small String Optimization (SSO for strings <= 15 bytes inline in a 24-byte struct)
and zero-allocation string slice descriptors (OmniStringSlice), eliminating CPython dependencies.

Binary Memory Layouts (24 bytes, 64-bit aligned):
1. Small String Optimization (SSO Mode, length <= 15):
   [byte 0]:      length (0..15) | 0x00 (bit 7 = 0 indicates SSO)
   [bytes 1..15]: raw UTF-8 payload (up to 15 bytes)
   [bytes 16..23]: zero padding (8 bytes)
   -> 0 heap allocations, optimal cacheline L1 locality!

2. Large String (Heap Mode, length > 15):
   [byte 0]:      0x80 (bit 7 = 1 indicates Heap buffer)
   [bytes 1..7]:  reserved / padding
   [offset 8]:    length (int64)
   [offset 16]:   data_ptr (int64, raw pointer to heap buffer allocated via omni_alloc)

3. Zero-Copy String Slice Descriptor (OmniStringSlice, 24 bytes):
   [offset 0]:    base_data_ptr (int64, pointer to start of characters)
   [offset 8]:    slice_offset  (int64, starting index in base data)
   [offset 16]:   slice_length  (int64, length of the slice)
   -> Slicing s[a:b] executes in O(1) time with 0 byte copying!
"""

import ctypes
import os
import struct
import sys
from typing import Dict, Any, Tuple, List, Optional

from runtime.native_heap import omni_alloc, get_global_arena

SSO_MAX_LEN = 15
FLAG_HEAP = 0x80

# Magic tags for runtime type discrimination (int32)
OMNI_STR_SSO_TAG = 0x53545230    # 'STR0' at offset 20
OMNI_STR_HEAP_TAG = 0x53545231   # 'STR1' at offset 4
OMNI_STR_SLICE_TAG = 0x53545232  # 'STR2' at offset 24


class OmniStringStruct(ctypes.Structure):
    _fields_ = [
        ("raw_bytes", ctypes.c_uint8 * 24)
    ]


def omni_str_new_from_bytes(py_bytes: bytes) -> int:
    """Creates a new native OmniString struct in memory, using SSO if len <= 15, or Heap if > 15."""
    str_ptr = omni_alloc(24)
    length = len(py_bytes)

    if length <= SSO_MAX_LEN:
        # SSO Mode
        ctypes.memset(str_ptr, 0, 24)
        ctypes.c_uint8.from_address(str_ptr).value = length
        if length > 0:
            ctypes.memmove(str_ptr + 1, py_bytes, length)
        # Write magic SSO tag at offset 20
        ctypes.c_uint32.from_address(str_ptr + 20).value = OMNI_STR_SSO_TAG
    else:
        # Heap Mode
        ctypes.memset(str_ptr, 0, 24)
        ctypes.c_uint8.from_address(str_ptr).value = FLAG_HEAP
        # Write magic Heap tag at offset 4
        ctypes.c_uint32.from_address(str_ptr + 4).value = OMNI_STR_HEAP_TAG
        ctypes.c_int64.from_address(str_ptr + 8).value = length
        # Allocate buffer on native heap (aligned + 1 for null terminator)
        data_buf = omni_alloc(length + 8)
        ctypes.memmove(data_buf, py_bytes, length)
        ctypes.c_int64.from_address(str_ptr + 16).value = data_buf

    return str_ptr


def omni_str_new_from_cstr(cstr_ptr: int, length: int) -> int:
    """Creates a native string from raw C pointer and length."""
    if length <= 0 or cstr_ptr == 0:
        return omni_str_new_from_bytes(b"")
    raw = ctypes.string_at(cstr_ptr, length)
    return omni_str_new_from_bytes(raw)


def omni_str_len(str_ptr: int) -> int:
    """Returns the byte length of the string in O(1)."""
    if str_ptr == 0:
        return 0
    header_byte = ctypes.c_uint8.from_address(str_ptr).value
    if (header_byte & FLAG_HEAP) == 0:
        # SSO Mode: length is stored in header byte
        return header_byte & 0x7F
    else:
        # Heap Mode: length is stored at offset 8
        return ctypes.c_int64.from_address(str_ptr + 8).value


def omni_str_data_ptr(str_ptr: int) -> int:
    """Returns the raw pointer to the characters."""
    if str_ptr == 0:
        return 0
    header_byte = ctypes.c_uint8.from_address(str_ptr).value
    if (header_byte & FLAG_HEAP) == 0:
        # SSO Mode: data starts at byte 1
        return str_ptr + 1
    else:
        # Heap Mode: data pointer is at offset 16
        return ctypes.c_int64.from_address(str_ptr + 16).value


def omni_str_get_byte(str_ptr: int, idx: int) -> int:
    """Gets the byte value at index `idx` (bounds-checked)."""
    length = omni_str_len(str_ptr)
    if idx < 0:
        idx += length
    if idx < 0 or idx >= length:
        return 0
    data_p = omni_str_data_ptr(str_ptr)
    return ctypes.c_uint8.from_address(data_p + idx).value


def omni_str_concat(s1: int, s2: int) -> int:
    """Concatenates two strings into a new native string."""
    len1 = omni_str_len(s1)
    len2 = omni_str_len(s2)
    tot_len = len1 + len2
    if tot_len == 0:
        return omni_str_new_from_bytes(b"")

    p1 = omni_str_data_ptr(s1)
    p2 = omni_str_data_ptr(s2)

    buf = bytearray(tot_len)
    if len1 > 0 and p1 != 0:
        ctypes.memmove((ctypes.c_char * len1).from_buffer(buf), p1, len1)
    if len2 > 0 and p2 != 0:
        dst = ctypes.addressof((ctypes.c_char * tot_len).from_buffer(buf)) + len1
        ctypes.memmove(dst, p2, len2)

    return omni_str_new_from_bytes(bytes(buf))


def omni_str_slice(str_ptr: int, start: int, stop: int) -> int:
    """
    Creates an O(1) Zero-Copy OmniStringSlice descriptor:
    [offset 0]: base_data_ptr
    [offset 8]: slice_offset
    [offset 16]: slice_length
    """
    length = omni_str_len(str_ptr)
    if start < 0:
        start += length
    if stop < 0:
        stop += length
    start = max(0, min(start, length))
    stop = max(start, min(stop, length))
    slice_len = stop - start

    slice_ptr = omni_alloc(32)
    data_p = omni_str_data_ptr(str_ptr)
    ctypes.c_int64.from_address(slice_ptr).value = data_p
    ctypes.c_int64.from_address(slice_ptr + 8).value = start
    ctypes.c_int64.from_address(slice_ptr + 16).value = slice_len
    ctypes.c_uint32.from_address(slice_ptr + 24).value = OMNI_STR_SLICE_TAG
    return slice_ptr


def omni_str_slice_to_str(slice_ptr: int) -> int:
    """Converts a zero-copy slice descriptor to an owned OmniString."""
    if slice_ptr == 0:
        return omni_str_new_from_bytes(b"")
    base_p = ctypes.c_int64.from_address(slice_ptr).value
    start = ctypes.c_int64.from_address(slice_ptr + 8).value
    slen = ctypes.c_int64.from_address(slice_ptr + 16).value
    if slen <= 0 or base_p == 0:
        return omni_str_new_from_bytes(b"")
    raw = ctypes.string_at(base_p + start, slen)
    return omni_str_new_from_bytes(raw)


def omni_str_eq(s1: int, s2: int) -> int:
    """Returns 1 if strings are byte-for-byte identical, 0 otherwise."""
    if s1 == s2:
        return 1
    if s1 == 0 or s2 == 0:
        return 0
    len1 = omni_str_len(s1)
    len2 = omni_str_len(s2)
    if len1 != len2:
        return 0
    if len1 == 0:
        return 1
    p1 = omni_str_data_ptr(s1)
    p2 = omni_str_data_ptr(s2)
    # Check 64-bit words first
    words = len1 // 8
    rem = len1 % 8
    for w in range(words):
        w1 = ctypes.c_int64.from_address(p1 + w * 8).value
        w2 = ctypes.c_int64.from_address(p2 + w * 8).value
        if w1 != w2:
            return 0
    for b in range(rem):
        idx = words * 8 + b
        b1 = ctypes.c_uint8.from_address(p1 + idx).value
        b2 = ctypes.c_uint8.from_address(p2 + idx).value
        if b1 != b2:
            return 0
    return 1


def omni_str_startswith(s1: int, prefix: int) -> int:
    """Returns 1 if `s1` begins with `prefix`, 0 otherwise."""
    len1 = omni_str_len(s1)
    len_p = omni_str_len(prefix)
    if len_p > len1:
        return 0
    if len_p == 0:
        return 1
    p1 = omni_str_data_ptr(s1)
    pp = omni_str_data_ptr(prefix)
    for i in range(len_p):
        if ctypes.c_uint8.from_address(p1 + i).value != ctypes.c_uint8.from_address(pp + i).value:
            return 0
    return 1


def omni_str_to_py(str_ptr: int) -> str:
    """Decodes a native OmniString into a Python str (for assertions & host interop)."""
    if str_ptr == 0:
        return ""
    length = omni_str_len(str_ptr)
    if length == 0:
        return ""
    data_p = omni_str_data_ptr(str_ptr)
    raw = ctypes.string_at(data_p, length)
    return raw.decode("utf-8", errors="replace")


# Registry of native string symbols for JIT trampolines & Linker resolution
NATIVE_STRING_SYMBOLS: Dict[str, Tuple[Any, List[Any], Any]] = {
    "omni_str_new_from_cstr": (omni_str_new_from_cstr, [ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_str_len": (omni_str_len, [ctypes.c_int64], ctypes.c_int64),
    "omni_str_data_ptr": (omni_str_data_ptr, [ctypes.c_int64], ctypes.c_int64),
    "omni_str_get_byte": (omni_str_get_byte, [ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_str_concat": (omni_str_concat, [ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_str_slice": (omni_str_slice, [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_str_slice_to_str": (omni_str_slice_to_str, [ctypes.c_int64], ctypes.c_int64),
    "omni_str_eq": (omni_str_eq, [ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_str_startswith": (omni_str_startswith, [ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
}
