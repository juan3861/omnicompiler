"""
OmniCompiler Dynamic Foreign Function Interface (FFI) Bridge (native_ffi.py).
Provides cross-platform dynamic library loading, dynamic C-ABI symbol resolution,
and hardware invocation trampolines for calling external C/Rust/C++ shared libraries
(Win32 DLLs and POSIX .so / .dylib) directly from OmniCompiler native machine code.
"""

import sys
import os
import ctypes
from typing import Dict, Tuple, Any, List, Optional, Union

from runtime.native_heap import omni_list_len, omni_list_get


_IS_WIN32 = sys.platform == "win32"

# Cache of loaded library handles and symbol pointers
_LOADED_LIBRARIES: Dict[str, Any] = {}
_HANDLE_COUNTER = 1000
_HANDLE_TO_OBJ: Dict[int, Any] = {}
_TRAMPOLINE_CACHE: Dict[Tuple[int, int], Any] = {}


def _extract_c_string(ptr_or_str: Union[int, str]) -> str:
    """Extracts a Python string from a str, an OmniString pointer, or a raw C-string pointer."""
    if isinstance(ptr_or_str, str):
        return ptr_or_str
    if not isinstance(ptr_or_str, int) or ptr_or_str == 0:
        return ""

    try:
        # Check SSO string tag at offset 20 (TAG_SSO = 0x53545230)
        tag_sso = ctypes.c_uint32.from_address(ptr_or_str + 20).value
        if tag_sso == 0x53545230:
            length = ctypes.c_uint8.from_address(ptr_or_str + 24).value
            raw_bytes = ctypes.string_at(ptr_or_str, min(15, length))
            return raw_bytes.decode("utf-8", errors="replace")

        # Check Heap string tag at offset 4 (TAG_HEAP = 0x53545231)
        tag_heap = ctypes.c_uint32.from_address(ptr_or_str + 4).value
        if tag_heap == 0x53545231:
            length = ctypes.c_int64.from_address(ptr_or_str + 8).value
            raw_bytes = ctypes.string_at(ptr_or_str + 16, length)
            return raw_bytes.decode("utf-8", errors="replace")

        # Check Slice string tag at offset 24 (TAG_SLICE = 0x53545232)
        tag_slice = ctypes.c_uint32.from_address(ptr_or_str + 24).value
        if tag_slice == 0x53545232:
            base_ptr = ctypes.c_uint64.from_address(ptr_or_str).value
            offset = ctypes.c_int64.from_address(ptr_or_str + 8).value
            length = ctypes.c_int64.from_address(ptr_or_str + 16).value
            raw_bytes = ctypes.string_at(base_ptr + offset, length)
            return raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        pass

    # Fallback to null-terminated C string
    try:
        raw_c_str = ctypes.string_at(ptr_or_str)
        return raw_c_str.decode("utf-8", errors="replace")
    except Exception:
        return ""


def omni_ffi_load_lib(lib_name_ptr: Union[int, str]) -> int:
    """
    Loads a dynamic shared library (DLL / .so / .dylib) into the process space.
    Returns an integer handle identifying the library.
    """
    global _HANDLE_COUNTER
    lib_name = _extract_c_string(lib_name_ptr).strip()

    if lib_name in _LOADED_LIBRARIES:
        return _LOADED_LIBRARIES[lib_name]

    lib_obj = None
    if _IS_WIN32:
        try:
            if not lib_name or lib_name.lower() in ("msvcrt", "libc"):
                lib_obj = ctypes.cdll.msvcrt
            elif lib_name.lower() in ("kernel32", "kernel32.dll"):
                lib_obj = ctypes.windll.kernel32
            else:
                lib_obj = ctypes.CDLL(lib_name)
        except Exception:
            try:
                lib_obj = ctypes.WinDLL(lib_name)
            except Exception:
                return 0
    else:
        try:
            if not lib_name or lib_name.lower() in ("libc", "c"):
                lib_obj = ctypes.CDLL(None)
            else:
                lib_obj = ctypes.CDLL(lib_name)
        except Exception:
            return 0

    if lib_obj is None:
        return 0

    _HANDLE_COUNTER += 1
    handle_id = _HANDLE_COUNTER
    _LOADED_LIBRARIES[lib_name] = handle_id
    _HANDLE_TO_OBJ[handle_id] = lib_obj
    return handle_id


def omni_ffi_get_symbol(lib_handle: int, sym_name_ptr: Union[int, str]) -> int:
    """
    Resolves an exported symbol by name from the specified library handle.
    Returns the 64-bit absolute memory address of the function pointer.
    """
    sym_name = _extract_c_string(sym_name_ptr).strip()
    if not sym_name:
        return 0

    lib_obj = _HANDLE_TO_OBJ.get(lib_handle)
    if lib_obj is None:
        # If handle is 0, check default runtime (msvcrt / libc)
        if _IS_WIN32:
            lib_obj = ctypes.cdll.msvcrt
        else:
            lib_obj = ctypes.CDLL(None)

    try:
        sym_addr = getattr(lib_obj, sym_name)
        ptr_val = ctypes.cast(sym_addr, ctypes.c_void_p).value
        return int(ptr_val or 0)
    except Exception:
        # Try OS specific GetProcAddress / dlsym directly
        if _IS_WIN32:
            try:
                k32 = ctypes.windll.kernel32
                h_mod = lib_obj._handle
                proc_addr = k32.GetProcAddress(h_mod, sym_name.encode("ascii"))
                return int(proc_addr or 0)
            except Exception:
                return 0
        return 0


# =====================================================================
# Dynamic C-ABI Trampolines (0 to 4 arguments + arbitrary args list)
# =====================================================================

def omni_ffi_call0(fn_ptr: int) -> int:
    """Calls fn_ptr() -> int64 with 0 arguments."""
    if fn_ptr == 0:
        return 0
    fn_type = ctypes.CFUNCTYPE(ctypes.c_int64)
    callable_fn = fn_type(fn_ptr)
    return int(callable_fn())


def omni_ffi_call1(fn_ptr: int, a0: int) -> int:
    """Calls fn_ptr(a0) -> int64 with 1 argument."""
    if fn_ptr == 0:
        return 0
    fn_type = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    callable_fn = fn_type(fn_ptr)
    return int(callable_fn(a0))


def omni_ffi_call2(fn_ptr: int, a0: int, a1: int) -> int:
    """Calls fn_ptr(a0, a1) -> int64 with 2 arguments."""
    if fn_ptr == 0:
        return 0
    fn_type = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    callable_fn = fn_type(fn_ptr)
    return int(callable_fn(a0, a1))


def omni_ffi_call3(fn_ptr: int, a0: int, a1: int, a2: int) -> int:
    """Calls fn_ptr(a0, a1, a2) -> int64 with 3 arguments."""
    if fn_ptr == 0:
        return 0
    fn_type = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    callable_fn = fn_type(fn_ptr)
    return int(callable_fn(a0, a1, a2))


def omni_ffi_call4(fn_ptr: int, a0: int, a1: int, a2: int, a3: int) -> int:
    """Calls fn_ptr(a0, a1, a2, a3) -> int64 with 4 arguments."""
    if fn_ptr == 0:
        return 0
    fn_type = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    callable_fn = fn_type(fn_ptr)
    return int(callable_fn(a0, a1, a2, a3))


def omni_ffi_call(fn_ptr: int, args_list_ptr: int) -> int:
    """
    Calls fn_ptr(*args) -> int64 dynamically unpacking arguments from an OmniList.
    Supports up to 8 64-bit integer arguments.
    """
    if fn_ptr == 0:
        return 0
    if args_list_ptr == 0:
        return omni_ffi_call0(fn_ptr)

    n_args = min(8, max(0, omni_list_len(args_list_ptr)))
    args = [omni_list_get(args_list_ptr, i) for i in range(n_args)]

    if n_args == 0:
        return omni_ffi_call0(fn_ptr)
    elif n_args == 1:
        return omni_ffi_call1(fn_ptr, args[0])
    elif n_args == 2:
        return omni_ffi_call2(fn_ptr, args[0], args[1])
    elif n_args == 3:
        return omni_ffi_call3(fn_ptr, args[0], args[1], args[2])
    elif n_args == 4:
        return omni_ffi_call4(fn_ptr, args[0], args[1], args[2], args[3])
    else:
        # Dynamic trampoline for 5 to 8 arguments
        sig_key = (fn_ptr, n_args)
        if sig_key not in _TRAMPOLINE_CACHE:
            arg_types = [ctypes.c_int64] * n_args
            fn_type = ctypes.CFUNCTYPE(ctypes.c_int64, *arg_types)
            _TRAMPOLINE_CACHE[sig_key] = fn_type(fn_ptr)
        return int(_TRAMPOLINE_CACHE[sig_key](*args))


class OmniFFI:
    """High-level Python API for OmniCompiler FFI."""

    @staticmethod
    def load_library(name: str) -> int:
        return omni_ffi_load_lib(name)

    @staticmethod
    def get_symbol(lib_handle: int, sym_name: str) -> int:
        return omni_ffi_get_symbol(lib_handle, sym_name)

    @staticmethod
    def call(fn_ptr: int, *args: int) -> int:
        if len(args) == 0:
            return omni_ffi_call0(fn_ptr)
        elif len(args) == 1:
            return omni_ffi_call1(fn_ptr, args[0])
        elif len(args) == 2:
            return omni_ffi_call2(fn_ptr, args[0], args[1])
        elif len(args) == 3:
            return omni_ffi_call3(fn_ptr, args[0], args[1], args[2])
        elif len(args) == 4:
            return omni_ffi_call4(fn_ptr, args[0], args[1], args[2], args[3])
        else:
            arg_types = [ctypes.c_int64] * len(args)
            fn_type = ctypes.CFUNCTYPE(ctypes.c_int64, *arg_types)
            return int(fn_type(fn_ptr)(*args))


# Exported symbols for runtime/native_heap.py integration
NATIVE_FFI_SYMBOLS: Dict[str, Tuple[Any, List[Any], Any]] = {
    "omni_ffi_load_lib": (omni_ffi_load_lib, [ctypes.c_int64], ctypes.c_int64),
    "omni_ffi_get_symbol": (omni_ffi_get_symbol, [ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_ffi_call0": (omni_ffi_call0, [ctypes.c_int64], ctypes.c_int64),
    "omni_ffi_call1": (omni_ffi_call1, [ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_ffi_call2": (omni_ffi_call2, [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_ffi_call3": (omni_ffi_call3, [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_ffi_call4": (omni_ffi_call4, [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_ffi_call": (omni_ffi_call, [ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
}
