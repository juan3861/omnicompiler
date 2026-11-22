"""
OmniCompiler Native File I/O & TCP/HTTP Runtime (Alpha-C76).

Provides C-ABI compatible file descriptor I/O (`omni_file_open`, `omni_file_write`,
`omni_file_read`, `omni_file_close`) backed directly by OS libc (`ucrtbase`/`msvcrt`
on Windows, `libc` on POSIX) and native TCP/HTTP loopback primitives without
exposing CPython file/socket objects across compiled ABI boundaries.
"""

import ctypes
import os
import socket
import sys
from typing import Any, Dict, List, Tuple


def _get_os_libc() -> ctypes.CDLL:
    if sys.platform == "win32":
        for dll_name in ("ucrtbase.dll", "msvcrt.dll"):
            try:
                return ctypes.CDLL(dll_name)
            except OSError:
                continue
        return ctypes.cdll.msvcrt
    return ctypes.CDLL(None)


_LIBC = _get_os_libc()


def omni_file_open(path_ptr: int, flags: int = 0, mode: int = 0o644) -> int:
    """
    Opens a file via native OS C-ABI (`_open` / `open`).
    flags: 0 = read-only, 1 = write/create/truncate, 2 = read-write/create.
    Returns file descriptor (>= 0) or -1 on error.
    """
    if not path_ptr:
        return -1
    c_path = ctypes.c_char_p(path_ptr)
    if sys.platform == "win32":
        # Windows _O_RDONLY=0, _O_WRONLY=1, _O_RDWR=2, _O_CREAT=0x0100, _O_TRUNC=0x0200, _O_BINARY=0x8000
        if flags == 1:
            os_flags = 0x0001 | 0x0100 | 0x0200 | 0x8000
        elif flags == 2:
            os_flags = 0x0002 | 0x0100 | 0x8000
        else:
            os_flags = 0x0000 | 0x8000
        fn = getattr(_LIBC, "_open")
        fn.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
        fn.restype = ctypes.c_int
        return int(fn(c_path, os_flags, 0o600))
    else:
        if flags == 1:
            os_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        elif flags == 2:
            os_flags = os.O_RDWR | os.O_CREAT
        else:
            os_flags = os.O_RDONLY
        fn = getattr(_LIBC, "open")
        fn.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
        fn.restype = ctypes.c_int
        return int(fn(c_path, os_flags, mode))


def omni_file_write(fd: int, buf_ptr: int, count: int) -> int:
    """Writes `count` bytes from raw pointer `buf_ptr` to OS file descriptor `fd`."""
    if fd < 0 or not buf_ptr or count <= 0:
        return -1
    fn = getattr(_LIBC, "_write" if sys.platform == "win32" else "write")
    fn.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint if sys.platform == "win32" else ctypes.c_size_t]
    fn.restype = ctypes.c_int if sys.platform == "win32" else ctypes.c_ssize_t
    return int(fn(fd, ctypes.c_void_p(buf_ptr), count))


def omni_file_read(fd: int, buf_ptr: int, count: int) -> int:
    """Reads up to `count` bytes from OS file descriptor `fd` into raw pointer `buf_ptr`."""
    if fd < 0 or not buf_ptr or count <= 0:
        return -1
    fn = getattr(_LIBC, "_read" if sys.platform == "win32" else "read")
    fn.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint if sys.platform == "win32" else ctypes.c_size_t]
    fn.restype = ctypes.c_int if sys.platform == "win32" else ctypes.c_ssize_t
    return int(fn(fd, ctypes.c_void_p(buf_ptr), count))


def omni_file_close(fd: int) -> int:
    """Closes OS file descriptor `fd`."""
    if fd < 0:
        return -1
    fn = getattr(_LIBC, "_close" if sys.platform == "win32" else "close")
    fn.argtypes = [ctypes.c_int]
    fn.restype = ctypes.c_int
    return int(fn(fd))


def omni_tcp_http_request(host_ptr: int, port: int, req_ptr: int, req_len: int, resp_ptr: int, resp_cap: int) -> int:
    """
    Sends raw TCP/HTTP payload from `req_ptr` (`req_len` bytes) to `host_ptr:port`
    and writes the response directly into `resp_ptr` (up to `resp_cap` bytes).
    Returns number of bytes received, or -1 on failure.
    """
    if not host_ptr or not req_ptr or not resp_ptr or req_len <= 0 or resp_cap <= 0:
        return -1
    host = ctypes.c_char_p(host_ptr).value.decode("utf-8", errors="replace")
    payload = ctypes.string_at(req_ptr, req_len)
    with socket.create_connection((host, int(port)), timeout=5.0) as sock:
        sock.sendall(payload)
        chunks = []
        total = 0
        while total < resp_cap:
            data = sock.recv(min(4096, resp_cap - total))
            if not data:
                break
            chunks.append(data)
            total += len(data)
        raw = b"".join(chunks)[:resp_cap]
        ctypes.memmove(resp_ptr, raw, len(raw))
        return len(raw)


NATIVE_IO_SYMBOLS: Dict[str, Tuple[Any, List[Any], Any]] = {
    "omni_file_open": (omni_file_open, [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_file_write": (omni_file_write, [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_file_read": (omni_file_read, [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64], ctypes.c_int64),
    "omni_file_close": (omni_file_close, [ctypes.c_int64], ctypes.c_int64),
    "omni_tcp_http_request": (
        omni_tcp_http_request,
        [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64],
        ctypes.c_int64,
    ),
}
