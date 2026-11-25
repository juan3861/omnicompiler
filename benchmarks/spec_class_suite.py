"""
Alpha-C100: SPEC-Class 7-Kernel Native Benchmark Suite (`benchmarks/spec_class_suite.py`).

Compiles 7 classical algorithmic kernels across Cryptography, Checksums, Linear Algebra,
Sorting, and Signal Processing from Python AST -> Omni-SSA -> Native / LLVM O3 machine code
and verifies bit-exact oracle parity + nanosecond/microsecond execution timings:
  1. Adler-32 Checksum (`spec_adler32`)
  2. CRC-32 IEEE 802.3 (`spec_crc32`)
  3. ChaCha20 ARX Quarter-Round Mix (`spec_chacha20_qr`)
  4. SHA-256 Compression Mix (`spec_sha256_mix`)
  5. Matrix Multiply 4x4 Integer Tile GEMM (`spec_gemm_4x4`)
  6. Branching Sort/Network 4-Key Checksum (`spec_sort_net4`)
  7. Radix-2 Cooley-Tukey Fixed-Point FFT Butterfly (`spec_fft_butterfly`)
"""

from __future__ import annotations

import ast
import ctypes
import time
from typing import Any, Callable, Dict, List, Tuple

from compiler.llvm_backend import LLVMBackend
from compiler.native_jit import NativeJitCompiler
from compiler.ssa_ir import lower_ast_to_ssa

KERNEL_SOURCES: List[Tuple[str, str, Tuple[int, int, int, int]]] = [
    (
        "spec_adler32",
        """
def spec_adler32(seed: int, salt: int, rounds: int, stride: int) -> int:
    s1 = (seed & 0xFFFF) + 1
    s2 = (salt & 0xFFFF)
    for i in range(rounds):
        byte_v = (seed + i * stride + salt) & 0xFF
        s1 = (s1 + byte_v) % 65521
        s2 = (s2 + s1) % 65521
    return (s2 << 16) | s1
""",
        (17, 31, 64, 13),
    ),
    (
        "spec_crc32",
        """
def spec_crc32(init_v: int, poly_seed: int, rounds: int, step: int) -> int:
    crc = (init_v ^ 0xFFFFFFFF) & 0xFFFFFFFF
    for i in range(rounds):
        b = (poly_seed + i * step) & 0xFF
        crc = crc ^ b
        for _ in range(8):
            lsb = crc & 1
            crc = (crc >> 1) & 0x7FFFFFFF
            if lsb != 0:
                crc = crc ^ 0xEDB88320
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF
""",
        (0x1234, 0x5A, 32, 7),
    ),
    (
        "spec_chacha20_qr",
        """
def spec_chacha20_qr(a: int, b: int, c: int, d: int) -> int:
    x0 = a & 0xFFFFFFFF
    x1 = b & 0xFFFFFFFF
    x2 = c & 0xFFFFFFFF
    x3 = d & 0xFFFFFFFF
    for _ in range(10):
        x0 = (x0 + x1) & 0xFFFFFFFF
        x3 = x3 ^ x0
        x3 = ((x3 << 16) | (x3 >> 16)) & 0xFFFFFFFF
        x2 = (x2 + x3) & 0xFFFFFFFF
        x1 = x1 ^ x2
        x1 = ((x1 << 12) | (x1 >> 20)) & 0xFFFFFFFF
        x0 = (x0 + x1) & 0xFFFFFFFF
        x3 = x3 ^ x0
        x3 = ((x3 << 8) | (x3 >> 24)) & 0xFFFFFFFF
        x2 = (x2 + x3) & 0xFFFFFFFF
        x1 = x1 ^ x2
        x1 = ((x1 << 7) | (x1 >> 25)) & 0xFFFFFFFF
    return (x0 ^ x1 ^ x2 ^ x3) & 0xFFFFFFFF
""",
        (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574),
    ),
    (
        "spec_sha256_mix",
        """
def spec_sha256_mix(e: int, f: int, g: int, h: int) -> int:
    s_e = e & 0xFFFFFFFF
    s_f = f & 0xFFFFFFFF
    s_g = g & 0xFFFFFFFF
    acc = h & 0xFFFFFFFF
    for i in range(16):
        s1 = (((s_e >> 6) | (s_e << 26)) ^ ((s_e >> 11) | (s_e << 21)) ^ ((s_e >> 25) | (s_e << 7))) & 0xFFFFFFFF
        ch = ((s_e & s_f) ^ ((~s_e) & s_g)) & 0xFFFFFFFF
        t1 = (acc + s1 + ch + 0x428A2F98 + i * 0x10101) & 0xFFFFFFFF
        acc = s_g
        s_g = s_f
        s_f = s_e
        s_e = (s_e + t1) & 0xFFFFFFFF
    return (acc ^ s_e ^ s_f ^ s_g) & 0xFFFFFFFF
""",
        (0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19),
    ),
    (
        "spec_gemm_4x4",
        """
def spec_gemm_4x4(a0: int, b0: int, n: int, scale: int) -> int:
    total = 0
    for i in range(n):
        for j in range(n):
            acc = 0
            for k in range(n):
                va = a0 + i * 5 + k * 3
                vb = b0 + k * 7 + j * 11
                acc = acc + va * vb
            total = total + (acc * scale)
    return total
""",
        (3, 5, 4, 2),
    ),
    (
        "spec_sort_net4",
        """
def spec_sort_net4(k0: int, k1: int, k2: int, k3: int) -> int:
    a = k0
    b = k1
    c = k2
    d = k3
    if a > b:
        t = a
        a = b
        b = t
    if c > d:
        t = c
        c = d
        d = t
    if a > c:
        t = a
        a = c
        c = t
    if b > d:
        t = b
        b = d
        d = t
    if b > c:
        t = b
        b = c
        c = t
    return a * 1 + b * 10 + c * 100 + d * 1000
""",
        (40, 10, 30, 20),
    ),
    (
        "spec_fft_butterfly",
        """
def spec_fft_butterfly(re_a: int, im_a: int, re_b: int, im_b: int) -> int:
    # Q16.16 fixed-point radix-2 butterfly with twiddle W=(46341, -46341) ~ cos/sin(-pi/4)*65536
    wr = 46341
    wi = -46341
    t_re = (re_b * wr - im_b * wi) >> 16
    t_im = (re_b * wi + im_b * wr) >> 16
    out0_re = re_a + t_re
    out0_im = im_a + t_im
    out1_re = re_a - t_re
    out1_im = im_a - t_im
    return out0_re + out0_im * 3 + out1_re * 7 + out1_im * 11
""",
        (1000, -250, 400, 600),
    ),
]


def run_spec_class_suite() -> Dict[str, Any]:
    """Compiles and benchmarks all 7 SPEC-class kernels vs Python reference oracles."""
    llvm_be = LLVMBackend(opt_level=3)
    native_jit = NativeJitCompiler()
    results: List[Dict[str, Any]] = []
    all_passed = True

    for name, src, args in KERNEL_SOURCES:
        ns: Dict[str, Any] = {}
        exec(compile(src, f"<oracle:{name}>", "exec"), ns)
        oracle_fn: Callable[..., int] = ns[name]
        t_py0 = time.perf_counter_ns()
        expected = int(oracle_fn(*args))
        py_ns = time.perf_counter_ns() - t_py0

        fn_ast = ast.parse(src).body[0]
        assert isinstance(fn_ast, ast.FunctionDef)
        ssa_fn = lower_ast_to_ssa(fn_ast, optimize=True)

        # Native JIT compilation & execution
        nat_ptr, nat_mem, _ = native_jit.compile_ssa(ssa_fn)
        try:
            t_n0 = time.perf_counter_ns()
            nat_val = int(nat_ptr(*args))
            nat_ns = time.perf_counter_ns() - t_n0
        finally:
            nat_mem.free()

        # LLVM O3 MCJIT compilation & execution
        llvm_val = None
        llvm_ns = None
        if llvm_be.is_available:
            ir = llvm_be.ssa_module_to_llvm_ir([ssa_fn], module_name=f"spec_{name}")
            mod = llvm_be.compile_ir(ir, optimize=True)
            l_ptr = llvm_be.create_jit_callable(
                mod, name, restype=ctypes.c_int64, argtypes=[ctypes.c_int64] * len(args)
            )
            t_l0 = time.perf_counter_ns()
            llvm_val = int(l_ptr(*args))
            llvm_ns = time.perf_counter_ns() - t_l0

        nat_ok = (nat_val == expected)
        llvm_ok = (llvm_val == expected) if llvm_val is not None else True
        kernel_ok = nat_ok and llvm_ok
        if not kernel_ok:
            all_passed = False

        results.append({
            "kernel": name,
            "expected": expected,
            "native_result": nat_val,
            "llvm_result": llvm_val,
            "python_ns": py_ns,
            "native_ns": nat_ns,
            "llvm_ns": llvm_ns,
            "bit_exact": kernel_ok,
        })

    return {
        "total_kernels": len(results),
        "passed_kernels": sum(1 for r in results if r["bit_exact"]),
        "all_passed": all_passed,
        "kernels": results,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run_spec_class_suite(), indent=2))
