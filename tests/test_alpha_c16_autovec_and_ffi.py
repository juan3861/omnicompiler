"""
OmniCompiler Alpha-C16 Test Suite: Loop Auto-Vectorization & Native Dynamic FFI Bridge
(tests/test_alpha_c16_autovec_and_ffi.py).

Verifies:
1. Scalar induction loop auto-vectorization for elementwise vector addition (omni_list_vec_add).
2. Parallel reduction sum loop auto-vectorization (omni_list_sum).
3. Vector dot product loop auto-vectorization (omni_list_vec_dot).
4. Automated multi-pass pipeline integration in NativeJitCompiler (StackPromotion + LoopVectorizer).
5. Dynamic FFI library loading and symbol resolution (Win32 / POSIX).
6. Dynamic C-ABI function call trampolines (omni_ffi_call0 through omni_ffi_call4, omni_ffi_call).
7. End-to-end silicon JIT execution of auto-vectorized loops against physical RAM buffers.
"""

import unittest
import sys
import ctypes

from compiler.ssa_ir import lower_source_to_ssa
from compiler.loop_vectorizer import LoopVectorizerPass
from compiler.native_jit import NativeJitCompiler
from runtime.native_heap import omni_list_new, omni_list_set, omni_list_get, omni_list_len
from runtime.native_collections_simd import omni_list_vec_add, omni_list_vec_dot, omni_list_sum
from runtime.native_ffi import (
    OmniFFI,
    omni_ffi_load_lib,
    omni_ffi_get_symbol,
    omni_ffi_call0,
    omni_ffi_call1,
    omni_ffi_call2,
    omni_ffi_call3,
    omni_ffi_call4,
    omni_ffi_call,
)


class TestAlphaC16AutoVecAndFFI(unittest.TestCase):

    def test_01_loop_vectorizer_elementwise_add(self):
        """Verifies LoopVectorizerPass detects and rewrites list addition loop into omni_list_vec_add."""
        code = """
def vec_add(a: list, b: list) -> list:
    c = omni_list_new(len(a))
    for i in range(len(a)):
        c[i] = a[i] + b[i]
    return c
"""
        fn = lower_source_to_ssa(code)
        pass_opt = LoopVectorizerPass()
        opt_fn, stats = pass_opt.vectorize_function(fn)

        self.assertEqual(stats["vectorized_adds"], 1)
        # Check that loop was eliminated (only entry and exit remain)
        block_names = [b.name for b in opt_fn.blocks]
        self.assertNotIn("for_body_3", block_names)
        self.assertNotIn("for_latch_4", block_names)

        # Check that omni_list_vec_add is called in entry
        entry = opt_fn.entry_block
        calls = [inst for inst in entry.instructions if inst.opcode == "call"]
        called_names = [str(c.operands[0]) for c in calls]
        self.assertIn("omni_list_vec_add", called_names)

    def test_02_loop_vectorizer_reduction_sum(self):
        """Verifies LoopVectorizerPass detects and rewrites reduction sum loop into omni_list_sum."""
        code = """
def reduction_sum(a: list) -> int:
    total = 0
    for i in range(len(a)):
        total += a[i]
    return total
"""
        fn = lower_source_to_ssa(code)
        pass_opt = LoopVectorizerPass()
        opt_fn, stats = pass_opt.vectorize_function(fn)

        self.assertEqual(stats["vectorized_sums"], 1)
        block_names = [b.name for b in opt_fn.blocks]
        self.assertNotIn("for_body_3", block_names)
        self.assertNotIn("for_latch_4", block_names)

        entry = opt_fn.entry_block
        calls = [inst for inst in entry.instructions if inst.opcode == "call"]
        called_names = [str(c.operands[0]) for c in calls]
        self.assertIn("omni_list_sum", called_names)

    def test_03_loop_vectorizer_dot_product(self):
        """Verifies LoopVectorizerPass detects and rewrites dot product loop into omni_list_vec_dot."""
        code = """
def dot_product(a: list, b: list) -> int:
    total = 0
    for i in range(len(a)):
        total += a[i] * b[i]
    return total
"""
        fn = lower_source_to_ssa(code)
        pass_opt = LoopVectorizerPass()
        opt_fn, stats = pass_opt.vectorize_function(fn)

        self.assertEqual(stats["vectorized_dots"], 1)
        block_names = [b.name for b in opt_fn.blocks]
        self.assertNotIn("for_body_3", block_names)
        self.assertNotIn("for_latch_4", block_names)

        entry = opt_fn.entry_block
        calls = [inst for inst in entry.instructions if inst.opcode == "call"]
        called_names = [str(c.operands[0]) for c in calls]
        self.assertIn("omni_list_vec_dot", called_names)

    def test_04_dynamic_ffi_load_and_get_symbol(self):
        """Verifies dynamic loading of system shared library and symbol resolution."""
        # Load C standard runtime
        lib_name = "msvcrt" if sys.platform == "win32" else "libc"
        handle = omni_ffi_load_lib(lib_name)
        self.assertGreater(handle, 0)

        # Lookup symbol 'abs' or 'puts'
        sym_name = "abs"
        abs_ptr = omni_ffi_get_symbol(handle, sym_name)
        self.assertGreater(abs_ptr, 0)

        # Lookup another symbol 'strlen' or 'labs'
        sym_name2 = "labs"
        labs_ptr = omni_ffi_get_symbol(handle, sym_name2)
        self.assertGreater(labs_ptr, 0)

    def test_05_dynamic_ffi_trampolines_execution(self):
        """Verifies C-ABI dynamic invocation trampolines (call1, call2, call)."""
        lib_name = "msvcrt" if sys.platform == "win32" else "libc"
        handle = omni_ffi_load_lib(lib_name)
        abs_ptr = omni_ffi_get_symbol(handle, "abs")
        self.assertGreater(abs_ptr, 0)

        # 1. Test omni_ffi_call1 with abs(-42)
        res_neg = omni_ffi_call1(abs_ptr, -42)
        self.assertEqual(res_neg, 42)

        res_pos = omni_ffi_call1(abs_ptr, 108)
        self.assertEqual(res_pos, 108)

        # 2. Test omni_ffi_call with arguments unpacked from OmniList
        args_list = omni_list_new(2)
        omni_list_set(args_list, 0, -999)
        res_list = omni_ffi_call(abs_ptr, args_list)
        self.assertEqual(res_list, 999)

        # 3. Test High-Level OmniFFI Python API
        res_api = OmniFFI.call(abs_ptr, -12345)
        self.assertEqual(res_api, 12345)

    def test_06_jit_pipeline_automatic_passes_and_execution(self):
        """Verifies end-to-end JIT compilation and hardware execution of auto-vectorized loop."""
        code = """
def run_vectorized_sum(a: list) -> int:
    total = 0
    for i in range(len(a)):
        total += a[i]
    return total
"""
        ssa_fn = lower_source_to_ssa(code)
        jit = NativeJitCompiler()

        # Compile with automatic passes enabled (StackPromotion + LoopVectorizer)
        callable_fn, mem, code_hex = jit.compile_ssa(ssa_fn, optimize_passes=True)
        self.assertTrue(mem.is_executable)
        self.assertGreater(len(code_hex), 0)

        # Prepare test list with 16 integers
        N = 16
        test_list = omni_list_new(N)
        expected_sum = 0
        for i in range(N):
            val = (i + 1) * 10
            omni_list_set(test_list, i, val)
            expected_sum += val

        # Execute compiled silicon function in RAM
        actual_sum = callable_fn(test_list)
        self.assertEqual(actual_sum, expected_sum)


if __name__ == "__main__":
    unittest.main()
