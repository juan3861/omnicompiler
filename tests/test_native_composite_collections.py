"""
OmniCompiler Native Composite Collections & Heap Lowering Test Suite.
Verifies end-to-end native compilation of heap-allocated dynamic lists (OmniList),
open-addressing hash dictionaries (OmniDict), `.append()`, `len()`, subscripts `lst[i]`,
mutations `lst[i] = v`, and collection loops `for x in lst:` on physical silicon.
"""

import ast
import ctypes
import os
import sys
import tempfile
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from compiler.ssa_ir import lower_source_to_ssa
from compiler.native_jit import NativeJitCompiler, PAGE_EXECUTE_READ
from compiler.native_codegen import X64CodeGenerator, Arm64CodeGenerator
from runtime.native_heap import (
    omni_list_new, omni_list_append, omni_list_len, omni_list_get, omni_list_set,
    omni_dict_new, omni_dict_set, omni_dict_get, omni_item_get, omni_item_set, omni_item_len,
    get_global_arena,
)
from validation.silicon_safety_sandbox import SiliconSafetySandbox
from omni_repo_compiler import OmniRepoCompiler


class TestNativeCompositeCollections(unittest.TestCase):

    def setUp(self):
        self.jit = NativeJitCompiler()

    # ==========================================================================
    # TEST 1: OmniList Native Heap Primitive Correctness
    # ==========================================================================
    def test_01_native_heap_list_and_dict_primitives(self):
        lst = omni_list_new(4)
        self.assertEqual(omni_list_len(lst), 0)
        omni_list_append(lst, 42)
        omni_list_append(lst, 108)
        self.assertEqual(omni_list_len(lst), 2)
        self.assertEqual(omni_list_get(lst, 0), 42)
        self.assertEqual(omni_list_get(lst, 1), 108)

        omni_list_set(lst, 1, 999)
        self.assertEqual(omni_list_get(lst, 1), 999)

        # Unified omni_item_* dispatch
        self.assertEqual(omni_item_len(lst), 2)
        self.assertEqual(omni_item_get(lst, 0), 42)
        omni_item_set(lst, 0, 777)
        self.assertEqual(omni_item_get(lst, 0), 777)

        # OmniDict primitives
        dct = omni_dict_new(8)
        omni_dict_set(dct, 101, 5555)
        omni_dict_set(dct, 202, 7777)
        self.assertEqual(omni_dict_get(dct, 101), 5555)
        self.assertEqual(omni_dict_get(dct, 202), 7777)
        self.assertEqual(omni_dict_get(dct, 999), 0)  # missing key

        # Unified omni_item_* dispatch on Dict
        self.assertEqual(omni_item_get(dct, 101), 5555)
        omni_item_set(dct, 101, 8888)
        self.assertEqual(omni_item_get(dct, 101), 8888)

    # ==========================================================================
    # TEST 2: Native JIT Literal List Creation and Indexing `[a, b, c]`
    # ==========================================================================
    def test_02_native_jit_list_creation_and_indexing(self):
        src = """
def sum_three_items(a, b, c):
    items = [a, b, c]
    return items[0] + items[1] + items[2]
"""
        fn, mem, _hex = self.jit.compile_function(src, "sum_three_items")
        if sys.platform == "win32":
            self.assertEqual(mem.query_os_protection(), PAGE_EXECUTE_READ)

        self.assertEqual(fn(10, 20, 35), 65)
        self.assertEqual(fn(100, -50, 25), 75)

    # ==========================================================================
    # TEST 3: Native JIT Dynamic List Growth `.append()` in Loop
    # ==========================================================================
    def test_03_native_jit_list_append_and_growth(self):
        src = """
def compute_sum_of_squares(n):
    nums = []
    for i in range(n):
        nums.append(i * i)
    total = 0
    for i in range(len(nums)):
        total += nums[i]
    return total
"""
        fn, _mem, _ = self.jit.compile_function(src, "compute_sum_of_squares")
        expected_10 = sum(i * i for i in range(10))
        self.assertEqual(fn(10), expected_10)

        expected_25 = sum(i * i for i in range(25))
        self.assertEqual(fn(25), expected_25)

    # ==========================================================================
    # TEST 4: Native JIT Direct Collection Iteration `for x in my_list:`
    # ==========================================================================
    def test_04_native_jit_for_in_collection_loop(self):
        src = """
def sum_collection(offset):
    vals = [10, 20, 30, 40, 50]
    total = offset
    for item in vals:
        total += item
    return total
"""
        fn, _mem, _ = self.jit.compile_function(src, "sum_collection")
        self.assertEqual(fn(0), 150)
        self.assertEqual(fn(25), 175)

    # ==========================================================================
    # TEST 5: Native JIT In-Place List Mutation `vals[i] = val`
    # ==========================================================================
    def test_05_native_jit_list_subscript_mutation(self):
        src = """
def scale_list_elements(factor):
    data = [1, 2, 3, 4]
    for i in range(len(data)):
        data[i] = data[i] * factor
    return data[0] + data[1] + data[2] + data[3]
"""
        fn, _mem, _ = self.jit.compile_function(src, "scale_list_elements")
        self.assertEqual(fn(1), 10)
        self.assertEqual(fn(10), 100)
        self.assertEqual(fn(5), 50)

    # ==========================================================================
    # TEST 6: Native JIT Dictionary Creation and Lookup `{k: v}`
    # ==========================================================================
    def test_06_native_jit_dict_literal_and_lookup(self):
        src = """
def lookup_score(player_id):
    scores = {101: 500, 202: 850, 303: 1200}
    return scores[player_id] + 15
"""
        fn, _mem, _ = self.jit.compile_function(src, "lookup_score")
        self.assertEqual(fn(101), 515)
        self.assertEqual(fn(202), 865)
        self.assertEqual(fn(303), 1215)
        self.assertEqual(fn(999), 15)  # Missing key returns 0 + 15

    # ==========================================================================
    # TEST 7: ARM64 Native Codegen with Load/Store on Unicorn Silicon
    # ==========================================================================
    def test_07_arm64_load_store_silicon_execution(self):
        # SSA function performing load and store
        src = """
def arm_load_store(base_ptr, idx, val):
    base_ptr[idx] = val
    return base_ptr[idx] + 7
"""
        ssa_fn = lower_source_to_ssa(src, "arm_load_store", optimize=False)
        arm_gen = Arm64CodeGenerator()
        artifact = arm_gen.compile_function(ssa_fn)
        self.assertGreater(len(artifact.code_bytes), 0)

        # Allocate simulated buffer for Unicorn
        sandbox = SiliconSafetySandbox()
        # In Unicorn, we need a readable/writable data buffer
        # Let's verify through emulator by writing to stack or code memory
        sim_buf_addr = sandbox.STACK_ADDR + 0x1000
        res = sandbox.emulate_arm64(artifact.code_bytes, args=[sim_buf_addr, 2, 88])
        self.assertTrue(res.is_safe_for_silicon, f"ARM64 load/store emulation failed: {res.error}")
        self.assertEqual(res.return_value, 95)  # 88 + 7 == 95

    # ==========================================================================
    # TEST 8: Full Multi-Repo End-to-End Compilation with Collections
    # ==========================================================================
    def test_08_multi_repo_compilation_with_collections(self):
        with tempfile.TemporaryDirectory() as td:
            repo_stats = os.path.join(td, "stats_repo")
            repo_api = os.path.join(td, "api_repo")
            os.makedirs(repo_stats)
            os.makedirs(repo_api)

            with open(os.path.join(repo_stats, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("[project]\nname = 'stats_repo'\nversion = '1.0.0'\n")
            with open(os.path.join(repo_stats, "analytics.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def compute_weighted_sum(weight):\n"
                    "    samples = [10, 20, 30, 40]\n"
                    "    acc = 0\n"
                    "    for s in samples:\n"
                    "        acc += s * weight\n"
                    "    return acc\n"
                )

            with open(os.path.join(repo_api, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("[project]\nname = 'api_repo'\nversion = '1.0.0'\n")
            with open(os.path.join(repo_api, "gateway.py"), "w", encoding="utf-8") as f:
                f.write(
                    "from stats_repo.analytics import compute_weighted_sum\n\n"
                    "def handle_query(multiplier):\n"
                    "    return compute_weighted_sum(multiplier) + 7\n"
                )

            compiler = OmniRepoCompiler(db_path=os.path.join(td, "collections.db"))
            try:
                out_dll = os.path.join(td, "dist", "collections_system.dll")
                res = compiler.compile_repositories(
                    repo_paths=[repo_stats, repo_api],
                    output_path=out_dll,
                    target_format="shared_lib",
                    entry_export="handle_query",
                    target_os="windows",
                    target_arch="x86_64",
                    export_all=True,
                )
                self.assertTrue(res["success"], f"Compilation failed: {res.get('error')}")
                self.assertEqual(res["stages"]["codegen"]["real_ast_functions_compiled"], 2)

                if sys.platform == "win32":
                    dll_path = res["stages"]["emission"]["artifact_path"]
                    lib = ctypes.WinDLL(dll_path)
                    try:
                        fn = getattr(lib, "handle_query")
                        fn.argtypes = [ctypes.c_int64]
                        fn.restype = ctypes.c_int64
                        # (10 + 20 + 30 + 40) * 2 + 7 = 100 * 2 + 7 = 207
                        self.assertEqual(fn(2), 207)
                        # (10 + 20 + 30 + 40) * 5 + 7 = 507
                        self.assertEqual(fn(5), 507)
                    finally:
                        h = lib._handle
                        del fn, lib
                        ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(h))
            finally:
                compiler.cpg.close()


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestNativeCompositeCollections)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
