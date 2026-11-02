"""
OmniCompiler Market-Leading Ceiling Engineering End-to-End Verification Suite.
Physically exercises all 9 ceiling architecture pillars on real silicon without mocks:
  1. Rust SIMD BLAKE3 + Batched SQLite CTE CPG + O(1) In-Mmap Binary Slot Store
  2. Sound Z3 QF_BV Fail-Closed Refinement & UB Verifier + Side-Effect Safe OmniMutator
  3. Turing-Complete Multi-Block Omni-SSA + W^X x86-64 JIT + Unicorn ARM64 Execution
  4. LLVM O3 Multi-Block Lowering + Native COFF/ELF Object Linking
  5. Halide AST Loop Strip-Mining + Hardware VEX 256-bit AVX2 YMM Tiled Vector Execution
  6. DWARF v5 `.debug_line` Round-Trip State Machine & Win64 `.pdata`/`.xdata` Unwind
  7. Sub-Millisecond W^X Jump-Thunk `HotPatchLinkerSession` Live Code Replacement
  8. Multi-Repo Real AST Compilation, Cross-Repo Native Calls, Multi-Export PE/ELF/Mach-O,
     Apple Silicon `LC_CODE_SIGNATURE` (SHA-256), & Standalone OS `stdout` Executable
  9. Persistent Keep-Alive Node.js V8 IPC Daemon + WASI Preview 2 Canonical ABI & Fuel Metering
"""

import ast
import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from crypto.blake3_engine import HAS_NATIVE_BLAKE3, blake3_hex, pure_python_blake3_digest, Blake3Hasher
from slicer.persistent_cpg import PersistentCodePropertyGraph
from storage.mmap_store import MmapArtifactStore
from validation.smt_refinement import SmtRefinementVerifier
from validation.refinement_memory_engine import MemoryRefinementVerifier
from evolution.omni_mutator import apply_omni_mutations
from compiler.ssa_ir import lower_source_to_ssa
from compiler.regalloc_graph_coloring import ChaitinBriggsAllocator, LinearScanAllocator
from compiler.native_codegen import NativeCodeGenerator, X64CodeGenerator, Arm64CodeGenerator
from compiler.native_jit import NativeJitCompiler, PAGE_EXECUTE_READ
from compiler.llvm_backend import LLVMBackend
from compiler.tensor_tiler import LoopScheduleTiler
from compiler.debug_info_emitter import DwarfV5Emitter, emit_win64_pdata_xdata, decode_win64_pdata
from compiler.object_linker import NativeObjectLinker, ObjectModule, HotPatchLinkerSession
from compiler.binary_emitter import StandaloneBinaryEmitter
from validation.binary_structure_auditor import BinaryStructureAuditor
from validation.silicon_safety_sandbox import SiliconSafetySandbox
from omni_repo_compiler import OmniRepoCompiler
from adapters.synthesizer import AdapterSynthesizer
from contracts.models import CapabilityContract
from compiler.wasm_backend import WasmBackend, parse_wit_world


class TestCeilingEngineeringComplete(unittest.TestCase):
    # ==========================================================================
    # PILLAR 1: Native SIMD BLAKE3 + Batched CPG CTE + O(1) Mmap Binary Store
    # ==========================================================================
    def test_01_simd_blake3_batched_cpg_and_mmap_store(self):
        self.assertTrue(HAS_NATIVE_BLAKE3, "Native Rust SIMD blake3 must be active")
        for sz in (0, 64, 1024, 65537):
            payload = os.urandom(sz)
            self.assertEqual(blake3_hex(payload), pure_python_blake3_digest(payload))

        # Throughput check on 4 MB payload
        buf_4mb = b"\x5a" * (4 * 1024 * 1024)
        t0 = time.perf_counter()
        digest = Blake3Hasher().update(buf_4mb).hexdigest()
        dt = max(1e-6, time.perf_counter() - t0)
        mb_per_s = 4.0 / dt
        self.assertEqual(len(digest), 64)
        self.assertGreater(mb_per_s, 100.0, f"Expected >100 MB/s SIMD BLAKE3 throughput, got {mb_per_s:.1f} MB/s")

        with tempfile.TemporaryDirectory() as td:
            # Batched on-disk SQLite CPG + nested control flow taint reachability
            db_path = os.path.join(td, "ceiling_cpg.db")
            cpg = PersistentCodePropertyGraph(db_path)
            try:
                src_code = "\n".join(
                    f"def fn_{i}(tenant_tok, x):\n"
                    f"    if x > 0:\n"
                    f"        acc = tenant_tok + {i}\n"
                    f"    else:\n"
                    f"        acc = x\n"
                    f"    return acc\n"
                    for i in range(40)
                )
                tree = ast.parse(src_code)
                t_cpg0 = time.perf_counter()
                with cpg.batch():
                    cpg.ingest_ast_module(tree, repo_name="fast_repo")
                t_cpg = max(1e-6, time.perf_counter() - t_cpg0)
                funcs_per_sec = 40.0 / t_cpg
                self.assertGreater(funcs_per_sec, 200.0, f"Expected >200 funcs/sec batched CPG, got {funcs_per_sec:.1f}")
                path = cpg.find_cross_repo_taint_path("tenant_tok", "return")
                self.assertIsNotNone(path)
                self.assertGreaterEqual(len(path), 3)
            finally:
                cpg.close()

            # O(1) In-Mmap Binary Open-Addressing Hash Table (OMMMAP02)
            store_dir = os.path.join(td, "mmap_dir")
            store = MmapArtifactStore(store_dir, initial_size_mb=2)
            try:
                for i in range(60):
                    store.store_artifact(f"art_{i}", f"payload_v1_{i}".encode("utf-8"))
                store.store_artifact("art_10", b"overwritten_v2_payload")
                self.assertTrue(store.delete_artifact("art_5"))
                self.assertIsNone(store.read_zero_copy("art_5"))
                mv = store.read_zero_copy("art_10")
                self.assertIsNotNone(mv)
                self.assertEqual(bytes(mv), b"overwritten_v2_payload")
                mv.release()
                del mv
            finally:
                store.close()

            # Reopen from disk to prove persistent binary header recovery without .meta.json
            self.assertFalse(os.path.exists(os.path.join(store_dir, "artifacts.mmap.meta.json")))
            reopened = MmapArtifactStore(store_dir, initial_size_mb=2)
            try:
                self.assertEqual(reopened.count(), 59)
                mv2 = reopened.read_zero_copy("art_10")
                self.assertEqual(bytes(mv2), b"overwritten_v2_payload")
                mv2.release()
                del mv2
            finally:
                reopened.close()

    # ==========================================================================
    # PILLAR 2: Sound Fail-Closed Z3 QF_BV Verifier + UB Verifier + OmniMutator
    # ==========================================================================
    def test_02_sound_fail_closed_z3_and_ub_refinement(self):
        verifier = SmtRefinementVerifier(bit_width=32)

        # Unsound inequality MUST be rejected with concrete counterexample
        bad = verifier.verify_arithmetic_refinement("x + 5", "x + 999")
        self.assertFalse(bad["proven"], "SmtRefinementVerifier MUST reject x + 5 vs x + 999!")
        self.assertGreater(len(bad["counterexamples"]), 0)

        # Valid strength reduction across arbitrary multi-variable AST
        good = verifier.verify_arithmetic_refinement("(x * 16) + (y * 8) - 0", "(x << 4) + (y << 3)")
        self.assertTrue(good["proven"])
        self.assertEqual(good["bits_verified"], 32)

        # Python floor division vs C truncation toward zero differs on negative odd integers!
        div_mismatch = verifier.verify_arithmetic_refinement("x // 2", "int(x / 2)")
        self.assertFalse(div_mismatch["proven"], "Must catch Python floor-div vs C trunc-div mismatch on negative odd ints!")

        # Unknown calls must fail closed
        unknown_call = verifier.verify_arithmetic_refinement("mystery_fn(x)", "mystery_fn(x)")
        self.assertFalse(unknown_call["proven"])
        self.assertTrue(unknown_call.get("fail_closed"))

        # UB Refinement Engine
        ub = MemoryRefinementVerifier(bit_width=32)
        ub_bad_zero = ub.verify_ub_poison_refinement("x + 1", "x // 0")
        self.assertFalse(ub_bad_zero["proven"], "Target introducing division by zero MUST fail UB refinement!")

        ub_bad_var = ub.verify_ub_poison_refinement("x + y", "y // x")
        self.assertFalse(ub_bad_var["proven"], "Target introducing conditional x==0 division MUST fail UB refinement!")

        ub_good = ub.verify_ub_poison_refinement("y // x", "y >> 4")
        self.assertTrue(ub_good["proven"], "Eliminating division UB into bounded shift MUST pass UB refinement!")

        # OmniMutator side-effect preservation
        side_effect_src = "def run(x):\n    return fetch_remote(x) * 0\n"
        mut_se, applied_se = apply_omni_mutations(side_effect_src)
        self.assertIn("fetch_remote(x)", mut_se, "OmniMutator must NOT erase side-effecting call in expr * 0!")
        self.assertEqual(len(applied_se), 0)

        pure_src = "def run(x):\n    return (x + 7) * 0\n"
        mut_pure, applied_pure = apply_omni_mutations(pure_src)
        self.assertIn("return 0", mut_pure)
        self.assertGreater(len(applied_pure), 0)

    # ==========================================================================
    # PILLAR 3: Turing-Complete Multi-Block Omni-SSA + W^X x86-64 + Unicorn ARM64
    # ==========================================================================
    def test_03_turing_complete_ssa_wx_x64_jit_and_arm64_silicon(self):
        fib_src = """
def fib(n):
    if n <= 1:
        return n
    a = 0
    b = 1
    i = 2
    while i <= n:
        a, b = b, a + b
        i += 1
    return b
"""
        gcd_src = """
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
"""
        collatz_src = """
def collatz_steps(n):
    steps = 0
    while n > 1:
        if n % 2 == 0:
            n = n // 2
        else:
            n = 3 * n + 1
        steps += 1
    return steps
"""
        for_break_src = """
def sum_filtered(limit):
    acc = 0
    for i in range(0, limit, 1):
        if i % 3 == 0:
            continue
        if acc > 500:
            break
        acc += i
    return acc
"""
        rec_fib_src = """
def fib_rec(n):
    if n <= 1:
        return n
    return fib_rec(n - 1) + fib_rec(n - 2)
"""
        # Verify Dominators + Both Register Allocators
        ssa_fib = lower_source_to_ssa(fib_src, "fib", optimize=True)
        doms = ssa_fib.compute_dominators()
        self.assertIn("entry", doms)
        self.assertIsNone(doms["entry"])
        cb_res = ChaitinBriggsAllocator().allocate(ssa_fib)
        ls_res = LinearScanAllocator().allocate(ssa_fib)
        self.assertTrue(cb_res["success"])
        self.assertTrue(ls_res["success"])

        if sys.platform == "win32" or sys.platform.startswith("linux"):
            jit = NativeJitCompiler()

            fn_fib, mem_fib, _ = jit.compile_function(fib_src, "fib")
            if sys.platform == "win32":
                self.assertEqual(mem_fib.query_os_protection(), PAGE_EXECUTE_READ, "JIT page must enforce strict W^X RX (0x20), never RWX (0x40)!")
            self.assertEqual(fn_fib(0), 0)
            self.assertEqual(fn_fib(1), 1)
            self.assertEqual(fn_fib(10), 55)
            self.assertEqual(fn_fib(20), 6765)
            self.assertEqual(fn_fib(35), 9227465)

            fn_gcd, _m2, _ = jit.compile_function(gcd_src, "gcd")
            self.assertEqual(fn_gcd(1071, 462), 21)
            self.assertEqual(fn_gcd(48, 18), 6)

            fn_col, _m3, _ = jit.compile_function(collatz_src, "collatz_steps")
            self.assertEqual(fn_col(27), 111)
            self.assertEqual(fn_col(6), 8)

            fn_for, _m4, _ = jit.compile_function(for_break_src, "sum_filtered")
            # Reference Python execution
            ns: dict = {}
            exec(for_break_src, ns)
            self.assertEqual(fn_for(60), ns["sum_filtered"](60))

            fn_rec, _m5, _ = jit.compile_function(rec_fib_src, "fib_rec")
            self.assertEqual(fn_rec(12), 144)

        # ARM64 Multi-Block Codegen + Unicorn ARMv8-A Silicon Emulation
        arm_gen = Arm64CodeGenerator()
        arm_fib_art = arm_gen.compile_function(ssa_fib)
        arm_gcd_art = arm_gen.compile_function(lower_source_to_ssa(gcd_src, "gcd", optimize=True))
        sandbox = SiliconSafetySandbox()
        res_arm_fib = sandbox.emulate_arm64(arm_fib_art.code_bytes, args=[20])
        self.assertTrue(res_arm_fib.is_safe_for_silicon, f"ARM64 fib emulation failed: {res_arm_fib.error}")
        self.assertEqual(res_arm_fib.return_value, 6765)

        res_arm_gcd = sandbox.emulate_arm64(arm_gcd_art.code_bytes, args=[1071, 462])
        self.assertTrue(res_arm_gcd.is_safe_for_silicon)
        self.assertEqual(res_arm_gcd.return_value, 21)

    # ==========================================================================
    # PILLAR 4: LLVM O3 Multi-Block Lowering + Native COFF/ELF .obj Linking
    # ==========================================================================
    def test_04_llvm_o3_multiblock_and_coff_object_linking(self):
        llvm_be = LLVMBackend(opt_level=3)
        if not llvm_be.is_available:
            self.skipTest("LLVM backend unavailable")

        fib_src = """
def llvm_fib(n):
    if n <= 1:
        return n
    a = 0
    b = 1
    for _i in range(2, n + 1):
        a, b = b, a + b
    return b
"""
        ssa_fn = lower_source_to_ssa(fib_src, "llvm_fib", optimize=True)
        ir_str = llvm_be.ssa_to_llvm_ir(ssa_fn)
        self.assertIn("phi i64", ir_str)
        mod = llvm_be.compile_ir(ir_str, optimize=True)
        cfunc = llvm_be.create_jit_callable(mod, "llvm_fib", restype=ctypes.c_int64, argtypes=[ctypes.c_int64])
        self.assertEqual(cfunc(30), 832040)

        # Emit native relocatable .obj/.o from LLVM calling external symbol `@ext_triple`
        caller_src = """
def llvm_caller(x):
    return ext_triple(x) + 7
"""
        caller_ssa = lower_source_to_ssa(caller_src, "llvm_caller", optimize=True)
        caller_ir = llvm_be.ssa_to_llvm_ir(caller_ssa)
        caller_mod = llvm_be.compile_ir(caller_ir, optimize=True)
        obj_bytes = llvm_be.emit_object(caller_mod)

        linker = NativeObjectLinker()
        if sys.platform == "win32":
            linker.add_coff_object(obj_bytes, repo_name="llvm_coff_unit")
        else:
            linker.add_elf_object(obj_bytes, repo_name="llvm_elf_unit")

        # Provide `ext_triple(x) = x * 3` from OmniCompiler's own X64CodeGenerator!
        callee_ssa = lower_source_to_ssa("def ext_triple(x):\n    return x * 3\n", "ext_triple", optimize=True)
        callee_art = X64CodeGenerator().compile_function(callee_ssa)
        provider_mod = ObjectModule("omni_native_unit")
        provider_mod.add_symbol("ext_triple", callee_art.code_bytes, is_exported=True)
        linker.add_module(provider_mod)

        with tempfile.TemporaryDirectory() as td:
            lib_path = linker.emit_linked_shared_library(
                os.path.join(td, "hybrid_llvm_omni"),
                export_name="llvm_caller",
            )
            if sys.platform == "win32":
                lib = ctypes.WinDLL(lib_path)
                try:
                    fn = getattr(lib, "llvm_caller")
                    fn.argtypes = [ctypes.c_int64]
                    fn.restype = ctypes.c_int64
                    self.assertEqual(fn(11), 40)  # 11 * 3 + 7 == 40
                finally:
                    h = lib._handle
                    del fn
                    del lib
                    ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(h))

    # ==========================================================================
    # PILLAR 5: Halide AST Loop Strip-Mining + Hardware AVX2 256-bit YMM Execution
    # ==========================================================================
    def test_05_halide_ast_tiling_and_avx2_ymm_vector_silicon(self):
        tiler = LoopScheduleTiler(l1_cache_bytes=32768)
        raw_loop = """
def sum_squares(n):
    acc = 0
    for i in range(n):
        acc += i * i
    return acc
"""
        tiled_ast = tiler.tile_loop_ast(raw_loop, tile_size=16)
        tiled_code = ast.unparse(tiled_ast)
        self.assertIn("_tile_i", tiled_code)
        self.assertIn("min(_tile_i + 16, n)", tiled_code)

        # Compile the strip-mined 2-level nested loop through Omni-SSA -> Native x86-64 JIT!
        jit = NativeJitCompiler()
        fn_tiled, _mem, _ = jit.compile_function(tiled_ast, "sum_squares")
        expected_sq = sum(i * i for i in range(100))
        self.assertEqual(fn_tiled(100), expected_sq)

        # Execute real VEX-encoded 256-bit AVX2 YMM `vpaddq` over 4,099 elements (vector + scalar tail)
        vec_a = [i * 3 - 500 for i in range(4099)]
        vec_b = [1000 - i for i in range(4099)]
        add_res = tiler.execute_avx2_tiled_vector_add(vec_a, vec_b)
        self.assertEqual(add_res["output"], [a + b for a, b in zip(vec_a, vec_b)])
        self.assertGreaterEqual(add_res["tiles_executed"], 6)

        red_res = tiler.execute_avx2_tiled_reduction(vec_a, vec_b)
        self.assertEqual(red_res["sum"], sum(a + b for a, b in zip(vec_a, vec_b)))

    # ==========================================================================
    # PILLAR 6: DWARF v5 `.debug_line` Round-Trip & Win64 `.pdata`/`.xdata` Unwind
    # ==========================================================================
    def test_06_dwarf_v5_debug_line_and_win64_pdata_unwind(self):
        src = "def calc(n):\n    x = n * 2\n    if x > 10:\n        return x + 1\n    return x - 1\n"
        ssa_fn = lower_source_to_ssa(src, "calc", optimize=False)
        art = X64CodeGenerator(target_os="windows").compile_function(ssa_fn)

        dwarf = DwarfV5Emitter()
        dl_bytes = dwarf.emit_debug_line(
            source_file="F:/repository-compiler/sample_calc.py",
            line_entries=art.line_table,
            code_size=len(art.code_bytes),
            base_address=0x140001000,
        )
        decoded = dwarf.decode_debug_line(dl_bytes)
        self.assertEqual(decoded["version"], 5)
        self.assertIn("sample_calc.py", decoded["files"])
        non_end_rows = [r for r in decoded["rows"] if not r["end_sequence"]]
        self.assertGreaterEqual(len(non_end_rows), 1)
        self.assertEqual(non_end_rows[0]["address"], 0x140001000 + (art.line_table[0][0] if art.line_table else 0))

        pdata, xdata = emit_win64_pdata_xdata(
            func_rva=0x1000,
            code_size=len(art.code_bytes),
            prologue_size=art.prologue_size,
            stack_frame_size=32,
            saved_regs=["rbp"],
        )
        unw = decode_win64_pdata(pdata, xdata)
        self.assertEqual(len(unw), 1)
        self.assertEqual(unw[0]["version"], 1)
        self.assertEqual(unw[0]["frame_register"], 5)  # RBP

        emitter = StandaloneBinaryEmitter()
        dll_bytes = emitter.build_pe64_dll(
            func_code=art.code_bytes,
            export_name="calc",
            pdata_xdata=(pdata, xdata),
        )
        rep = BinaryStructureAuditor().audit_binary(dll_bytes)
        self.assertTrue(rep.is_valid, f"PE DLL with .pdata failed audit: {rep.errors}")
        self.assertIn(".pdata", rep.sections)

    # ==========================================================================
    # PILLAR 7: Sub-Millisecond W^X Jump-Thunk `HotPatchLinkerSession`
    # ==========================================================================
    def test_07_sub_millisecond_wx_hotpatch_linker_session(self):
        x64 = X64CodeGenerator()
        art_k1 = x64.compile_function(lower_source_to_ssa("def hot_kernel(x):\n    return x + 10\n", "hot_kernel"))
        art_caller = x64.compile_function(lower_source_to_ssa("def hot_caller(x):\n    return hot_kernel(x) * 2\n", "hot_caller"))
        art_k2 = x64.compile_function(lower_source_to_ssa("def hot_kernel(x):\n    return x * 100\n", "hot_kernel"))

        session = HotPatchLinkerSession()
        try:
            session.register_or_patch_symbol("hot_kernel", art_k1.code_bytes, art_k1.relocations)
            session.register_or_patch_symbol("hot_caller", art_caller.code_bytes, art_caller.relocations)

            caller_fn = session.get_callable("hot_caller", arity=1)
            self.assertEqual(caller_fn(5), 30)  # (5 + 10) * 2 == 30

            # Live hot-patch `hot_kernel` WITHOUT relinking `hot_caller`!
            patch_meta = session.register_or_patch_symbol("hot_kernel", art_k2.code_bytes, art_k2.relocations)
            self.assertEqual(patch_meta["generation"], 2)
            self.assertLess(patch_meta["latency_ms"], 10.0)
            self.assertEqual(caller_fn(5), 1000)  # (5 * 100) * 2 == 1000!
        finally:
            session.close()

    # ==========================================================================
    # PILLAR 8: Multi-Repo Real AST Codegen, Multi-Export DLL/SO/Dylib,
    #           Apple Silicon CodeSign & Standalone OS `stdout` Executable
    # ==========================================================================
    def test_08_multi_repo_real_codegen_multi_export_codesign_and_stdout_exe(self):
        with tempfile.TemporaryDirectory() as td:
            repo_math = os.path.join(td, "math_engine")
            repo_app = os.path.join(td, "billing_app")
            os.makedirs(repo_math)
            os.makedirs(repo_app)

            with open(os.path.join(repo_math, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("[project]\nname = 'math_engine'\nversion = '1.0.0'\n")
            with open(os.path.join(repo_math, "ops.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def fib_num(n):\n"
                    "    if n <= 1:\n"
                    "        return n\n"
                    "    a, b = 0, 1\n"
                    "    for _k in range(2, n + 1):\n"
                    "        a, b = b, a + b\n"
                    "    return b\n\n"
                    "def gcd_num(a, b):\n"
                    "    while b != 0:\n"
                    "        a, b = b, a % b\n"
                    "    return a\n"
                )

            with open(os.path.join(repo_app, "pyproject.toml"), "w", encoding="utf-8") as f:
                f.write("[project]\nname = 'billing_app'\nversion = '1.0.0'\n")
            with open(os.path.join(repo_app, "service.py"), "w", encoding="utf-8") as f:
                f.write(
                    "from math_engine.ops import fib_num, gcd_num\n\n"
                    "def compute_invoice(units):\n"
                    "    return fib_num(units) + gcd_num(units * 6, 15)\n"
                )

            compiler = OmniRepoCompiler(db_path=os.path.join(td, "multi.db"))
            try:
                # 1. Windows x86-64 Multi-Export DLL + Live ctypes Verification
                dll_out = os.path.join(td, "dist", "unified_suite.dll")
                res_win = compiler.compile_repositories(
                    repo_paths=[repo_math, repo_app],
                    output_path=dll_out,
                    target_format="shared_lib",
                    entry_export="compute_invoice",
                    target_os="windows",
                    target_arch="x86_64",
                    export_all=True,
                )
                self.assertTrue(res_win["success"])
                self.assertEqual(res_win["stages"]["codegen"]["real_ast_functions_compiled"], 3)
                # Unicorn preflight simulated `compute_invoice(10) = fib(10) + gcd(60, 15) = 55 + 15 = 70`!
                self.assertEqual(res_win["stages"]["preflight_safety"]["simulated_return_value"], 70)
                for expected_sym in ("fib_num", "gcd_num", "compute_invoice"):
                    self.assertIn(expected_sym, res_win["stages"]["formal_audit"]["exported_symbols"])

                if sys.platform == "win32":
                    lib = ctypes.WinDLL(res_win["stages"]["emission"]["artifact_path"])
                    try:
                        f_fib = getattr(lib, "fib_num")
                        f_fib.argtypes, f_fib.restype = [ctypes.c_int64], ctypes.c_int64
                        f_gcd = getattr(lib, "gcd_num")
                        f_gcd.argtypes, f_gcd.restype = [ctypes.c_int64, ctypes.c_int64], ctypes.c_int64
                        f_inv = getattr(lib, "compute_invoice")
                        f_inv.argtypes, f_inv.restype = [ctypes.c_int64], ctypes.c_int64

                        self.assertEqual(f_fib(15), 610)
                        self.assertEqual(f_gcd(1071, 462), 21)
                        self.assertEqual(f_inv(10), 70)
                    finally:
                        h = lib._handle
                        del f_fib, f_gcd, f_inv, lib
                        ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(h))

                # 2. Linux x86-64 Multi-Export .so
                so_out = os.path.join(td, "dist", "libunified_suite.so")
                res_lin = compiler.compile_repositories(
                    repo_paths=[repo_math, repo_app],
                    output_path=so_out,
                    target_format="shared_lib",
                    entry_export="compute_invoice",
                    target_os="linux",
                    target_arch="x86_64",
                    export_all=True,
                )
                self.assertTrue(res_lin["success"])
                for expected_sym in ("fib_num", "gcd_num", "compute_invoice"):
                    self.assertIn(expected_sym, res_lin["stages"]["formal_audit"]["exported_symbols"])

                # 3. macOS Apple Silicon ARM64 Multi-Export .dylib + Ad-Hoc LC_CODE_SIGNATURE (SHA-256)
                dylib_out = os.path.join(td, "dist", "libunified_arm64.dylib")
                res_mac = compiler.compile_repositories(
                    repo_paths=[repo_math, repo_app],
                    output_path=dylib_out,
                    target_format="shared_lib",
                    entry_export="compute_invoice",
                    target_os="macos",
                    target_arch="arm64",
                    export_all=True,
                )
                self.assertTrue(res_mac["success"])
                # Unicorn ARM64 preflight ALSO computed `compute_invoice(10) == 70` on ARM64 machine code!
                self.assertEqual(res_mac["stages"]["preflight_safety"]["simulated_return_value"], 70)
                self.assertTrue(res_mac["stages"]["formal_audit"]["metrics"].get("codesign_verified"))
                for expected_sym in ("fib_num", "gcd_num", "compute_invoice"):
                    self.assertIn(expected_sym, res_mac["stages"]["formal_audit"]["exported_symbols"])
            finally:
                compiler.cpg.close()

            # 4. Standalone OS `stdout` Console Executable
            if sys.platform == "win32":
                stdout_exe = StandaloneBinaryEmitter().emit_stdout_executable(
                    os.path.join(td, "dist", "hello_silicon.exe"),
                    message="OMNICOMPILER_SILICON_STDOUT_OK\n",
                    target_format="pe64",
                    exit_code=0,
                )
                cp = subprocess.run([stdout_exe], capture_output=True, text=True, timeout=5)
                self.assertEqual(cp.returncode, 0)
                self.assertEqual(cp.stdout.replace("\r\n", "\n"), "OMNICOMPILER_SILICON_STDOUT_OK\n")

    # ==========================================================================
    # PILLAR 9: Persistent Node.js V8 Daemon + WASI Preview 2 Canonical ABI & Fuel
    # ==========================================================================
    def test_09_persistent_node_daemon_and_wasi_preview2_canonical_abi(self):
        # 1. Persistent Node.js Keep-Alive JSON-RPC Pipe Bridge
        node_bin = shutil.which("node") or r"C:\Program Files\nodejs\node.exe"
        if os.path.exists(node_bin):
            with tempfile.TemporaryDirectory() as td:
                js_path = os.path.join(td, "fast_math.js")
                with open(js_path, "w", encoding="utf-8") as f:
                    f.write("exports.blendScore = (x, y) => (x * 100) + y;\n")

                cap = CapabilityContract(
                    schema_version="0.1",
                    capability_id="cap_node_fast",
                    source_repo_id="node_repo",
                    entrypoint={"file_path": js_path, "operation": "blendScore", "language": "javascript"},
                    input_schema={"x": "int", "y": "int"},
                    output_schema={"result": "int"},
                    effects=[],
                    requires=[],
                    protocol={"type": "direct_call"},
                    evidence=[],
                    unknowns=[],
                )
                synth = AdapterSynthesizer()
                cand = synth.synthesize_adapter({"adapter_id": "fast_node_bridge", "requirement": "req_score"}, cap)

                ns: dict = {}
                exec(cand.code_content, ns)
                bridge = ns["FastNodeBridge"]()
                try:
                    # Warm-up initial worker boot
                    self.assertEqual(bridge.execute(x=4, y=19), 419)
                    # Measure 25 warm RPC calls over persistent pipe
                    t0 = time.perf_counter()
                    for k in range(25):
                        self.assertEqual(bridge.execute(x=k, y=7), k * 100 + 7)
                    avg_ms = ((time.perf_counter() - t0) * 1000.0) / 25.0
                    self.assertLess(avg_ms, 10.0, f"Expected <10 ms/call warm Node pipe RPC, got {avg_ms:.2f} ms")
                finally:
                    bridge.close()

        # 2. WASI Preview 2 WIT Parser + Multi-Block WAT + Fuel Metering + Canonical ABI
        wit_spec = """
        package omnicompiler:text-engine@2.0.0;
        interface transform {
            uppercase: func(input: string) -> string;
            sum-items: func(values: list<s64>) -> s64;
        }
        world omni-capsule {
            export transform;
        }
        """
        parsed_wit = parse_wit_world(wit_spec)
        self.assertEqual(parsed_wit["package"], "omnicompiler:text-engine")
        self.assertEqual(parsed_wit["version"], "2.0.0")
        self.assertEqual(len(parsed_wit["interfaces"]["transform"]), 2)

        wasm = WasmBackend()
        if wasm.is_available:
            fib_ssa = lower_source_to_ssa(
                "def wasm_fib(n):\n"
                "    if n <= 1:\n"
                "        return n\n"
                "    a, b = 0, 1\n"
                "    i = 2\n"
                "    while i <= n:\n"
                "        a, b = b, a + b\n"
                "        i += 1\n"
                "    return b\n",
                "wasm_fib",
                optimize=True,
            )
            wat_fib = wasm.ssa_to_wat(fib_ssa)
            tel = wasm.execute_wasm_with_telemetry(wat_fib, "wasm_fib", args=[20], fuel_budget=50000)
            self.assertEqual(tel["result"], 6765)
            self.assertGreater(tel["fuel_consumed"], 10)

            # Infinite loop MUST trap deterministically when fuel runs out
            inf_wat = "(module (func (export \"spin\") (result i64) (loop $l (br $l)) (i64.const 0)))"
            with self.assertRaises(Exception):
                wasm.execute_wasm(inf_wat, "spin", fuel_budget=250)

            # Canonical ABI (`cabi_realloc` + Linear Memory UTF-8 string & `list<s64>` marshalling)
            upper_out = wasm.execute_canonical_string_call("omnicompiler_wasi_preview2_ok!", operation="uppercase")
            self.assertEqual(upper_out, "OMNICOMPILER_WASI_PREVIEW2_OK!")

            h1 = wasm.execute_canonical_string_call("deterministic_seed", operation="fnv1a64")
            h2 = wasm.execute_canonical_string_call("deterministic_seed", operation="fnv1a64")
            self.assertEqual(h1, h2)

            slice_sum = wasm.execute_canonical_s64_list_sum([100, -25, 400, 1025, -500])
            self.assertEqual(slice_sum, 1000)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestCeilingEngineeringComplete)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
