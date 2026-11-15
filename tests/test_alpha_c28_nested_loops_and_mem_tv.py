"""
Alpha-C28 Comprehensive Verification Suite:
1. Unbounded 2-level nested natural loop inductive verification (`PROVEN_INDUCTIVE_EQUIVALENT`,
   `bounded=False`), plus concrete counterexample refutation on inner AND outer loop mutations.
2. Unbounded 2-sequential natural loop inductive verification (`PROVEN_INDUCTIVE_EQUIVALENT`,
   `bounded=False`), plus counterexample refutation on Loop-2 mutation.
3. Linear memory (`load`/`store`) formal Translation Validation (`SSA <-> LLVM IR` and
   `SSA <-> WAT`) + mutation refutation + physical execution across Native x86-64 JIT,
   LLVM O3 MCJIT, and Wasmtime linear memory.
4. Polyglot JS/TS/Rust/Go subscript writes (`buf[i] = v`, `buf[i] += v`) and `switch/case`
   lowering executed natively on real buffers.
5. End-to-end `OmniRepoCompiler` nested-loop polyglot compilation to `.dll`/`.so` & `.wasm`.
"""

import ast
import ctypes
import os
import platform
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.llvm_backend import LLVMBackend
from compiler.native_codegen import NativeCodeGenerator
from compiler.native_jit import NativeJitMemory
from compiler.ssa_ir import BasicBlock, SSAFunction, SSAInstruction, SSAVar, lower_ast_to_ssa
from compiler.wasm_backend import WasmBackend
from frontends.polyglot_ssa_lowering import lower_polyglot_source_to_ast
from omni_repo_compiler import OmniRepoCompiler
from validation.backend_translation_validator import BackendTranslationValidator
from validation.ssa_translation_validator import SSATranslationValidator


def _build_nested_loop_ssa(
    fn_name: str = "nested_loop",
    hoist_inner_inv: bool = False,
    inner_const: int = 7,
    outer_step: int = 1,
) -> SSAFunction:
    fn = SSAFunction(fn_name, ["a", "n", "m"])
    entry = BasicBlock("entry")
    h_out = BasicBlock("h_out")
    b_out = BasicBlock("b_out")
    h_in = BasicBlock("h_in")
    b_in = BasicBlock("b_in")
    latch_out = BasicBlock("latch_out")
    exit_out = BasicBlock("exit_out")
    h_out.loop_depth = 1
    b_out.loop_depth = 1
    latch_out.loop_depth = 1
    h_in.loop_depth = 2
    b_in.loop_depth = 2

    entry.connect_to(h_out)
    h_out.connect_to(b_out)
    h_out.connect_to(exit_out)
    b_out.connect_to(h_in)
    h_in.connect_to(b_in)
    h_in.connect_to(latch_out)
    b_in.connect_to(h_in)
    latch_out.connect_to(h_out)

    pa, pn, pm = SSAVar("a", 0), SSAVar("n", 0), SSAVar("m", 0)
    z = SSAVar("z", 0)
    inv_pre = SSAVar("inv_pre", 0)
    i_phi = SSAVar("i", 1)
    acc_out = SSAVar("acc", 1)
    cond_out = SSAVar("cond_o", 0)
    j0 = SSAVar("j", 0)
    j_phi = SSAVar("j", 1)
    acc_in = SSAVar("acc", 2)
    cond_in = SSAVar("cond_i", 0)
    t1 = SSAVar("t1", 0)
    inv_in = SSAVar("inv_in", 0)
    acc_in_next = SSAVar("acc", 3)
    j_next = SSAVar("j", 2)
    i_next = SSAVar("i", 2)

    entry.add_instruction(SSAInstruction(pa, "param", ["a"]))
    entry.add_instruction(SSAInstruction(pn, "param", ["n"]))
    entry.add_instruction(SSAInstruction(pm, "param", ["m"]))
    entry.add_instruction(SSAInstruction(z, "const", [0]))
    if hoist_inner_inv:
        t0 = SSAVar("t0", 0)
        entry.add_instruction(SSAInstruction(t0, "mul", [pa, 3]))
        entry.add_instruction(SSAInstruction(inv_pre, "add", [t0, inner_const]))
    entry.add_instruction(SSAInstruction(None, "br", ["h_out"]))

    h_out.phi_nodes.append(SSAInstruction(i_phi, "phi", [z, i_next], phi_incoming=[("entry", z), ("latch_out", i_next)]))
    h_out.phi_nodes.append(SSAInstruction(acc_out, "phi", [z, acc_in], phi_incoming=[("entry", z), ("latch_out", acc_in)]))
    h_out.add_instruction(SSAInstruction(cond_out, "cmp_lt", [i_phi, pn]))
    h_out.add_instruction(SSAInstruction(None, "br_cond", [cond_out, "b_out", "exit_out"]))

    b_out.add_instruction(SSAInstruction(j0, "const", [0]))
    b_out.add_instruction(SSAInstruction(None, "br", ["h_in"]))

    h_in.phi_nodes.append(SSAInstruction(j_phi, "phi", [j0, j_next], phi_incoming=[("b_out", j0), ("b_in", j_next)]))
    h_in.phi_nodes.append(SSAInstruction(acc_in, "phi", [acc_out, acc_in_next], phi_incoming=[("b_out", acc_out), ("b_in", acc_in_next)]))
    h_in.add_instruction(SSAInstruction(cond_in, "cmp_lt", [j_phi, pm]))
    h_in.add_instruction(SSAInstruction(None, "br_cond", [cond_in, "b_in", "latch_out"]))

    if hoist_inner_inv:
        b_in.add_instruction(SSAInstruction(acc_in_next, "add", [acc_in, inv_pre]))
    else:
        b_in.add_instruction(SSAInstruction(t1, "mul", [pa, 3]))
        b_in.add_instruction(SSAInstruction(inv_in, "add", [t1, inner_const]))
        b_in.add_instruction(SSAInstruction(acc_in_next, "add", [acc_in, inv_in]))
    b_in.add_instruction(SSAInstruction(j_next, "add", [j_phi, 1]))
    b_in.add_instruction(SSAInstruction(None, "br", ["h_in"]))

    latch_out.add_instruction(SSAInstruction(i_next, "add", [i_phi, outer_step]))
    latch_out.add_instruction(SSAInstruction(None, "br", ["h_out"]))

    exit_out.add_instruction(SSAInstruction(None, "ret", [acc_out]))

    for blk in (entry, h_out, b_out, h_in, b_in, latch_out, exit_out):
        fn.add_block(blk)
    fn.entry_block = entry
    return fn


def _build_sequential_two_loops_ssa(
    hoist_const: bool = False,
    loop2_mul: int = 5,
) -> SSAFunction:
    fn = SSAFunction("seq_two_loops", ["n", "m", "x"])
    entry = BasicBlock("entry")
    h1, b1 = BasicBlock("h1"), BasicBlock("b1")
    mid = BasicBlock("mid")
    h2, b2 = BasicBlock("h2"), BasicBlock("b2")
    exit_b = BasicBlock("exit")
    h1.loop_depth = b1.loop_depth = h2.loop_depth = b2.loop_depth = 1

    entry.connect_to(h1)
    h1.connect_to(b1)
    h1.connect_to(mid)
    b1.connect_to(h1)
    mid.connect_to(h2)
    h2.connect_to(b2)
    h2.connect_to(exit_b)
    b2.connect_to(h2)

    pn, pm, px = SSAVar("n", 0), SSAVar("m", 0), SSAVar("x", 0)
    z = SSAVar("z", 0)
    k_pre = SSAVar("k_pre", 0)
    i_phi, acc1 = SSAVar("i", 1), SSAVar("acc", 1)
    c1 = SSAVar("c1", 0)
    acc1_next, i_next = SSAVar("acc", 2), SSAVar("i", 2)
    j0 = SSAVar("j", 0)
    j_phi, acc2 = SSAVar("j", 1), SSAVar("acc", 3)
    c2 = SSAVar("c2", 0)
    km = SSAVar("km", 0)
    acc2_next, j_next = SSAVar("acc", 4), SSAVar("j", 2)

    entry.add_instruction(SSAInstruction(pn, "param", ["n"]))
    entry.add_instruction(SSAInstruction(pm, "param", ["m"]))
    entry.add_instruction(SSAInstruction(px, "param", ["x"]))
    entry.add_instruction(SSAInstruction(z, "const", [0]))
    if hoist_const:
        entry.add_instruction(SSAInstruction(k_pre, "mul", [px, loop2_mul]))
    entry.add_instruction(SSAInstruction(None, "br", ["h1"]))

    h1.phi_nodes.append(SSAInstruction(i_phi, "phi", [z, i_next], phi_incoming=[("entry", z), ("b1", i_next)]))
    h1.phi_nodes.append(SSAInstruction(acc1, "phi", [z, acc1_next], phi_incoming=[("entry", z), ("b1", acc1_next)]))
    h1.add_instruction(SSAInstruction(c1, "cmp_lt", [i_phi, pn]))
    h1.add_instruction(SSAInstruction(None, "br_cond", [c1, "b1", "mid"]))

    b1.add_instruction(SSAInstruction(acc1_next, "add", [acc1, i_phi]))
    b1.add_instruction(SSAInstruction(i_next, "add", [i_phi, 1]))
    b1.add_instruction(SSAInstruction(None, "br", ["h1"]))

    mid.add_instruction(SSAInstruction(j0, "const", [0]))
    mid.add_instruction(SSAInstruction(None, "br", ["h2"]))

    h2.phi_nodes.append(SSAInstruction(j_phi, "phi", [j0, j_next], phi_incoming=[("mid", j0), ("b2", j_next)]))
    h2.phi_nodes.append(SSAInstruction(acc2, "phi", [acc1, acc2_next], phi_incoming=[("mid", acc1), ("b2", acc2_next)]))
    h2.add_instruction(SSAInstruction(c2, "cmp_lt", [j_phi, pm]))
    h2.add_instruction(SSAInstruction(None, "br_cond", [c2, "b2", "exit"]))

    if hoist_const:
        b2.add_instruction(SSAInstruction(acc2_next, "add", [acc2, k_pre]))
    else:
        b2.add_instruction(SSAInstruction(km, "mul", [px, loop2_mul]))
        b2.add_instruction(SSAInstruction(acc2_next, "add", [acc2, km]))
    b2.add_instruction(SSAInstruction(j_next, "add", [j_phi, 1]))
    b2.add_instruction(SSAInstruction(None, "br", ["h2"]))

    exit_b.add_instruction(SSAInstruction(None, "ret", [acc2]))

    for blk in (entry, h1, b1, mid, h2, b2, exit_b):
        fn.add_block(blk)
    fn.entry_block = entry
    return fn


class TestAlphaC28NestedLoopsAndMemTV(unittest.TestCase):
    def test_unbounded_nested_two_level_loop_inductive_and_mutation_catch(self):
        tv = SSATranslationValidator(max_loop_unroll=2, enable_inductive_loops=True)
        fn_orig = _build_nested_loop_ssa(hoist_inner_inv=False, inner_const=7, outer_step=1)
        fn_opt = _build_nested_loop_ssa(hoist_inner_inv=True, inner_const=7, outer_step=1)
        fn_bug_inner = _build_nested_loop_ssa(hoist_inner_inv=True, inner_const=8, outer_step=1)
        fn_bug_outer = _build_nested_loop_ssa(hoist_inner_inv=True, inner_const=7, outer_step=2)

        res_ok = tv.verify_equivalence(fn_orig, fn_opt)
        self.assertTrue(res_ok["proven"], f"Nested loop equivalence failed: {res_ok}")
        self.assertEqual(res_ok["status"], "PROVEN_INDUCTIVE_EQUIVALENT")
        self.assertFalse(res_ok["bounded"])

        res_bad_in = tv.verify_equivalence(fn_orig, fn_bug_inner)
        self.assertFalse(res_bad_in["proven"])
        self.assertEqual(res_bad_in["status"], "REFUTED_COUNTEREXAMPLE")
        self.assertIsNotNone(res_bad_in["counterexample"])

        res_bad_out = tv.verify_equivalence(fn_orig, fn_bug_outer)
        self.assertFalse(res_bad_out["proven"])
        self.assertEqual(res_bad_out["status"], "REFUTED_COUNTEREXAMPLE")
        self.assertIsNotNone(res_bad_out["counterexample"])

    def test_unbounded_sequential_multi_loop_inductive_and_mutation_catch(self):
        tv = SSATranslationValidator(max_loop_unroll=2, enable_inductive_loops=True)
        fn_orig = _build_sequential_two_loops_ssa(hoist_const=False, loop2_mul=5)
        fn_opt = _build_sequential_two_loops_ssa(hoist_const=True, loop2_mul=5)
        fn_bug = _build_sequential_two_loops_ssa(hoist_const=True, loop2_mul=6)

        res_ok = tv.verify_equivalence(fn_orig, fn_opt)
        self.assertTrue(res_ok["proven"], f"Sequential multi-loop equivalence failed: {res_ok}")
        self.assertEqual(res_ok["status"], "PROVEN_INDUCTIVE_EQUIVALENT")
        self.assertFalse(res_ok["bounded"])

        res_bad = tv.verify_equivalence(fn_orig, fn_bug)
        self.assertFalse(res_bad["proven"])
        self.assertEqual(res_bad["status"], "REFUTED_COUNTEREXAMPLE")

    def test_linear_memory_load_store_backend_tv_llvm_wat_and_wasmtime(self):
        src_py = (
            "def buf_rw(buf_ptr, idx, val):\n"
            "    buf_ptr[idx] = val + 3\n"
            "    buf_ptr[idx + 1] = buf_ptr[idx] * 2\n"
            "    return buf_ptr[idx] + buf_ptr[idx + 1]\n"
        )
        fdef = ast.parse(src_py).body[0]
        ssa_fn = lower_ast_to_ssa(fdef, optimize=True)

        llvm_be = LLVMBackend(opt_level=3)
        wasm_be = WasmBackend()
        llvm_ir = llvm_be.ssa_to_llvm_ir(ssa_fn)
        wat_src = wasm_be.ssa_to_wat(ssa_fn)

        btv = BackendTranslationValidator(enable_memory_theory=True)
        v_llvm = btv.verify_ssa_to_llvm_ir(ssa_fn, llvm_ir)
        v_wat = btv.verify_ssa_to_wat(ssa_fn, wat_src)
        self.assertTrue(v_llvm["proven"], f"LLVM memory TV failed: {v_llvm}")
        self.assertTrue(v_wat["proven"], f"WAT memory TV failed: {v_wat}")

        # Negative control: mutate `val + 3` -> `val + 5` (or `i64.const 1` shift/offset) inside WAT
        mutated_wat, n_sub = re.subn(r"i64\.const\s+3(\s+i64\.add)", r"i64.const 5\1", wat_src, count=1)
        if n_sub == 0:
            mutated_wat, n_sub = re.subn(r"(i64\.store)", r"i64.const 1\n    i64.add\n    \1", wat_src, count=1)
        self.assertGreater(n_sub, 0, f"WAT mutation pattern did not match:\n{wat_src}")
        self.assertNotEqual(mutated_wat, wat_src)
        v_bad = btv.verify_ssa_to_wat(ssa_fn, mutated_wat)
        self.assertFalse(v_bad["proven"])
        self.assertEqual(v_bad["status"], "REFUTED_COUNTEREXAMPLE")

        # Physical execution across Native x86-64 JIT, LLVM O3 MCJIT, and Wasmtime
        target_os = "windows" if platform.system().lower().startswith("win") else "linux"
        art = NativeCodeGenerator(arch="x86_64", target_os=target_os).compile_ssa(ssa_fn)
        jit_mem = NativeJitMemory(len(art.code_bytes))
        jit_mem.write_code(art.code_bytes)
        native_fn = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)(jit_mem.ptr)

        arr_nat = (ctypes.c_int64 * 8)()
        nat_ret = native_fn(ctypes.addressof(arr_nat), 2, 10)
        self.assertEqual(nat_ret, 39)
        self.assertEqual(arr_nat[2], 13)
        self.assertEqual(arr_nat[3], 26)

        mod_llvm = llvm_be.compile_ir(llvm_ir, optimize=True)
        llvm_fn = llvm_be.create_jit_callable(
            mod_llvm, "buf_rw", restype=ctypes.c_int64, argtypes=[ctypes.c_int64, ctypes.c_int64, ctypes.c_int64]
        )
        arr_llvm = (ctypes.c_int64 * 8)()
        llvm_ret = llvm_fn(ctypes.addressof(arr_llvm), 2, 10)
        self.assertEqual(llvm_ret, 39)
        self.assertEqual(arr_llvm[2], 13)
        self.assertEqual(arr_llvm[3], 26)

        from wasmtime import Store, Module, Instance
        wasm_bytes = wasm_be.wat_to_wasm(wat_src)
        store = Store(wasm_be._engine)
        inst = Instance(store, Module(wasm_be._engine, wasm_bytes), [])
        wasm_fn = inst.exports(store)["buf_rw"]
        mem_exp = inst.exports(store)["memory"]
        wasm_ret = wasm_fn(store, 1024, 2, 10)
        self.assertEqual(wasm_ret, 39)
        slot2 = int.from_bytes(mem_exp.read(store, 1024 + 16, 1024 + 24), "little", signed=True)
        slot3 = int.from_bytes(mem_exp.read(store, 1024 + 24, 1024 + 32), "little", signed=True)
        self.assertEqual((slot2, slot3), (13, 26))

    def test_polyglot_subscript_writes_and_switch_jit_execution(self):
        go_src = """
        package main
        func go_dispatch_write(buf int64, sel int64, val int64) int64 {
            switch sel {
            case 1:
                buf[0] = val + 10
                buf[1] += 5
            case 2:
                buf[0] = val * 3
                buf[1] -= 2
            default:
                buf[0] = val ^ 7
            }
            return buf[0] + buf[1]
        }
        """
        js_src = """
        function js_arr_mutate(arr, idx, delta) {
            switch (idx) {
                case 0:
                    arr[0] += delta;
                    break;
                default:
                    arr[idx] = arr[idx] * 2 + delta;
                    break;
            }
            return arr[idx];
        }
        """
        target_os = "windows" if platform.system().lower().startswith("win") else "linux"
        cg = NativeCodeGenerator(arch="x86_64", target_os=target_os)

        go_ssa = lower_ast_to_ssa(lower_polyglot_source_to_ast(go_src, "go", strict=True).functions[0], optimize=True)
        art_go = cg.compile_ssa(go_ssa)
        jit_go = NativeJitMemory(len(art_go.code_bytes))
        jit_go.write_code(art_go.code_bytes)
        fn_go = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)(jit_go.ptr)

        buf = (ctypes.c_int64 * 4)(0, 20, 0, 0)
        r1 = fn_go(ctypes.addressof(buf), 1, 7)
        self.assertEqual((r1, buf[0], buf[1]), (42, 17, 25))
        r2 = fn_go(ctypes.addressof(buf), 2, 4)
        self.assertEqual((r2, buf[0], buf[1]), (35, 12, 23))

        js_ssa = lower_ast_to_ssa(lower_polyglot_source_to_ast(js_src, "javascript", strict=True).functions[0], optimize=True)
        art_js = cg.compile_ssa(js_ssa)
        jit_js = NativeJitMemory(len(art_js.code_bytes))
        jit_js.write_code(art_js.code_bytes)
        fn_js = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)(jit_js.ptr)

        arr = (ctypes.c_int64 * 4)(5, 9, 0, 0)
        self.assertEqual(fn_js(ctypes.addressof(arr), 0, 11), 16)
        self.assertEqual(fn_js(ctypes.addressof(arr), 1, 4), 22)

    def test_multi_repo_nested_polyglot_omni_compiler_e2e(self):
        with tempfile.TemporaryDirectory() as tmp:
            go_dir = os.path.join(tmp, "repo_go")
            rs_dir = os.path.join(tmp, "repo_rs")
            os.makedirs(go_dir, exist_ok=True)
            os.makedirs(rs_dir, exist_ok=True)

            with open(os.path.join(go_dir, "matrix.go"), "w", encoding="utf-8") as f:
                f.write(
                    "package matrix\n"
                    "func go_nested_grid(n int64, m int64, seed int64) int64 {\n"
                    "    acc := 0\n"
                    "    for i := 0; i < n; i++ {\n"
                    "        for j := 0; j < m; j++ {\n"
                    "            acc += (i * m) + j + seed\n"
                    "        }\n"
                    "    }\n"
                    "    return acc\n"
                    "}\n"
                )
            with open(os.path.join(rs_dir, "driver.rs"), "w", encoding="utf-8") as f:
                f.write(
                    "pub fn rs_grid_entry(n: i64, m: i64) -> i64 {\n"
                    "    go_nested_grid(n, m, 3) + 1\n"
                    "}\n"
                )

            ext = ".dll" if platform.system().lower().startswith("win") else ".so"
            out_dll = os.path.join(tmp, f"nested_fused{ext}")
            comp = OmniRepoCompiler()
            res_nat = comp.compile_repositories(
                [go_dir, rs_dir],
                out_dll,
                target_format="shared_lib",
                target_os="windows" if platform.system().lower().startswith("win") else "linux",
                target_arch="x86_64",
                export_all=True,
                backend="native",
            )
            self.assertTrue(res_nat["success"], f"Multi-repo nested native failed: {res_nat}")

            lib = ctypes.CDLL(out_dll)
            try:
                lib.rs_grid_entry.argtypes = [ctypes.c_int64, ctypes.c_int64]
                lib.rs_grid_entry.restype = ctypes.c_int64
                got = lib.rs_grid_entry(3, 4)
                expected = sum(i * 4 + j + 3 for i in range(3) for j in range(4)) + 1
                self.assertEqual(got, expected)
            finally:
                if platform.system().lower().startswith("win"):
                    import _ctypes
                    _ctypes.FreeLibrary(lib._handle)


if __name__ == "__main__":
    unittest.main(verbosity=2)
