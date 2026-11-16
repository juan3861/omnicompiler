"""
Alpha-C29 Comprehensive Verification Suite:
1. Generalized N-level recursive loop-tree inductive verification:
   - Unbounded 3-level triple nested loop equivalence (`PROVEN_INDUCTIVE_EQUIVALENT`,
     `bounded=False`) + refutation on mutations at depth 1, depth 2, and depth 3.
   - Hybrid CFG (outer loop containing 2 sequential inner loops) unbounded proof + mutation catch.
2. Polyglot extensions (`frontends/polyglot_ssa_lowering.py`):
   - JS/TS arrow functions (`const fn = (a, b) => ...`, `exports.blendScore = (x, y) => ...`)
   - Rust `match` statements/tails (`1 | 2 => ...`, `{ block }`, `_ => ...`)
   - JS/TS `do { ... } while (cond);`
   - Go multi-var tuple initialization & atomic swap (`a, b := 0, 1; a, b = b, a + b`) & JS comma decls
   Verified via LLVM/WAT formal TV and physical Native x86-64 JIT == LLVM O3 == Wasmtime execution.
3. Multi-repo polyglot fusion (TS Arrow + Rust Match + Go Tuple) through `OmniRepoCompiler`.
4. Zero `ResourceWarning`s on `FastNodeBridge.close()` (`adapters/synthesizer.py`).
"""

import ctypes
import os
import platform
import sys
import tempfile
import unittest
import warnings

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.llvm_backend import LLVMBackend
from compiler.ssa_ir import BasicBlock, SSAFunction, SSAInstruction, SSAVar, lower_ast_to_ssa
from compiler.wasm_backend import WasmBackend
from frontends.polyglot_ssa_lowering import lower_polyglot_source_to_ast
from omni_repo_compiler import OmniRepoCompiler
from validation.backend_translation_validator import BackendTranslationValidator
from validation.ssa_translation_validator import SSATranslationValidator


def _build_triple_nested_ssa(
    hoist_inv: bool = False,
    depth3_const: int = 11,
    depth2_step: int = 1,
    depth1_step: int = 1,
) -> SSAFunction:
    fn = SSAFunction("triple_nested", ["a", "n", "m", "p"])
    entry = BasicBlock("entry")
    h1, b1, l1, ex1 = BasicBlock("h1"), BasicBlock("b1"), BasicBlock("l1"), BasicBlock("ex1")
    h2, b2, l2 = BasicBlock("h2"), BasicBlock("b2"), BasicBlock("l2")
    h3, b3 = BasicBlock("h3"), BasicBlock("b3")

    entry.connect_to(h1)
    h1.connect_to(b1)
    h1.connect_to(ex1)
    b1.connect_to(h2)
    h2.connect_to(b2)
    h2.connect_to(l1)
    b2.connect_to(h3)
    h3.connect_to(b3)
    h3.connect_to(l2)
    b3.connect_to(h3)
    l2.connect_to(h2)
    l1.connect_to(h1)

    pa, pn, pm, pp = SSAVar("a", 0), SSAVar("n", 0), SSAVar("m", 0), SSAVar("p", 0)
    z = SSAVar("z", 0)
    inv_pre = SSAVar("inv_pre", 0)

    i_phi, acc1 = SSAVar("i", 1), SSAVar("acc", 1)
    c1, i_next = SSAVar("c1", 0), SSAVar("i", 2)

    j0, j_phi, acc2 = SSAVar("j", 0), SSAVar("j", 1), SSAVar("acc", 2)
    c2, j_next = SSAVar("c2", 0), SSAVar("j", 2)

    k0, k_phi, acc3 = SSAVar("k", 0), SSAVar("k", 1), SSAVar("acc", 3)
    c3, k_next = SSAVar("c3", 0), SSAVar("k", 2)
    t1, inv3, acc3_next = SSAVar("t1", 0), SSAVar("inv3", 0), SSAVar("acc", 4)

    entry.add_instruction(SSAInstruction(pa, "param", ["a"]))
    entry.add_instruction(SSAInstruction(pn, "param", ["n"]))
    entry.add_instruction(SSAInstruction(pm, "param", ["m"]))
    entry.add_instruction(SSAInstruction(pp, "param", ["p"]))
    entry.add_instruction(SSAInstruction(z, "const", [0]))
    if hoist_inv:
        t0 = SSAVar("t0", 0)
        entry.add_instruction(SSAInstruction(t0, "mul", [pa, 5]))
        entry.add_instruction(SSAInstruction(inv_pre, "add", [t0, depth3_const]))
    entry.add_instruction(SSAInstruction(None, "br", ["h1"]))

    h1.phi_nodes.append(SSAInstruction(i_phi, "phi", [z, i_next], phi_incoming=[("entry", z), ("l1", i_next)]))
    h1.phi_nodes.append(SSAInstruction(acc1, "phi", [z, acc2], phi_incoming=[("entry", z), ("l1", acc2)]))
    h1.add_instruction(SSAInstruction(c1, "cmp_lt", [i_phi, pn]))
    h1.add_instruction(SSAInstruction(None, "br_cond", [c1, "b1", "ex1"]))

    b1.add_instruction(SSAInstruction(j0, "const", [0]))
    b1.add_instruction(SSAInstruction(None, "br", ["h2"]))

    h2.phi_nodes.append(SSAInstruction(j_phi, "phi", [j0, j_next], phi_incoming=[("b1", j0), ("l2", j_next)]))
    h2.phi_nodes.append(SSAInstruction(acc2, "phi", [acc1, acc3], phi_incoming=[("b1", acc1), ("l2", acc3)]))
    h2.add_instruction(SSAInstruction(c2, "cmp_lt", [j_phi, pm]))
    h2.add_instruction(SSAInstruction(None, "br_cond", [c2, "b2", "l1"]))

    b2.add_instruction(SSAInstruction(k0, "const", [0]))
    b2.add_instruction(SSAInstruction(None, "br", ["h3"]))

    h3.phi_nodes.append(SSAInstruction(k_phi, "phi", [k0, k_next], phi_incoming=[("b2", k0), ("b3", k_next)]))
    h3.phi_nodes.append(SSAInstruction(acc3, "phi", [acc2, acc3_next], phi_incoming=[("b2", acc2), ("b3", acc3_next)]))
    h3.add_instruction(SSAInstruction(c3, "cmp_lt", [k_phi, pp]))
    h3.add_instruction(SSAInstruction(None, "br_cond", [c3, "b3", "l2"]))

    if hoist_inv:
        b3.add_instruction(SSAInstruction(acc3_next, "add", [acc3, inv_pre]))
    else:
        b3.add_instruction(SSAInstruction(t1, "mul", [pa, 5]))
        b3.add_instruction(SSAInstruction(inv3, "add", [t1, depth3_const]))
        b3.add_instruction(SSAInstruction(acc3_next, "add", [acc3, inv3]))
    b3.add_instruction(SSAInstruction(k_next, "add", [k_phi, 1]))
    b3.add_instruction(SSAInstruction(None, "br", ["h3"]))

    l2.add_instruction(SSAInstruction(j_next, "add", [j_phi, depth2_step]))
    l2.add_instruction(SSAInstruction(None, "br", ["h2"]))

    l1.add_instruction(SSAInstruction(i_next, "add", [i_phi, depth1_step]))
    l1.add_instruction(SSAInstruction(None, "br", ["h1"]))

    ex1.add_instruction(SSAInstruction(None, "ret", [acc1]))

    for blk in (entry, h1, b1, h2, b2, h3, b3, l2, l1, ex1):
        fn.add_block(blk)
    fn.entry_block = entry
    return fn


def _build_hybrid_nested_seq_inner_ssa(hoist_k: bool = False, inner2_bias: int = 3) -> SSAFunction:
    """
    Outer loop `i < n` containing TWO sequential inner loops:
      1) `j < m`: acc += 1
      2) `k < p`: acc += x * 2 + inner2_bias
    """
    fn = SSAFunction("hybrid_outer_two_inners", ["n", "m", "p", "x"])
    entry = BasicBlock("entry")
    ho, bo, mid, lout, exo = BasicBlock("ho"), BasicBlock("bo"), BasicBlock("mid"), BasicBlock("lout"), BasicBlock("exo")
    ha, ba = BasicBlock("ha"), BasicBlock("ba")
    hb, bb = BasicBlock("hb"), BasicBlock("bb")

    entry.connect_to(ho)
    ho.connect_to(bo)
    ho.connect_to(exo)
    bo.connect_to(ha)
    ha.connect_to(ba)
    ha.connect_to(mid)
    ba.connect_to(ha)
    mid.connect_to(hb)
    hb.connect_to(bb)
    hb.connect_to(lout)
    bb.connect_to(hb)
    lout.connect_to(ho)

    pn, pm, pp, px = SSAVar("n", 0), SSAVar("m", 0), SSAVar("p", 0), SSAVar("x", 0)
    z = SSAVar("z", 0)
    inv_pre = SSAVar("inv_pre", 0)
    i_phi, acc_o = SSAVar("i", 1), SSAVar("acc", 1)
    co, i_next = SSAVar("co", 0), SSAVar("i", 2)

    j0, j_phi, acc_a = SSAVar("j", 0), SSAVar("j", 1), SSAVar("acc", 2)
    ca, j_next, acc_a_next = SSAVar("ca", 0), SSAVar("j", 2), SSAVar("acc", 3)

    k0, k_phi, acc_b = SSAVar("k", 0), SSAVar("k", 1), SSAVar("acc", 4)
    cb, k_next, acc_b_next = SSAVar("cb", 0), SSAVar("k", 2), SSAVar("acc", 5)
    tb, invb = SSAVar("tb", 0), SSAVar("invb", 0)

    entry.add_instruction(SSAInstruction(pn, "param", ["n"]))
    entry.add_instruction(SSAInstruction(pm, "param", ["m"]))
    entry.add_instruction(SSAInstruction(pp, "param", ["p"]))
    entry.add_instruction(SSAInstruction(px, "param", ["x"]))
    entry.add_instruction(SSAInstruction(z, "const", [0]))
    if hoist_k:
        t0 = SSAVar("t0", 0)
        entry.add_instruction(SSAInstruction(t0, "mul", [px, 2]))
        entry.add_instruction(SSAInstruction(inv_pre, "add", [t0, inner2_bias]))
    entry.add_instruction(SSAInstruction(None, "br", ["ho"]))

    ho.phi_nodes.append(SSAInstruction(i_phi, "phi", [z, i_next], phi_incoming=[("entry", z), ("lout", i_next)]))
    ho.phi_nodes.append(SSAInstruction(acc_o, "phi", [z, acc_b], phi_incoming=[("entry", z), ("lout", acc_b)]))
    ho.add_instruction(SSAInstruction(co, "cmp_lt", [i_phi, pn]))
    ho.add_instruction(SSAInstruction(None, "br_cond", [co, "bo", "exo"]))

    bo.add_instruction(SSAInstruction(j0, "const", [0]))
    bo.add_instruction(SSAInstruction(None, "br", ["ha"]))

    ha.phi_nodes.append(SSAInstruction(j_phi, "phi", [j0, j_next], phi_incoming=[("bo", j0), ("ba", j_next)]))
    ha.phi_nodes.append(SSAInstruction(acc_a, "phi", [acc_o, acc_a_next], phi_incoming=[("bo", acc_o), ("ba", acc_a_next)]))
    ha.add_instruction(SSAInstruction(ca, "cmp_lt", [j_phi, pm]))
    ha.add_instruction(SSAInstruction(None, "br_cond", [ca, "ba", "mid"]))

    ba.add_instruction(SSAInstruction(acc_a_next, "add", [acc_a, 1]))
    ba.add_instruction(SSAInstruction(j_next, "add", [j_phi, 1]))
    ba.add_instruction(SSAInstruction(None, "br", ["ha"]))

    mid.add_instruction(SSAInstruction(k0, "const", [0]))
    mid.add_instruction(SSAInstruction(None, "br", ["hb"]))

    hb.phi_nodes.append(SSAInstruction(k_phi, "phi", [k0, k_next], phi_incoming=[("mid", k0), ("bb", k_next)]))
    hb.phi_nodes.append(SSAInstruction(acc_b, "phi", [acc_a, acc_b_next], phi_incoming=[("mid", acc_a), ("bb", acc_b_next)]))
    hb.add_instruction(SSAInstruction(cb, "cmp_lt", [k_phi, pp]))
    hb.add_instruction(SSAInstruction(None, "br_cond", [cb, "bb", "lout"]))

    if hoist_k:
        bb.add_instruction(SSAInstruction(acc_b_next, "add", [acc_b, inv_pre]))
    else:
        bb.add_instruction(SSAInstruction(tb, "mul", [px, 2]))
        bb.add_instruction(SSAInstruction(invb, "add", [tb, inner2_bias]))
        bb.add_instruction(SSAInstruction(acc_b_next, "add", [acc_b, invb]))
    bb.add_instruction(SSAInstruction(k_next, "add", [k_phi, 1]))
    bb.add_instruction(SSAInstruction(None, "br", ["hb"]))

    lout.add_instruction(SSAInstruction(i_next, "add", [i_phi, 1]))
    lout.add_instruction(SSAInstruction(None, "br", ["ho"]))

    exo.add_instruction(SSAInstruction(None, "ret", [acc_o]))

    for blk in (entry, ho, bo, ha, ba, mid, hb, bb, lout, exo):
        fn.add_block(blk)
    fn.entry_block = entry
    return fn


class TestAlphaC29RecursiveLoopsAndPolyglotExt(unittest.TestCase):
    def test_unbounded_triple_nested_three_level_loops_and_depth_mutations(self):
        tv = SSATranslationValidator(max_loop_unroll=2, enable_inductive_loops=True)
        fn_orig = _build_triple_nested_ssa(hoist_inv=False, depth3_const=11)
        fn_opt = _build_triple_nested_ssa(hoist_inv=True, depth3_const=11)
        fn_bad_d3 = _build_triple_nested_ssa(hoist_inv=True, depth3_const=12)
        fn_bad_d2 = _build_triple_nested_ssa(hoist_inv=True, depth3_const=11, depth2_step=2)
        fn_bad_d1 = _build_triple_nested_ssa(hoist_inv=True, depth3_const=11, depth1_step=2)

        res_ok = tv.verify_equivalence(fn_orig, fn_opt)
        self.assertTrue(res_ok["proven"], f"3-level loop equivalence failed: {res_ok}")
        self.assertEqual(res_ok["status"], "PROVEN_INDUCTIVE_EQUIVALENT")
        self.assertFalse(res_ok["bounded"])

        for label, bad_fn in [("depth3", fn_bad_d3), ("depth2", fn_bad_d2), ("depth1", fn_bad_d1)]:
            r_bad = tv.verify_equivalence(fn_orig, bad_fn)
            self.assertFalse(r_bad["proven"], f"Expected refutation for {label}")
            self.assertEqual(r_bad["status"], "REFUTED_COUNTEREXAMPLE")
            self.assertIsNotNone(r_bad["counterexample"])

    def test_hybrid_nested_plus_sequential_loop_hierarchy(self):
        tv = SSATranslationValidator(max_loop_unroll=2, enable_inductive_loops=True)
        fn_orig = _build_hybrid_nested_seq_inner_ssa(hoist_k=False, inner2_bias=3)
        fn_opt = _build_hybrid_nested_seq_inner_ssa(hoist_k=True, inner2_bias=3)
        fn_bad = _build_hybrid_nested_seq_inner_ssa(hoist_k=True, inner2_bias=9)

        res_ok = tv.verify_equivalence(fn_orig, fn_opt)
        self.assertTrue(res_ok["proven"], f"Hybrid nested+sequential equivalence failed: {res_ok}")
        self.assertEqual(res_ok["status"], "PROVEN_INDUCTIVE_EQUIVALENT")
        self.assertFalse(res_ok["bounded"])

        res_bad = tv.verify_equivalence(fn_orig, fn_bad)
        self.assertFalse(res_bad["proven"])
        self.assertEqual(res_bad["status"], "REFUTED_COUNTEREXAMPLE")

    def test_polyglot_arrows_rust_match_do_while_and_tuple_swap(self):
        js_src = """
        export const js_arrow_do = (n, x) => {
            let acc = x, i = 0;
            do {
                acc += (i * 2) + 1;
                i++;
            } while (i < n);
            return acc;
        };
        exports.blendScore = (x, y) => (x * 100) + y;
        """
        rs_src = """
        pub fn rs_match_score(tag: i64, x: i64) -> i64 {
            match tag {
                1 | 2 => x * 3 + 5,
                3 => {
                    let t: i64 = x + 10;
                    t * 2
                },
                _ => x - 4,
            }
        }
        """
        go_src = """
        package fib
        func go_fib_tuple(n int64) int64 {
            a, b := 0, 1
            for i := 0; i < n; i++ {
                a, b = b, a + b
            }
            return a
        }
        """

        tv = BackendTranslationValidator()

        js_parsed = lower_polyglot_source_to_ast(js_src, "javascript", strict=True)
        self.assertEqual([f.name for f in js_parsed.functions], ["js_arrow_do", "blendScore"])
        do_ssa = lower_ast_to_ssa(js_parsed.functions[0], optimize=True)
        do_res = tv.verify_differential_execution(do_ssa, [(0, 10), (1, 10), (4, 5)])
        self.assertTrue(do_res["equivalent"], f"JS do-while arrow diff failed: {do_res}")
        self.assertEqual(do_res["outputs_by_backend"]["native"], [11, 11, 21])

        blend_ssa = lower_ast_to_ssa(js_parsed.functions[1], optimize=True)
        self.assertTrue(tv.verify_ssa_to_llvm_ir(blend_ssa, LLVMBackend().ssa_to_llvm_ir(blend_ssa))["proven"])
        self.assertTrue(tv.verify_ssa_to_wat(blend_ssa, WasmBackend().ssa_to_wat(blend_ssa))["proven"])

        rs_parsed = lower_polyglot_source_to_ast(rs_src, "rust", strict=True)
        rs_ssa = lower_ast_to_ssa(rs_parsed.functions[0], optimize=True)
        rs_res = tv.verify_differential_execution(rs_ssa, [(1, 7), (2, 7), (3, 7), (99, 7)])
        self.assertTrue(rs_res["equivalent"], f"Rust match diff failed: {rs_res}")
        self.assertEqual(rs_res["outputs_by_backend"]["native"], [26, 26, 34, 3])

        go_parsed = lower_polyglot_source_to_ast(go_src, "go", strict=True)
        go_ssa = lower_ast_to_ssa(go_parsed.functions[0], optimize=True)
        go_res = tv.verify_differential_execution(go_ssa, [(0,), (1,), (6,), (10,)])
        self.assertTrue(go_res["equivalent"], f"Go tuple fib diff failed: {go_res}")
        self.assertEqual(go_res["outputs_by_backend"]["native"], [0, 1, 8, 55])

    def test_multi_repo_polyglot_fusion_arrows_match_tuple(self):
        with tempfile.TemporaryDirectory() as tmp:
            go_dir = os.path.join(tmp, "repo_go")
            rs_dir = os.path.join(tmp, "repo_rs")
            ts_dir = os.path.join(tmp, "repo_ts")
            for d in (go_dir, rs_dir, ts_dir):
                os.makedirs(d, exist_ok=True)

            with open(os.path.join(go_dir, "fib.go"), "w", encoding="utf-8") as f:
                f.write(
                    "package fib\n"
                    "func go_fib_n(n int64) int64 {\n"
                    "    a, b := 0, 1\n"
                    "    for i := 0; i < n; i++ {\n"
                    "        a, b = b, a + b\n"
                    "    }\n"
                    "    return a\n"
                    "}\n"
                )
            with open(os.path.join(rs_dir, "route.rs"), "w", encoding="utf-8") as f:
                f.write(
                    "pub fn rs_dispatch(sel: i64, v: i64) -> i64 {\n"
                    "    match sel {\n"
                    "        1 | 2 => v * 3,\n"
                    "        _ => v + 7,\n"
                    "    }\n"
                    "}\n"
                )
            with open(os.path.join(ts_dir, "entry.ts"), "w", encoding="utf-8") as f:
                f.write(
                    "export const ts_poly_fused = (sel: number, n: number): number => {\n"
                    "    return rs_dispatch(sel, go_fib_n(n));\n"
                    "};\n"
                )

            ext = ".dll" if platform.system().lower().startswith("win") else ".so"
            out_lib = os.path.join(tmp, f"poly_c29{ext}")
            comp = OmniRepoCompiler()
            res = comp.compile_repositories(
                [go_dir, rs_dir, ts_dir],
                out_lib,
                target_format="shared_lib",
                target_os="windows" if platform.system().lower().startswith("win") else "linux",
                target_arch="x86_64",
                export_all=True,
                backend="native",
            )
            self.assertTrue(res["success"], f"Polyglot C29 compile failed: {res}")

            lib = ctypes.CDLL(out_lib)
            try:
                lib.ts_poly_fused.argtypes = [ctypes.c_int64, ctypes.c_int64]
                lib.ts_poly_fused.restype = ctypes.c_int64
                self.assertEqual(lib.ts_poly_fused(2, 7), 13 * 3)
                self.assertEqual(lib.ts_poly_fused(9, 7), 13 + 7)
            finally:
                if platform.system().lower().startswith("win"):
                    import _ctypes
                    _ctypes.FreeLibrary(lib._handle)

    def test_fast_node_bridge_zero_resource_warnings(self):
        from adapters.synthesizer import AdapterSynthesizer
        from contracts.models import CapabilityContract

        with tempfile.TemporaryDirectory() as td:
            js_path = os.path.join(td, "fast_math.js")
            with open(js_path, "w", encoding="utf-8") as f:
                f.write("exports.blendScore = (x, y) => (x * 100) + y;\n")
            cap = CapabilityContract(
                schema_version="0.1",
                capability_id="cap_node_clean",
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
            cand = AdapterSynthesizer().synthesize_adapter(
                {"adapter_id": "fast_node_bridge", "requirement": "req_score"}, cap
            )
            ns: dict = {}
            exec(cand.code_content, ns)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", ResourceWarning)
                bridge = ns["FastNodeBridge"]()
                try:
                    self.assertEqual(bridge.execute(x=4, y=19), 419)
                finally:
                    bridge.close()
                    del bridge
                import gc
                gc.collect()
            res_warns = [w for w in caught if issubclass(w.category, ResourceWarning)]
            self.assertEqual(res_warns, [], f"Expected zero ResourceWarnings, got: {res_warns}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
