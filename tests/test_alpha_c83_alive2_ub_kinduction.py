import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from compiler.ssa_ir import SSAFunction, BasicBlock, SSAVar, SSAInstruction
from validation.ssa_translation_validator import SSATranslationValidator


def _link(blk_a: BasicBlock, blk_b: BasicBlock) -> None:
    if blk_b not in blk_a.successors:
        blk_a.successors.append(blk_b)
    if blk_a not in blk_b.predecessors:
        blk_b.predecessors.append(blk_a)


def _make_simple_fn(name: str, params, instr_builder, param_types=None, noalias_params=None) -> SSAFunction:
    fn = SSAFunction(name=name, params=list(params), param_types=dict(param_types or {}))
    if noalias_params is not None:
        fn.noalias_params = set(noalias_params)
    blk = BasicBlock("entry")
    pvars = {}
    for i, p in enumerate(params):
        pv = SSAVar(p, 0)
        pvars[p] = pv
        blk.add_instruction(SSAInstruction(pv, "param", [i]))
    for ins in instr_builder(pvars):
        blk.add_instruction(ins)
    fn.blocks = [blk]
    fn.entry_block = blk
    return fn


def _build_lag_loop_fn(name: str, lag_init: int, lag_add: int) -> SSAFunction:
    """
    Loop with 1-iteration warmup lag register:
      i = 0; acc = 0; lag = lag_init;
      if n <= 0: return 0
      do {
          use = select(i > 0, lag, x)
          acc_next = acc + use
          lag_next = x + lag_add
          i_next = i + 1
      } while (i_next < n)
      return acc_next
    """
    fn = SSAFunction(name=name, params=["n", "x"])
    n_v = SSAVar("n", 0)
    x_v = SSAVar("x", 0)

    entry = BasicBlock("entry")
    hdr = BasicBlock("hdr")
    exit_b = BasicBlock("exit")
    _link(entry, hdr)
    _link(entry, exit_b)
    _link(hdr, hdr)
    _link(hdr, exit_b)

    c0 = SSAVar("c0", 1)
    cond_enter = SSAVar("cond_enter", 1)
    init_lag = SSAVar("init_lag", 1)
    entry.add_instruction(SSAInstruction(n_v, "param", [0]))
    entry.add_instruction(SSAInstruction(x_v, "param", [1]))
    entry.add_instruction(SSAInstruction(c0, "const", [0]))
    entry.add_instruction(SSAInstruction(cond_enter, "cmp_gt", [n_v, c0]))
    entry.add_instruction(SSAInstruction(init_lag, "const", [lag_init]))
    entry.add_instruction(SSAInstruction(None, "br_cond", [cond_enter, "hdr", "exit"]))

    i_phi = SSAVar("i", 1)
    acc_phi = SSAVar("acc", 1)
    lag_phi = SSAVar("lag", 1)
    i_next = SSAVar("i", 2)
    acc_next = SSAVar("acc", 2)
    lag_next = SSAVar("lag", 2)

    hdr.phi_nodes = [
        SSAInstruction(i_phi, "phi", [], phi_incoming=[("entry", 0), ("hdr", i_next)]),
        SSAInstruction(acc_phi, "phi", [], phi_incoming=[("entry", 0), ("hdr", acc_next)]),
        SSAInstruction(lag_phi, "phi", [], phi_incoming=[("entry", init_lag), ("hdr", lag_next)]),
    ]
    is_gt0 = SSAVar("is_gt0", 1)
    use_v = SSAVar("use", 1)
    c_add = SSAVar("c_add", 1)
    c_1 = SSAVar("c1", 1)
    cont = SSAVar("cont", 1)
    hdr.add_instruction(SSAInstruction(is_gt0, "cmp_gt", [i_phi, 0]))
    hdr.add_instruction(SSAInstruction(use_v, "select", [is_gt0, lag_phi, x_v]))
    hdr.add_instruction(SSAInstruction(acc_next, "add", [acc_phi, use_v]))
    hdr.add_instruction(SSAInstruction(c_add, "const", [lag_add]))
    hdr.add_instruction(SSAInstruction(lag_next, "add", [x_v, c_add]))
    hdr.add_instruction(SSAInstruction(c_1, "const", [1]))
    hdr.add_instruction(SSAInstruction(i_next, "add", [i_phi, c_1]))
    hdr.add_instruction(SSAInstruction(cont, "cmp_lt", [i_next, n_v]))
    hdr.add_instruction(SSAInstruction(None, "br_cond", [cont, "hdr", "exit"]))

    res_phi = SSAVar("res", 1)
    exit_b.phi_nodes = [
        SSAInstruction(res_phi, "phi", [], phi_incoming=[("entry", 0), ("hdr", acc_next)])
    ]
    exit_b.add_instruction(SSAInstruction(None, "ret", [res_phi]))

    fn.blocks = [entry, hdr, exit_b]
    fn.entry_block = entry
    return fn


class TestAlphaC83Alive2AndKInduction(unittest.TestCase):
    def test_01_alive2_nsw_nuw_exact_sound_and_unsound(self):
        v = SSATranslationValidator(enable_ub_poison=True)

        # Unsound tightening: add -> add_nsw introduces poison on signed overflow
        src_wrap = _make_simple_fn(
            "add_wrap", ["x", "y"],
            lambda p: [
                SSAInstruction(SSAVar("r", 1), "add", [p["x"], p["y"]]),
                SSAInstruction(None, "ret", [SSAVar("r", 1)]),
            ],
        )
        tgt_nsw = _make_simple_fn(
            "add_nsw", ["x", "y"],
            lambda p: [
                SSAInstruction(SSAVar("r", 1), "add_nsw", [p["x"], p["y"]]),
                SSAInstruction(None, "ret", [SSAVar("r", 1)]),
            ],
        )
        r_bad = v.verify_refinement(src_wrap, tgt_nsw)
        self.assertFalse(r_bad["proven"])
        self.assertEqual(r_bad["status"], "REFUTED_COUNTEREXAMPLE")
        ce = r_bad["counterexample"]
        s64 = (ce["x"] + ce["y"]) & 0xFFFFFFFFFFFFFFFF
        if s64 >= (1 << 63):
            s64 -= (1 << 64)
        self.assertNotEqual(s64, ce["x"] + ce["y"])  # counterexample MUST actually signed-overflow

        # Sound refinement: (x +_nsw 1) > x  ==>  1
        src_nsw_cmp = _make_simple_fn(
            "nsw_gt", ["x"],
            lambda p: [
                SSAInstruction(SSAVar("one", 1), "const", [1]),
                SSAInstruction(SSAVar("xp1", 1), "add_nsw", [p["x"], SSAVar("one", 1)]),
                SSAInstruction(SSAVar("cmp", 1), "cmp_gt", [SSAVar("xp1", 1), p["x"]]),
                SSAInstruction(None, "ret", [SSAVar("cmp", 1)]),
            ],
        )
        tgt_true = _make_simple_fn(
            "const_1", ["x"],
            lambda p: [
                SSAInstruction(SSAVar("one", 1), "const", [1]),
                SSAInstruction(None, "ret", [SSAVar("one", 1)]),
            ],
        )
        r_good = v.verify_refinement(src_nsw_cmp, tgt_true)
        self.assertTrue(r_good["proven"], msg=r_good)
        self.assertEqual(r_good["status"], "PROVEN_REFINEMENT")

        # Without nsw (wrapping add), (x + 1) > x  ==>  1 MUST BE REFUTED at INT64_MAX
        src_wrap_cmp = _make_simple_fn(
            "wrap_gt", ["x"],
            lambda p: [
                SSAInstruction(SSAVar("one", 1), "const", [1]),
                SSAInstruction(SSAVar("xp1", 1), "add", [p["x"], SSAVar("one", 1)]),
                SSAInstruction(SSAVar("cmp", 1), "cmp_gt", [SSAVar("xp1", 1), p["x"]]),
                SSAInstruction(None, "ret", [SSAVar("cmp", 1)]),
            ],
        )
        r_wrap_bad = v.verify_refinement(src_wrap_cmp, tgt_true)
        self.assertFalse(r_wrap_bad["proven"])
        self.assertEqual(r_wrap_bad["counterexample"]["x"], (1 << 63) - 1)

        # sdiv_exact((x <<_nsw 1), 2) ==> x
        src_exact = _make_simple_fn(
            "shl_div", ["x"],
            lambda p: [
                SSAInstruction(SSAVar("s1", 1), "shl_nsw", [p["x"], 1]),
                SSAInstruction(SSAVar("q", 1), "sdiv_exact", [SSAVar("s1", 1), 2]),
                SSAInstruction(None, "ret", [SSAVar("q", 1)]),
            ],
        )
        tgt_id = _make_simple_fn(
            "id_x", ["x"],
            lambda p: [SSAInstruction(None, "ret", [p["x"]])],
        )
        self.assertTrue(v.verify_refinement(src_exact, tgt_id)["proven"])

    def test_02_alive2_div_zero_ub_speculation_and_freeze(self):
        v = SSATranslationValidator(enable_ub_poison=True)

        # Speculatively hoisting sdiv across condition: src guards y != 0, tgt executes unguarded sdiv => REFUTED
        def build_safe_div():
            fn = SSAFunction("safe_div", ["x", "y"])
            e, t, f = BasicBlock("entry"), BasicBlock("t"), BasicBlock("f")
            _link(e, t)
            _link(e, f)
            c = SSAVar("nz", 1)
            e.add_instruction(SSAInstruction(c, "cmp_ne", [SSAVar("y", 0), 0]))
            e.add_instruction(SSAInstruction(None, "br_cond", [c, "t", "f"]))
            q = SSAVar("q", 1)
            t.add_instruction(SSAInstruction(q, "sdiv", [SSAVar("x", 0), SSAVar("y", 0)]))
            t.add_instruction(SSAInstruction(None, "ret", [q]))
            f.add_instruction(SSAInstruction(None, "ret", [0]))
            fn.blocks = [e, t, f]
            fn.entry_block = e
            return fn

        tgt_speculative_div = _make_simple_fn(
            "spec_div", ["x", "y"],
            lambda p: [
                SSAInstruction(SSAVar("q", 1), "sdiv", [p["x"], p["y"]]),
                SSAInstruction(SSAVar("nz", 1), "cmp_ne", [p["y"], 0]),
                SSAInstruction(SSAVar("r", 1), "select", [SSAVar("nz", 1), SSAVar("q", 1), 0]),
                SSAInstruction(None, "ret", [SSAVar("r", 1)]),
            ],
        )
        r_spec = v.verify_refinement(build_safe_div(), tgt_speculative_div)
        self.assertFalse(r_spec["proven"])
        self.assertEqual(r_spec["status"], "REFUTED_COUNTEREXAMPLE")
        self.assertEqual(r_spec["counterexample"]["y"], 0)

        # freeze turns poison into non-poison arbitrary value: non-poison freeze refines itself cleanly,
        # while dropping freeze in branch-on-poison is UNSOUND vs frozen source
        src_freeze = _make_simple_fn(
            "with_freeze", ["x"],
            lambda p: [
                SSAInstruction(SSAVar("xp1", 1), "add_nsw", [p["x"], 1]),
                SSAInstruction(SSAVar("cmp", 1), "cmp_gt", [SSAVar("xp1", 1), p["x"]]),
                SSAInstruction(SSAVar("fz", 1), "freeze", [SSAVar("cmp", 1)]),
                SSAInstruction(None, "ret", [SSAVar("fz", 1)]),
            ],
        )
        tgt_unfrozen_poison = _make_simple_fn(
            "without_freeze", ["x"],
            lambda p: [
                SSAInstruction(SSAVar("xp1", 1), "add_nsw", [p["x"], 1]),
                SSAInstruction(SSAVar("cmp", 1), "cmp_gt", [SSAVar("xp1", 1), p["x"]]),
                SSAInstruction(None, "ret", [SSAVar("cmp", 1)]),
            ],
        )
        # Source with freeze is defined & non-poison for all x; Target returns poison at INT64_MAX -> UNSOUND!
        r_fz = v.verify_refinement(src_freeze, tgt_unfrozen_poison)
        self.assertFalse(r_fz["proven"])
        self.assertEqual(r_fz["counterexample"]["x"], (1 << 63) - 1)

    def test_03_pointer_base_disjointness_qf_abv(self):
        # Load p[0], Store q[0] = v vs Store q[0] = v, Load p[0]
        src = _make_simple_fn(
            "mem_before", ["p", "q", "v"],
            lambda args: [
                SSAInstruction(SSAVar("ld", 1), "load_off", [args["p"], 0, "i64"]),
                SSAInstruction(None, "store_off", [args["q"], 0, args["v"], "i64"]),
                SSAInstruction(None, "ret", [SSAVar("ld", 1)]),
            ],
            param_types={"p": "ptr", "q": "ptr", "v": "i64"},
        )
        tgt = _make_simple_fn(
            "mem_reordered", ["p", "q", "v"],
            lambda args: [
                SSAInstruction(None, "store_off", [args["q"], 0, args["v"], "i64"]),
                SSAInstruction(SSAVar("ld", 1), "load_off", [args["p"], 0, "i64"]),
                SSAInstruction(None, "ret", [SSAVar("ld", 1)]),
            ],
            param_types={"p": "ptr", "q": "ptr", "v": "i64"},
        )

        v_alias = SSATranslationValidator(enable_memory_theory=True, enable_pointer_disjointness=False)
        r_alias = v_alias.verify_equivalence(src, tgt)
        self.assertFalse(r_alias["proven"])
        self.assertEqual(r_alias["status"], "REFUTED_COUNTEREXAMPLE")

        v_disjoint = SSATranslationValidator(enable_memory_theory=True, enable_pointer_disjointness=True)
        r_disj = v_disjoint.verify_equivalence(src, tgt)
        self.assertTrue(r_disj["proven"], msg=r_disj)
        self.assertEqual(r_disj["status"], "PROVEN_EQUIVALENT")

        # Out-of-bounds alloca access caught by UB verifier
        src_oob = _make_simple_fn(
            "oob", ["v"],
            lambda args: [
                SSAInstruction(SSAVar("buf", 1), "alloca", [16]),
                SSAInstruction(None, "store_off", [SSAVar("buf", 1), 32, args["v"], "i64"]),
                SSAInstruction(None, "ret", [args["v"]]),
            ],
        )
        tgt_safe = _make_simple_fn(
            "safe_ret", ["v"],
            lambda args: [SSAInstruction(None, "ret", [args["v"]])],
        )
        v_ub = SSATranslationValidator(enable_memory_theory=True, enable_ub_poison=True)
        # Replacing OOB UB source with safe ret refines (Source is UB unconditionally)
        self.assertTrue(v_ub.verify_refinement(src_oob, tgt_safe)["proven"])
        # Replacing safe source with OOB store is refuted!
        self.assertFalse(v_ub.verify_refinement(tgt_safe, src_oob)["proven"])

    def test_04_k_induction_unbounded_loop_beyond_1_induction(self):
        # lag_init differs (0 vs 999) and is unused on iteration 0, synchronizing at step 1
        fn_b = _build_lag_loop_fn("lag_before", lag_init=0, lag_add=7)
        fn_a = _build_lag_loop_fn("lag_after_sync", lag_init=999, lag_add=7)
        fn_bug = _build_lag_loop_fn("lag_buggy", lag_init=999, lag_add=8)

        # 1-induction MUST fail (warmup init differs so 1-inductive base_inv rejects at t=0)
        v1 = SSATranslationValidator(max_loop_unroll=2, enable_inductive_loops=True, max_k_induction=1)
        r1 = v1.verify_equivalence(fn_b, fn_a)
        self.assertFalse(r1["proven"], msg=r1)

        # k-induction (k=2) MUST prove unbounded equivalence for ALL N!
        v2 = SSATranslationValidator(max_loop_unroll=2, enable_inductive_loops=True, max_k_induction=3)
        r2 = v2.verify_equivalence(fn_b, fn_a)
        self.assertTrue(r2["proven"], msg=r2)
        self.assertEqual(r2["status"], "PROVEN_K_INDUCTIVE_EQUIVALENT")
        self.assertEqual(r2["k"], 2)
        self.assertFalse(r2["bounded"])

        # Buggy version (lag_add=8 diverges on iteration 1) MUST still be refuted with counterexample!
        r_bug = v2.verify_equivalence(fn_b, fn_bug)
        self.assertFalse(r_bug["proven"])
        self.assertEqual(r_bug["status"], "REFUTED_COUNTEREXAMPLE")
        self.assertGreaterEqual(r_bug["counterexample"]["n"], 2)


if __name__ == "__main__":
    unittest.main()
