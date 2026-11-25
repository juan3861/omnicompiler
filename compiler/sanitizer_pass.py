"""
Alpha-C99: Compile-Time Native Sanitizer Instrumentation Pass (`compiler/sanitizer_pass.py`).

Lowers runtime memory safety (ASan bounds & null-pointer checks) and undefined-behavior
checks (UBSan divide-by-zero & invalid shift checks) directly into Omni-SSA IR before
x86-64 / ARM64 / LLVM / GCC codegen, emitting branches into `__omni_sanitizer_trap`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from compiler.ssa_ir import BasicBlock, SSAFunction, SSAInstruction, SSAVar
from runtime.native_sanitizer import (
    SANITIZER_KIND_DIV_ZERO,
    SANITIZER_KIND_NULL_DEREF,
    SANITIZER_KIND_STACK_OOB,
    SANITIZER_KIND_UB_SHIFT,
)


@dataclass
class SanitizerReport:
    function_name: str
    modes: List[str]
    ubsan_div_checks: int = 0
    ubsan_shift_checks: int = 0
    asan_null_checks: int = 0
    asan_bounds_checks: int = 0
    trap_blocks_inserted: int = 0


class SanitizerInstrumentationPass:
    """
    Instruments an `SSAFunction` with dynamic ASan (`asan`) and/or UBSan (`ubsan`)
    safety guards branching to `__omni_sanitizer_trap(kind, line, value)` on fault.
    """

    def __init__(self, mode: str = "asan,ubsan"):
        tokens = [m.strip().lower() for m in str(mode or "").split(",") if m.strip()]
        valid = {"asan", "ubsan", "all", "none"}
        unknown = [t for t in tokens if t not in valid]
        if unknown:
            raise ValueError(f"Unsupported sanitizer mode tokens: {unknown}. Expected 'asan', 'ubsan', or 'asan,ubsan'.")
        if "none" in tokens or not tokens:
            self.enable_asan = False
            self.enable_ubsan = False
        elif "all" in tokens:
            self.enable_asan = True
            self.enable_ubsan = True
        else:
            self.enable_asan = "asan" in tokens
            self.enable_ubsan = "ubsan" in tokens

    def instrument_function(self, fn: SSAFunction) -> SanitizerReport:
        rep = SanitizerReport(
            function_name=fn.name,
            modes=[m for m, on in (("asan", self.enable_asan), ("ubsan", self.enable_ubsan)) if on],
        )
        if not (self.enable_asan or self.enable_ubsan):
            return rep

        # Track known stack array/alloca bounds across instructions
        alloc_bounds: Dict[SSAVar, int] = {}
        for blk in fn.blocks:
            for ins in blk.instructions:
                if ins.opcode == "alloca" and isinstance(ins.result, SSAVar) and ins.operands:
                    if isinstance(ins.operands[0], int):
                        alloc_bounds[ins.result] = int(ins.operands[0])

        uid = 9000

        def _fresh(prefix: str) -> SSAVar:
            nonlocal uid
            uid += 1
            return SSAVar(f"__san_{prefix}", uid, "i64")

        def _find_checks(ins: SSAInstruction) -> List[Tuple[str, object, int, Optional[int], str]]:
            """
            Returns list of `(check_kind, arg0, trap_kind, bound_or_None, label_tag)`:
              - check_kind == 'eq0': trap if arg0 == 0
              - check_kind == 'lt0': trap if arg0 < 0
              - check_kind == 'ge_n': trap if arg0 >= bound_or_None
            """
            checks: List[Tuple[str, object, int, Optional[int], str]] = []
            if self.enable_ubsan and ins.opcode in ("div", "mod", "sdiv", "srem", "udiv", "urem") and len(ins.operands) >= 2:
                checks.append(("eq0", ins.operands[1], SANITIZER_KIND_DIV_ZERO, None, "div0"))
            if self.enable_ubsan and ins.opcode in ("shl", "shr") and len(ins.operands) >= 2:
                checks.append(("lt0", ins.operands[1], SANITIZER_KIND_UB_SHIFT, None, "shneg"))
                checks.append(("ge_n", ins.operands[1], SANITIZER_KIND_UB_SHIFT, 64, "shbig"))
            if self.enable_asan and ins.opcode in ("load_off", "store_off") and len(ins.operands) >= 2:
                ptr_op = ins.operands[0]
                off_op = ins.operands[1]
                checks.append(("eq0", ptr_op, SANITIZER_KIND_NULL_DEREF, None, "null"))
                if ptr_op in alloc_bounds:
                    bound_bytes = alloc_bounds[ptr_op]
                    checks.append(("lt0", off_op, SANITIZER_KIND_STACK_OOB, None, "oob_neg"))
                    checks.append(("ge_n", off_op, SANITIZER_KIND_STACK_OOB, bound_bytes, "oob_hi"))
            return checks

        new_blocks: List[BasicBlock] = []
        phi_remap: Dict[str, str] = {}

        for orig_blk in list(fn.blocks):
            cur_blk = BasicBlock(orig_blk.name)
            cur_blk.phi_nodes = list(orig_blk.phi_nodes)
            cur_blk.loop_depth = orig_blk.loop_depth
            for pred in orig_blk.predecessors:
                if pred not in cur_blk.predecessors:
                    cur_blk.predecessors.append(pred)
            new_blocks.append(cur_blk)
            if fn.entry_block is orig_blk:
                fn.entry_block = cur_blk

            for ins in orig_blk.instructions:
                checks = _find_checks(ins)
                if not checks:
                    cur_blk.add_instruction(ins)
                    continue

                for chk_type, val_op, trap_kind, bound_n, tag in checks:
                    uid += 1
                    trap_blk = BasicBlock(f"{orig_blk.name}__san_trap_{tag}_{uid}")
                    cont_blk = BasicBlock(f"{orig_blk.name}__san_ok_{tag}_{uid}")
                    cont_blk.loop_depth = orig_blk.loop_depth

                    cmp_res = _fresh(f"cond_{tag}")
                    if chk_type == "eq0":
                        z = _fresh("zero")
                        cur_blk.add_instruction(SSAInstruction(z, "const", [0], source_line=ins.source_line))
                        cur_blk.add_instruction(SSAInstruction(cmp_res, "cmp_eq", [val_op, z], source_line=ins.source_line))
                    elif chk_type == "lt0":
                        z = _fresh("zero")
                        cur_blk.add_instruction(SSAInstruction(z, "const", [0], source_line=ins.source_line))
                        cur_blk.add_instruction(SSAInstruction(cmp_res, "cmp_lt", [val_op, z], source_line=ins.source_line))
                    else:  # ge_n
                        b = _fresh("bound")
                        cur_blk.add_instruction(SSAInstruction(b, "const", [int(bound_n or 0)], source_line=ins.source_line))
                        cur_blk.add_instruction(SSAInstruction(cmp_res, "cmp_ge", [val_op, b], source_line=ins.source_line))

                    cur_blk.add_instruction(
                        SSAInstruction(None, "br_cond", [cmp_res, trap_blk.name, cont_blk.name], source_line=ins.source_line)
                    )
                    cur_blk.connect_to(trap_blk)
                    cur_blk.connect_to(cont_blk)

                    # Trap block: __omni_sanitizer_trap(kind, source_line, bad_value) -> ret 0
                    k_var = _fresh("kind")
                    l_var = _fresh("line")
                    rv_trap = _fresh("trap_ret")
                    rv_zero = _fresh("trap_zero")
                    trap_blk.add_instruction(SSAInstruction(k_var, "const", [trap_kind], source_line=ins.source_line))
                    trap_blk.add_instruction(SSAInstruction(l_var, "const", [int(ins.source_line or 0)], source_line=ins.source_line))
                    trap_blk.add_instruction(
                        SSAInstruction(rv_trap, "call", ["__omni_sanitizer_trap", k_var, l_var, val_op], source_line=ins.source_line)
                    )
                    trap_blk.add_instruction(SSAInstruction(rv_zero, "const", [0], source_line=ins.source_line))
                    trap_blk.add_instruction(SSAInstruction(None, "ret", [rv_zero], source_line=ins.source_line))

                    new_blocks.append(trap_blk)
                    new_blocks.append(cont_blk)
                    cur_blk = cont_blk

                    rep.trap_blocks_inserted += 1
                    if trap_kind == SANITIZER_KIND_DIV_ZERO:
                        rep.ubsan_div_checks += 1
                    elif trap_kind == SANITIZER_KIND_UB_SHIFT:
                        rep.ubsan_shift_checks += 1
                    elif trap_kind == SANITIZER_KIND_NULL_DEREF:
                        rep.asan_null_checks += 1
                    elif trap_kind == SANITIZER_KIND_STACK_OOB:
                        rep.asan_bounds_checks += 1

                cur_blk.add_instruction(ins)

            # Reconnect original outgoing successors from tail block of orig_blk
            for succ in orig_blk.successors:
                cur_blk.connect_to(succ)
            phi_remap[orig_blk.name] = cur_blk.name

        # Remap predecessor names cleanly inside all phi_nodes and rebuild pred/succ links
        blk_by_name = {b.name: b for b in new_blocks}
        for b in new_blocks:
            for phi in b.phi_nodes:
                if phi.phi_incoming:
                    phi.phi_incoming = [
                        (phi_remap.get(lbl, lbl), val) for (lbl, val) in phi.phi_incoming
                    ]
            b.successors = [blk_by_name[s.name] for s in b.successors if s.name in blk_by_name]
            b.predecessors = []
        for b in new_blocks:
            for s in b.successors:
                if b not in s.predecessors:
                    s.predecessors.append(b)

        fn.blocks = new_blocks
        return rep
