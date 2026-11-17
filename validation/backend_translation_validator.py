"""
OmniCompiler Cross-Backend Translation Validation & Differential Equivalence
(validation/backend_translation_validator.py)

Provides formal SMT equivalence proof across IR lowering boundaries plus physical
multi-backend differential execution checks:
1. `verify_ssa_to_llvm_ir`: Lifts emitted LLVM IR back to Omni-SSA IR and proves
   Z3 QF_BV / QF_ABV (and bounded / inductive loop) equivalence against `ssa_fn`.
2. `verify_ssa_to_wat`: Lifts emitted WebAssembly Text (WAT) stack-machine &
   `$cfg_dispatch` CFGs back to Omni-SSA IR and proves Z3 equivalence against `ssa_fn`.
3. `verify_differential_execution`: Physically executes compiled machine/JIT/WASM
   code across Native x86-64 W^X JIT, LLVM O3 MCJIT, and Wasmtime on test vectors.
"""

import ctypes
import platform
import re
import struct
from typing import Dict, List, Tuple, Any, Optional, Sequence

from compiler.ssa_ir import SSAFunction, BasicBlock, SSAInstruction, SSAVar
from compiler.native_codegen import NativeCodeGenerator
from compiler.native_jit import NativeJitMemory
from compiler.llvm_backend import LLVMBackend
from compiler.wasm_backend import WasmBackend
from validation.ssa_translation_validator import SSATranslationValidator


def _to_s64(v: int) -> int:
    v &= 0xFFFFFFFFFFFFFFFF
    return v - (1 << 64) if v >= (1 << 63) else v


class LLVMIRToSSALifter:
    """Deterministic lifter from emitted LLVM IR function text back to `SSAFunction`."""

    LLVM_BINOP_MAP = {
        "add": "add",
        "sub": "sub",
        "mul": "mul",
        "sdiv": "sdiv",
        "srem": "srem",
        "shl": "shl",
        "ashr": "sar",
        "lshr": "lshr",
        "and": "and",
        "or": "or",
        "xor": "xor",
    }
    LLVM_ICMP_MAP = {
        "eq": "cmp_eq",
        "ne": "cmp_ne",
        "slt": "cmp_lt",
        "sle": "cmp_le",
        "sgt": "cmp_gt",
        "sge": "cmp_ge",
    }

    LLVM_FCMP_MAP = {
        "oeq": "fcmp_eq",
        "one": "fcmp_ne",
        "olt": "fcmp_lt",
        "ole": "fcmp_le",
        "ogt": "fcmp_gt",
        "oge": "fcmp_ge",
    }

    @classmethod
    def lift_function(cls, llvm_ir: str, target_name: Optional[str] = None) -> Tuple[Optional[SSAFunction], Optional[str]]:
        func_match = None
        for m in re.finditer(r"define\s+(i64|double)\s+@([A-Za-z0-9_.$]+)\s*\(([^)]*)\)\s*\{([\s\S]*?)^\}", llvm_ir, re.MULTILINE):
            if target_name is None or m.group(2) == target_name:
                func_match = m
                break
        if func_match is None:
            return None, "LLVM_FUNC_NOT_FOUND"

        ret_llvm_ty = func_match.group(1)
        fn_name = func_match.group(2)
        raw_params = func_match.group(3).strip()
        body_text = func_match.group(4)

        params: List[str] = []
        param_types: Dict[str, str] = {}
        arg_var_map: Dict[str, SSAVar] = {}
        if raw_params:
            for p_part in raw_params.split(","):
                pm = re.search(r"(i64|double)\s+%([A-Za-z0-9_.$]+)", p_part.strip())
                if not pm:
                    return None, f"UNSUPPORTED_LLVM_PARAM_{p_part.strip()}"
                pty_str, raw_pname = pm.group(1), pm.group(2)
                clean_name = raw_pname[4:] if raw_pname.startswith("arg_") else raw_pname
                vty = "f64" if pty_str == "double" else "i64"
                params.append(clean_name)
                param_types[clean_name] = vty
                arg_var_map[raw_pname] = SSAVar(clean_name, 0, var_type=vty)

        ssa_fn = SSAFunction(
            fn_name,
            params,
            param_types=param_types,
            return_type="f64" if ret_llvm_ty == "double" else "i64",
        )
        ssa_vars: Dict[str, SSAVar] = dict(arg_var_map)
        var_counter = 0

        def get_or_create_var(tok: str, var_type: str = "i64") -> SSAVar:
            nonlocal var_counter
            name = tok[1:] if tok.startswith("%") else tok
            if name not in ssa_vars:
                var_counter += 1
                ssa_vars[name] = SSAVar(f"lv_{name}", var_counter, var_type=var_type)
            elif var_type == "f64" and ssa_vars[name].var_type != "f64":
                ssa_vars[name].var_type = "f64"
            return ssa_vars[name]

        def parse_val(tok: str, as_float: bool = False) -> Any:
            t = tok.strip()
            if t.startswith("%"):
                return get_or_create_var(t)
            if t == "true":
                return 1
            if t == "false":
                return 0
            if t.startswith("0x"):
                try:
                    raw_hex = t[2:].zfill(16)[-16:]
                    return struct.unpack(">d", bytes.fromhex(raw_hex))[0]
                except Exception:
                    return t
            if as_float or "." in t or "e" in t.lower():
                try:
                    return float(t)
                except ValueError:
                    pass
            try:
                return int(t)
            except ValueError:
                return t

        blocks: Dict[str, BasicBlock] = {}
        block_order: List[str] = []
        cur_bb: Optional[BasicBlock] = None
        alias_ptr: Dict[str, Tuple[Any, Any, bool]] = {}  # %ptr/%gep -> (base_op, idx_or_off, is_byte_off)
        alloca_ptrs: Dict[str, SSAVar] = {}
        ext_zext_map: Dict[str, SSAVar] = {}  # %i1_var -> aliased i64 SSAVar
        trunc_i32_map: Dict[str, Any] = {}
        fptrunc_f32_map: Dict[str, Any] = {}
        load_i32_map: Dict[str, Tuple[Any, Any, bool]] = {}
        load_f32_map: Dict[str, Tuple[Any, Any, bool]] = {}

        def ensure_block(label: str) -> BasicBlock:
            if label not in blocks:
                bb = BasicBlock(label)
                blocks[label] = bb
                block_order.append(label)
                if cur_bb is None and label == "entry":
                    ssa_fn.entry_block = bb
            return blocks[label]

        # Pre-register basic block labels
        for raw_ln in body_text.splitlines():
            ln = raw_ln.strip()
            lbl_m = re.match(r"^([A-Za-z0-9_.$]+):\s*(?:;.*)?$", ln)
            if lbl_m:
                ensure_block(lbl_m.group(1))

        if not block_order:
            ensure_block("entry")

        # Inject param materializations in entry block
        entry_bb = blocks[block_order[0]]
        for pname in params:
            entry_bb.add_instruction(
                SSAInstruction(SSAVar(pname, 0, var_type=param_types[pname]), "param", [pname])
            )

        for raw_ln in body_text.splitlines():
            ln = raw_ln.split(";", 1)[0].strip()
            if not ln:
                continue
            lbl_m = re.match(r"^([A-Za-z0-9_.$]+):$", ln)
            if lbl_m:
                cur_bb = ensure_block(lbl_m.group(1))
                continue
            if cur_bb is None:
                cur_bb = entry_bb

            # Branch & Return terminators
            if ln.startswith("br label %"):
                tgt = ln[len("br label %"):].strip()
                cur_bb.add_instruction(SSAInstruction(None, "br", [tgt]))
                continue

            m_brcond = re.match(r"^br\s+i1\s+(%[A-Za-z0-9_.$]+|true|false),\s*label\s+%([A-Za-z0-9_.$]+),\s*label\s+%([A-Za-z0-9_.$]+)$", ln)
            if m_brcond:
                cond_tok, t_bb, f_bb = m_brcond.group(1), m_brcond.group(2), m_brcond.group(3)
                cond_op = parse_val(cond_tok)
                if cond_tok.startswith("%") and cond_tok[1:] in ext_zext_map:
                    cond_op = ext_zext_map[cond_tok[1:]]
                cur_bb.add_instruction(SSAInstruction(None, "br_cond", [cond_op, t_bb, f_bb]))
                continue

            m_ret = re.match(r"^ret\s+(i64|double)\s+(.+)$", ln)
            if m_ret:
                is_f = m_ret.group(1) == "double"
                cur_bb.add_instruction(SSAInstruction(None, "ret", [parse_val(m_ret.group(2), as_float=is_f)]))
                continue

            if (
                ln.startswith("store i64 ")
                or ln.startswith("store double ")
                or ln.startswith("store i32 ")
                or ln.startswith("store float ")
            ):
                m_st = re.match(r"^store\s+(i64|double|i32|float)\s+([^,]+),\s*ptr\s+(%[A-Za-z0-9_.$]+)", ln)
                if not m_st:
                    return None, f"UNSUPPORTED_LLVM_STORE_{ln}"
                st_ty = m_st.group(1)
                val_tok = m_st.group(2).strip()
                p_name = m_st.group(3)[1:]
                pt_entry = alias_ptr.get(p_name)
                if pt_entry is None:
                    base_op, idx_op, is_byte_off = get_or_create_var(m_st.group(3)), 0, False
                else:
                    base_op, idx_op, is_byte_off = pt_entry
                if st_ty == "i32":
                    raw_n = val_tok[1:] if val_tok.startswith("%") else val_tok
                    val_op = trunc_i32_map.get(raw_n, parse_val(val_tok))
                    cur_bb.add_instruction(SSAInstruction(None, "store_off", [base_op, idx_op, val_op, "i32"]))
                elif st_ty == "float":
                    raw_n = val_tok[1:] if val_tok.startswith("%") else val_tok
                    val_op = fptrunc_f32_map.get(raw_n, parse_val(val_tok, as_float=True))
                    cur_bb.add_instruction(SSAInstruction(None, "store_off", [base_op, idx_op, val_op, "f32"]))
                else:
                    is_f_st = st_ty == "double"
                    val_op = parse_val(val_tok, as_float=is_f_st)
                    if is_byte_off:
                        cur_bb.add_instruction(
                            SSAInstruction(None, "store_off", [base_op, idx_op, val_op, "f64" if is_f_st else "i64"])
                        )
                    else:
                        cur_bb.add_instruction(SSAInstruction(None, "store", [base_op, idx_op, val_op]))
                continue

            # Assignment instructions: %lhs = ...
            m_asg = re.match(r"^(%[A-Za-z0-9_.$]+)\s*=\s*(.+)$", ln)
            if not m_asg:
                return None, f"UNSUPPORTED_LLVM_STMT_{ln}"

            lhs_tok = m_asg.group(1)
            lhs_name = lhs_tok[1:]
            rhs = m_asg.group(2).strip()

            m_phi = re.match(r"^phi\s+(i64|double)\s+(.+)$", rhs)
            if m_phi:
                is_f = m_phi.group(1) == "double"
                incoming_pairs: List[Tuple[str, Any]] = []
                for pm in re.finditer(r"\[\s*([^,\]]+),\s*%([A-Za-z0-9_.$]+)\s*\]", rhs):
                    incoming_pairs.append((pm.group(2), parse_val(pm.group(1), as_float=is_f)))
                if not incoming_pairs:
                    return None, f"INVALID_LLVM_PHI_{ln}"
                res_v = get_or_create_var(lhs_tok, var_type="f64" if is_f else "i64")
                cur_bb.phi_nodes.append(
                    SSAInstruction(
                        result=res_v,
                        opcode="phi",
                        operands=[v for _, v in incoming_pairs],
                        phi_incoming=incoming_pairs,
                    )
                )
                continue

            m_alloca = re.match(r"^alloca\s+i8,\s*i64\s+([^,]+)", rhs)
            if m_alloca:
                res_v = get_or_create_var(lhs_tok)
                alloca_ptrs[lhs_name] = res_v
                cur_bb.add_instruction(SSAInstruction(res_v, "alloca", [parse_val(m_alloca.group(1))]))
                continue

            m_ptoi = re.match(r"^ptrtoint\s+ptr\s+(%[A-Za-z0-9_.$]+)\s+to\s+i64$", rhs)
            if m_ptoi:
                src_p = m_ptoi.group(1)[1:]
                res_v = get_or_create_var(lhs_tok)
                if src_p in alloca_ptrs:
                    cur_bb.add_instruction(SSAInstruction(res_v, "mov", [alloca_ptrs[src_p]]))
                else:
                    cur_bb.add_instruction(SSAInstruction(res_v, "mov", [parse_val(m_ptoi.group(1))]))
                continue

            m_itop = re.match(r"^inttoptr\s+i64\s+([^ ]+)\s+to\s+ptr$", rhs)
            if m_itop:
                alias_ptr[lhs_name] = (parse_val(m_itop.group(1)), 0, False)
                continue

            m_gep = re.match(r"^getelementptr\s+(i64|double|i8),\s*ptr\s+(%[A-Za-z0-9_.$]+),\s*i64\s+(.+)$", rhs)
            if m_gep:
                elem_t = m_gep.group(1)
                src_p = m_gep.group(2)[1:]
                idx_op = parse_val(m_gep.group(3))
                base_op = alias_ptr[src_p][0] if src_p in alias_ptr else get_or_create_var(m_gep.group(2))
                alias_ptr[lhs_name] = (base_op, idx_op, elem_t == "i8")
                continue

            m_load = re.match(r"^load\s+(i64|double|i32|float),\s*ptr\s+(%[A-Za-z0-9_.$]+)", rhs)
            if m_load:
                ld_ty = m_load.group(1)
                p_name = m_load.group(2)[1:]
                pt_entry = alias_ptr.get(p_name)
                if pt_entry is None:
                    base_op, idx_op, is_byte_off = get_or_create_var(m_load.group(2)), 0, False
                else:
                    base_op, idx_op, is_byte_off = pt_entry
                if ld_ty == "i32":
                    load_i32_map[lhs_name] = (base_op, idx_op, is_byte_off)
                    continue
                if ld_ty == "float":
                    load_f32_map[lhs_name] = (base_op, idx_op, is_byte_off)
                    continue
                is_f_ld = ld_ty == "double"
                res_v = get_or_create_var(lhs_tok, var_type="f64" if is_f_ld else "i64")
                if is_byte_off:
                    cur_bb.add_instruction(
                        SSAInstruction(res_v, "load_off", [base_op, idx_op, "f64" if is_f_ld else "i64"])
                    )
                else:
                    cur_bb.add_instruction(SSAInstruction(res_v, "load", [base_op, idx_op]))
                continue

            m_sext = re.match(r"^sext\s+i32\s+(%[A-Za-z0-9_.$]+)\s+to\s+i64$", rhs)
            if m_sext:
                src_n = m_sext.group(1)[1:]
                if src_n in load_i32_map:
                    base_op, off_op, _ = load_i32_map[src_n]
                    res_v = get_or_create_var(lhs_tok, var_type="i64")
                    cur_bb.add_instruction(SSAInstruction(res_v, "load_off", [base_op, off_op, "i32"]))
                    continue

            m_fpext = re.match(r"^fpext\s+float\s+(%[A-Za-z0-9_.$]+)\s+to\s+double$", rhs)
            if m_fpext:
                src_n = m_fpext.group(1)[1:]
                if src_n in load_f32_map:
                    base_op, off_op, _ = load_f32_map[src_n]
                    res_v = get_or_create_var(lhs_tok, var_type="f64")
                    cur_bb.add_instruction(SSAInstruction(res_v, "load_off", [base_op, off_op, "f32"]))
                    continue

            m_trunc = re.match(r"^trunc\s+i64\s+(.+)\s+to\s+i32$", rhs)
            if m_trunc:
                trunc_i32_map[lhs_name] = parse_val(m_trunc.group(1))
                continue

            m_fptrunc = re.match(r"^fptrunc\s+double\s+(.+)\s+to\s+float$", rhs)
            if m_fptrunc:
                fptrunc_f32_map[lhs_name] = parse_val(m_fptrunc.group(1), as_float=True)
                continue

            m_icmp = re.match(r"^icmp\s+(eq|ne|slt|sle|sgt|sge)\s+i64\s+([^,]+),\s*(.+)$", rhs)
            if m_icmp:
                pred = m_icmp.group(1)
                op0 = parse_val(m_icmp.group(2))
                op1 = parse_val(m_icmp.group(3))
                res_v = get_or_create_var(lhs_tok)
                ext_zext_map[lhs_name] = res_v
                cur_bb.add_instruction(SSAInstruction(res_v, cls.LLVM_ICMP_MAP[pred], [op0, op1]))
                continue

            m_fcmp = re.match(r"^fcmp\s+(oeq|one|olt|ole|ogt|oge)\s+double\s+([^,]+),\s*(.+)$", rhs)
            if m_fcmp:
                pred = m_fcmp.group(1)
                op0 = parse_val(m_fcmp.group(2), as_float=True)
                op1 = parse_val(m_fcmp.group(3), as_float=True)
                res_v = get_or_create_var(lhs_tok)
                ext_zext_map[lhs_name] = res_v
                cur_bb.add_instruction(SSAInstruction(res_v, cls.LLVM_FCMP_MAP[pred], [op0, op1]))
                continue

            m_zext = re.match(r"^zext\s+i1\s+(%[A-Za-z0-9_.$]+)\s+to\s+i64$", rhs)
            if m_zext:
                src_n = m_zext.group(1)[1:]
                res_v = get_or_create_var(lhs_tok)
                src_v = ext_zext_map.get(src_n, get_or_create_var(m_zext.group(1)))
                cur_bb.add_instruction(SSAInstruction(res_v, "mov", [src_v]))
                continue

            m_sitofp = re.match(r"^sitofp\s+i64\s+(.+)\s+to\s+double$", rhs)
            if m_sitofp:
                res_v = get_or_create_var(lhs_tok, var_type="f64")
                cur_bb.add_instruction(SSAInstruction(res_v, "sitofp", [parse_val(m_sitofp.group(1))]))
                continue

            m_fptosi = re.match(r"^fptosi\s+double\s+(.+)\s+to\s+i64$", rhs)
            if m_fptosi:
                res_v = get_or_create_var(lhs_tok, var_type="i64")
                cur_bb.add_instruction(SSAInstruction(res_v, "fptosi", [parse_val(m_fptosi.group(1), as_float=True)]))
                continue

            m_fneg = re.match(r"^fneg\s+double\s+(.+)$", rhs)
            if m_fneg:
                res_v = get_or_create_var(lhs_tok, var_type="f64")
                cur_bb.add_instruction(SSAInstruction(res_v, "fneg", [parse_val(m_fneg.group(1), as_float=True)]))
                continue

            m_sel = re.match(r"^select\s+i1\s+([^,]+),\s*(i64|double)\s+([^,]+),\s*(i64|double)\s+(.+)$", rhs)
            if m_sel:
                c_tok = m_sel.group(1).strip()
                c_op = ext_zext_map[c_tok[1:]] if (c_tok.startswith("%") and c_tok[1:] in ext_zext_map) else parse_val(c_tok)
                is_f = m_sel.group(2) == "double"
                res_v = get_or_create_var(lhs_tok, var_type="f64" if is_f else "i64")
                cur_bb.add_instruction(
                    SSAInstruction(
                        res_v,
                        "select",
                        [c_op, parse_val(m_sel.group(3), as_float=is_f), parse_val(m_sel.group(5), as_float=is_f)],
                    )
                )
                continue

            m_bin = re.match(r"^([a-z]+)\s+i64\s+([^,]+),\s*(.+)$", rhs)
            if m_bin and m_bin.group(1) in cls.LLVM_BINOP_MAP:
                ssa_op = cls.LLVM_BINOP_MAP[m_bin.group(1)]
                res_v = get_or_create_var(lhs_tok)
                cur_bb.add_instruction(SSAInstruction(res_v, ssa_op, [parse_val(m_bin.group(2)), parse_val(m_bin.group(3))]))
                continue

            m_fbin = re.match(r"^(fadd|fsub|fmul|fdiv)\s+double\s+([^,]+),\s*(.+)$", rhs)
            if m_fbin:
                fop = m_fbin.group(1)
                lhs_arg = m_fbin.group(2).strip()
                rhs_arg = m_fbin.group(3).strip()
                res_v = get_or_create_var(lhs_tok, var_type="f64")
                if fop == "fadd" and lhs_arg == "-0.0":
                    val_r = parse_val(rhs_arg, as_float=True)
                    if isinstance(val_r, float):
                        cur_bb.add_instruction(SSAInstruction(res_v, "fconst", [val_r]))
                    else:
                        cur_bb.add_instruction(SSAInstruction(res_v, "mov", [val_r]))
                else:
                    cur_bb.add_instruction(
                        SSAInstruction(res_v, fop, [parse_val(lhs_arg, as_float=True), parse_val(rhs_arg, as_float=True)])
                    )
                continue

            m_call = re.match(r"^call\s+(i64|double)\s+@([A-Za-z0-9_.$]+)\((.*)\)$", rhs)
            if m_call:
                ret_is_f = m_call.group(1) == "double"
                callee = m_call.group(2)
                raw_args = m_call.group(3).strip()
                call_args: List[Any] = []
                if raw_args:
                    for part in raw_args.split(","):
                        toks = part.strip().split()
                        if not toks:
                            return None, f"INVALID_LLVM_CALL_ARG_{ln}"
                        is_af = toks[0] == "double"
                        call_args.append(parse_val(toks[-1], as_float=is_af))
                res_v = get_or_create_var(lhs_tok, var_type="f64" if ret_is_f else "i64")
                cur_bb.add_instruction(SSAInstruction(res_v, "call", [callee] + call_args))
                continue

            return None, f"UNSUPPORTED_LLVM_OP_{rhs}"

        for bname in block_order:
            ssa_fn.add_block(blocks[bname])

        # Wire CFG predecessor/successor links from terminators
        for bb in ssa_fn.blocks:
            for inst in bb.instructions:
                if inst.opcode == "br" and inst.operands:
                    t = str(inst.operands[0])
                    if t in blocks:
                        bb.connect_to(blocks[t])
                elif inst.opcode == "br_cond" and len(inst.operands) >= 3:
                    for t in (str(inst.operands[1]), str(inst.operands[2])):
                        if t in blocks:
                            bb.connect_to(blocks[t])

        return ssa_fn, None


class WATToSSALifter:
    """
    Deterministic lifter from `WasmBackend` WAT output (both single-block and
    `$cfg_dispatch` multi-block CFGs) back into `SSAFunction`.
    """

    WAT_BINOP_MAP = {
        "i64.add": "add",
        "i64.sub": "sub",
        "i64.mul": "mul",
        "i64.div_s": "sdiv",
        "i64.rem_s": "srem",
        "i64.shl": "shl",
        "i64.shr_s": "sar",
        "i64.shr_u": "lshr",
        "i64.and": "and",
        "i64.or": "or",
        "i64.xor": "xor",
    }
    WAT_CMP_MAP = {
        "i64.eq": "cmp_eq",
        "i64.ne": "cmp_ne",
        "i64.lt_s": "cmp_lt",
        "i64.le_s": "cmp_le",
        "i64.gt_s": "cmp_gt",
        "i64.ge_s": "cmp_ge",
    }
    WAT_FLOAT_BINOP_MAP = {
        "f64.add": "fadd",
        "f64.sub": "fsub",
        "f64.mul": "fmul",
        "f64.div": "fdiv",
    }
    WAT_FLOAT_CMP_MAP = {
        "f64.eq": "fcmp_eq",
        "f64.ne": "fcmp_ne",
        "f64.lt": "fcmp_lt",
        "f64.le": "fcmp_le",
        "f64.gt": "fcmp_gt",
        "f64.ge": "fcmp_ge",
    }

    @classmethod
    def _extract_func_block(cls, wat: str, target_name: Optional[str] = None) -> Optional[str]:
        idx = 0
        while True:
            pos = wat.find("(func ", idx)
            if pos == -1:
                return None
            depth = 0
            end = pos
            while end < len(wat):
                ch = wat[end]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        end += 1
                        break
                end += 1
            chunk = wat[pos:end]
            if target_name is None or f'${target_name}' in chunk.splitlines()[0] or f'"{target_name}"' in chunk.splitlines()[0]:
                return chunk
            idx = end

    @classmethod
    def _extract_func_arities(cls, wat: str) -> Dict[str, int]:
        arities: Dict[str, int] = {}
        idx = 0
        while True:
            pos = wat.find("(func ", idx)
            if pos == -1:
                break
            depth = 0
            end = pos
            while end < len(wat):
                ch = wat[end]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        end += 1
                        break
                end += 1
            chunk = wat[pos:end]
            chunk_lines = [ln.strip() for ln in chunk.splitlines() if ln.strip()]
            if chunk_lines:
                hdr = chunk_lines[0]
                m_sym = re.search(r"\(func\s+\$([^\s()]+)", hdr)
                m_exp = re.search(r'\(export\s+"([^"]+)"\)', hdr)
                # Count leading (param ...) declarations before body/local
                sig_text = [hdr]
                for ln in chunk_lines[1:]:
                    if ln.startswith("(param ") or ln.startswith("(result "):
                        sig_text.append(ln)
                    elif ln.startswith("(local "):
                        break
                    else:
                        break
                joined_sig = " ".join(sig_text)
                param_cnt = 0
                for p_inner in re.findall(r"\(param\b([^)]*)\)", joined_sig):
                    toks = [tk for tk in p_inner.split() if tk in ("i64", "i32", "f64", "f32")]
                    param_cnt += len(toks) if toks else 1
                if m_sym:
                    arities[m_sym.group(1)] = param_cnt
                if m_exp:
                    arities[m_exp.group(1)] = param_cnt
            idx = end
        return arities

    @classmethod
    def _extract_func_signatures(cls, wat: str) -> Tuple[Dict[str, int], Dict[str, str]]:
        arities: Dict[str, int] = {}
        ret_types: Dict[str, str] = {}
        idx = 0
        while True:
            pos = wat.find("(func ", idx)
            if pos < 0:
                break
            depth = 0
            end = pos
            while end < len(wat):
                ch = wat[end]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        end += 1
                        break
                end += 1
            chunk = wat[pos:end]
            chunk_lines = [ln.strip() for ln in chunk.splitlines() if ln.strip()]
            if chunk_lines:
                hdr = chunk_lines[0]
                m_sym = re.search(r"\(func\s+\$([^\s()]+)", hdr)
                m_exp = re.search(r'\(export\s+"([^"]+)"\)', hdr)
                sig_text = [hdr]
                for ln in chunk_lines[1:]:
                    if ln.startswith("(param ") or ln.startswith("(result "):
                        sig_text.append(ln)
                    elif ln.startswith("(local "):
                        break
                    else:
                        break
                joined_sig = " ".join(sig_text)
                param_cnt = 0
                for p_inner in re.findall(r"\(param\b([^)]*)\)", joined_sig):
                    toks = [tk for tk in p_inner.split() if tk in ("i64", "i32", "f64", "f32")]
                    param_cnt += len(toks) if toks else 1
                m_res_sig = re.search(r"\(result\s+(i64|i32|f64|f32)\)", joined_sig)
                ret_ty = "f64" if (m_res_sig and m_res_sig.group(1) in ("f64", "f32")) else "i64"
                if m_sym:
                    arities[m_sym.group(1)] = param_cnt
                    ret_types[m_sym.group(1)] = ret_ty
                if m_exp:
                    arities[m_exp.group(1)] = param_cnt
                    ret_types[m_exp.group(1)] = ret_ty
            idx = end
        return arities, ret_types

    @classmethod
    def lift_function(cls, wat: str, target_name: Optional[str] = None) -> Tuple[Optional[SSAFunction], Optional[str]]:
        chunk = cls._extract_func_block(wat, target_name=target_name)
        if chunk is None:
            return None, "WAT_FUNC_NOT_FOUND"
        func_arities, func_ret_types = cls._extract_func_signatures(wat)

        lines = [ln.strip() for ln in chunk.splitlines() if ln.strip()]
        header = lines[0]
        m_name = re.search(r"\(export\s+\"([^\"]+)\"\)", header)
        if not m_name:
            m_name = re.search(r"\(func\s+\$([^\s(]+)", header)
        fn_name = m_name.group(1) if m_name else (target_name or "wasm_fn")

        params: List[str] = []
        param_types: Dict[str, str] = {}
        for pm in re.finditer(r"\(param\s+\$([^\s)]+)\s+(i64|i32|f64|f32)\)", header):
            params.append(pm.group(1))
            param_types[pm.group(1)] = "f64" if pm.group(2) in ("f64", "f32") else "i64"
        m_res_hdr = re.search(r"\(result\s+(i64|i32|f64|f32)\)", header)
        ret_type = "f64" if (m_res_hdr and m_res_hdr.group(1) in ("f64", "f32")) else "i64"
        local_names: set = set()
        local_types: Dict[str, str] = {}
        body_start_idx = 1
        for i in range(1, len(lines)):
            ln = lines[i]
            if ln.startswith("(param "):
                for pm in re.finditer(r"\(param\s+\$([^\s)]+)\s+(i64|i32|f64|f32)\)", ln):
                    params.append(pm.group(1))
                    param_types[pm.group(1)] = "f64" if pm.group(2) in ("f64", "f32") else "i64"
                body_start_idx = i + 1
            elif ln.startswith("(result "):
                m_res_ln = re.search(r"\(result\s+(i64|i32|f64|f32)\)", ln)
                if m_res_ln and m_res_ln.group(1) in ("f64", "f32"):
                    ret_type = "f64"
                body_start_idx = i + 1
            elif ln.startswith("(local "):
                for lm in re.finditer(r"\(local\s+\$([^\s)]+)\s+(i64|i32|f64|f32)\)", ln):
                    local_names.add(lm.group(1))
                    local_types[lm.group(1)] = "f64" if lm.group(2) in ("f64", "f32") else "i64"
                body_start_idx = i + 1
            else:
                body_start_idx = i
                break

        body_lines = lines[body_start_idx:-1] if lines[-1] == ")" else lines[body_start_idx:]
        ssa_fn = SSAFunction(fn_name, params, param_types=param_types, return_type=ret_type)
        tmp_counter = 0

        def next_var(prefix: str = "wt", var_type: str = "i64") -> SSAVar:
            nonlocal tmp_counter
            tmp_counter += 1
            return SSAVar(prefix, tmp_counter, var_type=var_type)

        is_multiblock = any("(loop $cfg_dispatch" in ln for ln in body_lines)

        if not is_multiblock:
            entry = BasicBlock("entry")
            ssa_fn.add_block(entry)
            ssa_fn.entry_block = entry
            env: Dict[str, Any] = {}
            for p in params:
                pv = SSAVar(p, 0, var_type=param_types.get(p, "i64"))
                env[p] = pv
                entry.add_instruction(SSAInstruction(pv, "param", [p]))
            for loc in local_names:
                env.setdefault(loc, 0.0 if local_types.get(loc) == "f64" else 0)

            err = cls._lower_wat_block_lines(
                body_lines, entry, env, next_var, has_return_ref=[False],
                func_arities=func_arities, func_ret_types=func_ret_types,
            )
            if err:
                return None, err
            return ssa_fn, None

        # Multi-block `$cfg_dispatch` lifter: parse each `i32.const <k> / i32.eq / (if (then ...))` dispatch arm
        dispatch_chunks: Dict[int, List[str]] = {}
        i = 0
        while i < len(body_lines):
            if (
                i + 3 < len(body_lines)
                and body_lines[i] == "local.get $__bb"
                and body_lines[i + 1].startswith("i32.const ")
                and body_lines[i + 2] == "i32.eq"
                and body_lines[i + 3] == "(if"
            ):
                b_idx = int(body_lines[i + 1].split()[1])
                # Collect until matching closing `)` of this dispatch `(if`
                depth = 1
                j = i + 4
                arm_lines: List[str] = []
                while j < len(body_lines) and depth > 0:
                    tok = body_lines[j]
                    depth += tok.count("(") - tok.count(")")
                    if depth > 0:
                        arm_lines.append(tok)
                    j += 1
                # Strip outer `(then` and matching `)`
                if arm_lines and arm_lines[0] == "(then" and arm_lines[-1] == ")":
                    arm_lines = arm_lines[1:-1]
                dispatch_chunks[b_idx] = arm_lines
                i = j
            else:
                i += 1

        if not dispatch_chunks:
            return None, "WAT_EMPTY_DISPATCH"

        block_objs: Dict[int, BasicBlock] = {}
        for b_idx in sorted(dispatch_chunks.keys()):
            bb = BasicBlock(f"bb_{b_idx}")
            block_objs[b_idx] = bb
            ssa_fn.add_block(bb)
            if b_idx == 0:
                ssa_fn.entry_block = bb

        # Parameter initialization in block 0
        entry_bb = block_objs[0]
        local_ssa_vars: Dict[str, SSAVar] = {}
        for p in params:
            pv = SSAVar(p, 0, var_type=param_types.get(p, "i64"))
            local_ssa_vars[p] = pv
            entry_bb.add_instruction(SSAInstruction(pv, "param", [p]))
        for loc in sorted(local_names):
            if loc != "__bb" and loc not in local_ssa_vars:
                lv = SSAVar(loc, 0, var_type=local_types.get(loc, "i64"))
                local_ssa_vars[loc] = lv

        # Determine which `$loc` symbols are assigned on incoming edges (phi-nodes) vs intra-block
        # In WasmBackend, every `phi` variable is stored to its `$loc` on predecessor edge right before `local.set $__bb`.
        # Map `$loc` -> SSAVar cleanly across dispatch blocks via incoming phi resolution!
        edge_writes: Dict[Tuple[int, int], Dict[str, Any]] = {}
        block_env_end: Dict[int, Dict[str, Any]] = {}
        # Initialize entry locals to 0 / 0.0 if not params
        init_locals_bb0 = {k: v for k, v in local_ssa_vars.items()}
        for loc in sorted(local_names):
            if loc != "__bb" and loc not in params:
                init_val = 0.0 if local_types.get(loc) == "f64" else 0
                entry_bb.add_instruction(SSAInstruction(init_locals_bb0[loc], "const", [init_val]))

        # First pass: collect CFG edges + intra-block operations
        # Create per-block versioned local mapping so each SSA variable is single-assignment per block entry
        preds_of: Dict[int, List[int]] = {k: [] for k in block_objs}
        edges_by_src: Dict[int, List[Tuple[int, Dict[str, Any]]]] = {k: [] for k in block_objs}

        # Two-phase pass: identify control-flow transfers and stack expressions
        block_entry_vars: Dict[int, Dict[str, SSAVar]] = {}
        for b_idx in block_objs:
            if b_idx == 0:
                block_entry_vars[0] = dict(local_ssa_vars)
            else:
                bmap: Dict[str, SSAVar] = {}
                for k in sorted(local_ssa_vars.keys()):
                    bmap[k] = next_var(f"b{b_idx}_{k}", var_type=local_ssa_vars[k].var_type)
                block_entry_vars[b_idx] = bmap

        for b_idx in sorted(dispatch_chunks.keys()):
            bb = block_objs[b_idx]
            env: Dict[str, Any] = dict(block_entry_vars[b_idx])
            err = cls._lower_wat_multiblock_arm(
                dispatch_chunks[b_idx], b_idx, bb, env, block_objs,
                next_var, edge_writes, preds_of, edges_by_src,
                func_arities=func_arities,
                func_ret_types=func_ret_types,
            )
            if err:
                return None, err
            block_env_end[b_idx] = env

        # Second pass: wire SSA Phi nodes for every block with >= 1 predecessor
        for b_idx, bb in block_objs.items():
            preds = preds_of.get(b_idx, [])
            if not preds or b_idx == 0:
                if b_idx == 0 and preds:
                    # Edge back into block 0 -> needs phis too
                    pass
                else:
                    continue
            for loc_name, target_var in block_entry_vars[b_idx].items():
                incoming: List[Tuple[str, Any]] = []
                if b_idx == 0:
                    incoming.append(("__init__", local_ssa_vars[loc_name]))
                for p_idx in preds:
                    ew = edge_writes.get((p_idx, b_idx), {})
                    if loc_name in ew:
                        val = ew[loc_name]
                    else:
                        val = block_env_end[p_idx].get(loc_name, target_var)
                    incoming.append((f"bb_{p_idx}", val))
                if incoming:
                    bb.phi_nodes.append(
                        SSAInstruction(
                            result=target_var,
                            opcode="phi",
                            operands=[v for _, v in incoming],
                            phi_incoming=incoming,
                        )
                    )

        if preds_of.get(0):
            # Insert clean `__init__` preheader block so block 0 has valid preheader incoming phi edges
            init_bb = BasicBlock("__init__")
            for p in params:
                init_bb.add_instruction(SSAInstruction(SSAVar(p, 0, var_type=param_types.get(p, "i64")), "param", [p]))
            for loc in sorted(local_names):
                if loc != "__bb" and loc not in params:
                    init_val = 0.0 if local_types.get(loc) == "f64" else 0
                    init_bb.add_instruction(SSAInstruction(local_ssa_vars[loc], "const", [init_val]))
            init_bb.add_instruction(SSAInstruction(None, "br", ["bb_0"]))
            # Move entry instructions out of bb_0 since __init__ handles param/const initialization
            entry_bb.instructions = [
                inst for inst in entry_bb.instructions if inst.opcode not in ("param",)
            ]
            init_bb.connect_to(entry_bb)
            ssa_fn.blocks.insert(0, init_bb)
            ssa_fn.entry_block = init_bb

        return ssa_fn, None

    @classmethod
    def _eval_wat_step(
        cls,
        ln: str,
        stack: List[Any],
        bb: BasicBlock,
        env: Dict[str, Any],
        next_var,
        pending_edge_locs: Optional[Dict[str, Any]] = None,
        func_arities: Optional[Dict[str, int]] = None,
        func_ret_types: Optional[Dict[str, str]] = None,
    ) -> Optional[str]:
        if ln.startswith("i64.const "):
            stack.append(int(ln.split()[1]))
            return None
        if ln.startswith("f64.const "):
            stack.append(float(ln.split()[1]))
            return None
        if ln.startswith("local.get $"):
            vname = ln[len("local.get $"):].strip()
            stack.append(env.get(vname, 0))
            return None
        if ln.startswith("local.set $"):
            vname = ln[len("local.set $"):].strip()
            if not stack:
                return f"WAT_STACK_UNDERFLOW_{ln}"
            val = stack.pop()
            if pending_edge_locs is not None:
                pending_edge_locs[vname] = val
            else:
                prev_val = env.get(vname)
                val_vt = (
                    "f64"
                    if (
                        isinstance(val, float)
                        or (isinstance(val, SSAVar) and getattr(val, "var_type", "i64") == "f64")
                        or (isinstance(prev_val, SSAVar) and getattr(prev_val, "var_type", "i64") == "f64")
                    )
                    else "i64"
                )
                rv = next_var(vname, var_type=val_vt)
                bb.add_instruction(SSAInstruction(rv, "mov", [val]))
                env[vname] = rv
            return None
        if ln in cls.WAT_BINOP_MAP:
            if len(stack) < 2:
                return f"WAT_STACK_UNDERFLOW_{ln}"
            rhs = stack.pop()
            lhs = stack.pop()
            rv = next_var("wb")
            bb.add_instruction(SSAInstruction(rv, cls.WAT_BINOP_MAP[ln], [lhs, rhs]))
            stack.append(rv)
            return None
        if ln in cls.WAT_FLOAT_BINOP_MAP:
            if len(stack) < 2:
                return f"WAT_STACK_UNDERFLOW_{ln}"
            rhs = stack.pop()
            lhs = stack.pop()
            rv = next_var("wfb", var_type="f64")
            bb.add_instruction(SSAInstruction(rv, cls.WAT_FLOAT_BINOP_MAP[ln], [lhs, rhs]))
            stack.append(rv)
            return None
        if ln in cls.WAT_CMP_MAP:
            if len(stack) < 2:
                return f"WAT_STACK_UNDERFLOW_{ln}"
            rhs = stack.pop()
            lhs = stack.pop()
            rv = next_var("wc")
            bb.add_instruction(SSAInstruction(rv, cls.WAT_CMP_MAP[ln], [lhs, rhs]))
            stack.append(rv)
            return None
        if ln in cls.WAT_FLOAT_CMP_MAP:
            if len(stack) < 2:
                return f"WAT_STACK_UNDERFLOW_{ln}"
            rhs = stack.pop()
            lhs = stack.pop()
            rv = next_var("wfc")
            bb.add_instruction(SSAInstruction(rv, cls.WAT_FLOAT_CMP_MAP[ln], [lhs, rhs]))
            stack.append(rv)
            return None
        if ln == "f64.neg":
            if not stack:
                return "WAT_STACK_UNDERFLOW_fneg"
            v = stack.pop()
            rv = next_var("wfneg", var_type="f64")
            bb.add_instruction(SSAInstruction(rv, "fneg", [v]))
            stack.append(rv)
            return None
        if ln == "f64.convert_i64_s":
            if not stack:
                return "WAT_STACK_UNDERFLOW_convert"
            v = stack.pop()
            rv = next_var("wfp", var_type="f64")
            bb.add_instruction(SSAInstruction(rv, "sitofp", [v]))
            stack.append(rv)
            return None
        if ln == "i64.trunc_f64_s":
            if not stack:
                return "WAT_STACK_UNDERFLOW_trunc"
            v = stack.pop()
            rv = next_var("wtrunc")
            bb.add_instruction(SSAInstruction(rv, "fptosi", [v]))
            stack.append(rv)
            return None
        if ln == "i64.eqz":
            if not stack:
                return "WAT_STACK_UNDERFLOW_eqz"
            v = stack.pop()
            rv = next_var("wn")
            bb.add_instruction(SSAInstruction(rv, "not", [v]))
            stack.append(rv)
            return None
        if ln == "i64.extend_i32_u":
            return None  # already 0/1 in 64-bit Omni-SSA comparison vars
        if ln == "select":
            if len(stack) < 3:
                return "WAT_STACK_UNDERFLOW_select"
            cond = stack.pop()
            f_val = stack.pop()
            t_val = stack.pop()
            sel_vt = (
                "f64"
                if (
                    isinstance(t_val, float)
                    or isinstance(f_val, float)
                    or (isinstance(t_val, SSAVar) and getattr(t_val, "var_type", "i64") == "f64")
                    or (isinstance(f_val, SSAVar) and getattr(f_val, "var_type", "i64") == "f64")
                )
                else "i64"
            )
            rv = next_var("ws", var_type=sel_vt)
            bb.add_instruction(SSAInstruction(rv, "select", [cond, t_val, f_val]))
            stack.append(rv)
            return None
        if ln == "i32.wrap_i64":
            if not stack:
                return "WAT_STACK_UNDERFLOW_wrap"
            addr_val = stack.pop()
            if (
                len(bb.instructions) >= 2
                and bb.instructions[-1].opcode == "add"
                and bb.instructions[-1].result == addr_val
                and len(bb.instructions[-1].operands) == 2
                and bb.instructions[-2].opcode == "shl"
                and bb.instructions[-2].result == bb.instructions[-1].operands[1]
                and len(bb.instructions[-2].operands) == 2
                and bb.instructions[-2].operands[1] == 3
            ):
                base_op = bb.instructions[-1].operands[0]
                idx_op = bb.instructions[-2].operands[0]
                stack.append(("__wat_ptr__", base_op, idx_op))
            elif (
                len(bb.instructions) >= 1
                and bb.instructions[-1].opcode == "add"
                and bb.instructions[-1].result == addr_val
                and len(bb.instructions[-1].operands) == 2
            ):
                stack.append(("__wat_ptr_byte__", bb.instructions[-1].operands[0], bb.instructions[-1].operands[1]))
            else:
                stack.append(("__wat_ptr__", addr_val, 0))
            return None
        if ln in ("i64.load", "f64.load", "i64.load32_s", "f32.load"):
            if not stack:
                return "WAT_STACK_UNDERFLOW_load"
            addr_tok = stack.pop()
            if isinstance(addr_tok, tuple) and len(addr_tok) == 3 and addr_tok[0] == "__wat_ptr_byte__":
                base_op, idx_op, is_byte = addr_tok[1], addr_tok[2], True
            elif isinstance(addr_tok, tuple) and len(addr_tok) == 3 and addr_tok[0] == "__wat_ptr__":
                base_op, idx_op, is_byte = addr_tok[1], addr_tok[2], False
            else:
                base_op, idx_op, is_byte = addr_tok, 0, (ln in ("i64.load32_s", "f32.load"))
            if ln == "i64.load32_s":
                rv = next_var("wld32", var_type="i64")
                bb.add_instruction(SSAInstruction(rv, "load_off", [base_op, idx_op, "i32"]))
            elif ln == "f32.load":
                rv = next_var("wldf32", var_type="f64")
                bb.add_instruction(SSAInstruction(rv, "load_off", [base_op, idx_op, "f32"]))
            elif is_byte:
                rv = next_var("wldo", var_type="f64" if ln == "f64.load" else "i64")
                bb.add_instruction(SSAInstruction(rv, "load_off", [base_op, idx_op, "f64" if ln == "f64.load" else "i64"]))
            else:
                rv = next_var("wld", var_type="f64" if ln == "f64.load" else "i64")
                bb.add_instruction(SSAInstruction(rv, "load", [base_op, idx_op]))
            stack.append(rv)
            return None
        if ln in ("f64.promote_f32", "f32.demote_f64"):
            return None
        if ln in ("i64.store", "f64.store", "i64.store32", "f32.store"):
            if len(stack) < 2:
                return "WAT_STACK_UNDERFLOW_store"
            val_op = stack.pop()
            addr_tok = stack.pop()
            if isinstance(addr_tok, tuple) and len(addr_tok) == 3 and addr_tok[0] == "__wat_ptr_byte__":
                base_op, idx_op, is_byte = addr_tok[1], addr_tok[2], True
            elif isinstance(addr_tok, tuple) and len(addr_tok) == 3 and addr_tok[0] == "__wat_ptr__":
                base_op, idx_op, is_byte = addr_tok[1], addr_tok[2], False
            else:
                base_op, idx_op, is_byte = addr_tok, 0, (ln in ("i64.store32", "f32.store"))
            if ln == "i64.store32":
                bb.add_instruction(SSAInstruction(None, "store_off", [base_op, idx_op, val_op, "i32"]))
            elif ln == "f32.store":
                bb.add_instruction(SSAInstruction(None, "store_off", [base_op, idx_op, val_op, "f32"]))
            elif is_byte:
                bb.add_instruction(SSAInstruction(None, "store_off", [base_op, idx_op, val_op, "f64" if ln == "f64.store" else "i64"]))
            else:
                bb.add_instruction(SSAInstruction(None, "store", [base_op, idx_op, val_op]))
            return None
        if ln.startswith("call $"):
            callee = ln[len("call $") :].strip()
            if not func_arities or callee not in func_arities:
                return f"UNKNOWN_WAT_CALL_ARITY_{callee}"
            arity = func_arities[callee]
            if len(stack) < arity:
                return f"WAT_STACK_UNDERFLOW_call_{callee}"
            call_args = [stack.pop() for _ in range(arity)][::-1]
            call_vt = (func_ret_types or {}).get(callee, "i64")
            rv = next_var("wcall", var_type=call_vt)
            bb.add_instruction(SSAInstruction(rv, "call", [callee] + call_args))
            stack.append(rv)
            return None
        if ln == "return":
            rv = stack.pop() if stack else 0
            bb.add_instruction(SSAInstruction(None, "ret", [rv]))
            return None
        return f"UNSUPPORTED_WAT_OP_{ln}"

    @classmethod
    def _lower_wat_block_lines(
        cls,
        body_lines: List[str],
        bb: BasicBlock,
        env: Dict[str, Any],
        next_var,
        has_return_ref: List[bool],
        func_arities: Optional[Dict[str, int]] = None,
        func_ret_types: Optional[Dict[str, str]] = None,
    ) -> Optional[str]:
        stack: List[Any] = []
        for ln in body_lines:
            if ln == "return":
                has_return_ref[0] = True
            err = cls._eval_wat_step(
                ln, stack, bb, env, next_var,
                func_arities=func_arities,
                func_ret_types=func_ret_types,
            )
            if err:
                return err
        if not has_return_ref[0]:
            rv = stack.pop() if stack else 0
            bb.add_instruction(SSAInstruction(None, "ret", [rv]))
        return None

    @classmethod
    def _lower_wat_multiblock_arm(
        cls,
        arm_lines: List[str],
        b_idx: int,
        bb: BasicBlock,
        env: Dict[str, Any],
        block_objs: Dict[int, BasicBlock],
        next_var,
        edge_writes: Dict[Tuple[int, int], Dict[str, Any]],
        preds_of: Dict[int, List[int]],
        edges_by_src: Dict[int, List[Tuple[int, Dict[str, Any]]]],
        func_arities: Optional[Dict[str, int]] = None,
        func_ret_types: Optional[Dict[str, str]] = None,
    ) -> Optional[str]:
        stack: List[Any] = []
        i = 0
        while i < len(arm_lines):
            ln = arm_lines[i]
            # Unconditional CFG dispatch jump sequence: `i32.const K`, `local.set $__bb`, `br $cfg_dispatch`
            if (
                i + 2 < len(arm_lines)
                and arm_lines[i].startswith("i32.const ")
                and arm_lines[i + 1] == "local.set $__bb"
                and arm_lines[i + 2] == "br $cfg_dispatch"
            ):
                tgt_idx = int(arm_lines[i].split()[1])
                edge_writes[(b_idx, tgt_idx)] = dict(env)
                bb.add_instruction(SSAInstruction(None, "br", [f"bb_{tgt_idx}"]))
                bb.connect_to(block_objs[tgt_idx])
                if b_idx not in preds_of[tgt_idx]:
                    preds_of[tgt_idx].append(b_idx)
                return None

            # Conditional dispatch `(if (then ...) (else ...))`
            if ln == "(if":
                if not stack:
                    return "WAT_MISSING_IF_COND"
                cond_op = stack.pop()
                i += 1
                then_lines: List[str] = []
                else_lines: List[str] = []
                cur_target = None
                depth = 0
                while i < len(arm_lines):
                    t = arm_lines[i]
                    if t == "(then" and depth == 0:
                        cur_target = then_lines
                        depth = 1
                        i += 1
                        continue
                    if t == "(else" and depth == 0:
                        cur_target = else_lines
                        depth = 1
                        i += 1
                        continue
                    if t == ")" and depth == 0:
                        i += 1
                        break
                    depth += t.count("(") - t.count(")")
                    if depth == 0:
                        cur_target = None
                    elif cur_target is not None:
                        cur_target.append(t)
                    i += 1

                def parse_branch_arm(br_lines: List[str]) -> Tuple[Optional[int], Dict[str, Any], Optional[str]]:
                    br_stack: List[Any] = []
                    branch_env: Dict[str, Any] = dict(env)
                    tgt = None
                    j = 0
                    while j < len(br_lines):
                        bl = br_lines[j]
                        if (
                            j + 2 < len(br_lines)
                            and br_lines[j].startswith("i32.const ")
                            and br_lines[j + 1] == "local.set $__bb"
                            and br_lines[j + 2] == "br $cfg_dispatch"
                        ):
                            tgt = int(br_lines[j].split()[1])
                            break
                        err_s = cls._eval_wat_step(
                            bl, br_stack, bb, branch_env, next_var,
                            func_arities=func_arities,
                            func_ret_types=func_ret_types,
                        )
                        if err_s:
                            return None, {}, err_s
                        j += 1
                    return tgt, branch_env, None

                t_idx, t_writes, err_t = parse_branch_arm(then_lines)
                if err_t or t_idx is None:
                    return err_t or "WAT_INVALID_THEN_BRANCH"
                f_idx, f_writes, err_f = parse_branch_arm(else_lines)
                if err_f or f_idx is None:
                    return err_f or "WAT_INVALID_ELSE_BRANCH"

                edge_writes[(b_idx, t_idx)] = t_writes
                edge_writes[(b_idx, f_idx)] = f_writes
                bb.add_instruction(SSAInstruction(None, "br_cond", [cond_op, f"bb_{t_idx}", f"bb_{f_idx}"]))
                bb.connect_to(block_objs[t_idx])
                bb.connect_to(block_objs[f_idx])
                if b_idx not in preds_of[t_idx]:
                    preds_of[t_idx].append(b_idx)
                if b_idx not in preds_of[f_idx]:
                    preds_of[f_idx].append(b_idx)
                return None

            err = cls._eval_wat_step(
                ln, stack, bb, env, next_var,
                func_arities=func_arities,
                func_ret_types=func_ret_types,
            )
            if err:
                return err
            i += 1
        return None


class BackendTranslationValidator:
    """
    Verifies formal IR equivalence across backend lowerings (`LLVMBackend`, `WasmBackend`)
    and runs physical cross-backend differential execution checks.
    """

    def __init__(
        self,
        enable_memory_theory: bool = True,
        max_loop_unroll: int = 4,
        enable_inductive_loops: bool = True,
        enable_call_congruence: bool = True,
        enable_float_theory: bool = True,
    ):
        self.validator = SSATranslationValidator(
            enable_memory_theory=enable_memory_theory,
            max_loop_unroll=max_loop_unroll,
            enable_inductive_loops=enable_inductive_loops,
            enable_call_congruence=enable_call_congruence,
            enable_float_theory=enable_float_theory,
        )

    def verify_ssa_to_llvm_ir(
        self,
        ssa_fn: SSAFunction,
        llvm_ir: str,
        timeout_ms: int = 2000,
    ) -> Dict[str, Any]:
        lifted_ssa, err = LLVMIRToSSALifter.lift_function(llvm_ir, target_name=ssa_fn.name)
        if err or lifted_ssa is None:
            return {
                "proven": False,
                "status": f"UNVERIFIED_{err or 'LLVM_LIFT_FAILED'}",
                "counterexample": None,
                "backend": "llvm",
            }
        ver = self.validator.verify_equivalence(ssa_fn, lifted_ssa, timeout_ms=timeout_ms)
        ver["backend"] = "llvm"
        return ver

    def verify_ssa_to_wat(
        self,
        ssa_fn: SSAFunction,
        wat_source: str,
        timeout_ms: int = 2000,
    ) -> Dict[str, Any]:
        lifted_ssa, err = WATToSSALifter.lift_function(wat_source, target_name=ssa_fn.name)
        if err or lifted_ssa is None:
            return {
                "proven": False,
                "status": f"UNVERIFIED_{err or 'WAT_LIFT_FAILED'}",
                "counterexample": None,
                "backend": "wasm",
            }
        ver = self.validator.verify_equivalence(ssa_fn, lifted_ssa, timeout_ms=timeout_ms)
        ver["backend"] = "wasm"
        return ver

    def verify_differential_execution(
        self,
        ssa_fn: SSAFunction,
        test_vectors: Sequence[Sequence[Any]],
        backends: Tuple[str, ...] = ("native", "llvm", "wasm"),
    ) -> Dict[str, Any]:
        """
        Compiles and executes `ssa_fn` across the requested physical backends and
        asserts bit-exact 64-bit integer or IEEE-754 f64 return agreement for all vectors.
        """
        target_os = "windows" if platform.system().lower().startswith("win") else "linux"
        results_by_backend: Dict[str, List[Any]] = {}
        memory_by_backend: Dict[str, List[Dict[str, List[Any]]]] = {}
        active_backends: List[str] = []
        jit_allocs: List[Any] = []

        is_fp_ret = getattr(ssa_fn, "return_type", "i64") == "f64"
        argtypes = [
            ctypes.c_double if ssa_fn.param_types.get(p) == "f64" else ctypes.c_int64
            for p in ssa_fn.params
        ]
        restype = ctypes.c_double if is_fp_ret else ctypes.c_int64

        def fmt_out(v: Any) -> Any:
            return float(v) if is_fp_ret else _to_s64(int(v))

        def elem_bits(v: Any, is_f: bool) -> int:
            return struct.unpack("<Q", struct.pack("<d", float(v)))[0] if is_f else _to_s64(int(v))

        def cmp_key(ret_v: Any, mem_snap: Dict[str, Any]) -> Tuple[Any, ...]:
            r_bits = elem_bits(ret_v, is_fp_ret)
            m_bits = tuple(
                (
                    k,
                    vals
                    if isinstance(vals, (bytes, bytearray))
                    else tuple(
                        elem_bits(
                            el,
                            ssa_fn.param_types.get(k) == "ptr_f64" or isinstance(el, float),
                        )
                        for el in vals
                    ),
                )
                for k, vals in sorted(mem_snap.items())
            )
            return (r_bits, m_bits)

        def run_ctypes_callable(cfunc, vec: Sequence[Any]) -> Tuple[Any, Dict[str, Any]]:
            call_args: List[Any] = []
            live_bufs: List[Tuple[str, Any, str, int]] = []
            for p, x in zip(ssa_fn.params, vec):
                pty = ssa_fn.param_types.get(p, "i64")
                if isinstance(x, (bytes, bytearray)):
                    n_b = len(x)
                    cbuf = (ctypes.c_ubyte * max(1, n_b)).from_buffer_copy(bytearray(x) if n_b > 0 else bytearray(1))
                    live_bufs.append((p, cbuf, "bytes", n_b))
                    call_args.append(ctypes.addressof(cbuf))
                elif isinstance(x, list):
                    is_f_buf = pty == "ptr_f64" or any(isinstance(el, float) for el in x)
                    n_el = len(x)
                    if is_f_buf:
                        cbuf = (ctypes.c_double * max(1, n_el))(*[float(el) for el in x])
                    else:
                        cbuf = (ctypes.c_int64 * max(1, n_el))(*[int(el) for el in x])
                    live_bufs.append((p, cbuf, "f64" if is_f_buf else "i64", n_el))
                    call_args.append(ctypes.addressof(cbuf))
                elif pty == "f64":
                    call_args.append(float(x))
                else:
                    call_args.append(int(x))
            rv = fmt_out(cfunc(*call_args))
            mem_out: Dict[str, Any] = {}
            for p, cbuf, kind, n_el in live_bufs:
                if kind == "bytes":
                    mem_out[p] = bytes(cbuf)[:n_el]
                else:
                    mem_out[p] = [float(cbuf[i]) if kind == "f64" else _to_s64(int(cbuf[i])) for i in range(n_el)]
            return rv, mem_out

        if "native" in backends:
            codegen = NativeCodeGenerator(arch="x86_64", target_os=target_os)
            art = codegen.compile_ssa(ssa_fn)
            if not art.relocations:
                jit_mem = NativeJitMemory(len(art.code_bytes))
                jit_mem.write_code(art.code_bytes)
                jit_allocs.append(jit_mem)
                cfunc = ctypes.CFUNCTYPE(restype, *argtypes)(jit_mem.ptr)
                nat_outs, nat_mems = [], []
                for vec in test_vectors:
                    ro, mo = run_ctypes_callable(cfunc, vec)
                    nat_outs.append(ro)
                    nat_mems.append(mo)
                results_by_backend["native"] = nat_outs
                memory_by_backend["native"] = nat_mems
                active_backends.append("native")

        if "llvm" in backends:
            llvm_be = LLVMBackend(opt_level=3)
            if llvm_be.is_available:
                ir = llvm_be.ssa_to_llvm_ir(ssa_fn)
                mod = llvm_be.compile_ir(ir, optimize=True)
                lfunc = llvm_be.create_jit_callable(mod, ssa_fn.name, restype=restype, argtypes=argtypes)
                jit_allocs.append(lfunc)
                ll_outs, ll_mems = [], []
                for vec in test_vectors:
                    ro, mo = run_ctypes_callable(lfunc, vec)
                    ll_outs.append(ro)
                    ll_mems.append(mo)
                results_by_backend["llvm"] = ll_outs
                memory_by_backend["llvm"] = ll_mems
                active_backends.append("llvm")

        if "wasm" in backends:
            wasm_be = WasmBackend()
            if wasm_be.is_available:
                wat = wasm_be.ssa_to_wat(ssa_fn)
                wasm_bytes = wasm_be.wat_to_wasm(wat)
                from wasmtime import Store, Module, Instance
                store = Store(wasm_be._engine)
                mod = Module(wasm_be._engine, wasm_bytes)
                inst = Instance(store, mod, [])
                exports_map = inst.exports(store)
                exp_fn = exports_map[ssa_fn.name]
                wasm_mem = exports_map.get("memory")
                w_outs, w_mems = [], []
                for vec in test_vectors:
                    w_args: List[Any] = []
                    w_bufs: List[Tuple[str, int, int, str]] = []
                    cur_off = 1024
                    for p, x in zip(ssa_fn.params, vec):
                        pty = ssa_fn.param_types.get(p, "i64")
                        if isinstance(x, (bytes, bytearray)) and wasm_mem is not None:
                            raw_b = bytes(x)
                            n_b = len(raw_b)
                            if raw_b:
                                wasm_mem.write(store, raw_b, cur_off)
                            w_bufs.append((p, cur_off, n_b, "bytes"))
                            w_args.append(cur_off)
                            cur_off += max(64, ((n_b + 63) // 64) * 64)
                        elif isinstance(x, list) and wasm_mem is not None:
                            is_f_buf = pty == "ptr_f64" or any(isinstance(el, float) for el in x)
                            n_el = len(x)
                            if is_f_buf:
                                raw_b = struct.pack(f"<{n_el}d", *[float(el) for el in x]) if n_el > 0 else b""
                            else:
                                raw_b = struct.pack(f"<{n_el}q", *[_to_s64(int(el)) for el in x]) if n_el > 0 else b""
                            if raw_b:
                                wasm_mem.write(store, raw_b, cur_off)
                            w_bufs.append((p, cur_off, n_el, "f64" if is_f_buf else "i64"))
                            w_args.append(cur_off)
                            cur_off += max(64, ((len(raw_b) + 63) // 64) * 64)
                        elif pty == "f64":
                            w_args.append(float(x))
                        else:
                            w_args.append(int(x))
                    rv = fmt_out(exp_fn(store, *w_args))
                    mo: Dict[str, Any] = {}
                    if wasm_mem is not None:
                        for p, off, n_el, kind in w_bufs:
                            if kind == "bytes":
                                mo[p] = bytes(wasm_mem.read(store, off, off + n_el)) if n_el > 0 else b""
                            elif n_el == 0:
                                mo[p] = []
                            else:
                                raw_out = bytes(wasm_mem.read(store, off, off + n_el * 8))
                                if kind == "f64":
                                    mo[p] = list(struct.unpack(f"<{n_el}d", raw_out))
                                else:
                                    mo[p] = [_to_s64(v) for v in struct.unpack(f"<{n_el}q", raw_out)]
                    w_outs.append(rv)
                    w_mems.append(mo)
                results_by_backend["wasm"] = w_outs
                memory_by_backend["wasm"] = w_mems
                active_backends.append("wasm")

        mismatches: List[Dict[str, Any]] = []
        if len(active_backends) >= 2:
            for idx, vec in enumerate(test_vectors):
                per_be = {be: results_by_backend[be][idx] for be in active_backends}
                per_mem = {be: memory_by_backend[be][idx] for be in active_backends}
                keys = {cmp_key(per_be[be], per_mem[be]) for be in active_backends}
                if len(keys) != 1:
                    mismatches.append({"input": list(vec), "outputs": per_be, "memory": per_mem})

        return {
            "equivalent": len(mismatches) == 0 and len(active_backends) >= 2,
            "active_backends": active_backends,
            "outputs_by_backend": results_by_backend,
            "memory_by_backend": memory_by_backend,
            "mismatches": mismatches,
        }
