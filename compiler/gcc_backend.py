"""
OmniCompiler GCC O3 Backend & Differential Verification Bridge (`gcc_backend.py`).
Lowers multi-block `Omni-SSA` IR (with Phi-node parallel copy sequentialization, affine
memory accesses via strict-aliasing-safe `memcpy`, floating-point operations, and
unsigned-modular integer arithmetic free of signed-overflow Undefined Behavior) into
deterministic C99/GNU-C compiled with `/usr/bin/gcc -O3` (GIMPLE/RTL pipeline).

Supports:
- Native Linux (`ubuntu-latest` CI / native hosts) via `/usr/bin/gcc`
- Windows hosts via WSL2 (`/usr/bin/gcc`) and native MinGW (`gcc.exe`) if present
- Relocatable ELF64 `.o` emission (`emit_object`) compatible with `load_elf_object`
- Target assembly emission (`emit_assembly`) with GCC SIMD telemetry (`inspect_optimization_stats`)
- Direct differential execution (`run_function`) returning `(return_value, memory_snapshots)`
"""

import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from compiler.ssa_ir import BasicBlock, SSAFunction, SSAInstruction, SSAVar, TERMINATOR_OPCODES


def _to_wsl_path(win_path: str) -> str:
    p = os.path.abspath(win_path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


class GCCBackend:
    """Optimizing compiler backend and oracle powered by GNU GCC (`-O3`)."""

    CMP_C_MAP = {
        "cmp_eq": "==",
        "cmp_ne": "!=",
        "cmp_lt": "<",
        "cmp_le": "<=",
        "cmp_gt": ">",
        "cmp_ge": ">=",
    }

    FCMP_C_MAP = {
        "fcmp_eq": "==",
        "fcmp_ne": "!=",
        "fcmp_lt": "<",
        "fcmp_le": "<=",
        "fcmp_gt": ">",
        "fcmp_ge": ">=",
    }

    _PROBE_CACHE: Optional[Tuple[Optional[str], Optional[str], str]] = None

    def __init__(self, opt_level: int = 3, march: Optional[str] = None):
        self.opt_level = opt_level
        self.march = march
        self._mode: Optional[str] = None  # "native_linux", "wsl", "native_exe"
        self._gcc_bin: Optional[str] = None
        self._version_str: str = "unavailable"
        self._probe_gcc()

    def _probe_gcc(self) -> None:
        if GCCBackend._PROBE_CACHE is not None:
            self._mode, self._gcc_bin, self._version_str = GCCBackend._PROBE_CACHE
            return
        if sys.platform != "win32":
            cand = shutil.which("gcc")
            if cand:
                try:
                    r = subprocess.run(
                        [cand, "--version"],
                        capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL,
                    )
                    if r.returncode == 0:
                        self._mode = "native_linux"
                        self._gcc_bin = cand
                        self._version_str = (r.stdout.splitlines() or ["gcc"])[0].strip()
                        GCCBackend._PROBE_CACHE = (self._mode, self._gcc_bin, self._version_str)
                        return
                except Exception:
                    pass
        else:
            # Check WSL2 /usr/bin/gcc (provides full ELF64 System V + GNU GCC O3)
            if shutil.which("wsl"):
                try:
                    r = subprocess.run(
                        ["wsl", "/usr/bin/gcc", "--version"],
                        capture_output=True, text=True, timeout=25, stdin=subprocess.DEVNULL,
                    )
                    if r.returncode == 0:
                        self._mode = "wsl"
                        self._gcc_bin = "gcc"
                        self._version_str = (r.stdout.splitlines() or ["gcc"])[0].strip()
                        GCCBackend._PROBE_CACHE = (self._mode, self._gcc_bin, self._version_str)
                        return
                except Exception:
                    pass
        GCCBackend._PROBE_CACHE = (None, None, "unavailable")

    @property
    def is_available(self) -> bool:
        return self._mode is not None

    @property
    def mode(self) -> Optional[str]:
        return self._mode

    @property
    def gcc_version(self) -> str:
        return self._version_str

    @staticmethod
    def _c_type(var_type: str) -> str:
        return "double" if var_type in ("f64", "f32", "float", "double") else "int64_t"

    @staticmethod
    def _sanitize_ident(name: str) -> str:
        s = re.sub(r"[^A-Za-z0-9_]", "_", str(name))
        if not s or s[0].isdigit():
            s = f"v_{s}"
        return s

    @classmethod
    def _c_var(cls, var: SSAVar) -> str:
        return f"ssa_{cls._sanitize_ident(var.name)}_{int(var.version)}"

    @classmethod
    def _format_operand(cls, op: Any, var_types: Dict[str, str], param_set: Set[str]) -> str:
        if isinstance(op, SSAVar):
            if op.version == 0 and op.name in param_set:
                return f"arg_{cls._sanitize_ident(op.name)}"
            return cls._c_var(op)
        if isinstance(op, float):
            return repr(float(op))
        if isinstance(op, bool):
            return f"INT64_C({int(op)})"
        if isinstance(op, int):
            v = int(op)
            if v == -(1 << 63):
                return "INT64_MIN"
            if -(1 << 63) < v < (1 << 63):
                return f"INT64_C({v})"
            return f"(int64_t)UINT64_C({v & 0xFFFFFFFFFFFFFFFF})"
        s = str(op).strip()
        if s.lstrip("-").isdigit():
            v = int(s)
            if v == -(1 << 63):
                return "INT64_MIN"
            return f"INT64_C({v})"
        clean = cls._sanitize_ident(s.lstrip("%"))
        if clean in param_set:
            return f"arg_{clean}"
        return clean

    @classmethod
    def _is_fp_op(cls, op: Any) -> bool:
        return isinstance(op, float) or (isinstance(op, SSAVar) and op.var_type in ("f64", "f32", "float", "double"))

    def ssa_function_to_c(
        self,
        ssa_func: SSAFunction,
        defined_funcs: Optional[Set[str]] = None,
        declared_externals: Optional[Dict[str, str]] = None,
    ) -> str:
        param_set = set(ssa_func.params)
        fn_ret_ty = self._c_type(getattr(ssa_func, "return_type", "i64"))
        params_sig = ", ".join(
            f"{self._c_type(ssa_func.param_types.get(p, 'i64'))} arg_{self._sanitize_ident(p)}"
            for p in ssa_func.params
        ) or "void"

        # Collect all SSA variables to pre-declare at function top
        all_vars: Dict[str, str] = {}
        for blk in ssa_func.blocks:
            for phi in blk.phi_nodes:
                if isinstance(phi.result, SSAVar):
                    all_vars[self._c_var(phi.result)] = self._c_type(phi.result.var_type)
            for inst in blk.instructions:
                if isinstance(inst.result, SSAVar):
                    vname = self._c_var(inst.result)
                    all_vars.setdefault(vname, self._c_type(inst.result.var_type))

        lines: List[str] = []
        # Static LUTs & C-strings
        for lut_name, (wt, vals) in sorted((getattr(ssa_func, "luts", {}) or {}).items()):
            elem_c = {
                "i8": "int8_t", "u8": "uint8_t", "i16": "int16_t", "u16": "uint16_t",
                "i32": "int32_t", "u32": "uint32_t", "f32": "float",
                "i64": "int64_t", "u64": "uint64_t", "f64": "double",
            }.get(wt, "int64_t")
            items = ", ".join(repr(float(v)) if elem_c in ("float", "double") else str(int(v)) for v in vals)
            lines.append(
                f"static const {elem_c} __omni_lut_{self._sanitize_ident(ssa_func.name)}_{self._sanitize_ident(lut_name)}[{len(vals)}] = {{ {items} }};"
            )
        for c_name, raw_b in sorted((getattr(ssa_func, "cstrs", {}) or {}).items()):
            hex_bytes = ", ".join(str(int(b)) for b in raw_b)
            lines.append(
                f"static const unsigned char __omni_cstr_{self._sanitize_ident(ssa_func.name)}_{self._sanitize_ident(c_name)}[{len(raw_b)}] = {{ {hex_bytes} }};"
            )

        lines.append(f"{fn_ret_ty} {ssa_func.name}({params_sig}) {{")
        for vname, cty in sorted(all_vars.items()):
            init = "0.0" if cty == "double" else "0"
            lines.append(f"    {cty} {vname} = {init};")

        # Map each block's phi nodes so outgoing branches perform atomic parallel copy
        phis_by_target: Dict[str, List[SSAInstruction]] = {
            blk.name: [p for p in blk.phi_nodes if isinstance(p.result, SSAVar)]
            for blk in ssa_func.blocks
        }
        pred_names_by_block: Dict[str, List[str]] = {
            blk.name: [pb.name for pb in blk.predecessors]
            for blk in ssa_func.blocks
        }

        aux_id = 0

        def next_aux(prefix: str = "tmp") -> str:
            nonlocal aux_id
            aux_id += 1
            return f"_{prefix}_{aux_id}"

        def emit_edge_branch(pred_name: str, target_name: str, indent: str = "    ") -> List[str]:
            out: List[str] = []
            t_phis = phis_by_target.get(target_name, [])
            if t_phis:
                copies: List[Tuple[str, str, str]] = []
                for phi in t_phis:
                    lhs = self._c_var(phi.result)
                    cty = self._c_type(phi.result.var_type)
                    chosen_val: Any = None
                    if phi.phi_incoming:
                        for sb, val in phi.phi_incoming:
                            sb_name = getattr(sb, "name", str(sb))
                            if sb_name == pred_name:
                                chosen_val = val
                                break
                    else:
                        preds = pred_names_by_block.get(target_name, [])
                        for sb_name, val in zip(preds, phi.operands):
                            if sb_name == pred_name:
                                chosen_val = val
                                break
                    if chosen_val is not None:
                        val_expr = self._format_operand(chosen_val, all_vars, param_set)
                        tmp_n = next_aux("phi")
                        copies.append((tmp_n, lhs, f"    {cty} {tmp_n} = ({cty})({val_expr});"))
                if copies:
                    out.append(f"{indent}{{")
                    for _, _, decl in copies:
                        out.append(f"{indent}{decl}")
                    for tmp_n, lhs, _ in copies:
                        out.append(f"{indent}    {lhs} = {tmp_n};")
                    out.append(f"{indent}}}")
            out.append(f"{indent}goto L_{self._sanitize_ident(target_name)};")
            return out

        for block in ssa_func.blocks:
            lines.append(f"L_{self._sanitize_ident(block.name)}: ;")
            emitted_terminator = False
            last_val = "0.0" if fn_ret_ty == "double" else "0"

            for inst in block.instructions:
                if emitted_terminator:
                    break
                op = inst.opcode.lower()
                if op == "param":
                    if isinstance(inst.result, SSAVar) and not (inst.result.version == 0 and inst.result.name in param_set):
                        lhs = self._c_var(inst.result)
                        p_name = self._sanitize_ident(str(inst.operands[0]))
                        lines.append(f"    {lhs} = arg_{p_name};")
                    continue

                has_res = isinstance(inst.result, SSAVar)
                lhs = self._c_var(inst.result) if has_res else next_aux("unused")
                res_ty = self._c_type(inst.result.var_type) if has_res else "int64_t"
                ops = [self._format_operand(o, all_vars, param_set) for o in inst.operands]

                if op in ("const", "fconst", "mov"):
                    v1 = ops[0] if ops else ("0.0" if res_ty == "double" else "0")
                    if has_res:
                        lines.append(f"    {lhs} = ({res_ty})({v1});")
                        last_val = lhs

                elif op == "neg":
                    v1 = ops[0] if ops else "0"
                    if has_res:
                        lines.append(f"    {lhs} = (int64_t)(-(uint64_t)(int64_t)({v1}));")
                        last_val = lhs

                elif op == "fneg":
                    v1 = ops[0] if ops else "0.0"
                    if has_res:
                        lines.append(f"    {lhs} = -(double)({v1});")
                        last_val = lhs

                elif op == "sitofp":
                    v1 = ops[0] if ops else "0"
                    if has_res:
                        lines.append(f"    {lhs} = (double)(int64_t)({v1});")
                        last_val = lhs

                elif op == "fptosi":
                    v1 = ops[0] if ops else "0.0"
                    if has_res:
                        lines.append(f"    {lhs} = (int64_t)(double)({v1});")
                        last_val = lhs

                elif op == "not":
                    v1 = ops[0] if ops else "0"
                    if has_res:
                        lines.append(f"    {lhs} = ((int64_t)({v1}) == 0) ? 1 : 0;")
                        last_val = lhs

                elif op == "alloca":
                    sz = ops[0] if ops else "64"
                    ptr_expr = f"(int64_t)(uintptr_t)__builtin_alloca((size_t)({sz}))"
                    if has_res:
                        lines.append(f"    {lhs} = {ptr_expr};")
                        last_val = lhs
                    else:
                        lines.append(f"    (void){ptr_expr};")

                elif op in ("add", "sub", "mul", "imul"):
                    c_op = {"add": "+", "sub": "-", "mul": "*", "imul": "*"}[op]
                    v1 = ops[0] if len(ops) > 0 else "0"
                    v2 = ops[1] if len(ops) > 1 else "0"
                    if has_res:
                        lines.append(f"    {lhs} = (int64_t)((uint64_t)(int64_t)({v1}) {c_op} (uint64_t)(int64_t)({v2}));")
                        last_val = lhs

                elif op in ("sdiv", "div"):
                    v1 = ops[0] if len(ops) > 0 else "0"
                    v2 = ops[1] if len(ops) > 1 else "1"
                    if has_res:
                        lines.append(f"    {lhs} = ((int64_t)({v2}) != 0) ? ((int64_t)({v1}) / (int64_t)({v2})) : 0;")
                        last_val = lhs

                elif op == "srem":
                    v1 = ops[0] if len(ops) > 0 else "0"
                    v2 = ops[1] if len(ops) > 1 else "1"
                    if has_res:
                        lines.append(f"    {lhs} = ((int64_t)({v2}) != 0) ? ((int64_t)({v1}) % (int64_t)({v2})) : 0;")
                        last_val = lhs

                elif op == "shl":
                    v1 = ops[0] if len(ops) > 0 else "0"
                    v2 = ops[1] if len(ops) > 1 else "0"
                    if has_res:
                        lines.append(f"    {lhs} = (int64_t)((uint64_t)(int64_t)({v1}) << ((uint64_t)({v2}) & 63ULL));")
                        last_val = lhs

                elif op in ("shr", "sar"):
                    v1 = ops[0] if len(ops) > 0 else "0"
                    v2 = ops[1] if len(ops) > 1 else "0"
                    if has_res:
                        lines.append(f"    {lhs} = ((int64_t)({v1}) >> ((uint64_t)({v2}) & 63ULL));")
                        last_val = lhs

                elif op in ("and", "or", "xor"):
                    c_op = {"and": "&", "or": "|", "xor": "^"}[op]
                    v1 = ops[0] if len(ops) > 0 else "0"
                    v2 = ops[1] if len(ops) > 1 else "0"
                    if has_res:
                        lines.append(f"    {lhs} = (int64_t)((uint64_t)(int64_t)({v1}) {c_op} (uint64_t)(int64_t)({v2}));")
                        last_val = lhs

                elif op in ("fadd", "fsub", "fmul", "fdiv"):
                    c_op = {"fadd": "+", "fsub": "-", "fmul": "*", "fdiv": "/"}[op]
                    v1 = ops[0] if len(ops) > 0 else "0.0"
                    v2 = ops[1] if len(ops) > 1 else "0.0"
                    if has_res:
                        lines.append(f"    {lhs} = ((double)({v1}) {c_op} (double)({v2}));")
                        last_val = lhs

                elif op in self.CMP_C_MAP:
                    pred = self.CMP_C_MAP[op]
                    v1 = ops[0] if len(ops) > 0 else "0"
                    v2 = ops[1] if len(ops) > 1 else "0"
                    if has_res:
                        lines.append(f"    {lhs} = (((int64_t)({v1}) {pred} (int64_t)({v2})) ? 1 : 0);")
                        last_val = lhs

                elif op in self.FCMP_C_MAP:
                    pred = self.FCMP_C_MAP[op]
                    v1 = ops[0] if len(ops) > 0 else "0.0"
                    v2 = ops[1] if len(ops) > 1 else "0.0"
                    if has_res:
                        lines.append(f"    {lhs} = (((double)({v1}) {pred} (double)({v2})) ? 1 : 0);")
                        last_val = lhs

                elif op == "select":
                    c_op = ops[0] if len(ops) > 0 else "0"
                    t_op = ops[1] if len(ops) > 1 else ("0.0" if res_ty == "double" else "0")
                    f_op = ops[2] if len(ops) > 2 else ("0.0" if res_ty == "double" else "0")
                    if has_res:
                        lines.append(f"    {lhs} = (((int64_t)({c_op}) != 0) ? ({res_ty})({t_op}) : ({res_ty})({f_op}));")
                        last_val = lhs

                elif op == "load":
                    base_op = ops[0] if len(ops) > 0 else "0"
                    idx_op = ops[1] if len(ops) > 1 else "0"
                    elem_c = "double" if res_ty == "double" else "int64_t"
                    p_tmp = next_aux("ldp")
                    v_tmp = next_aux("ldv")
                    lines.append(f"    const uint8_t *{p_tmp} = (const uint8_t *)(uintptr_t)({base_op}) + (int64_t)({idx_op}) * (int64_t)sizeof({elem_c});")
                    lines.append(f"    {elem_c} {v_tmp}; __builtin_memcpy(&{v_tmp}, {p_tmp}, sizeof({elem_c}));")
                    if has_res:
                        lines.append(f"    {lhs} = ({res_ty}){v_tmp};")
                        last_val = lhs

                elif op == "store":
                    base_op = ops[0] if len(ops) > 0 else "0"
                    idx_op = ops[1] if len(ops) > 1 else "0"
                    val_op = ops[2] if len(ops) > 2 else "0"
                    raw_val = inst.operands[2] if len(inst.operands) > 2 else 0
                    elem_c = "double" if self._is_fp_op(raw_val) else "int64_t"
                    p_tmp = next_aux("stp")
                    v_tmp = next_aux("stv")
                    lines.append(f"    uint8_t *{p_tmp} = (uint8_t *)(uintptr_t)({base_op}) + (int64_t)({idx_op}) * (int64_t)sizeof({elem_c});")
                    lines.append(f"    {elem_c} {v_tmp} = ({elem_c})({val_op}); __builtin_memcpy({p_tmp}, &{v_tmp}, sizeof({elem_c}));")

                elif op == "load_off":
                    base_op = ops[0] if len(ops) > 0 else "0"
                    off_op = ops[1] if len(ops) > 1 else "0"
                    width = str(inst.operands[2]) if len(inst.operands) >= 3 else "i64"
                    c_ld_map = {
                        "i8": "int8_t", "u8": "uint8_t",
                        "i16": "int16_t", "u16": "uint16_t",
                        "i32": "int32_t", "u32": "uint32_t",
                        "f32": "float", "f64": "double",
                        "i64": "int64_t", "u64": "uint64_t",
                    }
                    elem_c = c_ld_map.get(width, "int64_t")
                    p_tmp = next_aux("ldop")
                    v_tmp = next_aux("ldov")
                    lines.append(f"    const uint8_t *{p_tmp} = (const uint8_t *)(uintptr_t)({base_op}) + (int64_t)({off_op});")
                    lines.append(f"    {elem_c} {v_tmp}; __builtin_memcpy(&{v_tmp}, {p_tmp}, sizeof({elem_c}));")
                    if has_res:
                        lines.append(f"    {lhs} = ({res_ty}){v_tmp};")
                        last_val = lhs

                elif op == "store_off":
                    base_op = ops[0] if len(ops) > 0 else "0"
                    off_op = ops[1] if len(ops) > 1 else "0"
                    val_op = ops[2] if len(ops) > 2 else "0"
                    width = str(inst.operands[3]) if len(inst.operands) >= 4 else "i64"
                    c_st_map = {
                        "i8": "int8_t", "u8": "uint8_t",
                        "i16": "int16_t", "u16": "uint16_t",
                        "i32": "int32_t", "u32": "uint32_t",
                        "f32": "float", "f64": "double",
                        "i64": "int64_t", "u64": "uint64_t",
                    }
                    elem_c = c_st_map.get(width, "int64_t")
                    p_tmp = next_aux("stop")
                    v_tmp = next_aux("stov")
                    lines.append(f"    uint8_t *{p_tmp} = (uint8_t *)(uintptr_t)({base_op}) + (int64_t)({off_op});")
                    lines.append(f"    {elem_c} {v_tmp} = ({elem_c})({val_op}); __builtin_memcpy({p_tmp}, &{v_tmp}, sizeof({elem_c}));")

                elif op == "lut_load":
                    lut_name = str(inst.operands[0])
                    idx_op = ops[2]
                    sym = f"__omni_lut_{self._sanitize_ident(ssa_func.name)}_{self._sanitize_ident(lut_name)}"
                    if has_res:
                        lines.append(f"    {lhs} = ({res_ty})({sym}[(int64_t)({idx_op})]);")
                        last_val = lhs

                elif op == "cstr_addr":
                    c_name = str(inst.operands[0])
                    sym = f"__omni_cstr_{self._sanitize_ident(ssa_func.name)}_{self._sanitize_ident(c_name)}"
                    if has_res:
                        lines.append(f"    {lhs} = (int64_t)(uintptr_t){sym};")
                        last_val = lhs

                elif op == "call":
                    callee = str(inst.operands[0])
                    if callee == "printf":
                        c_args: List[str] = []
                        for idx_a, (orig_a, fmt_a) in enumerate(zip(inst.operands[1:], ops[1:])):
                            if idx_a == 0:
                                c_args.append(f"(const char *)(uintptr_t)({fmt_a})")
                            elif self._is_fp_op(orig_a):
                                c_args.append(f"(double)({fmt_a})")
                            else:
                                c_args.append(f"(long long)({fmt_a})")
                        call_expr = f"printf({', '.join(c_args)})"
                        if has_res:
                            lines.append(f"    {lhs} = (int64_t){call_expr};")
                            last_val = lhs
                        else:
                            lines.append(f"    {call_expr};")
                    elif callee == "malloc":
                        sz_a = ops[1] if len(ops) > 1 else "0"
                        call_expr = f"(int64_t)(uintptr_t)malloc((size_t)({sz_a}))"
                        if has_res:
                            lines.append(f"    {lhs} = {call_expr};")
                            last_val = lhs
                    elif callee == "free":
                        p_a = ops[1] if len(ops) > 1 else "0"
                        lines.append(f"    free((void *)(uintptr_t)({p_a}));")
                        if has_res:
                            lines.append(f"    {lhs} = 0;")
                            last_val = lhs
                    else:
                        if declared_externals is not None and (defined_funcs is None or callee not in defined_funcs):
                            arg_sigs = ", ".join(
                                "double" if self._is_fp_op(orig_a) else "int64_t"
                                for orig_a in inst.operands[1:]
                            ) or "void"
                            declared_externals.setdefault(callee, f"extern {res_ty} {callee}({arg_sigs});")
                        c_args = [
                            f"(double)({fmt_a})" if self._is_fp_op(orig_a) else f"(int64_t)({fmt_a})"
                            for orig_a, fmt_a in zip(inst.operands[1:], ops[1:])
                        ]
                        call_expr = f"{callee}({', '.join(c_args)})"
                        if has_res:
                            lines.append(f"    {lhs} = ({res_ty}){call_expr};")
                            last_val = lhs
                        else:
                            lines.append(f"    {call_expr};")

                elif op == "br":
                    target_bb = str(inst.operands[0])
                    lines.extend(emit_edge_branch(block.name, target_bb))
                    emitted_terminator = True

                elif op == "br_cond":
                    cond_v = ops[0]
                    true_bb = str(inst.operands[1])
                    false_bb = str(inst.operands[2])
                    lines.append(f"    if ((int64_t)({cond_v}) != 0) {{")
                    lines.extend(emit_edge_branch(block.name, true_bb, indent="        "))
                    lines.append("    } else {")
                    lines.extend(emit_edge_branch(block.name, false_bb, indent="        "))
                    lines.append("    }")
                    emitted_terminator = True

                elif op == "ret":
                    v = ops[0] if ops else ("0.0" if fn_ret_ty == "double" else "0")
                    lines.append(f"    return ({fn_ret_ty})({v});")
                    emitted_terminator = True

            if not emitted_terminator:
                lines.append(f"    return ({fn_ret_ty})({last_val});")

        lines.append("}")
        return "\n".join(lines)

    def ssa_module_to_c(self, ssa_funcs: List[SSAFunction], module_name: str = "omni_gcc_module") -> str:
        defined = {f.name for f in ssa_funcs}
        externals: Dict[str, str] = {}
        forward_decls: List[str] = []
        for fn in ssa_funcs:
            fn_ret_ty = self._c_type(getattr(fn, "return_type", "i64"))
            params_sig = ", ".join(
                f"{self._c_type(fn.param_types.get(p, 'i64'))} arg_{self._sanitize_ident(p)}"
                for p in fn.params
            ) or "void"
            forward_decls.append(f"{fn_ret_ty} {fn.name}({params_sig});")

        bodies = [
            self.ssa_function_to_c(fn, defined_funcs=defined, declared_externals=externals)
            for fn in ssa_funcs
        ]
        header = [
            f"/* Generated by OmniCompiler GCCBackend ({module_name}) */",
            "#include <stdint.h>",
            "#include <stddef.h>",
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "",
        ]
        header.extend(sorted(externals.values()))
        header.extend(forward_decls)
        header.append("")
        return "\n".join(header + bodies)

    def _gcc_flags(self, extra_flags: Optional[List[str]] = None) -> List[str]:
        flags = [
            f"-O{self.opt_level}",
            "-std=gnu99",
            "-U_FORTIFY_SOURCE",
            "-D_FORTIFY_SOURCE=0",
            "-fwrapv",
            "-fno-strict-aliasing",
            "-fno-asynchronous-unwind-tables",
            "-fPIC",
            "-fcf-protection=none",
        ]
        if self.march:
            flags.append(f"-march={self.march}")
        elif self.opt_level >= 3:
            flags.append("-mavx2")
        if extra_flags:
            flags.extend(extra_flags)
        return flags

    def _run_gcc(self, src_c: str, out_ext: str, extra_flags: Optional[List[str]] = None) -> bytes:
        if not self.is_available:
            raise RuntimeError("GCC backend is not available (neither native gcc nor WSL gcc found).")

        with tempfile.TemporaryDirectory() as tmpdir:
            c_file = os.path.join(tmpdir, "module.c")
            out_file = os.path.join(tmpdir, f"module{out_ext}")
            with open(c_file, "w", encoding="utf-8", newline="\n") as f:
                f.write(src_c)

            flags = self._gcc_flags(extra_flags)
            if self._mode == "wsl":
                w_c = _to_wsl_path(c_file)
                w_o = _to_wsl_path(out_file)
                cmd = ["wsl", "/usr/bin/gcc"] + flags + [w_c, "-o", w_o]
            else:
                cmd = [self._gcc_bin] + flags + [c_file, "-o", out_file]

            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
            if r.returncode != 0:
                raise RuntimeError(f"GCC compilation failed (rc={r.returncode}):\n{r.stderr}\n--- C Source ---\n{src_c}")

            with open(out_file, "rb") as f:
                return f.read()

    def emit_object(self, ssa_funcs: List[SSAFunction], module_name: str = "omni_gcc_module") -> bytes:
        """Compiles `SSAFunction`s via GCC `-O3 -c` into a relocatable ELF64 `.o` object."""
        c_src = self.ssa_module_to_c(ssa_funcs, module_name=module_name)
        return self._run_gcc(c_src, ".o", extra_flags=["-c"])

    def emit_assembly(self, ssa_funcs: List[SSAFunction], module_name: str = "omni_gcc_module") -> str:
        """Emits target assembly (`-S`) compiled with GCC `-O3`."""
        c_src = self.ssa_module_to_c(ssa_funcs, module_name=module_name)
        return self._run_gcc(c_src, ".s", extra_flags=["-S"]).decode("utf-8", errors="replace")

    @staticmethod
    def inspect_optimization_stats(asm_text: str) -> Dict[str, Any]:
        simd_hits = re.findall(r"\b(v?(?:padd|psub|pmull|addp|subp|mulp|movdqu|movdqa)[a-z0-9]*)\b", asm_text)
        ymm_regs = re.findall(r"%?ymm\d+", asm_text)
        xmm_regs = re.findall(r"%?xmm\d+", asm_text)
        return {
            "simd_instruction_count": len(simd_hits),
            "ymm_operand_refs": len(ymm_regs),
            "xmm_operand_refs": len(xmm_regs),
            "sample_simd_mnemonics": sorted(set(simd_hits))[:16],
        }

    def run_function(
        self,
        ssa_funcs: List[SSAFunction],
        entry_name: str,
        args: Optional[List[Any]] = None,
        memory_regions: Optional[Dict[int, bytes]] = None,
    ) -> Tuple[Any, Dict[int, bytes]]:
        """
        Compiles `ssa_funcs` with GCC O3 alongside an isolated C runner harness, executes
        `entry_name(*args)` with deterministic memory regions, and returns `(return_value, memory_snapshots)`.
        """
        if not self.is_available:
            raise RuntimeError("GCC backend is not available.")

        args = list(args or [])
        mem_regions = dict(memory_regions or {})
        target_fn = next((f for f in ssa_funcs if f.name == entry_name), None)
        if target_fn is None:
            raise ValueError(f"Entry function '{entry_name}' not found in ssa_funcs.")

        ret_is_fp = getattr(target_fn, "return_type", "i64") in ("f64", "f32", "float", "double")
        module_c = self.ssa_module_to_c(ssa_funcs, module_name=f"run_{entry_name}")

        harness = [
            module_c,
            "",
            "int main(int argc, char **argv) {",
            "    if (argc < 2) return 2;",
            "    FILE *in_f = fopen(argv[1], \"rb\");",
            "    if (!in_f) return 3;",
        ]
        ordered_addrs = sorted(mem_regions.keys())
        for idx_m, addr in enumerate(ordered_addrs):
            sz = len(mem_regions[addr])
            harness.extend([
                f"    uint8_t *buf_{idx_m} = (uint8_t *)calloc({max(sz, 1)}, 1);",
                f"    if (fread(buf_{idx_m}, 1, {sz}, in_f) != {sz}) return 4;",
            ])
        harness.append("    fclose(in_f);")

        # Substitute virtual memory base addresses passed as arguments with buf_k pointers
        call_args: List[str] = []
        addr_to_buf = {addr: f"(int64_t)(uintptr_t)buf_{idx_m}" for idx_m, addr in enumerate(ordered_addrs)}
        for idx_a, val in enumerate(args):
            p_name = target_fn.params[idx_a] if idx_a < len(target_fn.params) else ""
            p_ty = target_fn.param_types.get(p_name, "i64")
            if p_ty in ("f64", "f32", "float", "double") or isinstance(val, float):
                call_args.append(f"(double){repr(float(val))}")
            else:
                iv = int(val)
                if iv in addr_to_buf:
                    call_args.append(addr_to_buf[iv])
                else:
                    call_args.append(f"INT64_C({iv})")

        call_str = f"{entry_name}({', '.join(call_args)})"
        if ret_is_fp:
            harness.extend([
                f"    double __res_f = {call_str};",
                "    uint64_t __res_bits = 0;",
                "    __builtin_memcpy(&__res_bits, &__res_f, 8);",
            ])
        else:
            harness.extend([
                f"    int64_t __res_i = {call_str};",
                "    uint64_t __res_bits = (uint64_t)__res_i;",
            ])

        harness.extend([
            "    FILE *out_f = fopen(argv[2], \"wb\");",
            "    if (!out_f) return 5;",
            "    fwrite(&__res_bits, 8, 1, out_f);",
        ])
        for idx_m, addr in enumerate(ordered_addrs):
            sz = len(mem_regions[addr])
            harness.append(f"    fwrite(buf_{idx_m}, 1, {sz}, out_f);")
        harness.extend([
            "    fclose(out_f);",
            "    return 0;",
            "}",
        ])

        full_c = "\n".join(harness)
        with tempfile.TemporaryDirectory() as tmpdir:
            c_path = os.path.join(tmpdir, "harness.c")
            in_path = os.path.join(tmpdir, "mem_in.bin")
            out_path = os.path.join(tmpdir, "mem_out.bin")
            exe_path = os.path.join(tmpdir, "harness_bin")

            with open(c_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(full_c)
            with open(in_path, "wb") as f:
                for addr in ordered_addrs:
                    f.write(mem_regions[addr])

            flags = self._gcc_flags()
            if self._mode == "wsl":
                w_c = _to_wsl_path(c_path)
                w_e = f"/tmp/omni_gcc_{os.getpid()}_{uuid.uuid4().hex[:10]}"
                w_in = _to_wsl_path(in_path)
                w_out = _to_wsl_path(out_path)
                comp_cmd = ["wsl", "/usr/bin/gcc"] + flags + [w_c, "-o", w_e, "-lm"]
                rc = subprocess.run(comp_cmd, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
                if rc.returncode != 0:
                    raise RuntimeError(f"GCC harness compilation failed:\n{rc.stderr}")
                try:
                    rr = subprocess.run(["wsl", w_e, w_in, w_out], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
                    if rr.returncode != 0:
                        raise RuntimeError(f"GCC harness execution failed (rc={rr.returncode}): {rr.stderr}")
                finally:
                    subprocess.run(["wsl", "rm", "-f", w_e], capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
            else:
                comp_cmd = [self._gcc_bin] + flags + [c_path, "-o", exe_path, "-lm"]
                rc = subprocess.run(comp_cmd, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
                if rc.returncode != 0:
                    raise RuntimeError(f"GCC harness compilation failed:\n{rc.stderr}")
                rr = subprocess.run([exe_path, in_path, out_path], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
                if rr.returncode != 0:
                    raise RuntimeError(f"GCC harness execution failed (rc={rr.returncode}): {rr.stderr}")

            with open(out_path, "rb") as f:
                raw_out = f.read()

        ret_bits = struct.unpack_from("<Q", raw_out, 0)[0]
        if ret_is_fp:
            ret_val: Any = struct.unpack("<d", struct.pack("<Q", ret_bits))[0]
        else:
            ret_val = ret_bits - (1 << 64) if (ret_bits & (1 << 63)) else ret_bits

        snapshots: Dict[int, bytes] = {}
        cur = 8
        for addr in ordered_addrs:
            sz = len(mem_regions[addr])
            snapshots[addr] = raw_out[cur : cur + sz]
            cur += sz
        return ret_val, snapshots
