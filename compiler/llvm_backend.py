"""
OmniCompiler Industrial LLVM Backend & JIT Engine.
Bridges Turing-complete multi-block Omni-SSA IR (`phi`, `br`, `br_cond`, `cmp_*`,
`select`, `sdiv`, `srem`, `shl`, `shr`, `load`, `store`, `call`) and multi-function modules
to LLVM IR, applies LLVM O3 PassBuilder optimization pipelines (auto-vectorization,
loop unrolling, GVN, instcombine), and compiles to MCJIT silicon or COFF/ELF object files.
"""

from typing import Optional, List, Dict, Any, Union
import ctypes
import re
import struct

from compiler.ssa_ir import SSAVar, SSAFunction, TERMINATOR_OPCODES

try:
    import llvmlite
    import llvmlite.binding as llvm
    LLVM_AVAILABLE = True
except ImportError:
    LLVM_AVAILABLE = False


class LLVMBackend:
    """
    Industrial optimizing backend using LLVM / llvmlite.
    Transforms multi-block SSA functions and LLVM IR into optimized native machine code.
    """

    CMP_PRED_MAP = {
        "cmp_eq": "eq",
        "cmp_ne": "ne",
        "cmp_lt": "slt",
        "cmp_le": "sle",
        "cmp_gt": "sgt",
        "cmp_ge": "sge",
    }

    FCMP_PRED_MAP = {
        "fcmp_eq": "oeq",
        "fcmp_ne": "one",
        "fcmp_lt": "olt",
        "fcmp_le": "ole",
        "fcmp_gt": "ogt",
        "fcmp_ge": "oge",
    }

    @staticmethod
    def _llvm_type(var_type: str) -> str:
        return "double" if var_type in ("f64", "f32", "float", "double") else "i64"

    def __init__(self, opt_level: int = 3, target_triple: Optional[str] = None, cpu: str = ""):
        self.opt_level = opt_level
        self._explicit_triple = target_triple
        self._cpu = cpu
        self._target = None
        self._target_machine = None
        self._obj_target_machine = None
        self._initialized = False

        if LLVM_AVAILABLE:
            try:
                if target_triple:
                    llvm.initialize_all_targets()
                    llvm.initialize_all_asmprinters()
                    target = llvm.Target.from_triple(target_triple)
                else:
                    llvm.initialize_native_target()
                    llvm.initialize_native_asmprinter()
                    target = llvm.Target.from_default_triple()
                self._target = target
                self._target_machine = target.create_target_machine(cpu=cpu, opt=self.opt_level, reloc="pic")
                self._obj_target_machine = target.create_target_machine(cpu=cpu, opt=self.opt_level, reloc="pic", codemodel="small")
                self._initialized = True
            except Exception:
                self._initialized = False

    @property
    def is_available(self) -> bool:
        return LLVM_AVAILABLE and self._initialized

    @property
    def target_triple(self) -> str:
        if self._target_machine:
            return self._explicit_triple or self._target_machine.triple
        return "unknown"

    def compile_ir(self, llvm_ir_str: str, optimize: bool = True) -> Any:
        """Parses and verifies an LLVM IR assembly string, applying O3 passes if requested."""
        if not self.is_available:
            raise RuntimeError("LLVM backend is not available on this system.")

        mod = llvm.parse_assembly(llvm_ir_str)
        mod.verify()

        if optimize and self._target_machine:
            pto = llvm.create_pipeline_tuning_options(speed_level=self.opt_level)
            pto.loop_vectorization = True
            pto.slp_vectorization = True
            pto.loop_unrolling = True
            pb = llvm.create_pass_builder(self._target_machine, pto)
            mpm = pb.getModulePassManager()
            mpm.run(mod, pb)

        return mod

    def emit_object(self, mod: Any) -> bytes:
        """Emits a native relocatable object file (Windows PE/COFF `.obj` or System V ELF64 `.o`)."""
        if not self.is_available:
            raise RuntimeError("LLVM backend is not available.")
        tm = self._obj_target_machine or self._target_machine
        prev_triple = getattr(mod, "triple", None)
        try:
            if prev_triple is not None:
                mod.triple = tm.triple
            return tm.emit_object(mod)
        finally:
            if prev_triple is not None:
                mod.triple = prev_triple

    def emit_assembly(self, mod: Any) -> str:
        """Emits target assembly code text from an LLVM module."""
        if not self.is_available:
            raise RuntimeError("LLVM backend is not available.")
        if self._explicit_triple and self._obj_target_machine is not None:
            tmp_mod = llvm.parse_assembly(str(mod))
            tmp_mod.triple = self._obj_target_machine.triple
            return self._obj_target_machine.emit_assembly(tmp_mod)
        return self._target_machine.emit_assembly(mod)

    def inspect_optimization_stats(self, mod: Any) -> Dict[str, Any]:
        """Counts vectorized SIMD mnemonics and YMM/XMM/NEON vector register refs from LLVM O3 assembly."""
        asm_text = self.emit_assembly(mod)
        simd_hits = re.findall(r"\b(v?(?:padd|psub|pmull|addp|subp|mulp|movdqu|movdqa|fadd|fmul)[a-z0-9]*)\b", asm_text)
        ymm_refs = re.findall(r"%?ymm\d+", asm_text)
        neon_refs = re.findall(r"\bv\d+\.(?:2d|4s|16b|8h)\b", asm_text, flags=re.IGNORECASE)
        return {
            "target_triple": self.target_triple,
            "simd_instruction_count": len(simd_hits),
            "ymm_operand_refs": len(ymm_refs),
            "neon_vector_refs": len(neon_refs),
            "sample_simd_mnemonics": sorted(set(simd_hits))[:16],
        }

    def create_jit_callable(self, mod: Any, func_name: str, restype=ctypes.c_int64, argtypes=None):
        """
        Compiles the LLVM module via MCJIT in host memory and returns a directly callable
        ctypes function pointer with specified signature.
        """
        if not self.is_available:
            raise RuntimeError("LLVM backend is not available.")

        argtypes = argtypes or []
        # create_mcjit_compiler takes ownership of the TargetMachine in llvmlite;
        # always allocate a fresh instance so self._target_machine stays reusable.
        jit_tm = self._target.create_target_machine(cpu=self._cpu, opt=self.opt_level, reloc="pic")
        ee = llvm.create_mcjit_compiler(mod, jit_tm)
        ee.finalize_object()
        func_ptr = ee.get_function_address(func_name)
        if func_ptr == 0:
            raise ValueError(f"Symbol '{func_name}' not found in compiled LLVM module.")

        cfunc = ctypes.CFUNCTYPE(restype, *argtypes)(func_ptr)
        cfunc._engine = ee
        return cfunc

    def _format_ssa_operand(self, op: Any, param_set: set) -> str:
        if isinstance(op, SSAVar):
            if op.version == 0 and op.name in param_set:
                return f"%arg_{op.name}"
            return f"%ssa_{op.name}_{op.version}"
        if isinstance(op, float):
            bits = struct.unpack(">Q", struct.pack(">d", op))[0]
            return f"0x{bits:016x}"
        if isinstance(op, bool):
            return str(int(op))
        if isinstance(op, int):
            return str(op)
        s = str(op).strip()
        if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
            return s
        clean = s.lstrip("%")
        if clean in param_set:
            return f"%arg_{clean}"
        return f"%{clean}"

    def _format_ssa_def(self, var: SSAVar) -> str:
        return f"%ssa_{var.name}_{var.version}"

    def ssa_function_to_llvm_body(self, ssa_func: SSAFunction, declared_externals: Optional[Dict[str, Any]] = None) -> str:
        param_set = set(ssa_func.params)
        fn_ret_ty = self._llvm_type(getattr(ssa_func, "return_type", "i64"))
        params_str = ", ".join(
            f"{self._llvm_type(ssa_func.param_types.get(p, 'i64'))} %arg_{p}"
            for p in ssa_func.params
        )
        lines = [f"define {fn_ret_ty} @{ssa_func.name}({params_str}) {{"]
        aux_counter = 0

        def next_aux(prefix: str = "aux") -> str:
            nonlocal aux_counter
            aux_counter += 1
            return f"%{prefix}_{aux_counter}"

        for block in ssa_func.blocks:
            lines.append(f"{block.name}:")

            # 1. Emit SSA Phi nodes at top of block (supports forward back-edge SSA names)
            for phi in block.phi_nodes:
                if phi.result is None:
                    continue
                lhs = self._format_ssa_def(phi.result)
                phi_ty = self._llvm_type(phi.result.var_type)
                pairs = []
                if phi.phi_incoming:
                    for pred_blk, val in phi.phi_incoming:
                        pairs.append(f"[ {self._format_ssa_operand(val, param_set)}, %{pred_blk} ]")
                else:
                    for pred_b, val in zip(block.predecessors, phi.operands):
                        pairs.append(f"[ {self._format_ssa_operand(val, param_set)}, %{pred_b.name} ]")
                if pairs:
                    lines.append(f"    {lhs} = phi {phi_ty} {', '.join(pairs)}")

            # 2. Emit instructions up to first terminator
            emitted_terminator = False
            last_val = "0.0" if fn_ret_ty == "double" else "0"

            for inst in block.instructions:
                if emitted_terminator:
                    break
                opcode = inst.opcode.lower()

                if opcode == "param":
                    if inst.result is not None and not (inst.result.version == 0 and inst.result.name in param_set):
                        lhs = self._format_ssa_def(inst.result)
                        p_name = str(inst.operands[0])
                        p_ty = self._llvm_type(inst.result.var_type)
                        if p_ty == "double":
                            lines.append(f"    {lhs} = fadd double -0.0, %arg_{p_name}")
                        else:
                            lines.append(f"    {lhs} = add i64 0, %arg_{p_name}")
                    continue

                lhs = self._format_ssa_def(inst.result) if inst.result is not None else next_aux("unused")
                ops = [self._format_ssa_operand(o, param_set) for o in inst.operands]
                res_ty = self._llvm_type(inst.result.var_type) if inst.result is not None else "i64"

                if opcode == "const":
                    is_fp_c = (res_ty == "double") or (bool(inst.operands) and isinstance(inst.operands[0], float))
                    if is_fp_c:
                        if inst.operands and isinstance(inst.operands[0], int) and not isinstance(inst.operands[0], bool):
                            v1 = self._format_ssa_operand(float(inst.operands[0]), param_set)
                        else:
                            v1 = ops[0] if ops else "0.0"
                        lines.append(f"    {lhs} = fadd double -0.0, {v1}")
                    else:
                        v1 = ops[0] if ops else "0"
                        lines.append(f"    {lhs} = add i64 0, {v1}")
                    last_val = lhs

                elif opcode == "fconst":
                    v1 = ops[0] if ops else "0.0"
                    lines.append(f"    {lhs} = fadd double -0.0, {v1}")
                    last_val = lhs

                elif opcode == "mov":
                    v1 = ops[0] if ops else ("0.0" if res_ty == "double" else "0")
                    if res_ty == "double":
                        lines.append(f"    {lhs} = fadd double -0.0, {v1}")
                    else:
                        lines.append(f"    {lhs} = add i64 0, {v1}")
                    last_val = lhs

                elif opcode == "neg":
                    v1 = ops[0] if ops else "0"
                    lines.append(f"    {lhs} = sub i64 0, {v1}")
                    last_val = lhs

                elif opcode == "fneg":
                    v1 = ops[0] if ops else "0.0"
                    lines.append(f"    {lhs} = fneg double {v1}")
                    last_val = lhs

                elif opcode == "sitofp":
                    v1 = ops[0] if ops else "0"
                    lines.append(f"    {lhs} = sitofp i64 {v1} to double")
                    last_val = lhs

                elif opcode == "fptosi":
                    v1 = ops[0] if ops else "0.0"
                    lines.append(f"    {lhs} = fptosi double {v1} to i64")
                    last_val = lhs

                elif opcode == "not":
                    v1 = ops[0] if ops else "0"
                    cmp_v = next_aux("not_cmp")
                    lines.append(f"    {cmp_v} = icmp eq i64 {v1}, 0")
                    lines.append(f"    {lhs} = zext i1 {cmp_v} to i64")
                    last_val = lhs

                elif opcode == "alloca":
                    sz = ops[0] if ops else "64"
                    ptr_v = next_aux("alloca_ptr")
                    lines.append(f"    {ptr_v} = alloca i8, i64 {sz}, align 8")
                    lines.append(f"    {lhs} = ptrtoint ptr {ptr_v} to i64")
                    last_val = lhs

                elif opcode in ("add", "sub", "mul", "imul", "sdiv", "div", "srem", "shl", "shr", "sar", "and", "or", "xor"):
                    llvm_op = {
                        "add": "add", "sub": "sub", "mul": "mul", "imul": "mul",
                        "sdiv": "sdiv", "div": "sdiv", "srem": "srem",
                        "shl": "shl", "shr": "ashr", "sar": "ashr",
                        "and": "and", "or": "or", "xor": "xor",
                    }[opcode]
                    v1 = ops[0] if len(ops) > 0 else "0"
                    v2 = ops[1] if len(ops) > 1 else "0"
                    lines.append(f"    {lhs} = {llvm_op} i64 {v1}, {v2}")
                    last_val = lhs

                elif opcode in ("fadd", "fsub", "fmul", "fdiv"):
                    v1 = ops[0] if len(ops) > 0 else "0.0"
                    v2 = ops[1] if len(ops) > 1 else "0.0"
                    lines.append(f"    {lhs} = {opcode} double {v1}, {v2}")
                    last_val = lhs

                elif opcode in self.CMP_PRED_MAP:
                    pred = self.CMP_PRED_MAP[opcode]
                    v1 = ops[0] if len(ops) > 0 else "0"
                    v2 = ops[1] if len(ops) > 1 else "0"
                    cmp_i1 = next_aux("cmp_i1")
                    lines.append(f"    {cmp_i1} = icmp {pred} i64 {v1}, {v2}")
                    lines.append(f"    {lhs} = zext i1 {cmp_i1} to i64")
                    last_val = lhs

                elif opcode in self.FCMP_PRED_MAP:
                    pred = self.FCMP_PRED_MAP[opcode]
                    v1 = ops[0] if len(ops) > 0 else "0.0"
                    v2 = ops[1] if len(ops) > 1 else "0.0"
                    cmp_i1 = next_aux("fcmp_i1")
                    lines.append(f"    {cmp_i1} = fcmp {pred} double {v1}, {v2}")
                    lines.append(f"    {lhs} = zext i1 {cmp_i1} to i64")
                    last_val = lhs

                elif opcode == "select":
                    c_op = ops[0] if len(ops) > 0 else "0"
                    t_op = ops[1] if len(ops) > 1 else ("0.0" if res_ty == "double" else "0")
                    f_op = ops[2] if len(ops) > 2 else ("0.0" if res_ty == "double" else "0")
                    sel_i1 = next_aux("sel_i1")
                    lines.append(f"    {sel_i1} = icmp ne i64 {c_op}, 0")
                    lines.append(f"    {lhs} = select i1 {sel_i1}, {res_ty} {t_op}, {res_ty} {f_op}")
                    last_val = lhs

                elif opcode == "load":
                    base_op = ops[0] if len(ops) > 0 else "0"
                    idx_op = ops[1] if len(ops) > 1 else "0"
                    elem_ty = "double" if res_ty == "double" else "i64"
                    ptr_v = next_aux("ptr")
                    gep_v = next_aux("gep")
                    lines.append(f"    {ptr_v} = inttoptr i64 {base_op} to ptr")
                    lines.append(f"    {gep_v} = getelementptr {elem_ty}, ptr {ptr_v}, i64 {idx_op}")
                    lines.append(f"    {lhs} = load {elem_ty}, ptr {gep_v}, align 8")
                    last_val = lhs

                elif opcode == "store":
                    base_op = ops[0] if len(ops) > 0 else "0"
                    idx_op = ops[1] if len(ops) > 1 else "0"
                    val_op = ops[2] if len(ops) > 2 else "0"
                    raw_val_op = inst.operands[2] if len(inst.operands) > 2 else 0
                    elem_ty = (
                        "double"
                        if (
                            isinstance(raw_val_op, float)
                            or (isinstance(raw_val_op, SSAVar) and raw_val_op.var_type == "f64")
                        )
                        else "i64"
                    )
                    ptr_v = next_aux("ptr")
                    gep_v = next_aux("gep")
                    lines.append(f"    {ptr_v} = inttoptr i64 {base_op} to ptr")
                    lines.append(f"    {gep_v} = getelementptr {elem_ty}, ptr {ptr_v}, i64 {idx_op}")
                    lines.append(f"    store {elem_ty} {val_op}, ptr {gep_v}, align 8")

                elif opcode == "load_off":
                    base_op = ops[0] if len(ops) > 0 else "0"
                    off_op = ops[1] if len(ops) > 1 else "0"
                    width = str(inst.operands[2]) if len(inst.operands) >= 3 else "i64"
                    ptr_v = next_aux("ptr")
                    gep_v = next_aux("gepb")
                    lines.append(f"    {ptr_v} = inttoptr i64 {base_op} to ptr")
                    lines.append(f"    {gep_v} = getelementptr i8, ptr {ptr_v}, i64 {off_op}")
                    if width in ("i8", "u8"):
                        w8 = next_aux("ld8")
                        ext_op = "sext" if width == "i8" else "zext"
                        lines.append(f"    {w8} = load i8, ptr {gep_v}, align 1")
                        lines.append(f"    {lhs} = {ext_op} i8 {w8} to i64")
                    elif width in ("i16", "u16"):
                        w16 = next_aux("ld16")
                        ext_op = "sext" if width == "i16" else "zext"
                        lines.append(f"    {w16} = load i16, ptr {gep_v}, align 1")
                        lines.append(f"    {lhs} = {ext_op} i16 {w16} to i64")
                    elif width in ("i32", "u32"):
                        w32 = next_aux("ld32")
                        ext_op = "sext" if width == "i32" else "zext"
                        lines.append(f"    {w32} = load i32, ptr {gep_v}, align 1")
                        lines.append(f"    {lhs} = {ext_op} i32 {w32} to i64")
                    elif width == "f32":
                        f32 = next_aux("ldf32")
                        lines.append(f"    {f32} = load float, ptr {gep_v}, align 1")
                        lines.append(f"    {lhs} = fpext float {f32} to double")
                    elif width == "f64":
                        lines.append(f"    {lhs} = load double, ptr {gep_v}, align 1")
                    else:
                        lines.append(f"    {lhs} = load i64, ptr {gep_v}, align 1")
                    last_val = lhs

                elif opcode == "store_off":
                    base_op = ops[0] if len(ops) > 0 else "0"
                    off_op = ops[1] if len(ops) > 1 else "0"
                    val_op = ops[2] if len(ops) > 2 else "0"
                    width = str(inst.operands[3]) if len(inst.operands) >= 4 else "i64"
                    ptr_v = next_aux("ptr")
                    gep_v = next_aux("gepb")
                    lines.append(f"    {ptr_v} = inttoptr i64 {base_op} to ptr")
                    lines.append(f"    {gep_v} = getelementptr i8, ptr {ptr_v}, i64 {off_op}")
                    if width in ("i8", "u8"):
                        t8 = next_aux("tr8")
                        lines.append(f"    {t8} = trunc i64 {val_op} to i8")
                        lines.append(f"    store i8 {t8}, ptr {gep_v}, align 1")
                    elif width in ("i16", "u16"):
                        t16 = next_aux("tr16")
                        lines.append(f"    {t16} = trunc i64 {val_op} to i16")
                        lines.append(f"    store i16 {t16}, ptr {gep_v}, align 1")
                    elif width in ("i32", "u32"):
                        t32 = next_aux("tr32")
                        lines.append(f"    {t32} = trunc i64 {val_op} to i32")
                        lines.append(f"    store i32 {t32}, ptr {gep_v}, align 1")
                    elif width == "f32":
                        tf32 = next_aux("trf32")
                        lines.append(f"    {tf32} = fptrunc double {val_op} to float")
                        lines.append(f"    store float {tf32}, ptr {gep_v}, align 1")
                    elif width == "f64":
                        lines.append(f"    store double {val_op}, ptr {gep_v}, align 1")
                    else:
                        lines.append(f"    store i64 {val_op}, ptr {gep_v}, align 1")

                elif opcode == "lut_load":
                    lut_name = str(inst.operands[0])
                    width = str(inst.operands[1])
                    idx_op = ops[2]
                    luts_m = getattr(ssa_func, "luts", {}) or {}
                    n_elems = len(luts_m[lut_name][1]) if lut_name in luts_m else 1
                    elem_ty, ext_kind = self._LLVM_LUT_ELEM.get(width, ("i64", None))
                    gep_v = next_aux("lutp")
                    lines.append(
                        f"    {gep_v} = getelementptr [{n_elems} x {elem_ty}], ptr @__omni_lut_{ssa_func.name}_{lut_name}, i64 0, i64 {idx_op}"
                    )
                    if ext_kind in ("sext", "zext"):
                        lv = next_aux("lutld")
                        lines.append(f"    {lv} = load {elem_ty}, ptr {gep_v}, align 1")
                        lines.append(f"    {lhs} = {ext_kind} {elem_ty} {lv} to i64")
                    elif ext_kind == "fpext":
                        lv = next_aux("lutf")
                        lines.append(f"    {lv} = load float, ptr {gep_v}, align 1")
                        lines.append(f"    {lhs} = fpext float {lv} to double")
                    else:
                        lines.append(f"    {lhs} = load {elem_ty}, ptr {gep_v}, align 1")
                    last_val = lhs

                elif opcode == "cstr_addr":
                    c_name = str(inst.operands[0])
                    lines.append(f"    {lhs} = ptrtoint ptr @__omni_cstr_{ssa_func.name}_{c_name} to i64")
                    last_val = lhs

                elif opcode == "call":
                    callee = str(inst.operands[0])
                    arg_pairs = []
                    arg_tys = []
                    for orig_a, fmt_a in zip(inst.operands[1:], ops[1:]):
                        aty = "double" if (isinstance(orig_a, float) or (isinstance(orig_a, SSAVar) and orig_a.var_type == "f64")) else "i64"
                        arg_pairs.append(f"{aty} {fmt_a}")
                        arg_tys.append(aty)
                    args_sig = ", ".join(arg_pairs)
                    if callee in ("printf",):
                        if declared_externals is not None and callee != ssa_func.name:
                            declared_externals[callee] = ("i64", "vararg")
                        lines.append(f"    {lhs} = call i64 (i64, ...) @{callee}({args_sig})")
                    else:
                        if declared_externals is not None and callee != ssa_func.name:
                            declared_externals.setdefault(callee, (res_ty, arg_tys))
                        lines.append(f"    {lhs} = call {res_ty} @{callee}({args_sig})")
                    last_val = lhs

                elif opcode == "br":
                    target_bb = str(inst.operands[0])
                    lines.append(f"    br label %{target_bb}")
                    emitted_terminator = True

                elif opcode == "br_cond":
                    cond_v = ops[0]
                    true_bb = str(inst.operands[1])
                    false_bb = str(inst.operands[2])
                    br_i1 = next_aux("br_i1")
                    lines.append(f"    {br_i1} = icmp ne i64 {cond_v}, 0")
                    lines.append(f"    br i1 {br_i1}, label %{true_bb}, label %{false_bb}")
                    emitted_terminator = True

                elif opcode == "ret":
                    v = ops[0] if ops else ("0.0" if fn_ret_ty == "double" else "0")
                    lines.append(f"    ret {fn_ret_ty} {v}")
                    emitted_terminator = True

            if not emitted_terminator:
                lines.append(f"    ret {fn_ret_ty} {last_val}")

        lines.append("}")
        return "\n".join(lines)

    _LLVM_LUT_ELEM = {
        "i8": ("i8", "sext"), "u8": ("i8", "zext"),
        "i16": ("i16", "sext"), "u16": ("i16", "zext"),
        "i32": ("i32", "sext"), "u32": ("i32", "zext"),
        "f32": ("float", "fpext"),
        "i64": ("i64", None), "u64": ("i64", None),
        "f64": ("double", None),
    }

    @classmethod
    def _emit_llvm_luts(cls, ssa_funcs: List[SSAFunction]) -> List[str]:
        out: List[str] = []
        for fn in ssa_funcs:
            for lut_name, (wt, vals) in sorted((getattr(fn, "luts", {}) or {}).items()):
                elem_ty, _ = cls._LLVM_LUT_ELEM.get(wt, ("i64", None))
                items = []
                for v in vals:
                    if elem_ty in ("double", "float"):
                        items.append(f"{elem_ty} {repr(float(v))}")
                    else:
                        items.append(f"{elem_ty} {int(v)}")
                out.append(
                    f"@__omni_lut_{fn.name}_{lut_name} = private unnamed_addr constant [{len(vals)} x {elem_ty}] [{', '.join(items)}], align 8"
                )
            for c_name, raw_b in sorted((getattr(fn, "cstrs", {}) or {}).items()):
                hex_str = "".join(f"\\{b:02X}" for b in raw_b)
                out.append(
                    f'@__omni_cstr_{fn.name}_{c_name} = private unnamed_addr constant [{len(raw_b)} x i8] c"{hex_str}", align 1'
                )
        return out

    @staticmethod
    def _format_external_decl(ext_name: str, spec: Any) -> str:
        if isinstance(spec, int):
            ret_ty, arg_tys = "i64", ["i64"] * spec
            return f"declare {ret_ty} @{ext_name}({', '.join(arg_tys)})"
        ret_ty, arg_tys = spec
        if arg_tys == "vararg":
            return f"declare {ret_ty} @{ext_name}(i64, ...)"
        return f"declare {ret_ty} @{ext_name}({', '.join(arg_tys)})"

    def ssa_to_llvm_ir(self, ssa_func: SSAFunction) -> str:
        """Lowers a single OmniCompiler `SSAFunction` (including multi-block CFGs & external decls) to LLVM IR."""
        externals: Dict[str, Any] = {}
        body = self.ssa_function_to_llvm_body(ssa_func, declared_externals=externals)
        header = [
            f'; ModuleID = "omni_{ssa_func.name}"',
            f'target triple = "{self.target_triple}"',
        ]
        header.extend(self._emit_llvm_luts([ssa_func]))
        for ext_name, spec in sorted(externals.items()):
            header.append(self._format_external_decl(ext_name, spec))
        header.append(body)
        return "\n".join(header)

    def ssa_module_to_llvm_ir(self, ssa_funcs: List[SSAFunction], module_name: str = "omni_module") -> str:
        """Lowers a multi-function repository module into a single LLVM IR compilation unit for LTO/O3."""
        defined = {f.name for f in ssa_funcs}
        externals: Dict[str, Any] = {}
        bodies = [self.ssa_function_to_llvm_body(f, declared_externals=externals) for f in ssa_funcs]
        lines = [
            f'; ModuleID = "{module_name}"',
            f'target triple = "{self.target_triple}"',
        ]
        lines.extend(self._emit_llvm_luts(ssa_funcs))
        for ext_name, spec in sorted(externals.items()):
            if ext_name not in defined:
                lines.append(self._format_external_decl(ext_name, spec))
        lines.extend(bodies)
        return "\n".join(lines)
