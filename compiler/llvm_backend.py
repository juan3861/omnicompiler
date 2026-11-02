"""
OmniCompiler Industrial LLVM Backend & JIT Engine.
Bridges Turing-complete multi-block Omni-SSA IR (`phi`, `br`, `br_cond`, `cmp_*`,
`select`, `sdiv`, `srem`, `shl`, `shr`, `load`, `store`, `call`) and multi-function modules
to LLVM IR, applies LLVM O3 PassBuilder optimization pipelines (auto-vectorization,
loop unrolling, GVN, instcombine), and compiles to MCJIT silicon or COFF/ELF object files.
"""

from typing import Optional, List, Dict, Any, Union
import ctypes

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

    def __init__(self, opt_level: int = 3):
        self.opt_level = opt_level
        self._target_machine = None
        self._obj_target_machine = None
        self._initialized = False

        if LLVM_AVAILABLE:
            try:
                llvm.initialize_native_target()
                llvm.initialize_native_asmprinter()
                target = llvm.Target.from_default_triple()
                self._target_machine = target.create_target_machine(opt=self.opt_level)
                self._obj_target_machine = target.create_target_machine(opt=self.opt_level, codemodel="small")
                self._initialized = True
            except Exception:
                self._initialized = False

    @property
    def is_available(self) -> bool:
        return LLVM_AVAILABLE and self._initialized

    @property
    def target_triple(self) -> str:
        if self._target_machine:
            return self._target_machine.triple
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
        return self._target_machine.emit_assembly(mod)

    def create_jit_callable(self, mod: Any, func_name: str, restype=ctypes.c_int64, argtypes=None):
        """
        Compiles the LLVM module via MCJIT in host memory and returns a directly callable
        ctypes function pointer with specified signature.
        """
        if not self.is_available:
            raise RuntimeError("LLVM backend is not available.")

        argtypes = argtypes or []
        ee = llvm.create_mcjit_compiler(mod, self._target_machine)
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

    def ssa_function_to_llvm_body(self, ssa_func: SSAFunction, declared_externals: Optional[Dict[str, int]] = None) -> str:
        param_set = set(ssa_func.params)
        params_str = ", ".join(f"i64 %arg_{p}" for p in ssa_func.params)
        lines = [f"define i64 @{ssa_func.name}({params_str}) {{"]
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
                pairs = []
                if phi.phi_incoming:
                    for pred_blk, val in phi.phi_incoming:
                        pairs.append(f"[ {self._format_ssa_operand(val, param_set)}, %{pred_blk} ]")
                else:
                    for pred_b, val in zip(block.predecessors, phi.operands):
                        pairs.append(f"[ {self._format_ssa_operand(val, param_set)}, %{pred_b.name} ]")
                if pairs:
                    lines.append(f"    {lhs} = phi i64 {', '.join(pairs)}")

            # 2. Emit instructions up to first terminator
            emitted_terminator = False
            last_val = "0"

            for inst in block.instructions:
                if emitted_terminator:
                    break
                opcode = inst.opcode.lower()

                if opcode == "param":
                    if inst.result is not None and not (inst.result.version == 0 and inst.result.name in param_set):
                        lhs = self._format_ssa_def(inst.result)
                        p_name = str(inst.operands[0])
                        lines.append(f"    {lhs} = add i64 0, %arg_{p_name}")
                    continue

                lhs = self._format_ssa_def(inst.result) if inst.result is not None else next_aux("unused")
                ops = [self._format_ssa_operand(o, param_set) for o in inst.operands]

                if opcode in ("const", "mov"):
                    v1 = ops[0] if ops else "0"
                    lines.append(f"    {lhs} = add i64 0, {v1}")
                    last_val = lhs

                elif opcode in ("add", "sub", "mul", "imul", "sdiv", "div", "srem", "shl", "shr", "and", "or", "xor"):
                    llvm_op = {
                        "add": "add", "sub": "sub", "mul": "mul", "imul": "mul",
                        "sdiv": "sdiv", "div": "sdiv", "srem": "srem",
                        "shl": "shl", "shr": "ashr",
                        "and": "and", "or": "or", "xor": "xor",
                    }[opcode]
                    v1 = ops[0] if len(ops) > 0 else "0"
                    v2 = ops[1] if len(ops) > 1 else "0"
                    lines.append(f"    {lhs} = {llvm_op} i64 {v1}, {v2}")
                    last_val = lhs

                elif opcode in self.CMP_PRED_MAP:
                    pred = self.CMP_PRED_MAP[opcode]
                    v1 = ops[0] if len(ops) > 0 else "0"
                    v2 = ops[1] if len(ops) > 1 else "0"
                    cmp_i1 = next_aux("cmp_i1")
                    lines.append(f"    {cmp_i1} = icmp {pred} i64 {v1}, {v2}")
                    lines.append(f"    {lhs} = zext i1 {cmp_i1} to i64")
                    last_val = lhs

                elif opcode == "select":
                    c_op = ops[0] if len(ops) > 0 else "0"
                    t_op = ops[1] if len(ops) > 1 else "0"
                    f_op = ops[2] if len(ops) > 2 else "0"
                    sel_i1 = next_aux("sel_i1")
                    lines.append(f"    {sel_i1} = icmp ne i64 {c_op}, 0")
                    lines.append(f"    {lhs} = select i1 {sel_i1}, i64 {t_op}, i64 {f_op}")
                    last_val = lhs

                elif opcode == "load":
                    base_op = ops[0] if len(ops) > 0 else "0"
                    idx_op = ops[1] if len(ops) > 1 else "0"
                    ptr_v = next_aux("ptr")
                    gep_v = next_aux("gep")
                    lines.append(f"    {ptr_v} = inttoptr i64 {base_op} to ptr")
                    lines.append(f"    {gep_v} = getelementptr i64, ptr {ptr_v}, i64 {idx_op}")
                    lines.append(f"    {lhs} = load i64, ptr {gep_v}, align 8")
                    last_val = lhs

                elif opcode == "store":
                    base_op = ops[0] if len(ops) > 0 else "0"
                    idx_op = ops[1] if len(ops) > 1 else "0"
                    val_op = ops[2] if len(ops) > 2 else "0"
                    ptr_v = next_aux("ptr")
                    gep_v = next_aux("gep")
                    lines.append(f"    {ptr_v} = inttoptr i64 {base_op} to ptr")
                    lines.append(f"    {gep_v} = getelementptr i64, ptr {ptr_v}, i64 {idx_op}")
                    lines.append(f"    store i64 {val_op}, ptr {gep_v}, align 8")

                elif opcode == "call":
                    callee = str(inst.operands[0])
                    call_args = [self._format_ssa_operand(a, param_set) for a in inst.operands[1:]]
                    if declared_externals is not None and callee != ssa_func.name:
                        declared_externals.setdefault(callee, len(call_args))
                    args_sig = ", ".join(f"i64 {a}" for a in call_args)
                    lines.append(f"    {lhs} = call i64 @{callee}({args_sig})")
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
                    v = ops[0] if ops else "0"
                    lines.append(f"    ret i64 {v}")
                    emitted_terminator = True

            if not emitted_terminator:
                lines.append(f"    ret i64 {last_val}")

        lines.append("}")
        return "\n".join(lines)

    def ssa_to_llvm_ir(self, ssa_func: SSAFunction) -> str:
        """Lowers a single OmniCompiler `SSAFunction` (including multi-block CFGs & external decls) to LLVM IR."""
        externals: Dict[str, int] = {}
        body = self.ssa_function_to_llvm_body(ssa_func, declared_externals=externals)
        header = [
            f'; ModuleID = "omni_{ssa_func.name}"',
            f'target triple = "{self.target_triple}"',
        ]
        for ext_name, arity in sorted(externals.items()):
            sig = ", ".join(["i64"] * arity)
            header.append(f"declare i64 @{ext_name}({sig})")
        header.append(body)
        return "\n".join(header)

    def ssa_module_to_llvm_ir(self, ssa_funcs: List[SSAFunction], module_name: str = "omni_module") -> str:
        """Lowers a multi-function repository module into a single LLVM IR compilation unit for LTO/O3."""
        defined = {f.name for f in ssa_funcs}
        externals: Dict[str, int] = {}
        bodies = [self.ssa_function_to_llvm_body(f, declared_externals=externals) for f in ssa_funcs]
        lines = [
            f'; ModuleID = "{module_name}"',
            f'target triple = "{self.target_triple}"',
        ]
        for ext_name, arity in sorted(externals.items()):
            if ext_name not in defined:
                sig = ", ".join(["i64"] * arity)
                lines.append(f"declare i64 @{ext_name}({sig})")
        lines.extend(bodies)
        return "\n".join(lines)
