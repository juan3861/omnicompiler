"""
OmniCompiler Industrial LLVM Backend & JIT Engine.
Bridges Omni-SSA IR to LLVM IR, applies LLVM O3 optimization pipelines
(auto-vectorization, loop unrolling, dead-code elimination), and compiles to
native machine code via MCJIT or emits native object files (.obj / .o).
"""

from typing import Optional, List, Dict, Any, Union
import ctypes

try:
    import llvmlite
    import llvmlite.binding as llvm
    LLVM_AVAILABLE = True
except ImportError:
    LLVM_AVAILABLE = False


class LLVMBackend:
    """
    Industrial optimizing backend using LLVM / llvmlite.
    Transforms SSA functions and LLVM IR into optimized native machine code.
    """

    def __init__(self, opt_level: int = 3):
        self.opt_level = opt_level
        self._target_machine = None
        self._initialized = False

        if LLVM_AVAILABLE:
            try:
                llvm.initialize_native_target()
                llvm.initialize_native_asmprinter()
                target = llvm.Target.from_default_triple()
                self._target_machine = target.create_target_machine(opt=self.opt_level)
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
            pb = llvm.create_pass_builder(self._target_machine, pto)
            mpm = pb.getModulePassManager()
            mpm.run(mod, pb)

        return mod

    def emit_object(self, mod: Any) -> bytes:
        """Emits a native machine-code object file (.o / .obj) from an LLVM module."""
        if not self.is_available:
            raise RuntimeError("LLVM backend is not available.")
        return self._target_machine.emit_object(mod)

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
        # Keep reference to execution engine so memory is not freed while callable is active
        cfunc._engine = ee
        return cfunc

    def ssa_to_llvm_ir(self, ssa_func) -> str:
        """
        Lowers an OmniCompiler SSAFunction to LLVM IR string format.
        """
        params_str = ", ".join(f"i64 %{p}" for p in ssa_func.params)
        lines = [
            f'; ModuleID = "omni_{ssa_func.name}"',
            f'target triple = "{self.target_triple}"',
            f"define i64 @{ssa_func.name}({params_str}) {{",
        ]

        var_map: Dict[str, str] = {}
        # Pre-populate function parameters
        for p in ssa_func.params:
            var_map[f"%{p}_0"] = f"%{p}"
            var_map[p] = f"%{p}"

        tmp_counter = 0

        for block in ssa_func.blocks:
            lines.append(f"{block.name}:")
            for inst in block.instructions:
                res_var = f"%t_{tmp_counter}"
                tmp_counter += 1

                ops = []
                for op in inst.operands:
                    op_str = str(op)
                    if op_str in var_map:
                        ops.append(var_map[op_str])
                    elif op_str.isdigit() or (op_str.startswith("-") and op_str[1:].isdigit()):
                        ops.append(op_str)
                    else:
                        ops.append(f"%{op_str.lstrip('%')}")

                opcode = inst.opcode.lower()
                if opcode == "add":
                    v1 = ops[0] if len(ops) > 0 else "0"
                    v2 = ops[1] if len(ops) > 1 else "0"
                    lines.append(f"    {res_var} = add i64 {v1}, {v2}")
                    if inst.result:
                        var_map[str(inst.result)] = res_var

                elif opcode in ("sub", "subq"):
                    v1 = ops[0] if len(ops) > 0 else "0"
                    v2 = ops[1] if len(ops) > 1 else "0"
                    lines.append(f"    {res_var} = sub i64 {v1}, {v2}")
                    if inst.result:
                        var_map[str(inst.result)] = res_var

                elif opcode in ("mul", "imul"):
                    v1 = ops[0] if len(ops) > 0 else "1"
                    v2 = ops[1] if len(ops) > 1 else "1"
                    lines.append(f"    {res_var} = mul i64 {v1}, {v2}")
                    if inst.result:
                        var_map[str(inst.result)] = res_var

                elif opcode in ("div", "sdiv"):
                    v1 = ops[0] if len(ops) > 0 else "0"
                    v2 = ops[1] if len(ops) > 1 else "1"
                    lines.append(f"    {res_var} = sdiv i64 {v1}, {v2}")
                    if inst.result:
                        var_map[str(inst.result)] = res_var

                elif opcode in ("const", "mov"):
                    v1 = ops[0] if len(ops) > 0 else "0"
                    lines.append(f"    {res_var} = add i64 0, {v1}")
                    if inst.result:
                        var_map[str(inst.result)] = res_var

                elif opcode == "ret":
                    v = ops[0] if len(ops) > 0 else "0"
                    lines.append(f"    ret i64 {v}")

        # Ensure block terminates with a ret if none was emitted
        if not any("ret " in line for line in lines):
            last_res = f"%t_{tmp_counter - 1}" if tmp_counter > 0 else "0"
            lines.append(f"    ret i64 {last_res}")

        lines.append("}")
        return "\n".join(lines)
