"""
OmniCompiler WebAssembly (WASM) Target & Sandbox.
Provides isolated, deterministic, portable WebAssembly code generation and execution
using Bytecode Alliance's Wasmtime runtime engine.
"""

from typing import List, Dict, Any, Optional, Union
import os

try:
    import wasmtime
    from wasmtime import Engine, Store, Module, Instance, Func
    WASMTIME_AVAILABLE = True
except ImportError:
    WASMTIME_AVAILABLE = False


class WasmBackend:
    """
    WebAssembly code generator, serializer, and sandboxed execution engine.
    Allows running compiled inter-repo capsules inside memory-safe WebAssembly sandboxes.
    """

    def __init__(self):
        self._engine = None
        if WASMTIME_AVAILABLE:
            try:
                self._engine = Engine()
            except Exception:
                self._engine = None

    @property
    def is_available(self) -> bool:
        return WASMTIME_AVAILABLE and self._engine is not None

    def compile_wat(self, wat_text: str) -> bytes:
        """Compiles WebAssembly Text format (WAT) to binary bytecode (.wasm)."""
        if not self.is_available:
            raise RuntimeError("Wasmtime engine is not available on this system.")
        module = Module(self._engine, wat_text)
        return bytes(module.serialize())

    def execute_wasm(
        self,
        wasm_code: Union[str, bytes],
        func_name: str,
        args: Optional[List[int]] = None
    ) -> int:
        """
        Instantiates a WebAssembly module and executes the specified exported function.
        """
        if not self.is_available:
            raise RuntimeError("Wasmtime engine is not available.")

        args = args or []
        store = Store(self._engine)

        if isinstance(wasm_code, str):
            module = Module(self._engine, wasm_code)
        else:
            module = Module.deserialize(self._engine, wasm_code)

        instance = Instance(store, module, [])
        exports = instance.exports(store)

        if func_name not in exports:
            raise ValueError(f"Exported function '{func_name}' not found in WASM module.")

        wasm_fn = exports[func_name]
        return wasm_fn(store, *args)

    def ssa_to_wat(self, ssa_func) -> str:
        """
        Lowers an OmniCompiler SSAFunction into a WebAssembly Text (WAT) module.
        """
        params_str = " ".join(f"(param ${p} i64)" for p in ssa_func.params)
        wat_lines = [
            f"(module",
            f'  (func (export "{ssa_func.name}") {params_str} (result i64)',
        ]

        var_locals = set()
        for block in ssa_func.blocks:
            for inst in block.instructions:
                if inst.result:
                    v_name = f"var_{inst.result.name}_{inst.result.version}"
                    var_locals.add(v_name)

        # Declare local variables
        for l in sorted(var_locals):
            wat_lines.append(f"    (local ${l} i64)")

        # Emit instructions
        for block in ssa_func.blocks:
            for inst in block.instructions:
                opcode = inst.opcode.lower()

                def emit_operand(op):
                    op_str = str(op)
                    if op_str.startswith("%"):
                        v = op_str.lstrip("%")
                        return f"local.get $var_{v}"
                    elif op_str.isdigit() or (op_str.startswith("-") and op_str[1:].isdigit()):
                        return f"i64.const {op_str}"
                    else:
                        # Named parameter or local
                        return f"local.get ${op_str}"

                if opcode == "add":
                    op1 = emit_operand(inst.operands[0])
                    op2 = emit_operand(inst.operands[1])
                    wat_lines.append(f"    {op1}")
                    wat_lines.append(f"    {op2}")
                    wat_lines.append(f"    i64.add")
                    if inst.result:
                        wat_lines.append(f"    local.set $var_{inst.result.name}_{inst.result.version}")

                elif opcode in ("sub", "subq"):
                    op1 = emit_operand(inst.operands[0])
                    op2 = emit_operand(inst.operands[1])
                    wat_lines.append(f"    {op1}")
                    wat_lines.append(f"    {op2}")
                    wat_lines.append(f"    i64.sub")
                    if inst.result:
                        wat_lines.append(f"    local.set $var_{inst.result.name}_{inst.result.version}")

                elif opcode in ("mul", "imul"):
                    op1 = emit_operand(inst.operands[0])
                    op2 = emit_operand(inst.operands[1])
                    wat_lines.append(f"    {op1}")
                    wat_lines.append(f"    {op2}")
                    wat_lines.append(f"    i64.mul")
                    if inst.result:
                        wat_lines.append(f"    local.set $var_{inst.result.name}_{inst.result.version}")

                elif opcode in ("const", "mov"):
                    op1 = emit_operand(inst.operands[0])
                    wat_lines.append(f"    {op1}")
                    if inst.result:
                        wat_lines.append(f"    local.set $var_{inst.result.name}_{inst.result.version}")

                elif opcode == "ret":
                    op = emit_operand(inst.operands[0])
                    wat_lines.append(f"    {op}")
                    wat_lines.append(f"    return")

        # If no explicit return, load the last computed variable
        if not any("return" in line for line in wat_lines):
            if var_locals:
                last_var = sorted(var_locals)[-1]
                wat_lines.append(f"    local.get ${last_var}")
            else:
                wat_lines.append(f"    i64.const 0")

        wat_lines.append("  )")
        wat_lines.append(")")
        return "\n".join(wat_lines)
