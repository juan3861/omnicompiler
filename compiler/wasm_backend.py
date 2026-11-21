"""
OmniCompiler WebAssembly (WASM) Target, Multi-Block Lowering, Fuel Metering
& WASI Preview 2 / Component Model Canonical ABI Sandbox (`wasm_backend.py`).

Capabilities:
1. Multi-block CFG Omni-SSA -> Structured WAT lowering (`phi`, `if/else`, `while`/`for`
   dispatch loops, `cmp_*`, `sdiv`, `srem`, `shl`, `shr`, `select`, recursive `call`).
2. Deterministic CPU Fuel Metering (`fuel_budget`) via Bytecode Alliance Wasmtime
   to bound execution steps and halt runaway capsules deterministically.
3. WASI Preview 2 / Component Model Canonical ABI (`cabi_realloc` + Linear Memory
   UTF-8 `string` & `list<s64>` marshalling + `.wit` Interface/World parser).
"""

import re
import struct
from typing import List, Dict, Any, Optional, Tuple, Union

from compiler.ssa_ir import SSAVar, SSAFunction, analyze_ssa_constant_offsets, is_contiguous_stride

try:
    import wasmtime
    from wasmtime import Config, Engine, Store, Module, Instance, Func, FuncType, ValType
    WASMTIME_AVAILABLE = True
except ImportError:
    WASMTIME_AVAILABLE = False


def parse_wit_world(wit_source: str) -> Dict[str, Any]:
    """
    Parses a WASI Preview 2 `.wit` interface/world specification, extracting
    package namespace, interfaces, record types, and typed function contracts.
    """
    pkg_match = re.search(r"package\s+([a-zA-Z0-9_:.-]+)(?:@([0-9.]+))?\s*;", wit_source)
    package_name = pkg_match.group(1) if pkg_match else "omni:component"
    package_ver = pkg_match.group(2) if (pkg_match and pkg_match.group(2)) else "1.0.0"

    interfaces: Dict[str, List[Dict[str, Any]]] = {}
    for iface_m in re.finditer(r"interface\s+([a-zA-Z0-9_-]+)\s*\{([^}]*)\}", wit_source, re.DOTALL):
        iname = iface_m.group(1)
        ibody = iface_m.group(2)
        funcs = []
        for fn_m in re.finditer(r"([a-zA-Z0-9_-]+)\s*:\s*func\s*\(([^)]*)\)(?:\s*->\s*([^;]+))?\s*;", ibody):
            fname = fn_m.group(1)
            raw_params = [p.strip() for p in fn_m.group(2).split(",") if p.strip()]
            parsed_params = []
            for rp in raw_params:
                if ":" in rp:
                    pn, pt = rp.split(":", 1)
                    parsed_params.append({"name": pn.strip(), "type": pt.strip()})
            ret_type = fn_m.group(3).strip() if fn_m.group(3) else "unit"
            funcs.append({"name": fname, "params": parsed_params, "result": ret_type})
        interfaces[iname] = funcs

    worlds: Dict[str, Dict[str, List[str]]] = {}
    for w_m in re.finditer(r"world\s+([a-zA-Z0-9_-]+)\s*\{([^}]*)\}", wit_source, re.DOTALL):
        wname = w_m.group(1)
        wbody = w_m.group(2)
        imports = re.findall(r"import\s+([a-zA-Z0-9_:/.-]+)\s*;", wbody)
        exports = re.findall(r"export\s+([a-zA-Z0-9_:/.-]+)\s*;", wbody)
        worlds[wname] = {"imports": imports, "exports": exports}

    return {
        "package": package_name,
        "version": package_ver,
        "interfaces": interfaces,
        "worlds": worlds,
    }


class WasmBackend:
    """
    WebAssembly code generator, serializer, deterministic fuel-metered sandbox,
    and WASI Preview 2 Canonical ABI linear-memory bridge.
    """

    WASM_BINOP_MAP = {
        "add": "i64.add",
        "sub": "i64.sub",
        "subq": "i64.sub",
        "mul": "i64.mul",
        "imul": "i64.mul",
        "sdiv": "i64.div_s",
        "div": "i64.div_s",
        "srem": "i64.rem_s",
        "shl": "i64.shl",
        "shr": "i64.shr_s",
        "sar": "i64.shr_s",
        "and": "i64.and",
        "or": "i64.or",
        "xor": "i64.xor",
    }

    WASM_CMP_MAP = {
        "cmp_eq": "i64.eq",
        "cmp_ne": "i64.ne",
        "cmp_lt": "i64.lt_s",
        "cmp_le": "i64.le_s",
        "cmp_gt": "i64.gt_s",
        "cmp_ge": "i64.ge_s",
    }

    WASM_FLOAT_BINOP_MAP = {
        "fadd": "f64.add",
        "fsub": "f64.sub",
        "fmul": "f64.mul",
        "fdiv": "f64.div",
    }

    WASM_FLOAT_CMP_MAP = {
        "fcmp_eq": "f64.eq",
        "fcmp_ne": "f64.ne",
        "fcmp_lt": "f64.lt",
        "fcmp_le": "f64.le",
        "fcmp_gt": "f64.gt",
        "fcmp_ge": "f64.ge",
    }

    def __init__(self):
        self._engine = None
        self._fuel_engine = None
        if WASMTIME_AVAILABLE:
            try:
                self._engine = Engine()
                fuel_cfg = Config()
                fuel_cfg.consume_fuel = True
                self._fuel_engine = Engine(fuel_cfg)
            except Exception:
                self._engine = None
                self._fuel_engine = None

    @property
    def is_available(self) -> bool:
        return WASMTIME_AVAILABLE and self._engine is not None

    def compile_wat(self, wat_text: str) -> bytes:
        """Compiles WebAssembly Text format (WAT) to Wasmtime serialized machine code."""
        if not self.is_available:
            raise RuntimeError("Wasmtime engine is not available on this system.")
        module = Module(self._engine, wat_text)
        return bytes(module.serialize())

    def wat_to_wasm(self, wat_text: str) -> bytes:
        """Compiles WebAssembly Text format (WAT) to standard portable .wasm binary (0x00 'asm')."""
        import wasmtime
        return bytes(wasmtime.wat2wasm(wat_text))

    def execute_wasm(
        self,
        wasm_code: Union[str, bytes],
        func_name: str,
        args: Optional[List[int]] = None,
        fuel_budget: Optional[int] = None,
    ) -> int:
        """
        Instantiates a WebAssembly module and executes `func_name`.
        When `fuel_budget` is specified, enforces deterministic Wasmtime instruction fuel metering.
        """
        if not self.is_available:
            raise RuntimeError("Wasmtime engine is not available.")

        args = args or []
        if fuel_budget is not None:
            assert self._fuel_engine is not None
            store = Store(self._fuel_engine)
            store.set_fuel(fuel_budget)
            module = Module(self._fuel_engine, wasm_code) if isinstance(wasm_code, str) else Module.deserialize(self._fuel_engine, wasm_code)
        else:
            store = Store(self._engine)
            module = Module(self._engine, wasm_code) if isinstance(wasm_code, str) else Module.deserialize(self._engine, wasm_code)

        instance, stdout_chunks = self._instantiate_with_host_libc(store, module)
        exports = instance.exports(store)
        if func_name not in exports:
            raise ValueError(f"Exported function '{func_name}' not found in WASM module.")

        wasm_fn = exports[func_name]
        self._last_captured_stdout = "".join(stdout_chunks)
        return wasm_fn(store, *args)

    def execute_wasm_with_telemetry(
        self,
        wasm_code: Union[str, bytes],
        func_name: str,
        args: Optional[List[int]] = None,
        fuel_budget: int = 100000,
    ) -> Dict[str, Any]:
        """Executes WASM with fuel metering and returns exact fuel consumption telemetry."""
        if not self.is_available or self._fuel_engine is None:
            raise RuntimeError("Wasmtime fuel engine is not available.")
        args = args or []
        store = Store(self._fuel_engine)
        store.set_fuel(fuel_budget)
        module = Module(self._fuel_engine, wasm_code) if isinstance(wasm_code, str) else Module(self._fuel_engine, bytes(wasm_code))
        instance, stdout_chunks = self._instantiate_with_host_libc(store, module)
        exports = instance.exports(store)
        res = exports[func_name](store, *args)
        remaining = store.get_fuel()
        return {
            "result": res,
            "fuel_budget": fuel_budget,
            "fuel_remaining": remaining,
            "fuel_consumed": fuel_budget - remaining,
            "captured_stdout": "".join(stdout_chunks),
        }

    # ------------------------------------------------------------------
    # Multi-Block Omni-SSA -> Structured WAT Lowering
    # ------------------------------------------------------------------
    _WASM_LUT_STRIDE = {
        "i8": (1, "i64.load8_s"), "u8": (1, "i64.load8_u"),
        "i16": (2, "i64.load16_s"), "u16": (2, "i64.load16_u"),
        "i32": (4, "i64.load32_s"), "u32": (4, "i64.load32_u"),
        "f32": (4, "f32.load"), "i64": (8, "i64.load"), "u64": (8, "i64.load"), "f64": (8, "f64.load"),
    }

    _WASM_HEAP_LIBC = frozenset({"malloc", "calloc", "realloc", "free"})
    _WASM_MEM_STR_MATH_LIBC = frozenset({"memcpy", "memmove", "memset", "strlen", "strcmp", "abs", "labs"})
    _WASM_STDIO_LIBC = frozenset({"printf", "puts", "putchar"})
    _WASM_ALL_LIBC = _WASM_HEAP_LIBC | _WASM_MEM_STR_MATH_LIBC | _WASM_STDIO_LIBC

    @staticmethod
    def _read_guest_cstr(memory: Any, store: Any, ptr: int, max_len: int = 4096) -> str:
        """Reads a NUL-terminated UTF-8 string from WASM Linear Memory starting at `ptr`."""
        mem_len = memory.data_len(store)
        addr = int(ptr) & 0xFFFFFFFF
        if addr <= 0 or addr >= mem_len:
            return ""
        end = min(mem_len, addr + max_len)
        raw = bytes(memory.read(store, addr, end))
        nul = raw.find(b"\x00")
        if nul != -1:
            raw = raw[:nul]
        return raw.decode("utf-8", errors="replace")

    @classmethod
    def _format_guest_printf(
        cls,
        memory: Any,
        store: Any,
        fmt_ptr: int,
        abuf_ptr: int,
        nargs: int,
        type_mask: int,
    ) -> str:
        """Formats a variadic C `printf` call reading format and args from WASM linear memory."""
        fmt = cls._read_guest_cstr(memory, store, fmt_ptr)
        parsed_args: List[Any] = []
        base_buf = int(abuf_ptr) & 0xFFFFFFFF
        for idx in range(max(0, int(nargs))):
            slot = base_buf + idx * 8
            raw = bytes(memory.read(store, slot, slot + 8))
            if (int(type_mask) >> idx) & 1:
                parsed_args.append(struct.unpack("<d", raw)[0])
            else:
                parsed_args.append(struct.unpack("<q", raw)[0])

        out_parts: List[str] = []
        pos = 0
        arg_i = 0
        spec_re = re.compile(r"%(%|[-+#0 ]*(?:\d+)?(?:\.\d+)?(?:ll|l|h|hh|z)?([diuoxXfFeEgGcsp]))")
        for m in spec_re.finditer(fmt):
            out_parts.append(fmt[pos:m.start()])
            pos = m.end()
            full_spec = m.group(0)
            conv = m.group(2)
            if m.group(1) == "%":
                out_parts.append("%")
                continue
            val = parsed_args[arg_i] if arg_i < len(parsed_args) else 0
            arg_i += 1
            if conv == "s":
                out_parts.append(cls._read_guest_cstr(memory, store, int(val)) if isinstance(val, int) else str(val))
            elif conv == "c":
                out_parts.append(chr(int(val) & 0xFF))
            elif conv == "p":
                out_parts.append(hex(int(val) & 0xFFFFFFFFFFFFFFFF))
            elif conv in ("f", "F", "e", "E", "g", "G"):
                py_spec = full_spec.replace("ll", "").replace("l", "").replace("h", "").replace("z", "")
                out_parts.append(py_spec % float(val))
            elif conv in ("u", "x", "X", "o"):
                is_64 = "ll" in full_spec or "l" in full_spec or "z" in full_spec
                uval = (int(val) & 0xFFFFFFFFFFFFFFFF) if is_64 else (int(val) & 0xFFFFFFFF)
                if conv == "u":
                    out_parts.append(str(uval))
                else:
                    py_spec = full_spec.replace("ll", "").replace("l", "").replace("h", "").replace("z", "")
                    out_parts.append(py_spec % uval)
            else:
                py_spec = re.sub(r"(?:ll|l|h|hh|z)", "", full_spec)
                if conv in ("i", "u"):
                    py_spec = py_spec[:-1] + "d"
                v_i = (int(val) & 0xFFFFFFFFFFFFFFFF) if (conv == "u" and ("ll" in full_spec or "l" in full_spec or "z" in full_spec)) else (
                    (int(val) & 0xFFFFFFFF) if conv == "u" else int(val)
                )
                out_parts.append(py_spec % v_i)
        out_parts.append(fmt[pos:])
        return "".join(out_parts)

    def _instantiate_with_host_libc(self, store: Any, module: Any) -> Tuple[Any, List[str]]:
        """Instantiates a compiled WASM `Module`, auto-binding `env` host stdio imports if requested."""
        stdout_chunks: List[str] = []
        mem_holder: Dict[str, Any] = {}
        imports: List[Any] = []
        i64_ty = ValType.i64()

        for imp in module.imports:
            if imp.module != "env":
                raise RuntimeError(f"Unsupported WASM import module '{imp.module}.{imp.name}'.")
            if imp.name == "__omni_printf_host":
                def _printf_cb(fmt_p: int, abuf_p: int, nargs: int, tmask: int) -> int:
                    mem = mem_holder.get("memory")
                    if mem is None:
                        return 0
                    rendered = self._format_guest_printf(mem, store, fmt_p, abuf_p, nargs, tmask)
                    stdout_chunks.append(rendered)
                    return len(rendered.encode("utf-8"))

                imports.append(Func(store, FuncType([i64_ty, i64_ty, i64_ty, i64_ty], [i64_ty]), _printf_cb))
            elif imp.name == "__omni_puts_host":
                def _puts_cb(str_p: int) -> int:
                    mem = mem_holder.get("memory")
                    if mem is None:
                        return 0
                    s_txt = self._read_guest_cstr(mem, store, str_p) + "\n"
                    stdout_chunks.append(s_txt)
                    return len(s_txt.encode("utf-8"))

                imports.append(Func(store, FuncType([i64_ty], [i64_ty]), _puts_cb))
            elif imp.name == "__omni_putchar_host":
                def _putchar_cb(ch: int) -> int:
                    c = chr(int(ch) & 0xFF)
                    stdout_chunks.append(c)
                    return int(ch) & 0xFF

                imports.append(Func(store, FuncType([i64_ty], [i64_ty]), _putchar_cb))
            else:
                raise RuntimeError(f"Unsupported WASM host libc import '{imp.module}.{imp.name}'.")

        instance = Instance(store, module, imports)
        exports = instance.exports(store)
        if "memory" in exports:
            mem_holder["memory"] = exports["memory"]
        return instance, stdout_chunks

    @classmethod
    def _build_wat_rodata_with_bounds(
        cls, ssa_funcs: List[SSAFunction]
    ) -> Tuple[Dict[Tuple[str, str], Tuple[int, str, int]], List[str], int]:
        """Assigns linear-memory .rodata addresses >= 245760 (0x3C000) and returns `(addr_map, data_lines, ro_end)`."""
        from compiler.native_codegen import _pack_lut_bytes
        ro_cursor = 245760  # Page 3 (0x3C000) cleanly disjoint from user vectors at < 240 KiB
        addr_map: Dict[Tuple[str, str], Tuple[int, str, int]] = {}
        data_lines: List[str] = []
        for fn in ssa_funcs:
            for lut_name, (wt, vals) in sorted((getattr(fn, "luts", {}) or {}).items()):
                ro_cursor = (ro_cursor + 7) & ~7
                packed = _pack_lut_bytes(wt, vals)
                esc = "".join(f"\\{b:02x}" for b in packed)
                data_lines.append(f'  (data (i32.const {ro_cursor}) "{esc}")')
                stride, _ = cls._WASM_LUT_STRIDE.get(wt, (8, "i64.load"))
                addr_map[(fn.name, lut_name)] = (ro_cursor, wt, stride)
                ro_cursor += max(8, len(packed))
            for c_name, raw_b in sorted((getattr(fn, "cstrs", {}) or {}).items()):
                ro_cursor = (ro_cursor + 7) & ~7
                esc = "".join(f"\\{b:02x}" for b in raw_b)
                data_lines.append(f'  (data (i32.const {ro_cursor}) "{esc}")')
                addr_map[(fn.name, f"__cstr_{c_name}")] = (ro_cursor, "u8", 1)
                ro_cursor += max(8, len(raw_b))
        return addr_map, data_lines, ro_cursor

    @classmethod
    def _build_wat_rodata(cls, ssa_funcs: List[SSAFunction]) -> Tuple[Dict[Tuple[str, str], Tuple[int, str, int]], List[str]]:
        """Assigns linear-memory .rodata addresses >= 245760 (0x3C000) and emits WAT (data ...) directives."""
        addr_map, data_lines, _ = cls._build_wat_rodata_with_bounds(ssa_funcs)
        return addr_map, data_lines

    def _ssa_function_to_wat_func(
        self, ssa_func: SSAFunction, lut_addr_map: Optional[Dict[Tuple[str, str], Tuple[int, str, int]]] = None
    ) -> str:
        """Lowers a single `SSAFunction` into a `(func ...)` WAT definition."""
        def _wty(vtype: str) -> str:
            return "f64" if vtype == "f64" else "i64"

        param_set = set(ssa_func.params)
        fn_ret_wty = _wty(getattr(ssa_func, "return_type", "i64"))
        params_str = " ".join(
            f"(param ${p} {_wty(ssa_func.param_types.get(p, 'i64'))})"
            for p in ssa_func.params
        )
        wat_lines = [
            f'  (func ${ssa_func.name} (export "{ssa_func.name}") {params_str} (result {fn_ret_wty})',
        ]

        local_types: Dict[str, str] = {}
        var_locals: set = set()
        phi_tmps: set = set()
        for block in ssa_func.blocks:
            for phi in block.phi_nodes:
                if phi.result:
                    wty = _wty(phi.result.var_type)
                    v_n = f"var_{phi.result.name}_{phi.result.version}"
                    p_n = f"ptmp_{phi.result.name}_{phi.result.version}"
                    var_locals.add(v_n)
                    phi_tmps.add(p_n)
                    local_types[v_n] = wty
                    local_types[p_n] = wty
            for inst in block.instructions:
                if inst.result and not (inst.result.version == 0 and inst.result.name in param_set and inst.opcode == "param"):
                    v_n = f"var_{inst.result.name}_{inst.result.version}"
                    var_locals.add(v_n)
                    local_types[v_n] = _wty(inst.result.var_type)

        is_multiblock = len(ssa_func.blocks) > 1
        has_alloca = any(
            ins.opcode.lower() == "alloca"
            for b in ssa_func.blocks
            for ins in b.instructions
        )
        uses_printf = any(
            ins.opcode.lower() == "call" and ins.operands and str(ins.operands[0]) == "printf"
            for b in ssa_func.blocks
            for ins in b.instructions
        )
        if is_multiblock:
            wat_lines.append("    (local $__bb i32)")
        if has_alloca:
            wat_lines.append("    (local $__sp_save i32)")
        if uses_printf:
            wat_lines.append("    (local $__pbuf i32)")
        for l_name in sorted(var_locals | phi_tmps):
            wat_lines.append(f"    (local ${l_name} {local_types.get(l_name, 'i64')})")
        if has_alloca:
            wat_lines.append("    global.get $__omni_sp")
            wat_lines.append("    local.set $__sp_save")

        def emit_operand(op: Any) -> str:
            if isinstance(op, SSAVar):
                if op.version == 0 and op.name in param_set:
                    return f"local.get ${op.name}"
                return f"local.get $var_{op.name}_{op.version}"
            if isinstance(op, float):
                return f"f64.const {repr(op)}"
            if isinstance(op, bool):
                return f"i64.const {int(op)}"
            if isinstance(op, int):
                return f"i64.const {op}"
            s = str(op).strip()
            if s.startswith("%"):
                v = s.lstrip("%")
                if v.endswith("_0") and v[:-2] in param_set:
                    return f"local.get ${v[:-2]}"
                return f"local.get $var_{v}"
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return f"i64.const {s}"
            return f"local.get ${s}"

        def set_result(res_var: Optional[SSAVar], indent: str) -> None:
            if res_var is not None:
                wat_lines.append(f"{indent}local.set $var_{res_var.name}_{res_var.version}")

        block_index_map = {b.name: idx for idx, b in enumerate(ssa_func.blocks)}
        block_by_name = {b.name: b for b in ssa_func.blocks}

        def emit_phi_edge(pred_name: str, succ_name: str, indent: str):
            succ_bb = block_by_name.get(succ_name)
            if not succ_bb or not succ_bb.phi_nodes:
                return
            # Two-phase parallel copy via $ptmp_* prevents Lost-Copy swap clobbering!
            staged = []
            for phi in succ_bb.phi_nodes:
                if phi.result is None:
                    continue
                chosen = None
                for bn, val in phi.phi_incoming:
                    if bn == pred_name:
                        chosen = val
                        break
                if chosen is None and phi.operands:
                    chosen = phi.operands[0]
                if chosen is None:
                    chosen = 0.0 if phi.result.var_type == "f64" else 0
                tmp_l = f"ptmp_{phi.result.name}_{phi.result.version}"
                dst_l = f"var_{phi.result.name}_{phi.result.version}"
                wat_lines.append(f"{indent}{emit_operand(chosen)}")
                wat_lines.append(f"{indent}local.set ${tmp_l}")
                staged.append((tmp_l, dst_l))
            for tmp_l, dst_l in staged:
                wat_lines.append(f"{indent}local.get ${tmp_l}")
                wat_lines.append(f"{indent}local.set ${dst_l}")

        _WASM_SIMD_64B_OPS = {
            "add": "i64x2.add",
            "sub": "i64x2.sub",
            "mul": "i64x2.mul",
            "imul": "i64x2.mul",
            "and": "v128.and",
            "or": "v128.or",
            "xor": "v128.xor",
            "fadd": "f64x2.add",
            "fsub": "f64x2.sub",
            "fmul": "f64x2.mul",
            "fdiv": "f64x2.div",
        }
        _WASM_SIMD_32B_OPS = {
            "add": "i32x4.add",
            "sub": "i32x4.sub",
            "mul": "i32x4.mul",
            "imul": "i32x4.mul",
            "and": "v128.and",
            "or": "v128.or",
            "xor": "v128.xor",
            "fadd": "f32x4.add",
            "fsub": "f32x4.sub",
            "fmul": "f32x4.mul",
            "fdiv": "f32x4.div",
        }

        fn_add_const = analyze_ssa_constant_offsets(ssa_func)

        def emit_inst_sequence(block, indent: str):
            blk_def_map: Dict[SSAVar, Any] = {
                b_ins.result: b_ins
                for b_ins in block.instructions
                if isinstance(b_ins.result, SSAVar)
            }

            def _are_contiguous_8b_offsets(off0: Any, off1: Any) -> bool:
                return is_contiguous_stride(fn_add_const, [off0, off1], 8)

            def _are_contiguous_4b_quad(off0: Any, off1: Any, off2: Any, off3: Any) -> bool:
                return is_contiguous_stride(fn_add_const, [off0, off1, off2, off3], 4)

            inst_idx = 0
            while inst_idx < len(block.instructions):
                inst = block.instructions[inst_idx]
                inst_idx += 1
                opcode = inst.opcode.lower()
                if opcode == "param":
                    if inst.result and not (inst.result.version == 0 and inst.result.name in param_set):
                        wat_lines.append(f"{indent}local.get ${inst.operands[0]}")
                        set_result(inst.result, indent)
                elif opcode in ("const", "fconst", "mov"):
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    set_result(inst.result, indent)
                elif opcode == "neg":
                    wat_lines.append(f"{indent}i64.const 0")
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    wat_lines.append(f"{indent}i64.sub")
                    set_result(inst.result, indent)
                elif opcode == "fneg":
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    wat_lines.append(f"{indent}f64.neg")
                    set_result(inst.result, indent)
                elif opcode == "sitofp":
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    wat_lines.append(f"{indent}f64.convert_i64_s")
                    set_result(inst.result, indent)
                elif opcode == "fptosi":
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    wat_lines.append(f"{indent}i64.trunc_f64_s")
                    set_result(inst.result, indent)
                elif opcode == "not":
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    wat_lines.append(f"{indent}i64.eqz")
                    wat_lines.append(f"{indent}i64.extend_i32_u")
                    set_result(inst.result, indent)
                elif opcode == "alloca":
                    sz_op = inst.operands[0] if inst.operands else 64
                    wat_lines.append(f"{indent}global.get $__omni_sp")
                    wat_lines.append(f"{indent}i64.extend_i32_u")
                    set_result(inst.result, indent)
                    wat_lines.append(f"{indent}global.get $__omni_sp")
                    wat_lines.append(f"{indent}{emit_operand(sz_op)}")
                    wat_lines.append(f"{indent}i32.wrap_i64")
                    wat_lines.append(f"{indent}i32.const 15")
                    wat_lines.append(f"{indent}i32.add")
                    wat_lines.append(f"{indent}i32.const -16")
                    wat_lines.append(f"{indent}i32.and")
                    wat_lines.append(f"{indent}i32.add")
                    wat_lines.append(f"{indent}global.set $__omni_sp")
                elif opcode in self.WASM_BINOP_MAP:
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[1])}")
                    wat_lines.append(f"{indent}{self.WASM_BINOP_MAP[opcode]}")
                    set_result(inst.result, indent)
                elif opcode in self.WASM_FLOAT_BINOP_MAP:
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[1])}")
                    wat_lines.append(f"{indent}{self.WASM_FLOAT_BINOP_MAP[opcode]}")
                    set_result(inst.result, indent)
                elif opcode in self.WASM_CMP_MAP:
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[1])}")
                    wat_lines.append(f"{indent}{self.WASM_CMP_MAP[opcode]}")
                    wat_lines.append(f"{indent}i64.extend_i32_u")
                    set_result(inst.result, indent)
                elif opcode in self.WASM_FLOAT_CMP_MAP:
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[1])}")
                    wat_lines.append(f"{indent}{self.WASM_FLOAT_CMP_MAP[opcode]}")
                    wat_lines.append(f"{indent}i64.extend_i32_u")
                    set_result(inst.result, indent)
                elif opcode == "select":
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[1])}")  # true_val
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[2])}")  # false_val
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")  # cond
                    wat_lines.append(f"{indent}i64.const 0")
                    wat_lines.append(f"{indent}i64.ne")
                    wat_lines.append(f"{indent}select")
                    set_result(inst.result, indent)
                elif opcode == "load":
                    base_op = inst.operands[0] if len(inst.operands) > 0 else 0
                    idx_op = inst.operands[1] if len(inst.operands) > 1 else 0
                    ld_op = "f64.load" if (inst.result is not None and inst.result.var_type == "f64") else "i64.load"
                    wat_lines.append(f"{indent}{emit_operand(base_op)}")
                    wat_lines.append(f"{indent}{emit_operand(idx_op)}")
                    wat_lines.append(f"{indent}i64.const 3")
                    wat_lines.append(f"{indent}i64.shl")
                    wat_lines.append(f"{indent}i64.add")
                    wat_lines.append(f"{indent}i32.wrap_i64")
                    wat_lines.append(f"{indent}{ld_op}")
                    set_result(inst.result, indent)
                elif opcode == "store":
                    base_op = inst.operands[0] if len(inst.operands) > 0 else 0
                    idx_op = inst.operands[1] if len(inst.operands) > 1 else 0
                    val_op = inst.operands[2] if len(inst.operands) > 2 else 0
                    st_op = (
                        "f64.store"
                        if (isinstance(val_op, float) or (isinstance(val_op, SSAVar) and val_op.var_type == "f64"))
                        else "i64.store"
                    )
                    wat_lines.append(f"{indent}{emit_operand(base_op)}")
                    wat_lines.append(f"{indent}{emit_operand(idx_op)}")
                    wat_lines.append(f"{indent}i64.const 3")
                    wat_lines.append(f"{indent}i64.shl")
                    wat_lines.append(f"{indent}i64.add")
                    wat_lines.append(f"{indent}i32.wrap_i64")
                    wat_lines.append(f"{indent}{emit_operand(val_op)}")
                    wat_lines.append(f"{indent}{st_op}")
                elif opcode == "load_off":
                    base_op = inst.operands[0] if len(inst.operands) > 0 else 0
                    off_op = inst.operands[1] if len(inst.operands) > 1 else 0
                    width = str(inst.operands[2]) if len(inst.operands) >= 3 else "i64"
                    wat_lines.append(f"{indent}{emit_operand(base_op)}")
                    wat_lines.append(f"{indent}{emit_operand(off_op)}")
                    wat_lines.append(f"{indent}i64.add")
                    wat_lines.append(f"{indent}i32.wrap_i64")
                    _wasm_load_map = {
                        "i8": "i64.load8_s", "u8": "i64.load8_u",
                        "i16": "i64.load16_s", "u16": "i64.load16_u",
                        "i32": "i64.load32_s", "u32": "i64.load32_u",
                    }
                    if width in _wasm_load_map:
                        wat_lines.append(f"{indent}{_wasm_load_map[width]}")
                    elif width == "f32":
                        wat_lines.append(f"{indent}f32.load")
                        wat_lines.append(f"{indent}f64.promote_f32")
                    elif width == "f64":
                        wat_lines.append(f"{indent}f64.load")
                    else:
                        wat_lines.append(f"{indent}i64.load")
                    set_result(inst.result, indent)
                elif opcode == "store_off":
                    base_op = inst.operands[0] if len(inst.operands) > 0 else 0
                    off_op = inst.operands[1] if len(inst.operands) > 1 else 0
                    val_op = inst.operands[2] if len(inst.operands) > 2 else 0
                    width = str(inst.operands[3]) if len(inst.operands) >= 4 else "i64"
                    if width in ("i64", "u64", "f64") and inst_idx < len(block.instructions):
                        nxt_st = block.instructions[inst_idx]
                        nxt_w = str(nxt_st.operands[3]) if (nxt_st.opcode.lower() == "store_off" and len(nxt_st.operands) >= 4) else ""
                        if (
                            nxt_st.opcode.lower() == "store_off"
                            and nxt_w == width
                            and nxt_st.operands[0] == base_op
                            and _are_contiguous_8b_offsets(off_op, nxt_st.operands[1])
                        ):
                            val0, val1 = val_op, nxt_st.operands[2]
                            ins0 = blk_def_map.get(val0) if isinstance(val0, SSAVar) else None
                            ins1 = blk_def_map.get(val1) if isinstance(val1, SSAVar) else None
                            wat_lines.append(f"{indent}{emit_operand(base_op)}")
                            wat_lines.append(f"{indent}{emit_operand(off_op)}")
                            wat_lines.append(f"{indent}i64.add")
                            wat_lines.append(f"{indent}i32.wrap_i64")
                            emitted_simd = False
                            if (
                                ins0 is not None and ins1 is not None
                                and ins0.opcode.lower() == ins1.opcode.lower()
                                and ins0.opcode.lower() in _WASM_SIMD_64B_OPS
                                and len(ins0.operands) == 2 and len(ins1.operands) == 2
                            ):
                                op_2x = ins0.opcode.lower()
                                is_f_op = op_2x.startswith("f")
                                if (width == "f64" and is_f_op) or (width in ("i64", "u64") and not is_f_op):
                                    ld_a0 = blk_def_map.get(ins0.operands[0]) if isinstance(ins0.operands[0], SSAVar) else None
                                    ld_a1 = blk_def_map.get(ins1.operands[0]) if isinstance(ins1.operands[0], SSAVar) else None
                                    ld_b0 = blk_def_map.get(ins0.operands[1]) if isinstance(ins0.operands[1], SSAVar) else None
                                    ld_b1 = blk_def_map.get(ins1.operands[1]) if isinstance(ins1.operands[1], SSAVar) else None
                                    if (
                                        ld_a0 is not None and ld_a1 is not None and ld_b0 is not None and ld_b1 is not None
                                        and ld_a0.opcode.lower() == "load_off" and ld_a1.opcode.lower() == "load_off"
                                        and ld_b0.opcode.lower() == "load_off" and ld_b1.opcode.lower() == "load_off"
                                        and str(ld_a0.operands[2]) == width == str(ld_a1.operands[2])
                                        and str(ld_b0.operands[2]) == width == str(ld_b1.operands[2])
                                        and ld_a0.operands[0] == ld_a1.operands[0]
                                        and ld_b0.operands[0] == ld_b1.operands[0]
                                        and _are_contiguous_8b_offsets(ld_a0.operands[1], ld_a1.operands[1])
                                        and _are_contiguous_8b_offsets(ld_b0.operands[1], ld_b1.operands[1])
                                    ):
                                        wat_lines.append(f"{indent}{emit_operand(ld_a0.operands[0])}")
                                        wat_lines.append(f"{indent}{emit_operand(ld_a0.operands[1])}")
                                        wat_lines.append(f"{indent}i64.add")
                                        wat_lines.append(f"{indent}i32.wrap_i64")
                                        wat_lines.append(f"{indent}v128.load")
                                        wat_lines.append(f"{indent}{emit_operand(ld_b0.operands[0])}")
                                        wat_lines.append(f"{indent}{emit_operand(ld_b0.operands[1])}")
                                        wat_lines.append(f"{indent}i64.add")
                                        wat_lines.append(f"{indent}i32.wrap_i64")
                                        wat_lines.append(f"{indent}v128.load")
                                        wat_lines.append(f"{indent}{_WASM_SIMD_64B_OPS[op_2x]}")
                                        wat_lines.append(f"{indent}v128.store")
                                        emitted_simd = True
                            if not emitted_simd:
                                pfx_2x = "f64x2" if (width == "f64" or (isinstance(val0, SSAVar) and val0.var_type == "f64") or isinstance(val0, float)) else "i64x2"
                                wat_lines.append(f"{indent}{emit_operand(val0)}")
                                wat_lines.append(f"{indent}{pfx_2x}.splat")
                                wat_lines.append(f"{indent}{emit_operand(val1)}")
                                wat_lines.append(f"{indent}{pfx_2x}.replace_lane 1")
                                wat_lines.append(f"{indent}v128.store")
                            inst_idx += 1
                            continue

                    if width in ("i32", "u32", "f32") and inst_idx + 2 < len(block.instructions):
                        st1 = block.instructions[inst_idx]
                        st2 = block.instructions[inst_idx + 1]
                        st3 = block.instructions[inst_idx + 2]
                        if (
                            st1.opcode.lower() == "store_off" and len(st1.operands) >= 4 and str(st1.operands[3]) == width
                            and st2.opcode.lower() == "store_off" and len(st2.operands) >= 4 and str(st2.operands[3]) == width
                            and st3.opcode.lower() == "store_off" and len(st3.operands) >= 4 and str(st3.operands[3]) == width
                            and st1.operands[0] == base_op == st2.operands[0] == st3.operands[0]
                            and _are_contiguous_4b_quad(off_op, st1.operands[1], st2.operands[1], st3.operands[1])
                        ):
                            vals_q = [val_op, st1.operands[2], st2.operands[2], st3.operands[2]]
                            inss_q = [blk_def_map.get(v) if isinstance(v, SSAVar) else None for v in vals_q]
                            wat_lines.append(f"{indent}{emit_operand(base_op)}")
                            wat_lines.append(f"{indent}{emit_operand(off_op)}")
                            wat_lines.append(f"{indent}i64.add")
                            wat_lines.append(f"{indent}i32.wrap_i64")
                            emitted_4x = False
                            if all(
                                x is not None
                                and x.opcode.lower() == inss_q[0].opcode.lower()
                                and x.opcode.lower() in _WASM_SIMD_32B_OPS
                                and len(x.operands) == 2
                                for x in inss_q
                            ):
                                op_4x = inss_q[0].opcode.lower()
                                is_f32_op = op_4x.startswith("f")
                                if (width == "f32" and is_f32_op) or (width in ("i32", "u32") and not is_f32_op):
                                    lds_a = [blk_def_map.get(x.operands[0]) if isinstance(x.operands[0], SSAVar) else None for x in inss_q]
                                    lds_b = [blk_def_map.get(x.operands[1]) if isinstance(x.operands[1], SSAVar) else None for x in inss_q]
                                    if (
                                        all(la is not None and la.opcode.lower() == "load_off" and str(la.operands[2]) == width and la.operands[0] == lds_a[0].operands[0] for la in lds_a)
                                        and all(lb is not None and lb.opcode.lower() == "load_off" and str(lb.operands[2]) == width and lb.operands[0] == lds_b[0].operands[0] for lb in lds_b)
                                        and _are_contiguous_4b_quad(lds_a[0].operands[1], lds_a[1].operands[1], lds_a[2].operands[1], lds_a[3].operands[1])
                                        and _are_contiguous_4b_quad(lds_b[0].operands[1], lds_b[1].operands[1], lds_b[2].operands[1], lds_b[3].operands[1])
                                    ):
                                        wat_lines.append(f"{indent}{emit_operand(lds_a[0].operands[0])}")
                                        wat_lines.append(f"{indent}{emit_operand(lds_a[0].operands[1])}")
                                        wat_lines.append(f"{indent}i64.add")
                                        wat_lines.append(f"{indent}i32.wrap_i64")
                                        wat_lines.append(f"{indent}v128.load")
                                        wat_lines.append(f"{indent}{emit_operand(lds_b[0].operands[0])}")
                                        wat_lines.append(f"{indent}{emit_operand(lds_b[0].operands[1])}")
                                        wat_lines.append(f"{indent}i64.add")
                                        wat_lines.append(f"{indent}i32.wrap_i64")
                                        wat_lines.append(f"{indent}v128.load")
                                        wat_lines.append(f"{indent}{_WASM_SIMD_32B_OPS[op_4x]}")
                                        wat_lines.append(f"{indent}v128.store")
                                        emitted_4x = True
                            if not emitted_4x:
                                if width == "f32":
                                    wat_lines.append(f"{indent}{emit_operand(vals_q[0])}")
                                    wat_lines.append(f"{indent}f32.demote_f64")
                                    wat_lines.append(f"{indent}f32x4.splat")
                                    for ln_i in range(1, 4):
                                        wat_lines.append(f"{indent}{emit_operand(vals_q[ln_i])}")
                                        wat_lines.append(f"{indent}f32.demote_f64")
                                        wat_lines.append(f"{indent}f32x4.replace_lane {ln_i}")
                                else:
                                    wat_lines.append(f"{indent}{emit_operand(vals_q[0])}")
                                    wat_lines.append(f"{indent}i32.wrap_i64")
                                    wat_lines.append(f"{indent}i32x4.splat")
                                    for ln_i in range(1, 4):
                                        wat_lines.append(f"{indent}{emit_operand(vals_q[ln_i])}")
                                        wat_lines.append(f"{indent}i32.wrap_i64")
                                        wat_lines.append(f"{indent}i32x4.replace_lane {ln_i}")
                                wat_lines.append(f"{indent}v128.store")
                            inst_idx += 3
                            continue

                    wat_lines.append(f"{indent}{emit_operand(base_op)}")
                    wat_lines.append(f"{indent}{emit_operand(off_op)}")
                    wat_lines.append(f"{indent}i64.add")
                    wat_lines.append(f"{indent}i32.wrap_i64")
                    wat_lines.append(f"{indent}{emit_operand(val_op)}")
                    _wasm_store_map = {
                        "i8": "i64.store8", "u8": "i64.store8",
                        "i16": "i64.store16", "u16": "i64.store16",
                        "i32": "i64.store32", "u32": "i64.store32",
                    }
                    if width in _wasm_store_map:
                        wat_lines.append(f"{indent}{_wasm_store_map[width]}")
                    elif width == "f32":
                        wat_lines.append(f"{indent}f32.demote_f64")
                        wat_lines.append(f"{indent}f32.store")
                    elif width == "f64":
                        wat_lines.append(f"{indent}f64.store")
                    else:
                        wat_lines.append(f"{indent}i64.store")
                elif opcode == "lut_load":
                    lut_name = str(inst.operands[0])
                    width = str(inst.operands[1])
                    idx_op = inst.operands[2]
                    base_ro, _w, stride = (lut_addr_map or {}).get((ssa_func.name, lut_name), (245760, width, 8))
                    _, ld_instr = self._WASM_LUT_STRIDE.get(width, (8, "i64.load"))
                    wat_lines.append(f"{indent}i64.const {base_ro}")
                    wat_lines.append(f"{indent}{emit_operand(idx_op)}")
                    if stride != 1:
                        wat_lines.append(f"{indent}i64.const {stride}")
                        wat_lines.append(f"{indent}i64.mul")
                    wat_lines.append(f"{indent}i64.add")
                    wat_lines.append(f"{indent}i32.wrap_i64")
                    wat_lines.append(f"{indent}{ld_instr}")
                    if width == "f32":
                        wat_lines.append(f"{indent}f64.promote_f32")
                    set_result(inst.result, indent)
                elif opcode == "cstr_addr":
                    c_name = str(inst.operands[0])
                    base_ro, _w, _s = (lut_addr_map or {}).get((ssa_func.name, f"__cstr_{c_name}"), (245760, "u8", 1))
                    wat_lines.append(f"{indent}i64.const {base_ro}")
                    set_result(inst.result, indent)
                elif opcode == "call":
                    callee = str(inst.operands[0])
                    if callee == "printf":
                        fmt_op = inst.operands[1] if len(inst.operands) > 1 else 0
                        varargs = list(inst.operands[2:])
                        nargs = len(varargs)
                        if nargs > 0:
                            buf_bytes = ((nargs * 8) + 15) & ~15
                            wat_lines.append(f"{indent}global.get $__omni_sp")
                            wat_lines.append(f"{indent}local.tee $__pbuf")
                            wat_lines.append(f"{indent}i32.const {buf_bytes}")
                            wat_lines.append(f"{indent}i32.add")
                            wat_lines.append(f"{indent}global.set $__omni_sp")
                            tmask = 0
                            for idx_v, vop in enumerate(varargs):
                                is_fp_v = isinstance(vop, float) or (isinstance(vop, SSAVar) and vop.var_type == "f64")
                                if is_fp_v:
                                    tmask |= (1 << idx_v)
                                wat_lines.append(f"{indent}local.get $__pbuf")
                                if idx_v > 0:
                                    wat_lines.append(f"{indent}i32.const {idx_v * 8}")
                                    wat_lines.append(f"{indent}i32.add")
                                wat_lines.append(f"{indent}{emit_operand(vop)}")
                                wat_lines.append(f"{indent}{'f64.store' if is_fp_v else 'i64.store'}")
                            wat_lines.append(f"{indent}{emit_operand(fmt_op)}")
                            wat_lines.append(f"{indent}local.get $__pbuf")
                            wat_lines.append(f"{indent}i64.extend_i32_u")
                            wat_lines.append(f"{indent}i64.const {nargs}")
                            wat_lines.append(f"{indent}i64.const {tmask}")
                            wat_lines.append(f"{indent}call $__omni_printf_host")
                            wat_lines.append(f"{indent}local.get $__pbuf")
                            wat_lines.append(f"{indent}global.set $__omni_sp")
                        else:
                            wat_lines.append(f"{indent}{emit_operand(fmt_op)}")
                            wat_lines.append(f"{indent}i64.const 0")
                            wat_lines.append(f"{indent}i64.const 0")
                            wat_lines.append(f"{indent}i64.const 0")
                            wat_lines.append(f"{indent}call $__omni_printf_host")
                        if inst.result is not None:
                            set_result(inst.result, indent)
                        else:
                            wat_lines.append(f"{indent}drop")
                    elif callee == "puts":
                        s_op = inst.operands[1] if len(inst.operands) > 1 else 0
                        wat_lines.append(f"{indent}{emit_operand(s_op)}")
                        wat_lines.append(f"{indent}call $__omni_puts_host")
                        if inst.result is not None:
                            set_result(inst.result, indent)
                        else:
                            wat_lines.append(f"{indent}drop")
                    elif callee == "putchar":
                        c_op = inst.operands[1] if len(inst.operands) > 1 else 0
                        wat_lines.append(f"{indent}{emit_operand(c_op)}")
                        wat_lines.append(f"{indent}call $__omni_putchar_host")
                        if inst.result is not None:
                            set_result(inst.result, indent)
                        else:
                            wat_lines.append(f"{indent}drop")
                    else:
                        for a in inst.operands[1:]:
                            wat_lines.append(f"{indent}{emit_operand(a)}")
                        wat_lines.append(f"{indent}call ${callee}")
                        if inst.result is not None:
                            set_result(inst.result, indent)
                        else:
                            wat_lines.append(f"{indent}drop")
                elif opcode == "br":
                    succ_n = str(inst.operands[0])
                    emit_phi_edge(block.name, succ_n, indent)
                    wat_lines.append(f"{indent}i32.const {block_index_map[succ_n]}")
                    wat_lines.append(f"{indent}local.set $__bb")
                    wat_lines.append(f"{indent}br $cfg_dispatch")
                elif opcode == "br_cond":
                    cond_op, t_n, f_n = inst.operands[0], str(inst.operands[1]), str(inst.operands[2])
                    wat_lines.append(f"{indent}{emit_operand(cond_op)}")
                    wat_lines.append(f"{indent}i64.const 0")
                    wat_lines.append(f"{indent}i64.ne")
                    wat_lines.append(f"{indent}(if")
                    wat_lines.append(f"{indent}  (then")
                    emit_phi_edge(block.name, t_n, indent + "    ")
                    wat_lines.append(f"{indent}    i32.const {block_index_map[t_n]}")
                    wat_lines.append(f"{indent}    local.set $__bb")
                    wat_lines.append(f"{indent}    br $cfg_dispatch")
                    wat_lines.append(f"{indent}  )")
                    wat_lines.append(f"{indent}  (else")
                    emit_phi_edge(block.name, f_n, indent + "    ")
                    wat_lines.append(f"{indent}    i32.const {block_index_map[f_n]}")
                    wat_lines.append(f"{indent}    local.set $__bb")
                    wat_lines.append(f"{indent}    br $cfg_dispatch")
                    wat_lines.append(f"{indent}  )")
                    wat_lines.append(f"{indent})")
                elif opcode == "ret":
                    if has_alloca:
                        wat_lines.append(f"{indent}local.get $__sp_save")
                        wat_lines.append(f"{indent}global.set $__omni_sp")
                    if inst.operands:
                        wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    else:
                        wat_lines.append(f"{indent}{'f64.const 0.0' if fn_ret_wty == 'f64' else 'i64.const 0'}")
                    wat_lines.append(f"{indent}return")

        if not is_multiblock:
            if ssa_func.blocks:
                emit_inst_sequence(ssa_func.blocks[0], "    ")
            if not any("return" in ln for ln in wat_lines):
                if has_alloca:
                    wat_lines.append("    local.get $__sp_save")
                    wat_lines.append("    global.set $__omni_sp")
                if var_locals:
                    wat_lines.append(f"    local.get ${sorted(var_locals)[-1]}")
                else:
                    wat_lines.append(f"    {'f64.const 0.0' if fn_ret_wty == 'f64' else 'i64.const 0'}")
        else:
            wat_lines.append("    i32.const 0")
            wat_lines.append("    local.set $__bb")
            wat_lines.append("    (loop $cfg_dispatch")
            for b_idx, block in enumerate(ssa_func.blocks):
                wat_lines.append(f"      local.get $__bb")
                wat_lines.append(f"      i32.const {b_idx}")
                wat_lines.append(f"      i32.eq")
                wat_lines.append(f"      (if")
                wat_lines.append(f"        (then")
                emit_inst_sequence(block, "          ")
                wat_lines.append(f"        )")
                wat_lines.append(f"      )")
            wat_lines.append("    )")
            if has_alloca:
                wat_lines.append("    local.get $__sp_save")
                wat_lines.append("    global.set $__omni_sp")
            wat_lines.append(f"    {'f64.const 0.0' if fn_ret_wty == 'f64' else 'i64.const 0'}")

        wat_lines.append("  )")
        return "\n".join(wat_lines)

    @staticmethod
    def inspect_optimization_stats(wat_text: str) -> Dict[str, Any]:
        """Counts WebAssembly 128-bit SIMD (`v128` / `i64x2` / `i32x4` / `f64x2` / `f32x4`) instructions in WAT."""
        simd_hits = re.findall(r"\b((?:v128|i64x2|i32x4|f64x2|f32x4)\.[a-z0-9_]+)\b", wat_text)
        return {
            "simd_instruction_count": len(simd_hits),
            "v128_instruction_count": len(simd_hits),
            "sample_simd_mnemonics": sorted(set(simd_hits))[:16],
            "wat_bytes": len(wat_text.encode("utf-8")),
        }

    def run_ssa_with_memory(
        self,
        ssa_funcs: List[SSAFunction],
        entry_name: str,
        args: Optional[List[Any]] = None,
        memory_regions: Optional[Dict[int, bytes]] = None,
        fuel_budget: Optional[int] = None,
    ) -> Tuple[Any, Dict[int, bytes], Dict[str, Any]]:
        """
        Compiles `ssa_funcs` into WebAssembly (with 128-bit `v128` SIMD where eligible),
        populates isolated linear-memory guest buffers matching virtual pointer args,
        executes `entry_name` in Wasmtime, and returns `(return_value, memory_snapshots, simd_stats)`.
        """
        if not self.is_available:
            raise RuntimeError("Wasmtime engine is not available.")

        args = list(args or [])
        mem_regions = dict(memory_regions or {})
        entry_fn = next((f for f in ssa_funcs if f.name == entry_name), None)
        if entry_fn is None:
            raise ValueError(f"Entry function '{entry_name}' not found in ssa_funcs.")

        wat_text = self.ssa_module_to_wat(ssa_funcs) if len(ssa_funcs) > 1 else self.ssa_to_wat(entry_fn)
        stats = self.inspect_optimization_stats(wat_text)

        if fuel_budget is not None and self._fuel_engine is not None:
            eng = self._fuel_engine
            store = Store(eng)
            store.set_fuel(fuel_budget)
        else:
            eng = self._engine
            store = Store(eng)

        module = Module(eng, wat_text)
        instance, stdout_chunks = self._instantiate_with_host_libc(store, module)
        exports = instance.exports(store)
        if entry_name not in exports:
            raise ValueError(f"Exported function '{entry_name}' not found in compiled WASM module.")
        memory = exports["memory"]

        ordered_addrs = sorted(mem_regions.keys())
        total_padded = sum((max(len(mem_regions[a]), 1) + 15) & ~15 for a in ordered_addrs)
        # Keep guest buffers < 192 KiB safely disjoint from $alloca (196608) & .rodata (245760).
        cursor = 4096 if total_padded <= 180224 else 327680
        guest_addrs: Dict[int, int] = {}
        for addr in ordered_addrs:
            guest_addrs[addr] = cursor
            cursor += (max(len(mem_regions[addr]), 1) + 15) & ~15

        current_bytes = memory.data_len(store)
        if cursor > current_bytes:
            extra_pages = (cursor - current_bytes + 65535) // 65536
            memory.grow(store, extra_pages)

        if "__omni_heap_ptr" in exports:
            heap_global = exports["__omni_heap_ptr"]
            safe_heap = max(int(heap_global.value(store)), (cursor + 4095) & ~4095)
            cur_len = memory.data_len(store)
            if safe_heap > cur_len:
                extra_hp_pages = (safe_heap - cur_len + 65535) // 65536
                memory.grow(store, extra_hp_pages)
            heap_global.set_value(store, safe_heap)

        for addr in ordered_addrs:
            raw = mem_regions[addr]
            if raw:
                memory.write(store, raw, guest_addrs[addr])

        wasm_args: List[Any] = []
        for idx_a, val in enumerate(args):
            p_name = entry_fn.params[idx_a] if idx_a < len(entry_fn.params) else ""
            p_ty = entry_fn.param_types.get(p_name, "i64")
            if p_ty in ("f64", "f32", "float", "double") or isinstance(val, float):
                wasm_args.append(float(val))
            else:
                iv = int(val)
                if iv in guest_addrs:
                    wasm_args.append(guest_addrs[iv])
                else:
                    u = iv & 0xFFFFFFFFFFFFFFFF
                    wasm_args.append(u - 0x10000000000000000 if (u & 0x8000000000000000) else u)

        raw_ret = exports[entry_name](store, *wasm_args)
        if fuel_budget is not None and self._fuel_engine is not None:
            stats["fuel_consumed"] = fuel_budget - store.get_fuel()
        if stdout_chunks:
            stats["captured_stdout"] = "".join(stdout_chunks)

        ret_is_fp = getattr(entry_fn, "return_type", "i64") in ("f64", "f32", "float", "double")
        if ret_is_fp:
            ret_val: Any = float(raw_ret)
        else:
            u = int(raw_ret) & 0xFFFFFFFFFFFFFFFF
            ret_val = u - 0x10000000000000000 if (u & 0x8000000000000000) else u

        snaps = {
            addr: bytes(memory.read(store, guest_addrs[addr], guest_addrs[addr] + len(mem_regions[addr])))
            for addr in ordered_addrs
        }
        return ret_val, snaps, stats

    def ssa_to_wat(self, ssa_func: SSAFunction) -> str:
        """
        Lowers single-block AND arbitrary multi-block `SSAFunction` CFGs (loops, branches,
        Phi nodes, recursion) into structured WebAssembly Text (WAT) with Linear Memory.
        """
        return self.ssa_module_to_wat([ssa_func])

    @classmethod
    def _emit_wat_libc_runtime(cls, needed_libc: set) -> List[str]:
        """Emits pure-WAT synthesized heap/memory/string/math libc functions referenced by SSA."""
        funcs: List[str] = []
        uses_heap = bool(needed_libc & cls._WASM_HEAP_LIBC)
        if uses_heap or "malloc" in needed_libc or "realloc" in needed_libc or "calloc" in needed_libc:
            funcs.append("""  (func $malloc (param $size i64) (result i64)
    (local $req i32)
    (local $hdr i32)
    (local $user i32)
    (local $new_end i32)
    (local $cur_bytes i32)
    (local $extra_pages i32)
    (local.set $req (i32.wrap_i64 (local.get $size)))
    (if (i32.lt_s (local.get $req) (i32.const 8))
      (then (local.set $req (i32.const 8)))
    )
    (local.set $req (i32.and (i32.add (local.get $req) (i32.const 15)) (i32.const -16)))
    (local.set $hdr (i32.and (i32.add (global.get $__omni_heap_ptr) (i32.const 15)) (i32.const -16)))
    (local.set $user (i32.add (local.get $hdr) (i32.const 16)))
    (local.set $new_end (i32.add (local.get $user) (local.get $req)))
    (local.set $cur_bytes (i32.shl (memory.size) (i32.const 16)))
    (if (i32.gt_u (local.get $new_end) (local.get $cur_bytes))
      (then
        (local.set $extra_pages
          (i32.div_u
            (i32.add (i32.sub (local.get $new_end) (local.get $cur_bytes)) (i32.const 65535))
            (i32.const 65536)
          )
        )
        (if (i32.eq (memory.grow (local.get $extra_pages)) (i32.const -1))
          (then (return (i64.const 0)))
        )
      )
    )
    (i64.store (local.get $hdr) (i64.extend_i32_u (local.get $req)))
    (i64.store (i32.add (local.get $hdr) (i32.const 8)) (i64.const 1330466377))
    (global.set $__omni_heap_ptr (local.get $new_end))
    (i64.extend_i32_u (local.get $user))
  )""")
        if uses_heap or "free" in needed_libc or "realloc" in needed_libc:
            funcs.append("""  (func $free (param $ptr i64) (result i64)
    (local $p32 i32)
    (local $hdr i32)
    (local $sz i32)
    (if (i64.ne (local.get $ptr) (i64.const 0))
      (then
        (local.set $p32 (i32.wrap_i64 (local.get $ptr)))
        (if (i32.ge_u (local.get $p32) (i32.const 16))
          (then
            (local.set $hdr (i32.sub (local.get $p32) (i32.const 16)))
            (if (i64.eq (i64.load (i32.add (local.get $hdr) (i32.const 8))) (i64.const 1330466377))
              (then
                (local.set $sz (i32.wrap_i64 (i64.load (local.get $hdr))))
                (i64.store (i32.add (local.get $hdr) (i32.const 8)) (i64.const 0))
                (if (i32.eq (i32.add (local.get $p32) (local.get $sz)) (global.get $__omni_heap_ptr))
                  (then (global.set $__omni_heap_ptr (local.get $hdr)))
                )
              )
            )
          )
        )
      )
    )
    (i64.const 0)
  )""")
        if "calloc" in needed_libc:
            funcs.append("""  (func $calloc (param $nmemb i64) (param $size i64) (result i64)
    (local $total i64)
    (local $ptr i64)
    (local $p32 i32)
    (local $n32 i32)
    (local $i i32)
    (local.set $total (i64.mul (local.get $nmemb) (local.get $size)))
    (local.set $ptr (call $malloc (local.get $total)))
    (if (i64.ne (local.get $ptr) (i64.const 0))
      (then
        (local.set $p32 (i32.wrap_i64 (local.get $ptr)))
        (local.set $n32 (i32.wrap_i64 (local.get $total)))
        (local.set $i (i32.const 0))
        (block $cz_done
          (loop $cz_loop
            (br_if $cz_done (i32.ge_u (local.get $i) (local.get $n32)))
            (i32.store8 (i32.add (local.get $p32) (local.get $i)) (i32.const 0))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br $cz_loop)
          )
        )
      )
    )
    (local.get $ptr)
  )""")
        if "realloc" in needed_libc:
            funcs.append("""  (func $realloc (param $ptr i64) (param $new_size i64) (result i64)
    (local $new_ptr i64)
    (local $old_p32 i32)
    (local $new_p32 i32)
    (local $old_sz i32)
    (local $req_sz i32)
    (local $copy_n i32)
    (local $i i32)
    (if (i64.eq (local.get $ptr) (i64.const 0))
      (then (return (call $malloc (local.get $new_size))))
    )
    (if (i64.le_s (local.get $new_size) (i64.const 0))
      (then
        (drop (call $free (local.get $ptr)))
        (return (i64.const 0))
      )
    )
    (local.set $old_p32 (i32.wrap_i64 (local.get $ptr)))
    (local.set $old_sz (i32.wrap_i64 (i64.load (i32.sub (local.get $old_p32) (i32.const 16)))))
    (local.set $new_ptr (call $malloc (local.get $new_size)))
    (if (i64.eq (local.get $new_ptr) (i64.const 0))
      (then (return (i64.const 0)))
    )
    (local.set $new_p32 (i32.wrap_i64 (local.get $new_ptr)))
    (local.set $req_sz (i32.wrap_i64 (local.get $new_size)))
    (local.set $copy_n (select (local.get $old_sz) (local.get $req_sz) (i32.lt_u (local.get $old_sz) (local.get $req_sz))))
    (local.set $i (i32.const 0))
    (block $rc_done
      (loop $rc_loop
        (br_if $rc_done (i32.ge_u (local.get $i) (local.get $copy_n)))
        (i32.store8 (i32.add (local.get $new_p32) (local.get $i)) (i32.load8_u (i32.add (local.get $old_p32) (local.get $i))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $rc_loop)
      )
    )
    (drop (call $free (local.get $ptr)))
    (local.get $new_ptr)
  )""")
        if "memcpy" in needed_libc:
            funcs.append("""  (func $memcpy (param $dst i64) (param $src i64) (param $n i64) (result i64)
    (local $d32 i32)
    (local $s32 i32)
    (local $n32 i32)
    (local $i i32)
    (local.set $d32 (i32.wrap_i64 (local.get $dst)))
    (local.set $s32 (i32.wrap_i64 (local.get $src)))
    (local.set $n32 (i32.wrap_i64 (local.get $n)))
    (local.set $i (i32.const 0))
    (block $mc_done
      (loop $mc_loop
        (br_if $mc_done (i32.ge_u (local.get $i) (local.get $n32)))
        (i32.store8 (i32.add (local.get $d32) (local.get $i)) (i32.load8_u (i32.add (local.get $s32) (local.get $i))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $mc_loop)
      )
    )
    (local.get $dst)
  )""")
        if "memmove" in needed_libc:
            funcs.append("""  (func $memmove (param $dst i64) (param $src i64) (param $n i64) (result i64)
    (local $d32 i32)
    (local $s32 i32)
    (local $n32 i32)
    (local $i i32)
    (local.set $d32 (i32.wrap_i64 (local.get $dst)))
    (local.set $s32 (i32.wrap_i64 (local.get $src)))
    (local.set $n32 (i32.wrap_i64 (local.get $n)))
    (if (i32.le_u (local.get $d32) (local.get $s32))
      (then
        (local.set $i (i32.const 0))
        (block $mf_done
          (loop $mf_loop
            (br_if $mf_done (i32.ge_u (local.get $i) (local.get $n32)))
            (i32.store8 (i32.add (local.get $d32) (local.get $i)) (i32.load8_u (i32.add (local.get $s32) (local.get $i))))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br $mf_loop)
          )
        )
      )
      (else
        (local.set $i (local.get $n32))
        (block $mb_done
          (loop $mb_loop
            (br_if $mb_done (i32.le_s (local.get $i) (i32.const 0)))
            (local.set $i (i32.sub (local.get $i) (i32.const 1)))
            (i32.store8 (i32.add (local.get $d32) (local.get $i)) (i32.load8_u (i32.add (local.get $s32) (local.get $i))))
            (br $mb_loop)
          )
        )
      )
    )
    (local.get $dst)
  )""")
        if "memset" in needed_libc:
            funcs.append("""  (func $memset (param $dst i64) (param $ch i64) (param $n i64) (result i64)
    (local $d32 i32)
    (local $c32 i32)
    (local $n32 i32)
    (local $i i32)
    (local.set $d32 (i32.wrap_i64 (local.get $dst)))
    (local.set $c32 (i32.and (i32.wrap_i64 (local.get $ch)) (i32.const 255)))
    (local.set $n32 (i32.wrap_i64 (local.get $n)))
    (local.set $i (i32.const 0))
    (block $ms_done
      (loop $ms_loop
        (br_if $ms_done (i32.ge_u (local.get $i) (local.get $n32)))
        (i32.store8 (i32.add (local.get $d32) (local.get $i)) (local.get $c32))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $ms_loop)
      )
    )
    (local.get $dst)
  )""")
        if "strlen" in needed_libc:
            funcs.append("""  (func $strlen (param $s i64) (result i64)
    (local $p32 i32)
    (local $n i32)
    (local.set $p32 (i32.wrap_i64 (local.get $s)))
    (local.set $n (i32.const 0))
    (block $sl_done
      (loop $sl_loop
        (br_if $sl_done (i32.eqz (i32.load8_u (i32.add (local.get $p32) (local.get $n)))))
        (local.set $n (i32.add (local.get $n) (i32.const 1)))
        (br $sl_loop)
      )
    )
    (i64.extend_i32_u (local.get $n))
  )""")
        if "strcmp" in needed_libc:
            funcs.append("""  (func $strcmp (param $a i64) (param $b i64) (result i64)
    (local $a32 i32)
    (local $b32 i32)
    (local $i i32)
    (local $ca i32)
    (local $cb i32)
    (local.set $a32 (i32.wrap_i64 (local.get $a)))
    (local.set $b32 (i32.wrap_i64 (local.get $b)))
    (local.set $i (i32.const 0))
    (block $sc_done
      (loop $sc_loop
        (local.set $ca (i32.load8_u (i32.add (local.get $a32) (local.get $i))))
        (local.set $cb (i32.load8_u (i32.add (local.get $b32) (local.get $i))))
        (br_if $sc_done (i32.or (i32.ne (local.get $ca) (local.get $cb)) (i32.eqz (local.get $ca))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $sc_loop)
      )
    )
    (i64.extend_i32_s (i32.sub (local.get $ca) (local.get $cb)))
  )""")
        if "abs" in needed_libc:
            funcs.append("""  (func $abs (param $x i64) (result i64)
    (if (result i64) (i64.lt_s (local.get $x) (i64.const 0))
      (then (i64.sub (i64.const 0) (local.get $x)))
      (else (local.get $x))
    )
  )""")
        if "labs" in needed_libc:
            funcs.append("""  (func $labs (param $x i64) (result i64)
    (if (result i64) (i64.lt_s (local.get $x) (i64.const 0))
      (then (i64.sub (i64.const 0) (local.get $x)))
      (else (local.get $x))
    )
  )""")
        return funcs

    def ssa_module_to_wat(self, ssa_funcs: List[SSAFunction]) -> str:
        """Lowers multiple `SSAFunction`s into a unified multi-export WAT module."""
        lut_map, data_lines, ro_end = self._build_wat_rodata_with_bounds(ssa_funcs)
        defined_names = {fn.name for fn in ssa_funcs}
        external_callees = {
            str(ins.operands[0])
            for fn in ssa_funcs
            for b in fn.blocks
            for ins in b.instructions
            if ins.opcode.lower() == "call" and ins.operands and str(ins.operands[0]) not in defined_names
        }
        needed_libc = external_callees & self._WASM_ALL_LIBC
        has_alloca = any(
            ins.opcode.lower() == "alloca"
            for fn in ssa_funcs
            for b in fn.blocks
            for ins in b.instructions
        )
        uses_heap = bool(needed_libc & self._WASM_HEAP_LIBC)
        uses_sp = has_alloca or ("printf" in needed_libc)

        heap_start = max(524288, (ro_end + 65535) & ~65535)
        ro_pages = max(2, (ro_end + 65535) // 65536) if data_lines else 2
        pages = max(4 if (data_lines or uses_sp) else 2, ro_pages)
        if uses_heap:
            pages = max(pages, (heap_start + 65535) // 65536 + 1)

        parts = ["(module"]
        if "printf" in needed_libc:
            parts.append('  (import "env" "__omni_printf_host" (func $__omni_printf_host (param i64 i64 i64 i64) (result i64)))')
        if "puts" in needed_libc:
            parts.append('  (import "env" "__omni_puts_host" (func $__omni_puts_host (param i64) (result i64)))')
        if "putchar" in needed_libc:
            parts.append('  (import "env" "__omni_putchar_host" (func $__omni_putchar_host (param i64) (result i64)))')
        parts.append(f'  (memory (export "memory") {pages})')
        if uses_sp:
            parts.append("  (global $__omni_sp (mut i32) (i32.const 196608))")
        if uses_heap:
            parts.append(f'  (global $__omni_heap_ptr (export "__omni_heap_ptr") (mut i32) (i32.const {heap_start}))')
        parts.extend(data_lines)
        parts.extend(self._emit_wat_libc_runtime(needed_libc))
        for fn in ssa_funcs:
            parts.append(self._ssa_function_to_wat_func(fn, lut_addr_map=lut_map))
        parts.append(")")
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # WASI Preview 2 / Component Model Canonical ABI Bridge (`cabi_realloc`)
    # ------------------------------------------------------------------
    def build_canonical_abi_module_wat(self) -> str:
        """
        Emits a WASI Preview 2 Component Model Canonical ABI compliant WASM module exporting:
          - `memory`: Linear memory (2 pages = 128 KB)
          - `cabi_realloc(old_ptr, old_size, align, new_size) -> ptr`: Canonical bump allocator
          - `fnv1a64_utf8(ptr: i32, len: i32) -> i64`: Guest UTF-8 string 64-bit FNV-1a hash
          - `transform_uppercase(ptr: i32, len: i32) -> i32`: Guest UTF-8 string transform returning retptr `(out_ptr, out_len)`
          - `sum_list_s64(ptr: i32, len: i32) -> i64`: Guest `list<s64>` Canonical ABI slice reduction
        """
        return """
(module
  (memory (export "memory") 2)
  (global $heap_ptr (mut i32) (i32.const 1024))

  (func $cabi_realloc (export "cabi_realloc")
    (param $old_ptr i32) (param $old_size i32) (param $align i32) (param $new_size i32)
    (result i32)
    (local $aligned i32)
    ;; Align $heap_ptr up to $align
    (local.set $aligned
      (i32.and
        (i32.add (global.get $heap_ptr) (i32.sub (local.get $align) (i32.const 1)))
        (i32.xor (i32.sub (local.get $align) (i32.const 1)) (i32.const -1))
      )
    )
    (global.set $heap_ptr (i32.add (local.get $aligned) (local.get $new_size)))
    (local.get $aligned)
  )

  (func (export "fnv1a64_utf8") (param $ptr i32) (param $len i32) (result i64)
    (local $i i32)
    (local $hash i64)
    (local.set $hash (i64.const -3750763034362895579)) ;; 0xcbf29ce484222325
    (local.set $i (i32.const 0))
    (block $done
      (loop $loop
        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
        (local.set $hash
          (i64.mul
            (i64.xor
              (local.get $hash)
              (i64.load8_u (i32.add (local.get $ptr) (local.get $i)))
            )
            (i64.const 1099511628211) ;; 0x100000001b3
          )
        )
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)
      )
    )
    (local.get $hash)
  )

  (func (export "transform_uppercase") (param $ptr i32) (param $len i32) (result i32)
    (local $out_ptr i32)
    (local $ret_area i32)
    (local $i i32)
    (local $ch i32)
    (local.set $out_ptr (call $cabi_realloc (i32.const 0) (i32.const 0) (i32.const 1) (local.get $len)))
    (local.set $i (i32.const 0))
    (block $done
      (loop $loop
        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
        (local.set $ch (i32.load8_u (i32.add (local.get $ptr) (local.get $i))))
        (if (i32.and (i32.ge_u (local.get $ch) (i32.const 97)) (i32.le_u (local.get $ch) (i32.const 122)))
          (then (local.set $ch (i32.sub (local.get $ch) (i32.const 32))))
        )
        (i32.store8 (i32.add (local.get $out_ptr) (local.get $i)) (local.get $ch))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)
      )
    )
    ;; Canonical ABI return area: 8-byte aligned (ptr: i32, len: i32)
    (local.set $ret_area (call $cabi_realloc (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 8)))
    (i32.store (local.get $ret_area) (local.get $out_ptr))
    (i32.store (i32.add (local.get $ret_area) (i32.const 4)) (local.get $len))
    (local.get $ret_area)
  )

  (func (export "sum_list_s64") (param $ptr i32) (param $len i32) (result i64)
    (local $i i32)
    (local $acc i64)
    (local.set $acc (i64.const 0))
    (local.set $i (i32.const 0))
    (block $done
      (loop $loop
        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
        (local.set $acc
          (i64.add
            (local.get $acc)
            (i64.load (i32.add (local.get $ptr) (i32.shl (local.get $i) (i32.const 3))))
          )
        )
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)
      )
    )
    (local.get $acc)
  )
)
"""

    def execute_canonical_string_call(self, text: str, operation: str = "uppercase") -> Union[str, int]:
        """
        Marshals a Python UTF-8 `str` into guest WASM Linear Memory via Component Model
        `cabi_realloc`, executes `transform_uppercase` or `fnv1a64_utf8`, and unmarshals the guest output.
        """
        if not self.is_available:
            raise RuntimeError("Wasmtime engine is not available.")
        wat = self.build_canonical_abi_module_wat()
        store = Store(self._engine)
        module = Module(self._engine, wat)
        instance = Instance(store, module, [])
        exports = instance.exports(store)
        memory = exports["memory"]
        realloc = exports["cabi_realloc"]

        utf8_bytes = text.encode("utf-8")
        guest_ptr = realloc(store, 0, 0, 1, len(utf8_bytes))
        memory.write(store, utf8_bytes, guest_ptr)

        if operation == "fnv1a64":
            raw_i64 = exports["fnv1a64_utf8"](store, guest_ptr, len(utf8_bytes))
            return raw_i64 & 0xFFFFFFFFFFFFFFFF

        ret_area = exports["transform_uppercase"](store, guest_ptr, len(utf8_bytes))
        hdr = memory.read(store, ret_area, ret_area + 8)
        out_ptr, out_len = struct.unpack("<II", bytes(hdr))
        out_bytes = bytes(memory.read(store, out_ptr, out_ptr + out_len))
        return out_bytes.decode("utf-8")

    def execute_canonical_s64_list_sum(self, values: List[int]) -> int:
        """
        Marshals a `list<s64>` slice into guest WASM Linear Memory (8-byte aligned via `cabi_realloc`)
        and executes `sum_list_s64`.
        """
        if not self.is_available:
            raise RuntimeError("Wasmtime engine is not available.")
        wat = self.build_canonical_abi_module_wat()
        store = Store(self._engine)
        module = Module(self._engine, wat)
        instance = Instance(store, module, [])
        exports = instance.exports(store)
        memory = exports["memory"]
        realloc = exports["cabi_realloc"]

        byte_len = len(values) * 8
        guest_ptr = realloc(store, 0, 0, 8, max(8, byte_len))
        if values:
            packed = struct.pack(f"<{len(values)}q", *values)
            memory.write(store, packed, guest_ptr)
        return int(exports["sum_list_s64"](store, guest_ptr, len(values)))
