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

from compiler.ssa_ir import SSAVar, SSAFunction

try:
    import wasmtime
    from wasmtime import Config, Engine, Store, Module, Instance
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
        """Compiles WebAssembly Text format (WAT) to binary bytecode (.wasm)."""
        if not self.is_available:
            raise RuntimeError("Wasmtime engine is not available on this system.")
        module = Module(self._engine, wat_text)
        return bytes(module.serialize())

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

        instance = Instance(store, module, [])
        exports = instance.exports(store)
        if func_name not in exports:
            raise ValueError(f"Exported function '{func_name}' not found in WASM module.")

        wasm_fn = exports[func_name]
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
        instance = Instance(store, module, [])
        exports = instance.exports(store)
        res = exports[func_name](store, *args)
        remaining = store.get_fuel()
        return {
            "result": res,
            "fuel_budget": fuel_budget,
            "fuel_remaining": remaining,
            "fuel_consumed": fuel_budget - remaining,
        }

    # ------------------------------------------------------------------
    # Multi-Block Omni-SSA -> Structured WAT Lowering
    # ------------------------------------------------------------------
    def ssa_to_wat(self, ssa_func: SSAFunction) -> str:
        """
        Lowers single-block AND arbitrary multi-block `SSAFunction` CFGs (loops, branches,
        Phi nodes, recursion) into structured WebAssembly Text (WAT) with Linear Memory.
        """
        param_set = set(ssa_func.params)
        params_str = " ".join(f"(param ${p} i64)" for p in ssa_func.params)
        wat_lines = [
            "(module",
            '  (memory (export "memory") 2)',
            f'  (func ${ssa_func.name} (export "{ssa_func.name}") {params_str} (result i64)',
        ]

        var_locals: set = set()
        phi_tmps: set = set()
        for block in ssa_func.blocks:
            for phi in block.phi_nodes:
                if phi.result:
                    v_n = f"var_{phi.result.name}_{phi.result.version}"
                    var_locals.add(v_n)
                    phi_tmps.add(f"ptmp_{phi.result.name}_{phi.result.version}")
            for inst in block.instructions:
                if inst.result and not (inst.result.version == 0 and inst.result.name in param_set and inst.opcode == "param"):
                    var_locals.add(f"var_{inst.result.name}_{inst.result.version}")

        is_multiblock = len(ssa_func.blocks) > 1
        if is_multiblock:
            wat_lines.append("    (local $__bb i32)")
        for l_name in sorted(var_locals | phi_tmps):
            wat_lines.append(f"    (local ${l_name} i64)")

        def emit_operand(op: Any) -> str:
            if isinstance(op, SSAVar):
                if op.version == 0 and op.name in param_set:
                    return f"local.get ${op.name}"
                return f"local.get $var_{op.name}_{op.version}"
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
                    chosen = 0
                tmp_l = f"ptmp_{phi.result.name}_{phi.result.version}"
                dst_l = f"var_{phi.result.name}_{phi.result.version}"
                wat_lines.append(f"{indent}{emit_operand(chosen)}")
                wat_lines.append(f"{indent}local.set ${tmp_l}")
                staged.append((tmp_l, dst_l))
            for tmp_l, dst_l in staged:
                wat_lines.append(f"{indent}local.get ${tmp_l}")
                wat_lines.append(f"{indent}local.set ${dst_l}")

        def emit_inst_sequence(block, indent: str):
            for inst in block.instructions:
                opcode = inst.opcode.lower()
                if opcode == "param":
                    if inst.result and not (inst.result.version == 0 and inst.result.name in param_set):
                        wat_lines.append(f"{indent}local.get ${inst.operands[0]}")
                        set_result(inst.result, indent)
                elif opcode in ("const", "mov"):
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    set_result(inst.result, indent)
                elif opcode in self.WASM_BINOP_MAP:
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[1])}")
                    wat_lines.append(f"{indent}{self.WASM_BINOP_MAP[opcode]}")
                    set_result(inst.result, indent)
                elif opcode in self.WASM_CMP_MAP:
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[1])}")
                    wat_lines.append(f"{indent}{self.WASM_CMP_MAP[opcode]}")
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
                elif opcode == "call":
                    callee = str(inst.operands[0])
                    for a in inst.operands[1:]:
                        wat_lines.append(f"{indent}{emit_operand(a)}")
                    wat_lines.append(f"{indent}call ${callee}")
                    set_result(inst.result, indent)
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
                    wat_lines.append(f"{indent}{emit_operand(inst.operands[0])}")
                    wat_lines.append(f"{indent}return")

        if not is_multiblock:
            if ssa_func.blocks:
                emit_inst_sequence(ssa_func.blocks[0], "    ")
            if not any("return" in ln for ln in wat_lines):
                if var_locals:
                    wat_lines.append(f"    local.get ${sorted(var_locals)[-1]}")
                else:
                    wat_lines.append("    i64.const 0")
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
            wat_lines.append("    i64.const 0")

        wat_lines.append("  )")
        wat_lines.append(")")
        return "\n".join(wat_lines)

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
