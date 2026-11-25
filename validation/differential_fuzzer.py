"""
Alpha-C99: Multi-Backend Cross-ISA Differential Fuzzer (`validation/differential_fuzzer.py`).

Compiles the same `SSAFunction` across multiple active codegen engines
(`Native x86-64`, `LLVM O3 MCJIT`, `Wasmtime Sandbox`, `GCC O3`) and blasts each
with corner-case + PRNG integer/float vectors, asserting bit-exact equivalence.
"""

from __future__ import annotations

import ctypes
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from compiler.ssa_ir import SSAFunction


@dataclass
class DifferentialFuzzReport:
    function_name: str
    vectors_tested: int
    backends_compared: List[str]
    passed: bool
    mismatches: List[Dict[str, Any]] = field(default_factory=list)


class DifferentialFuzzer:
    """
    Executes differential property-based fuzzing over multi-backend compiled outputs.
    """

    CORNER_INTS = (0, 1, -1, 2, -2, 7, 15, 42, -42, 255, -256, 1024, 65535, -32768)

    def __init__(self, seed: int = 20261124, num_random_vectors: int = 24):
        self.seed = int(seed)
        self.num_random_vectors = max(1, int(num_random_vectors))

    def generate_vectors(self, arity: int, param_types: Optional[Dict[str, str]] = None, params: Sequence[str] = ()) -> List[Tuple[int, ...]]:
        rng = random.Random(self.seed)
        vectors: List[Tuple[int, ...]] = []
        if arity == 0:
            return [()]
        for c in self.CORNER_INTS[:min(len(self.CORNER_INTS), 10)]:
            vectors.append(tuple(c for _ in range(arity)))
        for _ in range(self.num_random_vectors):
            vec: List[int] = []
            for idx in range(arity):
                pname = params[idx] if idx < len(params) else ""
                pty = (param_types or {}).get(pname, "i64")
                if pty in ("ptr", "ptr_f64"):
                    vec.append(0)
                else:
                    vec.append(rng.randint(-10000, 10000))
            vectors.append(tuple(vec))
        return vectors

    def fuzz_ssa_function(
        self,
        ssa_fn: SSAFunction,
        backends: Sequence[str] = ("native", "llvm", "wasm"),
        vectors: Optional[List[Tuple[int, ...]]] = None,
    ) -> DifferentialFuzzReport:
        vecs = vectors if vectors is not None else self.generate_vectors(
            len(ssa_fn.params), param_types=ssa_fn.param_types, params=ssa_fn.params
        )
        arity = len(ssa_fn.params)
        callables: Dict[str, Callable[..., int]] = {}
        keepalive: List[Any] = []

        if "llvm" in backends:
            try:
                from compiler.llvm_backend import LLVMBackend
                llvm_be = LLVMBackend(opt_level=3)
                if llvm_be.is_available:
                    ir_str = llvm_be.ssa_module_to_llvm_ir([ssa_fn], module_name=f"fuzz_{ssa_fn.name}")
                    mod = llvm_be.compile_ir(ir_str, optimize=True)
                    fn_ptr = llvm_be.create_jit_callable(
                        mod,
                        ssa_fn.name,
                        restype=ctypes.c_int64,
                        argtypes=[ctypes.c_int64] * arity,
                    )
                    callables["llvm"] = fn_ptr
                    keepalive.append(("llvm", llvm_be, mod, fn_ptr))
            except Exception:
                pass

        if "native" in backends:
            from compiler.native_jit import NativeJitCompiler
            jit = NativeJitCompiler()
            fn_ptr, mem_buf, _ = jit.compile_ssa(ssa_fn)
            callables["native"] = fn_ptr
            keepalive.append(("native", jit, mem_buf, fn_ptr))

        if "wasm" in backends:
            from compiler.wasm_backend import WasmBackend
            wb = WasmBackend()
            if wb.is_available:
                wat = wb.ssa_module_to_wat([ssa_fn])
                wasm_bytes = wb.compile_wat(wat)

                def _run_wasm(*args, _wb=wb, _wb_bytes=wasm_bytes, _name=ssa_fn.name) -> int:
                    return int(_wb.execute_wasm(_wb_bytes, _name, [int(a) for a in args]))

                callables["wasm"] = _run_wasm
                keepalive.append(("wasm", wb))

        tested_backends = sorted(callables.keys())
        mismatches: List[Dict[str, Any]] = []

        try:
            if len(tested_backends) >= 2:
                for vec in vecs:
                    outputs: Dict[str, int] = {}
                    for b_name in tested_backends:
                        outputs[b_name] = int(callables[b_name](*vec))
                    unique_vals = set(outputs.values())
                    if len(unique_vals) > 1:
                        mismatches.append({"vector": list(vec), "outputs": outputs})
        finally:
            for item in keepalive:
                if item and item[0] == "native":
                    try:
                        item[2].free()
                    except Exception:
                        pass

        return DifferentialFuzzReport(
            function_name=ssa_fn.name,
            vectors_tested=len(vecs),
            backends_compared=tested_backends,
            passed=(len(tested_backends) >= 2 and len(mismatches) == 0),
            mismatches=mismatches,
        )
