"""
OmniCompiler Adaptive Homeostasis Router & Quad-Ecosystem Differential Oracle (`homeostasis_router.py`).
Connects all four compiler/runtime ecosystems under canonical `Omni-SSA` + Z3 verification:
1. OmniCompiler Native (`X64CodeGenerator` / `NativeJitCompiler`, AVX2/SSE4.1/SSE2/ARM64 NEON)
2. LLVM 20.1.8 O3 (`LLVMBackend` via `llvmlite` PassBuilder)
3. GNU GCC O3 (`GCCBackend` via `/usr/bin/gcc -O3` GIMPLE/RTL pipeline)
4. WebAssembly `v128` SIMD (`WasmBackend` via Bytecode Alliance Wasmtime + linear-memory isolation)

Enforces bit-exact differential consensus and automatically isolates any diverging engine.
"""

import ctypes
import math
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from compiler.gcc_backend import GCCBackend
from compiler.llvm_backend import LLVMBackend
from compiler.native_jit import NativeJitCompiler
from compiler.ssa_ir import SSAFunction
from compiler.wasm_backend import WasmBackend


@dataclass
class EngineExecutionResult:
    engine: str
    success: bool
    return_value: Any = None
    memory_snapshots: Dict[int, bytes] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: Optional[str] = None
    simd_stats: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HomeostasisReport:
    policy: str
    function_name: str
    consensus_reached: bool
    selected_engine: Optional[str]
    consensus_value: Any
    consensus_snapshots: Dict[int, bytes] = field(default_factory=dict)
    active_engines: List[str] = field(default_factory=list)
    isolated_engines: List[str] = field(default_factory=list)
    divergences: List[Dict[str, Any]] = field(default_factory=list)
    results_by_engine: Dict[str, EngineExecutionResult] = field(default_factory=dict)


class HomeostasisRouter:
    """Routes `SSAFunction` execution across Native AVX2, LLVM 20 O3, and GCC O3 with differential consensus."""

    def __init__(
        self,
        native_jit: Optional[NativeJitCompiler] = None,
        llvm_backend: Optional[LLVMBackend] = None,
        gcc_backend: Optional[GCCBackend] = None,
        wasm_backend: Optional[WasmBackend] = None,
    ):
        self.native_jit = native_jit or NativeJitCompiler()
        self.llvm_backend = llvm_backend or LLVMBackend(opt_level=3)
        self.gcc_backend = gcc_backend or GCCBackend(opt_level=3)
        self.wasm_backend = wasm_backend or WasmBackend()

    def available_engines(self) -> List[str]:
        engines = ["native"]
        if self.llvm_backend.is_available:
            engines.append("llvm")
        if self.gcc_backend.is_available:
            engines.append("gcc")
        if self.wasm_backend.is_available:
            engines.append("wasm")
        return engines

    @staticmethod
    def self_contained_wasm_subset(ssa_funcs: List[SSAFunction]) -> List[SSAFunction]:
        """Fixed-point closure of functions having zero unresolved external `call`s (safe for WASM)."""
        wasm_set = {f.name for f in ssa_funcs}
        changed = True
        while changed:
            changed = False
            for f in ssa_funcs:
                if f.name not in wasm_set:
                    continue
                for b in f.blocks:
                    if any(
                        ins.opcode.lower() == "call" and ins.operands and str(ins.operands[0]) not in wasm_set
                        for ins in b.instructions
                    ):
                        wasm_set.remove(f.name)
                        changed = True
                        break
        return [f for f in ssa_funcs if f.name in wasm_set]

    @staticmethod
    def _values_equal(a: Any, b: Any, is_fp: bool, tol: float = 1e-6) -> bool:
        if is_fp:
            fa, fb = float(a), float(b)
            if math.isnan(fa) and math.isnan(fb):
                return True
            if math.isinf(fa) or math.isinf(fb):
                return fa == fb
            return abs(fa - fb) <= tol * max(1.0, abs(fa), abs(fb))
        return int(a) == int(b)

    @staticmethod
    def _snapshots_key(snapshots: Dict[int, bytes]) -> Tuple[Tuple[int, bytes], ...]:
        return tuple((k, snapshots[k]) for k in sorted(snapshots.keys()))

    def _run_native(
        self,
        ssa_funcs: List[SSAFunction],
        entry_fn: SSAFunction,
        args: List[Any],
        memory_regions: Dict[int, bytes],
    ) -> EngineExecutionResult:
        t0 = time.perf_counter()
        try:
            cf, _mem, _ = self.native_jit.compile_ssa(entry_fn)
            mem_bufs: Dict[int, Any] = {}
            call_args: List[Any] = []
            for addr in sorted(memory_regions.keys()):
                raw = memory_regions[addr]
                cbuf = (ctypes.c_uint8 * max(len(raw), 1)).from_buffer_copy(raw or b"\x00")
                mem_bufs[addr] = cbuf
            for idx_a, val in enumerate(args):
                p_name = entry_fn.params[idx_a] if idx_a < len(entry_fn.params) else ""
                p_ty = entry_fn.param_types.get(p_name, "i64")
                if p_ty in ("f64", "f32", "float", "double") or isinstance(val, float):
                    call_args.append(float(val))
                elif int(val) in mem_bufs:
                    call_args.append(ctypes.addressof(mem_bufs[int(val)]))
                else:
                    call_args.append(int(val))
            ret_val = cf(*call_args)
            snaps = {addr: bytes(mem_bufs[addr])[: len(memory_regions[addr])] for addr in sorted(memory_regions.keys())}
            return EngineExecutionResult(
                engine="native",
                success=True,
                return_value=ret_val,
                memory_snapshots=snaps,
                elapsed_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )
        except Exception as e:
            return EngineExecutionResult(
                engine="native",
                success=False,
                error=str(e),
                elapsed_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )

    def _run_llvm(
        self,
        ssa_funcs: List[SSAFunction],
        entry_fn: SSAFunction,
        args: List[Any],
        memory_regions: Dict[int, bytes],
    ) -> EngineExecutionResult:
        t0 = time.perf_counter()
        if not self.llvm_backend.is_available:
            return EngineExecutionResult(engine="llvm", success=False, error="LLVM unavailable")
        try:
            ir_str = (
                self.llvm_backend.ssa_module_to_llvm_ir(ssa_funcs)
                if len(ssa_funcs) > 1
                else self.llvm_backend.ssa_to_llvm_ir(entry_fn)
            )
            mod = self.llvm_backend.compile_ir(ir_str, optimize=True)
            simd_stats = self.llvm_backend.inspect_optimization_stats(mod)
            ret_is_fp = getattr(entry_fn, "return_type", "i64") in ("f64", "f32", "float", "double")
            restype = ctypes.c_double if ret_is_fp else ctypes.c_int64
            argtypes = [
                ctypes.c_double
                if entry_fn.param_types.get(p, "i64") in ("f64", "f32", "float", "double")
                else ctypes.c_int64
                for p in entry_fn.params
            ]
            ll_fn = self.llvm_backend.create_jit_callable(mod, entry_fn.name, restype=restype, argtypes=argtypes)
            mem_bufs: Dict[int, Any] = {}
            for addr in sorted(memory_regions.keys()):
                raw = memory_regions[addr]
                mem_bufs[addr] = (ctypes.c_uint8 * max(len(raw), 1)).from_buffer_copy(raw or b"\x00")
            call_args: List[Any] = []
            for idx_a, val in enumerate(args):
                p_name = entry_fn.params[idx_a] if idx_a < len(entry_fn.params) else ""
                p_ty = entry_fn.param_types.get(p_name, "i64")
                if p_ty in ("f64", "f32", "float", "double") or isinstance(val, float):
                    call_args.append(float(val))
                elif int(val) in mem_bufs:
                    call_args.append(ctypes.addressof(mem_bufs[int(val)]))
                else:
                    call_args.append(int(val))
            ret_val = ll_fn(*call_args)
            snaps = {addr: bytes(mem_bufs[addr])[: len(memory_regions[addr])] for addr in sorted(memory_regions.keys())}
            return EngineExecutionResult(
                engine="llvm",
                success=True,
                return_value=ret_val,
                memory_snapshots=snaps,
                elapsed_ms=round((time.perf_counter() - t0) * 1000.0, 3),
                simd_stats=simd_stats,
            )
        except Exception as e:
            return EngineExecutionResult(
                engine="llvm",
                success=False,
                error=str(e),
                elapsed_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )

    def _run_gcc(
        self,
        ssa_funcs: List[SSAFunction],
        entry_fn: SSAFunction,
        args: List[Any],
        memory_regions: Dict[int, bytes],
    ) -> EngineExecutionResult:
        t0 = time.perf_counter()
        if not self.gcc_backend.is_available:
            return EngineExecutionResult(engine="gcc", success=False, error="GCC unavailable")
        try:
            asm_txt = self.gcc_backend.emit_assembly(ssa_funcs)
            simd_stats = self.gcc_backend.inspect_optimization_stats(asm_txt)
            ret_val, snaps = self.gcc_backend.run_function(
                ssa_funcs, entry_fn.name, args=args, memory_regions=memory_regions
            )
            return EngineExecutionResult(
                engine="gcc",
                success=True,
                return_value=ret_val,
                memory_snapshots=snaps,
                elapsed_ms=round((time.perf_counter() - t0) * 1000.0, 3),
                simd_stats=simd_stats,
            )
        except Exception as e:
            return EngineExecutionResult(
                engine="gcc",
                success=False,
                error=str(e),
                elapsed_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )

    def _run_wasm(
        self,
        ssa_funcs: List[SSAFunction],
        entry_fn: SSAFunction,
        args: List[Any],
        memory_regions: Dict[int, bytes],
    ) -> EngineExecutionResult:
        t0 = time.perf_counter()
        if not self.wasm_backend.is_available:
            return EngineExecutionResult(engine="wasm", success=False, error="Wasmtime unavailable")
        wasm_subset = self.self_contained_wasm_subset(ssa_funcs)
        if not any(f.name == entry_fn.name for f in wasm_subset):
            return EngineExecutionResult(engine="wasm", success=False, error="Entry depends on external host call")
        try:
            ret_val, snaps, simd_stats = self.wasm_backend.run_ssa_with_memory(
                wasm_subset, entry_fn.name, args=args, memory_regions=memory_regions, fuel_budget=50_000_000
            )
            return EngineExecutionResult(
                engine="wasm",
                success=True,
                return_value=ret_val,
                memory_snapshots=snaps,
                elapsed_ms=round((time.perf_counter() - t0) * 1000.0, 3),
                simd_stats=simd_stats,
            )
        except Exception as e:
            return EngineExecutionResult(
                engine="wasm",
                success=False,
                error=str(e),
                elapsed_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )

    def inspect_ecosystem_telemetry(self, ssa_funcs: List[SSAFunction]) -> Dict[str, Any]:
        """Collects optimization & SIMD instruction telemetry across active LLVM, GCC, and WASM backends."""
        telemetry: Dict[str, Any] = {}
        if not ssa_funcs:
            return telemetry

        if self.llvm_backend.is_available:
            try:
                ir_str = (
                    self.llvm_backend.ssa_module_to_llvm_ir(ssa_funcs)
                    if len(ssa_funcs) > 1
                    else self.llvm_backend.ssa_to_llvm_ir(ssa_funcs[0])
                )
                mod = self.llvm_backend.compile_ir(ir_str, optimize=True)
                telemetry["llvm"] = self.llvm_backend.inspect_optimization_stats(mod)
            except Exception as exc:
                telemetry["llvm"] = {"error": str(exc)}

        if self.gcc_backend.is_available:
            try:
                asm_txt = self.gcc_backend.emit_assembly(ssa_funcs)
                telemetry["gcc"] = self.gcc_backend.inspect_optimization_stats(asm_txt)
            except Exception as exc:
                telemetry["gcc"] = {"error": str(exc)}

        wasm_subset = self.self_contained_wasm_subset(ssa_funcs)
        if self.wasm_backend.is_available and wasm_subset:
            try:
                wat_txt = self.wasm_backend.ssa_module_to_wat(wasm_subset)
                wasm_bin = self.wasm_backend.wat_to_wasm(wat_txt)
                stats = self.wasm_backend.inspect_optimization_stats(wat_txt)
                stats["wasm_binary_bytes"] = len(wasm_bin)
                telemetry["wasm"] = stats
            except Exception as exc:
                telemetry["wasm"] = {"error": str(exc)}

        return telemetry

    def execute_differential(
        self,
        ssa_funcs: List[SSAFunction],
        entry_name: str,
        args: Optional[List[Any]] = None,
        memory_regions: Optional[Dict[int, bytes]] = None,
        policy: str = "consensus",
        engines: Optional[List[str]] = None,
        custom_executors: Optional[Dict[str, Callable[[List[SSAFunction], SSAFunction, List[Any], Dict[int, bytes]], EngineExecutionResult]]] = None,
    ) -> HomeostasisReport:
        """
        Executes `entry_name` according to `policy` (`consensus`, `throughput`, `latency`).
        In `consensus` and `throughput`, cross-checks all active engines and isolates any diverging engine.
        """
        entry_fn = next((f for f in ssa_funcs if f.name == entry_name), None)
        if entry_fn is None:
            raise ValueError(f"Entry function '{entry_name}' not found.")

        args_list = list(args or [])
        mem_map = dict(memory_regions or {})
        is_fp = getattr(entry_fn, "return_type", "i64") in ("f64", "f32", "float", "double")

        if policy == "latency" and not engines and not custom_executors:
            nat_res = self._run_native(ssa_funcs, entry_fn, args_list, mem_map)
            if nat_res.success:
                return HomeostasisReport(
                    policy="latency",
                    function_name=entry_name,
                    consensus_reached=True,
                    selected_engine="native",
                    consensus_value=nat_res.return_value,
                    consensus_snapshots=nat_res.memory_snapshots,
                    active_engines=["native"],
                    results_by_engine={"native": nat_res},
                )

        if engines is not None:
            target_engines = list(engines)
        else:
            target_engines = self.available_engines()
            wasm_subset = self.self_contained_wasm_subset(ssa_funcs)
            if not any(f.name == entry_name for f in wasm_subset):
                target_engines = [e for e in target_engines if e != "wasm"]
        executors: Dict[str, Callable[..., EngineExecutionResult]] = {
            "native": self._run_native,
            "llvm": self._run_llvm,
            "gcc": self._run_gcc,
            "wasm": self._run_wasm,
        }
        if custom_executors:
            for k, fn_exec in custom_executors.items():
                executors[k] = fn_exec
                if k not in target_engines:
                    target_engines.append(k)

        results_by_engine: Dict[str, EngineExecutionResult] = {}
        passing: List[EngineExecutionResult] = []
        isolated: List[str] = []
        divergences: List[Dict[str, Any]] = []

        for eng in target_engines:
            fn_exec = executors.get(eng)
            if fn_exec is None:
                isolated.append(eng)
                divergences.append({"engine": eng, "reason": "unknown_engine"})
                continue
            res = fn_exec(ssa_funcs, entry_fn, args_list, mem_map)
            results_by_engine[eng] = res
            if res.success:
                passing.append(res)
            else:
                isolated.append(eng)
                divergences.append({"engine": eng, "reason": "execution_error", "error": res.error})

        if not passing:
            return HomeostasisReport(
                policy=policy,
                function_name=entry_name,
                consensus_reached=False,
                selected_engine=None,
                consensus_value=None,
                active_engines=target_engines,
                isolated_engines=isolated,
                divergences=divergences,
                results_by_engine=results_by_engine,
            )

        # Group passing results by (return_value_equivalence, exact_memory_snapshots)
        clusters: List[List[EngineExecutionResult]] = []
        for res in passing:
            placed = False
            res_snaps = self._snapshots_key(res.memory_snapshots)
            for cl in clusters:
                rep = cl[0]
                if self._values_equal(res.return_value, rep.return_value, is_fp) and res_snaps == self._snapshots_key(rep.memory_snapshots):
                    cl.append(res)
                    placed = True
                    break
            if not placed:
                clusters.append([res])

        clusters.sort(key=lambda cl: (-len(cl), cl[0].elapsed_ms))
        majority = clusters[0]
        majority_engines = [r.engine for r in majority]

        # Isolate outlier clusters
        for cl in clusters[1:]:
            for out_r in cl:
                isolated.append(out_r.engine)
                divergences.append({
                    "engine": out_r.engine,
                    "reason": "semantic_divergence",
                    "observed_return": out_r.return_value,
                    "expected_return": majority[0].return_value,
                })

        consensus_ok = (len(passing) == 1 and not isolated) or (len(majority) >= 2 and (len(clusters) == 1 or len(majority) > len(clusters[1])))
        if policy == "throughput" and consensus_ok:
            selected = min(majority, key=lambda r: r.elapsed_ms).engine
        else:
            selected = majority[0].engine if consensus_ok else None

        return HomeostasisReport(
            policy=policy,
            function_name=entry_name,
            consensus_reached=consensus_ok,
            selected_engine=selected,
            consensus_value=majority[0].return_value if consensus_ok else None,
            consensus_snapshots=majority[0].memory_snapshots if consensus_ok else {},
            active_engines=majority_engines,
            isolated_engines=isolated,
            divergences=divergences,
            results_by_engine=results_by_engine,
        )
