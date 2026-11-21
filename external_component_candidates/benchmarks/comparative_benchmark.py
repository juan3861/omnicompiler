"""
Comparative Benchmark Suite: Baseline vs. SOTA Integrations.
Measures throughput, latency, and memory footprint across:
1. Parsing: Tree-Sitter Polyglot vs. Regex
2. Execution: LLVM O3 JIT vs. Custom Machine Code vs. Wasmtime
3. Safety: Unicorn CPU Pre-Flight Emulation Overhead
4. Binary Audit: Formal pefile/pyelftools vs. Raw heuristic inspection
"""

import time
import ctypes
import json
import sys
import os
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from slicer.tree_sitter_polyglot import TreeSitterPolyglotEngine
from orchestrator.repo_manifest_ingestor import RepoManifestIngestor
from compiler.gcc_backend import GCCBackend
from compiler.homeostasis_router import HomeostasisRouter
from compiler.llvm_backend import LLVMBackend
from compiler.native_codegen import detect_host_simd_features
from compiler.native_jit import NativeJitCompiler
from compiler.ssa_ir import AstToSsaLowering
from compiler.wasm_backend import WasmBackend
from validation.silicon_safety_sandbox import SiliconSafetySandbox
from validation.binary_structure_auditor import BinaryStructureAuditor
from compiler.binary_emitter import StandaloneBinaryEmitter


def benchmark_parsing():
    c_header = b"""
    int64_t tensor_gemm(const double* a, const double* b, double* c, int64_t m, int64_t n, int64_t k);
    int64_t tensor_relu(double* x, int64_t size);
    int64_t tensor_softmax(double* x, int64_t size);
    void hardware_barrier();
    """ * 100

    ts_engine = TreeSitterPolyglotEngine()
    ingestor = RepoManifestIngestor()

    # 1. Tree-Sitter
    t0 = time.perf_counter()
    ts_symbols = ts_engine.parse_c_symbols(c_header, "test.h")
    dt_ts = time.perf_counter() - t0

    # 2. Regex
    t0 = time.perf_counter()
    import re
    proto_re = re.compile(r'^\s*(?:extern\s+)?([a-zA-Z0-9_]+(?:\s*\*+)?)\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*;', re.MULTILINE)
    text = c_header.decode("utf-8", errors="ignore")
    matches = list(proto_re.finditer(text))
    dt_regex = time.perf_counter() - t0

    return {
        "tree_sitter": {"time_sec": dt_ts, "symbols_extracted": len(ts_symbols)},
        "regex": {"time_sec": dt_regex, "symbols_extracted": len(matches)}
    }


def benchmark_execution():
    results = {}
    N = 100000

    # 1. LLVM O3 JIT
    llvm = LLVMBackend(opt_level=3)
    if llvm.is_available:
        ir = f"""
        target triple = "{llvm.target_triple}"
        define i64 @loop_calc(i64 %n) {{
        entry:
            br label %loop
        loop:
            %i = phi i64 [ 0, %entry ], [ %next_i, %loop ]
            %acc = phi i64 [ 0, %entry ], [ %next_acc, %loop ]
            %next_acc = add i64 %acc, %i
            %next_i = add i64 %i, 1
            %cond = icmp slt i64 %next_i, %n
            br i1 %cond, label %loop, label %exit
        exit:
            ret i64 %next_acc
        }}
        """
        mod = llvm.compile_ir(ir, optimize=True)
        fn = llvm.create_jit_callable(mod, "loop_calc", restype=ctypes.c_int64, argtypes=[ctypes.c_int64])
        t0 = time.perf_counter()
        val = fn(N)
        dt_llvm = time.perf_counter() - t0
        results["llvm_o3_jit"] = {"time_sec": dt_llvm, "result": val, "iterations": N}

    # 2. Wasmtime WASM
    wasm = WasmBackend()
    if wasm.is_available:
        wat = f"""
        (module
          (func (export "loop_calc") (param $n i64) (result i64)
            (local $i i64)
            (local $acc i64)
            (loop $loop
              local.get $acc
              local.get $i
              i64.add
              local.set $acc
              local.get $i
              i64.const 1
              i64.add
              local.set $i
              local.get $i
              local.get $n
              i64.lt_s
              br_if $loop
            )
            local.get $acc
          )
        )
        """
        t0 = time.perf_counter()
        wval = wasm.execute_wasm(wat, "loop_calc", args=[N])
        dt_wasm = time.perf_counter() - t0
        results["wasmtime_sandbox"] = {"time_sec": dt_wasm, "result": wval, "iterations": N}

    # 3. Omni Native x86-64 JIT
    try:
        jit = NativeJitCompiler()
        import ast
        src = "def loop_calc(n: int) -> int:\n    i = 0\n    acc = 0\n    while i < n:\n        acc += i\n        i += 1\n    return acc\n"
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        native_fn, mem, _ = jit.compile_ssa(ssa_fn)
        try:
            t0 = time.perf_counter()
            nval = native_fn(N)
            dt_nat = time.perf_counter() - t0
        finally:
            mem.free()
        results["omni_native_jit"] = {"time_sec": dt_nat, "result": nval, "iterations": N}
    except Exception as exc:
        results["omni_native_jit"] = {"error": str(exc)}

    # 4. GNU GCC O3 (when available)
    gcc = GCCBackend(opt_level=3)
    if gcc.is_available:
        import ast
        src = "def loop_calc(n: int) -> int:\n    i = 0\n    acc = 0\n    while i < n:\n        acc += i\n        i += 1\n    return acc\n"
        ssa_fn = AstToSsaLowering().lower_function_def(ast.parse(src).body[0])
        t0 = time.perf_counter()
        gval, _ = gcc.run_function([ssa_fn], "loop_calc", args=[N])
        dt_gcc = time.perf_counter() - t0
        results["gcc_o3"] = {"time_sec": dt_gcc, "result": gval, "iterations": N}

    return results


def benchmark_homeostasis_quad():
    import ast, struct
    feats = detect_host_simd_features()
    src_struct = """
class BenchF64:
    a: Array[f64, 64]
    b: Array[f64, 64]
    out: Array[f64, 64]

def quad_fma_bench(t: BenchF64, n: int) -> float:
    i = 0
    acc = 0.0
    while i < n:
        v = t.a[i] * t.b[i] + 1.25
        t.out[i] = v
        acc += v
        i += 1
    return acc
"""
    mod = ast.parse(src_struct)
    low = AstToSsaLowering()
    low.register_structs_from_statements(mod.body)
    fn_def = [n for n in mod.body if isinstance(n, ast.FunctionDef)][0]
    ssa_fn = low.lower_function_def(fn_def)
    arena = bytearray(64 * 8 * 3)
    for k in range(32):
        struct.pack_into("<d", arena, k * 8, float(k + 1) * 0.5)
        struct.pack_into("<d", arena, 64 * 8 + k * 8, float(k % 7 + 1) * 0.25)

    router = HomeostasisRouter()
    try:
        rep = router.execute_differential(
            [ssa_fn],
            "quad_fma_bench",
            args=[0x400000, 32],
            memory_regions={0x400000: bytes(arena)},
            policy="throughput",
        )
        return {
            "host_simd_tier": feats.get("recommended_tier"),
            "consensus_reached": rep.consensus_reached,
            "active_engines": rep.active_engines,
            "selected_engine": rep.selected_engine,
            "elapsed_ms_by_engine": {k: v.elapsed_ms for k, v in rep.results_by_engine.items() if v.success},
        }
    finally:
        router.close()


def benchmark_heterogeneous_hybrid():
    import tempfile
    from omni_repo_compiler import OmniRepoCompiler
    with tempfile.TemporaryDirectory() as td:
        r_a = Path(td) / "repo_a"
        r_b = Path(td) / "repo_b"
        r_a.mkdir()
        r_b.mkdir()
        (r_a / "omni_repo.json").write_text(
            json.dumps({"name": "repo_a", "language": "python", "exports": ["stage_native", "stage_mid"], "dependencies": []}),
            encoding="utf-8",
        )
        (r_a / "a.py").write_text(
            "def stage_native(x: int) -> int:\n    return (x * 7) + 13\n\n"
            "def stage_mid(x: int) -> int:\n    return stage_native(x) + 100\n",
            encoding="utf-8",
        )
        (r_b / "omni_repo.json").write_text(
            json.dumps({"name": "repo_b", "language": "python", "exports": ["stage_outer", "omni_main"], "dependencies": ["repo_a"]}),
            encoding="utf-8",
        )
        (r_b / "b.py").write_text(
            "def stage_outer(x: int) -> int:\n    return stage_mid(x) * 3\n\n"
            "def omni_main() -> int:\n    return stage_outer(10)\n",
            encoding="utf-8",
        )
        comp = OmniRepoCompiler(db_path=str(Path(td) / "runs.db"))
        try:
            host_ext = ".dll" if sys.platform == "win32" else ".so"
            out_lib = str(Path(td) / f"hybrid_bench{host_ext}")
            mid_eng = "gcc" if (sys.platform != "win32" and comp.gcc.supports_elf64) else "llvm"
            t0 = time.perf_counter()
            res = comp.compile_repositories(
                [str(r_a), str(r_b)],
                out_lib,
                target_format="shared_lib",
                entry_export="omni_main",
                backend="homeostasis",
                homeostasis_policy="throughput",
                homeostasis_function_overrides={
                    "stage_native": "native",
                    "stage_mid": mid_eng,
                    "stage_outer": "llvm",
                    "omni_main": "llvm",
                },
                audit_nonce="bench-hyb-c67",
            )
            compile_ms = (time.perf_counter() - t0) * 1000.0
            h_info = res["stages"]["homeostasis"]
            lib = ctypes.CDLL(out_lib)
            try:
                lib.stage_outer.argtypes = [ctypes.c_int64]
                lib.stage_outer.restype = ctypes.c_int64
                t1 = time.perf_counter()
                out_val = lib.stage_outer(10)
                call_ms = (time.perf_counter() - t1) * 1000.0
            finally:
                handle = getattr(lib, "_handle", None)
                del lib
                if sys.platform == "win32" and handle:
                    import _ctypes
                    _ctypes.FreeLibrary(handle)
            return {
                "heterogeneous_link": h_info["heterogeneous_link"],
                "binary_emitter_engine": h_info["binary_emitter_engine"],
                "hybrid_emitters_used": h_info["hybrid_emitters_used"],
                "compile_ms": round(compile_ms, 2),
                "call_ms": round(call_ms, 4),
                "result": int(out_val),
            }
        finally:
            comp.close()


def benchmark_safety_and_audit():
    # Measure Unicorn Pre-Flight emulation overhead vs physical execution
    code = b"\x48\x01\xd1\x48\x89\xc8\xc3"
    sandbox = SiliconSafetySandbox()
    t0 = time.perf_counter()
    for _ in range(50):
        res = sandbox.emulate_x86_64(code, args=[10, 20], abi="windows")
    dt_sandbox = (time.perf_counter() - t0) / 50

    # Measure Formal Binary Auditor latency
    emitter = StandaloneBinaryEmitter()
    pe_dll = emitter.build_pe64_dll(func_code=code, export_name="omni_calc")
    auditor = BinaryStructureAuditor()
    t0 = time.perf_counter()
    for _ in range(100):
        rep = auditor.audit_binary(pe_dll)
    dt_audit = (time.perf_counter() - t0) / 100

    return {
        "unicorn_preflight_latency_ms": dt_sandbox * 1000.0,
        "formal_audit_latency_ms": dt_audit * 1000.0
    }


if __name__ == "__main__":
    print("=" * 60)
    print("RUNNING COMPARATIVE SOTA BENCHMARKS")
    print("=" * 60)

    p_res = benchmark_parsing()
    print("[1] Parsing Benchmark (400 function prototypes):")
    print(f"    Tree-Sitter AST: {p_res['tree_sitter']['time_sec']*1000:.2f} ms ({p_res['tree_sitter']['symbols_extracted']} symbols)")
    print(f"    Regex Matcher:   {p_res['regex']['time_sec']*1000:.2f} ms ({p_res['regex']['symbols_extracted']} symbols)")

    e_res = benchmark_execution()
    print("\n[2] Execution Benchmark (100,000 loop iterations):")
    if "llvm_o3_jit" in e_res:
        print(f"    LLVM O3 JIT:      {e_res['llvm_o3_jit']['time_sec']*1000:.4f} ms (Result: {e_res['llvm_o3_jit']['result']})")
    if "wasmtime_sandbox" in e_res:
        print(f"    Wasmtime Sandbox: {e_res['wasmtime_sandbox']['time_sec']*1000:.4f} ms (Result: {e_res['wasmtime_sandbox']['result']})")
    if "omni_native_jit" in e_res and "time_sec" in e_res["omni_native_jit"]:
        print(f"    Omni Native JIT:  {e_res['omni_native_jit']['time_sec']*1000:.4f} ms (Result: {e_res['omni_native_jit']['result']})")
    if "gcc_o3" in e_res:
        print(f"    GCC O3 Subproc:   {e_res['gcc_o3']['time_sec']*1000:.4f} ms (Result: {e_res['gcc_o3']['result']})")

    h_res = benchmark_homeostasis_quad()
    print("\n[2b] Quad-Ecosystem Homeostasis Consensus Benchmark:")
    print(f"    Host SIMD Tier:   {h_res['host_simd_tier']} | Engines: {h_res['active_engines']} | Winner: {h_res['selected_engine']}")

    hyb_res = benchmark_heterogeneous_hybrid()
    print("\n[2c] Heterogeneous Per-Function Hybrid Linking Benchmark:")
    print(f"    Emitter Mode:     {hyb_res['binary_emitter_engine']} | Compile: {hyb_res['compile_ms']:.2f} ms | Result: {hyb_res['result']}")

    s_res = benchmark_safety_and_audit()
    print("\n[3] Pre-Flight & Formal Audit Overhead:")
    print(f"    Unicorn CPU Sandbox Latency: {s_res['unicorn_preflight_latency_ms']:.3f} ms / function")
    print(f"    Formal Binary Audit Latency: {s_res['formal_audit_latency_ms']:.3f} ms / binary")

    output_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "parsing": p_res,
        "execution": e_res,
        "homeostasis_quad": h_res,
        "heterogeneous_hybrid": hyb_res,
        "safety_and_audit": s_res
    }
    out_file = Path("external_component_candidates/benchmarks/benchmark_results.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(output_data, indent=2))
    print(f"\n[+] Benchmark results saved to {out_file}")
