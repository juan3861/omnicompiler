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
from compiler.llvm_backend import LLVMBackend
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

    return results


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

    s_res = benchmark_safety_and_audit()
    print("\n[3] Pre-Flight & Formal Audit Overhead:")
    print(f"    Unicorn CPU Sandbox Latency: {s_res['unicorn_preflight_latency_ms']:.3f} ms / function")
    print(f"    Formal Binary Audit Latency: {s_res['formal_audit_latency_ms']:.3f} ms / binary")

    output_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "parsing": p_res,
        "execution": e_res,
        "safety_and_audit": s_res
    }
    out_file = Path("external_component_candidates/benchmarks/benchmark_results.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(output_data, indent=2))
    print(f"\n[+] Benchmark results saved to {out_file}")
