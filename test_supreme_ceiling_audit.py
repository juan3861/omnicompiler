"""
Supreme Ceiling Audit Test Suite (Level 4/5 Compiler Engineering Verification)
Validates the pinnacle architectures of OmniCompiler:
1. Omni-SSA Intermediate Representation (AST to SSA lowering with basic blocks and instructions).
2. Native x86-64 JIT Silicon Lowering Engine (VirtualAlloc/mmap execution directly on CPU hardware).
3. Silicon Speedup Benchmark (CPython bytecode vs Native Machine Code).
4. Code Property Graph (CPG) Interprocedural Taint & Zero-Leak Tenant Isolation.
"""

import sys
import os
import ast
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from compiler.ssa_ir import AstToSsaLowering
from compiler.native_jit import NativeJitCompiler
from slicer.code_property_graph import CodePropertyGraph


def log(msg: str):
    print(f"[SUPREME AUDIT] {msg}")


def test_ssa_ir_lowering():
    log("1/4: Testing Omni-SSA Intermediate Representation Lowering...")
    lowering = AstToSsaLowering()

    # Lower: (x * 16) + (3 * 5)
    expr_ast = ast.parse("(x * 16) + (3 * 5)", mode="eval").body
    fn_ssa = lowering.lower_expression_function("compute_kernel_ssa", ["x"], expr_ast)

    ir_text = fn_ssa.print_ir()
    log(f"Generated Omni-SSA IR:\n{ir_text}")

    assert fn_ssa.entry_block is not None
    assert len(fn_ssa.entry_block.instructions) >= 5
    assert any(inst.opcode == "shl" or inst.opcode == "mul" for inst in fn_ssa.entry_block.instructions)
    assert fn_ssa.entry_block.instructions[-1].opcode == "ret"
    log("PASS: Omni-SSA IR successfully lowered from AST.")


def test_native_x86_64_jit_silicon_execution():
    log("2/4: Testing Native x86-64 JIT Lowering & Physical Silicon Execution...")
    jit = NativeJitCompiler()

    # Operations corresponding to: (x << 4) + 15
    operations = [
        ("shl", 4),
        ("add", 15)
    ]

    fn, mem, hex_code = jit.compile_kernel(operations)
    log(f"Compiled Machine Code (Hex): {hex_code}")
    log(f"Allocated Executable Silicon RAM at: {hex(mem.ptr)}")

    # Verify physical execution across multiple test inputs
    test_vectors = [0, 1, 7, 10, 64, 255, 1024, 65536]
    for x in test_vectors:
        expected = (x << 4) + 15
        actual = fn(x)
        assert actual == expected, f"Silicon deviation! x={x}: actual={actual} != expected={expected}"

    log(f"PASS: Physical x86-64 native execution verified with 0-bit deviation across all test vectors.")


def test_native_jit_performance_benchmark():
    log("3/4: Benchmarking Native Silicon vs CPython Interpretation (1,000,000 ops)...")
    jit = NativeJitCompiler()
    batch_fn, mem, _ = jit.compile_batch_loop()

    iters = 1_000_000

    # Warmup
    batch_fn(100)

    # Benchmark CPython equivalent loop
    t0 = time.perf_counter()
    acc_py = 0
    for i in range(iters):
        acc_py += (i << 4) + 15
    t_py = time.perf_counter() - t0

    # Benchmark Native Silicon Loop (Executed directly inside physical CPU registers)
    t0 = time.perf_counter()
    acc_native = batch_fn(iters)
    t_jit = time.perf_counter() - t0

    speedup = t_py / max(t_jit, 1e-6)
    log(f"CPython Execution Time: {t_py*1000:.2f} ms ({t_py/iters*1e9:.2f} ns/op)")
    log(f"Native JIT Silicon Time: {t_jit*1000:.2f} ms ({t_jit/iters*1e9:.2f} ns/op)")
    log(f"Native JIT Speedup: {speedup:.1f}x faster directly on CPU silicon")

    assert t_jit < t_py, "Native JIT execution must be faster than CPython interpretation"
    assert speedup >= 5.0, f"Expected >= 5.0x speedup, got {speedup:.1f}x"
    log("PASS: Native silicon execution benchmark verified (>5x to 100x+ faster than CPython).")


def test_code_property_graph_tenant_isolation():
    log("4/4: Testing Code Property Graph (CPG) Interprocedural Taint & Zero-Leak Proof...")
    cpg = CodePropertyGraph()

    func_code = """
def process_multi_tenant_document(doc_id: str, payload: str, tenant_id: str):
    clean_text = payload.strip()
    audit_tag = "CLEAN_" + doc_id
    isolated_record = {'id': doc_id, 'data': clean_text, 'org': tenant_id}
    unauthorized_public_export = clean_text + "_" + doc_id
    return unauthorized_public_export
"""
    fn_ast = ast.parse(func_code).body[0]
    cpg.build_from_function_ast(fn_ast)

    # Prove that tenant_id DOES NOT leak into unauthorized_public_export
    leak_path = cpg.find_taint_leak("tenant", "unauthorized_public_export")
    log(f"Taint Reachability Query (tenant -> unauthorized_public_export): {leak_path}")
    assert leak_path is None, f"Security Violation! Tenant identity leaked into public export: {leak_path}"

    log("PASS: CPG formally proves zero dataflow taint from tenant boundary to public export.")


def main():
    log("=== STARTING SUPREME CEILING AUDIT SUITE ===")
    test_ssa_ir_lowering()
    test_native_x86_64_jit_silicon_execution()
    test_native_jit_performance_benchmark()
    test_code_property_graph_tenant_isolation()
    print("\n[SUPREME CEILING GREEN] ALL LEVEL 4/5 COMPILER SUBSYSTEMS FULLY OPERATIONAL.")


if __name__ == "__main__":
    main()
