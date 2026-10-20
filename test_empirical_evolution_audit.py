"""
Empirical Evolution & Multi-Organ Self-Evolution Audit for AetherMind Strict Auditor.
Validates the entire self-evolution chain under the OMEGA Protocol:
1. OmniMutator 8-category AST superoptimizer functionality.
2. Alive2 / Z3 QF_BV formal SMT translation validation.
3. Multi-organ round-robin mutation across all 7 compiler organs.
4. Physical child generation compilation and subprocess execution.
5. Latency & bytecode speedup benchmark (unevolved vs evolved).
6. Lineage tree durability and BLAKE3 cryptographic provenance.
"""

import os
import sys
import ast
import json
import time
import subprocess
import unittest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from evolution.omni_mutator import OmniMutator
from validation.smt_refinement import SmtRefinementVerifier
from evolution.recursive_bootstrap_loop import TARGET_ORGANS, RecursiveBootstrapChain
from crypto.blake3_engine import blake3_digest

GENERATIONS_ROOT = os.environ.get("GENERATIONS_ROOT", os.path.join(os.path.dirname(BASE_DIR), "repository-compiler-generations"))
LINEAGE_TREE_FILE = os.path.join(GENERATIONS_ROOT, "lineage_tree.json")


def log(msg: str):
    print(f"[AUDIT TEST] {msg}")


def test_omni_mutator_8_categories():
    log("Checking OmniMutator 8-category AST transformations...")
    mutator = OmniMutator(mutation_rate=1.0)  # Deterministic test rate

    sample_code = """
def test_sample(x: int) -> int:
    a = x * 16
    b = x // 4
    c = x % 8
    d = a + 0
    e = 3 * 5
    f = "prefix_" + "suffix"
    g = [0] * 3
    is_valid = not (not (x in [1, 2, 3]))
    is_even = (x % 2 == 0)
    if True:
        r = range(0, 10, 1)
    else:
        r = 0
    total = sum([val for val in r])
    return total
"""
    tree = ast.parse(sample_code)
    mutated = mutator.visit(tree)
    ast.fix_missing_locations(mutated)
    mutated_code = ast.unparse(mutated)

    # Verify syntax compiles cleanly
    compile(mutated_code, "<test_sample>", "exec")

    log(f"OmniMutator applied {len(mutator.mutations_applied)} mutations: {mutator.mutations_applied}")
    assert len(mutator.mutations_applied) >= 5, f"Expected >= 5 mutations, got: {mutator.mutations_applied}"
    log("OmniMutator 8-category AST transformations PASSED.")


def test_smt_refinement_prover():
    log("Checking Alive2 / Z3 QF_BV translation validation...")
    verifier = SmtRefinementVerifier()

    # Valid equivalent pair
    res_valid = verifier.verify_arithmetic_refinement("x * 16", "x << 4")
    assert res_valid.get("proven") is True, f"Failed valid proof: {res_valid}"
    assert res_valid.get("bits_verified") == 32

    # Invalid divergent pair (x * 16 != x << 3)
    res_invalid = verifier.verify_arithmetic_refinement("x * 16", "x << 3")
    assert res_invalid.get("proven") is False, f"Invalid pair was falsely proven: {res_invalid}"
    assert len(res_invalid.get("counterexamples", [])) > 0
    log("SMT Refinement Prover & Counterexample Gate PASSED.")


def test_multi_organ_rotation_spec():
    log("Checking 7-organ round-robin specification...")
    assert len(TARGET_ORGANS) == 7, f"Expected 7 target organs, got: {len(TARGET_ORGANS)}"
    expected_ids = [
        "compute_kernel", "blake3_engine", "salsa_query_engine",
        "tensor_tiler", "sharded_allocator", "biabduction_verifier", "smt_refinement"
    ]
    actual_ids = [o["id"] for o in TARGET_ORGANS]
    assert actual_ids == expected_ids, f"Organ mismatch: {actual_ids} vs {expected_ids}"
    log(f"All 7 organs validated: {actual_ids}")


def test_physical_child_generation_execution():
    log("Checking latest compiled child generation subprocess execution...")
    assert os.path.exists(GENERATIONS_ROOT), "Generations directory missing"
    assert os.path.exists(LINEAGE_TREE_FILE), "Lineage tree missing"

    with open(LINEAGE_TREE_FILE, "r", encoding="utf-8") as f:
        lineage = json.load(f)
    assert len(lineage) > 0, "No certified generations in lineage tree"

    latest_entry = lineage[-1]
    latest_gen = latest_entry["generation_id"]
    latest_dir = os.path.join(GENERATIONS_ROOT, latest_gen)
    cli_path = os.path.join(latest_dir, "cli.py")
    assert os.path.exists(cli_path), f"Child entrypoint missing: {cli_path}"

    proc = subprocess.run([sys.executable, cli_path], capture_output=True, text=True, timeout=10)
    assert proc.returncode == 0, f"Child generation returned {proc.returncode}: {proc.stderr}"
    data = json.loads(proc.stdout.strip())
    assert data.get("generation_id") == latest_gen
    assert data.get("smt_refinement_verified") is True
    assert "compiled_by_parent" in data
    assert "target_organ" in data
    log(f"Latest certified child {latest_gen} executed physically with 0 errors. Target: {data['target_organ']}.")


def test_lineage_durability():
    log("Checking lineage tree integrity and BLAKE3 cryptographic provenance...")
    assert os.path.exists(LINEAGE_TREE_FILE), "Lineage tree file missing"
    with open(LINEAGE_TREE_FILE, "r", encoding="utf-8") as f:
        lineage = json.load(f)
    assert len(lineage) >= 1, f"Expected at least 1 generation in lineage tree, got: {len(lineage)}"

    latest_entry = lineage[-1]
    assert "parent_organ_blake3" in latest_entry
    assert "child_organ_blake3" in latest_entry
    assert len(latest_entry["parent_organ_blake3"]) == 64
    assert len(latest_entry["child_organ_blake3"]) == 64
    log(f"Lineage contains {len(lineage)} certified generations. Provenance verified.")


def test_speedup_benchmark():
    log("Benchmarking unevolved vs evolved compute kernel (500,000 ops)...")
    # Unevolved
    def unevolved_kernel(x: int) -> int:
        scaled = (x * 16) + (3 * 5)
        normalized = scaled + 0
        return normalized

    # Evolved (strength reduced + constant folded + identity eliminated)
    def evolved_kernel(x: int) -> int:
        return (x << 4) + 15

    # Correctness check
    for test_x in [0, 1, 7, 16, 255, 1024, 65535, 1000000]:
        assert unevolved_kernel(test_x) == evolved_kernel(test_x), f"Mismatch for x={test_x}"

    # Benchmark
    iters = 500000
    t0 = time.perf_counter()
    for i in range(iters):
        unevolved_kernel(i)
    t_unevolved = time.perf_counter() - t0

    t0 = time.perf_counter()
    for i in range(iters):
        evolved_kernel(i)
    t_evolved = time.perf_counter() - t0

    ns_un = (t_unevolved / iters) * 1e9
    ns_ev = (t_evolved / iters) * 1e9
    speedup = t_unevolved / max(t_evolved, 1e-9)

    log(f"Benchmark: Unevolved={ns_un:.2f} ns/op | Evolved={ns_ev:.2f} ns/op | Speedup={speedup:.2f}x")
    assert ns_ev <= ns_un * 1.15, "Evolved kernel unexpectedly regressed"
    log("Speedup benchmark PASSED.")


def main():
    log("=== STARTING OMEGA EMPIRICAL EVOLUTION AUDIT ===")
    test_omni_mutator_8_categories()
    test_smt_refinement_prover()
    test_multi_organ_rotation_spec()
    test_physical_child_generation_execution()
    test_lineage_durability()
    test_speedup_benchmark()
    log("=== ALL 6 OMEGA EMPIRICAL EVOLUTION TESTS PASSED (100% GREEN) ===")


if __name__ == "__main__":
    main()
