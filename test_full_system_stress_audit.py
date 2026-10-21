"""
OmniCompiler: Automated End-to-End Stress & Verification Audit Harness
Performs multi-dimensional stress testing, memory leak profiling,
dynamic CLI boundary tests, and full test suite verification.
"""

import sys
import os
import subprocess
import time
import ctypes
import gc
from typing import Dict, Any, List

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

PYTHON_EXE = sys.executable


def get_process_memory_mb() -> float:
    """Returns the working set size of the current process in MB."""
    try:
        import psutil
        return psutil.Process().memory_info().rss / (1024 * 1024)
    except ImportError:
        # Fallback via Windows API
        if sys.platform == "win32":
            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ('cb', ctypes.c_ulong),
                    ('PageFaultCount', ctypes.c_ulong),
                    ('PeakWorkingSetSize', ctypes.c_size_t),
                    ('WorkingSetSize', ctypes.c_size_t),
                    ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                    ('PagefileUsage', ctypes.c_size_t),
                    ('PeakPagefileUsage', ctypes.c_size_t),
                ]
            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                return counters.WorkingSetSize / (1024 * 1024)
    return 0.0


def run_command_checked(cmd: List[str], cwd: str = BASE_DIR, timeout: int = 60) -> Dict[str, Any]:
    t0 = time.perf_counter()
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return {
        "command": " ".join(cmd),
        "returncode": res.returncode,
        "elapsed_ms": elapsed_ms,
        "stdout": res.stdout,
        "stderr": res.stderr,
        "success": res.returncode == 0
    }


def execute_full_audit_round(round_number: int) -> Dict[str, Any]:
    print("\n" + "=" * 78)
    print(f" [ROUND {round_number}] FULL SYSTEM END-TO-END STRESS & INTEGRITY AUDIT")
    print("=" * 78)

    round_start = time.perf_counter()
    mem_initial = get_process_memory_mb()
    checks: List[Dict[str, Any]] = []
    bottlenecks: List[str] = []

    # -------------------------------------------------------------------------
    # Phase 1: Submodule Compilation via CLI
    # -------------------------------------------------------------------------
    print(f"[*] Phase 1: Ingesting & compiling 6 compiler submodules via omnicompiler_cli.py...")
    p1 = run_command_checked([PYTHON_EXE, "omnicompiler_cli.py", "compile"])
    if not p1["success"] or "PHYSICAL SILICON PROOF" not in p1["stdout"]:
        bottlenecks.append(f"Phase 1 compilation failed: {p1['stderr']}")
    checks.append({"name": "CLI Submodule Compilation", "elapsed_ms": p1["elapsed_ms"], "success": p1["success"]})
    print(f"    -> Status: {'OK' if p1['success'] else 'FAIL'} ({p1['elapsed_ms']:.2f} ms)")

    # -------------------------------------------------------------------------
    # Phase 2: Dynamic CLI Argument Boundary & Robustness Stress
    # -------------------------------------------------------------------------
    print(f"[*] Phase 2: Standalone binary bare-metal CLI execution & stress...")
    exe_name = "omnicompiler_standalone.exe" if sys.platform == "win32" else "omnicompiler_standalone"
    exe_path = os.path.join(BASE_DIR, "dist", exe_name)

    # First compile standalone executable
    from omni_repo_compiler import OmniRepoCompiler
    modules_dir = os.path.join(BASE_DIR, "compiler_modules")
    repos = [
        os.path.join(modules_dir, d)
        for d in sorted(os.listdir(modules_dir))
        if os.path.isdir(os.path.join(modules_dir, d))
    ]
    compiler = OmniRepoCompiler()
    c_res = compiler.compile_repositories(
        repo_paths=repos,
        output_path=exe_path,
        target_format="executable",
        entry_export="omnicompiler_entrypoint"
    )
    if not c_res["success"] or not os.path.exists(exe_path):
        bottlenecks.append("Phase 2: Failed to emit standalone binary")

    test_vectors = [
        ([], 175, "default argument (no args)"),
        (["5"], 95, "dynamic arg '5'"),
        (["7"], 127, "dynamic arg '7'"),
        (["0"], 15, "dynamic arg '0'"),
        (["2"], 47, "dynamic arg '2'"),
        (["invalid_text"], 175, "robustness non-numeric fallback to default"),
        (["100"], 1615 if sys.platform == "win32" else (1615 & 0xFF), "multi-digit arg '100' (exit code)"),
    ]

    phase2_latencies = []
    for args, expected_code, desc in test_vectors:
        t0 = time.perf_counter()
        proc = subprocess.run([exe_path] + args, capture_output=True)
        t_ms = (time.perf_counter() - t0) * 1000.0
        phase2_latencies.append(t_ms)
        if proc.returncode != expected_code:
            bottlenecks.append(f"Phase 2 mismatch for {desc}: got {proc.returncode}, expected {expected_code}")
        print(f"    -> Vector '{' '.join(args) or '(none)'}': exit {proc.returncode} (expected {expected_code}) in {t_ms:.2f} ms")

    avg_p2_latency = sum(phase2_latencies) / len(phase2_latencies)
    if avg_p2_latency > 150.0:
        bottlenecks.append(f"Phase 2 startup latency excessive: {avg_p2_latency:.2f} ms")
    checks.append({"name": "Standalone Dynamic CLI Vectors", "elapsed_ms": sum(phase2_latencies), "success": len(bottlenecks) == 0})

    # -------------------------------------------------------------------------
    # Phase 3: Repeated Memory-Mapped DLL Load/Unload Stress (Leak Detection)
    # -------------------------------------------------------------------------
    print(f"[*] Phase 3: Stress-testing 100 cycles of dynamic DLL loading/unloading in RAM...")
    dll_path = os.path.join(BASE_DIR, "dist", "omnicompiler_unified_engine.dll")
    gc.collect()
    mem_before_loop = get_process_memory_mb()

    if sys.platform == "win32" and os.path.exists(dll_path):
        loop_iterations = 100
        t0_loop = time.perf_counter()
        for i in range(loop_iterations):
            lib = ctypes.WinDLL(dll_path)
            fn = getattr(lib, "omnicompiler_entrypoint")
            fn.argtypes = [ctypes.c_int64]
            fn.restype = ctypes.c_int64
            val = fn(10)
            if val != 175:
                bottlenecks.append(f"Phase 3: DLL execution returned wrong value {val} at cycle {i}")
                break
            h = lib._handle
            del fn
            del lib
            ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(h))

        loop_elapsed_ms = (time.perf_counter() - t0_loop) * 1000.0
        gc.collect()
        mem_after_loop = get_process_memory_mb()
        mem_diff_mb = mem_after_loop - mem_before_loop

        print(f"    -> 100 LoadLibrary/FreeLibrary cycles executed in {loop_elapsed_ms:.2f} ms ({loop_elapsed_ms / loop_iterations:.2f} ms/cycle)")
        print(f"    -> Memory before: {mem_before_loop:.2f} MB | after: {mem_after_loop:.2f} MB | delta: {mem_diff_mb:+.2f} MB")

        if mem_diff_mb > 5.0:
            bottlenecks.append(f"Phase 3: Potential memory leak detected (delta {mem_diff_mb:.2f} MB)")
        checks.append({"name": "100 DLL Load/Unload Cycles", "elapsed_ms": loop_elapsed_ms, "success": mem_diff_mb <= 5.0})

    # -------------------------------------------------------------------------
    # Phase 4: Full Multi-Repository Compiler Pipeline (E2E)
    # -------------------------------------------------------------------------
    print(f"[*] Phase 4: Running test_omni_repo_compiler_e2e.py (all 8 stages)...")
    p4 = run_command_checked([PYTHON_EXE, "test_omni_repo_compiler_e2e.py"])
    if not p4["success"] or "100% GREEN" not in p4["stdout"]:
        bottlenecks.append(f"Phase 4 failed: {p4['stderr']}")
    checks.append({"name": "Multi-Repo Compiler E2E", "elapsed_ms": p4["elapsed_ms"], "success": p4["success"]})
    p4_status = 'OK' if p4['success'] else 'FAIL'
    print(f"    -> Status: {p4_status} ({p4['elapsed_ms']:.2f} ms)")

    # -------------------------------------------------------------------------
    # Phase 5: Compiler Subsystems Benchmark (4 Axes)
    # -------------------------------------------------------------------------
    print(f"[*] Phase 5: Running test_compiler_subsystems_benchmark.py (4 Axes)...")
    p5 = run_command_checked([PYTHON_EXE, "test_compiler_subsystems_benchmark.py"])
    if not p5["success"] or "100% EMPIRICAL PROOF" not in p5["stdout"]:
        bottlenecks.append(f"Phase 5 benchmark failed: {p5['stderr']}")
    checks.append({"name": "Subsystems Benchmark (4 Axes)", "elapsed_ms": p5["elapsed_ms"], "success": p5["success"]})
    p5_status = 'OK' if p5['success'] else 'FAIL'
    print(f"    -> Status: {p5_status} ({p5['elapsed_ms']:.2f} ms)")

    # -------------------------------------------------------------------------
    # Phase 6: Full Discovered Unit & Integration Test Suites
    # -------------------------------------------------------------------------
    print(f"[*] Phase 6: Running 53 discovered unit tests (unittest discover tests -v)...")
    p6 = run_command_checked([PYTHON_EXE, "-m", "unittest", "discover", "tests", "-v"], timeout=90)
    if not p6["success"] or "OK" not in p6["stderr"]:
        bottlenecks.append(f"Phase 6 unit tests failed: {p6['stderr']}")
    checks.append({"name": "53 Discovered Unit Tests", "elapsed_ms": p6["elapsed_ms"], "success": p6["success"]})
    p6_status = 'OK' if p6['success'] else 'FAIL'
    print(f"    -> Status: {p6_status} ({p6['elapsed_ms']:.2f} ms)")

    # -------------------------------------------------------------------------
    # Phase 7: Adversarial Security & Synthesis Fixtures
    # -------------------------------------------------------------------------
    print(f"[*] Phase 7: Running 24 Adversarial Security Fixtures...")
    p7 = run_command_checked([PYTHON_EXE, "benchmarks/adversarial_fixtures.py"])
    if not p7["success"] or "OK" not in p7["stderr"]:
        bottlenecks.append(f"Phase 7 adversarial fixtures failed: {p7['stderr']}")
    checks.append({"name": "24 Adversarial Fixtures", "elapsed_ms": p7["elapsed_ms"], "success": p7["success"]})
    p7_status = 'OK' if p7['success'] else 'FAIL'
    print(f"    -> Status: {p7_status} ({p7['elapsed_ms']:.2f} ms)")

    # -------------------------------------------------------------------------
    # Phase 8: Frontier Breakthrough & Supreme Ceiling Audits
    # -------------------------------------------------------------------------
    print(f"[*] Phase 8: Running Frontier Breakthrough & Supreme Ceiling Audits...")
    p8a = run_command_checked([PYTHON_EXE, "test_frontier_breakthrough.py"])
    p8b = run_command_checked([PYTHON_EXE, "test_supreme_ceiling_audit.py"])
    p8_ok = p8a["success"] and p8b["success"]
    if not p8_ok:
        bottlenecks.append(f"Phase 8 audits failed: {p8a['stderr']} {p8b['stderr']}")
    checks.append({"name": "Frontier & Supreme Audits", "elapsed_ms": p8a["elapsed_ms"] + p8b["elapsed_ms"], "success": p8_ok})
    print(f"    -> Status: {'OK' if p8_ok else 'FAIL'} ({p8a['elapsed_ms'] + p8b['elapsed_ms']:.2f} ms)")

    # -------------------------------------------------------------------------
    # Phase 9: CLI Multi-Command Sweep (unified, egraph, cpg, alive, cegis, mcts)
    # -------------------------------------------------------------------------
    print(f"[*] Phase 9: Sweeping all 6 omnicompiler_cli subcommands...")
    subcommands = [
        ["unified", "--expr", "x * 16 + 15"],
        ["egraph", "(+ (* x 4) (* x 4))"],
        ["cpg", "SAFE_SOURCE", "KERNEL_SINK"],
        ["alive", "--src", "mul16", "--tgt", "shl4"],
        ["cegis", "--spec", "17 * x"],
        ["mcts", "--spec", "kernel_opt"],
    ]
    p9_latencies = []
    for sc in subcommands:
        p_sc = run_command_checked([PYTHON_EXE, "omnicompiler_cli.py"] + sc)
        p9_latencies.append(p_sc["elapsed_ms"])
        if not p_sc["success"]:
            bottlenecks.append(f"Phase 9 subcommand {' '.join(sc)} failed: {p_sc['stderr']}")
        print(f"    -> Subcommand '{sc[0]}': {'OK' if p_sc['success'] else 'FAIL'} ({p_sc['elapsed_ms']:.2f} ms)")

    checks.append({"name": "CLI Subcommands Sweep", "elapsed_ms": sum(p9_latencies), "success": len(bottlenecks) == 0})

    round_total_ms = (time.perf_counter() - round_start) * 1000.0
    mem_final = get_process_memory_mb()
    print("-" * 78)
    print(f" [ROUND {round_number} RESULT] Duration: {round_total_ms / 1000.0:.2f}s | Memory: {mem_final:.2f} MB | Bottlenecks: {len(bottlenecks)}")
    if bottlenecks:
        print(" [!] Detected Bottlenecks / Errors:")
        for b in bottlenecks:
            print(f"     - {b}")
    else:
        print(" [+] ZERO BOTTLENECKS, ZERO MALFUNCTIONS, ZERO SURPRISES DETECTED.")
    print("-" * 78)

    return {
        "round": round_number,
        "total_elapsed_ms": round_total_ms,
        "checks": checks,
        "bottlenecks": bottlenecks,
        "clean_pass": len(bottlenecks) == 0
    }


def main():
    target_consecutive_rounds = 3
    consecutive_clean_rounds = 0
    total_rounds_attempted = 0
    max_attempts = 10

    round_history: List[Dict[str, Any]] = []

    print("==============================================================================")
    print(" OMNICOMPILER MASTER STRESS AUDIT: 3 CONSECUTIVE CLEAN ROUNDS PROTOCOL")
    print("==============================================================================")

    while consecutive_clean_rounds < target_consecutive_rounds and total_rounds_attempted < max_attempts:
        total_rounds_attempted += 1
        res = execute_full_audit_round(total_rounds_attempted)
        round_history.append(res)

        if res["clean_pass"]:
            consecutive_clean_rounds += 1
            print(f"\n[PROGRESS] Clean Round {consecutive_clean_rounds} of {target_consecutive_rounds} achieved.")
        else:
            print(f"\n[RESET] Bottleneck encountered. Resetting clean round counter from {consecutive_clean_rounds} to 0.")
            consecutive_clean_rounds = 0

    print("\n" + "=" * 78)
    print(f" FINAL AUDIT STATUS: {consecutive_clean_rounds}/{target_consecutive_rounds} CONSECUTIVE CLEAN ROUNDS")
    print("=" * 78)

    if consecutive_clean_rounds >= target_consecutive_rounds:
        print("[+] SUCCESS: The system has completed 3 consecutive rounds with ZERO bottlenecks, ZERO malfunctions, and ZERO surprise fixes.")
        return 0
    else:
        print(f"[!] FAILED: Reached maximum attempts ({max_attempts}) without achieving {target_consecutive_rounds} consecutive clean rounds.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
