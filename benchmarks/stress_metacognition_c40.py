"""
Alpha-C40 Stress Harness & Stage-Level Latency Profiler.
Compiles heavy polyglot multi-repo workloads, records per-stage timings and silent-error
counters, exposes bottlenecks empirically, and feeds the Metacognitive Improver.
"""

import _ctypes
import ctypes
import json
import os
import sys
import tempfile
import time
from typing import Any, Dict, List

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from omni_repo_compiler import OmniRepoCompiler


def _unload_cdll(lib: ctypes.CDLL) -> None:
    handle = getattr(lib, "_handle", None)
    del lib
    if handle is not None and sys.platform == "win32":
        _ctypes.FreeLibrary(handle)


def build_heavy_polyglot_workspace(base_dir: str, num_repos: int = 8, fns_per_repo: int = 4) -> List[str]:
    """Generates a multi-repo Python + Rust + Go + TypeScript topology with structs, LUTs & calls."""
    repo_paths: List[str] = []
    for r in range(num_repos):
        rp = os.path.join(base_dir, f"stress_repo_{r:02d}")
        os.makedirs(rp, exist_ok=True)

        # Mix languages across repos
        if r % 4 == 1:
            lines = []
            for k in range(fns_per_repo):
                lines.append(
                    f"pub fn rs_step_{r}_{k}(code: i64, x: i64) -> i64 {{\n"
                    f"    return match code {{\n"
                    f"        0 => x * {k + 2} + {r + 1},\n"
                    f"        1 | 2 => x * {k + 3} + 7,\n"
                    f"        _ => x + {r * 10 + k},\n"
                    f"    }};\n"
                    f"}}\n"
                )
            with open(os.path.join(rp, "lib.rs"), "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        elif r % 4 == 2:
            lines = []
            for k in range(fns_per_repo):
                lines.append(
                    f"func go_route_{r}_{k}(mode int, x int) int {{\n"
                    f"    switch mode {{\n"
                    f"    case 1, 2:\n"
                    f"        return x * {k + 4} + {r + 3}\n"
                    f"    default:\n"
                    f"        return x + {r * 5 + k}\n"
                    f"    }}\n"
                    f"}}\n"
                )
            with open(os.path.join(rp, "net.go"), "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        elif r % 4 == 3:
            lines = []
            for k in range(fns_per_repo):
                lines.append(
                    f"export function ts_filter_{r}_{k}(v: number): number {{\n"
                    f"    let acc: number = 0;\n"
                    f"    let i: number = 0;\n"
                    f"    while (i < 4) {{\n"
                    f"        acc = acc + v + i + {k};\n"
                    f"        i = i + 1;\n"
                    f"    }}\n"
                    f"    return acc;\n"
                    f"}}\n"
                )
            with open(os.path.join(rp, "filter.ts"), "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        else:
            lines = [
                f"STRESS_LUT_{r} = [{10 + r}, {20 + r}, {30 + r}, {40 + r}]\n",
                "class StressPacket:\n    flags: u32\n    weights: Array[f32, 4]\n\n",
            ]
            for k in range(fns_per_repo):
                lines.append(
                    f"def py_kernel_{r}_{k}(mode: int, x: int) -> int:\n"
                    f"    acc = x * {k + 2}\n"
                    f"    i = 0\n"
                    f"    while i < 4:\n"
                    f"        acc += STRESS_LUT_{r}[i]\n"
                    f"        i += 1\n"
                    f"    if mode >= 0 and mode < 4:\n"
                    f"        return acc + STRESS_LUT_{r}[mode]\n"
                    f"    return acc\n\n"
                    f"def py_safe_box_{r}_{k}(pkt: StressPacket) -> float:\n"
                    f"    s = 0.0\n"
                    f"    i = 0\n"
                    f"    while i < 4:\n"
                    f"        s += pkt.weights[i]\n"
                    f"        i += 1\n"
                    f"    return s\n"
                )
            with open(os.path.join(rp, "kernels.py"), "w", encoding="utf-8") as f:
                f.write("\n".join(lines))

        repo_paths.append(rp)

    # Top-level aggregator repo calling across languages
    agg_rp = os.path.join(base_dir, "stress_aggregator")
    os.makedirs(agg_rp, exist_ok=True)
    with open(os.path.join(agg_rp, "main.py"), "w", encoding="utf-8") as f:
        f.write(
            "def stress_master_entry(mode: int, x: int) -> int:\n"
            "    a = py_kernel_0_0(mode, x)\n"
            "    b = rs_step_1_0(mode, x)\n"
            "    c = go_route_2_0(mode, x)\n"
            "    d = ts_filter_3_0(x)\n"
            "    return a + b + c + d\n"
        )
    repo_paths.append(agg_rp)
    return repo_paths


def run_stress_suite(verbose: bool = True) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmpdir:
        repos = build_heavy_polyglot_workspace(tmpdir, num_repos=8, fns_per_repo=4)
        ext = ".dll" if sys.platform == "win32" else ".so"
        comp = OmniRepoCompiler()

        # 1. Cold heavy stress build (Native x86_64)
        out1 = os.path.join(tmpdir, f"stress_cold{ext}")
        t0 = time.perf_counter()
        res1 = comp.compile_repositories(
            repos, out1, target_format="shared_lib",
            entry_export="stress_master_entry", export_all=True,
            backend="native", audit_nonce="c40-stress-cold",
        )
        cold_total_ms = (time.perf_counter() - t0) * 1000.0

        # Verify real execution of fused cross-language entry
        lib = ctypes.CDLL(out1)
        try:
            fn = lib.stress_master_entry
            fn.argtypes = [ctypes.c_int64, ctypes.c_int64]
            fn.restype = ctypes.c_int64
            exec_val = fn(1, 5)
        finally:
            _unload_cdll(lib)

        # 2. Warm rebuild (0 edits)
        out2 = os.path.join(tmpdir, f"stress_warm{ext}")
        t1 = time.perf_counter()
        res2 = comp.compile_repositories(
            repos, out2, target_format="shared_lib",
            entry_export="stress_master_entry", export_all=True,
            backend="native", audit_nonce="c40-stress-warm",
        )
        warm_total_ms = (time.perf_counter() - t1) * 1000.0

        # 3. 1-file edit incremental rebuild
        with open(os.path.join(repos[-1], "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "def stress_master_entry(mode: int, x: int) -> int:\n"
                "    a = py_kernel_0_0(mode, x)\n"
                "    b = rs_step_1_0(mode, x)\n"
                "    c = go_route_2_0(mode, x)\n"
                "    d = ts_filter_3_0(x)\n"
                "    return a + b + c + d + 1000\n"
            )
        out3 = os.path.join(tmpdir, f"stress_edit1{ext}")
        t2 = time.perf_counter()
        res3 = comp.compile_repositories(
            repos, out3, target_format="shared_lib",
            entry_export="stress_master_entry", export_all=True,
            backend="native", audit_nonce="c40-stress-edit1",
        )
        edit1_total_ms = (time.perf_counter() - t2) * 1000.0

        lib3 = ctypes.CDLL(out3)
        try:
            fn3 = lib3.stress_master_entry
            fn3.argtypes = [ctypes.c_int64, ctypes.c_int64]
            fn3.restype = ctypes.c_int64
            exec_val_edit = fn3(1, 5)
        finally:
            _unload_cdll(lib3)

        from evolution.metacognitive_improver import MetacognitiveImprover
        improver = MetacognitiveImprover()
        analyses = [
            improver.analyze_run(res1, build_kind="cold"),
            improver.analyze_run(res2, build_kind="warm"),
            improver.analyze_run(res3, build_kind="incremental"),
        ]
        goals_md = os.path.join(REPO_ROOT, "engineering_evidence", "METACOGNITION_IMPROVEMENT_GOALS_C40.md")

        report = {
            "total_repos": len(repos),
            "exported_symbols_count": len(res1["stages"]["linking"]["exported_symbols"]),
            "cold_total_ms": round(cold_total_ms, 2),
            "warm_total_ms": round(warm_total_ms, 2),
            "edit1_total_ms": round(edit1_total_ms, 2),
            "warm_speedup_x": round(cold_total_ms / max(0.1, warm_total_ms), 2),
            "edit1_speedup_x": round(cold_total_ms / max(0.1, edit1_total_ms), 2),
            "exec_val": exec_val,
            "exec_val_edit": exec_val_edit,
            "cold_ingestion": res1["stages"]["ingestion"],
            "warm_ingestion": res2["stages"]["ingestion"],
            "edit1_ingestion": res3["stages"]["ingestion"],
            "cold_codegen": res1["stages"]["codegen"],
            "cold_timings_ms": res1["stages"].get("timings_ms", {}),
            "warm_timings_ms": res2["stages"].get("timings_ms", {}),
            "edit1_timings_ms": res3["stages"].get("timings_ms", {}),
            "metacognitive_analyses": analyses,
            "goals_report_path": goals_md,
        }
        improver.write_markdown_report(report, analyses, goals_md)
        if verbose:
            print("=== ALPHA-C40 STRESS PROFILER LOG ===")
            print(json.dumps(report, indent=2))
        return report


if __name__ == "__main__":
    run_stress_suite(verbose=True)
