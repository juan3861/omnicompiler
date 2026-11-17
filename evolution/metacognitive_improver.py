"""
Alpha-C40 Metacognitive Improver (Self-Diagnosis & Continuous Improvement Goals).
Inspects stage-level compilation timings, Salsa cache hit ratios, SMT rollback rates,
and Z3 spatial bounds telemetry to emit concrete, prioritized engineering goals.
"""

from dataclasses import dataclass, asdict
import os
from typing import Any, Dict, List


@dataclass
class ImprovementGoal:
    goal_id: str
    priority: str
    stage: str
    observed_metric: str
    target_metric: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MetacognitiveImprover:
    """Evaluates compilation telemetry and synthesizes actionable improvement goals."""

    def analyze_run(self, compile_results: Dict[str, Any], build_kind: str = "cold") -> Dict[str, Any]:
        stages = compile_results.get("stages", {})
        timings = stages.get("timings_ms", {})
        ingestion = stages.get("ingestion", {})
        codegen = stages.get("codegen", {})
        sep = stages.get("separation_logic", {})
        preflight = stages.get("preflight_safety", {})

        total_ms = float(timings.get("total_measured_stages", 0.0)) or 1.0
        goals: List[ImprovementGoal] = []

        # 1. Correctness / Safety invariants (P0)
        if not sep.get("z3_bounds_verified", True):
            goals.append(ImprovementGoal(
                goal_id="META-P0-BOUNDS",
                priority="P0_CRITICAL",
                stage="stage5c_z3_bounds",
                observed_metric=f"{len(sep.get('z3_bounds_violations', []))} spatial violations",
                target_metric="0 Z3 spatial bounds violations",
                recommendation="Inspect counterexamples in separation_logic.z3_bounds_violations and tighten loop guards.",
            ))
        if preflight and not preflight.get("is_safe_for_silicon", True):
            goals.append(ImprovementGoal(
                goal_id="META-P0-SILICON",
                priority="P0_CRITICAL",
                stage="stage6_link_unicorn_debug",
                observed_metric="is_safe_for_silicon=False",
                target_metric="is_safe_for_silicon=True",
                recommendation="Debug Unicorn pre-flight trap before binary emission.",
            ))
        if codegen.get("smt_pass_rollbacks", 0) > 0:
            goals.append(ImprovementGoal(
                goal_id="META-P1-SMT-ROLLBACK",
                priority="P1_HIGH",
                stage="stage5_ssa_opt_smt",
                observed_metric=f"{codegen.get('smt_pass_rollbacks')} pass rollbacks",
                target_metric="0 unsound pass rollbacks",
                recommendation="Fix SSA optimization pass generating unsound IR caught by VerifiedPassRunner.",
            ))

        # 2. Dominant latency stage bottleneck detection (P1/P2)
        stage_pairs = [
            (k, float(v))
            for k, v in timings.items()
            if k != "total_measured_stages"
        ]
        for s_name, s_ms in sorted(stage_pairs, key=lambda kv: kv[1], reverse=True):
            pct = (s_ms / total_ms) * 100.0
            if pct >= 40.0 and s_ms >= 250.0:
                goals.append(ImprovementGoal(
                    goal_id=f"META-BOTTLENECK-{s_name.upper()}",
                    priority="P1_HIGH",
                    stage=s_name,
                    observed_metric=f"{s_ms:.2f} ms ({pct:.1f}% of {total_ms:.2f} ms)",
                    target_metric="< 25% of total pipeline latency",
                    recommendation=f"Parallelize or memoize hot path in {s_name}.",
                ))

        # 3. Incremental cache efficiency checks
        if build_kind in ("warm", "incremental"):
            art_hits = int(ingestion.get("salsa_artifact_hits", 0))
            art_misses = int(ingestion.get("salsa_artifact_misses", 0))
            total_art = art_hits + art_misses
            if total_art > 0 and (art_hits / total_art) < 0.80:
                goals.append(ImprovementGoal(
                    goal_id="META-P1-SALSA-HITRATE",
                    priority="P1_HIGH",
                    stage="stage1_ingestion",
                    observed_metric=f"{art_hits}/{total_art} artifact hits",
                    target_metric=">= 80% artifact hits on incremental build",
                    recommendation="Tighten dependency keys in _salsa_ssa_cache / _salsa_obj_cache.",
                ))

        # 4. Optimization opportunity detection
        if codegen.get("real_ast_functions_compiled", 0) >= 4 and codegen.get("vectorized_loops", 0) == 0:
            goals.append(ImprovementGoal(
                goal_id="META-P2-VECTORIZER",
                priority="P2_OPTIMIZATION",
                stage="stage5_ssa_opt_smt",
                observed_metric="vectorized_loops=0",
                target_metric="Auto-vectorize contiguous array/struct reduction loops",
                recommendation="Extend LoopVectorizerPass to recognize C-ABI struct Array[T, N] reductions.",
            ))

        return {
            "build_kind": build_kind,
            "total_measured_ms": round(total_ms, 2),
            "goals_count": len(goals),
            "goals": [g.to_dict() for g in goals],
        }

    def write_markdown_report(
        self,
        stress_report: Dict[str, Any],
        analyses: List[Dict[str, Any]],
        output_path: str,
    ) -> str:
        lines = [
            "# ALPHA-C40 METACOGNITION & CONTINUOUS IMPROVEMENT GOALS",
            "",
            f"- **Stress Topology:** {stress_report['total_repos']} polyglot repos, {stress_report['exported_symbols_count']} exported symbols",
            f"- **Cold Compile:** `{stress_report['cold_total_ms']} ms` | **Warm Compile:** `{stress_report['warm_total_ms']} ms` (**{stress_report['warm_speedup_x']}x**)",
            f"- **1-File Edit Compile:** `{stress_report['edit1_total_ms']} ms` (`stage5_ssa_opt_smt`: `{stress_report['edit1_timings_ms'].get('stage5_ssa_opt_smt')} ms`, `salsa_artifact_hits`: `{stress_report['edit1_ingestion'].get('salsa_artifact_hits')}`)",
            "",
            "## Detected Bottlenecks & Generated Improvement Goals",
            "| Build | Goal ID | Priority | Stage | Observed | Target | Action |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for ana in analyses:
            bkind = ana["build_kind"]
            for g in ana["goals"]:
                lines.append(
                    f"| {bkind} | `{g['goal_id']}` | {g['priority']} | `{g['stage']}` | {g['observed_metric']} | {g['target_metric']} | {g['recommendation']} |"
                )
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return output_path
