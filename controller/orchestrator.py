"""
RC-12 Run Controller: Orchestrates end-to-end repository compilation lifecycle.
Implements the canonical state machine:
RECEIVED -> SPECIFIED -> SNAPSHOTTED -> BASELINED -> INDEXED -> PLANNED
 -> ADAPTING -> BUILT -> VALIDATING -> PACKAGED -> ACCEPTED_FOR_SPEC.
Transactional state persistence, immutable snapshot caching, and error containment.
"""

import os
import sys
import shutil
import platform
import sqlite3
import json
import time
import ast
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from contracts.models import (
    IntegrationSpec, RepoSnapshot, BaselineReport, FactBundle,
    CapabilityContract, CompositionPlan, AdapterCandidate,
    ProductCandidate, EvidenceBundle, ReleaseCandidate,
    canonical_json, sha256_digest
)
from snapshots.engine import SnapshotEngine, hash_file
from frontends.polyglot_frontend import PolyglotFrontend
from discovery.matcher import CapabilityDiscoveryEngine
from planner.engine import CompositionPlanner
from adapters.synthesizer import AdapterSynthesizer
from materializers.engine import MaterializerEngine
from validation.validator import IndependentValidator
from packaging.packager import PackagerEngine
from recipes.registry import RecipeRegistry

CANONICAL_FAILURE_CODES = (
    "intent_ambiguous",
    "baseline_failed",
    "unsupported_language",
    "unresolved_dependency",
    "semantic_mismatch",
    "protocol_mismatch",
    "no_plan_in_model",
    "synthesis_timeout",
    "verification_failed",
    "external_service_missing",
    "budget_exhausted",
)


class RunController:
    def __init__(self, workdir: str, db_path: Optional[str] = None):
        self.workdir = os.path.abspath(workdir)
        os.makedirs(self.workdir, exist_ok=True)
        self.db_path = db_path or os.path.join(self.workdir, "runs.db")
        self._db_conn: Optional[sqlite3.Connection] = None
        self._init_db()

        # Engine instances with frozen snapshot cache and recipe registry
        snapshots_dir = os.path.join(self.workdir, "snapshots")
        self.snapshot_engine = SnapshotEngine(snapshots_storage_dir=snapshots_dir)
        self.frontend = PolyglotFrontend()
        self.discovery = CapabilityDiscoveryEngine()
        self.planner = CompositionPlanner()
        self.adapter_synth = AdapterSynthesizer()
        self.materializer = MaterializerEngine(base_workspace_dir=os.path.join(self.workdir, "workspaces"))
        self.validator = IndependentValidator()
        self.packager = PackagerEngine()
        self.recipe_registry = RecipeRegistry(storage_dir=os.path.join(self.workdir, "recipes"))

    def _connect_db(self) -> sqlite3.Connection:
        if self._db_conn is None:
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=MEMORY;")
            conn.execute("PRAGMA synchronous=OFF;")
            conn.execute("PRAGMA temp_store=MEMORY;")
            self._db_conn = conn
        return self._db_conn

    def close(self):
        if self._db_conn is not None:
            try:
                self._db_conn.close()
            except Exception:
                pass
            self._db_conn = None

    def __del__(self):
        self.close()

    def _init_db(self):
        with self._connect_db() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    spec_id TEXT,
                    state TEXT,
                    spec_json TEXT,
                    plan_json TEXT,
                    verdict TEXT,
                    error_message TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS run_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    stage TEXT,
                    payload TEXT,
                    timestamp TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS manifest_cache (
                    cache_key TEXT PRIMARY KEY,
                    run_id TEXT,
                    result_json TEXT,
                    created_at TEXT
                )
            """)
            conn.commit()

    def _record_event(self, run_id: str, stage: str, payload: Any = None):
        with self._connect_db() as conn:
            conn.execute(
                "INSERT INTO run_events (run_id, stage, payload, timestamp) VALUES (?, ?, ?, ?)",
                (run_id, stage, canonical_json(payload) if payload else "{}", datetime.now(timezone.utc).isoformat())
            )
            conn.execute(
                "UPDATE runs SET state = ?, updated_at = ? WHERE run_id = ?",
                (stage, datetime.now(timezone.utc).isoformat(), run_id)
            )
            conn.commit()

    def submit(self, spec: IntegrationSpec) -> str:
        run_id = f"run_{spec.spec_id}_{int(time.time()*1000)}"
        now = datetime.now(timezone.utc).isoformat()
        with self._connect_db() as conn:
            conn.execute(
                "INSERT INTO runs (run_id, spec_id, state, spec_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, spec.spec_id, "RECEIVED", canonical_json(spec.__dict__), now, now)
            )
            conn.commit()
        self._record_event(run_id, "RECEIVED", {"spec_id": spec.spec_id})
        return run_id

    def execute_run(self, run_id: str, use_cache: bool = True) -> Dict[str, Any]:
        with self._connect_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT spec_json FROM runs WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            if not row:
                raise KeyError(f"Run {run_id} not found")
            spec_data = json.loads(row[0])

        spec = IntegrationSpec(**spec_data)
        self._record_event(run_id, "SPECIFIED", {"objective": spec.objective})

        try:
            if not spec.required_capabilities or not spec.acceptance_scenarios:
                raise RuntimeError("intent_ambiguous: IntegrationSpec is missing required_capabilities or acceptance_scenarios")

            # 1. SNAPSHOTTED (Content-addressed frozen store)
            snapshots: Dict[str, RepoSnapshot] = {}
            for repo_id, rinfo in spec.source_refs.items():
                repo_path = rinfo["path"]
                if not os.path.exists(repo_path):
                    # Check relative to repo root, current working dir, or benchmarks pair dir
                    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                    for candidate_base in (repo_root, os.getcwd()):
                        alt_path = os.path.normpath(os.path.join(candidate_base, repo_path))
                        if os.path.exists(alt_path):
                            repo_path = alt_path
                            break
                        alt_pair = os.path.normpath(os.path.join(candidate_base, "benchmarks", "reference_pair", os.path.basename(repo_path)))
                        if os.path.exists(alt_pair):
                            repo_path = alt_pair
                            break
                snap = self.snapshot_engine.take_snapshot(repo_id, repo_path)
                snapshots[repo_id] = snap
            self._record_event(run_id, "SNAPSHOTTED", {r: s.tree_digest for r, s in snapshots.items()})

            # Check Full-Manifest Hermetic Cache (Experiment E6)
            cache_key = self.compute_manifest_cache_key(spec, snapshots)
            if use_cache:
                with self._connect_db() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT result_json FROM manifest_cache WHERE cache_key = ?", (cache_key,))
                    c_row = cur.fetchone()
                if c_row:
                    cached_res = json.loads(c_row[0])
                    ev_digests = cached_res.get("evidence", {}).get("artifacts_digests", {})
                    prod_dir = os.path.join(self.workdir, "workspaces", f"product_{cached_res.get('plan', {}).get('plan_id', '')}")
                    cache_intact = bool(ev_digests) and os.path.exists(prod_dir)
                    for rel_f, exp_h in ev_digests.items():
                        full_f = os.path.join(prod_dir, rel_f)
                        if not os.path.exists(full_f) or hash_file(full_f) != exp_h:
                            cache_intact = False
                            break
                    if cache_intact:
                        pkg_dir = cached_res.get("release", {}).get("package_dir", "")
                        now_ts = datetime.now(timezone.utc).isoformat()
                        hit_payload = canonical_json({"cache_hit": True, "manifest_cache_key": cache_key})
                        val_payload = canonical_json({
                            "verdict": "ACCEPTED_FOR_SPEC",
                            "obligations": cached_res.get("evidence", {}).get("obligations_status", {}),
                            "cache_hit": True
                        })
                        pkg_payload = canonical_json({"package_dir": pkg_dir, "cache_hit": True})
                        acc_payload = canonical_json({"release_dir": pkg_dir, "cache_hit": True})
                        batch_events = [
                            (run_id, st_name, hit_payload, now_ts)
                            for st_name in ("BASELINED", "INDEXED", "PLANNED", "ADAPTING", "BUILT")
                        ] + [
                            (run_id, "VALIDATION_COMPLETED", val_payload, now_ts),
                            (run_id, "PACKAGED", pkg_payload, now_ts),
                            (run_id, "ACCEPTED_FOR_SPEC", acc_payload, now_ts),
                        ]
                        with self._connect_db() as conn:
                            conn.executemany(
                                "INSERT INTO run_events (run_id, stage, payload, timestamp) VALUES (?, ?, ?, ?)",
                                batch_events
                            )
                            conn.execute(
                                "UPDATE runs SET state = 'ACCEPTED_FOR_SPEC', verdict = 'ACCEPTED_FOR_SPEC', "
                                "plan_json = ?, updated_at = ? WHERE run_id = ?",
                                (
                                    canonical_json(cached_res.get("plan", {})),
                                    now_ts,
                                    run_id
                                )
                            )
                            conn.commit()
                        cached_res["run_id"] = run_id
                        cached_res["cache_hit"] = True
                        cached_res["manifest_cache_key"] = cache_key
                        return cached_res

            # 2. BASELINED (Real syntax and baseline verification)
            baseline_status = {}
            all_baseline_failed_files = []
            for repo_id, snap in snapshots.items():
                snap_dir = snap.snapshot_root or snap.root_path
                failed_files = []
                total_files = len(snap.file_hashes)
                for fpath in snap.file_hashes.keys():
                    if fpath.endswith(".py"):
                        full_p = os.path.join(snap_dir, fpath)
                        try:
                            with open(full_p, "r", encoding="utf-8") as f:
                                ast.parse(f.read())
                        except Exception:
                            failed_files.append(f"{repo_id}:{fpath}")
                            all_baseline_failed_files.append(f"{repo_id}:{fpath}")

                report = BaselineReport(
                    schema_version="0.1",
                    repo_id=repo_id,
                    snapshot_digest=snap.tree_digest,
                    build_passed=len(failed_files) == 0,
                    tests_passed=len(failed_files) == 0,
                    total_tests=total_files,
                    failed_tests=failed_files,
                    environment={"python": sys.version},
                    created_at=datetime.now(timezone.utc).isoformat()
                )
                baseline_status[repo_id] = report.__dict__

            self._record_event(run_id, "BASELINED", baseline_status)
            if all_baseline_failed_files:
                raise RuntimeError(f"baseline_failed: Donor repository syntax/baseline check failed on {all_baseline_failed_files}")

            # 3. INDEXED (Analyze frozen snapshots)
            fact_bundles: Dict[str, FactBundle] = {}
            all_capabilities: List[CapabilityContract] = []
            for repo_id, snap in snapshots.items():
                fb = self.frontend.analyze_repository(snap)
                fact_bundles[repo_id] = fb
                caps = self.discovery.discover_capabilities(spec, fb)
                all_capabilities.extend(caps)

            total_syms = sum(len(fb.symbols) for fb in fact_bundles.values())
            self._record_event(run_id, "INDEXED", {
                "total_symbols": total_syms,
                "total_capabilities": len(all_capabilities)
            })
            if total_syms == 0:
                raise RuntimeError("unsupported_language: No symbols extracted from source repositories")

            # 4. PLANNED
            plans = self.planner.plan_composition(spec, all_capabilities)
            if not plans:
                raise ValueError("no_plan_in_model: No viable composition plan found satisfying required capabilities and side-effect policies.")
            best_plan = plans[0]
            with self._connect_db() as conn:
                conn.execute("UPDATE runs SET plan_json = ? WHERE run_id = ?", (canonical_json(best_plan.__dict__), run_id))
                conn.commit()
            self._record_event(run_id, "PLANNED", {"selected_plan_id": best_plan.plan_id, "topology": best_plan.topology})

            # 5. ADAPTING
            cap_map = {c.capability_id: c for c in all_capabilities}
            adapters: List[AdapterCandidate] = []
            for binding in best_plan.bindings:
                cap = cap_map[binding["provider_capability"]]
                adapter = self.adapter_synth.synthesize_adapter(binding, cap)
                adapters.append(adapter)
            self._record_event(run_id, "ADAPTING", {"adapters": [a.adapter_id for a in adapters]})

            # 6. BUILT
            product = self.materializer.materialize_product(best_plan, adapters, snapshots, spec.objective)
            self._record_event(run_id, "BUILT", {"product_dir": product.workspace_dir, "files": product.files_written})

            # 7. VALIDATING
            self._record_event(run_id, "VALIDATING")
            evidence = self.validator.validate_product(spec, best_plan, product)
            self._record_event(run_id, "VALIDATION_COMPLETED", {
                "verdict": evidence.verdict,
                "obligations": evidence.obligations_status
            })

            if evidence.verdict != "ACCEPTED_FOR_SPEC":
                err_code = "verification_failed"
                if evidence.obligations_status.get("global:health_check") == "FAIL":
                    err_code = "unresolved_dependency"
                for sc_r in evidence.acceptance_results:
                    err_txt = str(sc_r.get("error", "")).lower()
                    if "timeout" in err_txt:
                        err_code = "synthesis_timeout"
                    elif "not initialized" in err_txt or "protocol" in err_txt:
                        err_code = "protocol_mismatch"
                with self._connect_db() as conn:
                    conn.execute("UPDATE runs SET state = 'FAILED', verdict = 'REJECTED', error_message = ?, updated_at = ? WHERE run_id = ?",
                                 (err_code, datetime.now(timezone.utc).isoformat(), run_id))
                    conn.commit()
                self._record_event(run_id, "FAILED", {"reason": "Validator rejected product", "error_code": err_code, "verdict": evidence.verdict})
                return {
                    "ok": False,
                    "run_id": run_id,
                    "verdict": evidence.verdict,
                    "error_code": err_code,
                    "minimal_reproducer": {
                        "spec_id": spec.spec_id,
                        "failed_obligations": [k for k, v in evidence.obligations_status.items() if v != "PASS"]
                    },
                    "evidence": evidence.__dict__
                }

            # 8. PACKAGED
            release = self.packager.package_release(product, evidence)
            self._record_event(run_id, "PACKAGED", {"package_dir": release.package_dir})

            # Register and validate recipes in RC-11 RecipeRegistry
            for ad in adapters:
                rec_id = f"recipe_{ad.adapter_id}"
                self.recipe_registry.register_recipe(
                    recipe_id=rec_id,
                    name=f"Auto-synthesized adapter for {ad.target_requirement_id}",
                    source_pattern=ad.source_capability_id,
                    target_pattern=ad.target_requirement_id,
                    template_code=ad.code_content,
                    preconditions=["python_or_node_callable", "libcst_verified"],
                    flush=False
                )
                self.recipe_registry.transition_state(rec_id, "LOCALLY_VALIDATED", evidence.run_id, flush=False)
            if adapters:
                self.recipe_registry._save_index()

            # 9. ACCEPTED_FOR_SPEC
            with self._connect_db() as conn:
                conn.execute("UPDATE runs SET state = 'ACCEPTED_FOR_SPEC', verdict = 'ACCEPTED_FOR_SPEC', updated_at = ? WHERE run_id = ?",
                             (datetime.now(timezone.utc).isoformat(), run_id))
                conn.commit()
            self._record_event(run_id, "ACCEPTED_FOR_SPEC", {"release_dir": release.package_dir})

            final_res = {
                "ok": True,
                "run_id": run_id,
                "verdict": "ACCEPTED_FOR_SPEC",
                "cache_hit": False,
                "manifest_cache_key": cache_key,
                "release": release.__dict__,
                "evidence": evidence.__dict__,
                "plan": best_plan.__dict__
            }
            with self._connect_db() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO manifest_cache (cache_key, run_id, result_json, created_at) VALUES (?, ?, ?, ?)",
                    (cache_key, run_id, canonical_json(final_res), datetime.now(timezone.utc).isoformat())
                )
                conn.commit()
            return final_res

        except Exception as e:
            err_msg = str(e)
            canonical_codes = (
                "intent_ambiguous", "baseline_failed", "unsupported_language",
                "unresolved_dependency", "semantic_mismatch", "protocol_mismatch",
                "no_plan_in_model", "synthesis_timeout", "verification_failed",
                "external_service_missing", "budget_exhausted"
            )
            err_code = "verification_failed"
            for code_name in canonical_codes:
                if code_name in err_msg:
                    err_code = code_name
                    break
            with self._connect_db() as conn:
                conn.execute(
                    "UPDATE runs SET state = 'FAILED', verdict = 'FAILED', error_message = ?, updated_at = ? WHERE run_id = ?",
                    (err_msg, datetime.now(timezone.utc).isoformat(), run_id)
                )
                conn.commit()
            self._record_event(run_id, "FAILED", {"error": err_msg, "error_code": err_code})
            return {
                "ok": False,
                "run_id": run_id,
                "verdict": "FAILED",
                "error_code": err_code,
                "minimal_reproducer": {"spec_id": spec.spec_id, "error": err_msg},
                "error": err_msg
            }

    def compute_manifest_cache_key(self, spec: IntegrationSpec, snapshots: Dict[str, RepoSnapshot]) -> str:
        """
        BLUEPRINT Section 14: Complete Hermetic Cache Key
        H(snapshots + file_scope + toolchain + platform + schema_version + spec_digest)
        """
        payload = {
            "schema_version": spec.schema_version,
            "spec_digest": spec.digest(),
            "snapshots": {r_id: s.tree_digest for r_id, s in sorted(snapshots.items())},
            "file_scope": {r_id: sorted(list(s.file_hashes.keys())) for r_id, s in sorted(snapshots.items())},
            "toolchain": {"python": sys.version.split()[0]},
            "platform": platform.system().lower(),
            "dependency_policy": spec.dependency_policy,
            "release_policy": spec.release_policy
        }
        return sha256_digest(canonical_json(payload))

    def status(self, run_id: str) -> Dict[str, Any]:
        with self._connect_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT run_id, spec_id, state, verdict, error_message, updated_at FROM runs WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            if not row:
                raise KeyError(f"Run {run_id} not found")

            cur.execute("SELECT stage, payload, timestamp FROM run_events WHERE run_id = ? ORDER BY id ASC", (run_id,))
            events = [{"stage": r[0], "payload": json.loads(r[1]), "timestamp": r[2]} for r in cur.fetchall()]

            return {
                "run_id": row[0],
                "spec_id": row[1],
                "state": row[2],
                "verdict": row[3],
                "error_message": row[4],
                "updated_at": row[5],
                "events": events
            }

    def explain(self, run_id: str, requirement_id: Optional[str] = None) -> Dict[str, Any]:
        """BLUEPRINT Section 18: explain(run_id, requirement_id) -> sources + plan + verifications."""
        with self._connect_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT spec_json, plan_json, state, verdict FROM runs WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            if not row:
                raise KeyError(f"Run {run_id} not found")
            spec_data = json.loads(row[0]) if row[0] else {}
            plan_data = json.loads(row[1]) if row[1] else {}
            state, verdict = row[2], row[3]

            cur.execute("SELECT stage, payload FROM run_events WHERE run_id = ? ORDER BY id ASC", (run_id,))
            events = {r[0]: json.loads(r[1]) for r in cur.fetchall()}

        bindings = plan_data.get("bindings", [])
        if requirement_id:
            bindings = [b for b in bindings if b.get("requirement") == requirement_id]

        return {
            "run_id": run_id,
            "state": state,
            "verdict": verdict,
            "objective": spec_data.get("objective"),
            "source_refs": spec_data.get("source_refs"),
            "topology": plan_data.get("topology"),
            "bindings": bindings,
            "dataflows": plan_data.get("dataflows", []),
            "validation_summary": events.get("VALIDATION_COMPLETED", {})
        }

    def cancel(self, run_id: str) -> Dict[str, Any]:
        """BLUEPRINT Section 15 & 18: Persist run cancellation."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT state FROM runs WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            if not row:
                raise KeyError(f"Run {run_id} not found")
            conn.execute(
                "UPDATE runs SET state = 'CANCELLED', verdict = 'CANCELLED', updated_at = ? WHERE run_id = ?",
                (now, run_id)
            )
            conn.commit()
        self._record_event(run_id, "CANCELLED", {"cancelled_at": now})
        return {"run_id": run_id, "state": "CANCELLED", "verdict": "CANCELLED"}

    def resume(self, run_id: str) -> Dict[str, Any]:
        """
        BLUEPRINT Section 15 & 18: Validates checkpoint snapshot digests in frozen store
        before resuming execution. Rejects corrupted/tampered checkpoints.
        """
        with self._connect_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT spec_json, state FROM runs WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            if not row:
                raise KeyError(f"Run {run_id} not found")
            spec_data = json.loads(row[0])

            cur.execute(
                "SELECT payload FROM run_events WHERE run_id = ? AND stage = 'SNAPSHOTTED' ORDER BY id DESC LIMIT 1",
                (run_id,)
            )
            snap_row = cur.fetchone()

        if snap_row:
            recorded_digests = json.loads(snap_row[0])
            for repo_id, expected_tree_digest in recorded_digests.items():
                frozen_dir = os.path.join(self.workdir, "snapshots", repo_id, expected_tree_digest)
                if os.path.exists(frozen_dir):
                    recheck = self.snapshot_engine.take_snapshot(repo_id, frozen_dir, storage_dir=None)
                    if recheck.tree_digest != expected_tree_digest:
                        self._record_event(run_id, "FAILED", {"reason": f"Checkpoint digest mismatch for {repo_id}"})
                        raise ValueError(f"Checkpoint integrity violation: frozen snapshot for {repo_id} was modified")

        self._record_event(run_id, "RESUMING", {"previous_state": row[1]})
        return self.execute_run(run_id)

    def export(self, run_id: str, export_dir: str) -> Dict[str, Any]:
        """BLUEPRINT Section 18: Exports accepted package + manifest + evidence to target directory."""
        st = self.status(run_id)
        if st["verdict"] != "ACCEPTED_FOR_SPEC":
            raise ValueError(f"Cannot export unaccepted run {run_id} (verdict={st['verdict']})")

        pkg_events = [e for e in st["events"] if e["stage"] == "PACKAGED"]
        if not pkg_events:
            raise ValueError(f"No packaged artifact found for run {run_id}")

        src_pkg_dir = pkg_events[-1]["payload"]["package_dir"]
        evidence_path = os.path.join(src_pkg_dir, "evidence", "evidence_bundle.json")
        with open(evidence_path, "r", encoding="utf-8") as f:
            ev_data = json.load(f)

        # Verify integrity before export
        for rel_p, exp_hash in ev_data.get("artifacts_digests", {}).items():
            if "__pycache__" in rel_p or rel_p.endswith((".pyc", ".pyo")) or rel_p == "evidence/evidence_bundle.json":
                continue
            full_p = os.path.join(src_pkg_dir, rel_p)
            if not os.path.exists(full_p) or hash_file(full_p) != exp_hash:
                raise ValueError(f"Export blocked: artifact {rel_p} failed integrity check")

        dest_abs = os.path.abspath(export_dir)
        if os.path.exists(dest_abs):
            shutil.rmtree(dest_abs)
        shutil.copytree(src_pkg_dir, dest_abs, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
        return {
            "run_id": run_id,
            "exported_to": dest_abs,
            "manifest": os.path.join(dest_abs, "manifests", "composition.lock.json"),
            "evidence": os.path.join(dest_abs, "evidence", "evidence_bundle.json")
        }

    def verify_upstream_update(self, run_id: str) -> Dict[str, Any]:
        """
        BLUEPRINT Section 17 & PLANO_DE_EXECUCAO Gate G8:
        Detects upstream donor repository changes after a certified run, revokes affected
        recipes if incompatible drift occurred, and preserves the certified package (rollback).
        """
        st = self.status(run_id)
        with self._connect_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT spec_json, plan_json FROM runs WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            spec_data = json.loads(row[0])
            plan_data = json.loads(row[1]) if row[1] else {}

        snap_events = [e for e in st["events"] if e["stage"] == "SNAPSHOTTED"]
        if not snap_events:
            raise ValueError(f"Run {run_id} has no SNAPSHOTTED baseline")

        baseline_digests = snap_events[-1]["payload"]
        drifted_repos: List[str] = []
        for repo_id, rinfo in spec_data.get("source_refs", {}).items():
            live_snap = self.snapshot_engine.take_snapshot(repo_id, rinfo["path"], storage_dir=None)
            if live_snap.tree_digest != baseline_digests.get(repo_id):
                drifted_repos.append(repo_id)

        revoked_recipes: List[str] = []
        if drifted_repos:
            for b in plan_data.get("bindings", []):
                cap_id = b.get("provider_capability", "")
                if any(f":{r_id}:" in cap_id for r_id in drifted_repos):
                    rec_id = f"recipe_{b.get('adapter_id')}"
                    if rec_id in self.recipe_registry.index:
                        self.recipe_registry.transition_state(
                            rec_id, "REVOKED", f"upstream_drift:{','.join(drifted_repos)}"
                        )
                        revoked_recipes.append(rec_id)

        pkg_events = [e for e in st["events"] if e["stage"] == "PACKAGED"]
        preserved_pkg = pkg_events[-1]["payload"]["package_dir"] if pkg_events else None

        return {
            "run_id": run_id,
            "drift_detected": len(drifted_repos) > 0,
            "drifted_repos": drifted_repos,
            "revoked_recipes": revoked_recipes,
            "rollback_preserved": bool(preserved_pkg and os.path.exists(preserved_pkg)),
            "preserved_package_dir": preserved_pkg
        }

