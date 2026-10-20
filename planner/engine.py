"""
RC-06 Composition Planner: Generates and ranks composition plans
connecting capabilities across repositories according to the IntegrationSpec.
Uses Potassco Clingo (Answer Set Programming / ASP Solver) to enforce hard constraints,
side effect boundaries, and requirement-to-capability matching, and Microsoft Z3 (SMT Solver)
to formally verify and synthesize cross-repository dataflows (A -> B).
"""

from typing import List, Dict, Any, Optional, Tuple
import clingo
import z3
from contracts.models import IntegrationSpec, CapabilityContract, CompositionPlan, sha256_digest


class CompositionPlanner:
    _Z3_FLOW_CACHE: Dict[Any, Optional[Dict[str, Any]]] = {}

    def __init__(self, schema_version: str = "0.1"):
        self.schema_version = schema_version

    def _solve_with_clingo_asp(
        self,
        spec: IntegrationSpec,
        capabilities: List[CapabilityContract]
    ) -> Optional[Dict[str, CapabilityContract]]:
        """
        Uses Potassco Clingo ASP Solver (same engine as Spack) to solve
        Requirements <-> Capabilities under hard side-effect constraints.
        Returns None if UNSATISFIABLE.
        """
        if not spec.required_capabilities:
            return {}

        cap_by_idx: Dict[int, CapabilityContract] = {}
        req_by_idx: Dict[int, str] = {}
        asp_lines: List[str] = [
            "% ---Repository Compiler ASP Composition Formulation (Clingo) ---",
            "#defined candidate/4.",
            "#defined cap_effect/2.",
            "#defined allowed_effect/1.",
            "{ chosen(R, C) : candidate(R, C, _, _) } = 1 :- req(R).",
            "% Hard Constraint: Forbidden side effects are strictly rejected",
            ":- chosen(R, C), cap_effect(C, E), not allowed_effect(E).",
            "% Lexicographic Optimization: 1. Match Tier (exact=1, substring=2), 2. Unknowns count",
            "#minimize { Tier@2, R, C : chosen(R, C), candidate(R, C, Tier, _) }.",
            "#minimize { Unk@1, R, C : chosen(R, C), candidate(R, C, _, Unk) }.",
            "#show chosen/2."
        ]

        for eff in spec.allowed_side_effects:
            safe_eff = eff.replace('"', '\\"')
            asp_lines.append(f'allowed_effect("{safe_eff}").')

        for c_idx, cap in enumerate(capabilities):
            cap_by_idx[c_idx] = cap
            for eff in cap.effects:
                safe_eff = eff.replace('"', '\\"')
                asp_lines.append(f'cap_effect({c_idx}, "{safe_eff}").')

        for r_idx, req in enumerate(spec.required_capabilities):
            req_by_idx[r_idx] = req
            asp_lines.append(f"req({r_idx}).")
            req_clean = req.strip().lower().replace("-", "_")

            exact_found = False
            for c_idx, c in enumerate(capabilities):
                op_name = str(c.entrypoint.get("operation", "")).lower()
                cap_id_clean = c.capability_id.split(":")[-1].lower().replace("-", "_")
                if op_name == req_clean or cap_id_clean == req_clean:
                    exact_found = True
                    asp_lines.append(f"candidate({r_idx}, {c_idx}, 1, {len(c.unknowns)}).")

            if not exact_found:
                for c_idx, c in enumerate(capabilities):
                    op_name = str(c.entrypoint.get("operation", "")).lower()
                    if req_clean in op_name:
                        asp_lines.append(f"candidate({r_idx}, {c_idx}, 2, {len(c.unknowns)}).")

        ctl = clingo.Control(["--opt-mode=optN"], logger=lambda code, msg: None)
        ctl.add("base", [], "\n".join(asp_lines))
        ctl.ground([("base", [])])

        best_model_pairs: List[Tuple[int, int]] = []
        is_sat = False

        def _on_model(model: clingo.Model):
            nonlocal best_model_pairs, is_sat
            is_sat = True
            pairs = []
            for sym in model.symbols(shown=True):
                if sym.name == "chosen" and len(sym.arguments) == 2:
                    r_i = sym.arguments[0].number
                    c_i = sym.arguments[1].number
                    pairs.append((r_i, c_i))
            best_model_pairs = pairs

        solve_result = ctl.solve(on_model=_on_model)
        if not solve_result.satisfiable or not is_sat:
            return None

        selected: Dict[str, CapabilityContract] = {}
        for r_i, c_i in best_model_pairs:
            selected[req_by_idx[r_i]] = cap_by_idx[c_i]

        if len(selected) != len(spec.required_capabilities):
            return None
        return selected

    def _synthesize_dataflow_with_z3_smt(
        self,
        ingest_cap: CapabilityContract,
        index_cap: CapabilityContract
    ) -> Optional[Dict[str, Any]]:
        """
        Uses Microsoft Z3 SMT Solver to verify and synthesize semantic parameter mapping
        between producer capability (A) and consumer capability (B).
        """
        # Semantic equivalence classes for field alignment
        semantic_groups = [
            {"doc_id", "id", "document_id", "item_id", "record_id", "order_id", "event_id", "sensor_id", "tx_id"},
            {"content", "text", "body", "payload", "raw_text", "html", "data", "message", "stream_data"},
            {"tenant_id", "tenant", "org_id", "account_id", "workspace_id"},
            {"amount", "value", "price", "subtotal", "metric_value", "reading"}
        ]

        def _semantically_compatible(s_f: str, t_f: str) -> bool:
            if s_f == t_f:
                return True
            for grp in semantic_groups:
                if s_f in grp and t_f in grp:
                    return True
            return False

        src_fields = list(ingest_cap.input_schema.keys()) or ["doc_id", "content", "tenant_id"]
        if index_cap.input_schema:
            tgt_fields = [
                k for k, v in index_cap.input_schema.items()
                if v.get("required", True) or any(_semantically_compatible(s_f, k) for s_f in src_fields)
            ]
        else:
            tgt_fields = ["doc_id", "text", "tenant_id"]

        cache_key = (
            ingest_cap.capability_id,
            index_cap.capability_id,
            ingest_cap.entrypoint["operation"],
            index_cap.entrypoint["operation"],
            tuple(src_fields),
            tuple(tgt_fields)
        )
        if cache_key in self._Z3_FLOW_CACHE:
            cached = self._Z3_FLOW_CACHE[cache_key]
            return dict(cached) if cached else None

        solver = z3.SolverFor("QF_FD")
        # Decision variables: bind[t_f][s_f] is Bool indicating source field s_f feeds target field t_f
        bind_vars: Dict[str, Dict[str, z3.BoolRef]] = {}

        for t_f in tgt_fields:
            bind_vars[t_f] = {}
            compatible_vars = []
            for s_f in src_fields:
                v = z3.Bool(f"bind_{t_f}_from_{s_f}")
                bind_vars[t_f][s_f] = v
                if _semantically_compatible(s_f, t_f):
                    compatible_vars.append(v)
                else:
                    solver.add(z3.Not(v))

            # Every required target field MUST be satisfied by exactly one compatible source field
            if not compatible_vars:
                self._Z3_FLOW_CACHE[cache_key] = None
                return None
            solver.add(z3.PbEq([(cv, 1) for cv in compatible_vars], 1))

        if solver.check() != z3.sat:
            self._Z3_FLOW_CACHE[cache_key] = None
            return None

        model = solver.model()
        synthesized_mapping: Dict[str, str] = {}
        for t_f in tgt_fields:
            for s_f in src_fields:
                if z3.is_true(model.evaluate(bind_vars[t_f][s_f])):
                    synthesized_mapping[s_f] = t_f

        flow_res = {
            "source_capability": ingest_cap.capability_id,
            "target_capability": index_cap.capability_id,
            "source_operation": ingest_cap.entrypoint["operation"],
            "target_operation": index_cap.entrypoint["operation"],
            "mapping": synthesized_mapping,
            "smt_verified": True,
            "smt_solver": "Z3Prover/z3"
        }
        self._Z3_FLOW_CACHE[cache_key] = flow_res
        return dict(flow_res)

    def plan_composition(
        self,
        spec: IntegrationSpec,
        capabilities: List[CapabilityContract]
    ) -> List[CompositionPlan]:
        # Solve Requirements <-> Capabilities + Hard Side-Effect Constraints via Clingo ASP
        selected_capabilities = self._solve_with_clingo_asp(spec, capabilities)
        if selected_capabilities is None:
            return []

        # Synthesize and formally verify multi-repo dataflow opportunities via Z3 SMT Solver
        dataflows: List[Dict[str, Any]] = []
        producer_keywords = (
            "ingest", "save", "synthesize", "compile", "slice", "parse", "normalize",
            "scrub", "collect", "create", "produce", "emit", "connect", "encode", "record"
        )
        consumer_keywords = (
            "index", "audit", "analyze", "compute", "generate_sbom", "scan", "evolve",
            "sanitize", "render", "aggregate", "sink", "encrypt", "process", "verify",
            "tokenize", "score", "calculate", "reorder"
        )

        producers = []
        consumers = []
        for req, cap in selected_capabilities.items():
            req_low = req.lower()
            if any(k in req_low for k in producer_keywords):
                producers.append(cap)
            elif any(k in req_low for k in consumer_keywords) and "search" not in req_low and "get_" not in req_low:
                consumers.append(cap)

        for prod_cap in producers:
            for cons_cap in consumers:
                if prod_cap.source_repo_id != cons_cap.source_repo_id:
                    df = self._synthesize_dataflow_with_z3_smt(prod_cap, cons_cap)
                    if df:
                        dataflows.append(df)

        plans: List[CompositionPlan] = []
        repo_ids = list(spec.source_refs.keys())
        topologies = ["NEW_SHELL"]
        if len(repo_ids) >= 2:
            topologies.extend(["A_HOSTS_B", "B_HOSTS_A"])

        for topo in topologies:
            bindings = []
            adapters_needed = []
            unknown_penalty = 0.0

            for req in spec.required_capabilities:
                selected_cap = selected_capabilities[req]
                safe_req = req.replace("-", "_")
                safe_repo = selected_cap.source_repo_id.replace("-", "_")
                adapter_id = f"adapter_{safe_repo}_{safe_req}"

                bindings.append({
                    "requirement": req,
                    "provider_capability": selected_cap.capability_id,
                    "adapter_id": adapter_id,
                    "entrypoint": selected_cap.entrypoint
                })
                adapters_needed.append(adapter_id)
                unknown_penalty += len(selected_cap.unknowns) * 1.5

            topo_bonus = 5.0 if topo == "NEW_SHELL" else 0.0
            dataflow_bonus = 10.0 if dataflows else 0.0
            rank_score = 100.0 + topo_bonus + dataflow_bonus - unknown_penalty

            components_role = {}
            if topo == "NEW_SHELL":
                for rid in repo_ids:
                    components_role[f"component_{rid}"] = rid
            elif topo == "A_HOSTS_B":
                components_role["host"] = repo_ids[0]
                components_role["guest"] = repo_ids[1] if len(repo_ids) > 1 else repo_ids[0]
            elif topo == "B_HOSTS_A":
                components_role["host"] = repo_ids[1] if len(repo_ids) > 1 else repo_ids[0]
                components_role["guest"] = repo_ids[0]

            plan_id = f"plan_{topo.lower()}_{sha256_digest(topo + str(bindings))[:8]}"

            plan = CompositionPlan(
                schema_version=self.schema_version,
                plan_id=plan_id,
                topology=topo,
                components=components_role,
                bindings=bindings,
                adapters_needed=adapters_needed,
                isolation_mode="MODULE",
                runtime_config={
                    "env": "local",
                    "timeout_seconds": spec.budget.get("timeout_seconds", 30),
                    "asp_solver": "potassco/clingo",
                    "smt_solver": "Z3Prover/z3"
                },
                resolved_requirements=list(spec.required_capabilities),
                risks=[],
                rank_score=rank_score,
                dataflows=dataflows
            )
            plans.append(plan)

        plans.sort(key=lambda p: p.rank_score, reverse=True)
        return plans

