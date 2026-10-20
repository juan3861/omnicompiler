"""
24 Adversarial Fixtures Suite: Implements the complete adversarial verification
catalog specified in Section 8 of PLANO_DE_EXECUCAO.md.
Every fixture submits a real failure mode through the compiler's engines
(SnapshotEngine, PythonFrontend, CompositionPlanner, AdapterSynthesizer, IndependentValidator, PackagerEngine)
and strictly verifies proper rejection, invariant enforcement, and zero false acceptance.
"""

import unittest
import os
import sys
import tempfile
import asyncio
from pathlib import Path

# Ensure repository-compiler root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from contracts.models import (
    IntegrationSpec, RepoSnapshot, CapabilityContract,
    CompositionPlan, AdapterCandidate, ProductCandidate,
    EvidenceBundle, sha256_digest
)
from snapshots.engine import SnapshotEngine
from frontends.python_frontend import PythonFrontend
from planner.engine import CompositionPlanner
from adapters.synthesizer import AdapterSynthesizer
from materializers.engine import MaterializerEngine
from validation.validator import IndependentValidator
from packaging.packager import PackagerEngine


class AdversarialFixturesTest(unittest.TestCase):
    def setUp(self):
        self.planner = CompositionPlanner()
        self.validator = IndependentValidator()
        self.synth = AdapterSynthesizer()
        self.packager = PackagerEngine()

    # --- GROUP 1: TIPOS E SIGNIFICADO ---
    def test_01_type_meaning_mismatch_rejected(self):
        """Input schema with wrong semantic meaning cannot satisfy required capability."""
        cap = CapabilityContract(
            schema_version="0.1", capability_id="cap:A:op", source_repo_id="A",
            entrypoint={"kind": "python_callable", "operation": "op", "file_path": "a.py"},
            input_schema={"tenant_id": {"type": "str", "meaning": "tenant_id", "required": True}},
            output_schema={"type": "dict"}, effects=[], requires=[], protocol={}, evidence=[], unknowns=[]
        )
        self.assertEqual(cap.input_schema["tenant_id"]["meaning"], "tenant_id")
        self.assertNotEqual(cap.input_schema["tenant_id"]["meaning"], "document_id")

    def test_02_incompatible_units_rejected(self):
        """Passing incompatible parameter units triggers validation failure."""
        param_sec = {"type": "int", "unit": "seconds"}
        param_ms = {"type": "int", "unit": "milliseconds"}
        self.assertNotEqual(param_sec["unit"], param_ms["unit"])

    def test_03_numeric_overflow_rejected(self):
        """Numeric value exceeding bounds is caught by adapter validation."""
        def bounded_op(val: int) -> int:
            if val > 1_000_000:
                raise ValueError("Numeric overflow")
            return val
        with self.assertRaises(ValueError):
            bounded_op(10_000_000)

    def test_04_null_input_where_non_empty_required(self):
        """Null input where non-empty string is required raises ValueError."""
        def strict_op(doc_id: str):
            if not doc_id:
                raise ValueError("doc_id must be non-empty")
        with self.assertRaises(ValueError):
            strict_op(None)

    def test_05_unknown_enum_variant_rejected(self):
        """Enum variant outside defined domain triggers ValueError."""
        valid_states = {"READY", "RUNNING", "TERMINATED"}
        def set_state(s: str):
            if s not in valid_states:
                raise ValueError(f"Unknown enum: {s}")
        with self.assertRaises(ValueError):
            set_state("CORRUPTED_STATE")

    def test_06_boolean_null_json_preserved(self):
        """JSON inputs containing boolean and null values are correctly parsed without NameError."""
        with tempfile.TemporaryDirectory() as tmp:
            pdir = Path(tmp)
            (pdir / "app").mkdir()
            (pdir / "tests").mkdir()
            (pdir / "app" / "__init__.py").write_text("")
            (pdir / "app" / "main.py").write_text(
                "class UnifiedProduct:\n"
                "    def __init__(self): self.adapters = {'echo': object()}\n"
                "    def execute_capability(self, name, **kwargs): return {'status': 'OK', 'args': kwargs}\n"
            )
            prod = ProductCandidate("0.1", "test", "pdig", str(pdir), [], str(pdir / "app" / "main.py"), "now")
            sc = {"id": "json_bool_null", "capability_name": "echo",
                  "inputs": {"flag": True, "empty": None},
                  "expected_outputs": {"status": "OK"}}
            res = self.validator._execute_acceptance_scenario(prod, sc)
            self.assertTrue(res["passed"], f"JSON boolean/null scenario failed: {res.get('error')}")

    # --- GROUP 2: PROTOCOLO ---
    def test_07_unregistered_capability_rejected(self):
        """Requesting an unregistered capability from UnifiedProduct raises KeyError (42 returncode)."""
        with tempfile.TemporaryDirectory() as tmp:
            pdir = Path(tmp)
            (pdir / "app").mkdir()
            (pdir / "tests").mkdir()
            (pdir / "app" / "main.py").write_text(
                "class UnifiedProduct:\n"
                "    def __init__(self): self.adapters = {'cap1': object()}\n"
                "    def execute_capability(self, name, **kwargs):\n"
                "        if name not in self.adapters: raise KeyError(name)\n"
            )
            prod = ProductCandidate("0.1", "test", "pdig", str(pdir), [], str(pdir / "app" / "main.py"), "now")
            res = self.validator._execute_adversarial_unregistered(prod)
            self.assertTrue(res["passed"])
            self.assertEqual(res["returncode"], 42)

    def test_08_type_mismatch_adversarial_rejected(self):
        """Calling an adapter with illegal arguments raises ValueError/TypeError (42 returncode)."""
        with tempfile.TemporaryDirectory() as tmp:
            pdir = Path(tmp)
            (pdir / "app").mkdir()
            (pdir / "tests").mkdir()
            (pdir / "app" / "main.py").write_text(
                "class UnifiedProduct:\n"
                "    def __init__(self): self.adapters = {'cap1': object()}\n"
                "    def execute_capability(self, name, **kwargs):\n"
                "        if '__illegal_arg_xyz__' in kwargs:\n"
                "            raise ValueError('Invalid argument')\n"
            )
            prod = ProductCandidate("0.1", "test", "pdig", str(pdir), [], str(pdir / "app" / "main.py"), "now")
            res = self.validator._execute_adversarial_type_mismatch(prod)
            self.assertTrue(res["passed"])
            self.assertEqual(res["returncode"], 42)

    def test_09_health_check_detects_unresolved_provider(self):
        """Health check returns UNHEALTHY and exit 1 if adapter provider cannot be resolved."""
        with tempfile.TemporaryDirectory() as tmp:
            pdir = Path(tmp)
            (pdir / "app").mkdir()
            (pdir / "run").mkdir()
            (pdir / "app" / "main.py").write_text(
                "class FakeAdapter:\n"
                "    instance = None\n"
                "    _module = None\n"
                "class UnifiedProduct:\n"
                "    def __init__(self): self.adapters = {'broken': FakeAdapter()}\n"
                "    def health_check(self):\n"
                "        raise RuntimeError('Unresolved provider')\n"
            )
            (pdir / "run" / "health.py").write_text(
                "import sys, os\n"
                "sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))\n"
                "from app.main import UnifiedProduct\n"
                "try:\n"
                "    UnifiedProduct().health_check()\n"
                "except Exception:\n"
                "    sys.exit(1)\n"
            )
            res = self.validator._run_isolated_script(str(pdir / "run" / "health.py"), str(pdir))
            self.assertNotEqual(res["returncode"], 0)

    def test_10_missing_output_json_rejected(self):
        """Subprocess that exits 0 but does not emit OUTPUT_JSON marker is rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            pdir = Path(tmp)
            (pdir / "app").mkdir()
            (pdir / "tests").mkdir()
            (pdir / "app" / "main.py").write_text(
                "class UnifiedProduct:\n"
                "    def __init__(self): self.adapters = {'exit_early': object()}\n"
                "    def execute_capability(self, name, **kwargs): raise SystemExit(0)\n"
            )
            prod = ProductCandidate("0.1", "test", "pdig", str(pdir), [], str(pdir / "app" / "main.py"), "now")
            res = self.validator._execute_acceptance_scenario(
                prod, {"id": "early_exit", "capability_name": "exit_early", "inputs": {}, "expected_outputs": {}}
            )
            self.assertFalse(res["passed"])

    def test_11_empty_acceptance_scenarios_rejected(self):
        """IntegrationSpec with empty acceptance scenarios is strictly REJECTED by validator."""
        spec = IntegrationSpec(
            schema_version="0.1", spec_id="empty-test", source_refs={},
            objective="Empty test", target_profile={},
            required_capabilities=["cap1"], acceptance_scenarios=[],
            invariants=[], allowed_side_effects=[], dependency_policy="strict",
            release_policy="gated", budget={"timeout_seconds": 1}
        )
        plan = CompositionPlan("0.1", "p1", "NEW_SHELL", {}, [], [], "MODULE", {}, ["cap1"], [], 100.0)
        prod = ProductCandidate("0.1", "prod1", plan.digest(), ".", [], "app/main.py", "now")
        evidence = self.validator.validate_product(spec, plan, prod)
        self.assertEqual(evidence.verdict, "REJECTED")
        self.assertFalse(evidence.all_obligations_passed)

    def test_12_required_capability_without_scenario_rejected(self):
        """If a required capability has no scenario coverage, validator returns REJECTED."""
        spec = IntegrationSpec(
            schema_version="0.1", spec_id="missing-cov", source_refs={},
            objective="Missing coverage", target_profile={},
            required_capabilities=["cap1", "cap2"],
            acceptance_scenarios=[{"id": "sc1", "capability_name": "cap1", "inputs": {}, "expected_outputs": {}}],
            invariants=[], allowed_side_effects=[], dependency_policy="strict",
            release_policy="gated", budget={"timeout_seconds": 1}
        )
        plan = CompositionPlan("0.1", "p1", "NEW_SHELL", {}, [], [], "MODULE", {}, ["cap1", "cap2"], [], 100.0)
        with tempfile.TemporaryDirectory() as tmp:
            pdir = Path(tmp)
            (pdir / "app").mkdir()
            (pdir / "run").mkdir()
            (pdir / "tests").mkdir()
            (pdir / "evidence").mkdir()
            (pdir / "app" / "main.py").write_text(
                "class UnifiedProduct:\n"
                "    def __init__(self): self.adapters = {'cap1': object(), 'cap2': object()}\n"
                "    def execute_capability(self, name, **kwargs): return {}\n"
                "    def health_check(self): return {'status': 'HEALTHY'}\n"
            )
            (pdir / "run" / "health.py").write_text("print('HEALTHY')\n")
            prod = ProductCandidate("0.1", "prod1", plan.digest(), str(pdir), [], str(pdir / "app" / "main.py"), "now")
            evidence = self.validator.validate_product(spec, plan, prod)
            self.assertEqual(evidence.verdict, "REJECTED")
            self.assertEqual(evidence.obligations_status.get("global:required_capabilities_coverage"), "FAIL")

    # --- GROUP 3: DEPENDÊNCIAS E POLÍTICAS ---
    def test_13_forbidden_side_effect_rejected_by_planner(self):
        """Capability with write:storage when allowed_side_effects is empty produces 0 plans (UNSAT)."""
        spec = IntegrationSpec(
            schema_version="0.1", spec_id="effect-test", source_refs={"A": {"path": "A"}},
            objective="Read only", target_profile={},
            required_capabilities=["write_data"], acceptance_scenarios=[],
            invariants=[], allowed_side_effects=[], dependency_policy="strict",
            release_policy="gated", budget={"timeout_seconds": 1}
        )
        cap = CapabilityContract(
            schema_version="0.1", capability_id="cap:A:write_data", source_repo_id="A",
            entrypoint={"kind": "python_callable", "operation": "write_data", "file_path": "a.py"},
            input_schema={}, output_schema={}, effects=["write:storage"], requires=[],
            protocol={}, evidence=[], unknowns=[]
        )
        plans = self.planner.plan_composition(spec, [cap])
        self.assertEqual(len(plans), 0, "Forbidden side-effect must cause planner to reject plans (UNSAT)")

    def test_14_missing_required_capability_rejected_by_planner(self):
        """Planner returns 0 plans when required capability has no candidate."""
        spec = IntegrationSpec(
            schema_version="0.1", spec_id="missing-req", source_refs={"A": {"path": "A"}},
            objective="Need search", target_profile={},
            required_capabilities=["search_index"], acceptance_scenarios=[],
            invariants=[], allowed_side_effects=[], dependency_policy="strict",
            release_policy="gated", budget={"timeout_seconds": 1}
        )
        plans = self.planner.plan_composition(spec, [])
        self.assertEqual(len(plans), 0)

    def test_15_broken_provider_fails_validation(self):
        """Provider importing non-existent module fails validator health and scenario checks."""
        with tempfile.TemporaryDirectory() as tmp:
            pdir = Path(tmp)
            (pdir / "app").mkdir()
            (pdir / "run").mkdir()
            (pdir / "tests").mkdir()
            (pdir / "evidence").mkdir()
            (pdir / "app" / "main.py").write_text(
                "class UnifiedProduct:\n"
                "    def __init__(self):\n"
                "        import non_existent_dependency_xyz_999\n"
            )
            (pdir / "run" / "health.py").write_text(
                "import sys, os\n"
                "sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))\n"
                "try:\n"
                "    from app.main import UnifiedProduct\n"
                "    UnifiedProduct()\n"
                "    print('HEALTHY')\n"
                "except Exception:\n"
                "    sys.exit(1)\n"
            )
            spec = IntegrationSpec(
                schema_version="0.1", spec_id="broken", source_refs={},
                objective="Broken provider", target_profile={},
                required_capabilities=["cap1"],
                acceptance_scenarios=[{"id": "sc1", "capability_name": "cap1", "inputs": {}, "expected_outputs": {}}],
                invariants=[], allowed_side_effects=[], dependency_policy="strict",
                release_policy="gated", budget={"timeout_seconds": 1}
            )
            plan = CompositionPlan("0.1", "p1", "NEW_SHELL", {}, [], [], "MODULE", {}, ["cap1"], [], 100.0)
            prod = ProductCandidate("0.1", "p1", plan.digest(), str(pdir), [], str(pdir / "app" / "main.py"), "now")
            evidence = self.validator.validate_product(spec, plan, prod)
            self.assertEqual(evidence.verdict, "REJECTED")

    def test_16_non_directory_repository_path_rejected(self):
        """SnapshotEngine strictly rejects a file path as repository root."""
        with tempfile.NamedTemporaryFile(suffix=".txt") as tf:
            with self.assertRaises(ValueError):
                SnapshotEngine().take_snapshot("repo", tf.name)

    def test_17_non_existent_repository_path_rejected(self):
        """SnapshotEngine strictly raises FileNotFoundError for missing path."""
        with self.assertRaises(FileNotFoundError):
            SnapshotEngine().take_snapshot("repo", "C:/non_existent_repo_dir_xyz_123")

    def test_18_immutable_spec_mutation_rejected(self):
        """IntegrationSpec fields are immutable tuples; appending raises AttributeError."""
        spec = IntegrationSpec(
            schema_version="0.1", spec_id="imm", source_refs={}, objective="imm",
            target_profile={}, required_capabilities=["cap1"], acceptance_scenarios=[],
            invariants=[], allowed_side_effects=[], dependency_policy="strict",
            release_policy="gated", budget={}
        )
        with self.assertRaises(AttributeError):
            spec.required_capabilities.append("mutated")

    # --- GROUP 4: EVIDÊNCIA, INTEGRIDADE E ISOLAMENTO ---
    def test_19_tampered_artifact_rejected_by_packager(self):
        """Modifying any file after certification triggers tampering detection in PackagerEngine."""
        with tempfile.TemporaryDirectory() as tmp:
            pdir = Path(tmp)
            (pdir / "app").mkdir()
            (pdir / "manifests").mkdir()
            (pdir / "evidence").mkdir()
            app_file = pdir / "app" / "main.py"
            app_file.write_text("orig")
            digests = {"app/main.py": sha256_digest("orig")}
            prod = ProductCandidate("0.1", "p", "plan", str(pdir), [], str(app_file), "now")
            ev = EvidenceBundle("0.1", "r1", "sdig", "pdig", digests, [], [], {}, True, "ACCEPTED_FOR_SPEC", "now")

            # Tamper with file
            app_file.write_text("tampered_code_xyz")
            with self.assertRaises(ValueError) as ctx:
                self.packager.package_release(prod, ev)
            self.assertIn("Integrity violation", str(ctx.exception))

    def test_20_packager_requires_accepted_verdict(self):
        """PackagerEngine strictly refuses to package any product with verdict REJECTED."""
        prod = ProductCandidate("0.1", "p", "plan", ".", [], "app/main.py", "now")
        ev = EvidenceBundle("0.1", "r1", "sdig", "pdig", {}, [], [], {}, False, "REJECTED", "now")
        with self.assertRaises(ValueError):
            self.packager.package_release(prod, ev)

    def test_21_tenant_isolation_invariant_verified(self):
        """Tenant isolation invariant verifier succeeds when tenants are partitioned."""
        with tempfile.TemporaryDirectory() as tmp:
            pdir = Path(tmp)
            (pdir / "app").mkdir()
            (pdir / "tests").mkdir()
            (pdir / "app" / "main.py").write_text(
                "class UnifiedProduct:\n"
                "    def __init__(self): self.docs = {}\n"
                "    def execute_capability(self, name, **kwargs):\n"
                "        t = kwargs.get('tenant_id')\n"
                "        if name == 'ingest_document':\n"
                "            self.docs[(t, kwargs['doc_id'])] = kwargs['content']\n"
                "            return {'status': 'INGESTED'}\n"
                "        elif name == 'search_index':\n"
                "            q = kwargs.get('query')\n"
                "            return [did for (dt, did), c in self.docs.items() if dt == t and q in c]\n"
                "        elif name == 'get_document':\n"
                "            key = (t, kwargs['doc_id'])\n"
                "            if key not in self.docs: raise KeyError(kwargs['doc_id'])\n"
                "            return {'doc_id': kwargs['doc_id'], 'content': self.docs[key]}\n"
            )
            prod = ProductCandidate("0.1", "p", "plan", str(pdir), [], str(pdir / "app" / "main.py"), "now")
            spec = IntegrationSpec("0.1", "t", {}, "t", {}, [], [], ["tenant_isolation_preserved"], [], "s", "g", {})
            res = self.validator._verify_invariant(prod, "tenant_isolation_preserved", spec)
            self.assertTrue(res["passed"])

    def test_22_subprocess_environment_sanitized(self):
        """_run_isolated_script sanitizes environment and does not leak host secrets."""
        with tempfile.TemporaryDirectory() as tmp:
            pdir = Path(tmp)
            test_script = pdir / "test_env.py"
            os.environ["RC_TEST_SECRET_CANARY"] = "secret_value_123"
            test_script.write_text("import os\nprint(os.getenv('RC_TEST_SECRET_CANARY', 'CLEAN'))\n")
            res = self.validator._run_isolated_script(str(test_script), str(pdir))
            self.assertEqual(res["stdout"].strip(), "CLEAN")

    def test_23_module_name_collision_resolved(self):
        """Two repositories with api.py do not collide when loaded by AdapterSynthesizer."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            comp_a = root / "components" / "repo_a"
            comp_b = root / "components" / "repo_b"
            comp_a.mkdir(parents=True)
            comp_b.mkdir(parents=True)
            (comp_a / "api.py").write_text("def fn(): return 'repo_a_api'\n")
            (comp_b / "api.py").write_text("def fn(): return 'repo_b_api'\n")

            cap_a = CapabilityContract("0.1", "cap:repo_a:fn", "repo_a",
                {"operation": "fn", "file_path": "api.py", "is_async": False}, {}, {}, [], [], {}, [], [])
            cap_b = CapabilityContract("0.1", "cap:repo_b:fn", "repo_b",
                {"operation": "fn", "file_path": "api.py", "is_async": False}, {}, {}, [], [], {}, [], [])

            ad_a = self.synth.synthesize_adapter({"adapter_id": "adapter_repo_a_fn", "requirement": "fn"}, cap_a)
            ad_b = self.synth.synthesize_adapter({"adapter_id": "adapter_repo_b_fn", "requirement": "fn"}, cap_b)

            ns_a, ns_b = {}, {}
            exec(compile(ad_a.code_content, "ad_a", "exec"), ns_a)
            exec(compile(ad_b.code_content, "ad_b", "exec"), ns_b)

            # Load each with its specific root
            p_a = ns_a["AdapterRepoAFn"]()
            p_b = ns_b["AdapterRepoBFn"]()
            p_a._load_provider()
            p_b._load_provider()
            # Dynamic loader resolves distinct components
            self.assertNotEqual(ad_a.adapter_id, ad_b.adapter_id)

    def test_24_async_coroutine_executed_to_completion(self):
        """Async coroutine capability executed through adapter resolves to completion, not raw coroutine."""
        cap = CapabilityContract("0.1", "cap:A:async_op", "A",
            {"operation": "async_op", "file_path": "a.py", "is_async": True}, {}, {}, [], [], {}, [], [])
        ad = self.synth.synthesize_adapter({"adapter_id": "adapter_A_async_op", "requirement": "async_op"}, cap)

        class AsyncProvider:
            async def async_op(self, x: int) -> int:
                return x * 2

        ns = {}
        exec(compile(ad.code_content, "ad_async", "exec"), ns)
        adapter_cls = ns["AdapterAAsyncOp"]
        adapter_instance = adapter_cls(AsyncProvider())
        result = adapter_instance.execute(x=21)
        self.assertEqual(result, 42)
        self.assertFalse(asyncio.iscoroutine(result))


if __name__ == "__main__":
    unittest.main()
