"""
RC-08 Materializer Engine: Materializes the synthesized product into a fresh,
isolated workspace adhering to the canonical product directory structure.
Strictly isolates sources, registers component manifests, synthesizes dataflows,
and writes isolated adapters.
"""

import os
import shutil
import json
from datetime import datetime, timezone
from typing import List, Dict, Any
from contracts.models import (
    CompositionPlan, AdapterCandidate, RepoSnapshot, ProductCandidate,
    canonical_json, sha256_digest
)
from slicer.capsule_extractor import CapsuleExtractor


class MaterializerEngine:
    def __init__(self, base_workspace_dir: str, schema_version: str = "0.1"):
        self.base_workspace_dir = os.path.abspath(base_workspace_dir)
        self.schema_version = schema_version
        self.capsule_extractor = CapsuleExtractor()

    def materialize_product(
        self,
        plan: CompositionPlan,
        adapters: List[AdapterCandidate],
        snapshots: Dict[str, RepoSnapshot],
        spec_objective: str
    ) -> ProductCandidate:
        product_id = f"product_{plan.plan_id}"
        product_dir = os.path.join(self.base_workspace_dir, product_id)

        # Standard blueprint structure
        subdirs = [
            "app", "components", "adapters", "config",
            "tests", "run", "manifests", "evidence"
        ]
        for sub in subdirs:
            os.makedirs(os.path.join(product_dir, sub), exist_ok=True)

        files_written: List[str] = []

        # 1. Copy source components from frozen snapshot_root into components/
        for repo_id, snapshot in snapshots.items():
            comp_dest = os.path.join(product_dir, "components", repo_id)
            if os.path.exists(comp_dest):
                shutil.rmtree(comp_dest)

            src_root = snapshot.snapshot_root or snapshot.root_path

            def _ignore(path, names):
                return {n for n in names if n in (".git", "__pycache__", ".pytest_cache")}

            shutil.copytree(src_root, comp_dest, ignore=_ignore, copy_function=shutil.copyfile)
            files_written.append(f"components/{repo_id}")

        # 1b. Apply Cross-File Surgical Capsule Slicing (LibCST + NetworkX) per component repo
        ops_by_repo_and_file: Dict[str, Dict[str, set]] = {}
        for b in plan.bindings:
            ep = b.get("entrypoint", {})
            f_rel = ep.get("file_path", "").replace("\\", "/")
            op_name = ep.get("operation", "")
            cls_name = ep.get("class_name")
            cap_id = b.get("provider_capability", "")
            parts = cap_id.split(":")
            r_id = parts[1] if len(parts) >= 3 else ""
            if r_id and f_rel and op_name:
                repo_ops = ops_by_repo_and_file.setdefault(r_id, {})
                file_ops = repo_ops.setdefault(f_rel, set())
                file_ops.add(cls_name or op_name)
                file_ops.add(op_name)

        slicing_reports: Dict[str, Any] = {}
        for r_id, entry_map in ops_by_repo_and_file.items():
            py_entry_map = {f_k: ops for f_k, ops in entry_map.items() if f_k.endswith(".py")}
            comp_root = os.path.join(product_dir, "components", r_id)
            if os.path.exists(comp_root) and py_entry_map:
                repo_slice_res = self.capsule_extractor.extract_repository_capsule(
                    comp_root=comp_root,
                    entry_ops_by_rel_path=py_entry_map,
                    prune_unreferenced_files=True
                )
                slicing_reports[r_id] = repo_slice_res

        # 2. Write synthesized adapters into adapters/
        adapters_init = os.path.join(product_dir, "adapters", "__init__.py")
        with open(adapters_init, "w", encoding="utf-8") as f:
            f.write("# Auto-generated adapters package\nfrom pkgutil import extend_path\n__path__ = extend_path(__path__, __name__)\n")
        files_written.append("adapters/__init__.py")

        for ad in adapters:
            ad_path = os.path.join(product_dir, "adapters", ad.file_name)
            with open(ad_path, "w", encoding="utf-8") as f:
                f.write(ad.code_content)
            files_written.append(f"adapters/{ad.file_name}")

        # 3. Write unified application shell in app/
        app_main = os.path.join(product_dir, "app", "main.py")
        main_content = self._generate_main_app(plan, adapters, snapshots, spec_objective)
        with open(app_main, "w", encoding="utf-8") as f:
            f.write(main_content)
        files_written.append("app/main.py")

        app_init = os.path.join(product_dir, "app", "__init__.py")
        with open(app_init, "w", encoding="utf-8") as f:
            f.write("# Main app package\n")
        files_written.append("app/__init__.py")

        # 4. Write operational scripts in run/
        start_script = os.path.join(product_dir, "run", "start.py")
        with open(start_script, "w", encoding="utf-8") as f:
            f.write(self._generate_start_script())
        files_written.append("run/start.py")

        health_script = os.path.join(product_dir, "run", "health.py")
        with open(health_script, "w", encoding="utf-8") as f:
            f.write(self._generate_health_script())
        files_written.append("run/health.py")

        # 5. Write composition manifest and WIT (WebAssembly Interface Types) contract in manifests/
        manifest_data = {
            "schema_version": self.schema_version,
            "product_id": product_id,
            "plan_digest": plan.digest(),
            "topology": plan.topology,
            "components": {rid: s.tree_digest for rid, s in snapshots.items()},
            "adapters": [ad.adapter_id for ad in adapters],
            "dataflows": plan.dataflows,
            "slicing_reports": slicing_reports,
            "engines": [
                "potassco/clingo",
                "Z3Prover/z3",
                "Instagram/LibCST",
                "ast-grep/ast-grep",
                "bytecodealliance/wasmtime"
            ],
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        manifest_file = os.path.join(product_dir, "manifests", "composition.lock.json")
        with open(manifest_file, "w", encoding="utf-8") as f:
            f.write(canonical_json(manifest_data))
        files_written.append("manifests/composition.lock.json")

        wit_file = os.path.join(product_dir, "manifests", "component_world.wit")
        wit_lines = [
            f"// Auto-generated WebAssembly Component Model (WIT) Contract for {product_id}",
            "// Compatible with bytecodealliance/wac (wac plug / wac compose) and wasmtime",
            "package aethermind:unified-product@0.1.0;",
            "",
            "interface capabilities {"
        ]
        for b in plan.bindings:
            wit_op = b["requirement"].replace("_", "-").lower()
            wit_lines.append(f"  {wit_op}: func(payload: string) -> result<string, string>;")
        wit_lines.extend([
            "}",
            "",
            "world unified-product {",
            "  export capabilities;",
            "}"
        ])
        with open(wit_file, "w", encoding="utf-8") as f:
            f.write("\n".join(wit_lines) + "\n")
        files_written.append("manifests/component_world.wit")

        # 6. Write README.md
        readme_file = os.path.join(product_dir, "README.md")
        with open(readme_file, "w", encoding="utf-8") as f:
            f.write(f"# Unified Product: {product_id}\n\nObjective: {spec_objective}\nTopology: {plan.topology}\n")
        files_written.append("README.md")

        return ProductCandidate(
            schema_version=self.schema_version,
            product_id=product_id,
            plan_digest=plan.digest(),
            workspace_dir=product_dir,
            files_written=files_written,
            entrypoint_script=app_main,
            created_at=datetime.now(timezone.utc).isoformat()
        )

    def _generate_main_app(
        self,
        plan: CompositionPlan,
        adapters: List[AdapterCandidate],
        snapshots: Dict[str, RepoSnapshot],
        objective: str
    ) -> str:
        lines = [
            '"""',
            f'Unified Product Application Entrypoint',
            f'Topology: {plan.topology}',
            f'Objective: {objective}',
            '"""',
            '',
            'import sys',
            'import os',
            'from typing import Any, Dict',
            '',
            '# Ensure product root and adapters are on sys.path',
            'CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))',
            'PRODUCT_ROOT = os.path.dirname(CURRENT_DIR)',
            'if PRODUCT_ROOT not in sys.path:',
            '    sys.path.insert(0, PRODUCT_ROOT)',
            'if os.path.join(PRODUCT_ROOT, "adapters") not in sys.path:',
            '    sys.path.insert(0, os.path.join(PRODUCT_ROOT, "adapters"))',
            '',
            'class UnifiedProduct:',
            '    def __init__(self):',
            '        self.adapters = {}',
            f'        self.dataflows = {repr(plan.dataflows)}',
            '        self._initialize_adapters()',
            '',
            '    def _initialize_adapters(self):',
        ]

        for ad in adapters:
            class_type_name = "".join(part.capitalize() for part in ad.adapter_id.split("_") if part)
            mod_name = ad.adapter_id
            lines.append(f'        from adapters.{mod_name} import {class_type_name}')
            lines.append(f'        self.adapters["{ad.target_requirement_id}"] = {class_type_name}()')

        lines.extend([
            '',
            '    def execute_capability(self, capability_name: str, **kwargs) -> Any:',
            '        if capability_name not in self.adapters:',
            '            raise KeyError(f"Capability \'{capability_name}\' is not registered in unified product")',
            '        ',
            '        # Primary capability execution',
            '        result = self.adapters[capability_name].execute(**kwargs)',
            '        ',
            '        # Automatic dataflow propagation (e.g. Ingest -> Index)',
            '        for flow in self.dataflows:',
            '            src_op = flow.get("source_operation", "")',
            '            tgt_op = flow.get("target_operation", "")',
            '            if capability_name == src_op or flow.get("source_capability", "").endswith(capability_name):',
            '                if tgt_op in self.adapters:',
            '                    # Map parameters from result or kwargs',
            '                    target_kwargs = {}',
            '                    mapping = flow.get("mapping", {})',
            '                    for src_field, tgt_field in mapping.items():',
            '                        val = None',
            '                        if isinstance(result, dict):',
            '                            val = result.get(src_field)',
            '                            if val is None and "record" in result and isinstance(result["record"], dict):',
            '                                val = result["record"].get(src_field)',
            '                        if val is None:',
            '                            val = kwargs.get(src_field)',
            '                        if val is not None:',
            '                            target_kwargs[tgt_field] = val',
            '                    ',
            '                    try:',
            '                        flow_res = self.adapters[tgt_op].execute(**target_kwargs)',
            '                        if isinstance(result, dict):',
            '                            result.setdefault("dataflow_outputs", {})[tgt_op] = flow_res',
            '                    except Exception as flow_err:',
            '                        # Dataflow failure must be logged or raised',
            '                        raise RuntimeError(f"Chained dataflow to {tgt_op} failed: {flow_err}") from flow_err',
            '        ',
            '        return result',
            '',
            '    def health_check(self) -> Dict[str, Any]:',
            '        # Actively test that registered adapters resolve',
            '        for name, adapter in self.adapters.items():',
            '            if getattr(adapter, "instance", None) is None and getattr(adapter, "_module", None) is None:',
            '                raise RuntimeError(f"Adapter \'{name}\' failed to load underlying provider")',
            '        return {',
            '            "status": "HEALTHY",',
            '            "registered_capabilities": list(self.adapters.keys())',
            '        }',
            '',
            'if __name__ == "__main__":',
            '    app = UnifiedProduct()',
            '    print("Product initialized successfully.")',
            '    print("Health:", app.health_check())',
            ''
        ])

        return "\n".join(lines)

    def _generate_start_script(self) -> str:
        return (
            "import sys, os\n"
            "sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))\n"
            "from app.main import UnifiedProduct\n"
            "if __name__ == '__main__':\n"
            "    app = UnifiedProduct()\n"
            "    print('Product running with status:', app.health_check()['status'])\n"
        )

    def _generate_health_script(self) -> str:
        return (
            "import sys, os, json\n"
            "sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))\n"
            "from app.main import UnifiedProduct\n"
            "if __name__ == '__main__':\n"
            "    try:\n"
            "        app = UnifiedProduct()\n"
            "        print(json.dumps(app.health_check()))\n"
            "    except Exception as e:\n"
            "        print(json.dumps({'status': 'UNHEALTHY', 'error': str(e)}))\n"
            "        sys.exit(1)\n"
        )
