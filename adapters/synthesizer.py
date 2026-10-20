"""
RC-07 Adapter Synthesizer: Implements the Adaptation Ladder (L0-L2)
Generates typed glue code, parameter translation, serialization, and error wrapping.
Verifies and formats generated code using Meta LibCST (Lossless Concrete Syntax Tree).
Supports isolated module loading, async coroutine resolution, and sanitized identifiers.
"""

from typing import Dict, Any, List
import libcst as cst
from contracts.models import CapabilityContract, AdapterCandidate


class AdapterSynthesizer:
    _ADAPTER_CACHE: Dict[Any, AdapterCandidate] = {}

    def __init__(self, schema_version: str = "0.1"):
        self.schema_version = schema_version

    def synthesize_adapter(
        self,
        binding: Dict[str, Any],
        capability: CapabilityContract
    ) -> AdapterCandidate:
        raw_adapter_id = binding["adapter_id"]
        # Sanitize identifier: replace hyphens and invalid chars with underscores
        safe_adapter_id = raw_adapter_id.replace("-", "_").replace(" ", "_").replace(".", "_")
        req_name = binding["requirement"]
        cache_key = (safe_adapter_id, req_name, capability.digest())
        if cache_key in self._ADAPTER_CACHE:
            return self._ADAPTER_CACHE[cache_key]
        entrypoint = capability.entrypoint
        op_name = entrypoint["operation"]
        file_path = entrypoint["file_path"].replace("\\", "/")
        repo_id = capability.source_repo_id
        safe_repo = repo_id.replace("-", "_").replace(".", "_")
        class_name = entrypoint.get("class_name")

        level = "L2"
        obligations = [
            {"id": f"ob_{safe_adapter_id}_typecheck", "description": "Adapter inputs and outputs match type contracts", "status": "PENDING", "engine": "Instagram/LibCST"},
            {"id": f"ob_{safe_adapter_id}_exception_safety", "description": "Adapter catches and maps unexpected errors without crash", "status": "PENDING", "engine": "Instagram/LibCST"},
            {"id": f"ob_{safe_adapter_id}_idempotency", "description": "Adapter does not induce side-effect leaks", "status": "PENDING", "engine": "Instagram/LibCST"}
        ]

        class_type_name = "".join(part.capitalize() for part in safe_adapter_id.split("_") if part)

        expected_params = list(capability.input_schema.keys())
        semantic_groups = [
            ["doc_id", "id", "document_id", "item_id", "record_id", "order_id", "event_id", "sensor_id", "tx_id"],
            ["content", "text", "body", "payload", "raw_text", "html", "data", "message", "stream_data"],
            ["tenant_id", "tenant", "org_id", "account_id", "workspace_id"],
            ["query", "q", "search_query", "keyword", "filter_term"],
            ["title", "name", "heading", "label"],
            ["amount", "value", "price", "subtotal", "metric_value", "reading"]
        ]
        alias_map: Dict[str, str] = {}
        for p_name in expected_params:
            for grp in semantic_groups:
                if p_name in grp:
                    for alias in grp:
                        if alias != p_name and alias not in expected_params:
                            alias_map[alias] = p_name

        lang = entrypoint.get("language", "python")
        is_node = lang in ("javascript", "typescript") or file_path.endswith((".js", ".ts"))

        if is_node:
            code_lines = [
                '"""',
                f'Auto-generated Polyglot Node.js/TypeScript Adapter: {safe_adapter_id}',
                f'Target Requirement: {req_name}',
                f'Source Capability: {capability.capability_id}',
                f'Language Runtime: {lang} (Node.js IPC Bridge)',
                'Synthesized & Verified by: Meta LibCST Concrete Syntax Tree Engine',
                '"""',
                '',
                'from typing import Any, Dict',
                'import logging',
                'import json',
                'import os',
                'import shutil',
                'import subprocess',
                '',
                f'logger = logging.getLogger("{safe_adapter_id}")',
                '',
                f'class {class_type_name}:',
                f'    _ALIAS_MAP = {repr(alias_map)}',
                f'    _EXPECTED_PARAMS = {repr(expected_params)}',
                '',
                '    def __init__(self, component_instance=None):',
                '        self.instance = component_instance',
                '        self._module = None',
                '        self._comp_file = None',
                '        self._load_provider()',
                '',
                '    def _load_provider(self):',
                '        if self.instance is not None:',
                '            return',
                '        current_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()',
                '        product_root = os.path.dirname(current_dir)',
                f'        comp_file = os.path.join(product_root, "components", "{repo_id}", "{file_path}")',
                '        if not os.path.exists(comp_file):',
                '            comp_file = os.path.abspath("' + file_path + '")',
                '        if os.path.exists(comp_file):',
                '            self._comp_file = comp_file',
                f'            self._module = {{"kind": "node_callable", "file": comp_file, "operation": "{op_name}"}}',
                '',
                '    def execute(self, **kwargs) -> Any:',
                '        """Executes polyglot JavaScript/TypeScript capability via isolated Node.js bridge."""',
                '        try:',
                '            if not self._comp_file or not os.path.exists(self._comp_file):',
                f'                raise ModuleNotFoundError("Node provider missing for operation \'{op_name}\'")',
                '            translated_kwargs = {}',
                '            for k, v in kwargs.items():',
                '                mapped_key = self._ALIAS_MAP.get(k, k)',
                '                translated_kwargs[mapped_key] = v',
                '            for k in translated_kwargs:',
                '                if self._EXPECTED_PARAMS and k not in self._EXPECTED_PARAMS:',
                f'                    raise TypeError(f"{op_name}() got an unexpected keyword argument \'{{k}}\'")',
                '            ordered_args = [translated_kwargs.get(p) for p in self._EXPECTED_PARAMS]',
                '            node_bin = shutil.which("node") or r"C:\\Program Files\\nodejs\\node.exe"',
                '            if not os.path.exists(node_bin):',
                '                raise RuntimeError("Node.js runtime not found")',
                '            js_runner = (',
                '                "const path = require(\'path\'); const { pathToFileURL } = require(\'url\');\\n"',
                '                "(async () => {\\n"',
                '                "  const fileUrl = pathToFileURL(process.env.RC_COMP_FILE).href;\\n"',
                '                "  let mod; try { mod = require(process.env.RC_COMP_FILE); } catch (e) { mod = await import(fileUrl); }\\n"',
                f'                "  const fn = mod[\'{op_name}\'] || (mod.default && mod.default[\'{op_name}\']);\\n"',
                '                "  if (typeof fn !== \'function\') { throw new Error(\'Missing JS/TS function\'); }\\n"',
                '                "  const args = JSON.parse(process.env.RC_ARGS_JSON);\\n"',
                '                "  const out = await fn(...args);\\n"',
                '                "  console.log(\'NODE_JSON_OUT:\' + JSON.stringify({ result: out }));\\n"',
                '                "})().catch(err => { console.error(err); process.exit(1); });"',
                '            )',
                '            env = os.environ.copy()',
                '            env["RC_COMP_FILE"] = self._comp_file',
                '            env["RC_ARGS_JSON"] = json.dumps(ordered_args)',
                '            cmd = [node_bin]',
                '            if self._comp_file.endswith(".ts"):',
                '                cmd.extend(["--experimental-strip-types", "--no-warnings"])',
                '            cmd.extend(["-e", js_runner])',
                '            proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=15)',
                '            if proc.returncode != 0:',
                '                raise RuntimeError(f"Node execution failed: {proc.stderr}")',
                '            for line in proc.stdout.splitlines():',
                '                if line.startswith("NODE_JSON_OUT:"):',
                '                    return json.loads(line[len("NODE_JSON_OUT:"):])["result"]',
                '            raise RuntimeError("Node bridge produced no JSON output")',
                '        except KeyError as ke:',
                '            raise KeyError(str(ke)) from ke',
                '        except TypeError as te:',
                '            logger.error(f"Parameter mismatch in adapter execution: {te}")',
                '            raise ValueError(f"Invalid parameters supplied to adapter: {te}") from te',
                '        except Exception as e:',
                '            logger.error(f"Adapter execution failed: {e}")',
                '            raise RuntimeError(f"Underlying capability failed: {e}") from e',
                ''
            ]
        else:
            code_lines = [
                '"""',
                f'Auto-generated Adapter: {safe_adapter_id}',
                f'Target Requirement: {req_name}',
                f'Source Capability: {capability.capability_id}',
                f'Adaptation Level: {level}',
                'Synthesized & Verified by: Meta LibCST Concrete Syntax Tree Engine',
                '"""',
                '',
                'from typing import Any, Dict, Optional',
                'import logging',
                'import importlib.util',
                'import inspect',
                'import asyncio',
                'import os',
                'import sys',
                '',
                f'logger = logging.getLogger("{safe_adapter_id}")',
                '',
                f'class {class_type_name}:',
                f'    _ALIAS_MAP = {repr(alias_map)}',
                '',
                '    def __init__(self, component_instance=None):',
                '        self.instance = component_instance',
                '        self._module = None',
                '        self._comp_dir = None',
                '        self._scoped_modules = {}',
                '        self._sibling_names = set()',
                '        self._load_provider()',
                '',
                '    def _enter_scope(self):',
                '        saved_sys_mods = {}',
                '        if self._comp_dir:',
                '            if self._comp_dir not in sys.path:',
                '                sys.path.insert(0, self._comp_dir)',
                '            for s_name in self._sibling_names:',
                '                if s_name in sys.modules:',
                '                    saved_sys_mods[s_name] = sys.modules.pop(s_name)',
                '                if s_name in self._scoped_modules:',
                '                    sys.modules[s_name] = self._scoped_modules[s_name]',
                '        return saved_sys_mods',
                '',
                '    def _exit_scope(self, saved_sys_mods):',
                '        if self._comp_dir:',
                '            for s_name in self._sibling_names:',
                '                if s_name in sys.modules:',
                '                    self._scoped_modules[s_name] = sys.modules.pop(s_name)',
                '                if s_name in saved_sys_mods:',
                '                    sys.modules[s_name] = saved_sys_mods[s_name]',
                '            if self._comp_dir in sys.path:',
                '                sys.path.remove(self._comp_dir)',
                '',
                '    def _load_provider(self):',
                '        if self.instance is not None:',
                '            return',
                '        current_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()',
                '        product_root = os.path.dirname(current_dir)',
                f'        comp_file = os.path.join(product_root, "components", "{repo_id}", "{file_path}")',
                '        if not os.path.exists(comp_file):',
                '            comp_file = os.path.abspath("' + file_path + '")',
                '        ',
                '        if os.path.exists(comp_file):',
                '            self._comp_dir = os.path.dirname(comp_file)',
                '            for fn in os.listdir(self._comp_dir):',
                '                if fn.endswith(".py") and fn != "__init__.py":',
                '                    self._sibling_names.add(fn[:-3])',
                '            saved_mods = self._enter_scope()',
                '            try:',
                f'                base_clean = os.path.basename(comp_file)[:-3]',
                f'                mod_name = f"comp_{safe_repo}_{{base_clean}}"',
                '                spec = importlib.util.spec_from_file_location(mod_name, comp_file)',
                '                if spec and spec.loader:',
                '                    mod = importlib.util.module_from_spec(spec)',
                '                    sys.modules[mod_name] = mod',
                '                    spec.loader.exec_module(mod)',
                '                    self._module = mod',
            ]

            if class_name:
                code_lines.extend([
                    f'                    cls = getattr(self._module, "{class_name}", None)',
                    '                    if cls:',
                    '                        self.instance = cls()',
                ])

            code_lines.extend([
                '            finally:',
                '                self._exit_scope(saved_mods)',
                '',
                '    def _ensure_initialized(self, target):',
                '        if target is None:',
                '            return',
                '        if getattr(target, "_initialized", True) is False or getattr(target, "is_initialized", True) is False:',
                '            for init_name in ("initialize", "connect", "setup", "open_session"):',
                '                init_fn = getattr(target, init_name, None)',
                '                if callable(init_fn):',
                '                    init_fn()',
                '                    break',
                '',
                '    def execute(self, **kwargs) -> Any:',
                '        """Executes adapted capability with scoped dependency isolation, protocol auto-init, and semantic parameter translation."""',
                '        saved_mods = self._enter_scope()',
                '        try:',
                '            fn = None',
                '            target = None',
                f'            if self.instance and hasattr(self.instance, "{op_name}"):',
                '                target = self.instance',
                f'                fn = getattr(self.instance, "{op_name}")',
                f'            elif self._module and hasattr(self._module, "{op_name}"):',
                '                target = self._module',
                f'                fn = getattr(self._module, "{op_name}")',
                '            else:',
                f'                raise ModuleNotFoundError(f"Provider {{self.instance or self._module}} missing operation \'{op_name}\'")',
                '            ',
                '            self._ensure_initialized(target)',
                '            ',
                '            # Semantic L2 parameter translation for known schema aliases',
                '            translated_kwargs = {}',
                '            for k, v in kwargs.items():',
                '                mapped_key = self._ALIAS_MAP.get(k, k)',
                '                translated_kwargs[mapped_key] = v',
                '            ',
                '            # Invoke target function',
                '            result = fn(**translated_kwargs)',
                '            ',
                '            # If coroutine or async, resolve with asyncio.run',
                '            if inspect.iscoroutine(result):',
                '                try:',
                '                    loop = asyncio.get_event_loop()',
                '                    if loop.is_running():',
                '                        result = asyncio.run_coroutine_threadsafe(result, loop).result()',
                '                    else:',
                '                        result = loop.run_until_complete(result)',
                '                except RuntimeError:',
                '                    result = asyncio.run(result)',
                '            ',
                '            return result',
                '        except KeyError as ke:',
                '            raise KeyError(str(ke)) from ke',
                '        except TypeError as te:',
                '            logger.error(f"Parameter mismatch in adapter execution: {te}")',
                '            raise ValueError(f"Invalid parameters supplied to adapter: {te}") from te',
                '        except Exception as e:',
                '            logger.error(f"Adapter execution failed: {e}")',
                '            raise RuntimeError(f"Underlying capability failed: {e}") from e',
                '        finally:',
                '            self._exit_scope(saved_mods)',
                ''
            ])

        raw_code = "\n".join(code_lines)
        # Validate and serialize via Meta LibCST lossless Concrete Syntax Tree
        cst_tree = cst.parse_module(raw_code)
        code_content = cst_tree.code

        cand = AdapterCandidate(
            schema_version=self.schema_version,
            adapter_id=safe_adapter_id,
            level=level,
            source_capability_id=capability.capability_id,
            target_requirement_id=req_name,
            file_name=f"{safe_adapter_id}.py",
            code_content=code_content,
            obligations=obligations
        )
        self._ADAPTER_CACHE[cache_key] = cand
        return cand

