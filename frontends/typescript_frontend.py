"""
Alpha-C119: TypeScript AOT Native Compiler Frontend (`frontends/typescript_frontend.py`).

Supports `tsconfig.json` discovery, `export type` / `type` aliases, `export const`
compile-time constants, ES module `import { ... } from "./..."`, `interface` C-ABI
structs, and statically typed functions lowered directly into Omni-SSA -> Native x86-64/ARM64/LLVM.
"""

from __future__ import annotations

import ast
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from frontends.polyglot_ssa_lowering import PolyglotParseResult, lower_polyglot_source_to_ast


_TS_IMPORT_RE = re.compile(
    r"^\s*import\s+(?:type\s+)?(?:\{([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*))\s+from\s+[\"']([^\"']+)[\"']\s*;?\s*$",
    re.MULTILINE,
)
_TS_TYPE_ALIAS_RE = re.compile(
    r"^\s*(?:export\s+)?type\s+[A-Za-z_][A-Za-z0-9_]*(?:<[^>]+>)?\s*=\s*[^;]+;\s*$",
    re.MULTILINE,
)
_TS_CONST_EXPORT_RE = re.compile(
    r"^\s*export\s+const\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[A-Za-z0-9_<>\[\]| ]+)?\s*=\s*(-?(?:0x[0-9a-fA-F]+|\d+))\s*;\s*$",
    re.MULTILINE,
)


class TypeScriptFrontend:
    """Stateless-safe TypeScript AOT frontend targeting Omni-SSA IR."""

    @staticmethod
    def load_tsconfig(repo_path: str) -> Dict[str, Any]:
        ts_cfg = os.path.join(repo_path, "tsconfig.json")
        if not os.path.isfile(ts_cfg):
            return {}
        try:
            with open(ts_cfg, "r", encoding="utf-8") as f:
                raw = f.read()
            # Strip // and /* */ JSONC comments common in tsconfig.json
            cleaned = re.sub(r"/\*.*?\*/", "", raw, flags=re.S)
            cleaned = re.sub(r"(?m)^\s*//.*$", "", cleaned)
            data = json.loads(cleaned)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def preprocess_ts_source(source: str) -> Tuple[str, List[str], Dict[str, int]]:
        imported_specs: List[str] = []
        imported_syms: List[str] = []
        for m in _TS_IMPORT_RE.finditer(source):
            names_grp = m.group(1) or m.group(2) or ""
            mod_path = m.group(3)
            imported_specs.append(mod_path)
            for item in names_grp.split(","):
                item_s = item.strip()
                if item_s:
                    imported_syms.append(item_s.split(" as ", 1)[0].strip())

        const_map: Dict[str, int] = {}
        for cm in _TS_CONST_EXPORT_RE.finditer(source):
            cname = cm.group(1)
            cval = int(cm.group(2), 0)
            const_map[cname] = cval

        stripped = _TS_IMPORT_RE.sub("", source)
        stripped = _TS_TYPE_ALIAS_RE.sub("", stripped)
        # Preserve integer export const bindings cleanly via constant substitution in body lines
        stripped = _TS_CONST_EXPORT_RE.sub("", stripped)
        for cname, cval in const_map.items():
            stripped = re.sub(rf"\b{re.escape(cname)}\b", str(cval), stripped)

        return stripped, sorted(set(imported_syms + imported_specs)), const_map

    def compile_ts_source(self, source: str, file_path: str = "<module.ts>") -> PolyglotParseResult:
        clean_src, imp_list, const_map = self.preprocess_ts_source(source)
        res = lower_polyglot_source_to_ast(clean_src, language="typescript", file_path=file_path, strict=False)
        for cname, cval in sorted(const_map.items()):
            res.module.body.insert(
                0,
                ast.Assign(
                    targets=[ast.Name(id=cname, ctx=ast.Store(), lineno=1)],
                    value=ast.Constant(value=cval, lineno=1),
                    lineno=1,
                ),
            )
        for isym in imp_list:
            if isym not in res.imported_modules:
                res.imported_modules.append(isym)
        return res

    def ingest_workspace(self, repo_path: str) -> List[PolyglotParseResult]:
        results: List[PolyglotParseResult] = []
        ts_files: List[str] = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "dist", "build", ".venv")]
            for fn in sorted(files):
                if fn.endswith(".ts") and not fn.endswith(".d.ts"):
                    ts_files.append(os.path.join(root, fn))
        for fp in ts_files:
            with open(fp, "r", encoding="utf-8") as f:
                src = f.read()
            results.append(self.compile_ts_source(src, file_path=fp))
        return results
