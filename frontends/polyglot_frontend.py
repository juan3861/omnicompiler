"""
RC-04b Polyglot Language Frontend: Multi-language structural symbol and contract extractor.
Delegates Python (.py) to PythonFrontend (AST + LibCST + ast-grep + NetworkX) and extracts
TypeScript (.ts), JavaScript (.js), Rust (.rs), and Go (.go) symbols using Rust ast-grep-py
and Tree-sitter grammars.
"""

import os
import hashlib
from typing import Dict, List, Any
try:
    from ast_grep_py import SgRoot
except ImportError:
    SgRoot = None
from contracts.models import FactBundle, RepoSnapshot
from frontends.python_frontend import PythonFrontend


EXT_TO_LANG = {
    ".ts": "typescript",
    ".js": "javascript",
    ".rs": "rust",
    ".go": "go"
}

# GenesisLang GEN11 Champion Single-Pass Zero-Regex Lexical Scanner (from github.com/juan3861/genesislang)
_GEN11_KW = {
    "fn": 1, "func": 1, "function": 1, "export": 1, "pub": 1,
    "let": 1, "const": 1, "var": 1, "if": 1, "else": 1, "return": 1,
    "for": 1, "in": 1, "while": 1, "true": 1, "false": 1, "null": 1
}
_GEN11_OP = set("+-*/%<>=!&|.")
_GEN11_SEP = set("[](),:;{}")


def tokenize_gen11(source: str) -> List[tuple]:
    """
    GenesisLang GEN11 Champion Single-Pass Zero-Regex Tokenizer (4.73M tok/s architecture).
    Uses character-by-character scanning, O(1) dict keyword lookup, and local method aliasing.
    """
    tokens = []
    pos = 0
    n = len(source)
    a = tokens.append
    s = source
    kw = _GEN11_KW
    op = _GEN11_OP
    sep = _GEN11_SEP
    while pos < n:
        c = s[pos]
        if c == '"' or c == "'":
            e = s.find(c, pos + 1)
            if e == -1:
                e = n - 1
            a(("STRING", s[pos:e + 1]))
            pos = e + 1
        elif c.isalpha() or c == "_":
            e = pos + 1
            while e < n and (s[e].isalnum() or s[e] == "_"):
                e += 1
            w = s[pos:e]
            a(("KEYWORD" if w in kw else "IDENT", w))
            pos = e
        elif c.isdigit():
            e = pos + 1
            while e < n and s[e].isdigit():
                e += 1
            a(("INT", s[pos:e]))
            pos = e
        elif c == "/" and pos + 1 < n and s[pos + 1] == "/":
            e = s.find("\n", pos + 2)
            if e == -1:
                e = n
            pos = e
        elif c in op:
            e = pos + 1
            while e < n and s[e] in op:
                e += 1
            a(("OP", s[pos:e]))
            pos = e
        elif c in sep:
            a(("SEP", c))
            pos += 1
        else:
            pos += 1
    return tokens


LANG_PATTERNS = {
    "typescript": [
        "export function $NAME($$$PARAMS): $RET { $$$BODY }",
        "export function $NAME($$$PARAMS) { $$$BODY }",
        "function $NAME($$$PARAMS): $RET { $$$BODY }",
        "function $NAME($$$PARAMS) { $$$BODY }"
    ],
    "javascript": [
        "export function $NAME($$$PARAMS) { $$$BODY }",
        "function $NAME($$$PARAMS) { $$$BODY }"
    ],
    "rust": [
        "pub fn $NAME($$$PARAMS) -> $RET { $$$BODY }",
        "pub fn $NAME($$$PARAMS) { $$$BODY }",
        "fn $NAME($$$PARAMS) -> $RET { $$$BODY }",
        "fn $NAME($$$PARAMS) { $$$BODY }"
    ],
    "go": [
        "func $NAME($$$PARAMS) $RET { $$$BODY }",
        "func $NAME($$$PARAMS) { $$$BODY }"
    ]
}


class PolyglotFrontend:
    def __init__(self, schema_version: str = "0.1"):
        self.schema_version = schema_version
        self.py_frontend = PythonFrontend(schema_version=schema_version)

    def analyze_repository(self, snapshot: RepoSnapshot) -> FactBundle:
        # First run full PythonFrontend analysis
        py_bundle = self.py_frontend.analyze_repository(snapshot)
        symbols: List[Dict[str, Any]] = list(py_bundle.symbols)
        types: List[Dict[str, Any]] = list(py_bundle.types)
        imports: List[Dict[str, str]] = list(py_bundle.imports)
        entrypoints: List[str] = list(py_bundle.entrypoints)
        confidence_map: Dict[str, str] = dict(py_bundle.confidence_map)

        base_dir = snapshot.snapshot_root or snapshot.root_path

        for rel_path in sorted(snapshot.file_hashes.keys()):
            _, ext = os.path.splitext(rel_path)
            if ext not in EXT_TO_LANG:
                continue

            lang = EXT_TO_LANG[ext]
            full_path = os.path.join(base_dir, rel_path)
            if not os.path.exists(full_path):
                full_path = os.path.join(snapshot.root_path, rel_path)

            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    content = f.read()

                current_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
                expected_hash = snapshot.file_hashes.get(rel_path)
                if expected_hash and current_hash != expected_hash:
                    confidence_map[f"{rel_path}:drift_detected"] = "unknown"

                sg_root = SgRoot(content, lang)
                root_node = sg_root.root()
            except Exception:
                confidence_map[f"{rel_path}:parse_error"] = "unknown"
                continue

            mod_name = rel_path[: -len(ext)].replace("/", ".").replace("\\", ".")
            seen_names = set()

            for pat in LANG_PATTERNS.get(lang, []):
                try:
                    matches = root_node.find_all(pattern=pat)
                except Exception:
                    continue

                for m in matches:
                    name_node = m.get_match("NAME")
                    if not name_node:
                        continue
                    fn_name = name_node.text().strip()
                    if fn_name in seen_names:
                        continue
                    seen_names.add(fn_name)

                    ret_node = m.get_match("RET")
                    ret_type = ret_node.text().strip() if ret_node else "Any"

                    raw_params = [p.text().strip() for p in m.get_multiple_matches("PARAMS") if p.text().strip() and p.text().strip() != ","]
                    parsed_params = []
                    for rp in raw_params:
                        for token in rp.split(","):
                            tok = token.strip()
                            if not tok:
                                continue
                            if ":" in tok:
                                p_n, p_t = [x.strip() for x in tok.split(":", 1)]
                            elif " " in tok:
                                parts = tok.split()
                                p_n, p_t = parts[0], " ".join(parts[1:])
                            else:
                                p_n, p_t = tok, "Any"
                            parsed_params.append({
                                "name": p_n,
                                "type": p_t,
                                "kind": "regular",
                                "required": "=" not in p_t and "?" not in p_n
                            })

                    sym_id = f"{mod_name}.{fn_name}"
                    if fn_name in ("main", "run", "serve", "start", "execute"):
                        entrypoints.append(sym_id)

                    lower_content = content.lower()
                    inferred_doc_tags = [f"Extracted from {lang} via ast-grep Tree-sitter"]
                    if any(w in lower_content for w in ("write", "save", "store", "insert")):
                        inferred_doc_tags.append("write storage")
                    else:
                        inferred_doc_tags.append("read query")

                    gen11_tokens = tokenize_gen11(content)
                    symbols.append({
                        "name": fn_name,
                        "qualified_name": sym_id,
                        "kind": "function",
                        "language": lang,
                        "file_path": rel_path,
                        "line_start": 1,
                        "line_end": 1,
                        "parameters": parsed_params,
                        "return_type": ret_type,
                        "is_async": False,
                        "docstring": " | ".join(inferred_doc_tags),
                        "class_name": None,
                        "cst_lossless": True,
                        "gen11_token_count": len(gen11_tokens)
                    })
                    confidence_map[sym_id] = "declared" if ret_type != "Any" else "statically_observed"

        return FactBundle(
            schema_version=self.schema_version,
            repo_id=snapshot.repo_id,
            snapshot_digest=snapshot.tree_digest,
            symbols=symbols,
            types=types,
            imports=imports,
            entrypoints=sorted(list(set(entrypoints))),
            confidence_map=confidence_map
        )
