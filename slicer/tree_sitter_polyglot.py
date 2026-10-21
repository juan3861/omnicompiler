"""
OmniCompiler Tree-Sitter Polyglot AST Engine.
Provides grammar-accurate multi-language syntax tree parsing and symbol extraction
for C/C++, Rust, and Python codebases without fragile regex heuristics.
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional

try:
    import tree_sitter_language_pack as tslp
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


def _make_symbol_signature(name: str, params: List[str], return_type: str, visibility: str, language: str, source_file: str):
    from orchestrator.repo_manifest_ingestor import SymbolSignature
    return SymbolSignature(
        name=name,
        params=params,
        return_type=return_type,
        visibility=visibility,
        language=language,
        source_file=source_file
    )


class TreeSitterPolyglotEngine:
    """
    Grammar-accurate multi-language parser and symbol signature extractor.
    Uses Tree-Sitter grammars for C, C++, Rust, and Python.
    """

    def __init__(self):
        self._c_parser = None
        self._rust_parser = None
        self._python_parser = None

        if TREE_SITTER_AVAILABLE:
            try:
                self._c_parser = tslp.get_parser("c")
            except Exception:
                pass
            try:
                self._rust_parser = tslp.get_parser("rust")
            except Exception:
                pass
            try:
                self._python_parser = tslp.get_parser("python")
            except Exception:
                pass

    @property
    def is_available(self) -> bool:
        return TREE_SITTER_AVAILABLE and self._c_parser is not None

    def parse_c_symbols(self, content: bytes, source_file: str = "") -> List[SymbolSignature]:
        """Extracts exported function prototypes and definitions from C/C++ source/headers."""
        if not self._c_parser:
            return []

        tree = self._c_parser.parse(content)
        signatures: List[SymbolSignature] = []

        def visit(node):
            if node.type in ("declaration", "function_definition"):
                decl = node.child_by_field_name("declarator")
                type_node = node.child_by_field_name("type")
                ret_type = type_node.text.decode("utf-8", errors="ignore") if type_node else "void"

                # Find innermost function_declarator
                curr_decl = decl
                while curr_decl and curr_decl.type != "function_declarator":
                    curr_decl = curr_decl.child_by_field_name("declarator")

                if curr_decl and curr_decl.type == "function_declarator":
                    fn_name_node = curr_decl.child_by_field_name("declarator")
                    fn_name = fn_name_node.text.decode("utf-8", errors="ignore") if fn_name_node else ""

                    params = []
                    params_node = curr_decl.child_by_field_name("parameters")
                    if params_node:
                        for p in params_node.children:
                            if p.type == "parameter_declaration":
                                p_decl = p.child_by_field_name("declarator")
                                if p_decl:
                                    # Handle pointer or simple identifier
                                    while p_decl.child_by_field_name("declarator"):
                                        p_decl = p_decl.child_by_field_name("declarator")
                                    params.append(p_decl.text.decode("utf-8", errors="ignore"))

                    if fn_name:
                        signatures.append(_make_symbol_signature(
                            name=fn_name,
                            params=params,
                            return_type=ret_type,
                            visibility="public",
                            language="c",
                            source_file=source_file
                        ))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return signatures

    def parse_rust_symbols(self, content: bytes, source_file: str = "") -> List[SymbolSignature]:
        """Extracts public functions and signatures from Rust source files."""
        if not self._rust_parser:
            return []

        tree = self._rust_parser.parse(content)
        signatures: List[SymbolSignature] = []

        def visit(node):
            if node.type == "function_item":
                is_pub = False
                for c in node.children:
                    if c.type == "visibility_modifier" and "pub" in c.text.decode("utf-8", errors="ignore"):
                        is_pub = True
                        break

                name_node = node.child_by_field_name("name")
                ret_node = node.child_by_field_name("return_type")
                params_node = node.child_by_field_name("parameters")

                fn_name = name_node.text.decode("utf-8", errors="ignore") if name_node else ""
                ret_type = ret_node.text.decode("utf-8", errors="ignore").lstrip("->").strip() if ret_node else "()"

                params = []
                if params_node:
                    for p in params_node.children:
                        if p.type == "parameter":
                            p_name = p.child_by_field_name("pattern")
                            if p_name:
                                params.append(p_name.text.decode("utf-8", errors="ignore"))

                if fn_name and is_pub:
                    signatures.append(_make_symbol_signature(
                        name=fn_name,
                        params=params,
                        return_type=ret_type,
                        visibility="public",
                        language="rust",
                        source_file=source_file
                    ))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return signatures

    def parse_python_symbols(self, content: bytes, source_file: str = "") -> List[SymbolSignature]:
        """Extracts public functions and signatures from Python source files."""
        if not self._python_parser:
            return []

        tree = self._python_parser.parse(content)
        signatures: List[SymbolSignature] = []

        def visit(node):
            if node.type == "function_definition":
                name_node = node.child_by_field_name("name")
                fn_name = name_node.text.decode("utf-8", errors="ignore") if name_node else ""

                if fn_name and not fn_name.startswith("_"):
                    ret_node = node.child_by_field_name("return_type")
                    ret_type = ret_node.text.decode("utf-8", errors="ignore").lstrip("->").strip() if ret_node else "any"

                    params = []
                    params_node = node.child_by_field_name("parameters")
                    if params_node:
                        for p in params_node.children:
                            if p.type in ("identifier", "default_parameter", "typed_parameter", "typed_default_parameter"):
                                ident = p if p.type == "identifier" else p.child_by_field_name("name") or p.children[0]
                                p_name = ident.text.decode("utf-8", errors="ignore")
                                if p_name != "self" and p_name != "cls":
                                    params.append(p_name)

                    signatures.append(_make_symbol_signature(
                        name=fn_name,
                        params=params,
                        return_type=ret_type,
                        visibility="public",
                        language="python",
                        source_file=source_file
                    ))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return signatures
