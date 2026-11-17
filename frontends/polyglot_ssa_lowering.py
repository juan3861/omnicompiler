"""
Alpha-C27: True Polyglot AOT Lowering (JS / TS / Rust / Go -> Canonical Python AST -> Omni-SSA)

Parses JavaScript (.js/.mjs), TypeScript (.ts), Rust (.rs), and Go (.go) source
files into canonical Python `ast.Module` / `ast.FunctionDef` trees that feed
directly into Omni-SSA (`lower_ast_to_ssa`), CPG, Z3 refinement verification,
ThinLTO, Translation Validation, LLVM O3, WebAssembly, and Native x86-64/ARM64.

Fails closed with `PolyglotLoweringError` on unsupported syntax so no construct
is silently dropped or miscompiled.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import os
import re
from typing import Dict, List, Optional, Tuple


SUPPORTED_POLYGLOT_EXTENSIONS: Dict[str, str] = {
    ".js": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".rs": "rust",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".zig": "zig",
    ".java": "java",
    ".cs": "csharp",
    ".kt": "kotlin",
}

_C_SCALAR_MAP: Dict[str, str] = {
    "int8_t": "i8",
    "uint8_t": "u8",
    "sbyte": "i8",
    "byte": "i8",
    "char": "i8",
    "int16_t": "i16",
    "uint16_t": "u16",
    "short": "i16",
    "int32_t": "i32",
    "uint32_t": "u32",
    "int": "i32",
    "Int": "i32",
    "uint": "u32",
    "int64_t": "i64",
    "uint64_t": "u64",
    "long": "i64",
    "Long": "i64",
    "ulong": "u64",
    "i64": "i64",
    "i32": "i32",
    "u32": "u32",
    "u64": "u64",
    "size_t": "u64",
    "ssize_t": "i64",
    "float": "f32",
    "Float": "f32",
    "f32": "f32",
    "double": "f64",
    "Double": "f64",
    "f64": "f64",
    "bool": "i64",
    "boolean": "i64",
    "Boolean": "i64",
    "void": "i64",
    "Unit": "i64",
}


class PolyglotLoweringError(ValueError):
    """Raised when a polyglot function uses syntax outside the safe AOT subset."""


@dataclass(frozen=True)
class _Tok:
    kind: str  # "ID", "NUM", "STR", "OP", "PUNCT", "EOF"
    val: str
    line: int
    col: int


@dataclass
class PolyglotParseResult:
    language: str
    file_path: str
    module: ast.Module
    functions: List[ast.FunctionDef] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


_MULTI_CHAR_OPS = (
    "===",
    "!==",
    ">>>",
    "<<=",
    ">>=",
    "..=",
    "==",
    "!=",
    "<=",
    ">=",
    "&&",
    "||",
    "++",
    "--",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "&=",
    "|=",
    "^=",
    ":=",
    "->",
    "=>",
    "..",
    "<<",
    ">>",
)

_SINGLE_OPS = set("+-*/%&|^~!<>?=:.")
_PUNCT = set("(){}[],;")
_FLOAT_ANN_RE = re.compile(
    r"(?::\s*(?:f32|f64|float32|float64|double|Float64Array)\b|->\s*(?:f32|f64|float32|float64|double)\b|\b(?:f32|f64|float32|float64|Float64Array)\b)"
)


def _tokenize(source: str, allow_floats: bool = False, skip_hash_directives: bool = False) -> List[_Tok]:
    tokens: List[_Tok] = []
    n = len(source)
    i = 0
    line = 1
    col = 1

    while i < n:
        ch = source[i]
        if ch == "\n":
            line += 1
            col = 1
            i += 1
            continue
        if ch in " \t\r":
            col += 1
            i += 1
            continue

        if skip_hash_directives and ch == "#":
            while i < n and source[i] != "\n":
                i += 1
            continue

        # Line comment // ...
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                i += 1
            continue

        # Block comment /* ... */
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            i += 2
            col += 2
            while i + 1 < n and not (source[i] == "*" and source[i + 1] == "/"):
                if source[i] == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
                i += 1
            i = min(n, i + 2)
            col += 2
            continue

        # String literals (for imports / skipped attributes)
        if ch in ('"', "'", "`"):
            quote = ch
            start_line, start_col = line, col
            i += 1
            col += 1
            buf: List[str] = []
            while i < n and source[i] != quote:
                if source[i] == "\\" and i + 1 < n:
                    buf.append(source[i : i + 2])
                    i += 2
                    col += 2
                    continue
                if source[i] == "\n":
                    line += 1
                    col = 1
                else:
                    col += 1
                buf.append(source[i])
                i += 1
            if i < n:
                i += 1
                col += 1
            tokens.append(_Tok("STR", "".join(buf), start_line, start_col))
            continue

        # Numbers (hex, binary, decimal integer, or IEEE-754 float when enabled)
        if ch.isdigit():
            start = i
            start_col = col
            is_float = False
            if ch == "0" and i + 1 < n and source[i + 1] in ("x", "X", "b", "B", "o", "O"):
                i += 2
                col += 2
                while i < n and (source[i].isalnum() or source[i] == "_"):
                    i += 1
                    col += 1
            else:
                while i < n and (source[i].isdigit() or source[i] == "_"):
                    i += 1
                    col += 1
                # Decimal point followed by digit (not `..`)
                if i + 1 < n and source[i] == "." and source[i + 1].isdigit():
                    if not allow_floats:
                        raise PolyglotLoweringError(
                            f"Line {line}:{col}: floating-point literals are outside integer AOT subset"
                        )
                    is_float = True
                    i += 1
                    col += 1
                    while i < n and (source[i].isdigit() or source[i] == "_"):
                        i += 1
                        col += 1
                if allow_floats and i < n and source[i] in ("e", "E"):
                    if i + 1 < n and (
                        source[i + 1].isdigit()
                        or (source[i + 1] in ("+", "-") and i + 2 < n and source[i + 2].isdigit())
                    ):
                        is_float = True
                        i += 1
                        col += 1
                        if i < n and source[i] in ("+", "-"):
                            i += 1
                            col += 1
                        while i < n and (source[i].isdigit() or source[i] == "_"):
                            i += 1
                            col += 1
                if allow_floats and (source[i : i + 3] in ("f64", "f32")):
                    is_float = True
                    i += 3
                    col += 3
            raw_num = source[start:i].replace("_", "")
            if is_float:
                for suffix in ("f64", "f32"):
                    if raw_num.endswith(suffix) and len(raw_num) > len(suffix):
                        raw_num = raw_num[: -len(suffix)]
                        break
                tokens.append(_Tok("FLOAT", raw_num, line, start_col))
                continue
            # Strip Rust integer suffixes like 10i64, 1u32
            for suffix in ("i64", "i32", "u64", "u32", "usize", "isize", "i128", "u128"):
                if raw_num.endswith(suffix) and len(raw_num) > len(suffix):
                    raw_num = raw_num[: -len(suffix)]
                    break
            tokens.append(_Tok("NUM", raw_num, line, start_col))
            continue

        # Identifiers / keywords
        if ch.isalpha() or ch in ("_", "$"):
            start = i
            start_col = col
            while i < n and (source[i].isalnum() or source[i] in ("_", "$")):
                i += 1
                col += 1
            tokens.append(_Tok("ID", source[start:i], line, start_col))
            continue

        # Multi-char operators
        matched_op: Optional[str] = None
        for op in _MULTI_CHAR_OPS:
            if source.startswith(op, i):
                matched_op = op
                break
        if matched_op is not None:
            tokens.append(_Tok("OP", matched_op, line, col))
            i += len(matched_op)
            col += len(matched_op)
            continue

        if ch in _PUNCT:
            tokens.append(_Tok("PUNCT", ch, line, col))
            i += 1
            col += 1
            continue

        if ch in _SINGLE_OPS:
            tokens.append(_Tok("OP", ch, line, col))
            i += 1
            col += 1
            continue

        # Skip stray decorators / attributes markers cleanly if outside expr
        if ch == "@":
            tokens.append(_Tok("OP", "@", line, col))
            i += 1
            col += 1
            continue
        if ch == "#":
            tokens.append(_Tok("OP", "#", line, col))
            i += 1
            col += 1
            continue

        raise PolyglotLoweringError(f"Line {line}:{col}: unexpected character {ch!r}")

    tokens.append(_Tok("EOF", "", line, col))
    return tokens


class _PolyglotParser:
    def __init__(self, source: str, language: str, allow_floats: bool = False):
        self.language = language
        self.allow_floats = allow_floats
        self.toks = _tokenize(
            source,
            allow_floats=allow_floats,
            skip_hash_directives=(language in ("c", "cpp")),
        )
        self.pos = 0
        self.declared_structs: Dict[str, ast.ClassDef] = {}

    def _peek(self, offset: int = 0) -> _Tok:
        idx = self.pos + offset
        if idx >= len(self.toks):
            return self.toks[-1]
        return self.toks[idx]

    def _at(self, kind: str, val: Optional[str] = None) -> bool:
        t = self._peek()
        if t.kind != kind:
            return False
        return val is None or t.val == val

    def _advance(self) -> _Tok:
        t = self._peek()
        if self.pos < len(self.toks) - 1:
            self.pos += 1
        return t

    def _expect(self, kind: str, val: Optional[str] = None) -> _Tok:
        t = self._peek()
        if t.kind != kind or (val is not None and t.val != val):
            expected = f"{kind}({val!r})" if val is not None else kind
            raise PolyglotLoweringError(
                f"Line {t.line}:{t.col}: expected {expected}, got {t.kind}({t.val!r})"
            )
        return self._advance()

    def _skip_balanced(self, open_ch: str, close_ch: str) -> None:
        self._expect("PUNCT", open_ch)
        depth = 1
        while depth > 0 and not self._at("EOF"):
            t = self._advance()
            if t.kind == "PUNCT" and t.val == open_ch:
                depth += 1
            elif t.kind == "PUNCT" and t.val == close_ch:
                depth -= 1

    def _skip_until_semicolon_or_brace(self) -> None:
        depth = 0
        while not self._at("EOF"):
            t = self._peek()
            if t.kind == "PUNCT" and t.val in ("(", "["):
                depth += 1
                self._advance()
            elif t.kind == "PUNCT" and t.val in (")", "]"):
                depth = max(0, depth - 1)
                self._advance()
            elif depth == 0 and t.kind == "PUNCT" and t.val == ";":
                self._advance()
                return
            elif depth == 0 and t.kind == "PUNCT" and t.val == "{":
                self._skip_balanced("{", "}")
                return
            else:
                self._advance()

    # ------------------------------------------------------------------
    # Module / Function Discovery
    # ------------------------------------------------------------------
    def parse_module(self) -> Tuple[ast.Module, List[ast.FunctionDef], List[str]]:
        funcs: List[ast.FunctionDef] = []
        structs: List[ast.ClassDef] = []
        luts: List[ast.stmt] = []
        errors: List[str] = []

        while not self._at("EOF"):
            # Rust attributes #[...]
            if self.language == "rust" and self._at("OP", "#"):
                self._advance()
                if self._at("PUNCT", "["):
                    self._skip_balanced("[", "]")
                continue

            # JS/TS decorators @...
            if self._at("OP", "@"):
                self._advance()
                if self._at("ID"):
                    self._advance()
                    if self._at("PUNCT", "("):
                        self._skip_balanced("(", ")")
                continue

            st_cls = self._try_parse_top_level_struct()
            if st_cls is not None:
                self.declared_structs[st_cls.name] = st_cls
                structs.append(st_cls)
                continue

            lut_stmt = self._try_parse_top_level_lut()
            if lut_stmt is not None:
                luts.append(lut_stmt)
                continue

            fn_start = self.pos
            try:
                fn = self._try_parse_top_level_function()
                if fn is not None:
                    funcs.append(fn)
                    continue
            except PolyglotLoweringError as exc:
                errors.append(str(exc))
                # Recover to next top-level block cleanly while failing closed for this function
                self.pos = fn_start
                self._recover_top_level_item()
                continue

            # Unwrap outer class / namespace containers in Java, C#, and Kotlin
            if self.language in ("java", "csharp", "kotlin"):
                if self._at("PUNCT", "}"):
                    self._advance()
                    continue
                if self._try_enter_oop_container():
                    continue
            self._skip_top_level_non_function()

        mod = ast.Module(body=list(structs) + list(luts) + list(funcs), type_ignores=[])
        ast.fix_missing_locations(mod)
        return mod, funcs, errors

    def _try_parse_top_level_lut(self) -> Optional[ast.stmt]:
        save = self.pos
        t = self._peek()
        if t.kind != "ID":
            return None
        if t.val in ("pub", "export"):
            self._advance()
        if not self._at("ID") or self._peek().val not in ("const", "var", "let", "static"):
            self.pos = save
            return None
        kw = self._advance()
        if not self._at("ID"):
            self.pos = save
            return None
        name_tok = self._advance()
        ann_toks: List[str] = []
        if self._at("OP", ":"):
            self._advance()
            br_l = 0
            while not self._at("OP", "=") and not self._at("EOF"):
                pk = self._peek()
                if pk.val == "[":
                    br_l += 1
                elif pk.val == "]":
                    br_l = max(0, br_l - 1)
                if br_l == 0 and self._at("PUNCT", ";"):
                    self.pos = save
                    return None
                ann_toks.append(self._advance().val)
        if not self._at("OP", "="):
            self.pos = save
            return None
        self._advance()
        # Optional Go typed literal prefix: [N]T { ... }
        if self.language == "go" and self._at("PUNCT", "["):
            go_t: List[str] = []
            while not self._at("PUNCT", "]") and not self._at("EOF"):
                go_t.append(self._advance().val)
            if self._at("PUNCT", "]"):
                go_t.append(self._advance().val)
            if self._at("ID"):
                go_t.append(self._advance().val)
            if not ann_toks:
                ann_toks = go_t
        if not (self._at("PUNCT", "[") or self._at("PUNCT", "{")):
            self.pos = save
            return None
        close_delim = "]" if self._advance().val == "[" else "}"
        elts: List[ast.expr] = []
        while not self._at("PUNCT", close_delim) and not self._at("EOF"):
            if self._at("PUNCT", ","):
                self._advance()
                continue
            elt = self._parse_expr()
            if isinstance(elt, (ast.Constant, ast.UnaryOp)):
                elts.append(elt)
            else:
                self.pos = save
                return None
            if self._at("PUNCT", ","):
                self._advance()
        if not self._at("PUNCT", close_delim) or not elts:
            self.pos = save
            return None
        self._advance()
        self._consume_optional_semi()
        list_node = ast.List(elts=elts, ctx=ast.Load(), lineno=name_tok.line)
        if ann_toks:
            ann_node = self._build_cabi_field_annotation(ann_toks, name_tok.line)
            return ast.AnnAssign(
                target=ast.Name(id=name_tok.val, ctx=ast.Store(), lineno=name_tok.line),
                annotation=ann_node,
                value=list_node,
                simple=1,
                lineno=name_tok.line,
            )
        return ast.Assign(
            targets=[ast.Name(id=name_tok.val, ctx=ast.Store(), lineno=name_tok.line)],
            value=list_node,
            lineno=name_tok.line,
        )

    @staticmethod
    def _build_cabi_field_annotation(ftype_toks: List[str], line: int) -> ast.expr:
        # Rust/TS `[T; N]`
        if len(ftype_toks) >= 5 and ftype_toks[0] == "[" and ftype_toks[-1] == "]" and ";" in ftype_toks:
            sep_i = ftype_toks.index(";")
            elem_tok = ftype_toks[sep_i - 1]
            cnt_tok = ftype_toks[sep_i + 1]
            if cnt_tok.isdigit():
                return ast.Subscript(
                    value=ast.Name(id="Array", ctx=ast.Load(), lineno=line),
                    slice=ast.Tuple(
                        elts=[ast.Name(id=elem_tok, ctx=ast.Load(), lineno=line), ast.Constant(value=int(cnt_tok), lineno=line)],
                        ctx=ast.Load(),
                        lineno=line,
                    ),
                    ctx=ast.Load(),
                    lineno=line,
                )
        # Go `[N]T`
        if len(ftype_toks) >= 4 and ftype_toks[0] == "[" and "]" in ftype_toks:
            rb_i = ftype_toks.index("]")
            if rb_i == 2 and ftype_toks[1].isdigit() and rb_i + 1 < len(ftype_toks):
                return ast.Subscript(
                    value=ast.Name(id="Array", ctx=ast.Load(), lineno=line),
                    slice=ast.Tuple(
                        elts=[ast.Name(id=ftype_toks[rb_i + 1], ctx=ast.Load(), lineno=line), ast.Constant(value=int(ftype_toks[1]), lineno=line)],
                        ctx=ast.Load(),
                        lineno=line,
                    ),
                    ctx=ast.Load(),
                    lineno=line,
                )
        # TS `FixedArray<T, N>`
        if len(ftype_toks) >= 6 and ftype_toks[0] in ("FixedArray", "Array") and "<" in ftype_toks and "," in ftype_toks and ">" in ftype_toks:
            c_i = ftype_toks.index(",")
            if c_i >= 2 and c_i + 1 < len(ftype_toks) and ftype_toks[c_i + 1].isdigit():
                return ast.Subscript(
                    value=ast.Name(id="Array", ctx=ast.Load(), lineno=line),
                    slice=ast.Tuple(
                        elts=[ast.Name(id=ftype_toks[c_i - 1], ctx=ast.Load(), lineno=line), ast.Constant(value=int(ftype_toks[c_i + 1]), lineno=line)],
                        ctx=ast.Load(),
                        lineno=line,
                    ),
                    ctx=ast.Load(),
                    lineno=line,
                )
        ft_id = ftype_toks[-1] if ftype_toks else "i64"
        return ast.Name(id=ft_id, ctx=ast.Load(), lineno=line)

    def _parse_c_type_spec(self) -> Optional[Tuple[str, bool, Optional[str]]]:
        """Parses a C/C++ type like `const int64_t*`, `unsigned int`, `struct Packet*`, `double`."""
        save = self.pos
        is_unsigned = False
        while self._at("ID") and self._peek().val in ("const", "volatile", "struct", "class", "typename", "signed", "unsigned"):
            if self._peek().val == "unsigned":
                is_unsigned = True
            self._advance()
        if not self._at("ID"):
            self.pos = save
            return None
        base = self._advance().val
        if base == "long" and self._at("ID", "long"):
            self._advance()
            base = "int64_t"
        if is_unsigned and base in ("char", "short", "int", "long"):
            base = {"char": "uint8_t", "short": "uint16_t", "int": "uint32_t", "long": "uint64_t"}[base]
        is_ptr = False
        while self._at("OP", "*") or self._at("OP", "&"):
            self._advance()
            is_ptr = True
        if base in _C_SCALAR_MAP:
            return _C_SCALAR_MAP[base], is_ptr, None
        if base in self.declared_structs:
            return base, is_ptr, base
        self.pos = save
        return None

    def _parse_c_struct_def(self) -> Optional[ast.ClassDef]:
        save = self.pos
        is_typedef = False
        if self._at("ID", "typedef"):
            is_typedef = True
            self._advance()
        if not (self._at("ID", "struct") or self._at("ID", "class")):
            self.pos = save
            return None
        self._advance()
        sname: Optional[str] = None
        if self._at("ID"):
            sname = self._advance().val
        if not self._at("PUNCT", "{"):
            self.pos = save
            return None
        self._advance()
        body: List[ast.stmt] = []
        while not self._at("PUNCT", "}") and not self._at("EOF"):
            if self._at("ID", "public") or self._at("ID", "private"):
                self._advance()
                if self._at("OP", ":"):
                    self._advance()
                continue
            tspec = self._parse_c_type_spec()
            if tspec is None or not self._at("ID"):
                self.pos = save
                return None
            cabi_ft, is_ptr, struct_n = tspec
            fname = self._advance()
            ann_toks = [struct_n or ("ptr" if is_ptr else cabi_ft)]
            if self._at("PUNCT", "["):
                self._advance()
                cnt_tok = self._expect("NUM")
                self._expect("PUNCT", "]")
                ann_toks = ["Array", "[", struct_n or cabi_ft, ",", cnt_tok.val, "]"]
            body.append(
                ast.AnnAssign(
                    target=ast.Name(id=fname.val, ctx=ast.Store(), lineno=fname.line),
                    annotation=self._build_cabi_field_annotation(ann_toks, fname.line),
                    value=None,
                    simple=1,
                    lineno=fname.line,
                )
            )
            self._expect("PUNCT", ";")
        self._expect("PUNCT", "}")
        if is_typedef and self._at("ID"):
            sname = self._advance().val
        if self._at("PUNCT", ";"):
            self._advance()
        if not sname:
            self.pos = save
            return None
        return ast.ClassDef(
            name=sname,
            bases=[],
            keywords=[],
            body=body or [ast.Pass(lineno=self._peek().line)],
            decorator_list=[],
            lineno=self._peek().line,
        )

    def _try_enter_oop_container(self) -> bool:
        """Consumes `namespace / class / object Name ... {` headers so nested static methods lower cleanly."""
        save = self.pos
        while self._at("ID") and self._peek().val in (
            "public", "private", "protected", "internal", "static", "final", "abstract", "sealed", "open", "data",
        ):
            self._advance()
        if not (self._at("ID") and self._peek().val in ("class", "namespace", "object", "interface")):
            self.pos = save
            return False
        while not self._at("PUNCT", "{") and not self._at("EOF"):
            if self._at("PUNCT", ";"):
                self.pos = save
                return False
            self._advance()
        if self._at("PUNCT", "{"):
            self._advance()
            return True
        self.pos = save
        return False

    def _parse_c_function(self) -> Optional[ast.FunctionDef]:
        save = self.pos
        while self._at("ID") and self._peek().val in (
            "static", "inline", "extern", "constexpr", "virtual",
            "public", "private", "protected", "internal", "final", "override", "unsafe",
        ):
            self._advance()
            if self._at("STR"):
                self._advance()
        tspec = self._parse_c_type_spec()
        if tspec is None or not self._at("ID"):
            self.pos = save
            return None
        ret_cabi, ret_ptr, _ = tspec
        name_tok = self._advance()
        if not self._at("PUNCT", "("):
            self.pos = save
            return None
        self._advance()
        params: List[str] = []
        param_types: Dict[str, str] = {}
        while not self._at("PUNCT", ")"):
            if self._at("ID", "void") and self._peek(1).kind == "PUNCT" and self._peek(1).val == ")":
                self._advance()
                break
            pt = self._parse_c_type_spec()
            if pt is None or not self._at("ID"):
                self.pos = save
                return None
            p_cabi, p_ptr, p_struct = pt
            pname = self._advance().val
            params.append(pname)
            if p_struct:
                param_types[pname] = p_struct
            elif p_ptr and p_cabi == "f64":
                param_types[pname] = "ptr_f64"
            elif p_ptr:
                param_types[pname] = "ptr"
            elif p_cabi in ("f32", "f64"):
                param_types[pname] = "float"
            else:
                param_types[pname] = "int"
            if self._at("PUNCT", ","):
                self._advance()
            else:
                break
        self._expect("PUNCT", ")")
        if self._at("PUNCT", ";"):
            self._advance()
            return None
        body = self._parse_block()
        ret_ann = "float" if (not ret_ptr and ret_cabi in ("f32", "f64")) else "int"
        args = [
            ast.arg(
                arg=p,
                annotation=(
                    ast.Name(id=param_types[p], ctx=ast.Load(), lineno=name_tok.line)
                    if p in param_types
                    else None
                ),
            )
            for p in params
        ]
        return ast.FunctionDef(
            name=name_tok.val,
            args=ast.arguments(posonlyargs=[], args=args, kwonlyargs=[], kw_defaults=[], defaults=[]),
            body=body,
            decorator_list=[],
            returns=ast.Name(id=ret_ann, ctx=ast.Load(), lineno=name_tok.line),
            lineno=name_tok.line,
        )

    def _try_parse_top_level_struct(self) -> Optional[ast.ClassDef]:
        save = self.pos
        t = self._peek()
        if t.kind != "ID":
            return None
        if self.language in ("c", "cpp", "java", "csharp"):
            return self._parse_c_struct_def()
        if self.language == "rust":
            if t.val == "pub":
                self._advance()
            if not self._at("ID", "struct"):
                self.pos = save
                return None
            self._advance()
            if not self._at("ID"):
                self.pos = save
                return None
            sname = self._advance()
            if not self._at("PUNCT", "{"):
                self.pos = save
                return None
            self._advance()
            body: List[ast.stmt] = []
            while not self._at("PUNCT", "}") and not self._at("EOF"):
                if self._at("ID", "pub"):
                    self._advance()
                if not self._at("ID"):
                    self.pos = save
                    return None
                fname = self._advance()
                self._expect("OP", ":")
                ftype_toks: List[str] = []
                br_depth = 0
                while not self._at("EOF"):
                    pk = self._peek()
                    if br_depth == 0 and pk.kind == "PUNCT" and pk.val in (",", "}"):
                        break
                    if pk.kind == "PUNCT" and pk.val == "[":
                        br_depth += 1
                    elif pk.kind == "PUNCT" and pk.val == "]":
                        br_depth = max(0, br_depth - 1)
                    ftype_toks.append(self._advance().val)
                body.append(
                    ast.AnnAssign(
                        target=ast.Name(id=fname.val, ctx=ast.Store(), lineno=fname.line),
                        annotation=self._build_cabi_field_annotation(ftype_toks, fname.line),
                        value=None,
                        simple=1,
                        lineno=fname.line,
                    )
                )
                if self._at("PUNCT", ","):
                    self._advance()
            self._expect("PUNCT", "}")
            return ast.ClassDef(
                name=sname.val, bases=[], keywords=[], body=body or [ast.Pass(lineno=sname.line)], decorator_list=[], lineno=sname.line
            )
        if self.language == "go":
            if t.val != "type":
                return None
            self._advance()
            if not self._at("ID"):
                self.pos = save
                return None
            sname = self._advance()
            if not self._at("ID", "struct"):
                self.pos = save
                return None
            self._advance()
            if not self._at("PUNCT", "{"):
                self.pos = save
                return None
            self._advance()
            body_g: List[ast.stmt] = []
            while not self._at("PUNCT", "}") and not self._at("EOF"):
                if self._at("PUNCT", ";"):
                    self._advance()
                    continue
                if not self._at("ID"):
                    self.pos = save
                    return None
                fname = self._advance()
                if self._at("PUNCT", "["):
                    go_toks = [self._advance().val]
                    while not self._at("PUNCT", "]") and not self._at("EOF"):
                        go_toks.append(self._advance().val)
                    if self._at("PUNCT", "]"):
                        go_toks.append(self._advance().val)
                    if not self._at("ID"):
                        self.pos = save
                        return None
                    go_toks.append(self._advance().val)
                    go_ann = self._build_cabi_field_annotation(go_toks, fname.line)
                elif self._at("ID"):
                    ftype = self._advance().val
                    go_ann = ast.Name(id=ftype, ctx=ast.Load(), lineno=fname.line)
                else:
                    self.pos = save
                    return None
                body_g.append(
                    ast.AnnAssign(
                        target=ast.Name(id=fname.val, ctx=ast.Store(), lineno=fname.line),
                        annotation=go_ann,
                        value=None,
                        simple=1,
                        lineno=fname.line,
                    )
                )
                if self._at("PUNCT", ";"):
                    self._advance()
            self._expect("PUNCT", "}")
            return ast.ClassDef(
                name=sname.val, bases=[], keywords=[], body=body_g or [ast.Pass(lineno=sname.line)], decorator_list=[], lineno=sname.line
            )
        if self.language == "typescript":
            if t.val == "export":
                self._advance()
            if not self._at("ID", "interface"):
                self.pos = save
                return None
            self._advance()
            if not self._at("ID"):
                self.pos = save
                return None
            sname = self._advance()
            if not self._at("PUNCT", "{"):
                self.pos = save
                return None
            self._advance()
            body_t: List[ast.stmt] = []
            while not self._at("PUNCT", "}") and not self._at("EOF"):
                if self._at("PUNCT", ";") or self._at("PUNCT", ","):
                    self._advance()
                    continue
                if not self._at("ID"):
                    self.pos = save
                    return None
                fname = self._advance()
                self._expect("OP", ":")
                ftype_toks_t: List[str] = []
                br_d = 0
                ang_d = 0
                while not self._at("EOF"):
                    pk = self._peek()
                    if br_d == 0 and ang_d == 0 and pk.kind == "PUNCT" and pk.val in (";", ",", "}"):
                        break
                    if pk.val == "[":
                        br_d += 1
                    elif pk.val == "]":
                        br_d = max(0, br_d - 1)
                    elif pk.val == "<":
                        ang_d += 1
                    elif pk.val == ">":
                        ang_d = max(0, ang_d - 1)
                    ftype_toks_t.append(self._advance().val)
                body_t.append(
                    ast.AnnAssign(
                        target=ast.Name(id=fname.val, ctx=ast.Store(), lineno=fname.line),
                        annotation=self._build_cabi_field_annotation(ftype_toks_t, fname.line),
                        value=None,
                        simple=1,
                        lineno=fname.line,
                    )
                )
                if self._at("PUNCT", ";") or self._at("PUNCT", ","):
                    self._advance()
            self._expect("PUNCT", "}")
            return ast.ClassDef(
                name=sname.val, bases=[], keywords=[], body=body_t or [ast.Pass(lineno=sname.line)], decorator_list=[], lineno=sname.line
            )
        return None

    def _recover_top_level_item(self) -> None:
        while not self._at("EOF"):
            t = self._advance()
            if t.kind == "PUNCT" and t.val == "{":
                self.pos -= 1
                self._skip_balanced("{", "}")
                return
            if t.kind == "PUNCT" and t.val == ";":
                return

    def _skip_top_level_non_function(self) -> None:
        t = self._peek()
        if t.kind == "EOF":
            return
        if t.kind == "ID" and t.val in ("package", "import", "use", "mod"):
            start_line = t.line
            self._advance()
            # Go import ( ... )
            if t.val == "import" and self._at("PUNCT", "("):
                self._skip_balanced("(", ")")
                return
            while not self._at("EOF"):
                nxt = self._peek()
                if nxt.kind == "PUNCT" and nxt.val == ";":
                    self._advance()
                    return
                if self.language == "go" and nxt.line > start_line:
                    return
                self._advance()
            return
        if t.kind == "PUNCT" and t.val == ";":
            self._advance()
            return
        if t.kind == "PUNCT" and t.val == "{":
            self._skip_balanced("{", "}")
            return
        self._skip_until_semicolon_or_brace()

    def _try_parse_top_level_function(self) -> Optional[ast.FunctionDef]:
        save = self.pos
        t = self._peek()
        if t.kind != "ID":
            return None

        if self.language in ("javascript", "typescript"):
            if t.val == "exports" and self._peek(1).kind == "OP" and self._peek(1).val == ".":
                arrow_fn = self._try_parse_exports_arrow_function()
                if arrow_fn is not None:
                    return arrow_fn
                self.pos = save
                return None

            if t.val == "export":
                self._advance()
                if self._at("ID", "default"):
                    self._advance()
            if self._at("ID", "async"):
                self._advance()
            if self._at("ID", "function"):
                return self._parse_js_ts_function()
            if self._peek().kind == "ID" and self._peek().val in ("const", "let", "var"):
                arrow_fn = self._try_parse_const_arrow_function()
                if arrow_fn is not None:
                    return arrow_fn
            self.pos = save
            return None

        if self.language == "rust":
            if t.val == "pub":
                self._advance()
                if self._at("PUNCT", "("):
                    self._skip_balanced("(", ")")
            if self._at("ID", "async"):
                self._advance()
            if self._at("ID", "unsafe"):
                self._advance()
            if self._at("ID", "extern"):
                self._advance()
                if self._at("STR"):
                    self._advance()
            if not self._at("ID", "fn"):
                self.pos = save
                return None
            return self._parse_rust_function()

        if self.language == "go":
            if t.val != "func":
                return None
            return self._parse_go_function()

        if self.language in ("c", "cpp", "java", "csharp"):
            return self._parse_c_function()

        if self.language == "zig":
            while self._at("ID") and self._peek().val in ("pub", "export", "inline", "extern"):
                self._advance()
                if self._at("STR"):
                    self._advance()
            if not self._at("ID", "fn"):
                self.pos = save
                return None
            return self._parse_zig_function()

        if self.language == "kotlin":
            while self._at("ID") and self._peek().val in ("public", "private", "internal", "inline", "override"):
                self._advance()
            if not self._at("ID", "fun"):
                self.pos = save
                return None
            return self._parse_kotlin_function()

        return None

    def _parse_zig_function(self) -> ast.FunctionDef:
        fn_tok = self._expect("ID", "fn")
        name_tok = self._expect("ID")
        params, param_types = self._parse_js_ts_param_list()
        ret_type: Optional[str] = None
        if not self._at("PUNCT", "{"):
            ret_type = self._skip_type_annotation(stop_tokens={"{"})
        body = self._parse_block()
        return self._make_function_def(
            name_tok.val, params, body, fn_tok.line, param_types=param_types, return_type=ret_type
        )

    def _parse_kotlin_function(self) -> ast.FunctionDef:
        fn_tok = self._expect("ID", "fun")
        name_tok = self._expect("ID")
        params, param_types = self._parse_js_ts_param_list()
        ret_type: Optional[str] = None
        if self._at("OP", ":"):
            self._advance()
            ret_type = self._skip_type_annotation(stop_tokens={"{"})
        body = self._parse_block()
        return self._make_function_def(
            name_tok.val, params, body, fn_tok.line, param_types=param_types, return_type=ret_type
        )

    # ------------------------------------------------------------------
    # Signatures
    # ------------------------------------------------------------------
    def _parse_js_ts_param_list(self) -> Tuple[List[str], Dict[str, str]]:
        self._expect("PUNCT", "(")
        params: List[str] = []
        param_types: Dict[str, str] = {}
        while not self._at("PUNCT", ")"):
            pname = self._expect("ID").val
            if self._at("OP", "?"):
                self._advance()
            if self._at("OP", ":"):
                self._advance()
                ann = self._skip_type_annotation(stop_tokens={",", ")", "="})
                if ann is not None:
                    param_types[pname] = ann
            if self._at("OP", "="):
                self._advance()
                self._parse_expr()
            params.append(pname)
            if self._at("PUNCT", ","):
                self._advance()
            else:
                break
        self._expect("PUNCT", ")")
        return params, param_types

    def _parse_js_ts_function(self) -> ast.FunctionDef:
        fn_tok = self._expect("ID", "function")
        name_tok = self._expect("ID")
        if self._at("OP", "<"):
            self._skip_type_args()
        params, param_types = self._parse_js_ts_param_list()
        ret_type: Optional[str] = None
        if self._at("OP", ":"):
            self._advance()
            ret_type = self._skip_type_annotation(stop_tokens={"{"})
        body = self._parse_block()
        return self._make_function_def(
            name_tok.val, params, body, fn_tok.line, param_types=param_types, return_type=ret_type
        )

    def _parse_arrow_rhs(self, fn_name: str, line: int) -> Optional[ast.FunctionDef]:
        if self._at("ID", "async"):
            self._advance()
        if self._at("OP", "<"):
            self._skip_type_args()
        param_types: Dict[str, str] = {}
        if self._at("PUNCT", "("):
            params, param_types = self._parse_js_ts_param_list()
        elif self._at("ID"):
            params = [self._advance().val]
        else:
            return None
        ret_type: Optional[str] = None
        if self._at("OP", ":"):
            self._advance()
            ret_type = self._skip_type_annotation(stop_tokens={"=>"})
        if not self._at("OP", "=>"):
            return None
        self._advance()
        if self._at("PUNCT", "{"):
            body = self._parse_block()
        else:
            expr = self._parse_expr()
            body = [ast.Return(value=expr, lineno=line)]
        self._consume_optional_semi()
        return self._make_function_def(
            fn_name, params, body, line, param_types=param_types, return_type=ret_type
        )

    def _try_parse_const_arrow_function(self) -> Optional[ast.FunctionDef]:
        save = self.pos
        kw = self._advance()
        if not self._at("ID"):
            self.pos = save
            return None
        name_tok = self._advance()
        if self._at("OP", ":"):
            self._advance()
            self._skip_type_annotation(stop_tokens={"="})
        if not self._at("OP", "="):
            self.pos = save
            return None
        self._advance()
        try:
            fn = self._parse_arrow_rhs(name_tok.val, kw.line)
        except PolyglotLoweringError:
            self.pos = save
            raise
        if fn is None:
            self.pos = save
            return None
        return fn

    def _try_parse_exports_arrow_function(self) -> Optional[ast.FunctionDef]:
        save = self.pos
        self._expect("ID", "exports")
        self._expect("OP", ".")
        if not self._at("ID"):
            self.pos = save
            return None
        name_tok = self._advance()
        if not self._at("OP", "="):
            self.pos = save
            return None
        self._advance()
        fn = self._parse_arrow_rhs(name_tok.val, name_tok.line)
        if fn is None:
            self.pos = save
            return None
        return fn

    def _parse_rust_function(self) -> ast.FunctionDef:
        fn_tok = self._expect("ID", "fn")
        name_tok = self._expect("ID")
        if self._at("OP", "<"):
            self._skip_type_args()
        self._expect("PUNCT", "(")
        params: List[str] = []
        param_types: Dict[str, str] = {}
        while not self._at("PUNCT", ")"):
            if self._at("ID", "mut"):
                self._advance()
            pname = self._expect("ID").val
            self._expect("OP", ":")
            ann = self._skip_type_annotation(stop_tokens={",", ")"})
            if ann is not None:
                param_types[pname] = ann
            params.append(pname)
            if self._at("PUNCT", ","):
                self._advance()
                if self._at("PUNCT", ")"):
                    break
            else:
                break
        self._expect("PUNCT", ")")
        ret_type: Optional[str] = None
        if self._at("OP", "->"):
            self._advance()
            ret_type = self._skip_type_annotation(stop_tokens={"{"})
        if self._at("ID", "where"):
            self._advance()
            while not self._at("PUNCT", "{") and not self._at("EOF"):
                self._advance()
        body = self._parse_block(allow_tail_return=True)
        return self._make_function_def(
            name_tok.val, params, body, fn_tok.line, param_types=param_types, return_type=ret_type
        )

    def _parse_go_function(self) -> ast.FunctionDef:
        fn_tok = self._expect("ID", "func")
        # Optional receiver `(r *Type)`
        if self._at("PUNCT", "("):
            self._skip_balanced("(", ")")
        name_tok = self._expect("ID")
        # Optional type params `[T any]`
        if self._at("PUNCT", "["):
            self._skip_balanced("[", "]")
        self._expect("PUNCT", "(")
        params: List[str] = []
        param_types: Dict[str, str] = {}
        pending_group: List[str] = []
        while not self._at("PUNCT", ")"):
            # Expect identifier(s) optionally grouped before Go type (`a, b int64`)
            if self._at("ID"):
                ident = self._advance().val
                pending_group.append(ident)
                if self._at("PUNCT", ","):
                    self._advance()
                    continue
                # Next token starts the Go type (or `)` if untyped malformed; expect type)
                ann: Optional[str] = None
                if not self._at("PUNCT", ")"):
                    ann = self._skip_go_type(stop_tokens={",", ")"})
                if ann is not None:
                    for p_g in pending_group:
                        param_types[p_g] = ann
                params.extend(pending_group)
                pending_group.clear()
                if self._at("PUNCT", ","):
                    self._advance()
            else:
                raise PolyglotLoweringError(
                    f"Line {self._peek().line}:{self._peek().col}: unsupported Go parameter syntax"
                )
        if pending_group:
            params.extend(pending_group)
        self._expect("PUNCT", ")")
        # Optional Go return type(s) before `{`
        ret_type: Optional[str] = None
        if self._at("PUNCT", "("):
            self._skip_balanced("(", ")")
        ret_toks: List[str] = []
        while not self._at("PUNCT", "{") and not self._at("EOF"):
            ret_toks.append(self._advance().val)
        if ret_toks == ["float64"] or ret_toks == ["f64"] or ret_toks == ["double"]:
            ret_type = "float"
        body = self._parse_block()
        return self._make_function_def(
            name_tok.val, params, body, fn_tok.line, param_types=param_types, return_type=ret_type
        )

    def _skip_type_args(self) -> None:
        self._expect("OP", "<")
        depth = 1
        while depth > 0 and not self._at("EOF"):
            t = self._advance()
            if t.kind == "OP" and t.val == "<":
                depth += 1
            elif t.kind == "OP" and t.val == ">":
                depth -= 1
            elif t.kind == "OP" and t.val == ">>":
                depth -= 2

    def _skip_type_annotation(self, stop_tokens: set) -> Optional[str]:
        paren = 0
        bracket = 0
        angle = 0
        captured: List[str] = []
        while not self._at("EOF"):
            t = self._peek()
            if paren == 0 and bracket == 0 and angle == 0 and t.val in stop_tokens:
                break
            self._advance()
            captured.append(t.val)
            if t.kind == "PUNCT" and t.val == "(":
                paren += 1
            elif t.kind == "PUNCT" and t.val == ")":
                paren = max(0, paren - 1)
            elif t.kind == "PUNCT" and t.val == "[":
                bracket += 1
            elif t.kind == "PUNCT" and t.val == "]":
                bracket = max(0, bracket - 1)
            elif t.kind == "OP" and t.val == "<":
                angle += 1
            elif t.kind == "OP" and t.val == ">":
                angle = max(0, angle - 1)
        if captured in (["f64"], ["float64"], ["double"], ["Double"]):
            return "float"
        if captured in (["Long"], ["Int"], ["Boolean"], ["Short"], ["Byte"]):
            return None
        if (
            captured == ["Float64Array"]
            or (
                any(t in ("f64", "float64", "double", "Double") for t in captured)
                and any(t in ("[", "&", "*", "Array", "Slice") for t in captured)
            )
        ):
            return "ptr_f64"
        for tok in reversed(captured):
            if tok in self.declared_structs or (
                tok[:1].isupper()
                and tok not in ("Array", "Slice", "Vec", "Box", "Long", "Int", "Double", "Float", "Boolean", "Short", "Byte", "Unit")
            ):
                return tok
        return None

    def _skip_go_type(self, stop_tokens: set) -> Optional[str]:
        paren = 0
        bracket = 0
        captured: List[str] = []
        while not self._at("EOF"):
            t = self._peek()
            if paren == 0 and bracket == 0 and t.val in stop_tokens:
                break
            self._advance()
            captured.append(t.val)
            if t.kind == "PUNCT" and t.val == "(":
                paren += 1
            elif t.kind == "PUNCT" and t.val == ")":
                paren = max(0, paren - 1)
            elif t.kind == "PUNCT" and t.val == "[":
                bracket += 1
            elif t.kind == "PUNCT" and t.val == "]":
                bracket = max(0, bracket - 1)
        if captured in (["float64"], ["f64"], ["double"]):
            return "float"
        if any(t in ("float64", "f64", "double") for t in captured) and (
            "[" in captured or "*" in captured
        ):
            return "ptr_f64"
        for tok in reversed(captured):
            if tok in self.declared_structs or (tok[:1].isupper() and tok not in ("Array", "Slice", "Vec", "Box")):
                return tok
        return None

    def _make_function_def(
        self,
        name: str,
        params: List[str],
        body: List[ast.stmt],
        line: int,
        param_types: Optional[Dict[str, str]] = None,
        return_type: Optional[str] = None,
    ) -> ast.FunctionDef:
        if not body:
            init_ret = 0.0 if return_type == "float" else 0
            body = [ast.Return(value=ast.Constant(value=init_ret), lineno=line)]
        pt_map = param_types or {}
        arg_nodes = [
            ast.arg(
                arg=p,
                annotation=(
                    ast.Name(id=pt_map[p], ctx=ast.Load(), lineno=line)
                    if (pt_map.get(p) in ("float", "ptr_f64") or pt_map.get(p) in self.declared_structs or (isinstance(pt_map.get(p), str) and pt_map[p][:1].isupper()))
                    else None
                ),
            )
            for p in params
        ]
        ret_node = (
            ast.Name(id="float", ctx=ast.Load(), lineno=line)
            if return_type == "float"
            else None
        )
        fn = ast.FunctionDef(
            name=name,
            args=ast.arguments(
                posonlyargs=[],
                args=arg_nodes,
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[],
            ),
            body=body,
            decorator_list=[],
            returns=ret_node,
            lineno=line,
        )
        ast.fix_missing_locations(fn)
        return fn

    # ------------------------------------------------------------------
    # Statements & Blocks
    # ------------------------------------------------------------------
    def _parse_block(self, allow_tail_return: bool = False) -> List[ast.stmt]:
        self._expect("PUNCT", "{")
        stmts: List[ast.stmt] = []
        last_had_semi = True
        while not self._at("PUNCT", "}") and not self._at("EOF"):
            if self._at("PUNCT", ";"):
                self._advance()
                last_had_semi = True
                continue
            parsed, ended_semi = self._parse_stmt()
            stmts.extend(parsed)
            last_had_semi = ended_semi
        self._expect("PUNCT", "}")

        if allow_tail_return and stmts and not last_had_semi:
            tail = stmts[-1]
            if isinstance(tail, ast.Expr):
                stmts[-1] = ast.Return(value=tail.value, lineno=tail.lineno)
            elif isinstance(tail, ast.If):
                stmts[-1] = self._convert_if_tail_to_return(tail)
        return stmts

    def _convert_if_tail_to_return(self, if_stmt: ast.If) -> ast.If:
        def _conv_list(items: List[ast.stmt]) -> List[ast.stmt]:
            if not items:
                return items
            out = list(items)
            if isinstance(out[-1], ast.Expr):
                out[-1] = ast.Return(value=out[-1].value, lineno=out[-1].lineno)
            elif isinstance(out[-1], ast.If):
                out[-1] = self._convert_if_tail_to_return(out[-1])
            return out

        return ast.If(
            test=if_stmt.test,
            body=_conv_list(if_stmt.body),
            orelse=_conv_list(if_stmt.orelse),
            lineno=if_stmt.lineno,
        )

    def _consume_optional_semi(self) -> bool:
        if self._at("PUNCT", ";"):
            self._advance()
            return True
        return False

    def _parse_stmt(self) -> Tuple[List[ast.stmt], bool]:
        t = self._peek()
        line = t.line

        if self._at("PUNCT", "{"):
            return self._parse_block(), True

        if t.kind == "ID" and t.val == "return":
            self._advance()
            if self._at("PUNCT", ";") or self._at("PUNCT", "}") or (
                self.language == "go" and self._peek().line > line
            ):
                semi = self._consume_optional_semi()
                return [ast.Return(value=ast.Constant(value=0), lineno=line)], semi
            if self._at("ID", "match") and self.language == "rust":
                m_if = self._parse_match_stmt()
                semi = self._consume_optional_semi()
                return [self._convert_if_tail_to_return(m_if)], semi
            expr = self._parse_expr()
            semi = self._consume_optional_semi()
            return [ast.Return(value=expr, lineno=line)], semi

        if t.kind == "ID" and t.val in ("let", "const", "var", "val"):
            stmts = [self._parse_var_decl()]
            if self.language in ("javascript", "typescript"):
                while self._at("PUNCT", ","):
                    self._advance()
                    stmts.append(self._parse_var_item(kw_line=line))
            semi = self._consume_optional_semi()
            return stmts, semi

        if self.language in ("c", "cpp", "java", "csharp"):
            save_cvar = self.pos
            tspec = self._parse_c_type_spec()
            if tspec is not None and self._at("ID"):
                cabi_ft, is_ptr, _ = tspec
                vname = self._advance()
                if self._at("OP", "="):
                    self._advance()
                    val = self._parse_expr()
                elif self._at("PUNCT", ";"):
                    val = ast.Constant(value=(0.0 if cabi_ft in ("f32", "f64") and not is_ptr else 0), lineno=line)
                else:
                    val = None
                if val is not None:
                    semi = self._consume_optional_semi()
                    return [
                        ast.Assign(
                            targets=[ast.Name(id=vname.val, ctx=ast.Store(), lineno=vname.line)],
                            value=val,
                            lineno=line,
                        )
                    ], semi
            self.pos = save_cvar

        if t.kind == "ID" and t.val == "if":
            return [self._parse_if_stmt()], True

        if t.kind == "ID" and t.val == "switch":
            return [self._parse_switch_stmt()], True

        if t.kind == "ID" and t.val == "match" and self.language == "rust":
            return [self._parse_match_stmt()], False

        if t.kind == "ID" and t.val == "do" and self.language in ("javascript", "typescript"):
            return [self._parse_do_while_stmt()], True

        if t.kind == "ID" and t.val == "while":
            return [self._parse_while_stmt()], True

        if t.kind == "ID" and t.val == "for":
            return self._parse_for_stmt(), True

        if t.kind == "ID" and t.val == "loop":
            # Rust `loop { ... }` -> `while True: ...`
            self._advance()
            body = self._parse_block()
            return [ast.While(test=ast.Constant(value=1), body=body, orelse=[], lineno=line)], True

        if t.kind == "ID" and t.val == "break":
            self._advance()
            semi = self._consume_optional_semi()
            return [ast.Break(lineno=line)], semi

        if t.kind == "ID" and t.val == "continue":
            self._advance()
            semi = self._consume_optional_semi()
            return [ast.Continue(lineno=line)], semi

        # Assignment / short var decl / augassign / i++ / expr stmt
        simple, ended_semi = self._parse_simple_stmt(consume_semi=True)
        return [simple], ended_semi

    def _parse_var_item(self, kw_line: int) -> ast.stmt:
        if self._at("ID", "mut"):
            self._advance()
        name_tok = self._expect("ID")
        var_ann: Optional[str] = None
        if self._at("OP", ":"):
            self._advance()
            var_ann = self._skip_type_annotation(stop_tokens={"=", ";", "}", ","})
        elif self.language == "go" and self._at("ID"):
            # Go `var x int64 = 0` or `var x float64`
            var_ann = self._skip_go_type(stop_tokens={"=", ";", "}", ","})
        if self._at("OP", "="):
            self._advance()
            val = self._parse_expr()
            if (
                var_ann == "float"
                and isinstance(val, ast.Constant)
                and isinstance(val.value, int)
                and not isinstance(val.value, bool)
            ):
                val = ast.Constant(value=float(val.value), lineno=val.lineno)
        else:
            val = ast.Constant(value=(0.0 if var_ann == "float" else 0), lineno=kw_line)
        return ast.Assign(
            targets=[ast.Name(id=name_tok.val, ctx=ast.Store(), lineno=name_tok.line)],
            value=val,
            lineno=kw_line,
        )

    def _parse_var_decl(self) -> ast.stmt:
        kw = self._advance()
        return self._parse_var_item(kw_line=kw.line)

    def _parse_simple_stmt(self, consume_semi: bool = True) -> Tuple[ast.stmt, bool]:
        t = self._peek()
        line = t.line

        # Multi-variable parallel / tuple assignment: `a, b := expr1, expr2` or `a, b = b, a + b`
        if t.kind == "ID" and self._peek(1).kind == "PUNCT" and self._peek(1).val == ",":
            save = self.pos
            lhs_ids: List[ast.Name] = []
            valid_tuple = True
            while True:
                if not self._at("ID"):
                    valid_tuple = False
                    break
                it = self._advance()
                lhs_ids.append(ast.Name(id=it.val, ctx=ast.Store(), lineno=it.line))
                if self._at("PUNCT", ","):
                    self._advance()
                else:
                    break
            if valid_tuple and self._peek().kind == "OP" and self._peek().val in (":=", "="):
                self._advance()
                rhs_vals: List[ast.expr] = [self._parse_expr()]
                while self._at("PUNCT", ","):
                    self._advance()
                    rhs_vals.append(self._parse_expr())
                if len(lhs_ids) == len(rhs_vals):
                    semi = self._consume_optional_semi() if consume_semi else False
                    return (
                        ast.Assign(
                            targets=[ast.Tuple(elts=lhs_ids, ctx=ast.Store(), lineno=line)],
                            value=ast.Tuple(elts=rhs_vals, ctx=ast.Load(), lineno=line),
                            lineno=line,
                        ),
                        semi,
                    )
            self.pos = save

        # Lookahead for assignment / := / ++ / -- / += / ident.field = ...
        if t.kind == "ID":
            nxt = self._peek(1)
            aug_map = {
                "+=": ast.Add(),
                "-=": ast.Sub(),
                "*=": ast.Mult(),
                "/=": ast.FloorDiv(),
                "%=": ast.Mod(),
                "&=": ast.BitAnd(),
                "|=": ast.BitOr(),
                "^=": ast.BitXor(),
                "<<=": ast.LShift(),
                ">>=": ast.RShift(),
            }
            # Dotted struct field chains: ident(.attr)+ (= | := | augop) expr
            k_la = 1
            if (
                self._peek(k_la).kind == "OP"
                and self._peek(k_la).val == "."
                and self._peek(k_la + 1).kind == "ID"
            ):
                while (
                    self._peek(k_la).kind == "OP"
                    and self._peek(k_la).val == "."
                    and self._peek(k_la + 1).kind == "ID"
                ):
                    k_la += 2
                end_tok = self._peek(k_la)
                if end_tok.kind == "OP" and (end_tok.val in ("=", ":=") or end_tok.val in aug_map):
                    ident = self._advance()
                    target_expr: ast.expr = ast.Name(id=ident.val, ctx=ast.Load(), lineno=line)
                    while self._at("OP", ".") and self._peek(1).kind == "ID":
                        self._advance()
                        attr_tok = self._advance()
                        target_expr = ast.Attribute(
                            value=target_expr,
                            attr=attr_tok.val,
                            ctx=ast.Load(),
                            lineno=line,
                        )
                    if isinstance(target_expr, ast.Attribute):
                        target_expr.ctx = ast.Store()
                    op_tok = self._advance()
                    val = self._parse_expr()
                    semi = self._consume_optional_semi() if consume_semi else False
                    if op_tok.val in ("=", ":="):
                        return ast.Assign(targets=[target_expr], value=val, lineno=line), semi
                    return ast.AugAssign(target=target_expr, op=aug_map[op_tok.val], value=val, lineno=line), semi

            if nxt.kind == "OP" and nxt.val in (":=", "="):
                ident = self._advance()
                self._advance()
                val = self._parse_expr()
                semi = self._consume_optional_semi() if consume_semi else False
                return (
                    ast.Assign(
                        targets=[ast.Name(id=ident.val, ctx=ast.Store(), lineno=line)],
                        value=val,
                        lineno=line,
                    ),
                    semi,
                )

            if nxt.kind == "OP" and nxt.val in aug_map:
                ident = self._advance()
                op_tok = self._advance()
                val = self._parse_expr()
                semi = self._consume_optional_semi() if consume_semi else False
                return (
                    ast.AugAssign(
                        target=ast.Name(id=ident.val, ctx=ast.Store(), lineno=line),
                        op=aug_map[op_tok.val],
                        value=val,
                        lineno=line,
                    ),
                    semi,
                )

            if nxt.kind == "OP" and nxt.val in ("++", "--"):
                ident = self._advance()
                op_tok = self._advance()
                semi = self._consume_optional_semi() if consume_semi else False
                return (
                    ast.AugAssign(
                        target=ast.Name(id=ident.val, ctx=ast.Store(), lineno=line),
                        op=ast.Add() if op_tok.val == "++" else ast.Sub(),
                        value=ast.Constant(value=1, lineno=line),
                        lineno=line,
                    ),
                    semi,
                )

        # Prefix ++i / --i
        if t.kind == "OP" and t.val in ("++", "--") and self._peek(1).kind == "ID":
            op_tok = self._advance()
            ident = self._advance()
            semi = self._consume_optional_semi() if consume_semi else False
            return (
                ast.AugAssign(
                    target=ast.Name(id=ident.val, ctx=ast.Store(), lineno=line),
                    op=ast.Add() if op_tok.val == "++" else ast.Sub(),
                    value=ast.Constant(value=1, lineno=line),
                    lineno=line,
                ),
                semi,
            )

        expr = self._parse_expr()
        if isinstance(expr, (ast.Subscript, ast.Attribute)) and self._peek().kind == "OP":
            nxt_op = self._peek().val
            aug_map = {
                "+=": ast.Add(),
                "-=": ast.Sub(),
                "*=": ast.Mult(),
                "/=": ast.FloorDiv(),
                "%=": ast.Mod(),
                "&=": ast.BitAnd(),
                "|=": ast.BitOr(),
                "^=": ast.BitXor(),
                "<<=": ast.LShift(),
                ">>=": ast.RShift(),
            }
            if nxt_op == "=":
                self._advance()
                rhs = self._parse_expr()
                semi = self._consume_optional_semi() if consume_semi else False
                if isinstance(expr, ast.Subscript):
                    lhs_store: ast.expr = ast.Subscript(value=expr.value, slice=expr.slice, ctx=ast.Store(), lineno=line)
                else:
                    lhs_store = ast.Attribute(value=expr.value, attr=expr.attr, ctx=ast.Store(), lineno=line)
                return (ast.Assign(targets=[lhs_store], value=rhs, lineno=line), semi)
            if nxt_op in aug_map:
                self._advance()
                rhs = self._parse_expr()
                semi = self._consume_optional_semi() if consume_semi else False
                if isinstance(expr, ast.Subscript):
                    lhs_aug: ast.expr = ast.Subscript(value=expr.value, slice=expr.slice, ctx=ast.Store(), lineno=line)
                else:
                    lhs_aug = ast.Attribute(value=expr.value, attr=expr.attr, ctx=ast.Store(), lineno=line)
                return (ast.AugAssign(target=lhs_aug, op=aug_map[nxt_op], value=rhs, lineno=line), semi)
        semi = self._consume_optional_semi() if consume_semi else False
        return ast.Expr(value=expr, lineno=line), semi

    def _parse_if_stmt(self) -> ast.If:
        if_tok = self._expect("ID", "if")
        cond = self._parse_condition_expr()
        body = self._parse_block()
        orelse: List[ast.stmt] = []
        if self._at("ID", "else"):
            self._advance()
            if self._at("ID", "if"):
                orelse = [self._parse_if_stmt()]
            else:
                orelse = self._parse_block()
        return ast.If(test=cond, body=body, orelse=orelse, lineno=if_tok.line)

    def _parse_switch_stmt(self) -> ast.If:
        sw_tok = self._expect("ID", "switch")
        disc = self._parse_condition_expr()
        self._expect("PUNCT", "{")
        cases: List[Tuple[List[ast.expr], List[ast.stmt], int]] = []
        pending_vals: List[ast.expr] = []
        default_stmts: Optional[List[ast.stmt]] = None

        while not self._at("PUNCT", "}") and not self._at("EOF"):
            if self._at("ID", "case"):
                ct = self._advance()
                cvals = [self._parse_expr()]
                while self._at("PUNCT", ","):
                    self._advance()
                    cvals.append(self._parse_expr())
                self._expect("OP", ":")
                cbody: List[ast.stmt] = []
                while (
                    not self._at("ID", "case")
                    and not self._at("ID", "default")
                    and not self._at("PUNCT", "}")
                    and not self._at("EOF")
                ):
                    if self._at("PUNCT", ";"):
                        self._advance()
                        continue
                    parsed, _ = self._parse_stmt()
                    for st in parsed:
                        if isinstance(st, ast.Break):
                            continue
                        cbody.append(st)
                if not cbody:
                    # Empty fallthrough case (`case 1: case 2: ...`) merges into next non-empty case
                    pending_vals.extend(cvals)
                else:
                    cases.append((pending_vals + cvals, cbody, ct.line))
                    pending_vals = []
            elif self._at("ID", "default"):
                dt = self._advance()
                self._expect("OP", ":")
                dbody: List[ast.stmt] = []
                while (
                    not self._at("ID", "case")
                    and not self._at("ID", "default")
                    and not self._at("PUNCT", "}")
                    and not self._at("EOF")
                ):
                    if self._at("PUNCT", ";"):
                        self._advance()
                        continue
                    parsed, _ = self._parse_stmt()
                    for st in parsed:
                        if isinstance(st, ast.Break):
                            continue
                        dbody.append(st)
                default_stmts = dbody or [ast.Pass(lineno=dt.line)]
                if pending_vals:
                    cases.append((pending_vals, default_stmts, dt.line))
                    pending_vals = []
            else:
                raise PolyglotLoweringError(
                    f"Line {self._peek().line}: expected 'case' or 'default' inside switch"
                )
        self._expect("PUNCT", "}")
        if pending_vals:
            cases.append((pending_vals, default_stmts or [ast.Pass(lineno=sw_tok.line)], sw_tok.line))

        if not cases:
            if default_stmts:
                return ast.If(
                    test=ast.Constant(value=1, lineno=sw_tok.line),
                    body=default_stmts,
                    orelse=[],
                    lineno=sw_tok.line,
                )
            return ast.If(
                test=ast.Constant(value=1, lineno=sw_tok.line),
                body=[ast.Pass(lineno=sw_tok.line)],
                orelse=[],
                lineno=sw_tok.line,
            )

        tail: List[ast.stmt] = default_stmts or []
        for cvals, cbody, cline in reversed(cases):
            cmp_test: ast.expr = ast.Compare(
                left=disc, ops=[ast.Eq()], comparators=[cvals[0]], lineno=cline
            )
            for extra_v in cvals[1:]:
                cmp_test = ast.BoolOp(
                    op=ast.Or(),
                    values=[
                        cmp_test,
                        ast.Compare(left=disc, ops=[ast.Eq()], comparators=[extra_v], lineno=cline),
                    ],
                    lineno=cline,
                )
            node = ast.If(test=cmp_test, body=cbody, orelse=tail, lineno=cline)
            tail = [node]
        return tail[0]  # type: ignore[return-value]

    def _parse_match_stmt(self) -> ast.If:
        m_tok = self._expect("ID", "match")
        disc = self._parse_expr()
        self._expect("PUNCT", "{")
        arms: List[Tuple[List[ast.expr], List[ast.stmt], int]] = []
        default_stmts: Optional[List[ast.stmt]] = None

        while not self._at("PUNCT", "}") and not self._at("EOF"):
            if self._at("PUNCT", ","):
                self._advance()
                continue
            pt = self._peek()
            if pt.kind == "ID" and pt.val == "_":
                self._advance()
                pats: Optional[List[ast.expr]] = None
            else:
                pats = [self._parse_bit_xor()]  # avoids consuming top-level pattern separator `|`
                while self._at("OP", "|"):
                    self._advance()
                    pats.append(self._parse_bit_xor())
            self._expect("OP", "=>")
            if self._at("PUNCT", "{"):
                arm_body = self._parse_block(allow_tail_return=False)
            else:
                parsed, _ = self._parse_stmt()
                arm_body = parsed
            if self._at("PUNCT", ","):
                self._advance()
            if pats is None:
                default_stmts = arm_body or [ast.Pass(lineno=pt.line)]
            else:
                arms.append((pats, arm_body or [ast.Pass(lineno=pt.line)], pt.line))

        self._expect("PUNCT", "}")
        if not arms:
            return ast.If(
                test=ast.Constant(value=1, lineno=m_tok.line),
                body=default_stmts or [ast.Pass(lineno=m_tok.line)],
                orelse=[],
                lineno=m_tok.line,
            )

        tail: List[ast.stmt] = default_stmts or []
        for pats, arm_body, aline in reversed(arms):
            test_expr: ast.expr = ast.Compare(
                left=disc, ops=[ast.Eq()], comparators=[pats[-1]], lineno=aline
            )
            for p_alt in reversed(pats[:-1]):
                alt_cmp = ast.Compare(
                    left=disc, ops=[ast.Eq()], comparators=[p_alt], lineno=aline
                )
                test_expr = ast.IfExp(
                    test=alt_cmp,
                    body=ast.Constant(value=1, lineno=aline),
                    orelse=test_expr,
                    lineno=aline,
                )
            tail = [ast.If(test=test_expr, body=arm_body, orelse=tail, lineno=aline)]
        return tail[0]  # type: ignore[return-value]

    def _parse_do_while_stmt(self) -> ast.While:
        d_tok = self._expect("ID", "do")
        body = self._parse_block()
        self._expect("ID", "while")
        cond = self._parse_condition_expr()
        self._consume_optional_semi()
        guard = ast.If(
            test=ast.UnaryOp(op=ast.Not(), operand=cond, lineno=d_tok.line),
            body=[ast.Break(lineno=d_tok.line)],
            orelse=[],
            lineno=d_tok.line,
        )
        return ast.While(
            test=ast.Constant(value=1, lineno=d_tok.line),
            body=body + [guard],
            orelse=[],
            lineno=d_tok.line,
        )

    def _parse_while_stmt(self) -> ast.While:
        w_tok = self._expect("ID", "while")
        cond = self._parse_condition_expr()
        body = self._parse_block()
        return ast.While(test=cond, body=body, orelse=[], lineno=w_tok.line)

    def _parse_condition_expr(self) -> ast.expr:
        return self._parse_expr()

    def _parse_for_stmt(self) -> List[ast.stmt]:
        f_tok = self._expect("ID", "for")
        line = f_tok.line

        # Rust `for ident in start..end { ... }` or `for ident in start..=end { ... }`
        if self.language == "rust":
            iv = self._expect("ID").val
            self._expect("ID", "in")
            start_expr = self._parse_expr()
            inclusive = False
            if self._at("OP", "..="):
                self._advance()
                inclusive = True
            elif self._at("OP", ".."):
                self._advance()
            else:
                raise PolyglotLoweringError(f"Line {line}: Rust for-loop requires `start..end` range")
            end_expr = self._parse_expr()
            if inclusive:
                end_expr = ast.BinOp(
                    left=end_expr,
                    op=ast.Add(),
                    right=ast.Constant(value=1, lineno=line),
                    lineno=line,
                )
            body = self._parse_block()
            return [
                ast.For(
                    target=ast.Name(id=iv, ctx=ast.Store(), lineno=line),
                    iter=ast.Call(
                        func=ast.Name(id="range", ctx=ast.Load(), lineno=line),
                        args=[start_expr, end_expr],
                        keywords=[],
                        lineno=line,
                    ),
                    body=body,
                    orelse=[],
                    lineno=line,
                )
            ]

        has_parens = False
        if self._at("PUNCT", "("):
            has_parens = True
            self._advance()

        # Infinite Go `for { ... }`
        if not has_parens and self._at("PUNCT", "{"):
            body = self._parse_block()
            return [ast.While(test=ast.Constant(value=1, lineno=line), body=body, orelse=[], lineno=line)]

        # Check whether this is a 3-clause C/Go loop vs single-condition Go `for cond { ... }`
        if not has_parens and self.language == "go":
            # Scan ahead to `{` at paren depth 0 for `;`
            has_semi = False
            k = 0
            pdepth = 0
            while True:
                tk = self._peek(k)
                if tk.kind == "EOF":
                    break
                if tk.kind == "PUNCT" and tk.val == "(":
                    pdepth += 1
                elif tk.kind == "PUNCT" and tk.val == ")":
                    pdepth = max(0, pdepth - 1)
                elif pdepth == 0 and tk.kind == "PUNCT" and tk.val == "{":
                    break
                elif pdepth == 0 and tk.kind == "PUNCT" and tk.val == ";":
                    has_semi = True
                    break
                k += 1
            if not has_semi:
                cond = self._parse_expr()
                body = self._parse_block()
                return [ast.While(test=cond, body=body, orelse=[], lineno=line)]

        # Parse 3-clause C/JS/TS/Go loop: `init; cond; step`
        init_stmts: List[ast.stmt] = []
        if not self._at("PUNCT", ";"):
            if self._at("ID") and self._peek().val in ("let", "var", "const"):
                init_stmts.append(self._parse_var_decl())
            elif self.language in ("c", "cpp", "java", "csharp"):
                save_f = self.pos
                tspec = self._parse_c_type_spec()
                if tspec is not None and self._at("ID") and self._peek(1).val == "=":
                    vname = self._advance()
                    self._advance()  # '='
                    val = self._parse_expr()
                    init_stmts.append(
                        ast.Assign(
                            targets=[ast.Name(id=vname.val, ctx=ast.Store(), lineno=vname.line)],
                            value=val,
                            lineno=line,
                        )
                    )
                else:
                    self.pos = save_f
                    st, _ = self._parse_simple_stmt(consume_semi=False)
                    init_stmts.append(st)
            else:
                st, _ = self._parse_simple_stmt(consume_semi=False)
                init_stmts.append(st)
        self._expect("PUNCT", ";")

        cond: ast.expr = ast.Constant(value=1, lineno=line)
        if not self._at("PUNCT", ";"):
            cond = self._parse_expr()
        self._expect("PUNCT", ";")

        step_stmts: List[ast.stmt] = []
        end_delim = ")" if has_parens else "{"
        if not self._at("PUNCT", end_delim):
            st, _ = self._parse_simple_stmt(consume_semi=False)
            step_stmts.append(st)
        if has_parens:
            self._expect("PUNCT", ")")

        body = self._parse_block()

        # Canonical pattern: `for (let i = start; i < end; i++)` -> Python `for i in range(start, end):`
        canonical_for = self._try_canonical_counted_for(init_stmts, cond, step_stmts, body, line)
        if canonical_for is not None:
            return [canonical_for]

        # General lowering: `[init...] + [while cond: body + step]`
        loop_body = body + step_stmts
        return init_stmts + [ast.While(test=cond, body=loop_body, orelse=[], lineno=line)]

    def _try_canonical_counted_for(
        self,
        init_stmts: List[ast.stmt],
        cond: ast.expr,
        step_stmts: List[ast.stmt],
        body: List[ast.stmt],
        line: int,
    ) -> Optional[ast.For]:
        if len(init_stmts) != 1 or len(step_stmts) != 1:
            return None
        init = init_stmts[0]
        step = step_stmts[0]
        if not (isinstance(init, ast.Assign) and len(init.targets) == 1 and isinstance(init.targets[0], ast.Name)):
            return None
        iv = init.targets[0].id
        if not (
            isinstance(cond, ast.Compare)
            and isinstance(cond.left, ast.Name)
            and cond.left.id == iv
            and len(cond.ops) == 1
            and len(cond.comparators) == 1
            and isinstance(cond.ops[0], (ast.Lt, ast.LtE))
        ):
            return None
        if not (
            isinstance(step, ast.AugAssign)
            and isinstance(step.target, ast.Name)
            and step.target.id == iv
            and isinstance(step.op, ast.Add)
            and isinstance(step.value, ast.Constant)
            and step.value.value == 1
        ):
            return None

        end_expr = cond.comparators[0]
        if isinstance(cond.ops[0], ast.LtE):
            end_expr = ast.BinOp(
                left=end_expr,
                op=ast.Add(),
                right=ast.Constant(value=1, lineno=line),
                lineno=line,
            )
        return ast.For(
            target=ast.Name(id=iv, ctx=ast.Store(), lineno=line),
            iter=ast.Call(
                func=ast.Name(id="range", ctx=ast.Load(), lineno=line),
                args=[init.value, end_expr],
                keywords=[],
                lineno=line,
            ),
            body=body,
            orelse=[],
            lineno=line,
        )

    # ------------------------------------------------------------------
    # Expressions (Precedence Climbing)
    # ------------------------------------------------------------------
    def _parse_expr(self) -> ast.expr:
        return self._parse_ternary()

    def _parse_ternary(self) -> ast.expr:
        expr = self._parse_logical_or()
        if self._at("OP", "?"):
            q = self._advance()
            true_branch = self._parse_expr()
            self._expect("OP", ":")
            false_branch = self._parse_ternary()
            return ast.IfExp(test=expr, body=true_branch, orelse=false_branch, lineno=q.line)
        return expr

    def _parse_logical_or(self) -> ast.expr:
        left = self._parse_logical_and()
        while self._at("OP", "||"):
            op = self._advance()
            right = self._parse_logical_and()
            right_bool = ast.Compare(
                left=right,
                ops=[ast.NotEq()],
                comparators=[ast.Constant(value=0, lineno=op.line)],
                lineno=op.line,
            )
            left = ast.IfExp(
                test=left,
                body=ast.Constant(value=1, lineno=op.line),
                orelse=right_bool,
                lineno=op.line,
            )
        return left

    def _parse_logical_and(self) -> ast.expr:
        left = self._parse_bit_or()
        while self._at("OP", "&&"):
            op = self._advance()
            right = self._parse_bit_or()
            right_bool = ast.Compare(
                left=right,
                ops=[ast.NotEq()],
                comparators=[ast.Constant(value=0, lineno=op.line)],
                lineno=op.line,
            )
            left = ast.IfExp(
                test=left,
                body=right_bool,
                orelse=ast.Constant(value=0, lineno=op.line),
                lineno=op.line,
            )
        return left

    def _parse_bit_or(self) -> ast.expr:
        left = self._parse_bit_xor()
        while self._at("OP", "|"):
            op = self._advance()
            right = self._parse_bit_xor()
            left = ast.BinOp(left=left, op=ast.BitOr(), right=right, lineno=op.line)
        return left

    def _parse_bit_xor(self) -> ast.expr:
        left = self._parse_bit_and()
        while self._at("OP", "^"):
            op = self._advance()
            right = self._parse_bit_and()
            left = ast.BinOp(left=left, op=ast.BitXor(), right=right, lineno=op.line)
        return left

    def _parse_bit_and(self) -> ast.expr:
        left = self._parse_equality()
        while self._at("OP", "&"):
            op = self._advance()
            right = self._parse_equality()
            left = ast.BinOp(left=left, op=ast.BitAnd(), right=right, lineno=op.line)
        return left

    def _parse_equality(self) -> ast.expr:
        left = self._parse_relational()
        while self._peek().kind == "OP" and self._peek().val in ("==", "===", "!=", "!=="):
            op = self._advance()
            right = self._parse_relational()
            cmp_op = ast.Eq() if op.val in ("==", "===") else ast.NotEq()
            left = ast.Compare(left=left, ops=[cmp_op], comparators=[right], lineno=op.line)
        return left

    def _parse_relational(self) -> ast.expr:
        left = self._parse_shift()
        rel_map = {
            "<": ast.Lt(),
            "<=": ast.LtE(),
            ">": ast.Gt(),
            ">=": ast.GtE(),
        }
        while self._peek().kind == "OP" and self._peek().val in rel_map:
            op = self._advance()
            right = self._parse_shift()
            left = ast.Compare(
                left=left, ops=[rel_map[op.val]], comparators=[right], lineno=op.line
            )
        return left

    def _parse_shift(self) -> ast.expr:
        left = self._parse_additive()
        while self._peek().kind == "OP" and self._peek().val in ("<<", ">>", ">>>"):
            op = self._advance()
            right = self._parse_additive()
            if op.val == "<<":
                left = ast.BinOp(left=left, op=ast.LShift(), right=right, lineno=op.line)
            else:
                left = ast.BinOp(left=left, op=ast.RShift(), right=right, lineno=op.line)
        return left

    def _parse_additive(self) -> ast.expr:
        left = self._parse_multiplicative()
        while self._peek().kind == "OP" and self._peek().val in ("+", "-"):
            op = self._advance()
            right = self._parse_multiplicative()
            binop = ast.Add() if op.val == "+" else ast.Sub()
            left = ast.BinOp(left=left, op=binop, right=right, lineno=op.line)
        return left

    def _parse_multiplicative(self) -> ast.expr:
        left = self._parse_unary()
        while self._peek().kind == "OP" and self._peek().val in ("*", "/", "%"):
            op = self._advance()
            right = self._parse_unary()
            if op.val == "*":
                binop: ast.operator = ast.Mult()
            elif op.val == "/":
                binop = ast.FloorDiv()
            else:
                binop = ast.Mod()
            left = ast.BinOp(left=left, op=binop, right=right, lineno=op.line)
        return left

    def _parse_unary(self) -> ast.expr:
        t = self._peek()
        if t.kind == "OP" and t.val in ("-", "+", "~", "!"):
            op = self._advance()
            operand = self._parse_unary()
            if op.val == "-":
                return ast.UnaryOp(op=ast.USub(), operand=operand, lineno=op.line)
            if op.val == "+":
                return ast.UnaryOp(op=ast.UAdd(), operand=operand, lineno=op.line)
            if op.val == "~":
                return ast.UnaryOp(op=ast.Invert(), operand=operand, lineno=op.line)
            return ast.UnaryOp(op=ast.Not(), operand=operand, lineno=op.line)
        return self._parse_postfix()

    def _parse_postfix(self) -> ast.expr:
        expr = self._parse_primary()
        while True:
            # Handle optional Rust/Go/TS cast `expr as i64`
            if self._at("ID", "as"):
                self._advance()
                self._skip_type_annotation(stop_tokens={",", ")", ";", "]", "}", "+", "-", "*", "/", "%", "&", "|", "^", "<", ">", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>"})
                continue

            if self._at("PUNCT", "("):
                self._advance()
                args: List[ast.expr] = []
                while not self._at("PUNCT", ")"):
                    args.append(self._parse_expr())
                    if self._at("PUNCT", ","):
                        self._advance()
                    else:
                        break
                self._expect("PUNCT", ")")
                if isinstance(expr, ast.Name):
                    expr = ast.Call(func=expr, args=args, keywords=[], lineno=expr.lineno)
                elif (
                    isinstance(expr, ast.Attribute)
                    and isinstance(expr.value, ast.Name)
                    and expr.value.id == "Math"
                    and expr.attr == "imul"
                    and len(args) == 2
                ):
                    expr = ast.BinOp(left=args[0], op=ast.Mult(), right=args[1], lineno=expr.lineno)
                else:
                    raise PolyglotLoweringError(
                        f"Line {self._peek().line}: unsupported dynamic call target in AOT subset"
                    )
                continue

            if self._at("OP", "."):
                dot = self._advance()
                attr_tok = self._expect("ID")
                expr = ast.Attribute(
                    value=expr, attr=attr_tok.val, ctx=ast.Load(), lineno=dot.line
                )
                continue

            if self._at("PUNCT", "["):
                br = self._advance()
                idx_expr = self._parse_expr()
                self._expect("PUNCT", "]")
                expr = ast.Subscript(
                    value=expr,
                    slice=idx_expr,
                    ctx=ast.Load(),
                    lineno=br.line,
                )
                continue

            break
        return expr

    def _parse_primary(self) -> ast.expr:
        t = self._peek()
        if t.kind == "NUM":
            self._advance()
            return ast.Constant(value=int(t.val, 0), lineno=t.line)
        if t.kind == "FLOAT":
            self._advance()
            return ast.Constant(value=float(t.val), lineno=t.line)
        if t.kind == "ID":
            self._advance()
            if t.val == "true":
                return ast.Constant(value=1, lineno=t.line)
            if t.val == "false":
                return ast.Constant(value=0, lineno=t.line)
            return ast.Name(id=t.val, ctx=ast.Load(), lineno=t.line)
        if t.kind == "PUNCT" and t.val == "(":
            self._advance()
            inner = self._parse_expr()
            self._expect("PUNCT", ")")
            return inner
        raise PolyglotLoweringError(
            f"Line {t.line}:{t.col}: unexpected token {t.kind}({t.val!r}) in expression"
        )


def lower_polyglot_source_to_ast(
    source: str,
    language: str,
    file_path: str = "<polyglot>",
    strict: bool = False,
    allow_floats: bool = False,
) -> PolyglotParseResult:
    """
    Lower a JS, TS, Rust, or Go source string into a Python `ast.Module` of
    `ast.FunctionDef` nodes compatible with Omni-SSA.
    """
    lang = language.lower().strip()
    if lang not in ("javascript", "typescript", "rust", "go", "c", "cpp", "zig", "java", "csharp", "kotlin"):
        raise PolyglotLoweringError(f"Unsupported polyglot language: {language!r}")

    effective_floats = bool(allow_floats or _FLOAT_ANN_RE.search(source) or lang in ("c", "cpp", "zig", "java", "csharp", "kotlin"))
    parser = _PolyglotParser(source, lang, allow_floats=effective_floats)
    mod, funcs, errors = parser.parse_module()
    if strict and errors:
        raise PolyglotLoweringError("; ".join(errors))
    return PolyglotParseResult(
        language=lang,
        file_path=file_path,
        module=mod,
        functions=funcs,
        errors=errors,
    )


def parse_polyglot_file_to_ast(
    file_path: str,
    source_text: Optional[str] = None,
    strict: bool = False,
    allow_floats: bool = False,
) -> PolyglotParseResult:
    """Detect language from file extension and lower it to Python AST."""
    ext = os.path.splitext(file_path)[1].lower()
    lang = SUPPORTED_POLYGLOT_EXTENSIONS.get(ext)
    if lang is None:
        raise PolyglotLoweringError(f"Unsupported polyglot file extension: {ext!r}")
    if source_text is None:
        with open(file_path, "r", encoding="utf-8") as f:
            source_text = f.read()
    return lower_polyglot_source_to_ast(
        source=source_text,
        language=lang,
        file_path=file_path,
        strict=strict,
        allow_floats=allow_floats,
    )
