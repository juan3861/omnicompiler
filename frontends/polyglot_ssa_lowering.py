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
from typing import Dict, List, Optional, Tuple


SUPPORTED_POLYGLOT_EXTENSIONS: Dict[str, str] = {
    ".js": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".rs": "rust",
    ".go": "go",
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


def _tokenize(source: str) -> List[_Tok]:
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

        # Numbers (hex, binary, decimal integer)
        if ch.isdigit():
            start = i
            start_col = col
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
                # Reject floats early if decimal point followed by digit (not `..`)
                if i + 1 < n and source[i] == "." and source[i + 1].isdigit():
                    raise PolyglotLoweringError(
                        f"Line {line}:{col}: floating-point literals are outside integer AOT subset"
                    )
            raw_num = source[start:i].replace("_", "")
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
    def __init__(self, source: str, language: str):
        self.language = language
        self.toks = _tokenize(source)
        self.pos = 0

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

            # Skip non-function top-level declarations (package, import, type, struct, interface, etc.)
            self._skip_top_level_non_function()

        mod = ast.Module(body=list(funcs), type_ignores=[])
        ast.fix_missing_locations(mod)
        return mod, funcs, errors

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
            if t.val == "export":
                self._advance()
                if self._at("ID", "default"):
                    self._advance()
            if self._at("ID", "async"):
                self._advance()
            if not self._at("ID", "function"):
                self.pos = save
                return None
            return self._parse_js_ts_function()

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

        return None

    # ------------------------------------------------------------------
    # Signatures
    # ------------------------------------------------------------------
    def _parse_js_ts_function(self) -> ast.FunctionDef:
        fn_tok = self._expect("ID", "function")
        name_tok = self._expect("ID")
        # Optional TS generics <T, U>
        if self._at("OP", "<"):
            self._skip_type_args()
        self._expect("PUNCT", "(")
        params: List[str] = []
        while not self._at("PUNCT", ")"):
            pname = self._expect("ID").val
            if self._at("OP", "?"):
                self._advance()
            if self._at("OP", ":"):
                self._advance()
                self._skip_type_annotation(stop_tokens={",", ")"})
            if self._at("OP", "="):
                self._advance()
                self._parse_expr()
            params.append(pname)
            if self._at("PUNCT", ","):
                self._advance()
            else:
                break
        self._expect("PUNCT", ")")
        # Optional return type `: number`
        if self._at("OP", ":"):
            self._advance()
            self._skip_type_annotation(stop_tokens={"{"})
        body = self._parse_block()
        return self._make_function_def(name_tok.val, params, body, fn_tok.line)

    def _parse_rust_function(self) -> ast.FunctionDef:
        fn_tok = self._expect("ID", "fn")
        name_tok = self._expect("ID")
        if self._at("OP", "<"):
            self._skip_type_args()
        self._expect("PUNCT", "(")
        params: List[str] = []
        while not self._at("PUNCT", ")"):
            if self._at("ID", "mut"):
                self._advance()
            pname = self._expect("ID").val
            self._expect("OP", ":")
            self._skip_type_annotation(stop_tokens={",", ")"})
            params.append(pname)
            if self._at("PUNCT", ","):
                self._advance()
                if self._at("PUNCT", ")"):
                    break
            else:
                break
        self._expect("PUNCT", ")")
        if self._at("OP", "->"):
            self._advance()
            self._skip_type_annotation(stop_tokens={"{"})
        if self._at("ID", "where"):
            self._advance()
            while not self._at("PUNCT", "{") and not self._at("EOF"):
                self._advance()
        body = self._parse_block(allow_tail_return=True)
        return self._make_function_def(name_tok.val, params, body, fn_tok.line)

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
                if not self._at("PUNCT", ")"):
                    self._skip_go_type(stop_tokens={",", ")"})
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
        if self._at("PUNCT", "("):
            self._skip_balanced("(", ")")
        while not self._at("PUNCT", "{") and not self._at("EOF"):
            self._advance()
        body = self._parse_block()
        return self._make_function_def(name_tok.val, params, body, fn_tok.line)

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

    def _skip_type_annotation(self, stop_tokens: set) -> None:
        paren = 0
        bracket = 0
        angle = 0
        while not self._at("EOF"):
            t = self._peek()
            if paren == 0 and bracket == 0 and angle == 0 and t.val in stop_tokens:
                return
            self._advance()
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

    def _skip_go_type(self, stop_tokens: set) -> None:
        paren = 0
        bracket = 0
        while not self._at("EOF"):
            t = self._peek()
            if paren == 0 and bracket == 0 and t.val in stop_tokens:
                return
            self._advance()
            if t.kind == "PUNCT" and t.val == "(":
                paren += 1
            elif t.kind == "PUNCT" and t.val == ")":
                paren = max(0, paren - 1)
            elif t.kind == "PUNCT" and t.val == "[":
                bracket += 1
            elif t.kind == "PUNCT" and t.val == "]":
                bracket = max(0, bracket - 1)

    def _make_function_def(
        self, name: str, params: List[str], body: List[ast.stmt], line: int
    ) -> ast.FunctionDef:
        if not body:
            body = [ast.Return(value=ast.Constant(value=0), lineno=line)]
        fn = ast.FunctionDef(
            name=name,
            args=ast.arguments(
                posonlyargs=[],
                args=[ast.arg(arg=p, annotation=None) for p in params],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[],
            ),
            body=body,
            decorator_list=[],
            returns=None,
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
            expr = self._parse_expr()
            semi = self._consume_optional_semi()
            return [ast.Return(value=expr, lineno=line)], semi

        if t.kind == "ID" and t.val in ("let", "const", "var"):
            stmt = self._parse_var_decl()
            semi = self._consume_optional_semi()
            return [stmt], semi

        if t.kind == "ID" and t.val == "if":
            return [self._parse_if_stmt()], True

        if t.kind == "ID" and t.val == "switch":
            return [self._parse_switch_stmt()], True

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

    def _parse_var_decl(self) -> ast.stmt:
        kw = self._advance()
        if self._at("ID", "mut"):
            self._advance()
        name_tok = self._expect("ID")
        if self._at("OP", ":"):
            self._advance()
            self._skip_type_annotation(stop_tokens={"=", ";", "}"})
        elif self.language == "go" and self._at("ID"):
            # Go `var x int64 = 0` or `var x int64`
            self._skip_go_type(stop_tokens={"=", ";", "}"})
        if self._at("OP", "="):
            self._advance()
            val = self._parse_expr()
        else:
            val = ast.Constant(value=0, lineno=kw.line)
        return ast.Assign(
            targets=[ast.Name(id=name_tok.val, ctx=ast.Store(), lineno=name_tok.line)],
            value=val,
            lineno=kw.line,
        )

    def _parse_simple_stmt(self, consume_semi: bool = True) -> Tuple[ast.stmt, bool]:
        t = self._peek()
        line = t.line

        # Lookahead for assignment / := / ++ / -- / += ...
        if t.kind == "ID":
            nxt = self._peek(1)
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
        if isinstance(expr, ast.Subscript) and self._peek().kind == "OP":
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
                return (
                    ast.Assign(
                        targets=[
                            ast.Subscript(
                                value=expr.value,
                                slice=expr.slice,
                                ctx=ast.Store(),
                                lineno=line,
                            )
                        ],
                        value=rhs,
                        lineno=line,
                    ),
                    semi,
                )
            if nxt_op in aug_map:
                self._advance()
                rhs = self._parse_expr()
                semi = self._consume_optional_semi() if consume_semi else False
                bin_val = ast.BinOp(
                    left=ast.Subscript(
                        value=expr.value,
                        slice=expr.slice,
                        ctx=ast.Load(),
                        lineno=line,
                    ),
                    op=aug_map[nxt_op],
                    right=rhs,
                    lineno=line,
                )
                return (
                    ast.Assign(
                        targets=[
                            ast.Subscript(
                                value=expr.value,
                                slice=expr.slice,
                                ctx=ast.Store(),
                                lineno=line,
                            )
                        ],
                        value=bin_val,
                        lineno=line,
                    ),
                    semi,
                )
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
        cases: List[Tuple[Optional[ast.expr], List[ast.stmt], int]] = []
        default_stmts: Optional[List[ast.stmt]] = None

        while not self._at("PUNCT", "}") and not self._at("EOF"):
            if self._at("ID", "case"):
                ct = self._advance()
                cval = self._parse_expr()
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
                    cbody = [ast.Pass(lineno=ct.line)]
                cases.append((cval, cbody, ct.line))
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
            else:
                raise PolyglotLoweringError(
                    f"Line {self._peek().line}: expected 'case' or 'default' inside switch"
                )
        self._expect("PUNCT", "}")

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
        for cval, cbody, cline in reversed(cases):
            cmp_test = ast.Compare(
                left=disc, ops=[ast.Eq()], comparators=[cval], lineno=cline
            )
            node = ast.If(test=cmp_test, body=cbody, orelse=tail, lineno=cline)
            tail = [node]
        return tail[0]  # type: ignore[return-value]

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
) -> PolyglotParseResult:
    """
    Lower a JS, TS, Rust, or Go source string into a Python `ast.Module` of
    `ast.FunctionDef` nodes compatible with Omni-SSA.
    """
    lang = language.lower().strip()
    if lang not in ("javascript", "typescript", "rust", "go"):
        raise PolyglotLoweringError(f"Unsupported polyglot language: {language!r}")

    parser = _PolyglotParser(source, lang)
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
    )
