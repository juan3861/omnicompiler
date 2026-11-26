"""
Alpha-C100: JSON-RPC 2.0 Stdio Language Server Protocol (`lsp/omnicc_lsp.py`).

Provides live IDE diagnostics and hover intelligence backed by OmniCompiler's
AST parser, Omni-SSA IR lowering, Sanitizer static pattern checks, and CPG/ABI metadata.
Uses standard LSP `Content-Length: <n>\\r\\n\\r\\n<payload>` wire framing.
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

from compiler.sanitizer_pass import SanitizerInstrumentationPass
from compiler.ssa_ir import lower_ast_to_ssa


def encode_lsp_message(payload: Dict[str, Any]) -> bytes:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    return header + body


def read_lsp_message(stream: BinaryIO) -> Optional[Dict[str, Any]]:
    headers: Dict[str, str] = {}
    while True:
        line_b = stream.readline()
        if not line_b:
            return None
        line = line_b.decode("ascii", errors="replace").strip()
        if not line:
            if headers:
                break
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    body = b""
    while len(body) < length:
        chunk = stream.read(length - len(body))
        if not chunk:
            return None
        body += chunk
    return json.loads(body.decode("utf-8"))


class OmniLSPServer:
    """In-process & stdio JSON-RPC 2.0 LSP state machine with cross-file workspace CPG index."""

    def __init__(self) -> None:
        self.documents: Dict[str, str] = {}
        self.workspace_roots: List[str] = []
        self.symbol_defs: Dict[str, List[Dict[str, Any]]] = {}  # sym -> [{"uri", "range", "kind", "lang"}]
        self.doc_symbols: Dict[str, List[Dict[str, Any]]] = {}
        self.shutdown_requested: bool = False

    @staticmethod
    def _uri_to_path(uri: str) -> str:
        if not uri.startswith("file://"):
            return os.path.abspath(uri)
        parsed = urllib.parse.urlparse(uri)
        path = urllib.request.url2pathname(parsed.path)
        if parsed.netloc:
            path = f"//{parsed.netloc}{path}"
        return os.path.abspath(path)

    @staticmethod
    def _path_to_uri(path: str) -> str:
        return "file:///" + os.path.abspath(path).replace("\\", "/").lstrip("/")

    def _index_document(self, uri: str, text: str) -> None:
        self.documents[uri] = text
        # Clear prior definitions for this URI
        for sym_list in self.symbol_defs.values():
            sym_list[:] = [d for d in sym_list if d.get("uri") != uri]

        doc_syms: List[Dict[str, Any]] = []
        ext = os.path.splitext(uri)[1].lower()
        if ext == ".py" or not ext:
            try:
                tree = ast.parse(text, filename=uri)
                for node in tree.body:
                    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                        sl = max(0, node.lineno - 1)
                        el = max(sl, (getattr(node, "end_lineno", node.lineno) or node.lineno) - 1)
                        sc = max(0, getattr(node, "col_offset", 0))
                        rng = {"start": {"line": sl, "character": sc}, "end": {"line": sl, "character": sc + len(node.name)}}
                        full_rng = {"start": {"line": sl, "character": 0}, "end": {"line": el, "character": 0}}
                        kind = 5 if isinstance(node, ast.ClassDef) else 12
                        self.symbol_defs.setdefault(node.name, []).append({"uri": uri, "range": rng, "kind": kind, "lang": "python"})
                        doc_syms.append({"name": node.name, "kind": kind, "range": full_rng, "selectionRange": rng})
            except SyntaxError:
                pass
        else:
            # Polyglot C / C++ / Go / Rust definition extraction
            lines = text.splitlines()
            fn_pats = (
                re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
                re.compile(r"^\s*func\s+(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\("),
                re.compile(r"^\s*(?:pub\s+)?(?:unsafe\s+)?(?:extern\s+\"C\"\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
                re.compile(r"^\s*(?:extern\s+(?:\"C\"\s+)?)?(?:static\s+|inline\s+)*(?:[A-Za-z_][A-Za-z0-9_*\s]+?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*(?:\{|$)"),
            )
            for idx_l, line_str in enumerate(lines):
                for pat in fn_pats:
                    m = pat.match(line_str)
                    if m:
                        sname = m.group(1)
                        if sname in ("if", "for", "while", "switch", "return"):
                            continue
                        col = max(0, line_str.find(sname))
                        rng = {"start": {"line": idx_l, "character": col}, "end": {"line": idx_l, "character": col + len(sname)}}
                        self.symbol_defs.setdefault(sname, []).append({"uri": uri, "range": rng, "kind": 12, "lang": ext.lstrip(".")})
                        doc_syms.append({"name": sname, "kind": 12, "range": rng, "selectionRange": rng})
                        break
        self.doc_symbols[uri] = doc_syms

    def index_workspace_root(self, root_path: str) -> int:
        if not root_path or not os.path.isdir(root_path):
            return 0
        count = 0
        exts = {".py", ".c", ".h", ".cc", ".cpp", ".hpp", ".rs", ".go"}
        for rdir, _, files in os.walk(root_path):
            if any(p in rdir for p in (".git", "__pycache__", ".venv", "node_modules", "target", "build")):
                continue
            for fn in sorted(files):
                if os.path.splitext(fn)[1].lower() in exts:
                    fp = os.path.join(rdir, fn)
                    uri = self._path_to_uri(fp)
                    try:
                        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                            self._index_document(uri, f.read())
                        count += 1
                    except OSError:
                        pass
        return count

    @staticmethod
    def _ident_at(text: str, line: int, character: int) -> Optional[str]:
        lines = text.splitlines()
        if line < 0 or line >= len(lines):
            return None
        row = lines[line]
        if not row:
            return None
        pos = min(max(0, character), len(row) - 1)
        if not (row[pos].isalnum() or row[pos] == "_"):
            if pos > 0 and (row[pos - 1].isalnum() or row[pos - 1] == "_"):
                pos -= 1
            else:
                return None
        l_i = pos
        while l_i > 0 and (row[l_i - 1].isalnum() or row[l_i - 1] == "_"):
            l_i -= 1
        r_i = pos + 1
        while r_i < len(row) and (row[r_i].isalnum() or row[r_i] == "_"):
            r_i += 1
        tok = row[l_i:r_i]
        return tok if (tok and (tok[0].isalpha() or tok[0] == "_")) else None

    def find_definitions(self, uri: str, line: int, character: int) -> List[Dict[str, Any]]:
        ident = self._ident_at(self.documents.get(uri, ""), line, character)
        if not ident:
            return []
        return [{"uri": d["uri"], "range": d["range"]} for d in self.symbol_defs.get(ident, [])]

    def find_references(self, uri: str, line: int, character: int) -> List[Dict[str, Any]]:
        ident = self._ident_at(self.documents.get(uri, ""), line, character)
        if not ident:
            return []
        pat = re.compile(rf"\b{re.escape(ident)}\b")
        locs: List[Dict[str, Any]] = []
        for doc_uri, txt in sorted(self.documents.items()):
            for idx_l, row in enumerate(txt.splitlines()):
                for m in pat.finditer(row):
                    locs.append({
                        "uri": doc_uri,
                        "range": {
                            "start": {"line": idx_l, "character": m.start()},
                            "end": {"line": idx_l, "character": m.end()},
                        },
                    })
        return locs

    def analyze_diagnostics(self, uri: str, text: str) -> List[Dict[str, Any]]:
        diags: List[Dict[str, Any]] = []
        try:
            tree = ast.parse(text, filename=uri)
        except SyntaxError as exc:
            ln = max(0, (exc.lineno or 1) - 1)
            col = max(0, (exc.offset or 1) - 1)
            diags.append({
                "range": {"start": {"line": ln, "character": col}, "end": {"line": ln, "character": col + 1}},
                "severity": 1,
                "source": "omnicc",
                "message": f"SyntaxError: {exc.msg}",
            })
            return diags

        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                if isinstance(node.right, ast.Constant) and node.right.value == 0:
                    ln = max(0, getattr(node, "lineno", 1) - 1)
                    col = max(0, getattr(node, "col_offset", 0))
                    diags.append({
                        "range": {"start": {"line": ln, "character": col}, "end": {"line": ln, "character": col + 4}},
                        "severity": 1,
                        "source": "omnicc-ubsan",
                        "message": "Constant divisor is 0 (UBSAN_INTEGER_DIVIDE_BY_ZERO guaranteed trap)",
                    })
        return diags

    def build_hover(self, uri: str, line: int) -> Optional[Dict[str, Any]]:
        text = self.documents.get(uri, "")
        if not text:
            return None
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return None

        target_fn: Optional[ast.FunctionDef] = None
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                start_l = max(0, node.lineno - 1)
                end_l = max(start_l, (getattr(node, "end_lineno", node.lineno) or node.lineno) - 1)
                if start_l <= line <= end_l:
                    target_fn = node
                    break
        if target_fn is None:
            return None

        ssa_fn = lower_ast_to_ssa(target_fn, optimize=True)
        n_blocks = len(ssa_fn.blocks)
        n_insts = sum(len(b.instructions) for b in ssa_fn.blocks)
        san_rep = SanitizerInstrumentationPass("asan,ubsan").instrument_function(ssa_fn)
        win_regs = ["RCX", "RDX", "R8", "R9"][:len(ssa_fn.params)]
        sysv_regs = ["RDI", "RSI", "RDX", "RCX", "R8", "R9"][:len(ssa_fn.params)]
        md = (
            f"### OmniCompiler Symbol `{target_fn.name}`\n"
            f"- **Omni-SSA IR**: {n_blocks} block(s), {n_insts} instruction(s)\n"
            f"- **Sanitizer Traps Guarded**: {san_rep.trap_blocks_inserted} "
            f"(div={san_rep.ubsan_div_checks}, shift={san_rep.ubsan_shift_checks}, "
            f"null={san_rep.asan_null_checks}, oob={san_rep.asan_bounds_checks})\n"
            f"- **Win64 ABI Regs**: `{', '.join(win_regs) or 'void'}` -> `RAX`\n"
            f"- **System V AMD64 Regs**: `{', '.join(sysv_regs) or 'void'}` -> `RAX`"
        )
        return {"contents": {"kind": "markdown", "value": md}}

    def build_code_actions(
        self,
        uri: str,
        range_obj: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Generates automated CodeAction quick-fixes for UBSan/syntax diagnostics."""
        actions: List[Dict[str, Any]] = []
        txt = self.documents.get(uri, "")
        lines = txt.splitlines()
        diags = (context or {}).get("diagnostics") or []
        if not diags and lines:
            diags = self.analyze_diagnostics(uri, txt)

        req_line = int(((range_obj or {}).get("start") or {}).get("line", 0))
        for d in diags:
            msg = str(d.get("message", ""))
            d_rng = d.get("range") or {}
            d_line = int(((d_rng.get("start") or {}).get("line", req_line)))
            if "DIVIDE_BY_ZERO" in msg or "divisor is 0" in msg.lower():
                if 0 <= d_line < len(lines):
                    src_line = lines[d_line]
                    indent = src_line[: len(src_line) - len(src_line.lstrip())]
                    guarded = f"{indent}# guarded by omnicc UBSan quickfix\n{indent}return 0  # replaced div-by-zero: {src_line.strip()}"
                    actions.append({
                        "title": "Guard constant division-by-zero (OmniCompiler UBSan)",
                        "kind": "quickfix",
                        "diagnostics": [d],
                        "isPreferred": True,
                        "edit": {
                            "changes": {
                                uri: [{
                                    "range": {
                                        "start": {"line": d_line, "character": 0},
                                        "end": {"line": d_line, "character": len(src_line)},
                                    },
                                    "newText": guarded,
                                }]
                            }
                        },
                    })
        return actions

    def build_completions(self, uri: str, line: int, character: int) -> List[Dict[str, Any]]:
        """Returns workspace-wide symbol completions sorted deterministically."""
        txt = self.documents.get(uri, "")
        prefix = self._ident_at(txt, line, max(0, character - 1)) or ""
        pref_low = prefix.lower()
        items: List[Dict[str, Any]] = []
        seen: set = set()
        for sym_name in sorted(self.symbol_defs.keys()):
            if sym_name in seen:
                continue
            if pref_low and not sym_name.lower().startswith(pref_low):
                continue
            seen.add(sym_name)
            defs = self.symbol_defs[sym_name]
            meta = defs[0] if defs else {}
            lang = meta.get("lang", "omni")
            base_f = os.path.basename(self._uri_to_path(str(meta.get("uri", ""))))
            lsp_kind = 7 if meta.get("kind") == 5 else 3  # Class=7, Function=3
            items.append({
                "label": sym_name,
                "kind": lsp_kind,
                "detail": f"[{lang}] {base_f}",
                "insertText": sym_name,
            })
        return items

    def build_semantic_tokens(self, uri: str) -> Dict[str, List[int]]:
        """Encodes LSP delta-encoded 5-int semantic tokens over Python AST definitions/params."""
        text = self.documents.get(uri, "")
        raw_tokens: List[Tuple[int, int, int, int, int]] = []
        # Legend indices: 0=function, 1=class, 2=parameter, 3=variable, 4=keyword
        try:
            tree = ast.parse(text, filename=uri)
            lines = text.splitlines()
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    ln = max(0, node.lineno - 1)
                    if ln < len(lines):
                        col = lines[ln].find(node.name, getattr(node, "col_offset", 0))
                        if col >= 0:
                            raw_tokens.append((ln, col, len(node.name), 0, 1))
                    for arg in node.args.args:
                        aln = max(0, getattr(arg, "lineno", node.lineno) - 1)
                        acol = max(0, getattr(arg, "col_offset", 0))
                        raw_tokens.append((aln, acol, len(arg.arg), 2, 1))
                elif isinstance(node, ast.ClassDef):
                    ln = max(0, node.lineno - 1)
                    if ln < len(lines):
                        col = lines[ln].find(node.name, getattr(node, "col_offset", 0))
                        if col >= 0:
                            raw_tokens.append((ln, col, len(node.name), 1, 1))
        except SyntaxError:
            pass

        raw_tokens.sort(key=lambda t: (t[0], t[1]))
        data: List[int] = []
        prev_line = 0
        prev_char = 0
        for ln, col, length, ttype, tmod in raw_tokens:
            d_line = ln - prev_line
            d_char = (col - prev_char) if d_line == 0 else col
            data.extend([d_line, d_char, length, ttype, tmod])
            prev_line = ln
            prev_char = col
        return {"data": data}

    def handle_message(self, msg: Dict[str, Any]) -> List[Dict[str, Any]]:
        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") or {}
        outgoing: List[Dict[str, Any]] = []

        if method == "initialize":
            root_uri = params.get("rootUri")
            if isinstance(root_uri, str) and root_uri:
                rp = self._uri_to_path(root_uri)
                if rp not in self.workspace_roots:
                    self.workspace_roots.append(rp)
                    self.index_workspace_root(rp)
            for wf in params.get("workspaceFolders") or []:
                if isinstance(wf, dict) and wf.get("uri"):
                    rp = self._uri_to_path(str(wf["uri"]))
                    if rp not in self.workspace_roots:
                        self.workspace_roots.append(rp)
                        self.index_workspace_root(rp)
            outgoing.append({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "capabilities": {
                        "textDocumentSync": 1,
                        "hoverProvider": True,
                        "definitionProvider": True,
                        "referencesProvider": True,
                        "documentSymbolProvider": True,
                        "codeActionProvider": True,
                        "completionProvider": {"triggerCharacters": [".", ":"]},
                        "semanticTokensProvider": {
                            "legend": {
                                "tokenTypes": ["function", "class", "parameter", "variable", "keyword"],
                                "tokenModifiers": ["declaration", "definition"],
                            },
                            "full": True,
                        },
                    },
                    "serverInfo": {"name": "omnicc-lsp", "version": "1.2.0"},
                },
            })
        elif method == "textDocument/didOpen":
            td = params.get("textDocument", {})
            uri = str(td.get("uri", ""))
            txt = str(td.get("text", ""))
            self._index_document(uri, txt)
            outgoing.append({
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {"uri": uri, "diagnostics": self.analyze_diagnostics(uri, txt)},
            })
        elif method == "textDocument/didChange":
            td = params.get("textDocument", {})
            uri = str(td.get("uri", ""))
            changes = params.get("contentChanges", [])
            if changes:
                txt = str(changes[-1].get("text", ""))
                self._index_document(uri, txt)
                outgoing.append({
                    "jsonrpc": "2.0",
                    "method": "textDocument/publishDiagnostics",
                    "params": {"uri": uri, "diagnostics": self.analyze_diagnostics(uri, txt)},
                })
        elif method == "textDocument/hover":
            td = params.get("textDocument", {})
            pos = params.get("position", {})
            uri = str(td.get("uri", ""))
            hover_res = self.build_hover(uri, int(pos.get("line", 0)))
            outgoing.append({"jsonrpc": "2.0", "id": msg_id, "result": hover_res})
        elif method == "textDocument/definition":
            td = params.get("textDocument", {})
            pos = params.get("position", {})
            uri = str(td.get("uri", ""))
            defs = self.find_definitions(uri, int(pos.get("line", 0)), int(pos.get("character", 0)))
            outgoing.append({"jsonrpc": "2.0", "id": msg_id, "result": defs})
        elif method == "textDocument/references":
            td = params.get("textDocument", {})
            pos = params.get("position", {})
            uri = str(td.get("uri", ""))
            refs = self.find_references(uri, int(pos.get("line", 0)), int(pos.get("character", 0)))
            outgoing.append({"jsonrpc": "2.0", "id": msg_id, "result": refs})
        elif method == "textDocument/documentSymbol":
            td = params.get("textDocument", {})
            uri = str(td.get("uri", ""))
            outgoing.append({"jsonrpc": "2.0", "id": msg_id, "result": self.doc_symbols.get(uri, [])})
        elif method == "textDocument/codeAction":
            td = params.get("textDocument", {})
            uri = str(td.get("uri", ""))
            actions = self.build_code_actions(uri, params.get("range") or {}, params.get("context") or {})
            outgoing.append({"jsonrpc": "2.0", "id": msg_id, "result": actions})
        elif method == "textDocument/completion":
            td = params.get("textDocument", {})
            pos = params.get("position", {})
            uri = str(td.get("uri", ""))
            items = self.build_completions(uri, int(pos.get("line", 0)), int(pos.get("character", 0)))
            outgoing.append({"jsonrpc": "2.0", "id": msg_id, "result": items})
        elif method == "textDocument/semanticTokens/full":
            td = params.get("textDocument", {})
            uri = str(td.get("uri", ""))
            toks = self.build_semantic_tokens(uri)
            outgoing.append({"jsonrpc": "2.0", "id": msg_id, "result": toks})
        elif method == "shutdown":
            self.shutdown_requested = True
            outgoing.append({"jsonrpc": "2.0", "id": msg_id, "result": None})
        elif method == "exit":
            self.shutdown_requested = True
        elif msg_id is not None:
            outgoing.append({
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            })
        return outgoing


def run_stdio_server(in_stream: Optional[BinaryIO] = None, out_stream: Optional[BinaryIO] = None) -> int:
    inp = in_stream or sys.stdin.buffer
    out = out_stream or sys.stdout.buffer
    srv = OmniLSPServer()

    while True:
        msg = read_lsp_message(inp)
        if msg is None:
            break
        responses = srv.handle_message(msg)
        for resp in responses:
            out.write(encode_lsp_message(resp))
        out.flush()
        if msg.get("method") == "exit":
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(run_stdio_server())
