"""
Alpha-C100: JSON-RPC 2.0 Stdio Language Server Protocol (`lsp/omnicc_lsp.py`).

Provides live IDE diagnostics and hover intelligence backed by OmniCompiler's
AST parser, Omni-SSA IR lowering, Sanitizer static pattern checks, and CPG/ABI metadata.
Uses standard LSP `Content-Length: <n>\\r\\n\\r\\n<payload>` wire framing.
"""

from __future__ import annotations

import ast
import json
import sys
from typing import Any, BinaryIO, Dict, List, Optional

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
    """In-process & stdio JSON-RPC 2.0 LSP state machine for `.py` / Omni sources."""

    def __init__(self) -> None:
        self.documents: Dict[str, str] = {}
        self.shutdown_requested: bool = False

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

    def handle_message(self, msg: Dict[str, Any]) -> List[Dict[str, Any]]:
        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") or {}
        outgoing: List[Dict[str, Any]] = []

        if method == "initialize":
            outgoing.append({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "capabilities": {
                        "textDocumentSync": 1,
                        "hoverProvider": True,
                    },
                    "serverInfo": {"name": "omnicc-lsp", "version": "1.0.0"},
                },
            })
        elif method == "textDocument/didOpen":
            td = params.get("textDocument", {})
            uri = str(td.get("uri", ""))
            txt = str(td.get("text", ""))
            self.documents[uri] = txt
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
                self.documents[uri] = txt
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
