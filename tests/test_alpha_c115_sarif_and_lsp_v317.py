import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

from lsp.omnicc_lsp import OmniLSPServer, encode_lsp_message, read_lsp_message
from omnicc_cli import main as omnicc_cli_main
from packaging.sarif_exporter import SARIFExporter, SARIF_SCHEMA_URL


class TestAlphaC115SarifAndLspV317(unittest.TestCase):
    def test_sarif_cli_end_to_end_and_findings_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_a = os.path.join(tmp, "repo_a")
            repo_b = os.path.join(tmp, "repo_b")
            os.makedirs(repo_a, exist_ok=True)
            os.makedirs(repo_b, exist_ok=True)

            with open(os.path.join(repo_a, "omnicompiler.json"), "w", encoding="utf-8") as mf:
                json.dump({"name": "repo_a", "language": "python"}, mf)
            with open(os.path.join(repo_b, "omnicompiler.json"), "w", encoding="utf-8") as mf:
                json.dump({"name": "repo_b", "language": "python"}, mf)

            with open(os.path.join(repo_a, "calc.py"), "w", encoding="utf-8") as f:
                f.write(
                    "def checked_calc(x: int, y: int) -> int:\n"
                    "    q = x // y\n"
                    "    s = x << (y & 7)\n"
                    "    return q + s\n"
                )
            with open(os.path.join(repo_b, "app.py"), "w", encoding="utf-8") as f:
                f.write(
                    "from calc import checked_calc\n\n"
                    "def omni_main(a: int, b: int) -> int:\n"
                    "    return checked_calc(a, b)\n"
                )

            out_base = os.path.join(tmp, "out", "c115_mod")
            sarif_path = os.path.join(tmp, "out", "c115_report.sarif")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = omnicc_cli_main([
                    "build",
                    "--repos",
                    f"{repo_a},{repo_b}",
                    "--output",
                    out_base,
                    "--backend",
                    "native",
                    "--sanitize",
                    "asan,ubsan",
                    "--no-provenance",
                    "--sarif",
                    sarif_path,
                    "--json",
                ])
            self.assertEqual(rc, 0)
            summary = json.loads(buf.getvalue())
            self.assertTrue(summary["success"])
            self.assertEqual(os.path.abspath(summary["sarif_path"]), os.path.abspath(sarif_path))
            self.assertEqual(summary["sarif"]["schema"], "2.1.0")
            self.assertTrue(os.path.isfile(sarif_path))

            with open(sarif_path, "r", encoding="utf-8") as sf:
                doc = json.load(sf)

            self.assertEqual(doc["version"], "2.1.0")
            self.assertEqual(doc["$schema"], SARIF_SCHEMA_URL)
            run0 = doc["runs"][0]
            self.assertEqual(run0["tool"]["driver"]["name"], "OmniRepoCompiler")
            rule_ids = {r["id"] for r in run0["tool"]["driver"]["rules"]}
            self.assertTrue({
                "OMNI-CPG-TAINT-001",
                "OMNI-BIABD-HEAP-002",
                "OMNI-SAN-TRAP-003",
                "OMNI-ASM-INV-004",
                "OMNI-BIN-SEC-005",
            }.issubset(rule_ids))

            san_findings = [r for r in run0["results"] if r["ruleId"] == "OMNI-SAN-TRAP-003"]
            self.assertGreaterEqual(len(san_findings), 1)
            self.assertTrue(any("checked_calc" in r["message"]["text"] for r in san_findings))

            # Verify synthetic security rule mapping directly
            sec_doc = SARIFExporter.build_sarif(
                {
                    "stages": {
                        "cpg_security": {"taint_leak_detected": True, "isolation_preserved": False},
                        "separation_logic": {"heap_disjointness_proven": False},
                        "formal_audit": {"is_valid": False, "structural_audit": False},
                    }
                },
                artifact_path=summary["artifact_path"],
                repo_paths=[repo_a, repo_b],
            )
            sec_ids = {r["ruleId"] for r in sec_doc["runs"][0]["results"]}
            self.assertEqual(sec_ids, {"OMNI-CPG-TAINT-001", "OMNI-BIABD-HEAP-002", "OMNI-BIN-SEC-005"})

    def test_lsp_v317_stdio_wire_codeaction_completion_and_semantic_tokens(self) -> None:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as ws:
            helper_path = os.path.join(ws, "helper.py")
            main_path = os.path.join(ws, "main.py")
            with open(helper_path, "w", encoding="utf-8") as hf:
                hf.write(
                    "def compute_hash_token(seed: int) -> int:\n"
                    "    return (seed * 17) ^ 31\n"
                )
            main_src = (
                "def entry_risk(val: int) -> int:\n"
                "    return val // 0\n\n"
                "def caller_probe(x: int) -> int:\n"
                "    return compute_\n"
            )
            with open(main_path, "w", encoding="utf-8") as mf:
                mf.write(main_src)

            main_uri = OmniLSPServer._path_to_uri(main_path)
            ws_uri = OmniLSPServer._path_to_uri(ws)

            proc = subprocess.Popen(
                [sys.executable, "omnicc_cli.py", "lsp"],
                cwd=repo_root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                assert proc.stdin is not None and proc.stdout is not None

                def send(msg: dict) -> None:
                    proc.stdin.write(encode_lsp_message(msg))
                    proc.stdin.flush()

                def recv() -> dict:
                    resp = read_lsp_message(proc.stdout)
                    self.assertIsNotNone(resp)
                    assert resp is not None
                    return resp

                # 1. initialize (indexes workspace helper.py)
                send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"rootUri": ws_uri}})
                init_resp = recv()
                self.assertEqual(init_resp["id"], 1)
                caps = init_resp["result"]["capabilities"]
                self.assertTrue(caps["codeActionProvider"])
                self.assertIn("completionProvider", caps)
                self.assertTrue(caps["semanticTokensProvider"]["full"])
                self.assertEqual(init_resp["result"]["serverInfo"]["version"], "1.2.0")

                # 2. didOpen -> publishDiagnostics (constant div-by-zero)
                send({
                    "jsonrpc": "2.0",
                    "method": "textDocument/didOpen",
                    "params": {"textDocument": {"uri": main_uri, "languageId": "python", "version": 1, "text": main_src}},
                })
                diag_msg = recv()
                self.assertEqual(diag_msg["method"], "textDocument/publishDiagnostics")
                diags = diag_msg["params"]["diagnostics"]
                self.assertTrue(any("DIVIDE_BY_ZERO" in d["message"] for d in diags))

                # 3. textDocument/codeAction -> quickfix
                send({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "textDocument/codeAction",
                    "params": {
                        "textDocument": {"uri": main_uri},
                        "range": {"start": {"line": 1, "character": 0}, "end": {"line": 1, "character": 18}},
                        "context": {"diagnostics": diags},
                    },
                })
                ca_resp = recv()
                self.assertEqual(ca_resp["id"], 2)
                actions = ca_resp["result"]
                self.assertGreaterEqual(len(actions), 1)
                self.assertEqual(actions[0]["kind"], "quickfix")
                edits = actions[0]["edit"]["changes"][main_uri]
                self.assertIn("UBSan quickfix", edits[0]["newText"])

                # 4. textDocument/completion on 'compute_' (cross-file helper.py)
                send({
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "textDocument/completion",
                    "params": {
                        "textDocument": {"uri": main_uri},
                        "position": {"line": 4, "character": 19},
                    },
                })
                comp_resp = recv()
                self.assertEqual(comp_resp["id"], 3)
                labels = [item["label"] for item in comp_resp["result"]]
                self.assertIn("compute_hash_token", labels)

                # 5. textDocument/semanticTokens/full
                send({
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "textDocument/semanticTokens/full",
                    "params": {"textDocument": {"uri": main_uri}},
                })
                tok_resp = recv()
                self.assertEqual(tok_resp["id"], 4)
                tok_data = tok_resp["result"]["data"]
                self.assertGreaterEqual(len(tok_data), 10)
                self.assertEqual(len(tok_data) % 5, 0)

                # 6. shutdown + exit
                send({"jsonrpc": "2.0", "id": 5, "method": "shutdown", "params": {}})
                shut_resp = recv()
                self.assertEqual(shut_resp["id"], 5)
                send({"jsonrpc": "2.0", "method": "exit", "params": {}})
                rc = proc.wait(timeout=5)
                self.assertEqual(rc, 0)
            finally:
                if proc.stdin:
                    proc.stdin.close()
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    stderr_bytes = proc.stderr.read()
                    proc.stderr.close()
                    if proc.returncode not in (0, None):
                        self.fail(f"LSP stderr: {stderr_bytes.decode('utf-8', errors='replace')}")
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    unittest.main()
