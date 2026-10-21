"""
Disk-Backed Persistent Code Property Graph (CPG) & Multi-Repository Slicer
Inspired by joernio/joern, ShiftLeft, and facebook/infer.
Provides zero-memory-exhaustion persistence using an embedded indexed engine,
enabling inter-repository call resolution and cross-project taint analysis.
"""

import os
import sqlite3
import json
import ast
from typing import Dict, List, Set, Tuple, Any, Optional


class PersistentCPGNode:
    __slots__ = ("node_id", "repo_name", "kind", "label", "properties")

    def __init__(self, node_id: int, repo_name: str, kind: str, label: str, properties: Dict[str, Any]):
        self.node_id = node_id
        self.repo_name = repo_name
        self.kind = kind
        self.label = label
        self.properties = properties

    def __repr__(self) -> str:
        return f"PersistentCPGNode({self.node_id}:{self.repo_name}::{self.kind}::{self.label})"


class PersistentCodePropertyGraph:
    """
    Disk-backed Code Property Graph with SQL indices.
    Supports scaling to millions of AST, CFG, and DDG nodes across multiple repositories.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or ":memory:"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA synchronous = NORMAL")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._init_schema()

    def _init_schema(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS cpg_nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    label TEXT NOT NULL,
                    properties TEXT
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS cpg_edges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src INTEGER NOT NULL,
                    dst INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    FOREIGN KEY(src) REFERENCES cpg_nodes(id),
                    FOREIGN KEY(dst) REFERENCES cpg_nodes(id)
                )
            """)
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_cpg_nodes_repo_label ON cpg_nodes(repo_name, label)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_cpg_nodes_kind ON cpg_nodes(kind)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_cpg_edges_src_kind ON cpg_edges(src, kind)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_cpg_edges_dst_kind ON cpg_edges(dst, kind)")

    def add_node(
        self,
        kind: str,
        label: str,
        repo_name: str = "global",
        properties: Optional[Dict[str, Any]] = None
    ) -> int:
        props_json = json.dumps(properties or {})
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO cpg_nodes (repo_name, kind, label, properties) VALUES (?, ?, ?, ?)",
            (repo_name, kind, label, props_json)
        )
        self.conn.commit()
        return cur.lastrowid

    def add_edge(self, src: int, dst: int, kind: str):
        with self.conn:
            self.conn.execute(
                "INSERT INTO cpg_edges (src, dst, kind) VALUES (?, ?, ?)",
                (src, dst, kind)
            )

    def get_node(self, node_id: int) -> Optional[PersistentCPGNode]:
        cur = self.conn.cursor()
        cur.execute("SELECT id, repo_name, kind, label, properties FROM cpg_nodes WHERE id = ?", (node_id,))
        row = cur.fetchone()
        if not row:
            return None
        props = json.loads(row[4]) if row[4] else {}
        return PersistentCPGNode(row[0], row[1], row[2], row[3], props)

    def find_nodes(self, repo_name: Optional[str] = None, kind: Optional[str] = None, label: Optional[str] = None) -> List[PersistentCPGNode]:
        query = "SELECT id, repo_name, kind, label, properties FROM cpg_nodes WHERE 1=1"
        params: List[Any] = []
        if repo_name:
            query += " AND repo_name = ?"
            params.append(repo_name)
        if kind:
            query += " AND kind = ?"
            params.append(kind)
        if label:
            query += " AND label = ?"
            params.append(label)

        cur = self.conn.cursor()
        cur.execute(query, params)
        results = []
        for row in cur.fetchall():
            props = json.loads(row[4]) if row[4] else {}
            results.append(PersistentCPGNode(row[0], row[1], row[2], row[3], props))
        return results

    def build_from_ast_function(self, fn_ast: ast.FunctionDef, repo_name: str = "core") -> int:
        """Parses Python AST function into persistent AST, CFG, and DDG nodes/edges."""
        fn_node = self.add_node("FUNCTION", fn_ast.name, repo_name=repo_name)
        prev_cfg = fn_node
        var_defs: Dict[str, int] = {}

        # Add parameters
        for arg in fn_ast.args.args:
            is_tenant = "tenant" in arg.arg.lower() or "org" in arg.arg.lower()
            p_kind = "PARAM:TENANT" if is_tenant else "PARAM"
            p_node = self.add_node(p_kind, arg.arg, repo_name=repo_name, properties={"is_tenant": is_tenant})
            self.add_edge(fn_node, p_node, "AST_CHILD")
            self.add_edge(prev_cfg, p_node, "CFG_NEXT")
            prev_cfg = p_node
            var_defs[arg.arg] = p_node

        # Walk body
        for stmt in fn_ast.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        target_name = target.id
                        v_node = self.add_node("VAR", target_name, repo_name=repo_name)
                        self.add_edge(fn_node, v_node, "AST_CHILD")
                        self.add_edge(prev_cfg, v_node, "CFG_NEXT")
                        prev_cfg = v_node

                        # Connect dataflow (DDG_FLOW)
                        for subnode in ast.walk(stmt.value):
                            if isinstance(subnode, ast.Name) and subnode.id in var_defs:
                                self.add_edge(var_defs[subnode.id], v_node, "DDG_FLOW")
                            elif isinstance(subnode, ast.Call) and isinstance(subnode.func, ast.Name):
                                # Mark call node
                                call_node = self.add_node("CALL", subnode.func.id, repo_name=repo_name)
                                self.add_edge(prev_cfg, call_node, "CFG_NEXT")
                                self.add_edge(call_node, v_node, "DDG_FLOW")
                                prev_cfg = call_node

                        var_defs[target_name] = v_node

            elif isinstance(stmt, ast.Return):
                ret_node = self.add_node("SINK:RETURN", "return", repo_name=repo_name)
                self.add_edge(prev_cfg, ret_node, "CFG_NEXT")
                if stmt.value:
                    for subnode in ast.walk(stmt.value):
                        if isinstance(subnode, ast.Name) and subnode.id in var_defs:
                            self.add_edge(var_defs[subnode.id], ret_node, "DDG_FLOW")
                prev_cfg = ret_node

        return fn_node

    def link_inter_repo_call(self, caller_repo: str, callee_repo: str, target_fn_name: str) -> int:
        """
        Creates an inter-repository bridge edge: connects CALL nodes in `caller_repo`
        to matching FUNCTION entrypoints in `callee_repo`.
        """
        call_nodes = self.find_nodes(repo_name=caller_repo, kind="CALL", label=target_fn_name)
        target_fns = self.find_nodes(repo_name=callee_repo, kind="FUNCTION", label=target_fn_name)

        linked_count = 0
        for c in call_nodes:
            for t in target_fns:
                self.add_edge(c.node_id, t.node_id, "CALL:INTER_REPO")
                self.add_edge(c.node_id, t.node_id, "DDG_FLOW:INTER_REPO")
                linked_count += 1
        return linked_count

    def find_cross_repo_taint_path(self, source_pattern: str, sink_pattern: str) -> Optional[List[int]]:
        """
        Executes an inter-repository dataflow traversal along DDG_FLOW and DDG_FLOW:INTER_REPO edges
        to detect cross-tenant data leakage across project boundaries.
        """
        cur = self.conn.cursor()
        # Find start nodes
        cur.execute("SELECT id FROM cpg_nodes WHERE kind LIKE ? OR label LIKE ?",
                    (f"%{source_pattern}%", f"%{source_pattern}%"))
        start_ids = [r[0] for r in cur.fetchall()]

        # Find target sinks
        cur.execute("SELECT id FROM cpg_nodes WHERE kind LIKE ? OR label LIKE ?",
                    (f"%{sink_pattern}%", f"%{sink_pattern}%"))
        sink_ids = set(r[0] for r in cur.fetchall())

        for start in start_ids:
            visited = set()
            queue = [[start]]

            while queue:
                path = queue.pop(0)
                curr = path[-1]

                if curr in sink_ids and len(path) > 1:
                    return path

                if curr not in visited:
                    visited.add(curr)
                    cur.execute(
                        "SELECT dst FROM cpg_edges WHERE src = ? AND kind IN ('DDG_FLOW', 'DDG_FLOW:INTER_REPO')",
                        (curr,)
                    )
                    for row in cur.fetchall():
                        dst = row[0]
                        if dst not in visited:
                            queue.append(path + [dst])

        return None

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
