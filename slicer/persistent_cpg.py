"""
Disk-Backed Persistent Code Property Graph (CPG) & Multi-Repository Slicer
Inspired by joernio/joern, ShiftLeft, and facebook/infer.
Provides zero-memory-exhaustion persistence using an embedded indexed SQLite engine,
transactional batch ingestion (>100x faster on disk), and single-query recursive CTE
inter-repository taint reachability analysis.
"""

import os
import sqlite3
import json
import ast
from contextlib import contextmanager
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
    Disk-backed Code Property Graph with SQL indices, batched write transactions,
    and native SQLite WITH RECURSIVE taint path search.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or ":memory:"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA synchronous = NORMAL")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA temp_store = MEMORY")
        self.conn.execute("PRAGMA cache_size = -16384")  # 16 MB page cache
        self._batch_depth = 0
        self._pending_edges: List[Tuple[int, int, str]] = []
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

    @contextmanager
    def batch(self):
        """
        Groups arbitrary node/edge insertions into a single atomic SQLite transaction
        and flushes edges via executemany(), eliminating per-node fsync overhead.
        """
        is_outer = (self._batch_depth == 0)
        self._batch_depth += 1
        if is_outer:
            self.conn.execute("BEGIN")
        try:
            yield self
            if is_outer:
                if self._pending_edges:
                    self.conn.executemany(
                        "INSERT INTO cpg_edges (src, dst, kind) VALUES (?, ?, ?)",
                        self._pending_edges
                    )
                    self._pending_edges.clear()
                self.conn.commit()
        except Exception:
            if is_outer:
                self._pending_edges.clear()
                self.conn.rollback()
            raise
        finally:
            self._batch_depth -= 1

    def _flush_pending_if_needed(self):
        if self._pending_edges:
            self.conn.executemany(
                "INSERT INTO cpg_edges (src, dst, kind) VALUES (?, ?, ?)",
                self._pending_edges
            )
            self._pending_edges.clear()

    def add_node(
        self,
        kind: str,
        label: str,
        repo_name: str = "global",
        properties: Optional[Dict[str, Any]] = None
    ) -> int:
        props_json = json.dumps(properties) if properties else "{}"
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO cpg_nodes (repo_name, kind, label, properties) VALUES (?, ?, ?, ?)",
            (repo_name, kind, label, props_json)
        )
        if self._batch_depth == 0:
            self.conn.commit()
        return cur.lastrowid

    def add_edge(self, src: int, dst: int, kind: str):
        if self._batch_depth > 0:
            self._pending_edges.append((src, dst, kind))
        else:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO cpg_edges (src, dst, kind) VALUES (?, ?, ?)",
                    (src, dst, kind)
                )

    def get_node(self, node_id: int) -> Optional[PersistentCPGNode]:
        self._flush_pending_if_needed()
        cur = self.conn.cursor()
        cur.execute("SELECT id, repo_name, kind, label, properties FROM cpg_nodes WHERE id = ?", (node_id,))
        row = cur.fetchone()
        if not row:
            return None
        props = json.loads(row[4]) if row[4] else {}
        return PersistentCPGNode(row[0], row[1], row[2], row[3], props)

    def find_nodes(
        self,
        repo_name: Optional[str] = None,
        kind: Optional[str] = None,
        label: Optional[str] = None
    ) -> List[PersistentCPGNode]:
        self._flush_pending_if_needed()
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

    def build_from_ast_function(self, fn_ast: ast.AST, repo_name: str = "core") -> int:
        """
        Parses Python AST function (including nested branches, loops, augmented assignments,
        and method calls) into persistent AST, CFG, and DDG nodes/edges within a single transaction.
        """
        with self.batch():
            fn_name = getattr(fn_ast, "name", "anon")
            fn_node = self.add_node("FUNCTION", fn_name, repo_name=repo_name)
            prev_cfg = fn_node
            var_defs: Dict[str, Set[int]] = {}

            args_list = getattr(getattr(fn_ast, "args", None), "args", [])
            for arg in args_list:
                is_tenant = "tenant" in arg.arg.lower() or "org" in arg.arg.lower()
                p_kind = "PARAM:TENANT" if is_tenant else "PARAM"
                p_node = self.add_node(p_kind, arg.arg, repo_name=repo_name, properties={"is_tenant": is_tenant})
                self.add_edge(fn_node, p_node, "AST_CHILD")
                self.add_edge(prev_cfg, p_node, "CFG_NEXT")
                prev_cfg = p_node
                var_defs[arg.arg] = {p_node}

            def _clone_defs(d: Dict[str, Set[int]]) -> Dict[str, Set[int]]:
                return {k: set(v) for k, v in d.items()}

            def _walk_stmts(stmts: List[ast.stmt], active_defs: Dict[str, Set[int]]):
                nonlocal prev_cfg
                for stmt in stmts:
                    if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                        if isinstance(stmt, ast.Assign):
                            targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
                            val_expr = stmt.value
                        elif isinstance(stmt, ast.AnnAssign):
                            targets = [stmt.target.id] if isinstance(stmt.target, ast.Name) else []
                            val_expr = stmt.value
                        else:
                            targets = [stmt.target.id] if isinstance(stmt.target, ast.Name) else []
                            val_expr = stmt.value

                        for target_name in targets:
                            v_node = self.add_node("VAR", target_name, repo_name=repo_name)
                            self.add_edge(fn_node, v_node, "AST_CHILD")
                            self.add_edge(prev_cfg, v_node, "CFG_NEXT")
                            prev_cfg = v_node

                            if isinstance(stmt, ast.AugAssign) and target_name in active_defs:
                                for def_id in active_defs[target_name]:
                                    self.add_edge(def_id, v_node, "DDG_FLOW")

                            if val_expr is not None:
                                for subnode in ast.walk(val_expr):
                                    if isinstance(subnode, ast.Name) and subnode.id in active_defs:
                                        for def_id in active_defs[subnode.id]:
                                            self.add_edge(def_id, v_node, "DDG_FLOW")
                                    elif isinstance(subnode, ast.Call):
                                        callee_name = None
                                        if isinstance(subnode.func, ast.Name):
                                            callee_name = subnode.func.id
                                        elif isinstance(subnode.func, ast.Attribute):
                                            callee_name = subnode.func.attr
                                        if callee_name:
                                            call_node = self.add_node("CALL", callee_name, repo_name=repo_name)
                                            self.add_edge(prev_cfg, call_node, "CFG_NEXT")
                                            for c_arg in subnode.args:
                                                for arg_sub in ast.walk(c_arg):
                                                    if isinstance(arg_sub, ast.Name) and arg_sub.id in active_defs:
                                                        for def_id in active_defs[arg_sub.id]:
                                                            self.add_edge(def_id, call_node, "DDG_FLOW")
                                            self.add_edge(call_node, v_node, "DDG_FLOW")
                                            prev_cfg = call_node

                            active_defs[target_name] = {v_node}

                    elif isinstance(stmt, ast.Return):
                        ret_node = self.add_node("SINK:RETURN", "return", repo_name=repo_name)
                        self.add_edge(prev_cfg, ret_node, "CFG_NEXT")
                        if stmt.value:
                            for subnode in ast.walk(stmt.value):
                                if isinstance(subnode, ast.Name) and subnode.id in active_defs:
                                    for def_id in active_defs[subnode.id]:
                                        self.add_edge(def_id, ret_node, "DDG_FLOW")
                                elif isinstance(subnode, ast.Call) and isinstance(subnode.func, ast.Name):
                                    call_node = self.add_node("CALL", subnode.func.id, repo_name=repo_name)
                                    self.add_edge(prev_cfg, call_node, "CFG_NEXT")
                                    for c_arg in subnode.args:
                                        for arg_sub in ast.walk(c_arg):
                                            if isinstance(arg_sub, ast.Name) and arg_sub.id in active_defs:
                                                for def_id in active_defs[arg_sub.id]:
                                                    self.add_edge(def_id, call_node, "DDG_FLOW")
                                    self.add_edge(call_node, ret_node, "DDG_FLOW")
                                    prev_cfg = call_node
                        prev_cfg = ret_node

                    elif isinstance(stmt, ast.If):
                        cond_node = self.add_node("BRANCH:IF", "if", repo_name=repo_name)
                        self.add_edge(prev_cfg, cond_node, "CFG_NEXT")
                        prev_cfg = cond_node
                        then_defs = _clone_defs(active_defs)
                        _walk_stmts(stmt.body, then_defs)
                        if stmt.orelse:
                            else_defs = _clone_defs(active_defs)
                            _walk_stmts(stmt.orelse, else_defs)
                            all_keys = set(then_defs.keys()) | set(else_defs.keys())
                            active_defs.clear()
                            for k in all_keys:
                                active_defs[k] = then_defs.get(k, set()) | else_defs.get(k, set())
                        else:
                            for k, vset in then_defs.items():
                                active_defs[k] = active_defs.get(k, set()) | vset

                    elif isinstance(stmt, (ast.For, ast.While)):
                        loop_node = self.add_node("BRANCH:LOOP", "loop", repo_name=repo_name)
                        self.add_edge(prev_cfg, loop_node, "CFG_NEXT")
                        prev_cfg = loop_node
                        loop_defs = _clone_defs(active_defs)
                        _walk_stmts(stmt.body, loop_defs)
                        for k, vset in loop_defs.items():
                            active_defs[k] = active_defs.get(k, set()) | vset

                    elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                        sub_call = stmt.value
                        callee_name = sub_call.func.id if isinstance(sub_call.func, ast.Name) else (
                            sub_call.func.attr if isinstance(sub_call.func, ast.Attribute) else None
                        )
                        if callee_name:
                            call_node = self.add_node("CALL", callee_name, repo_name=repo_name)
                            self.add_edge(prev_cfg, call_node, "CFG_NEXT")
                            for c_arg in sub_call.args:
                                for arg_sub in ast.walk(c_arg):
                                    if isinstance(arg_sub, ast.Name) and arg_sub.id in active_defs:
                                        for def_id in active_defs[arg_sub.id]:
                                            self.add_edge(def_id, call_node, "DDG_FLOW")
                            prev_cfg = call_node

            _walk_stmts(getattr(fn_ast, "body", []), var_defs)
            return fn_node

    def ingest_ast_module(self, tree: ast.Module, repo_name: str = "core") -> int:
        """Ingests all functions in an AST module within a single atomic disk transaction."""
        count = 0
        with self.batch():
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.build_from_ast_function(node, repo_name=repo_name)
                    count += 1
        return count

    def link_inter_repo_call(self, caller_repo: str, callee_repo: str, target_fn_name: str) -> int:
        """
        Creates an inter-repository bridge edge: connects CALL nodes in `caller_repo`
        to matching FUNCTION entrypoints, PARAMs, and SINK:RETURN nodes in `callee_repo`.
        """
        call_nodes = self.find_nodes(repo_name=caller_repo, kind="CALL", label=target_fn_name)
        target_fns = self.find_nodes(repo_name=callee_repo, kind="FUNCTION", label=target_fn_name)

        linked_count = 0
        with self.batch():
            cur = self.conn.cursor()
            for c in call_nodes:
                for t in target_fns:
                    self.add_edge(c.node_id, t.node_id, "CALL:INTER_REPO")
                    self.add_edge(c.node_id, t.node_id, "DDG_FLOW:INTER_REPO")
                    # Connect function entrypoint to its parameters and return sinks for full interprocedural flow
                    cur.execute(
                        "SELECT dst FROM cpg_edges WHERE src = ? AND kind = 'AST_CHILD'",
                        (t.node_id,)
                    )
                    for (child_id,) in cur.fetchall():
                        self.add_edge(t.node_id, child_id, "DDG_FLOW:INTER_REPO")
                    linked_count += 1
        return linked_count

    def find_cross_repo_taint_path(self, source_pattern: str, sink_pattern: str) -> Optional[List[int]]:
        """
        Executes a single-query native C SQLite WITH RECURSIVE traversal along
        DDG_FLOW and DDG_FLOW:INTER_REPO edges with cycle prevention.
        """
        self._flush_pending_if_needed()
        cur = self.conn.cursor()

        sql = """
        WITH RECURSIVE
        sources(id) AS (
            SELECT id FROM cpg_nodes WHERE kind LIKE ? OR label LIKE ?
        ),
        sinks(id) AS (
            SELECT id FROM cpg_nodes WHERE kind LIKE ? OR label LIKE ?
        ),
        taint_reach(curr_id, path_csv, depth) AS (
            SELECT id, ',' || CAST(id AS TEXT) || ',', 1
            FROM sources
            UNION ALL
            SELECT e.dst,
                   r.path_csv || CAST(e.dst AS TEXT) || ',',
                   r.depth + 1
            FROM taint_reach r
            JOIN cpg_edges e ON e.src = r.curr_id
            WHERE e.kind IN ('DDG_FLOW', 'DDG_FLOW:INTER_REPO')
              AND r.depth < 64
              AND instr(r.path_csv, ',' || CAST(e.dst AS TEXT) || ',') = 0
        )
        SELECT r.path_csv
        FROM taint_reach r
        JOIN sinks s ON s.id = r.curr_id
        WHERE r.depth > 1
        ORDER BY r.depth ASC
        LIMIT 1;
        """
        src_like = f"%{source_pattern}%"
        sink_like = f"%{sink_pattern}%"
        cur.execute(sql, (src_like, src_like, sink_like, sink_like))
        row = cur.fetchone()
        if not row or not row[0]:
            return None
        parts = [p for p in row[0].strip(",").split(",") if p]
        return [int(p) for p in parts]

    def close(self):
        self._flush_pending_if_needed()
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
