"""
Repository B: Inverted Index Search Engine.
Provides tokenization, persistent inverted index building, and semantic term search.
Enforces tenant isolation: tokens are strictly indexed and queried per tenant.
"""

import os
import re
import sqlite3
from typing import Dict, List, Set, Any

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.db")


_CONN_BY_PATH: Dict[str, sqlite3.Connection] = {}


def _get_connection():
    conn = _CONN_BY_PATH.get(DB_PATH)
    if conn is None:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA journal_mode=MEMORY;")
        conn.execute("PRAGMA synchronous=OFF;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS inverted_index (
                tenant_id TEXT,
                token TEXT,
                doc_id TEXT,
                PRIMARY KEY (tenant_id, token, doc_id)
            )
        """)
        _CONN_BY_PATH[DB_PATH] = conn
    return conn


def index_text(doc_id: str, text: str, tenant_id: str = "default") -> Dict[str, Any]:
    """Tokenizes text and registers document ID in the persistent index scoped to tenant_id."""
    if not doc_id:
        raise ValueError("doc_id must be non-empty")
    tokens = set(re.findall(r"\w+", (text or "").lower()))
    with _get_connection() as conn:
        for tok in tokens:
            conn.execute(
                "INSERT OR IGNORE INTO inverted_index (tenant_id, token, doc_id) VALUES (?, ?, ?)",
                (tenant_id, tok, doc_id)
            )
        conn.commit()
    return {"status": "INDEXED", "doc_id": doc_id, "tenant_id": tenant_id, "token_count": len(tokens)}


def search_index(query: str, tenant_id: str = "default") -> List[str]:
    """Queries persistent inverted index and returns matching document IDs strictly for tenant_id."""
    if not query:
        return []
    tokens = set(re.findall(r"\w+", query.lower()))
    results: Set[str] = set()
    with _get_connection() as conn:
        cur = conn.cursor()
        for tok in tokens:
            cur.execute(
                "SELECT doc_id FROM inverted_index WHERE tenant_id = ? AND token = ?",
                (tenant_id, tok)
            )
            for row in cur.fetchall():
                results.add(row[0])
    return sorted(list(results))
