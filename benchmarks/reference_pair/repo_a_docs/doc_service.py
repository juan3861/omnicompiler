"""
Repository A: Document Storage and Management Service.
Provides persistent document ingestion, retrieval, and isolation by tenant.
Enforces composite primary key (tenant_id, doc_id) so tenants never overwrite each other.
"""

import os
import sqlite3
from typing import Dict, List, Optional, Any

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs.db")


_CONN_BY_PATH: Dict[str, sqlite3.Connection] = {}


def _get_connection():
    conn = _CONN_BY_PATH.get(DB_PATH)
    if conn is None:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA journal_mode=MEMORY;")
        conn.execute("PRAGMA synchronous=OFF;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                tenant_id TEXT,
                doc_id TEXT,
                title TEXT,
                content TEXT,
                PRIMARY KEY (tenant_id, doc_id)
            )
        """)
        _CONN_BY_PATH[DB_PATH] = conn
    return conn


def ingest_document(doc_id: str, title: str, content: str, tenant_id: str) -> Dict[str, Any]:
    """Ingests and stores a document in repository storage scoped strictly to tenant_id."""
    if not doc_id or not title:
        raise ValueError("doc_id and title must be non-empty strings")
    if not tenant_id:
        raise ValueError("tenant_id must be provided for isolation")

    with _get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO documents (tenant_id, doc_id, title, content) VALUES (?, ?, ?, ?)",
            (tenant_id, doc_id, title, content)
        )
        conn.commit()

    record = {
        "doc_id": doc_id,
        "title": title,
        "content": content,
        "tenant_id": tenant_id
    }
    return {"status": "INGESTED", "doc_id": doc_id, "tenant_id": tenant_id, "record": record}


def get_document(doc_id: str, tenant_id: str = "default") -> Dict[str, Any]:
    """Retrieves document strictly within tenant boundary."""
    with _get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT tenant_id, doc_id, title, content FROM documents WHERE tenant_id = ? AND doc_id = ?",
            (tenant_id, doc_id)
        )
        row = cur.fetchone()
        if not row:
            raise KeyError(f"Document '{doc_id}' not found for tenant '{tenant_id}'")
        return {
            "tenant_id": row[0],
            "doc_id": row[1],
            "title": row[2],
            "content": row[3]
        }


def list_documents(tenant_id: str) -> List[Dict[str, Any]]:
    """Lists all documents belonging to a tenant."""
    with _get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT tenant_id, doc_id, title, content FROM documents WHERE tenant_id = ?", (tenant_id,))
        return [
            {"tenant_id": r[0], "doc_id": r[1], "title": r[2], "content": r[3]}
            for r in cur.fetchall()
        ]
