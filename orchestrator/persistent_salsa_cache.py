"""
Alpha-C42 Persistent Disk-Backed Salsa Cache (SQLite).
Persists Z3 SMT equivalence proofs, Z3 spatial bounds proofs, and compiled native
machine code artifacts across separate CLI/compiler process invocations without
holding persistent file locks across builds (Windows TemporaryDirectory safe).
"""

import json
import os
import pickle
import sqlite3
import threading
from typing import Any, Dict, Optional, Tuple


class PersistentSalsaCache:
    """Thread-safe SQLite-backed cache for cross-process incremental compilation."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._enabled = bool(db_path and db_path != ":memory:")
        if self._enabled:
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                try:
                    conn.execute("PRAGMA synchronous=NORMAL;")
                    conn.execute(
                        "CREATE TABLE IF NOT EXISTS smt_proofs (k TEXT PRIMARY KEY, v TEXT NOT NULL)"
                    )
                    conn.execute(
                        "CREATE TABLE IF NOT EXISTS bounds_proofs (k TEXT PRIMARY KEY, v TEXT NOT NULL)"
                    )
                    conn.execute(
                        "CREATE TABLE IF NOT EXISTS compiled_objs (k TEXT PRIMARY KEY, v BLOB NOT NULL)"
                    )
                    conn.commit()
                finally:
                    conn.close()

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def get_smt_proof(self, key_str: str) -> Optional[Dict[str, Any]]:
        if not self._enabled:
            return None
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cur = conn.execute("SELECT v FROM smt_proofs WHERE k = ?", (key_str,))
                row = cur.fetchone()
                return json.loads(row[0]) if row else None
            finally:
                conn.close()

    def put_smt_proof(self, key_str: str, verdict: Dict[str, Any]) -> None:
        if not self._enabled:
            return
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO smt_proofs (k, v) VALUES (?, ?)",
                    (key_str, json.dumps(verdict)),
                )
                conn.commit()
            finally:
                conn.close()

    def get_bounds_proof(self, key_str: str) -> Optional[Tuple[Any, Any]]:
        if not self._enabled:
            return None
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cur = conn.execute("SELECT v FROM bounds_proofs WHERE k = ?", (key_str,))
                row = cur.fetchone()
                if not row:
                    return None
                data = json.loads(row[0])
                return data[0], data[1]
            finally:
                conn.close()

    def put_bounds_proof(self, key_str: str, b_res: Any, d_res: Any) -> None:
        if not self._enabled:
            return
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO bounds_proofs (k, v) VALUES (?, ?)",
                    (key_str, json.dumps([b_res, d_res])),
                )
                conn.commit()
            finally:
                conn.close()

    def get_compiled_obj(self, key_str: str) -> Optional[Any]:
        if not self._enabled:
            return None
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cur = conn.execute("SELECT v FROM compiled_objs WHERE k = ?", (key_str,))
                row = cur.fetchone()
                return pickle.loads(row[0]) if row else None
            finally:
                conn.close()

    def put_compiled_obj(self, key_str: str, artifact: Any) -> None:
        if not self._enabled:
            return
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO compiled_objs (k, v) VALUES (?, ?)",
                    (key_str, sqlite3.Binary(pickle.dumps(artifact))),
                )
                conn.commit()
            finally:
                conn.close()

    def attach_cas(self, cas: Any) -> None:
        self._cas = cas

    def put_cas_artifact(self, key_str: str, raw_bytes: bytes) -> Optional[str]:
        cas = getattr(self, "_cas", None)
        if cas is None:
            return None
        digest = cas.put_blob(raw_bytes)
        self.put_compiled_obj(f"cas::{key_str}", digest)
        return digest

    def get_cas_artifact(self, key_str: str) -> Optional[bytes]:
        cas = getattr(self, "_cas", None)
        if cas is None:
            return None
        digest = self.get_compiled_obj(f"cas::{key_str}")
        if not digest or not cas.has_blob(digest):
            return None
        return cas.get_blob(digest)

    def close(self) -> None:
        pass
