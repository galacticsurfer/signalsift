"""SQLite-backed cache for analyses and query results.

Cache keys hash the log group, window, query parameters, processing
version, model name and prompt version — any change invalidates. TTL is
configurable; expired rows are purged lazily.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from signalsift import PROCESSING_VERSION
from signalsift.analysis.prompts import PROMPT_VERSION

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_kind ON cache(kind);

CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at REAL NOT NULL,
    operation TEXT NOT NULL,
    payload TEXT NOT NULL
);
"""


def make_cache_key(kind: str, model_name: str, **params: Any) -> str:
    material = json.dumps(
        {
            "kind": kind,
            "model": model_name,
            "processing_version": PROCESSING_VERSION,
            "prompt_version": PROMPT_VERSION,
            "params": params,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(material.encode()).hexdigest()


class SqliteCache:
    def __init__(self, path: Path | str, ttl_seconds: int = 900) -> None:
        self._path = Path(path).expanduser()
        if str(self._path) != ":memory:":
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._ttl = ttl_seconds
        self._conn = sqlite3.connect(str(self._path))
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def get(self, key: str) -> dict[str, Any] | None:
        self._purge_expired()
        row = self._conn.execute("SELECT value FROM cache WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    def set(self, key: str, kind: str, value: dict[str, Any]) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO cache (key, kind, value, created_at) VALUES (?, ?, ?, ?)",
            (key, kind, json.dumps(value, default=str), time.time()),
        )
        self._conn.commit()

    def _purge_expired(self) -> None:
        cutoff = time.time() - self._ttl
        self._conn.execute("DELETE FROM cache WHERE created_at < ?", (cutoff,))
        self._conn.commit()

    # --- local telemetry -------------------------------------------------
    def record_metric(self, operation: str, payload: dict[str, Any]) -> None:
        self._conn.execute(
            "INSERT INTO metrics (recorded_at, operation, payload) VALUES (?, ?, ?)",
            (time.time(), operation, json.dumps(payload, default=str)),
        )
        self._conn.commit()

    def recent_metrics(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT recorded_at, operation, payload FROM metrics ORDER BY recorded_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [{"recorded_at": r[0], "operation": r[1], **json.loads(r[2])} for r in rows]

    def close(self) -> None:
        self._conn.close()
