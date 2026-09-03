"""Local-only telemetry.

SignalSift measures itself (latencies, sizes, compression ratios, cache
hits) and stores everything in the local SQLite database. Nothing is
ever sent externally.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any

from signalsift.cache.sqlite import SqliteCache


class Telemetry:
    def __init__(self, cache: SqliteCache | None) -> None:
        self._cache = cache

    def record(self, operation: str, **payload: Any) -> None:
        if self._cache is not None:
            self._cache.record_metric(operation, payload)

    @contextmanager
    def timed(self, operation: str, **payload: Any):
        start = time.monotonic()
        extra: dict[str, Any] = {}
        try:
            yield extra
        finally:
            duration = round(time.monotonic() - start, 3)
            self.record(operation, duration_seconds=duration, **payload, **extra)

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        if self._cache is None:
            return []
        return self._cache.recent_metrics(limit)
