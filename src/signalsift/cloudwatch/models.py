"""Internal typed models for log data.

CloudWatch responses are converted into `LogEvent` immediately; every
downstream component (redaction, normalization, clustering, LLM context)
operates on these models, never on raw boto3 structures.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class QueryStats(BaseModel):
    """Statistics reported by CloudWatch Logs Insights for one query."""

    records_matched: float = 0.0
    records_scanned: float = 0.0
    bytes_scanned: float = 0.0
    duration_seconds: float = 0.0


class LogEvent(BaseModel):
    """One log event in SignalSift's internal representation."""

    timestamp: datetime
    message: str
    log_stream: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    service: str | None = None
    level: str | None = None
    parsed_fields: dict[str, Any] = Field(default_factory=dict)

    # Populated by the processing pipeline (never by CloudWatch parsing):
    normalized_message: str | None = None
    fingerprint: str | None = None
    exception_type: str | None = None
    endpoint: str | None = None
    status_code: int | None = None


class QueryResult(BaseModel):
    """Typed result of one Logs Insights query."""

    events: list[LogEvent]
    stats: QueryStats
    truncated: bool = False


def parse_cloudwatch_timestamp(value: str) -> datetime:
    """Parse an @timestamp value from Logs Insights (UTC, no tz suffix)."""
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    # ISO 8601 fallback (also covers values that already carry an offset)
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt
