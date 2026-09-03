"""The deterministic log reducer.

Pipeline: redact -> enrich (stack parse, endpoint/status extraction,
normalize, fingerprint) -> cluster -> score/rank -> budget -> sample.

Everything here is deterministic Python; the LLM only ever sees the
reduced output. The `ReductionStats` compression report is a first-class
product feature.
"""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel

from signalsift.cloudwatch.models import LogEvent
from signalsift.config import Settings
from signalsift.processing.clusterer import (
    LogCluster,
    cluster_events,
    count_logical_events,
    score_clusters,
)
from signalsift.processing.fingerprint import fingerprint_message, fingerprint_trace
from signalsift.processing.normalizer import normalize_message
from signalsift.processing.redactor import Redactor
from signalsift.processing.sampler import sample_clusters
from signalsift.processing.stacktrace import extract_exception_type, parse_stack_trace

_ENDPOINT_PATTERN = re.compile(
    r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/[A-Za-z0-9_\-./{}<>]*)"
)
_ENDPOINT_KEYS = ("endpoint", "path", "route", "url_path", "uri")
_STATUS_KEYS = ("status", "status_code", "statusCode", "http_status", "response_code")
_STATUS_PATTERN = re.compile(r"\bstatus(?:[ _-]?code)?\s*[=:]?\s*([1-5]\d{2})\b", re.IGNORECASE)
_LEVEL_PATTERN = re.compile(r"\b(CRITICAL|FATAL|ERROR|WARNING|WARN|INFO|DEBUG)\b")


class ReductionStats(BaseModel):
    cloudwatch_events: int = 0
    events_after_filtering: int = 0
    logical_events: int = 0
    clusters: int = 0
    clusters_after_budget: int = 0
    clusters_sent_to_llm: int = 0
    events_sent_to_llm: int = 0
    truncated: bool = False

    @property
    def compression_ratio(self) -> float:
        if self.cloudwatch_events == 0:
            return 0.0
        return round(self.events_sent_to_llm / self.cloudwatch_events, 4)


class ReducedLogs(BaseModel):
    clusters: list[LogCluster]
    stats: ReductionStats
    window_start: datetime
    window_end: datetime


def _extract_endpoint(event: LogEvent) -> str | None:
    for key in _ENDPOINT_KEYS:
        value = event.parsed_fields.get(key)
        if isinstance(value, str) and value.startswith("/"):
            return value
    match = _ENDPOINT_PATTERN.search(event.message)
    return match.group(1) if match else None


def _extract_status_code(event: LogEvent) -> int | None:
    for key in _STATUS_KEYS:
        value = event.parsed_fields.get(key)
        if isinstance(value, int) and 100 <= value <= 599:
            return value
        if isinstance(value, str) and value.isdigit() and 100 <= int(value) <= 599:
            return int(value)
    match = _STATUS_PATTERN.search(event.message)
    return int(match.group(1)) if match else None


def _extract_level(event: LogEvent) -> str | None:
    if event.level:
        return event.level
    match = _LEVEL_PATTERN.search(event.message)
    if not match:
        return None
    level = match.group(1)
    return "WARNING" if level == "WARN" else level


def enrich_event(event: LogEvent) -> LogEvent:
    """Parse stack traces, extract endpoint/status/level, normalize, fingerprint."""
    endpoint = _extract_endpoint(event)
    status_code = _extract_status_code(event)
    level = _extract_level(event)
    trace = parse_stack_trace(event.message)
    if trace is not None:
        root = trace.root
        exception_type = root.exception_type
        normalized = normalize_message(f"{exception_type}: {root.exception_message}")
        fingerprint = fingerprint_trace(trace, normalized)
    else:
        exception_type = extract_exception_type(event.message)
        normalized = normalize_message(event.message)
        fingerprint = fingerprint_message(normalized, exception_type, endpoint, status_code)
    return event.model_copy(
        update={
            "normalized_message": normalized,
            "fingerprint": fingerprint,
            "exception_type": exception_type,
            "endpoint": endpoint,
            "status_code": status_code,
            "level": level,
        }
    )


class LogReducer:
    def __init__(self, settings: Settings, redactor: Redactor | None = None) -> None:
        self._settings = settings
        self._redactor = redactor or Redactor(settings)

    def reduce(
        self,
        events: list[LogEvent],
        window_start: datetime,
        window_end: datetime,
        source_truncated: bool = False,
    ) -> ReducedLogs:
        stats = ReductionStats(cloudwatch_events=len(events), truncated=source_truncated)

        # 1. Redaction — always before anything else sees the text.
        redacted = self._redactor.redact_events(events)

        # 2. Filtering: drop empty messages.
        filtered = [e for e in redacted if e.message.strip()]
        stats.events_after_filtering = len(filtered)

        # 3. Enrichment (normalize + fingerprint). A multi-line stack trace
        #    is already one CloudWatch event; enrichment collapses variants.
        enriched = [enrich_event(e) for e in filtered]

        # 4. Dedup + cluster.
        stats.logical_events = count_logical_events(enriched)
        clusters = cluster_events(enriched)
        stats.clusters = len(clusters)

        # 5. Rank deterministically.
        clusters = score_clusters(clusters, window_end)

        # 6. Budget: keep top-N clusters.
        if len(clusters) > self._settings.max_clusters:
            clusters = clusters[: self._settings.max_clusters]
            stats.truncated = True
        stats.clusters_after_budget = len(clusters)

        # 7. Sample representative events with per-example char caps.
        clusters = sample_clusters(clusters, self._settings.max_examples_per_cluster)
        for cluster in clusters:
            cluster.representative_events = [
                event.model_copy(
                    update={"message": event.message[: self._settings.max_chars_per_example]}
                )
                for event in cluster.representative_events
            ]

        return ReducedLogs(
            clusters=clusters,
            stats=stats,
            window_start=window_start,
            window_end=window_end,
        )
