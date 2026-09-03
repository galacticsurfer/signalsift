"""Structured output schemas for the local model and final reports."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from signalsift.processing.reducer import ReductionStats

Severity = Literal["low", "medium", "high", "critical"]


class Evidence(BaseModel):
    statement: str
    cluster_ids: list[str] = Field(default_factory=list)


class RootCauseHypothesis(BaseModel):
    cause: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[Evidence] = Field(default_factory=list)


class IncidentAnalysis(BaseModel):
    """What the local model returns. Every field is validated afterwards."""

    summary: str
    severity: Severity
    likely_root_causes: list[RootCauseHypothesis] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    timeline: list[str] = Field(default_factory=list)
    recommended_checks: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)


class ClusterSummary(BaseModel):
    """Deterministic cluster facts included in every report."""

    cluster_id: str
    exception_type: str | None
    normalized_message: str
    count: int
    first_seen: str
    last_seen: str
    affected_endpoints: dict[str, int]
    status_codes: dict[str, int]
    score: float


class TimelinePoint(BaseModel):
    """One bucket of the full-window volume timeline."""

    time: str
    count: int


class IncidentReport(BaseModel):
    """Final MCP/CLI response: deterministic facts + validated semantics."""

    service: str | None
    log_group: str
    window_start: str
    window_end: str
    total_events: int
    clusters: list[ClusterSummary]
    # Server-side aggregation over the FULL window — complete even when
    # event retrieval was truncated by the query limit.
    volume_timeline: list[TimelinePoint] = Field(default_factory=list)
    semantic_analysis_status: Literal["ok", "unavailable", "degraded"]
    semantic_analysis_error: str | None = None
    analysis: IncidentAnalysis | None = None
    validation_warnings: list[str] = Field(default_factory=list)
    stats: ReductionStats
    compression_ratio: float
    cache_hit: bool = False


class WindowProfile(BaseModel):
    """One window's deterministic error profile (for compare_windows)."""

    window_start: str
    window_end: str
    total_events: int
    clusters: list[ClusterSummary]


class ClusterDelta(BaseModel):
    cluster_id: str
    exception_type: str | None
    normalized_message: str
    baseline_count: int
    comparison_count: int
    change: Literal["new", "disappeared", "increased", "decreased", "stable"]
    ratio: float | None = None
    new_endpoints: list[str] = Field(default_factory=list)


class ComparisonReport(BaseModel):
    log_group: str
    service: str | None
    baseline: WindowProfile
    comparison: WindowProfile
    new_clusters: list[ClusterDelta]
    disappeared_clusters: list[ClusterDelta]
    changed_clusters: list[ClusterDelta]
    semantic_analysis_status: Literal["ok", "unavailable", "degraded"]
    analysis: IncidentAnalysis | None = None
    validation_warnings: list[str] = Field(default_factory=list)


class TraceReport(BaseModel):
    """trace_request output: chronological, redacted, size-capped."""

    log_group: str
    request_id: str
    window_start: str
    window_end: str
    total_events: int
    events: list[dict[str, str]]
    truncated: bool = False
