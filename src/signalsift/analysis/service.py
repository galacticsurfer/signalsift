"""IncidentService: the single service layer behind both CLI and MCP.

Orchestrates: query planning -> CloudWatch -> deterministic reduction ->
context building -> one local-LLM call -> evidence validation -> report.
Degrades gracefully to a deterministic-only report when the local model
is unavailable.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from signalsift.analysis.context_builder import ContextBuilder
from signalsift.analysis.prompts import build_comparison_prompt, build_incident_prompt
from signalsift.analysis.schemas import (
    ClusterDelta,
    ClusterSummary,
    ComparisonReport,
    IncidentAnalysis,
    IncidentReport,
    TimelinePoint,
    TraceReport,
    WindowProfile,
)
from signalsift.analysis.validator import validate_analysis
from signalsift.cache.sqlite import SqliteCache, make_cache_key
from signalsift.cloudwatch.client import CloudWatchLogsClient
from signalsift.cloudwatch.models import parse_timeline_rows
from signalsift.cloudwatch.query_planner import (
    ErrorSearchRequest,
    QueryPlanner,
    TraceRequest,
)
from signalsift.config import Settings
from signalsift.errors import SignalSiftError
from signalsift.llm.base import LocalLLMProvider
from signalsift.observability.metrics import Telemetry
from signalsift.processing.clusterer import LogCluster
from signalsift.processing.redactor import Redactor
from signalsift.processing.reducer import LogReducer, ReducedLogs

logger = logging.getLogger(__name__)


def _cluster_summary(cluster: LogCluster) -> ClusterSummary:
    return ClusterSummary(
        cluster_id=cluster.fingerprint,
        exception_type=cluster.exception_type,
        normalized_message=cluster.normalized_message[:300],
        count=cluster.count,
        first_seen=cluster.first_seen.isoformat(),
        last_seen=cluster.last_seen.isoformat(),
        affected_endpoints=cluster.affected_endpoints,
        status_codes=cluster.status_codes,
        score=cluster.score,
    )


class IncidentService:
    def __init__(
        self,
        settings: Settings,
        cloudwatch: CloudWatchLogsClient,
        llm: LocalLLMProvider | None,
        cache: SqliteCache | None = None,
        telemetry: Telemetry | None = None,
    ) -> None:
        self._settings = settings
        self._cloudwatch = cloudwatch
        self._llm = llm
        self._cache = cache
        self._telemetry = telemetry or Telemetry(cache)
        self._planner = QueryPlanner(settings)
        self._reducer = LogReducer(settings)
        self._context_builder = ContextBuilder(settings)
        self._redactor = Redactor(settings)

    # ------------------------------------------------------------------
    # analyze_incident / search_errors
    # ------------------------------------------------------------------
    async def analyze_incident(
        self,
        log_group: str,
        start_time: datetime,
        end_time: datetime,
        service: str | None = None,
        symptom: str | None = None,
    ) -> IncidentReport:
        request = ErrorSearchRequest(
            log_group=log_group,
            start_time=start_time,
            end_time=end_time,
            service=service,
        )
        return await self._run_analysis(
            request,
            service=service,
            symptom=symptom,
            semantic=True,
            kind="analyze_incident",
            report_clusters=self._settings.max_report_clusters,
        )

    async def search_errors(
        self,
        log_group: str,
        start_time: datetime,
        end_time: datetime,
        service: str | None = None,
        exception_type: str | None = None,
        status_code: int | None = None,
        text: str | None = None,
        semantic: bool = False,
    ) -> IncidentReport:
        request = ErrorSearchRequest(
            log_group=log_group,
            start_time=start_time,
            end_time=end_time,
            service=service,
            exception_type=exception_type,
            status_code=status_code,
            text=text,
        )
        # Search is for sifting: include EVERY cluster that survived the
        # reducer's max_clusters budget, not just the top of the ranking.
        return await self._run_analysis(
            request,
            service=service,
            symptom=None,
            semantic=semantic,
            kind="search_errors",
            report_clusters=None,
        )

    async def _run_analysis(
        self,
        request: ErrorSearchRequest,
        *,
        service: str | None,
        symptom: str | None,
        semantic: bool,
        kind: str,
        report_clusters: int | None,
    ) -> IncidentReport:
        cache_key = make_cache_key(
            kind,
            self._llm.model_name if self._llm else "none",
            **request.model_dump(mode="json"),
            symptom=symptom,
            semantic=semantic,
        )
        if self._cache is not None:
            cached = self._cache.get(cache_key)
            if cached is not None:
                report = IncidentReport.model_validate(cached)
                report.cache_hit = True
                self._telemetry.record(kind, cache_hit=True)
                return report

        with self._telemetry.timed(kind, cache_hit=False) as metric:
            reduced = await self._query_and_reduce(request, metric)
            timeline = await self._fetch_timeline(request)
            report = await self._build_report(
                reduced,
                log_group=request.log_group,
                service=service,
                symptom=symptom,
                semantic=semantic,
                report_clusters=report_clusters,
                timeline=timeline,
            )
            metric.update(
                cloudwatch_events=report.stats.cloudwatch_events,
                clusters=report.stats.clusters,
                events_sent_to_llm=report.stats.events_sent_to_llm,
                compression_ratio=report.compression_ratio,
                semantic_status=report.semantic_analysis_status,
            )

        if self._cache is not None and report.semantic_analysis_status != "unavailable":
            self._cache.set(cache_key, kind, report.model_dump(mode="json"))
        return report

    async def _fetch_timeline(self, request: ErrorSearchRequest) -> list[TimelinePoint]:
        """Full-window volume timeline via server-side stats aggregation.

        Complete even when event retrieval hit the query limit. Failures
        never break the analysis — the report just omits the timeline.
        """
        try:
            planned = self._planner.plan_error_timeline(request)
            rows = await self._cloudwatch.run_stats_query(planned)
            return [
                TimelinePoint(time=bucket.start.isoformat(), count=bucket.count)
                for bucket in parse_timeline_rows(rows)
            ]
        except SignalSiftError as exc:
            logger.warning("Timeline query failed (continuing without): %s", exc.message)
            return []

    async def list_log_groups(self) -> list[dict[str, Any]]:
        """Allowlisted log groups with metadata, for dynamic discovery.

        Only groups matching the allowlist (exact names or glob patterns)
        are ever returned — the security boundary is unchanged; this just
        makes what's inside it discoverable.
        """
        from signalsift.security.policy import SecurityPolicy

        policy = SecurityPolicy(self._settings)
        all_groups = await self._cloudwatch.list_log_groups()
        by_name = {g.get("logGroupName", ""): g for g in all_groups}
        allowed_names = policy.filter_log_groups(list(by_name))
        result = []
        for name in sorted(allowed_names):
            group = by_name[name]
            result.append(
                {
                    "name": name,
                    "stored_bytes": group.get("storedBytes"),
                    "retention_days": group.get("retentionInDays"),
                }
            )
        self._telemetry.record("list_log_groups", returned=len(result))
        return result

    async def analyze_events(
        self,
        events: list,
        *,
        window_start: datetime,
        window_end: datetime,
        log_group: str = "offline",
        service: str | None = None,
        symptom: str | None = None,
        semantic: bool = True,
    ) -> IncidentReport:
        """Run the reduction+analysis pipeline on already-fetched events.

        Public entry point for offline tooling (raw log files, fixtures)
        — same reducer, LLM call and validation as the CloudWatch path,
        no AWS involved.
        """
        reduced = self._reducer.reduce(events, window_start, window_end)
        return await self._build_report(
            reduced,
            log_group=log_group,
            service=service,
            symptom=symptom,
            semantic=semantic and self._llm is not None,
            report_clusters=None,
        )

    async def _query_and_reduce(
        self, request: ErrorSearchRequest, metric: dict[str, Any]
    ) -> ReducedLogs:
        planned = self._planner.plan_error_search(request)
        result = await self._cloudwatch.run_query(planned)
        metric.update(
            records_scanned=result.stats.records_scanned,
            bytes_scanned=result.stats.bytes_scanned,
        )
        return self._reducer.reduce(
            result.events,
            window_start=request.start_time,
            window_end=request.end_time,
            source_truncated=result.truncated,
        )

    async def _build_report(
        self,
        reduced: ReducedLogs,
        *,
        log_group: str,
        service: str | None,
        symptom: str | None,
        semantic: bool,
        report_clusters: int | None = None,
        timeline: list[TimelinePoint] | None = None,
    ) -> IncidentReport:
        stats = reduced.stats
        analysis: IncidentAnalysis | None = None
        warnings: list[str] = []
        semantic_status: str = "unavailable"
        semantic_error: str | None = None

        # Zero errors: report calm, never invent an incident, skip the LLM.
        if not reduced.clusters:
            semantic_status = "ok"
            analysis = IncidentAnalysis(
                summary="No matching error events were found in this window.",
                severity="low",
            )
        elif semantic and self._llm is not None:
            evidence_json, selected = self._context_builder.build_incident_evidence(
                reduced, service, log_group, timeline=timeline
            )
            stats.clusters_sent_to_llm = len(selected)
            stats.events_sent_to_llm = sum(len(c.representative_events) for c in selected)
            prompt = build_incident_prompt(evidence_json, symptom)
            try:
                with self._telemetry.timed(
                    "llm_analyze", prompt_chars=len(prompt), model=self._llm.model_name
                ):
                    raw_analysis = await self._llm.analyze(prompt, IncidentAnalysis)
                validated = validate_analysis(
                    raw_analysis, selected, known_context=[service or "", log_group]
                )
                analysis = validated.analysis
                warnings = validated.warnings
                semantic_status = "degraded" if warnings else "ok"
            except SignalSiftError as exc:
                logger.warning("Local LLM analysis unavailable: %s", exc.message)
                semantic_status = "unavailable"
                semantic_error = exc.message
        else:
            semantic_status = "unavailable" if semantic else "ok"

        return IncidentReport(
            service=service,
            log_group=log_group,
            window_start=reduced.window_start.isoformat(),
            window_end=reduced.window_end.isoformat(),
            total_events=stats.cloudwatch_events,
            clusters=[
                _cluster_summary(c)
                for c in (
                    reduced.clusters
                    if report_clusters is None
                    else reduced.clusters[:report_clusters]
                )
            ],
            volume_timeline=timeline or [],
            semantic_analysis_status=semantic_status,  # type: ignore[arg-type]
            semantic_analysis_error=semantic_error,
            analysis=analysis,
            validation_warnings=warnings,
            stats=stats,
            compression_ratio=stats.compression_ratio,
        )

    # ------------------------------------------------------------------
    # trace_request
    # ------------------------------------------------------------------
    async def trace_request(
        self,
        log_group: str,
        request_id: str,
        start_time: datetime,
        end_time: datetime,
        max_events: int = 100,
    ) -> TraceReport:
        request = TraceRequest(
            log_group=log_group,
            request_id=request_id,
            start_time=start_time,
            end_time=end_time,
        )
        planned = self._planner.plan_trace(request)
        with self._telemetry.timed("trace_request"):
            result = await self._cloudwatch.run_query(planned)
        redacted = self._redactor.redact_events(result.events)
        redacted.sort(key=lambda e: e.timestamp)
        truncated = result.truncated or len(redacted) > max_events
        shown = redacted[:max_events]
        return TraceReport(
            log_group=log_group,
            request_id=request_id,
            window_start=start_time.isoformat(),
            window_end=end_time.isoformat(),
            total_events=len(redacted),
            events=[
                {
                    "timestamp": event.timestamp.isoformat(),
                    "level": event.level or "",
                    "message": event.message[: self._settings.max_chars_per_example],
                }
                for event in shown
            ],
            truncated=truncated,
        )

    # ------------------------------------------------------------------
    # compare_windows
    # ------------------------------------------------------------------
    async def compare_windows(
        self,
        log_group: str,
        baseline_start: datetime,
        baseline_end: datetime,
        comparison_start: datetime,
        comparison_end: datetime,
        service: str | None = None,
    ) -> ComparisonReport:
        async def profile(start: datetime, end: datetime) -> ReducedLogs:
            request = ErrorSearchRequest(
                log_group=log_group, start_time=start, end_time=end, service=service
            )
            planned = self._planner.plan_error_search(request)
            result = await self._cloudwatch.run_query(planned)
            return self._reducer.reduce(
                result.events,
                window_start=start,
                window_end=end,
                source_truncated=result.truncated,
            )

        with self._telemetry.timed("compare_windows"):
            baseline = await profile(baseline_start, baseline_end)
            comparison = await profile(comparison_start, comparison_end)

        new, disappeared, changed = self._compute_deltas(baseline, comparison)

        analysis: IncidentAnalysis | None = None
        warnings: list[str] = []
        semantic_status = "unavailable"
        if self._llm is not None and (new or disappeared or changed):
            evidence = self._context_builder.build_comparison_evidence(
                self._window_payload(baseline),
                self._window_payload(comparison),
                {
                    "new_clusters": [d.model_dump() for d in new],
                    "disappeared_clusters": [d.model_dump() for d in disappeared],
                    "changed_clusters": [d.model_dump() for d in changed],
                },
            )
            try:
                raw = await self._llm.analyze(build_comparison_prompt(evidence), IncidentAnalysis)
                validated = validate_analysis(
                    raw,
                    baseline.clusters + comparison.clusters,
                    known_context=[service or "", log_group],
                )
                analysis = validated.analysis
                warnings = validated.warnings
                semantic_status = "degraded" if warnings else "ok"
            except SignalSiftError as exc:
                logger.warning("Comparison LLM analysis unavailable: %s", exc.message)
                semantic_status = "unavailable"

        return ComparisonReport(
            log_group=log_group,
            service=service,
            baseline=self._window_profile(baseline),
            comparison=self._window_profile(comparison),
            new_clusters=new,
            disappeared_clusters=disappeared,
            changed_clusters=changed,
            semantic_analysis_status=semantic_status,  # type: ignore[arg-type]
            analysis=analysis,
            validation_warnings=warnings,
        )

    @staticmethod
    def _cluster_key(cluster: LogCluster) -> tuple[str | None, str]:
        return (cluster.exception_type, cluster.normalized_message)

    def _compute_deltas(
        self, baseline: ReducedLogs, comparison: ReducedLogs
    ) -> tuple[list[ClusterDelta], list[ClusterDelta], list[ClusterDelta]]:
        base_by_key = {self._cluster_key(c): c for c in baseline.clusters}
        comp_by_key = {self._cluster_key(c): c for c in comparison.clusters}

        new: list[ClusterDelta] = []
        disappeared: list[ClusterDelta] = []
        changed: list[ClusterDelta] = []

        for key, comp in comp_by_key.items():
            base = base_by_key.get(key)
            if base is None:
                new.append(
                    ClusterDelta(
                        cluster_id=comp.fingerprint,
                        exception_type=comp.exception_type,
                        normalized_message=comp.normalized_message[:200],
                        baseline_count=0,
                        comparison_count=comp.count,
                        change="new",
                        new_endpoints=sorted(comp.affected_endpoints),
                    )
                )
                continue
            ratio = comp.count / base.count if base.count else None
            if ratio is not None and 0.5 <= ratio <= 2.0:
                change = "stable"
            elif ratio is not None and ratio > 2.0:
                change = "increased"
            else:
                change = "decreased"
            delta = ClusterDelta(
                cluster_id=comp.fingerprint,
                exception_type=comp.exception_type,
                normalized_message=comp.normalized_message[:200],
                baseline_count=base.count,
                comparison_count=comp.count,
                change=change,
                ratio=round(ratio, 2) if ratio is not None else None,
                new_endpoints=sorted(set(comp.affected_endpoints) - set(base.affected_endpoints)),
            )
            if change != "stable":
                changed.append(delta)

        for key, base in base_by_key.items():
            if key not in comp_by_key:
                disappeared.append(
                    ClusterDelta(
                        cluster_id=base.fingerprint,
                        exception_type=base.exception_type,
                        normalized_message=base.normalized_message[:200],
                        baseline_count=base.count,
                        comparison_count=0,
                        change="disappeared",
                    )
                )
        return new, disappeared, changed

    def _window_profile(self, reduced: ReducedLogs) -> WindowProfile:
        return WindowProfile(
            window_start=reduced.window_start.isoformat(),
            window_end=reduced.window_end.isoformat(),
            total_events=reduced.stats.cloudwatch_events,
            clusters=[_cluster_summary(c) for c in reduced.clusters[:10]],
        )

    def _window_payload(self, reduced: ReducedLogs) -> dict[str, Any]:
        profile = self._window_profile(reduced)
        return profile.model_dump()
