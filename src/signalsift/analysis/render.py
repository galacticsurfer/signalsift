"""Render reports as compact text for MCP/CLI.

Output is deliberately small: the whole point of SignalSift is that
Claude receives ~1-2K tokens of high-signal evidence, never raw logs.
Sections separate Observed (deterministic facts), Likely interpretation
(validated model inference) and Unknown (model-declared uncertainty).
"""

from __future__ import annotations

from signalsift.analysis.schemas import ComparisonReport, IncidentReport, TraceReport

# Clusters rendered with full detail (timestamps, endpoints); anything
# beyond this renders as a compact one-liner.
_DETAIL_CLUSTER_LIMIT = 10


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 60] + "\n\n[... truncated by SignalSift response size limit ...]"


def render_incident_report(report: IncidentReport, max_chars: int = 12000) -> str:
    lines: list[str] = []
    lines.append("INCIDENT SUMMARY")
    lines.append("----------------")
    if report.service:
        lines.append(f"Service: {report.service}")
    lines.append(f"Log group: {report.log_group}")
    lines.append(f"Window: {report.window_start} .. {report.window_end}")
    if report.cache_hit:
        lines.append("(cached result)")
    lines.append("")

    if report.total_events == 0:
        lines.append("No matching error events were found in this window.")
        lines.append("")
    else:
        if report.analysis:
            lines.append(f"Severity: {report.analysis.severity.upper()}")
            lines.append("")
            lines.append(report.analysis.summary)
            lines.append("")

        shown = len(report.clusters)
        total = report.stats.clusters
        header = "OBSERVED (deterministic)"
        if total > shown:
            header += f" — top {shown} of {total} clusters"
        lines.append(header)
        lines.append("-" * len(header))
        # Full detail for the dominant clusters, compact one-liners for the
        # tail so a broad search can show everything within the size cap.
        for i, cluster in enumerate(report.clusters):
            if i < _DETAIL_CLUSTER_LIMIT:
                endpoints = ", ".join(
                    f"{ep} ({n})"
                    for ep, n in sorted(
                        cluster.affected_endpoints.items(), key=lambda kv: -kv[1]
                    )[:3]
                )
                lines.append(
                    f"- [{cluster.cluster_id}] {cluster.exception_type or 'no-exception'} "
                    f"x{cluster.count}: {cluster.normalized_message[:140]}"
                )
                lines.append(
                    f"    first {cluster.first_seen}  last {cluster.last_seen}"
                    + (f"  endpoints: {endpoints}" if endpoints else "")
                )
            else:
                lines.append(
                    f"- [{cluster.cluster_id}] {cluster.exception_type or 'no-exception'} "
                    f"x{cluster.count}: {cluster.normalized_message[:90]}"
                )
        lines.append("")

        if report.analysis and report.analysis.likely_root_causes:
            lines.append("LIKELY INTERPRETATION (local model, evidence-validated)")
            lines.append("-------------------------------------------------------")
            for cause in report.analysis.likely_root_causes:
                lines.append(f"- {cause.cause} (confidence {cause.confidence:.2f})")
                for evidence in cause.evidence:
                    refs = f" [{', '.join(evidence.cluster_ids)}]" if evidence.cluster_ids else ""
                    lines.append(f"    evidence: {evidence.statement}{refs}")
            lines.append("")

        if report.analysis and report.analysis.timeline:
            lines.append("TIMELINE")
            lines.append("--------")
            lines.extend(f"- {item}" for item in report.analysis.timeline)
            lines.append("")

        if report.analysis and report.analysis.recommended_checks:
            lines.append("RECOMMENDED CHECKS")
            lines.append("------------------")
            lines.extend(
                f"{i}. {check}" for i, check in enumerate(report.analysis.recommended_checks, 1)
            )
            lines.append("")

        if report.analysis and report.analysis.uncertainties:
            lines.append("UNKNOWN / UNCERTAIN")
            lines.append("-------------------")
            lines.extend(f"- {item}" for item in report.analysis.uncertainties)
            lines.append("")

    if report.semantic_analysis_status == "unavailable":
        lines.append(
            "NOTE: semantic analysis unavailable"
            + (f" ({report.semantic_analysis_error})" if report.semantic_analysis_error else "")
            + " — deterministic results above are complete."
        )
        lines.append("")
    if report.validation_warnings:
        lines.append("VALIDATION WARNINGS")
        lines.append("-------------------")
        lines.extend(f"- {w}" for w in report.validation_warnings)
        lines.append("")

    stats = report.stats
    lines.append("SIGNALSIFT STATS")
    lines.append("----------------")
    lines.append(f"CloudWatch events: {stats.cloudwatch_events:,}")
    lines.append(f"After filtering: {stats.events_after_filtering:,}")
    lines.append(f"Unique logical events: {stats.logical_events:,}")
    lines.append(f"Clusters: {stats.clusters:,}")
    lines.append(f"Clusters sent to local LLM: {stats.clusters_sent_to_llm}")
    lines.append(f"Events sent to local LLM: {stats.events_sent_to_llm}")
    lines.append(f"Compression ratio: {report.compression_ratio}")
    if stats.truncated:
        lines.append("Note: some data was truncated by budget limits.")

    return _truncate("\n".join(lines), max_chars)


def render_trace_report(report: TraceReport, max_chars: int = 12000) -> str:
    lines = [
        "REQUEST TRACE",
        "-------------",
        f"Request ID: {report.request_id}",
        f"Log group: {report.log_group}",
        f"Window: {report.window_start} .. {report.window_end}",
        f"Events: {report.total_events}" + ("  (truncated)" if report.truncated else ""),
        "",
    ]
    if not report.events:
        lines.append("No events found for this request ID in the window.")
    for event in report.events:
        level = f" {event['level']}" if event["level"] else ""
        lines.append(f"[{event['timestamp']}]{level} {event['message']}")
    return _truncate("\n".join(lines), max_chars)


def render_comparison_report(report: ComparisonReport, max_chars: int = 12000) -> str:
    lines = [
        "WINDOW COMPARISON",
        "-----------------",
        f"Log group: {report.log_group}",
        f"Baseline:   {report.baseline.window_start} .. {report.baseline.window_end}"
        f"  ({report.baseline.total_events:,} events)",
        f"Comparison: {report.comparison.window_start} .. {report.comparison.window_end}"
        f"  ({report.comparison.total_events:,} events)",
        "",
    ]
    if report.analysis:
        lines.append(report.analysis.summary)
        lines.append("")

    def _delta_lines(title: str, deltas: list) -> None:
        if not deltas:
            return
        lines.append(title)
        lines.append("-" * len(title))
        for delta in deltas:
            ratio = f" ({delta.ratio}x)" if delta.ratio else ""
            lines.append(
                f"- [{delta.change.upper()}] {delta.exception_type or 'no-exception'}: "
                f"{delta.normalized_message[:120]} "
                f"({delta.baseline_count} -> {delta.comparison_count}{ratio})"
            )
            if delta.new_endpoints:
                lines.append(f"    new endpoints: {', '.join(delta.new_endpoints)}")
        lines.append("")

    _delta_lines("NEW CLUSTERS", report.new_clusters)
    _delta_lines("DISAPPEARED CLUSTERS", report.disappeared_clusters)
    _delta_lines("CHANGED CLUSTERS", report.changed_clusters)

    if report.analysis and report.analysis.likely_root_causes:
        lines.append("LIKELY INTERPRETATION")
        lines.append("---------------------")
        for cause in report.analysis.likely_root_causes:
            lines.append(f"- {cause.cause} (confidence {cause.confidence:.2f})")
        lines.append("")
    if report.analysis and report.analysis.uncertainties:
        lines.append("UNKNOWN / UNCERTAIN")
        lines.append("-------------------")
        lines.extend(f"- {item}" for item in report.analysis.uncertainties)
        lines.append("")
    if report.semantic_analysis_status == "unavailable":
        lines.append(
            "NOTE: semantic analysis unavailable — deterministic deltas above are complete."
        )
    return _truncate("\n".join(lines), max_chars)
