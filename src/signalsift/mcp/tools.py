"""MCP tool implementations.

Thin adapters: parse/validate arguments, call the shared IncidentService,
render compact text. Expected SignalSift errors become actionable
messages; raw stack traces are only exposed in debug mode.
"""

from __future__ import annotations

import logging
import traceback
from datetime import UTC, datetime

from signalsift.analysis.render import (
    render_comparison_report,
    render_incident_report,
    render_trace_report,
)
from signalsift.app import SignalSiftApp
from signalsift.errors import SignalSiftError

logger = logging.getLogger(__name__)


def parse_time(value: str, field_name: str) -> datetime:
    """Parse an ISO-8601 timestamp; naive values are treated as UTC."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SignalSiftError(
            f"Could not parse {field_name}={value!r} as an ISO-8601 timestamp.",
            hint="Use e.g. 2026-09-03T14:00:00Z",
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def handle_errors(debug: bool):
    """Decorator: expected errors -> actionable text, unexpected -> generic."""

    def decorator(func):
        async def wrapper(*args, **kwargs) -> str:
            try:
                return await func(*args, **kwargs)
            except SignalSiftError as exc:
                return f"SignalSift error: {exc.render()}"
            except Exception as exc:  # noqa: BLE001
                logger.exception("Unexpected error in MCP tool %s", func.__name__)
                if debug:
                    return f"Unexpected error: {exc}\n{traceback.format_exc()}"
                return (
                    "SignalSift hit an unexpected internal error. "
                    "Enable SIGNALSIFT_DEBUG=true for details."
                )

        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper

    return decorator


class SignalSiftTools:
    """Bound tool coroutines around one app instance."""

    def __init__(self, app: SignalSiftApp) -> None:
        self._app = app
        debug = app.settings.debug
        self.list_log_groups = handle_errors(debug)(self._list_log_groups)
        self.analyze_incident = handle_errors(debug)(self._analyze_incident)
        self.search_errors = handle_errors(debug)(self._search_errors)
        self.trace_request = handle_errors(debug)(self._trace_request)
        self.compare_windows = handle_errors(debug)(self._compare_windows)

    async def _list_log_groups(self) -> str:
        groups = await self._app.service.list_log_groups()
        if not groups:
            return "No log groups exist in this AWS account/region."

        def _fmt(group: dict) -> str:
            size = ""
            if group["stored_bytes"] is not None:
                size = f"  ~{group['stored_bytes'] / 1_000_000:,.0f} MB"
            retention = f"  retention {group['retention_days']}d" if group["retention_days"] else ""
            return f"- {group['name']}{size}{retention}"

        allowed = [g for g in groups if g["allowed"]]
        blocked = [g for g in groups if not g["allowed"]]
        lines: list[str] = []
        if allowed:
            lines.append("QUERYABLE now (in the allowlist):")
            lines.extend(_fmt(g) for g in allowed)
            lines.append("")
        if blocked:
            lines.append("NOT queryable — add to SIGNALSIFT_ALLOWED_LOG_GROUPS to enable:")
            lines.extend(_fmt(g) for g in blocked)
            lines.append("")
        if not allowed:
            lines.append(
                "Nothing is allowlisted yet, so the analysis tools will refuse "
                "every query. Pick the groups you want from the list above and "
                "set SIGNALSIFT_ALLOWED_LOG_GROUPS (comma-separated; glob "
                "patterns like 'benefits-broker-*' work), then restart the "
                "server. This allowlist is a deliberate safety boundary — it "
                "keeps the assistant from reaching log groups you didn't choose."
            )
        return "\n".join(lines).rstrip()

    async def _analyze_incident(
        self,
        log_group: str,
        start_time: str,
        end_time: str,
        service: str | None = None,
        symptom: str | None = None,
    ) -> str:
        report = await self._app.service.analyze_incident(
            log_group=log_group,
            start_time=parse_time(start_time, "start_time"),
            end_time=parse_time(end_time, "end_time"),
            service=service,
            symptom=symptom,
        )
        return render_incident_report(report, self._app.settings.max_mcp_response_chars)

    async def _search_errors(
        self,
        log_group: str,
        start_time: str,
        end_time: str,
        service: str | None = None,
        exception_type: str | None = None,
        status_code: int | None = None,
        text: str | None = None,
    ) -> str:
        report = await self._app.service.search_errors(
            log_group=log_group,
            start_time=parse_time(start_time, "start_time"),
            end_time=parse_time(end_time, "end_time"),
            service=service,
            exception_type=exception_type,
            status_code=status_code,
            text=text,
        )
        return render_incident_report(report, self._app.settings.max_mcp_response_chars)

    async def _trace_request(
        self,
        log_group: str,
        request_id: str,
        time_hint: str | None = None,
    ) -> str:
        # Default window: the last max_time_range_minutes; a time_hint
        # centers the window on that moment instead.
        from datetime import timedelta

        half = timedelta(minutes=self._app.settings.max_time_range_minutes / 2)
        if time_hint:
            center = parse_time(time_hint, "time_hint")
            start, end = center - half, center + half
        else:
            end = datetime.now(UTC)
            start = end - 2 * half
        report = await self._app.service.trace_request(
            log_group=log_group, request_id=request_id, start_time=start, end_time=end
        )
        return render_trace_report(report, self._app.settings.max_mcp_response_chars)

    async def _compare_windows(
        self,
        log_group: str,
        baseline_start: str,
        baseline_end: str,
        comparison_start: str,
        comparison_end: str,
        service: str | None = None,
    ) -> str:
        report = await self._app.service.compare_windows(
            log_group=log_group,
            baseline_start=parse_time(baseline_start, "baseline_start"),
            baseline_end=parse_time(baseline_end, "baseline_end"),
            comparison_start=parse_time(comparison_start, "comparison_start"),
            comparison_end=parse_time(comparison_end, "comparison_end"),
            service=service,
        )
        return render_comparison_report(report, self._app.settings.max_mcp_response_chars)
