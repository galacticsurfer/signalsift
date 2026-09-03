"""SignalSift MCP server (stdio transport)."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from signalsift.app import SignalSiftApp
from signalsift.mcp.tools import SignalSiftTools


def create_server(app: SignalSiftApp | None = None) -> MCPServer:
    app = app or SignalSiftApp()
    tools = SignalSiftTools(app)
    mcp = MCPServer(
        "signalsift",
        instructions=(
            "SignalSift analyzes AWS CloudWatch logs locally: it queries, "
            "redacts, deduplicates and clusters errors, runs a local LLM on "
            "the reduced evidence, and returns a compact validated incident "
            "report. Raw logs never leave the user's machine."
        ),
    )

    @mcp.tool()
    async def analyze_incident(
        log_group: str,
        start_time: str,
        end_time: str,
        service: str | None = None,
        symptom: str | None = None,
    ) -> str:
        """Diagnose an incident: fetch errors from a CloudWatch log group for a
        time window (ISO-8601), reduce them deterministically, analyze with a
        local LLM, and return a compact validated incident report.

        Args:
            log_group: CloudWatch log group (must be allowlisted).
            start_time: Window start, ISO-8601 (e.g. 2026-09-03T14:00:00Z).
            end_time: Window end, ISO-8601.
            service: Optional service name to filter on.
            symptom: Optional operator-reported symptom (e.g. "502s on checkout").
        """
        return await tools.analyze_incident(log_group, start_time, end_time, service, symptom)

    @mcp.tool()
    async def search_errors(
        log_group: str,
        start_time: str,
        end_time: str,
        service: str | None = None,
        exception_type: str | None = None,
        status_code: int | None = None,
        text: str | None = None,
    ) -> str:
        """Find and summarize error patterns in a CloudWatch log group.
        Returns deterministic cluster summaries (counts, endpoints, first/last
        seen) without LLM interpretation — fast pattern discovery.

        Args:
            log_group: CloudWatch log group (must be allowlisted).
            start_time: Window start, ISO-8601.
            end_time: Window end, ISO-8601.
            service: Optional service name filter.
            exception_type: Optional exception class name filter.
            status_code: Optional HTTP status code filter.
            text: Optional literal text filter.
        """
        return await tools.search_errors(
            log_group, start_time, end_time, service, exception_type, status_code, text
        )

    @mcp.tool()
    async def trace_request(
        log_group: str,
        request_id: str,
        time_hint: str | None = None,
    ) -> str:
        """Retrieve the chronological (redacted) log events for one request ID.

        Args:
            log_group: CloudWatch log group (must be allowlisted).
            request_id: The request/correlation ID to trace.
            time_hint: Optional ISO-8601 timestamp to center the search window on.
        """
        return await tools.trace_request(log_group, request_id, time_hint)

    @mcp.tool()
    async def compare_windows(
        log_group: str,
        baseline_start: str,
        baseline_end: str,
        comparison_start: str,
        comparison_end: str,
        service: str | None = None,
    ) -> str:
        """Compare error profiles between two time windows (e.g. before/after a
        deployment): new clusters, disappeared clusters, frequency changes,
        newly affected endpoints, plus a local-LLM interpretation.

        Args:
            log_group: CloudWatch log group (must be allowlisted).
            baseline_start: Baseline window start, ISO-8601.
            baseline_end: Baseline window end, ISO-8601.
            comparison_start: Comparison window start, ISO-8601.
            comparison_end: Comparison window end, ISO-8601.
            service: Optional service name filter.
        """
        return await tools.compare_windows(
            log_group, baseline_start, baseline_end, comparison_start, comparison_end, service
        )

    return mcp


def run() -> None:
    create_server().run()


if __name__ == "__main__":
    run()
