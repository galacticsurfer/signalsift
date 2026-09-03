"""SignalSift CLI.

Same service layer as MCP — this exists so the whole pipeline can be
exercised and debugged without Claude in the loop.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from datetime import UTC, datetime, timedelta

import click

from signalsift.analysis.render import (
    render_comparison_report,
    render_incident_report,
    render_trace_report,
)
from signalsift.app import SignalSiftApp
from signalsift.errors import SignalSiftError
from signalsift.mcp.tools import parse_time

_DURATION = re.compile(r"^(\d+)\s*(m|min|h|hr|d)$")


def parse_last(value: str) -> timedelta:
    match = _DURATION.match(value.strip().lower())
    if not match:
        raise click.BadParameter("use forms like 30m, 2h, 1d")
    amount = int(match.group(1))
    unit = match.group(2)
    if unit in ("m", "min"):
        return timedelta(minutes=amount)
    if unit in ("h", "hr"):
        return timedelta(hours=amount)
    return timedelta(days=amount)


def _window(last: str | None, start: str | None, end: str | None) -> tuple[datetime, datetime]:
    if last:
        end_dt = datetime.now(UTC)
        return end_dt - parse_last(last), end_dt
    if start and end:
        return parse_time(start, "start"), parse_time(end, "end")
    raise click.UsageError("Provide either --last (e.g. --last 30m) or --start and --end.")


def _run(coro):
    try:
        return asyncio.run(coro)
    except SignalSiftError as exc:
        click.echo(f"Error: {exc.render()}", err=True)
        sys.exit(1)


@click.group()
def cli() -> None:
    """SignalSift: local-first CloudWatch incident analysis."""


@cli.command()
def health() -> None:
    """Check AWS, CloudWatch, Ollama, model and cache readiness."""
    from signalsift.health import run_health_checks

    app = SignalSiftApp()
    report = _run(run_health_checks(app.settings, app.llm))
    click.echo(report.render())
    sys.exit(0 if report.ready else 1)


@cli.command()
@click.option("--log-group", required=True)
@click.option("--last", default=None, help="Relative window, e.g. 30m, 2h")
@click.option("--start", default=None, help="ISO-8601 window start")
@click.option("--end", default=None, help="ISO-8601 window end")
@click.option("--service", default=None)
@click.option("--symptom", default=None, help="Operator-reported symptom")
@click.option("--json", "as_json", is_flag=True, help="Emit the raw JSON report")
def analyze(log_group, last, start, end, service, symptom, as_json) -> None:
    """Full incident analysis: reduce + local LLM + validated report."""
    app = SignalSiftApp()
    start_dt, end_dt = _window(last, start, end)
    report = _run(
        app.service.analyze_incident(
            log_group=log_group,
            start_time=start_dt,
            end_time=end_dt,
            service=service,
            symptom=symptom,
        )
    )
    if as_json:
        click.echo(json.dumps(report.model_dump(mode="json"), indent=2))
    else:
        click.echo(render_incident_report(report, app.settings.max_mcp_response_chars))


@cli.command()
@click.option("--log-group", required=True)
@click.option("--last", default=None)
@click.option("--start", default=None)
@click.option("--end", default=None)
@click.option("--service", default=None)
@click.option("--exception-type", default=None)
@click.option("--status-code", type=int, default=None)
@click.option("--text", default=None)
@click.option("--json", "as_json", is_flag=True)
def search(log_group, last, start, end, service, exception_type, status_code, text, as_json):
    """Deterministic error-pattern search (no LLM)."""
    app = SignalSiftApp()
    start_dt, end_dt = _window(last, start, end)
    report = _run(
        app.service.search_errors(
            log_group=log_group,
            start_time=start_dt,
            end_time=end_dt,
            service=service,
            exception_type=exception_type,
            status_code=status_code,
            text=text,
        )
    )
    if as_json:
        click.echo(json.dumps(report.model_dump(mode="json"), indent=2))
    else:
        click.echo(render_incident_report(report, app.settings.max_mcp_response_chars))


@cli.command()
@click.option("--log-group", required=True)
@click.option("--request-id", required=True)
@click.option("--last", default="60m", help="How far back to search")
def trace(log_group, request_id, last) -> None:
    """Trace all (redacted) events for one request ID."""
    app = SignalSiftApp()
    end_dt = datetime.now(UTC)
    start_dt = end_dt - parse_last(last)
    report = _run(
        app.service.trace_request(
            log_group=log_group,
            request_id=request_id,
            start_time=start_dt,
            end_time=end_dt,
        )
    )
    click.echo(render_trace_report(report, app.settings.max_mcp_response_chars))


@cli.command()
@click.option("--log-group", required=True)
@click.option("--baseline-start", required=True)
@click.option("--baseline-end", required=True)
@click.option("--comparison-start", required=True)
@click.option("--comparison-end", required=True)
@click.option("--service", default=None)
def compare(log_group, baseline_start, baseline_end, comparison_start, comparison_end, service):
    """Compare error profiles between two windows."""
    app = SignalSiftApp()
    report = _run(
        app.service.compare_windows(
            log_group=log_group,
            baseline_start=parse_time(baseline_start, "baseline_start"),
            baseline_end=parse_time(baseline_end, "baseline_end"),
            comparison_start=parse_time(comparison_start, "comparison_start"),
            comparison_end=parse_time(comparison_end, "comparison_end"),
            service=service,
        )
    )
    click.echo(render_comparison_report(report, app.settings.max_mcp_response_chars))


@cli.command()
@click.option("--limit", default=20, help="Number of recent operations to show")
def stats(limit) -> None:
    """Show recent local telemetry (never sent anywhere)."""
    app = SignalSiftApp()
    metrics = app.telemetry.recent(limit)
    if not metrics:
        click.echo("No telemetry recorded yet.")
        return
    for metric in metrics:
        ts = datetime.fromtimestamp(metric.pop("recorded_at"), tz=UTC).isoformat()
        op = metric.pop("operation")
        rest = " ".join(f"{k}={v}" for k, v in metric.items())
        click.echo(f"{ts}  {op:<18} {rest}")


@cli.command()
def serve() -> None:
    """Run the MCP server on stdio (for Claude Code / Claude Desktop)."""
    from signalsift.mcp.server import run as run_server

    run_server()


if __name__ == "__main__":
    cli()
