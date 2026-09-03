"""MCP server tests: registration and error surfacing through tools."""

from __future__ import annotations

from signalsift.app import SignalSiftApp
from signalsift.config import Settings
from signalsift.mcp.server import create_server
from signalsift.mcp.tools import SignalSiftTools


def _app(settings: Settings) -> SignalSiftApp:
    return SignalSiftApp(settings)


async def test_all_tools_registered(settings: Settings) -> None:
    server = create_server(_app(settings))
    names = {tool.name for tool in await server.list_tools()}
    assert names == {
        "list_log_groups",
        "analyze_incident",
        "search_errors",
        "trace_request",
        "compare_windows",
    }


async def test_disallowed_log_group_returns_actionable_text(settings: Settings) -> None:
    tools = SignalSiftTools(_app(settings))
    out = await tools.analyze_incident(
        "/aws/app/forbidden", "2026-09-03T14:00:00Z", "2026-09-03T14:30:00Z"
    )
    assert "not in the allowlist" in out
    assert "Traceback" not in out


async def test_bad_timestamp_returns_actionable_text(settings: Settings) -> None:
    tools = SignalSiftTools(_app(settings))
    out = await tools.analyze_incident("/aws/app/payments-prod", "yesterday-ish", "now")
    assert "ISO-8601" in out
    assert "Traceback" not in out


async def test_unexpected_errors_hidden_without_debug(settings: Settings) -> None:
    app = _app(settings)
    tools = SignalSiftTools(app)

    async def boom(**kwargs):
        raise RuntimeError("internal boom with /etc/secret/path")

    app.service.analyze_incident = boom  # type: ignore[method-assign]
    out = await tools.analyze_incident(
        "/aws/app/payments-prod", "2026-09-03T14:00:00Z", "2026-09-03T14:30:00Z"
    )
    assert "internal boom" not in out
    assert "unexpected internal error" in out
