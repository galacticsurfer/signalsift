"""Opt-in integration tests against real AWS / real Ollama.

Skipped unless RUN_AWS_INTEGRATION_TESTS=1 / RUN_OLLAMA_INTEGRATION_TESTS=1.
Normal CI never needs AWS or a running model.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

from signalsift.analysis.schemas import IncidentAnalysis
from signalsift.config import load_settings
from signalsift.llm.ollama import OllamaProvider

requires_aws = pytest.mark.skipif(
    os.environ.get("RUN_AWS_INTEGRATION_TESTS") != "1",
    reason="set RUN_AWS_INTEGRATION_TESTS=1 to run against real AWS",
)
requires_ollama = pytest.mark.skipif(
    os.environ.get("RUN_OLLAMA_INTEGRATION_TESTS") != "1",
    reason="set RUN_OLLAMA_INTEGRATION_TESTS=1 to run against real Ollama",
)


@requires_aws
async def test_real_cloudwatch_query() -> None:
    from signalsift.cloudwatch.client import CloudWatchLogsClient
    from signalsift.cloudwatch.query_planner import ErrorSearchRequest, QueryPlanner

    settings = load_settings()
    assert settings.allowed_log_groups, "configure SIGNALSIFT_ALLOWED_LOG_GROUPS"
    planner = QueryPlanner(settings)
    end = datetime.now(UTC)
    planned = planner.plan_error_search(
        ErrorSearchRequest(
            log_group=settings.allowed_log_groups[0],
            start_time=end - timedelta(minutes=30),
            end_time=end,
            limit=50,
        )
    )
    result = await CloudWatchLogsClient(settings).run_query(planned)
    assert result.stats is not None


@requires_ollama
async def test_real_ollama_structured_output() -> None:
    settings = load_settings()
    provider = OllamaProvider(settings)
    assert await provider.is_available(), "Ollama is not running"
    analysis = await provider.analyze(
        "Analyze this incident evidence and respond in JSON.\n"
        "BEGIN_LOG_DATA\n"
        '{"clusters": [{"cluster_id": "abc", "exception_type": "TimeoutError", "count": 100}]}\n'
        "END_LOG_DATA",
        IncidentAnalysis,
    )
    assert isinstance(analysis, IncidentAnalysis)
    assert analysis.severity in ("low", "medium", "high", "critical")
    await provider.aclose()
