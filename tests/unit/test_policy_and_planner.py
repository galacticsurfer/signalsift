"""Allowlist, time-range and query-generation safety tests."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest

from signalsift.cloudwatch.query_planner import ErrorSearchRequest, QueryPlanner, TraceRequest
from signalsift.cloudwatch.query_templates import escape_regex
from signalsift.config import Settings
from signalsift.errors import (
    InvalidTimeRangeError,
    LogGroupNotAllowedError,
    TimeRangeTooLargeError,
)
from signalsift.security.policy import SecurityPolicy

START = datetime(2026, 9, 3, 14, 0, tzinfo=UTC)
END = datetime(2026, 9, 3, 14, 30, tzinfo=UTC)


def _request(**overrides) -> ErrorSearchRequest:
    defaults = dict(log_group="/aws/app/payments-prod", start_time=START, end_time=END)
    defaults.update(overrides)
    return ErrorSearchRequest(**defaults)


class TestSecurityPolicy:
    def test_allowed_log_group_passes(self, settings: Settings) -> None:
        SecurityPolicy(settings).check_log_group("/aws/app/payments-prod")

    def test_unlisted_log_group_rejected(self, settings: Settings) -> None:
        with pytest.raises(LogGroupNotAllowedError):
            SecurityPolicy(settings).check_log_group("/aws/app/secret-prod")

    def test_empty_allowlist_rejects_everything(self) -> None:
        settings = Settings(_env_file=None, allowed_log_groups=[])
        with pytest.raises(LogGroupNotAllowedError):
            SecurityPolicy(settings).check_log_group("/aws/app/payments-prod")

    def test_time_range_too_large(self, settings: Settings) -> None:
        with pytest.raises(TimeRangeTooLargeError):
            SecurityPolicy(settings).check_time_range(START, START + timedelta(hours=3))

    def test_end_before_start(self, settings: Settings) -> None:
        with pytest.raises(InvalidTimeRangeError):
            SecurityPolicy(settings).check_time_range(END, START)

    def test_naive_datetime_rejected(self, settings: Settings) -> None:
        with pytest.raises(InvalidTimeRangeError):
            SecurityPolicy(settings).check_time_range(
                START.replace(tzinfo=None), END.replace(tzinfo=None)
            )

    def test_limit_clamped(self, settings: Settings) -> None:
        policy = SecurityPolicy(settings)
        assert policy.clamp_limit(999999) == settings.max_query_results
        assert policy.clamp_limit(10) == 10
        assert policy.clamp_limit(None) == settings.max_query_results


class TestQueryPlanner:
    def test_plans_error_search(self, settings: Settings) -> None:
        planned = QueryPlanner(settings).plan_error_search(_request(status_code=502))
        assert "fields @timestamp, @message, @logStream" in planned.query_string
        assert "502" in planned.query_string
        assert "sort @timestamp desc" in planned.query_string
        assert planned.limit == 2000

    def test_rejects_unlisted_group(self, settings: Settings) -> None:
        with pytest.raises(LogGroupNotAllowedError):
            QueryPlanner(settings).plan_error_search(_request(log_group="/aws/app/other"))

    def test_text_is_regex_escaped(self, settings: Settings) -> None:
        planned = QueryPlanner(settings).plan_error_search(_request(text="a.b*c/ | limit 100000"))
        # Metacharacters must be escaped so user text cannot alter the query.
        assert r"a\.b\*c\/" in planned.query_string
        assert r"\|" in planned.query_string  # the injected pipe is inert
        # The only effective limit directive is the planner's own.
        assert planned.query_string.strip().endswith("limit 2000")

    def test_trace_query_sorted_ascending(self, settings: Settings) -> None:
        planned = QueryPlanner(settings).plan_trace(
            TraceRequest(
                log_group="/aws/app/payments-prod",
                request_id="abc-123",
                start_time=START,
                end_time=END,
            )
        )
        assert "sort @timestamp asc" in planned.query_string
        assert "abc-123" in planned.query_string


def test_escape_regex_neutralizes_metacharacters() -> None:
    escaped = escape_regex("^a.b$|(c)*/")
    assert escaped == r"\^a\.b\$\|\(c\)\*\/"


_VALID_PIPE_STAGE = re.compile(
    r"^(fields\s+@\w|filter\s+@\w|sort\s+@\w+\s+(asc|desc)$|limit\s+\d+$)"
)


def _assert_valid_insights_syntax(query: str) -> None:
    """Structural check of generated Logs Insights queries.

    Guards against the MalformedQueryException class of bug (e.g. a
    repeated `filter` keyword after `or`, which CloudWatch rejects with
    'unexpected @ symbol').
    """
    stages = [s.strip() for s in query.split("|")]
    for stage in stages:
        assert _VALID_PIPE_STAGE.match(stage), f"invalid pipe stage: {stage!r}"
        # `or` joins conditions WITHIN one filter; the keyword must not repeat.
        assert " or filter " not in stage, f"repeated filter keyword: {stage!r}"


def test_generated_queries_are_syntactically_valid(settings: Settings) -> None:
    planner = QueryPlanner(settings)
    full = planner.plan_error_search(
        _request(
            service="payments",
            exception_type="TimeoutError",
            status_code=502,
            request_id="req-1",
            text="pool exhausted",
        )
    )
    _assert_valid_insights_syntax(full.query_string)

    default_level = planner.plan_error_search(_request())
    _assert_valid_insights_syntax(default_level.query_string)
    assert "or filter" not in default_level.query_string
    assert "filter @message like /ERROR/ or @message like /error/" in default_level.query_string

    trace = planner.plan_trace(
        TraceRequest(
            log_group="/aws/app/payments-prod",
            request_id="abc-123",
            start_time=START,
            end_time=END,
        )
    )
    _assert_valid_insights_syntax(trace.query_string)
