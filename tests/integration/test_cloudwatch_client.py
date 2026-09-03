"""CloudWatch client tests against a scripted fake boto3 client."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from botocore.exceptions import ClientError

from signalsift.cloudwatch.client import CloudWatchLogsClient
from signalsift.cloudwatch.query_planner import PlannedQuery
from signalsift.config import Settings
from signalsift.errors import (
    AwsAuthError,
    CloudWatchQueryError,
    CloudWatchThrottledError,
    CloudWatchTimeoutError,
)
from tests.conftest import FakeLogsClient
from tests.fixtures.generators import WINDOW_END, WINDOW_START, make_row

PLANNED = PlannedQuery(
    log_group="/aws/app/payments-prod",
    query_string="fields @timestamp, @message",
    start_time=WINDOW_START,
    end_time=WINDOW_END,
    limit=100,
)


def _fast_settings(**overrides) -> Settings:
    return Settings(
        _env_file=None,
        allowed_log_groups=["/aws/app/payments-prod"],
        query_poll_initial_seconds=0.001,
        query_poll_max_seconds=0.002,
        **overrides,
    )


async def test_successful_query_converts_events() -> None:
    rows = [make_row(WINDOW_START, "ERROR TimeoutError: db down")]
    client = CloudWatchLogsClient(_fast_settings(), FakeLogsClient(rows))
    result = await client.run_query(PLANNED)
    assert len(result.events) == 1
    event = result.events[0]
    assert event.timestamp == WINDOW_START
    assert event.log_stream == "app/instance-1"
    assert result.stats.records_matched == 1.0


async def test_json_messages_parse_structured_fields() -> None:
    rows = [
        make_row(
            WINDOW_START,
            '{"level": "error", "request_id": "req-9", "service": "payments", "msg": "boom"}',
        )
    ]
    client = CloudWatchLogsClient(_fast_settings(), FakeLogsClient(rows))
    result = await client.run_query(PLANNED)
    event = result.events[0]
    assert event.level == "ERROR"
    assert event.request_id == "req-9"
    assert event.service == "payments"


async def test_polls_until_complete() -> None:
    class SlowClient(FakeLogsClient):
        def __init__(self) -> None:
            super().__init__([make_row(WINDOW_START, "ERROR x")])
            self.calls = 0

        def get_query_results(self, *, queryId: str) -> dict[str, Any]:  # noqa: N803
            self.calls += 1
            if self.calls < 3:
                return {"status": "Running"}
            return super().get_query_results(queryId=queryId)

    slow = SlowClient()
    client = CloudWatchLogsClient(_fast_settings(), slow)
    result = await client.run_query(PLANNED)
    assert slow.calls == 3
    assert len(result.events) == 1


async def test_timeout_stops_query() -> None:
    class NeverDone(FakeLogsClient):
        def get_query_results(self, *, queryId: str) -> dict[str, Any]:  # noqa: N803
            return {"status": "Running"}

    fake = NeverDone([])
    client = CloudWatchLogsClient(_fast_settings(query_timeout_seconds=0), fake)
    with pytest.raises(CloudWatchTimeoutError):
        await client.run_query(PLANNED)
    assert fake.stopped == ["q-1"]


async def test_failed_status_raises() -> None:
    class Failing(FakeLogsClient):
        def get_query_results(self, *, queryId: str) -> dict[str, Any]:  # noqa: N803
            return {"status": "Failed"}

    client = CloudWatchLogsClient(_fast_settings(), Failing([]))
    with pytest.raises(CloudWatchQueryError):
        await client.run_query(PLANNED)


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "StartQuery")


async def test_expired_token_becomes_auth_error() -> None:
    class Expired(FakeLogsClient):
        def start_query(self, **kwargs: Any) -> dict[str, Any]:
            raise _client_error("ExpiredTokenException")

    client = CloudWatchLogsClient(_fast_settings(), Expired([]))
    with pytest.raises(AwsAuthError):
        await client.run_query(PLANNED)


async def test_throttling_translated() -> None:
    class Throttled(FakeLogsClient):
        def start_query(self, **kwargs: Any) -> dict[str, Any]:
            raise _client_error("ThrottlingException")

    client = CloudWatchLogsClient(_fast_settings(), Throttled([]))
    with pytest.raises(CloudWatchThrottledError):
        await client.run_query(PLANNED)


async def test_start_query_receives_epoch_seconds() -> None:
    fake = FakeLogsClient([])
    client = CloudWatchLogsClient(_fast_settings(), fake)
    await client.run_query(PLANNED)
    call = fake.started_queries[0]
    assert call["startTime"] == int(WINDOW_START.timestamp())
    assert call["endTime"] == int(WINDOW_END.timestamp())
    assert call["limit"] == 100
    assert isinstance(datetime.fromtimestamp(call["startTime"], tz=UTC), datetime)
