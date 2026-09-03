"""trace_request and compare_windows service tests."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from signalsift.analysis.render import render_comparison_report, render_trace_report
from signalsift.analysis.service import IncidentService
from signalsift.cloudwatch.client import CloudWatchLogsClient
from signalsift.config import Settings
from tests.conftest import FakeLogsClient
from tests.fixtures.generators import (
    MONGO_TRACE,
    WINDOW_END,
    WINDOW_START,
    make_row,
    scenario_http_timeout,
    scenario_mongodb,
)

LOG_GROUP = "/aws/app/payments-prod"


def _fast(settings: Settings) -> Settings:
    return settings.model_copy(
        update={"query_poll_initial_seconds": 0.001, "query_poll_max_seconds": 0.002}
    )


async def test_trace_request_chronological_and_redacted(settings, fake_llm):
    rows = [
        make_row(WINDOW_START + timedelta(minutes=2), "INFO req abc-123 step 2 password=secretpw1"),
        make_row(WINDOW_START, "INFO req abc-123 step 1"),
        make_row(WINDOW_START + timedelta(minutes=5), "ERROR req abc-123 failed"),
    ]
    fast = _fast(settings)
    service = IncidentService(fast, CloudWatchLogsClient(fast, FakeLogsClient(rows)), fake_llm)
    report = await service.trace_request(LOG_GROUP, "abc-123", WINDOW_START, WINDOW_END)
    assert report.total_events == 3
    timestamps = [e["timestamp"] for e in report.events]
    assert timestamps == sorted(timestamps)
    assert all("secretpw1" not in e["message"] for e in report.events)
    rendered = render_trace_report(report)
    assert "abc-123" in rendered


class SequencedClient(FakeLogsClient):
    """Returns a different canned result set for each successive query."""

    def __init__(self, result_sets: list[list[list[dict]]]) -> None:
        super().__init__([])
        self.result_sets = result_sets
        self.query_index = -1

    def start_query(self, **kwargs: Any) -> dict[str, Any]:
        self.query_index += 1
        return super().start_query(**kwargs)

    def get_query_results(self, *, queryId: str) -> dict[str, Any]:  # noqa: N803
        rows = self.result_sets[min(self.query_index, len(self.result_sets) - 1)]
        return {
            "status": "Complete",
            "results": rows,
            "statistics": {"recordsMatched": float(len(rows))},
        }


async def test_compare_windows_detects_new_and_disappeared(settings, fake_llm):
    baseline_rows = scenario_http_timeout(50)
    comparison_rows = scenario_mongodb(200)
    fast = _fast(settings)
    client = CloudWatchLogsClient(fast, SequencedClient([baseline_rows, comparison_rows]))
    service = IncidentService(fast, client, fake_llm)
    baseline_end = WINDOW_START
    baseline_start = baseline_end - timedelta(minutes=30)
    report = await service.compare_windows(
        LOG_GROUP, baseline_start, baseline_end, WINDOW_START, WINDOW_END
    )
    new_types = {d.exception_type for d in report.new_clusters}
    gone_types = {d.exception_type for d in report.disappeared_clusters}
    assert "MongoServerSelectionTimeout" in new_types
    assert "ReadTimeout" in gone_types
    rendered = render_comparison_report(report)
    assert "NEW CLUSTERS" in rendered
    assert "DISAPPEARED CLUSTERS" in rendered


async def test_compare_windows_frequency_increase(settings, fake_llm):
    def mongo_rows(count: int) -> list[list[dict]]:
        return [
            make_row(WINDOW_START + timedelta(seconds=i), f"ERROR status=502\n{MONGO_TRACE}")
            for i in range(count)
        ]

    fast = _fast(settings)
    client = CloudWatchLogsClient(fast, SequencedClient([mongo_rows(10), mongo_rows(100)]))
    service = IncidentService(fast, client, fake_llm)
    report = await service.compare_windows(
        LOG_GROUP,
        WINDOW_START - timedelta(minutes=30),
        WINDOW_START,
        WINDOW_START,
        WINDOW_END,
    )
    assert len(report.changed_clusters) == 1
    delta = report.changed_clusters[0]
    assert delta.change == "increased"
    assert delta.ratio == 10.0
