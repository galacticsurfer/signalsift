"""Clustering, ranking and sampling tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from signalsift.cloudwatch.models import LogEvent
from signalsift.processing.clusterer import cluster_events, count_logical_events, score_clusters
from signalsift.processing.sampler import sample_cluster_events

BASE = datetime(2026, 9, 3, 14, 0, tzinfo=UTC)


def _event(
    i: int,
    fingerprint: str,
    exception: str | None = "TimeoutError",
    normalized: str = "TimeoutError: db timeout",
    endpoint: str | None = None,
    level: str = "ERROR",
    status: int | None = None,
) -> LogEvent:
    return LogEvent(
        timestamp=BASE + timedelta(seconds=i),
        message=f"raw message {i}",
        fingerprint=fingerprint,
        exception_type=exception,
        normalized_message=normalized,
        endpoint=endpoint,
        level=level,
        status_code=status,
    )


def test_groups_by_exception_and_message() -> None:
    events = (
        [_event(i, "fp-a", endpoint="/checkout") for i in range(10)]
        + [_event(i, "fp-b", endpoint="/order") for i in range(5)]
        + [_event(i, "fp-c", "ValidationError", "ValidationError: bad email") for i in range(2)]
    )
    clusters = cluster_events(events)
    assert len(clusters) == 2  # timeout merged across endpoints, validation separate
    timeout = next(c for c in clusters if c.exception_type == "TimeoutError")
    assert timeout.count == 15
    assert timeout.affected_endpoints == {"/checkout": 10, "/order": 5}
    assert count_logical_events(events) == 3


def test_cluster_first_last_seen() -> None:
    events = [_event(i, "fp-a") for i in (5, 1, 9)]
    cluster = cluster_events(events)[0]
    assert cluster.first_seen == BASE + timedelta(seconds=1)
    assert cluster.last_seen == BASE + timedelta(seconds=9)


def test_scoring_prefers_frequent_recent_5xx() -> None:
    big_5xx = [_event(i, "fp-a", status=502) for i in range(100)]
    small_warn = [
        _event(i, "fp-b", "ValidationError", "ValidationError: bad", level="WARNING")
        for i in range(3)
    ]
    clusters = score_clusters(cluster_events(big_5xx + small_warn), BASE + timedelta(minutes=5))
    assert clusters[0].exception_type == "TimeoutError"
    assert clusters[0].score > clusters[1].score


def test_scoring_deterministic_order() -> None:
    events = [_event(i, f"fp-{i % 4}", normalized=f"msg {i % 4}") for i in range(40)]
    a = [c.fingerprint for c in score_clusters(cluster_events(events), BASE)]
    b = [c.fingerprint for c in score_clusters(cluster_events(events), BASE)]
    assert a == b


def test_sampling_first_middle_last() -> None:
    events = [_event(i, "fp-a") for i in range(100)]
    sampled = sample_cluster_events(events, 3)
    assert len(sampled) == 3
    assert sampled[0].timestamp == events[0].timestamp
    assert sampled[-1].timestamp == events[-1].timestamp
    assert sampled[1].timestamp not in (events[0].timestamp, events[-1].timestamp)


def test_sampling_small_cluster_untouched() -> None:
    events = [_event(i, "fp-a") for i in range(2)]
    assert len(sample_cluster_events(events, 5)) == 2
