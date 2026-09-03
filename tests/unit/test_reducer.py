"""End-to-end reducer tests: budgets, stats and golden scenarios."""

from __future__ import annotations

from signalsift.cloudwatch.client import convert_results
from signalsift.config import Settings
from signalsift.processing.reducer import LogReducer, enrich_event
from tests.fixtures.generators import (
    WINDOW_END,
    WINDOW_START,
    make_row,
    scenario_mixed_validation,
    scenario_mongodb,
)


def _events_from_rows(rows):
    result = convert_results({"results": rows, "statistics": {}})
    return result.events


def _reduce(rows, settings: Settings):
    return LogReducer(settings).reduce(_events_from_rows(rows), WINDOW_START, WINDOW_END)


def test_thousands_of_duplicates_collapse_to_few_clusters(settings: Settings) -> None:
    reduced = _reduce(scenario_mongodb(500), settings)
    assert reduced.stats.cloudwatch_events == 500
    # All 500 events share one stack trace -> essentially one cluster.
    assert reduced.stats.clusters <= 3
    top = reduced.clusters[0]
    assert top.exception_type == "MongoServerSelectionTimeout"
    assert top.count >= 490
    assert set(top.affected_endpoints) == {"/checkout", "/order"}


def test_mixed_scenario_separates_failure_modes(settings: Settings) -> None:
    reduced = _reduce(scenario_mixed_validation(), settings)
    types = {c.exception_type for c in reduced.clusters}
    assert "MongoServerSelectionTimeout" in types
    assert "ValidationError" in types
    # Real 500s should outrank noisy 400 validation errors despite lower count.
    mongo = next(c for c in reduced.clusters if c.exception_type == "MongoServerSelectionTimeout")
    validation = next(c for c in reduced.clusters if c.exception_type == "ValidationError")
    assert mongo.count < validation.count  # sanity: validation is noisier
    assert reduced.clusters.index(mongo) < reduced.clusters.index(validation)


def test_cluster_budget_enforced(settings: Settings) -> None:
    settings = settings.model_copy(update={"max_clusters": 5})
    rows = [
        make_row(WINDOW_START, f"ERROR Failure{i}Error: distinct problem number {i}")
        for i in range(20)
    ]
    reduced = _reduce(rows, settings)
    assert reduced.stats.clusters == 20
    assert len(reduced.clusters) == 5
    assert reduced.stats.truncated is True


def test_example_char_budget(settings: Settings) -> None:
    settings = settings.model_copy(update={"max_chars_per_example": 50})
    rows = [make_row(WINDOW_START, "ERROR " + "x" * 500)]
    reduced = _reduce(rows, settings)
    for cluster in reduced.clusters:
        for event in cluster.representative_events:
            assert len(event.message) <= 50


def test_examples_per_cluster_budget(settings: Settings) -> None:
    reduced = _reduce(scenario_mongodb(300), settings)
    for cluster in reduced.clusters:
        assert len(cluster.representative_events) <= settings.max_examples_per_cluster


def test_compression_ratio_reported(settings: Settings) -> None:
    reduced = _reduce(scenario_mongodb(500), settings)
    stats = reduced.stats
    assert stats.cloudwatch_events == 500
    assert stats.logical_events < 50
    assert 0 <= stats.compression_ratio < 1


def test_enrich_extracts_endpoint_and_status(settings: Settings) -> None:
    events = _events_from_rows(
        [make_row(WINDOW_START, "ERROR POST /checkout status=502 TimeoutError: db down")]
    )
    enriched = enrich_event(events[0])
    assert enriched.endpoint == "/checkout"
    assert enriched.status_code == 502
    assert enriched.exception_type == "TimeoutError"
    assert enriched.fingerprint


def test_secrets_redacted_before_clustering(settings: Settings) -> None:
    rows = [make_row(WINDOW_START, "ERROR AuthError: fail password=hunter2secret")]
    reduced = _reduce(rows, settings)
    for cluster in reduced.clusters:
        assert "hunter2secret" not in cluster.normalized_message
        for event in cluster.representative_events:
            assert "hunter2secret" not in event.message
