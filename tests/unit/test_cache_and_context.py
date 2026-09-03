"""Cache key/TTL and context-builder budget tests."""

from __future__ import annotations

import time
from datetime import timedelta

from signalsift.analysis.context_builder import ContextBuilder
from signalsift.cache.sqlite import SqliteCache, make_cache_key
from signalsift.cloudwatch.client import convert_results
from signalsift.config import Settings
from signalsift.processing.reducer import LogReducer
from tests.fixtures.generators import WINDOW_END, WINDOW_START, make_row, scenario_mongodb


class TestCache:
    def test_roundtrip(self, tmp_path) -> None:
        cache = SqliteCache(tmp_path / "c.sqlite3", ttl_seconds=60)
        cache.set("k1", "analysis", {"a": 1})
        assert cache.get("k1") == {"a": 1}
        assert cache.get("missing") is None

    def test_ttl_expiry(self, tmp_path) -> None:
        cache = SqliteCache(tmp_path / "c.sqlite3", ttl_seconds=0)
        cache.set("k1", "analysis", {"a": 1})
        time.sleep(0.01)
        assert cache.get("k1") is None

    def test_key_varies_with_all_inputs(self) -> None:
        base = make_cache_key("analyze", "m1", log_group="/a", start="s")
        assert make_cache_key("analyze", "m2", log_group="/a", start="s") != base
        assert make_cache_key("analyze", "m1", log_group="/b", start="s") != base
        assert make_cache_key("search", "m1", log_group="/a", start="s") != base
        assert make_cache_key("analyze", "m1", log_group="/a", start="s") == base

    def test_metrics_roundtrip(self, tmp_path) -> None:
        cache = SqliteCache(tmp_path / "c.sqlite3")
        cache.record_metric("analyze", {"duration_seconds": 1.5})
        metrics = cache.recent_metrics()
        assert metrics[0]["operation"] == "analyze"
        assert metrics[0]["duration_seconds"] == 1.5


class TestContextBuilder:
    def _reduced(self, settings: Settings):
        result = convert_results({"results": scenario_mongodb(200), "statistics": {}})
        return LogReducer(settings).reduce(result.events, WINDOW_START, WINDOW_END)

    def test_evidence_is_structured_and_bounded(self, settings: Settings) -> None:
        reduced = self._reduced(settings)
        evidence, selected = ContextBuilder(settings).build_incident_evidence(
            reduced, "payments", "/aws/app/payments-prod"
        )
        assert len(evidence) <= settings.max_llm_input_chars
        assert '"cluster_id"' in evidence
        assert '"count"' in evidence
        assert len(selected) <= settings.max_clusters_to_llm

    def test_budget_shrinks_clusters(self, settings: Settings) -> None:
        tight = settings.model_copy(update={"max_llm_input_chars": 1500})
        rows = []
        for i in range(30):
            rows.extend(
                make_row(
                    WINDOW_START + timedelta(seconds=j),
                    f"ERROR Failure{i}Error: problem {i} " + "detail " * 30,
                )
                for j in range(2)
            )
        result = convert_results({"results": rows, "statistics": {}})
        reduced = LogReducer(tight).reduce(result.events, WINDOW_START, WINDOW_END)
        evidence, selected = ContextBuilder(tight).build_incident_evidence(
            reduced, None, "/aws/app/payments-prod"
        )
        assert len(evidence) <= 1500
        assert len(selected) >= 1
