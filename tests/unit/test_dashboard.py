"""Dashboard rendering tests (pure function, no I/O)."""

from __future__ import annotations

from signalsift.observability.dashboard import render_dashboard


def _metrics():
    return [
        {
            "recorded_at": 1788400000.0 + i,
            "operation": "analyze_incident",
            "duration_seconds": 2.0 + i,
            "cloudwatch_events": 1000 * (i + 1),
            "clusters": 5,
            "events_sent_to_llm": 9,
            "compression_ratio": 0.005,
            "cache_hit": i == 2,
        }
        for i in range(3)
    ] + [
        {"recorded_at": 1788400010.0, "operation": "llm_analyze", "duration_seconds": 8.5},
    ]


def test_renders_tiles_charts_and_table() -> None:
    html = render_dashboard(_metrics(), "2026-09-04 10:00 UTC")
    assert "<!doctype html>" in html
    assert "operations recorded" in html
    assert "median LLM latency" in html
    assert "8.5s" in html
    assert 'class="bar"' in html  # chart bars present
    assert "<table>" in html  # accessible table view
    assert "prefers-color-scheme: dark" in html  # theme-aware
    assert "http" not in html.split("</title>")[1]  # fully self-contained


def test_empty_telemetry_renders_gracefully() -> None:
    html = render_dashboard([], "2026-09-04 10:00 UTC")
    assert "No analyses recorded yet" in html
