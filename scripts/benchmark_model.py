"""Benchmark local models on fixed incident datasets (requires Ollama).

Measures per model: total latency, structured-output success rate, and
analysis correctness against expected structured facts (never prose
similarity). Lets you decide whether 2B/4B/9B is sufficient for your Mac.

Usage:
    uv run python scripts/benchmark_model.py \
        --models qwen3:4b qwen2.5:7b qwen2.5:3b --runs 3
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from fixtures.generators import SCENARIOS, WINDOW_END, WINDOW_START  # noqa: E402

from signalsift.analysis.context_builder import ContextBuilder  # noqa: E402
from signalsift.analysis.prompts import build_incident_prompt  # noqa: E402
from signalsift.analysis.schemas import IncidentAnalysis  # noqa: E402
from signalsift.analysis.validator import validate_analysis  # noqa: E402
from signalsift.cloudwatch.client import convert_results  # noqa: E402
from signalsift.config import Settings  # noqa: E402
from signalsift.errors import SignalSiftError  # noqa: E402
from signalsift.llm.ollama import OllamaProvider  # noqa: E402
from signalsift.processing.reducer import LogReducer  # noqa: E402

# Evaluation dataset: expected structured facts per scenario (spec §36).
EVAL_CASES = [
    {
        "scenario": "mongodb",
        "count": 500,
        "expected": {
            "primary_exception": "MongoServerSelectionTimeout",
            "category_keywords": ["mongo", "database", "connect", "pool", "timeout"],
            "affected_endpoint": "/checkout",
            "min_severity": ("medium", "high", "critical"),
        },
    },
    {
        "scenario": "http_timeout",
        "count": 200,
        "expected": {
            "primary_exception": "ReadTimeout",
            "category_keywords": ["timeout", "downstream", "inventory", "http"],
            "affected_endpoint": "/inventory",
            "min_severity": ("medium", "high", "critical"),
        },
    },
    {
        "scenario": "mixed_validation",
        "count": None,
        "expected": {
            "primary_exception": "MongoServerSelectionTimeout",
            "category_keywords": ["mongo", "database", "500", "server"],
            "affected_endpoint": "/pay",
            "min_severity": ("medium", "high", "critical"),
        },
    },
]


def _score_case(analysis: IncidentAnalysis, expected: dict) -> tuple[float, list[str]]:
    """Score structured facts, 0.0-1.0."""
    notes: list[str] = []
    points = 0.0
    text = " ".join(
        [analysis.summary]
        + [c.cause for c in analysis.likely_root_causes]
        + analysis.affected_components
    ).lower()

    if expected["primary_exception"].lower() in text:
        points += 0.4
    else:
        notes.append(f"missed primary exception {expected['primary_exception']}")
    if any(kw in text for kw in expected["category_keywords"]):
        points += 0.3
    else:
        notes.append("missed failure category")
    if expected["affected_endpoint"] in " ".join(analysis.affected_components + [analysis.summary]):
        points += 0.2
    else:
        notes.append(f"missed endpoint {expected['affected_endpoint']}")
    if analysis.severity in expected["min_severity"]:
        points += 0.1
    else:
        notes.append(f"severity {analysis.severity} lower than expected")
    return points, notes


async def benchmark_model(model: str, runs: int) -> None:
    settings = Settings(
        _env_file=None,
        allowed_log_groups=["/aws/app/example"],
        llm_model=model,
        cache_path=":memory:",
    )
    provider = OllamaProvider(settings)
    if not await provider.is_available():
        print("Ollama is not reachable; start it with `ollama serve`.")
        sys.exit(1)
    if not await provider.model_available():
        print(f"Model {model} not pulled. Run: ollama pull {model}")
        return

    reducer = LogReducer(settings)
    builder = ContextBuilder(settings)
    latencies: list[float] = []
    successes = 0
    attempts = 0
    scores: list[float] = []

    print(f"\n=== {model} ===")
    for case in EVAL_CASES:
        generator = SCENARIOS[case["scenario"]]
        rows = generator(case["count"]) if case["count"] else generator()
        events = convert_results({"results": rows, "statistics": {}}).events
        reduced = reducer.reduce(events, WINDOW_START, WINDOW_END)
        evidence, selected = builder.build_incident_evidence(reduced, "example", "/aws/app/example")
        prompt = build_incident_prompt(evidence)

        for run in range(runs):
            attempts += 1
            start = time.monotonic()
            try:
                analysis = await provider.analyze(prompt, IncidentAnalysis)
                latency = time.monotonic() - start
                latencies.append(latency)
                successes += 1
                validated = validate_analysis(analysis, selected)
                score, notes = _score_case(validated.analysis, case["expected"])
                scores.append(score)
                note_str = f"  ({'; '.join(notes)})" if notes else ""
                print(
                    f"  {case['scenario']:<18} run {run + 1}: {latency:6.1f}s "
                    f"score {score:.2f}{note_str}"
                )
            except SignalSiftError as exc:
                print(f"  {case['scenario']:<18} run {run + 1}: FAILED ({exc.message})")

    print(f"\n  structured-output success: {successes}/{attempts}")
    if latencies:
        print(
            f"  latency: median {statistics.median(latencies):.1f}s  "
            f"min {min(latencies):.1f}s  max {max(latencies):.1f}s"
        )
    if scores:
        print(f"  mean correctness score: {statistics.mean(scores):.2f} / 1.00")
    await provider.aclose()


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models", nargs="+", default=["qwen3:4b"])
    parser.add_argument("--runs", type=int, default=2)
    args = parser.parse_args()
    for model in args.models:
        await benchmark_model(model, args.runs)


if __name__ == "__main__":
    asyncio.run(main())
