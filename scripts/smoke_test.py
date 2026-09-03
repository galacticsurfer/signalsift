"""End-to-end smoke test of the full pipeline with NO AWS and NO Ollama.

Feeds fixture logs through the real service layer with a fake CloudWatch
client and (optionally) real Ollama if it happens to be running, printing
the rendered incident report and compression stats.

Usage:
    uv run python scripts/smoke_test.py
    uv run python scripts/smoke_test.py --scenario mixed_validation --llm
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from fixtures.generators import SCENARIOS, WINDOW_END, WINDOW_START  # noqa: E402

from signalsift.analysis.render import render_incident_report  # noqa: E402
from signalsift.analysis.service import IncidentService  # noqa: E402
from signalsift.cloudwatch.client import CloudWatchLogsClient  # noqa: E402
from signalsift.config import Settings  # noqa: E402
from signalsift.llm.ollama import OllamaProvider  # noqa: E402


class FakeLogsClient:
    def __init__(self, rows: list) -> None:
        self.rows = rows

    def start_query(self, **kwargs: Any) -> dict:
        return {"queryId": "smoke"}

    def get_query_results(self, *, queryId: str) -> dict:  # noqa: N803
        return {
            "status": "Complete",
            "results": self.rows,
            "statistics": {"recordsMatched": float(len(self.rows))},
        }

    def stop_query(self, *, queryId: str) -> dict:  # noqa: N803
        return {}


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", default="mongodb", choices=sorted(SCENARIOS))
    parser.add_argument("--count", type=int, default=2000)
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Use real Ollama if reachable (otherwise deterministic-only)",
    )
    args = parser.parse_args()

    settings = Settings(
        _env_file=None,
        allowed_log_groups=["/aws/app/example"],
        cache_path=":memory:",
        query_poll_initial_seconds=0.01,
    )
    import inspect

    generator = SCENARIOS[args.scenario]
    kwargs = {"count": args.count} if "count" in inspect.signature(generator).parameters else {}
    rows = generator(**kwargs)

    llm = None
    if args.llm:
        candidate = OllamaProvider(settings)
        if await candidate.is_available():
            llm = candidate
            print(f"Using real Ollama model: {llm.model_name}\n")
        else:
            print("Ollama not reachable; running deterministic-only.\n")

    service = IncidentService(settings, CloudWatchLogsClient(settings, FakeLogsClient(rows)), llm)
    report = await service.analyze_incident(
        "/aws/app/example", WINDOW_START, WINDOW_END, service="example"
    )
    print(render_incident_report(report))
    print()
    ratio = report.compression_ratio
    print(
        f"Pipeline OK: {report.stats.cloudwatch_events} events -> "
        f"{report.stats.clusters} clusters "
        f"(compression ratio {ratio})"
    )


if __name__ == "__main__":
    asyncio.run(main())
